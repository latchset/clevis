// vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80:
//
// Copyright (c) 2026 Red Hat, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#include "ecmr_ops.h"
#include "jose_wrapper.h"
#include "jose_types.h"
#include "key_deriver.h"
#include "tang_client.h"

extern "C" {
#include <openssl/crypto.h>
#include <openssl/evp.h>
}

#include <array>
#include <cstring>
#include <iostream>
#include <string>
#include <unistd.h>

static constexpr const char* DEFAULT_THP_ALG = "S256";
static constexpr const char* ALT_THP_ALG = "S1";

namespace {

using namespace clevis;

static constexpr const char* DEFAULT_KEM_ALG = "ML-KEM-768";

static constexpr std::array<const char*, 3> VALID_KEM_ALGS = {{
    "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"
}};

void validateKemAlg(const std::string& alg)
{
    for (auto valid : VALID_KEM_ALGS) {
        if (alg == valid)
            return;
    }
    throw PinError("Unsupported KEM algorithm: " + alg);
}

struct JweHeader {
    JsonPtr clientEcPub;
    std::string kid;
    std::string kemKid;
    std::string kemAlg = DEFAULT_KEM_ALG;
    std::string clevisKemCt;
    std::string url;
    std::string ekDigest;
    JsonPtr advertisement;
    TlsConfig tls;
};

JweHeader parseHeader(const json_t* header)
{
    JweHeader hdr;

    auto epk = json_object_get(header, "epk");
    if (!epk)
        throw PinError("JWE missing required 'epk' header parameter!");
    hdr.clientEcPub = jsonDeepCopy(epk);

    auto kidVal = json_string_value(
        json_object_get(header, "kid"));
    if (!kidVal)
        throw PinError("JWE missing required 'kid' header parameter!");
    hdr.kid = kidVal;
    validateBase64Url(hdr.kid, "kid");

    auto kemKidVal = json_string_value(
        json_object_get(header, "kem_kid"));
    if (kemKidVal) {
        hdr.kemKid = kemKidVal;
        validateBase64Url(hdr.kemKid, "kem_kid");
    }

    auto clevis = json_object_get(header, "clevis");
    auto tang = clevis ? json_object_get(clevis, "tang-pqc") : nullptr;
    if (!tang)
        throw PinError("JWE missing 'clevis.tang-pqc' header!");

    auto urlVal = json_string_value(json_object_get(tang, "url"));
    if (!urlVal)
        throw PinError(
            "JWE missing required 'clevis.tang.url' header!");
    hdr.url = urlVal;

    auto kemCtVal = json_string_value(
        json_object_get(tang, "clevis_kem_ct"));
    if (kemCtVal)
        hdr.clevisKemCt = kemCtVal;

    auto ekDigVal = json_string_value(
        json_object_get(tang, "ek_digest"));
    if (ekDigVal)
        hdr.ekDigest = ekDigVal;

    auto algVal = json_string_value(json_object_get(tang, "alg"));
    if (algVal) {
        hdr.kemAlg = algVal;
        validateKemAlg(hdr.kemAlg);
    }

    auto adv = json_object_get(tang, "adv");
    if (adv)
        hdr.advertisement = jsonDeepCopy(adv);

    auto cacertVal = json_string_value(
        json_object_get(tang, "cacert"));
    if (cacertVal)
        hdr.tls.cacert = cacertVal;
    auto certVal = json_string_value(
        json_object_get(tang, "cert"));
    if (certVal)
        hdr.tls.cert = certVal;
    auto keyVal = json_string_value(
        json_object_get(tang, "key"));
    if (keyVal)
        hdr.tls.key = keyVal;

    return hdr;
}

JsonPtr findServerKeyInAdv(
    json_t* adv, const std::string& kid)
{
    if (!adv)
        return nullptr;

    size_t idx;
    json_t* key;
    auto keysArr = json_object_get(adv, "keys");
    if (!keysArr)
        keysArr = adv;

    json_array_foreach(keysArr, idx, key) {
        try {
            if (JoseWrapper::thumbprint(key, DEFAULT_THP_ALG) == kid)
                return jsonDeepCopy(key);
        } catch (...) {}
        try {
            if (JoseWrapper::thumbprint(key, ALT_THP_ALG) == kid)
                return jsonDeepCopy(key);
        } catch (...) {}
    }
    return nullptr;
}

bool validateTangPub(const json_t* tangPub, const std::string& kid)
{
    try {
        if (JoseWrapper::thumbprint(tangPub, DEFAULT_THP_ALG) == kid)
            return true;
    } catch (...) {}

    try {
        if (JoseWrapper::thumbprint(tangPub, ALT_THP_ALG) == kid)
            return true;
    } catch (...) {}

    return false;
}

struct EcmrRecoveryResult {
    JsonPtr ecSharedSecret;
    JsonPtr serverPub;
};

EcmrRecoveryResult ecmrRecover(
    TangClient& tang,
    const json_t* clientEcPub,
    const json_t* ephemeral,
    const json_t* serverPubHint,
    const std::string& kid,
    const std::string& crv)
{
    auto xfr = EcmrOps::blind(clientEcPub, ephemeral);
    auto fullRep = tang.ecmrRecover(kid, xfr.get());

    JsonPtr serverPub;
    auto tangPubField = json_object_get(fullRep.get(), "tang_pub");
    if (tangPubField) {
        if (!validateTangPub(tangPubField, kid))
            throw PinError(
                "tang_pub thumbprint does not match kid!");
        serverPub = jsonDeepCopy(tangPubField);
    } else if (serverPubHint) {
        serverPub = jsonDeepCopy(serverPubHint);
    }

    if (!serverPub) {
        try {
            auto advJws = tang.fetchAdvertisement("");
            auto advJwks = JoseWrapper::jwsPayload(advJws.get());
            serverPub = findServerKeyInAdv(advJwks.get(), kid);
        } catch (const std::exception& e) {
            std::cerr << "Fallback /adv fetch failed: "
                      << e.what() << std::endl;
        }
    }

    if (!serverPub)
        throw PinError(
            "Unable to determine server exchange key");

    auto rep = jsonDeepCopy(fullRep.get());
    json_object_del(rep.get(), "tang_pub");

    auto kty = json_string_value(
        json_object_get(rep.get(), "kty"));
    auto repCrv = json_string_value(
        json_object_get(rep.get(), "crv"));
    if (!kty || std::strcmp(kty, "EC") != 0
        || !repCrv || crv != repCrv)
        throw PinError("Received invalid server reply!");

    auto ecKey = EcmrOps::unblind(
        rep.get(), ephemeral, serverPub.get());
    return {std::move(ecKey), std::move(serverPub)};
}

JsonPtr fetchKemKey(
    TangClient& tang,
    const std::string& kemKid,
    const json_t* verKeys)
{
    auto kemJws = tang.fetchKemKeyByThumbprint(kemKid);

    if (!JoseWrapper::jwsVerify(kemJws.get(), verKeys, true))
        throw PinError(
            "KEM key signature verification failed "
            "(possible MITM)!");

    auto kemJwks = JoseWrapper::jwsPayload(kemJws.get());

    auto keysArr = json_object_get(kemJwks.get(), "keys");
    if (!keysArr)
        keysArr = kemJwks.get();

    size_t idx;
    json_t* key;
    json_array_foreach(keysArr, idx, key) {
        try {
            if (JoseWrapper::thumbprint(key, DEFAULT_THP_ALG) == kemKid)
                return jsonDeepCopy(key);
        } catch (...) {}
        try {
            if (JoseWrapper::thumbprint(key, ALT_THP_ALG) == kemKid)
                return jsonDeepCopy(key);
        } catch (...) {}
    }

    throw PinError("KEM key not found in server response");
}

std::string computeSha256B64Url(const std::string& input)
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digestLen = 0;

    if (!EVP_Digest(
            input.data(), input.size(),
            digest, &digestLen,
            EVP_sha256(), nullptr))
        throw PinError("SHA-256 computation failed");

    return JoseWrapper::base64UrlEncode(digest, digestLen);
}

void validateStringField(
    const json_t* hdr,
    const char* field,
    const std::string& expected)
{
    auto val = json_string_value(json_object_get(hdr, field));
    if (!val || expected != val)
        throw PinError(
            std::string("Response header: ") + field + " mismatch");
}

void validateReqDigest(
    const json_t* hdr, const std::string& reqProtB64)
{
    auto reqDigest = json_string_value(
        json_object_get(hdr, "req_digest"));
    if (!reqDigest)
        throw PinError("Response header: missing req_digest");

    auto expected = computeSha256B64Url(reqProtB64);
    if (expected != reqDigest)
        throw PinError(
            "Response header: req_digest mismatch "
            "(possible replay/reflection)");
}

void validateCritFieldsPresence(const json_t* hdr)
{
    auto crit = json_object_get(hdr, "crit");
    if (!crit || !json_is_array(crit))
        throw PinError("Response header: missing crit array");

    static constexpr std::array<const char*, 6> REQUIRED = {{
        "kem_ver", "suite", "kid", "kem_kid",
        "msg_dir", "req_digest"
    }};
    for (auto field : REQUIRED) {
        bool found = false;
        size_t idx;
        json_t* val;
        json_array_foreach(crit, idx, val) {
            auto s = json_string_value(val);
            if (s && std::strcmp(s, field) == 0) {
                found = true;
                break;
            }
        }
        if (!found)
            throw PinError(
                std::string("Response header: crit missing '")
                + field + "'");
    }
}

void validateResponseHeader(
    const json_t* respJwe,
    const std::string& reqProtB64,
    const std::string& kid,
    const std::string& kemKid,
    const std::string& kemAlg)
{
    auto protB64 = json_string_value(
        json_object_get(respJwe, "protected"));
    if (!protB64)
        return;

    auto protBytes = JoseWrapper::base64UrlDecode(protB64);
    std::string protStr(protBytes.begin(), protBytes.end());
    auto hdr = jsonParse(protStr);

    if (!json_object_get(hdr.get(), "kem_ver"))
        return;

    std::string expectedSuite = "ECMR+" + kemAlg;
    validateCritFieldsPresence(hdr.get());
    validateStringField(hdr.get(), "kem_ver", "hybrid-v1");
    validateStringField(hdr.get(), "suite", expectedSuite);
    validateStringField(hdr.get(), "msg_dir", "tang-to-clevis");
    validateStringField(hdr.get(), "kid", kid);
    validateStringField(hdr.get(), "kem_kid", kemKid);
    validateReqDigest(hdr.get(), reqProtB64);
}

CleansedString secureTransportRecover(
    TangClient& tang,
    const JweHeader& hdr,
    const json_t* tangKemPub)
{
    auto kemKeySpecJson = makeJsonPtr(
        json_pack("{s:s}", "alg", hdr.kemAlg.c_str()));
    if (!kemKeySpecJson)
        throw PinError("Failed to build KEM key spec");
    auto kemKeySpecDump = jsonDump(kemKeySpecJson.get());
    CleansedJsonPtr clevisKemPriv(
        JoseWrapper::generateKey(
            kemKeySpecDump.get()).release());
    auto clevisKemPub = JoseWrapper::publicKey(
        clevisKemPriv.get());

    auto [clevisTransportCt, clevisTransportKey_] =
        JoseWrapper::encapsulate(tangKemPub);
    CleansedJsonPtr clevisTransportKey(
        clevisTransportKey_.release());

    auto innerObj = makeJsonPtr(json_pack(
        "{s:s, s:O, s:s}",
        "clevis_kem_ct", hdr.clevisKemCt.c_str(),
        "clevis_kem_pub", clevisKemPub.get(),
        "ek_digest", hdr.ekDigest.c_str()));
    if (!innerObj)
        throw PinError("Failed to build inner payload");
    auto innerPayloadDump = jsonDump(innerObj.get());
    CleansedString innerPayload(innerPayloadDump.get());

    std::string suite = "ECMR+" + hdr.kemAlg;
    auto blobProt = makeJsonPtr(json_pack(
        "{s:s, s:s, s:s, s:s, s:s, s:s, s:s, s:[s,s,s,s,s]}",
        "alg", "dir",
        "enc", "A256GCM",
        "kem_ver", "hybrid-v1",
        "suite", suite.c_str(),
        "kid", hdr.kid.c_str(),
        "kem_kid", hdr.kemKid.c_str(),
        "msg_dir", "clevis-to-tang",
        "crit", "kem_ver", "suite", "kid", "kem_kid", "msg_dir"));
    if (!blobProt)
        throw PinError("Failed to build transport protected header");
    auto blobJwe = makeJsonPtr(json_pack(
        "{s:O}", "protected", blobProt.get()));
    if (!blobJwe)
        throw PinError("Failed to build inner blob JWE");
    if (!JoseWrapper::jweEncrypt(
            blobJwe.get(), clevisTransportKey.get(),
            innerPayload.data(), innerPayload.size()))
        throw PinError("Failed to encrypt inner payload");

    auto reqProtB64 = json_string_value(
        json_object_get(blobJwe.get(), "protected"));
    if (!reqProtB64)
        throw PinError("Failed to extract request protected header");
    std::string reqProtB64Str(reqProtB64);

    auto encryptedBlob = JoseWrapper::jweToCompact(blobJwe.get());

    auto kemResp = tang.kemRecover(
        hdr.kemKid, encryptedBlob, clevisTransportCt);

    CleansedJsonPtr tangTransportKey(
        JoseWrapper::decapsulate(
            clevisKemPriv.get(),
            kemResp.tangTransportCt).release());

    auto tangEncJwe = JoseWrapper::jweFromCompact(
        kemResp.tangEncryptedKey);

    validateResponseHeader(
        tangEncJwe.get(), reqProtB64Str,
        hdr.kid, hdr.kemKid, hdr.kemAlg);

    CleansedVector<uint8_t> encKeyBytes(
        JoseWrapper::jweDecrypt(
            tangEncJwe.get(), tangTransportKey.get()));

    CleansedString encKeyJson(
        encKeyBytes.begin(), encKeyBytes.end());
    CleansedJsonPtr encKeyObj(jsonParse(encKeyJson).release());
    auto kVal = json_string_value(
        json_object_get(encKeyObj.get(), "k"));
    if (!kVal)
        throw PinError("Recovered enc_key missing 'k' field");

    return CleansedString(kVal);
}

std::string readCompactJwe()
{
    constexpr size_t maxSize = 1 << 20;
    std::string result;
    std::array<char, 4096> buf{};
    while (std::cin.read(buf.data(), buf.size())
           || std::cin.gcount() > 0) {
        result.append(buf.data(),
            static_cast<size_t>(std::cin.gcount()));
        if (result.size() > maxSize)
            throw PinError("JWE input exceeds maximum size");
    }
    return result;
}

} // anonymous namespace

int main(int argc, char* argv[])
{
    if (argc == 2 && std::strcmp(argv[1], "--summary") == 0)
        return 2;

    if (isatty(STDIN_FILENO)) {
        std::cerr
            << "\n"
            << "Usage: clevis decrypt tang-pqc < JWE > PLAINTEXT\n"
            << "\n";
        return 2;
    }

    try {
        auto compactJwe = readCompactJwe();
        auto jwe = JoseWrapper::jweFromCompact(compactJwe);

        auto protB64 = json_string_value(
            json_object_get(jwe.get(), "protected"));
        if (!protB64)
            throw PinError("JWE missing protected header");

        auto protBytes = JoseWrapper::base64UrlDecode(protB64);
        std::string protStr(protBytes.begin(), protBytes.end());
        auto header = jsonParse(protStr);

        auto pin = json_string_value(json_object_get(
            json_object_get(header.get(), "clevis"), "pin"));
        if (!pin || std::strcmp(pin, "tang-pqc") != 0)
            throw PinError("JWE pin mismatch!");

        auto hdr = parseHeader(header.get());

        if (hdr.clevisKemCt.empty() || hdr.kemKid.empty())
            throw PinError(
                "Not a hybrid PQC JWE. "
                "Use clevis-decrypt-tang for classical mode.");

        auto crv = json_string_value(
            json_object_get(hdr.clientEcPub.get(), "crv"));
        if (!crv)
            throw PinError("Unable to determine EPK's curve!");
        validateEcCurve(crv);

        JsonPtr serverPubHint;
        if (hdr.advertisement)
            serverPubHint = findServerKeyInAdv(
                hdr.advertisement.get(), hdr.kid);

        TangClient tang(hdr.url, hdr.tls);

        JsonPtr advJwks;
        if (hdr.advertisement) {
            advJwks = jsonDeepCopy(hdr.advertisement.get());
        } else {
            auto advJws = tang.fetchAdvertisement("");
            advJwks = JoseWrapper::jwsPayload(advJws.get());
        }
        auto verKeys = JoseWrapper::filterKeysByUse(
            advJwks.get(), "verify");

        auto ephSpecJson = makeJsonPtr(json_pack(
            "{s:s, s:s}", "alg", "ECMR", "crv", crv));
        if (!ephSpecJson)
            throw PinError("Failed to build ephemeral key spec");
        auto ephSpecDump = jsonDump(ephSpecJson.get());
        CleansedJsonPtr ephemeral(
            JoseWrapper::generateKey(
                ephSpecDump.get()).release());

        auto [ecKey_, serverPub] = ecmrRecover(
            tang, hdr.clientEcPub.get(), ephemeral.get(),
            serverPubHint.get(), hdr.kid, crv);
        CleansedJsonPtr ecKey(ecKey_.release());

        auto ecX = json_string_value(
            json_object_get(ecKey.get(), "x"));
        if (!ecX)
            throw PinError("ECMR result missing x-coordinate");

        auto tangKemPub = fetchKemKey(
            tang, hdr.kemKid, verKeys.get());

        CleansedString encKeyK(
            secureTransportRecover(
                tang, hdr, tangKemPub.get()));

        CleansedJsonPtr encKey(
            KeyDeriver::deriveEncKey(
                ecX, encKeyK, hdr.kid,
                hdr.kemKid, hdr.kemAlg).release());

        CleansedVector<uint8_t> plaintext(
            JoseWrapper::jweDecrypt(
                jwe.get(), encKey.get()));

        std::cout.write(
            reinterpret_cast<const char*>(plaintext.data()),
            static_cast<std::streamsize>(plaintext.size()));

        return 0;

    } catch (const PinError& e) {
        std::cerr << e.what() << std::endl;
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Internal error: " << e.what() << std::endl;
        return 1;
    }
}
