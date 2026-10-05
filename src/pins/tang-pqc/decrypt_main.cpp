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
}

#include <cstring>
#include <iostream>
#include <iterator>
#include <string>
#include <unistd.h>

static constexpr const char* DEFAULT_THP_ALG = "S256";
static constexpr const char* ALT_THP_ALG = "S1";

namespace {

using namespace clevis;

struct JweHeader {
    JsonPtr clientEcPub;
    std::string kid;
    std::string kemKid;
    std::string clevisKemCt;
    std::string url;
    std::string ekDigest;
    JsonPtr tangKemPub;
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

    auto kemKidVal = json_string_value(
        json_object_get(header, "kem_kid"));
    if (kemKidVal)
        hdr.kemKid = kemKidVal;

    auto clevis = json_object_get(header, "clevis");
    auto tang = clevis ? json_object_get(clevis, "tang") : nullptr;
    if (!tang)
        throw PinError("JWE missing 'clevis.tang' header!");

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

    auto kemPub = json_object_get(tang, "tang_kem_pub");
    if (kemPub)
        hdr.tangKemPub = jsonDeepCopy(kemPub);

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

std::string secureTransportRecover(
    TangClient& tang,
    const JweHeader& hdr,
    const std::string& ecX)
{
    auto clevisKemPriv = JoseWrapper::generateKey(
        "{\"alg\":\"ML-KEM-768\"}");
    auto clevisKemPub = JoseWrapper::publicKey(
        clevisKemPriv.get());

    auto [transportCt, transportKey] =
        JoseWrapper::encapsulate(hdr.tangKemPub.get());

    auto clevisKemPubStr = jsonDump(clevisKemPub.get());
    std::string innerPayload =
        "{\"clevis_kem_ct\":\""
        + hdr.clevisKemCt
        + "\",\"clevis_kem_pub\":"
        + clevisKemPubStr.get()
        + ",\"ek_digest\":\""
        + hdr.ekDigest + "\"}";

    auto blobJwe = jsonParse(
        "{\"protected\":{\"alg\":\"dir\",\"enc\":\"A256GCM\"}}");
    if (!JoseWrapper::jweEncrypt(
            blobJwe.get(), transportKey.get(),
            innerPayload.data(), innerPayload.size()))
        throw PinError("Failed to encrypt inner payload");

    auto encryptedBlob = JoseWrapper::jweToCompact(blobJwe.get());

    auto kemResp = tang.kemRecover(
        hdr.kemKid, encryptedBlob, transportCt);

    auto tangTransportKey = JoseWrapper::decapsulate(
        clevisKemPriv.get(), kemResp.tangTransportCt);

    auto tangEncJwe = JoseWrapper::jweFromCompact(
        kemResp.tangEncryptedKey);
    auto encKeyBytes = JoseWrapper::jweDecrypt(
        tangEncJwe.get(), tangTransportKey.get());

    std::string encKeyJson(
        encKeyBytes.begin(), encKeyBytes.end());
    auto encKeyObj = jsonParse(encKeyJson);
    auto kVal = json_string_value(
        json_object_get(encKeyObj.get(), "k"));
    if (!kVal)
        throw PinError("Recovered enc_key missing 'k' field");

    OPENSSL_cleanse(&innerPayload[0], innerPayload.size());
    OPENSSL_cleanse(&encKeyJson[0], encKeyJson.size());

    return std::string(kVal);
}

std::string readCompactJwe()
{
    std::cin >> std::noskipws;
    return std::string(
        std::istream_iterator<char>(std::cin),
        std::istream_iterator<char>());
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

        JsonPtr serverPubHint;
        if (hdr.advertisement)
            serverPubHint = findServerKeyInAdv(
                hdr.advertisement.get(), hdr.kid);

        TangClient tang(hdr.url, hdr.tls);

        std::string ephSpec =
            "{\"alg\":\"ECMR\",\"crv\":\""
            + std::string(crv) + "\"}";
        auto ephemeral = JoseWrapper::generateKey(ephSpec);

        auto [ecKey, serverPub] = ecmrRecover(
            tang, hdr.clientEcPub.get(), ephemeral.get(),
            serverPubHint.get(), hdr.kid, crv);

        auto ecX = json_string_value(
            json_object_get(ecKey.get(), "x"));
        if (!ecX)
            throw PinError("ECMR result missing x-coordinate");

        auto encKeyK = secureTransportRecover(
            tang, hdr, ecX);

        auto encKey = KeyDeriver::deriveEncKey(
            ecX, encKeyK, hdr.kid, hdr.kemKid);

        OPENSSL_cleanse(&encKeyK[0], encKeyK.size());

        auto plaintext = JoseWrapper::jweDecrypt(
            jwe.get(), encKey.get());

        std::cout.write(
            reinterpret_cast<const char*>(plaintext.data()),
            static_cast<std::streamsize>(plaintext.size()));

        OPENSSL_cleanse(plaintext.data(), plaintext.size());
        return 0;

    } catch (const PinError& e) {
        std::cerr << e.what() << std::endl;
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Internal error: " << e.what() << std::endl;
        return 1;
    }
}
