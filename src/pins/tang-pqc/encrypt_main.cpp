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

#include <array>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <unistd.h>

static constexpr const char* SUMMARY =
    "Encrypts using a Tang hybrid PQC binding server policy";
static constexpr const char* DEFAULT_THP_ALG = "S256";

namespace {

using namespace clevis;

void printUsage()
{
    std::cerr
        << "\n"
        << "Usage: clevis encrypt tang-pqc CONFIG [-y] "
           "< PLAINTEXT > JWE\n"
        << "\n"
        << SUMMARY << "\n"
        << "\n"
        << "  -y              Skip the advertisement trust check\n"
        << "\n"
        << "This command uses the following configuration properties:\n"
        << "\n"
        << "  url: <string>   The base URL of the Tang server "
           "(REQUIRED)\n"
        << "\n"
        << "  thp: <string>   The thumbprint of a trusted signing key\n"
        << "\n"
        << "  adv: <string>   A filename containing a trusted "
           "advertisement\n"
        << "  adv: <object>   A trusted advertisement (raw JSON)\n"
        << "\n"
        << "  adv_kem: <string>  A filename containing a trusted "
           "KEM advertisement\n"
        << "  adv_kem: <object>  A trusted KEM advertisement "
           "(raw JSON)\n"
        << "\n"
        << "  alg: <string>     KEM algorithm (default: ML-KEM-768)\n"
        << "\n"
        << "  cacert: <string>  CA bundle for verifying Tang's TLS "
           "certificate\n"
        << "  cert: <string>    Client TLS certificate for mTLS\n"
        << "  key: <string>     Private key for the client TLS "
           "certificate\n"
        << "\n";
}

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

struct Config {
    std::string url;
    std::string thp;
    std::string kemAlg = DEFAULT_KEM_ALG;
    TlsConfig tls;
    JsonPtr inlineAdv;
    std::string advFile;
    JsonPtr inlineAdvKem;
    std::string advKemFile;
    bool trust = false;
};

Config parseConfig(const std::string& configStr, bool autoTrust)
{
    auto cfg = jsonParse(configStr);
    Config config;
    config.trust = autoTrust;

    auto urlVal = json_string_value(json_object_get(cfg.get(), "url"));
    if (!urlVal)
        throw PinError("Missing the required 'url' property!");
    config.url = urlVal;

    auto thpVal = json_string_value(json_object_get(cfg.get(), "thp"));
    if (thpVal) {
        config.thp = thpVal;
        if (config.thp != "any")
            validateBase64Url(config.thp, "thp");
    }

    auto cacertVal = json_string_value(
        json_object_get(cfg.get(), "cacert"));
    if (cacertVal)
        config.tls.cacert = cacertVal;

    auto certVal = json_string_value(
        json_object_get(cfg.get(), "cert"));
    if (certVal)
        config.tls.cert = certVal;

    auto keyVal = json_string_value(
        json_object_get(cfg.get(), "key"));
    if (keyVal)
        config.tls.key = keyVal;

    auto adv = json_object_get(cfg.get(), "adv");
    if (adv && json_is_object(adv)) {
        config.inlineAdv = jsonDeepCopy(adv);
        if (config.thp.empty())
            config.thp = "any";
    } else if (adv && json_is_string(adv)) {
        config.advFile = json_string_value(adv);
        if (config.thp.empty())
            config.thp = "any";
    }

    auto algVal = json_string_value(json_object_get(cfg.get(), "alg"));
    if (algVal) {
        config.kemAlg = algVal;
        validateKemAlg(config.kemAlg);
    }

    auto advKem = json_object_get(cfg.get(), "adv_kem");
    if (advKem && json_is_object(advKem)) {
        config.inlineAdvKem = jsonDeepCopy(advKem);
    } else if (advKem && json_is_string(advKem)) {
        config.advKemFile = json_string_value(advKem);
    }

    return config;
}

JsonPtr findKemKey(json_t* jwks, const std::string& kemAlg)
{
    auto keysArray = json_object_get(jwks, "keys");
    if (!keysArray)
        keysArray = jwks;

    size_t idx;
    json_t* key;
    json_array_foreach(keysArray, idx, key) {
        auto kty = json_string_value(json_object_get(key, "kty"));
        if (!kty || std::strcmp(kty, "AKP") != 0)
            continue;
        auto alg = json_string_value(json_object_get(key, "alg"));
        if (alg && kemAlg != alg)
            continue;
        return jsonDeepCopy(key);
    }
    return nullptr;
}

JsonPtr findExchangeKey(const json_t* jwks)
{
    auto filtered = JoseWrapper::filterKeysByUse(jwks, "deriveKey");
    auto keysArr = json_is_array(filtered.get()) ? filtered.get()
        : json_object_get(filtered.get(), "keys");

    json_t* first = nullptr;
    if (json_is_array(keysArr) && json_array_size(keysArr) > 0)
        first = json_array_get(keysArr, 0);
    else if (json_is_object(keysArr))
        first = keysArr;

    if (!first)
        throw PinError("No exchange keys found!");

    auto result = jsonDeepCopy(first);
    json_object_del(result.get(), "key_ops");
    json_object_del(result.get(), "alg");
    return result;
}

bool verifyTrust(
    const json_t* jwks, const std::string& thp, bool autoTrust)
{
    auto verKeys = JoseWrapper::filterKeysByUse(jwks, "verify");
    if (json_array_size(verKeys.get()) == 0)
        return false;

    if (autoTrust || thp == "any")
        return true;

    if (thp.empty()) {
        std::cerr << "The advertisement contains the following "
                     "signing keys:\n\n";
        size_t idx;
        json_t* key;
        json_array_foreach(verKeys.get(), idx, key) {
            auto t = JoseWrapper::thumbprint(key, DEFAULT_THP_ALG);
            std::cerr << t << "\n";
        }
        std::cerr << "\n";

        std::cerr << "Do you wish to trust these keys? [ynYN] ";
        std::string ans;
        std::ifstream tty("/dev/tty");
        if (!tty)
            return false;
        std::getline(tty, ans);
        return !ans.empty() && (ans[0] == 'y' || ans[0] == 'Y');
    }

    return JoseWrapper::thumbprintMatch(
        verKeys.get(), thp, DEFAULT_THP_ALG);
}

std::string readStdin()
{
    constexpr size_t maxSize = 1 << 20;
    std::string result;
    std::array<char, 4096> buf{};
    while (std::cin.read(buf.data(), buf.size())
           || std::cin.gcount() > 0) {
        result.append(buf.data(),
            static_cast<size_t>(std::cin.gcount()));
        if (result.size() > maxSize)
            throw PinError("Input exceeds maximum size");
    }
    return result;
}

std::string readBoundedFile(const std::string& path)
{
    constexpr size_t maxSize = 1 << 20;
    std::ifstream f(path);
    if (!f)
        throw PinError("File '" + path + "' not found!");
    std::string result;
    std::array<char, 4096> buf{};
    while (f.read(buf.data(), buf.size()) || f.gcount() > 0) {
        result.append(buf.data(),
            static_cast<size_t>(f.gcount()));
        if (result.size() > maxSize)
            throw PinError(
                "File '" + path + "' exceeds maximum size");
    }
    return result;
}

std::string hybridEncrypt(
    const json_t* tangEcPub,
    const json_t* tangKemPub,
    const std::string& kid,
    const Config& config,
    const json_t* jwks,
    bool hasTangPub,
    const std::string& plaintext)
{
    auto crv = json_string_value(
        json_object_get(tangEcPub, "crv"));
    if (!crv)
        throw PinError("Tang EC key missing 'crv'");
    validateEcCurve(crv);

    auto keySpecJson = makeJsonPtr(json_pack(
        "{s:s, s:s}", "alg", "ECMR", "crv", crv));
    if (!keySpecJson)
        throw PinError("Failed to build key spec");
    auto keySpecDump = jsonDump(keySpecJson.get());
    CleansedJsonPtr clevisEcKey(
        JoseWrapper::generateKey(
            keySpecDump.get()).release());
    auto clevisEcPub = JoseWrapper::publicKey(clevisEcKey.get());

    CleansedJsonPtr encEcKey(
        JoseWrapper::keyExchange(
            clevisEcKey.get(), tangEcPub).release());
    auto encEcX = json_string_value(
        json_object_get(encEcKey.get(), "x"));
    if (!encEcX)
        throw PinError("ECDH result missing x-coordinate");
    CleansedString encEcXStr(encEcX);

    auto [kemCt, kemSs_] = JoseWrapper::encapsulate(tangKemPub);
    CleansedJsonPtr kemSs(kemSs_.release());
    auto kemK = json_string_value(
        json_object_get(kemSs.get(), "k"));
    if (!kemK)
        throw PinError("KEM shared secret missing 'k' field");
    CleansedString kemKStr(kemK);

    auto ekDigest = JoseWrapper::thumbprint(kemSs.get(), "S256");

    auto kemKid = JoseWrapper::thumbprint(tangKemPub, DEFAULT_THP_ALG);

    CleansedJsonPtr encKey(
        KeyDeriver::deriveEncKey(
            encEcXStr, kemKStr, kid, kemKid,
            config.kemAlg).release());

    auto jwe = jsonParse(
        "{\"protected\":{"
        "\"alg\":\"dir\","
        "\"enc\":\"A256GCM\","
        "\"clevis\":{\"pin\":\"tang-pqc\",\"tang-pqc\":{}}"
        "}}");
    auto prot = json_object_get(jwe.get(), "protected");

    jsonObjectSetChecked(prot, "kid", json_string(kid.c_str()));
    jsonObjectSetChecked(prot, "kem_kid",
                         json_string(kemKid.c_str()));

    auto tang = json_object_get(
        json_object_get(prot, "clevis"), "tang-pqc");
    jsonObjectSetChecked(tang, "url",
                         json_string(config.url.c_str()));
    jsonObjectSetChecked(prot, "epk",
                         json_deep_copy(clevisEcPub.get()));
    jsonObjectSetChecked(tang, "clevis_kem_ct",
                         json_string(kemCt.c_str()));
    jsonObjectSetChecked(tang, "tang_kem_pub",
                         json_deep_copy(tangKemPub));
    jsonObjectSetChecked(tang, "ek_digest",
                         json_string(ekDigest.c_str()));
    jsonObjectSetChecked(tang, "alg",
                         json_string(config.kemAlg.c_str()));

    if (!config.tls.cacert.empty())
        jsonObjectSetChecked(tang, "cacert",
            json_string(config.tls.cacert.c_str()));
    if (!config.tls.cert.empty())
        jsonObjectSetChecked(tang, "cert",
            json_string(config.tls.cert.c_str()));
    if (!config.tls.key.empty())
        jsonObjectSetChecked(tang, "key",
            json_string(config.tls.key.c_str()));

    if (!hasTangPub && jwks)
        jsonObjectSetChecked(tang, "adv", json_deep_copy(jwks));

    if (!JoseWrapper::jweEncrypt(
            jwe.get(), encKey.get(),
            plaintext.data(), plaintext.size()))
        throw PinError("JWE encryption failed");

    return JoseWrapper::jweToCompact(jwe.get());
}

} // anonymous namespace

int main(int argc, char* argv[])
{
    if (argc > 1 && std::strcmp(argv[1], "--summary") == 0) {
        std::cout << SUMMARY << std::endl;
        return 0;
    }

    if (isatty(STDIN_FILENO)) {
        printUsage();
        return 2;
    }

    if (argc < 2) {
        printUsage();
        return 2;
    }

    try {
        bool autoTrust = (argc >= 3
                          && std::strcmp(argv[2], "-y") == 0);
        auto config = parseConfig(argv[1], autoTrust);

        TangClient tang(config.url, config.tls);

        JsonPtr jws;
        bool fetchedFromNetwork = false;

        if (config.inlineAdv) {
            jws = std::move(config.inlineAdv);
        } else if (!config.advFile.empty()) {
            jws = jsonParse(readBoundedFile(config.advFile));
        } else {
            jws = tang.fetchAdvertisement(config.thp);
            fetchedFromNetwork = true;
        }

        auto jwks = JoseWrapper::jwsPayload(jws.get());

        auto verKeys = JoseWrapper::filterKeysByUse(
            jwks.get(), "verify");
        if (!JoseWrapper::jwsVerify(
                jws.get(), verKeys.get(), true))
            throw PinError("Advertisement is missing signatures!");

        if (!verifyTrust(
                jwks.get(), config.thp, config.trust))
            throw PinError(
                "Advertisement trust check failed!");

        auto tangEcPub = findExchangeKey(jwks.get());
        auto kid = JoseWrapper::thumbprint(
            tangEcPub.get(), DEFAULT_THP_ALG);

        bool advOffline = !fetchedFromNetwork;
        bool kemOffline = config.inlineAdvKem
                          || !config.advKemFile.empty();

        if (advOffline != kemOffline)
            throw PinError(
                "Both 'adv' and 'adv_kem' must be provided "
                "together for offline binding.");

        JsonPtr kemJws;
        bool hasTangPub = false;

        if (advOffline) {
            if (config.inlineAdvKem) {
                kemJws = std::move(config.inlineAdvKem);
            } else {
                kemJws = jsonParse(
                    readBoundedFile(config.advKemFile));
            }
        } else {
            VersionInfo version = tang.fetchVersion();

            if (!version.hybridRecovery)
                throw PinError(
                    "Tang server does not support hybrid PQC. "
                    "Use clevis-encrypt-tang for classical "
                    "mode.");

            hasTangPub = version.tangPub;
            kemJws = tang.fetchKemAdvertisement(config.kemAlg);
        }

        if (!JoseWrapper::jwsVerify(
                kemJws.get(), verKeys.get(), true))
            throw PinError(
                "KEM advertisement signature verification "
                "failed!");

        auto kemJwks = JoseWrapper::jwsPayload(kemJws.get());
        auto tangKemPub = findKemKey(kemJwks.get(), config.kemAlg);
        if (!tangKemPub)
            throw PinError(
                "No " + config.kemAlg + " key found in KEM "
                "advertisement. Use clevis-encrypt-tang for "
                "classical mode.");

        CleansedString plaintext(readStdin());
        auto result = hybridEncrypt(
            tangEcPub.get(), tangKemPub.get(), kid,
            config, jwks.get(), hasTangPub, plaintext);

        std::cout << result;
        return 0;

    } catch (const PinError& e) {
        std::cerr << e.what() << std::endl;
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Internal error: " << e.what() << std::endl;
        return 1;
    }
}
