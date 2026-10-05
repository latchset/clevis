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
#include <fstream>
#include <iostream>
#include <iterator>
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
        << "  cacert: <string>  CA bundle for verifying Tang's TLS "
           "certificate\n"
        << "  cert: <string>    Client TLS certificate for mTLS\n"
        << "  key: <string>     Private key for the client TLS "
           "certificate\n"
        << "\n";
}

struct Config {
    std::string url;
    std::string thp;
    TlsConfig tls;
    JsonPtr inlineAdv;
    std::string advFile;
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
    if (thpVal)
        config.thp = thpVal;

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

    return config;
}

JsonPtr findKemKey(json_t* jwks)
{
    auto keysArray = json_object_get(jwks, "keys");
    if (!keysArray)
        keysArray = jwks;

    size_t idx;
    json_t* key;
    json_array_foreach(keysArray, idx, key) {
        auto kty = json_string_value(json_object_get(key, "kty"));
        if (kty && std::strcmp(kty, "AKP") == 0)
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
        std::getline(std::cin, ans);
        return !ans.empty() && (ans[0] == 'y' || ans[0] == 'Y');
    }

    return JoseWrapper::thumbprintMatch(
        verKeys.get(), thp, DEFAULT_THP_ALG);
}

std::string readStdin()
{
    std::cin >> std::noskipws;
    return std::string(
        std::istream_iterator<char>(std::cin),
        std::istream_iterator<char>());
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

    std::string keySpec =
        "{\"alg\":\"ECMR\",\"crv\":\"" + std::string(crv) + "\"}";
    auto clevisEcKey = JoseWrapper::generateKey(keySpec);
    auto clevisEcPub = JoseWrapper::publicKey(clevisEcKey.get());

    auto encEcKey = JoseWrapper::keyExchange(
        clevisEcKey.get(), tangEcPub);
    auto encEcX = json_string_value(
        json_object_get(encEcKey.get(), "x"));
    if (!encEcX)
        throw PinError("ECDH result missing x-coordinate");
    std::string encEcXStr(encEcX);

    auto [kemCt, kemSs] = JoseWrapper::encapsulate(tangKemPub);
    auto kemK = json_string_value(
        json_object_get(kemSs.get(), "k"));
    if (!kemK)
        throw PinError("KEM shared secret missing 'k' field");
    std::string kemKStr(kemK);

    auto ekDigest = JoseWrapper::thumbprint(kemSs.get(), "S256");

    auto kemKid = JoseWrapper::thumbprint(tangKemPub, DEFAULT_THP_ALG);

    auto encKey = KeyDeriver::deriveEncKey(
        encEcXStr, kemKStr, kid, kemKid);

    OPENSSL_cleanse(&encEcXStr[0], encEcXStr.size());
    OPENSSL_cleanse(&kemKStr[0], kemKStr.size());

    auto jwe = jsonParse(
        "{\"protected\":{"
        "\"alg\":\"dir\","
        "\"enc\":\"A256GCM\","
        "\"clevis\":{\"pin\":\"tang-pqc\",\"tang\":{}}"
        "}}");
    auto prot = json_object_get(jwe.get(), "protected");

    json_object_set_new(prot, "kid", json_string(kid.c_str()));
    json_object_set_new(prot, "kem_kid",
                        json_string(kemKid.c_str()));

    auto tang = json_object_get(
        json_object_get(prot, "clevis"), "tang");
    json_object_set_new(tang, "url",
                        json_string(config.url.c_str()));
    json_object_set_new(prot, "epk",
                        json_deep_copy(clevisEcPub.get()));
    json_object_set_new(tang, "clevis_kem_ct",
                        json_string(kemCt.c_str()));
    json_object_set_new(tang, "tang_kem_pub",
                        json_deep_copy(tangKemPub));
    json_object_set_new(tang, "ek_digest",
                        json_string(ekDigest.c_str()));

    if (!config.tls.cacert.empty())
        json_object_set_new(tang, "cacert",
            json_string(config.tls.cacert.c_str()));
    if (!config.tls.cert.empty())
        json_object_set_new(tang, "cert",
            json_string(config.tls.cert.c_str()));
    if (!config.tls.key.empty())
        json_object_set_new(tang, "key",
            json_string(config.tls.key.c_str()));

    if (!hasTangPub && jwks)
        json_object_set_new(tang, "adv", json_deep_copy(jwks));

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
            auto f = std::ifstream(config.advFile);
            if (!f)
                throw PinError("Advertisement file '"
                    + config.advFile + "' not found!");
            std::string content(
                (std::istreambuf_iterator<char>(f)),
                std::istreambuf_iterator<char>());
            jws = jsonParse(content);
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

        VersionInfo version;
        if (fetchedFromNetwork)
            version = tang.fetchVersion();

        if (!version.hybridRecovery)
            throw PinError(
                "Tang server does not support hybrid PQC. "
                "Use clevis-encrypt-tang for classical mode.");

        auto kemJws = tang.fetchKemAdvertisement();
        if (!JoseWrapper::jwsVerify(
                kemJws.get(), verKeys.get(), true))
            throw PinError(
                "KEM advertisement signature verification "
                "failed!");

        auto kemJwks = JoseWrapper::jwsPayload(kemJws.get());
        auto tangKemPub = findKemKey(kemJwks.get());
        if (!tangKemPub)
            throw PinError(
                "No ML-KEM key found in Tang /adv-kem. "
                "Use clevis-encrypt-tang for classical mode.");

        auto plaintext = readStdin();
        auto result = hybridEncrypt(
            tangEcPub.get(), tangKemPub.get(), kid,
            config, jwks.get(), version.tangPub, plaintext);

        OPENSSL_cleanse(&plaintext[0], plaintext.size());

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
