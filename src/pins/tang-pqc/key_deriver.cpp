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

#include "key_deriver.h"
#include "jose_wrapper.h"

extern "C" {
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
}

#include <cstring>

namespace clevis {

namespace {

struct EvpKdfDeleter {
    void operator()(EVP_KDF* k) const noexcept { EVP_KDF_free(k); }
};

struct EvpKdfCtxDeleter {
    void operator()(EVP_KDF_CTX* c) const noexcept { EVP_KDF_CTX_free(c); }
};

using EvpKdfPtr = std::unique_ptr<EVP_KDF, EvpKdfDeleter>;
using EvpKdfCtxPtr = std::unique_ptr<EVP_KDF_CTX, EvpKdfCtxDeleter>;

void appendUint32BE(std::vector<uint8_t>& out, uint32_t val)
{
    out.push_back(static_cast<uint8_t>((val >> 24) & 0xFF));
    out.push_back(static_cast<uint8_t>((val >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((val >>  8) & 0xFF));
    out.push_back(static_cast<uint8_t>((val      ) & 0xFF));
}

} // anonymous namespace

std::vector<uint8_t> KeyDeriver::hkdfSha256(
    const std::vector<uint8_t>& ikm,
    const std::vector<uint8_t>& info,
    size_t outputLen)
{
    EvpKdfPtr kdf(EVP_KDF_fetch(nullptr, "HKDF", nullptr));
    if (!kdf)
        throw PinError("Failed to fetch HKDF algorithm");

    EvpKdfCtxPtr ctx(EVP_KDF_CTX_new(kdf.get()));
    if (!ctx)
        throw PinError("Failed to create HKDF context");

    int mode = EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;
    const char* digest = "SHA256";

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_int(
            OSSL_KDF_PARAM_MODE, &mode),
        OSSL_PARAM_construct_utf8_string(
            OSSL_KDF_PARAM_DIGEST,
            const_cast<char*>(digest), 0),
        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_KEY,
            const_cast<uint8_t*>(ikm.data()), ikm.size()),
        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_INFO,
            const_cast<uint8_t*>(info.data()), info.size()),
        OSSL_PARAM_construct_end()
    };

    std::vector<uint8_t> output(outputLen);
    if (EVP_KDF_derive(ctx.get(), output.data(), outputLen, params) <= 0)
        throw PinError("HKDF derivation failed");

    return output;
}

std::vector<uint8_t> KeyDeriver::buildIkm(
    const std::vector<uint8_t>& ecX,
    const std::vector<uint8_t>& kemK)
{
    std::vector<uint8_t> ikm;
    ikm.reserve(8 + ecX.size() + kemK.size());
    appendUint32BE(ikm, static_cast<uint32_t>(ecX.size()));
    ikm.insert(ikm.end(), ecX.begin(), ecX.end());
    appendUint32BE(ikm, static_cast<uint32_t>(kemK.size()));
    ikm.insert(ikm.end(), kemK.begin(), kemK.end());
    return ikm;
}

std::vector<uint8_t> KeyDeriver::buildInfo(
    const std::string& kid, const std::string& kemKid)
{
    std::vector<uint8_t> info;
    auto labelLen = std::strlen(LABEL);
    auto suiteLen = std::strlen(SUITE);
    info.reserve(labelLen + VERSION_LEN + suiteLen
                 + kid.size() + kemKid.size());

    info.insert(info.end(), LABEL, LABEL + labelLen);
    info.insert(info.end(), VERSION, VERSION + VERSION_LEN);
    info.insert(info.end(), SUITE, SUITE + suiteLen);
    info.insert(info.end(), kid.begin(), kid.end());
    info.insert(info.end(), kemKid.begin(), kemKid.end());
    return info;
}

JsonPtr KeyDeriver::deriveEncKey(
    const std::string& ecXBase64,
    const std::string& kemKBase64,
    const std::string& kid,
    const std::string& kemKid)
{
    auto ecXBytes = JoseWrapper::base64UrlDecode(ecXBase64);
    auto kemKBytes = JoseWrapper::base64UrlDecode(kemKBase64);

    auto ikm = buildIkm(ecXBytes, kemKBytes);
    OPENSSL_cleanse(ecXBytes.data(), ecXBytes.size());
    OPENSSL_cleanse(kemKBytes.data(), kemKBytes.size());
    auto info = buildInfo(kid, kemKid);
    auto derived = hkdfSha256(ikm, info);

    OPENSSL_cleanse(ikm.data(), ikm.size());

    auto kBase64 = JoseWrapper::base64UrlEncode(derived);
    OPENSSL_cleanse(derived.data(), derived.size());

    std::string keyJson = "{\"alg\":\"A256GCM\",\"k\":\"" + kBase64
                        + "\",\"kty\":\"oct\"}";
    OPENSSL_cleanse(&kBase64[0], kBase64.size());
    auto key = jsonParse(keyJson);
    OPENSSL_cleanse(&keyJson[0], keyJson.size());
    return key;
}

} // namespace clevis
