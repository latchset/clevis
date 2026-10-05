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

#include "jose_wrapper.h"

extern "C" {
#include <jose/jose.h>
#include <jose/b64.h>
#include <jose/jwe.h>
#include <jose/jwk.h>
#include <jose/jws.h>
}

#include <cstring>

namespace clevis {

JsonPtr JoseWrapper::generateKey(const std::string& spec)
{
    auto jwk = jsonParse(spec);
    if (!jose_jwk_gen(nullptr, jwk.get()))
        throw PinError("Failed to generate JWK");
    return jwk;
}

JsonPtr JoseWrapper::publicKey(const json_t* key)
{
    auto pub = jsonDeepCopy(key);
    if (!jose_jwk_pub(nullptr, pub.get()))
        throw PinError("Failed to extract public key");
    return pub;
}

JsonPtr JoseWrapper::keyExchange(const json_t* local, const json_t* remote)
{
    auto result = jose_jwk_exc(nullptr, local, remote);
    if (!result)
        throw PinError("ECDH key exchange failed");
    return makeJsonPtr(result);
}

JsonPtr JoseWrapper::ecmrExchange(const json_t* local, const json_t* remote)
{
    auto localCopy = jsonDeepCopy(local);
    json_object_set_new(localCopy.get(), "alg", json_string("ECMR"));
    auto result = jose_jwk_exc(nullptr, localCopy.get(), remote);
    if (!result)
        throw PinError("ECMR exchange failed");
    return makeJsonPtr(result);
}

JoseWrapper::EncapResult JoseWrapper::encapsulate(const json_t* pub)
{
    auto result = jose_jwk_kem_enc(nullptr, pub);
    if (!result)
        throw PinError("KEM encapsulation failed");

    auto resultPtr = makeJsonPtr(result);

    auto ctVal = json_string_value(json_object_get(result, "ct"));
    if (!ctVal)
        throw PinError("KEM encapsulation: missing ct");

    auto ss = json_object_get(result, "ss");
    if (!ss)
        throw PinError("KEM encapsulation: missing ss");

    return {std::string(ctVal), jsonDeepCopy(ss)};
}

JsonPtr JoseWrapper::decapsulate(
    const json_t* priv, const std::string& ct)
{
    auto ctJson = makeJsonPtr(json_string(ct.c_str()));
    auto ss = jose_jwk_kem_dec(nullptr, priv, ctJson.get());
    if (!ss)
        throw PinError("KEM decapsulation failed");
    return makeJsonPtr(ss);
}

std::string JoseWrapper::thumbprint(
    const json_t* key, const std::string& alg)
{
    size_t hashLen = jose_jwk_thp_buf(
        nullptr, nullptr, alg.c_str(), nullptr, 0);
    if (hashLen == SIZE_MAX)
        throw PinError("Failed to determine thumbprint size");

    std::vector<uint8_t> hashBuf(hashLen);
    if (!jose_jwk_thp_buf(
            nullptr, key, alg.c_str(), hashBuf.data(), hashLen))
        throw PinError("Failed to compute thumbprint hash");

    size_t b64Len = jose_b64_enc_buf(
        nullptr, hashLen, nullptr, 0);
    if (b64Len == SIZE_MAX)
        throw PinError("Failed to determine base64url size");

    std::string result(b64Len, '\0');
    if (jose_b64_enc_buf(
            hashBuf.data(), hashLen, &result[0], b64Len) != b64Len)
        throw PinError("Failed to base64url-encode thumbprint");

    return result;
}

bool JoseWrapper::thumbprintMatch(
    const json_t* keys, const std::string& thp, const std::string& alg)
{
    if (!json_is_array(keys) && !json_is_object(keys))
        return false;

    auto keysArray = json_is_array(keys) ? keys
        : json_object_get(keys, "keys");
    if (!keysArray)
        keysArray = keys;

    if (json_is_object(keysArray)) {
        auto computed = thumbprint(keysArray, alg);
        return computed == thp;
    }

    size_t idx;
    json_t* key;
    json_array_foreach(keysArray, idx, key) {
        try {
            if (thumbprint(key, alg) == thp)
                return true;
        } catch (...) {
            continue;
        }
    }
    return false;
}

std::string JoseWrapper::base64UrlEncode(
    const uint8_t* data, size_t len)
{
    auto b64 = jose_b64_enc(data, len);
    if (!b64)
        throw PinError("base64url encoding failed");
    auto b64Ptr = makeJsonPtr(b64);
    return json_string_value(b64);
}

std::string JoseWrapper::base64UrlEncode(
    const std::vector<uint8_t>& data)
{
    return base64UrlEncode(data.data(), data.size());
}

std::vector<uint8_t> JoseWrapper::base64UrlDecode(const std::string& encoded)
{
    auto b64Json = makeJsonPtr(json_string(encoded.c_str()));

    size_t len = jose_b64_dec(b64Json.get(), nullptr, 0);
    if (len == SIZE_MAX || len == 0)
        throw PinError("base64url decoding: failed to determine size");

    std::vector<uint8_t> buf(len);
    if (jose_b64_dec(b64Json.get(), buf.data(), len) != len)
        throw PinError("base64url decoding failed");

    return buf;
}

bool JoseWrapper::jweEncrypt(
    json_t* jwe, const json_t* key,
    const void* plaintext, size_t plaintextLen)
{
    return jose_jwe_enc(nullptr, jwe, nullptr, key, plaintext, plaintextLen);
}

std::vector<uint8_t> JoseWrapper::jweDecrypt(
    const json_t* jwe, const json_t* key)
{
    size_t ptLen = 0;
    auto pt = jose_jwe_dec(nullptr, jwe, nullptr, key, &ptLen);
    if (!pt)
        throw PinError("JWE decryption failed");
    BufferPtr guard(pt);
    auto bytes = static_cast<uint8_t*>(pt);
    return std::vector<uint8_t>(bytes, bytes + ptLen);
}

bool JoseWrapper::jwsVerify(
    const json_t* jws, const json_t* keys, bool allSignatures)
{
    return jose_jws_ver(nullptr, jws, nullptr, keys, allSignatures);
}

JsonPtr JoseWrapper::filterKeysByUse(
    const json_t* keys, const std::string& use)
{
    auto filtered = makeJsonPtr(json_array());

    auto keysObj = const_cast<json_t*>(keys);
    auto keysArray = json_object_get(keysObj, "keys");
    if (!keysArray)
        keysArray = keysObj;

    if (json_is_object(keysArray)) {
        if (jose_jwk_prm(nullptr, keysArray, false, use.c_str()))
            json_array_append(filtered.get(), keysArray);
        return filtered;
    }

    size_t idx;
    json_t* key;
    json_array_foreach(keysArray, idx, key) {
        if (jose_jwk_prm(nullptr, key, false, use.c_str()))
            json_array_append(filtered.get(), key);
    }
    return filtered;
}

std::string JoseWrapper::jweToCompact(const json_t* jwe)
{
    auto prot = json_string_value(
        json_object_get(jwe, "protected"));
    auto ekey = json_string_value(
        json_object_get(jwe, "encrypted_key"));
    auto iv   = json_string_value(json_object_get(jwe, "iv"));
    auto ct   = json_string_value(json_object_get(jwe, "ciphertext"));
    auto tag  = json_string_value(json_object_get(jwe, "tag"));

    if (!prot || !iv || !ct || !tag)
        throw PinError("JWE missing required fields for compact format");
    if (!ekey)
        ekey = "";

    std::string result;
    result.reserve(std::strlen(prot) + std::strlen(ekey)
        + std::strlen(iv) + std::strlen(ct) + std::strlen(tag) + 4);
    result += prot;
    result += '.';
    result += ekey;
    result += '.';
    result += iv;
    result += '.';
    result += ct;
    result += '.';
    result += tag;
    return result;
}

JsonPtr JoseWrapper::jweFromCompact(const std::string& compact)
{
    size_t dots[4];
    int n = 0;
    for (size_t i = 0; i < compact.size() && n < 4; ++i) {
        if (compact[i] == '.')
            dots[n++] = i;
    }
    if (n != 4)
        throw PinError("Invalid compact JWE: expected 4 dots");

    auto jwe = makeJsonPtr(json_object());
    json_object_set_new(jwe.get(), "protected",
        json_stringn(compact.c_str(), dots[0]));
    json_object_set_new(jwe.get(), "encrypted_key",
        json_stringn(compact.c_str() + dots[0] + 1,
                     dots[1] - dots[0] - 1));
    json_object_set_new(jwe.get(), "iv",
        json_stringn(compact.c_str() + dots[1] + 1,
                     dots[2] - dots[1] - 1));
    json_object_set_new(jwe.get(), "ciphertext",
        json_stringn(compact.c_str() + dots[2] + 1,
                     dots[3] - dots[2] - 1));
    json_object_set_new(jwe.get(), "tag",
        json_string(compact.c_str() + dots[3] + 1));
    return jwe;
}

JsonPtr JoseWrapper::jwsPayload(const json_t* jws)
{
    auto payloadB64 = json_string_value(
        json_object_get(jws, "payload"));
    if (!payloadB64)
        throw PinError("JWS missing payload");

    auto b64Json = makeJsonPtr(json_string(payloadB64));

    size_t len = jose_b64_dec(b64Json.get(), nullptr, 0);
    if (len == SIZE_MAX || len == 0)
        throw PinError("Failed to determine JWS payload size");

    std::vector<uint8_t> buf(len);
    if (jose_b64_dec(b64Json.get(), buf.data(), len) != len)
        throw PinError("Failed to decode JWS payload");

    auto payload = json_loadb(
        reinterpret_cast<const char*>(buf.data()), len, 0, nullptr);
    if (!payload)
        throw PinError("JWS payload is not valid JSON");
    return makeJsonPtr(payload);
}

} // namespace clevis
