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

#pragma once

#include "jose_types.h"

#include <cstdint>
#include <string>
#include <vector>

namespace clevis {

class JoseWrapper {
public:
    static JsonPtr generateKey(const std::string& spec);
    static JsonPtr publicKey(const json_t* key);
    static JsonPtr keyExchange(const json_t* local, const json_t* remote);
    static JsonPtr ecmrExchange(const json_t* local, const json_t* remote);

    struct EncapResult {
        std::string ct;
        JsonPtr sharedSecret;
    };

    static EncapResult encapsulate(const json_t* pub);
    static JsonPtr decapsulate(const json_t* priv, const std::string& ct);

    static std::string thumbprint(
        const json_t* key, const std::string& alg = "S256");
    static bool thumbprintMatch(
        const json_t* keys, const std::string& thp,
        const std::string& alg = "S256");

    static std::string base64UrlEncode(
        const uint8_t* data, size_t len);
    static std::string base64UrlEncode(
        const std::vector<uint8_t>& data);
    static std::vector<uint8_t> base64UrlDecode(const std::string& encoded);

    static bool jweEncrypt(
        json_t* jwe, const json_t* key,
        const void* plaintext, size_t plaintextLen);
    static std::vector<uint8_t> jweDecrypt(
        const json_t* jwe, const json_t* key);

    static bool jwsVerify(
        const json_t* jws, const json_t* keys, bool allSignatures);
    static JsonPtr filterKeysByUse(
        const json_t* keys, const std::string& use);

    static std::string jweToCompact(const json_t* jwe);
    static JsonPtr jweFromCompact(const std::string& compact);

    static JsonPtr jwsPayload(const json_t* jws);
};

} // namespace clevis
