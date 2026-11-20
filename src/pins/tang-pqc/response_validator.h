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

#include <string>

namespace clevis {

// Protocol constants of the hybrid (ECMR + ML-KEM) recovery exchange.
inline constexpr const char* REC_KEM_VERSION = "hybrid-v1";
inline constexpr const char* REC_KEM_SUITE_PREFIX = "ECMR+";
inline constexpr const char* REC_KEM_MSG_DIR_REQUEST = "clevis-to-tang";
inline constexpr const char* REC_KEM_MSG_DIR_RESPONSE = "tang-to-clevis";

// JWE envelope of the hybrid exchange: the key material is sealed
// with a directly held symmetric key. Every JWE clevis builds pins
// these values by construction, and the /rec-kem response is
// validated against them: jose selects its decryption and
// decompression code paths from these header fields, so a response
// must never steer jose_jwe_dec anywhere the request contract does
// not go.
inline constexpr const char* REC_KEM_JWE_ALG = "dir";
inline constexpr const char* REC_KEM_JWE_ENC = "A256GCM";

// Expected values for the /rec-kem response JWE protected header. Every
// value MUST be derived locally by clevis -- from the verified
// advertisement and the keys it selected -- and never taken from stored
// metadata, user input, or server hints.
struct RecKemResponseExpectations {
    std::string ecmrKid; // 'kid': S256 thumbprint of tang's ECMR key
    std::string kemKid;  // 'kem_kid': KEM kid used in the request URL
    std::string kemAlg;  // 'alg' of the verified tang KEM key
};

// Derives the hybrid suite name ("ECMR+" + kemAlg) from the algorithm
// of the tang KEM key selected from the verified advertisement.
std::string deriveRecKemSuite(const std::string& kemAlg);

// Validates the /rec-kem response JWE protected header. Fails closed:
// throws PinError on any missing or malformed protected header, on any
// crit-listed field that does not match the locally derived
// expectations, and -- per RFC 7515 section 4.1.11, enforced
// client-side -- on a 'crit' that is present but not an array of
// strings drawn from the known extension parameters. 'crit' itself is
// optional: only membership is checked, not presence or length. The
// standard JOSE header 'kid' is not an extension parameter and is
// never a valid crit entry. The JWE envelope is pinned to the same
// values clevis pins on its own requests ('alg' = dir, 'enc' =
// A256GCM, no 'zip', empty 'encrypted_key'), closing the
// algorithm-substitution and decompression paths before jose_jwe_dec
// is reached. This MUST be called before the response transport key
// or the recovered key are used in any way.
void validateRecKemResponse(
    const json_t* responseJwe,
    const RecKemResponseExpectations& expected);

} // namespace clevis
