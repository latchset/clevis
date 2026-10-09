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

class KeyDeriver {
public:
    static constexpr const char* LABEL = "NBDE-HYBRID-v1";
    static constexpr const char* VERSION = "\x00\x01";
    static constexpr size_t VERSION_LEN = 2;
    static constexpr const char* SUITE = "ECMR+ML-KEM-768";
    static constexpr size_t OUTPUT_LEN = 32;

    static std::vector<uint8_t> hkdfSha256(
        const std::vector<uint8_t>& ikm,
        const std::vector<uint8_t>& info,
        size_t outputLen = OUTPUT_LEN);

    static std::vector<uint8_t> buildIkm(
        const std::vector<uint8_t>& ecX,
        const std::vector<uint8_t>& kemK);

    static std::vector<uint8_t> buildInfo(
        const std::string& kid,
        const std::string& kemKid);

    static JsonPtr deriveEncKey(
        const std::string& ecXBase64,
        const std::string& kemKBase64,
        const std::string& kid,
        const std::string& kemKid);
};

} // namespace clevis
