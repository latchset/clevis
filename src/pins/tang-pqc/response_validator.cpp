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

#include "response_validator.h"
#include "jose_wrapper.h"

#include <array>
#include <cstring>

namespace clevis {

namespace {

// The extension parameters clevis understands as crit entries
// (RFC 7515 section 4.1.11). The standard JOSE header 'kid' is NOT an
// extension parameter and is therefore not a valid crit entry. A
// response carrying any crit entry outside this list MUST be rejected:
// clevis cannot know which semantics the server attached to it.
constexpr std::array<const char*, 4> KNOWN_CRIT_FIELDS = {{
    "kem_ver", "suite", "kem_kid", "msg_dir"
}};

void validateCritEntries(const json_t* hdr)
{
    // 'crit' is optional: only membership in the known extension set is
    // enforced, not presence, completeness, or length.
    auto crit = json_object_get(hdr, "crit");
    if (!crit)
        return;

    if (!json_is_array(crit))
        throw PinError(
            "Rec-kem response: 'crit' must be an array");

    size_t idx;
    json_t* val;
    json_array_foreach(crit, idx, val) {
        auto entry = json_string_value(val);
        if (!entry)
            throw PinError(
                "Rec-kem response: 'crit' contains a non-string entry");

        bool known = false;
        for (auto field : KNOWN_CRIT_FIELDS) {
            if (std::strcmp(entry, field) == 0) {
                known = true;
                break;
            }
        }
        if (!known)
            throw PinError(
                std::string("Rec-kem response: non-understood 'crit' "
                            "entry: '") + entry + "'");
    }
}

void validateStringField(
    const json_t* hdr, const char* field, const std::string& expected)
{
    auto val = json_string_value(json_object_get(hdr, field));
    if (!val)
        throw PinError(
            std::string("Rec-kem response: missing '") + field + "'");

    if (expected != val)
        throw PinError(
            std::string("Rec-kem response: '") + field
            + "' mismatch: expected '" + expected + "', got '" + val
            + "' (possible downgrade or MITM attack)");
}

} // anonymous namespace

std::string deriveRecKemSuite(const std::string& kemAlg)
{
    return std::string(REC_KEM_SUITE_PREFIX) + kemAlg;
}

void validateRecKemResponse(
    const json_t* responseJwe,
    const RecKemResponseExpectations& expected)
{
    if (!responseJwe || !json_is_object(responseJwe))
        throw PinError("Rec-kem response: missing JWE object");

    auto protB64 = json_string_value(
        json_object_get(responseJwe, "protected"));
    if (!protB64)
        throw PinError("Rec-kem response: missing protected header");

    auto protBytes = JoseWrapper::base64UrlDecode(protB64);
    JsonPtr hdr;
    try {
        hdr = jsonParse(
            std::string(protBytes.begin(), protBytes.end()));
    } catch (const std::exception&) {
        throw PinError(
            "Rec-kem response: protected header is not valid JSON");
    }
    if (!json_is_object(hdr.get()))
        throw PinError(
            "Rec-kem response: protected header is not a JSON object");

    validateCritEntries(hdr.get());
    validateStringField(hdr.get(), "kem_ver", REC_KEM_VERSION);
    validateStringField(
        hdr.get(), "suite", deriveRecKemSuite(expected.kemAlg));
    validateStringField(
        hdr.get(), "msg_dir", REC_KEM_MSG_DIR_RESPONSE);
    validateStringField(hdr.get(), "kid", expected.ecmrKid);
    validateStringField(hdr.get(), "kem_kid", expected.kemKid);
}

} // namespace clevis
