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
#include "jose_types.h"

#include <cstring>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

using namespace clevis;

static int failures = 0;

static void check(bool cond, const char* name)
{
    if (cond) {
        std::cerr << "  PASS: " << name << "\n";
    } else {
        std::cerr << "  FAIL: " << name << "\n";
        ++failures;
    }
}

static const std::string ECMR_KID = "ECMRKIDAAAAAAAAAAAAAAAAAAAAAAAA";
static const std::string KEM_KID = "KEMKIDAAAAAAAAAAAAAAAAAAAAAAAAAA";
static const std::string KEM_ALG = "ML-KEM-768";

// The crit list tang emits: exactly the four extension parameters.
// The standard JOSE header 'kid' is never crit'd.
static const std::string CRIT_KNOWN =
    "[\"kem_ver\",\"suite\",\"kem_kid\",\"msg_dir\"]";

static RecKemResponseExpectations defaultExpectations()
{
    RecKemResponseExpectations exp;
    exp.ecmrKid = ECMR_KID;
    exp.kemKid = KEM_KID;
    exp.kemAlg = KEM_ALG;
    return exp;
}

// Builds a response JWE whose protected header is the base64url
// encoding of protJson.
static JsonPtr makeResponseJwe(const std::string& protJson)
{
    std::vector<uint8_t> bytes(protJson.begin(), protJson.end());
    auto protB64 = JoseWrapper::base64UrlEncode(bytes);
    return makeJsonPtr(json_pack(
        "{s:s, s:s, s:s, s:s, s:s}",
        "protected", protB64.c_str(),
        "encrypted_key", "",
        "iv", "",
        "ciphertext", "",
        "tag", ""));
}

// Builds a response protected header. Empty override values remove the
// field; crit is raw JSON ("" removes it, "[]" is an empty array).
static std::string makeProtHeader(
    const std::string& crit = CRIT_KNOWN,
    const std::string& kemVer = "hybrid-v1",
    const std::string& suite = "ECMR+" + KEM_ALG,
    const std::string& kid = ECMR_KID,
    const std::string& kemKid = KEM_KID,
    const std::string& msgDir = "tang-to-clevis")
{
    std::string hdr = "{\"alg\":\"dir\",\"enc\":\"A256GCM\"";
    if (!crit.empty())
        hdr += ",\"crit\":" + crit;
    if (!kemVer.empty())
        hdr += ",\"kem_ver\":\"" + kemVer + "\"";
    if (!suite.empty())
        hdr += ",\"suite\":\"" + suite + "\"";
    if (!kid.empty())
        hdr += ",\"kid\":\"" + kid + "\"";
    if (!kemKid.empty())
        hdr += ",\"kem_kid\":\"" + kemKid + "\"";
    if (!msgDir.empty())
        hdr += ",\"msg_dir\":\"" + msgDir + "\"";
    return hdr + "}";
}

template<typename Fn>
static bool rejects(Fn&& fn)
{
    try {
        fn();
    } catch (const PinError&) {
        return true;
    } catch (...) {
        return false;
    }
    return false;
}

static void checkAccepts(const std::string& hdrJson, const char* name)
{
    bool ok = true;
    try {
        validateRecKemResponse(
            makeResponseJwe(hdrJson).get(), defaultExpectations());
    } catch (const std::exception& e) {
        std::cerr << "    unexpected error: " << e.what() << "\n";
        ok = false;
    }
    check(ok, name);
}

static void checkRejects(const std::string& hdrJson, const char* name)
{
    check(rejects([&] {
        validateRecKemResponse(
            makeResponseJwe(hdrJson).get(), defaultExpectations());
    }), name);
}

static void testValidResponse()
{
    std::cerr << "== testValidResponse ==\n";
    checkAccepts(makeProtHeader(),
                 "valid response header (4-entry crit) is accepted");
    checkAccepts(makeProtHeader(""),
                 "response without crit is accepted");
    checkAccepts(makeProtHeader("[]"),
                 "response with empty crit is accepted");
    checkAccepts(makeProtHeader("[\"kem_ver\"]"),
                 "response with partial crit is accepted");
    checkAccepts(makeProtHeader("[\"msg_dir\",\"suite\"]"),
                 "response with reordered partial crit is accepted");
}

static void testTamperedSuite()
{
    std::cerr << "== testTamperedSuite ==\n";
    checkRejects(makeProtHeader(CRIT_KNOWN, "hybrid-v1",
                                "ECMR+ML-KEM-512"),
                 "tampered suite (weaker KEM) is rejected");
    checkRejects(makeProtHeader(CRIT_KNOWN, "hybrid-v1",
                                "ECMR+ML-KEM-1024"),
                 "tampered suite (different KEM) is rejected");
    checkRejects(makeProtHeader(CRIT_KNOWN, "hybrid-v1",
                                "ECDH+ML-KEM-768"),
                 "tampered suite (wrong prefix) is rejected");
}

static void testWrongKidEcho()
{
    std::cerr << "== testWrongKidEcho ==\n";
    checkRejects(makeProtHeader(CRIT_KNOWN, "hybrid-v1",
                                "ECMR+" + KEM_ALG,
                                "EVILECMRKIDAAAAAAAAAAAAAAAAAAAA"),
                 "wrong kid echo is rejected");
}

static void testWrongKemKid()
{
    std::cerr << "== testWrongKemKid ==\n";
    checkRejects(makeProtHeader(CRIT_KNOWN, "hybrid-v1",
                                "ECMR+" + KEM_ALG, ECMR_KID,
                                "EVILKEMKIDAAAAAAAAAAAAAAAAAAAA"),
                 "wrong kem_kid echo is rejected");
}

static void testWrongMsgDir()
{
    std::cerr << "== testWrongMsgDir ==\n";
    checkRejects(makeProtHeader(CRIT_KNOWN, "hybrid-v1",
                                "ECMR+" + KEM_ALG, ECMR_KID, KEM_KID,
                                "clevis-to-tang"),
                 "wrong msg_dir (reflected request) is rejected");
}

static void testUnknownKemVer()
{
    std::cerr << "== testUnknownKemVer ==\n";
    checkRejects(makeProtHeader(CRIT_KNOWN, "hybrid-v2"),
                 "unknown kem_ver is rejected");
}

static void testMissingFields()
{
    std::cerr << "== testMissingFields ==\n";

    // (field to omit, name of the check)
    const std::pair<const char*, const char*> cases[] = {
        {"kem_ver", "missing 'kem_ver' is rejected"},
        {"suite", "missing 'suite' is rejected"},
        {"kid", "missing 'kid' is rejected"},
        {"kem_kid", "missing 'kem_kid' is rejected"},
        {"msg_dir", "missing 'msg_dir' is rejected"},
    };

    for (const auto& c : cases) {
        std::string hdr;
        if (std::strcmp(c.first, "kem_ver") == 0)
            hdr = makeProtHeader(CRIT_KNOWN, "");
        else if (std::strcmp(c.first, "suite") == 0)
            hdr = makeProtHeader(CRIT_KNOWN, "hybrid-v1", "");
        else if (std::strcmp(c.first, "kid") == 0)
            hdr = makeProtHeader(CRIT_KNOWN, "hybrid-v1",
                                 "ECMR+" + KEM_ALG, "");
        else if (std::strcmp(c.first, "kem_kid") == 0)
            hdr = makeProtHeader(CRIT_KNOWN, "hybrid-v1",
                                 "ECMR+" + KEM_ALG, ECMR_KID, "");
        else
            hdr = makeProtHeader(CRIT_KNOWN, "hybrid-v1",
                                 "ECMR+" + KEM_ALG, ECMR_KID, KEM_KID,
                                 "");
        checkRejects(hdr, c.second);
    }
}

static void testCritValidation()
{
    std::cerr << "== testCritValidation ==\n";

    // RFC 7515 section 4.1.11, enforced client-side: 'kid' is a
    // standard JOSE header, not an extension parameter, so critting it
    // is a protocol violation.
    checkRejects(
        makeProtHeader("[\"kem_ver\",\"suite\",\"kid\",\"kem_kid\","
                       "\"msg_dir\"]"),
        "crit containing the standard 'kid' header is rejected");

    // Any unknown extension parameter must be rejected.
    checkRejects(makeProtHeader("[\"evil\"]"),
                 "non-understood crit entry is rejected");
    checkRejects(makeProtHeader("[\"kem_ver\",\"req_digest\"]"),
                 "legacy crit entry (req_digest) is rejected");

    // crit must be an array of strings when present.
    checkRejects(makeProtHeader("\"kem_ver\""),
                 "crit that is not an array is rejected");
    checkRejects(makeProtHeader("[\"kem_ver\",42]"),
                 "non-string crit entry is rejected");
    checkRejects(makeProtHeader("[\"kem_ver\",null]"),
                 "null crit entry is rejected");
}

static void testMalformedResponses()
{
    std::cerr << "== testMalformedResponses ==\n";
    check(rejects([&] {
        validateRecKemResponse(nullptr, defaultExpectations());
    }), "null response is rejected");

    check(rejects([&] {
        validateRecKemResponse(
            makeJsonPtr(json_object()).get(),
            defaultExpectations());
    }), "response without protected header is rejected");

    check(rejects([&] {
        validateRecKemResponse(
            makeResponseJwe("not json at all").get(),
            defaultExpectations());
    }), "protected header that is not JSON is rejected");

    check(rejects([&] {
        validateRecKemResponse(
            makeResponseJwe("[1,2,3]").get(),
            defaultExpectations());
    }), "protected header that is not an object is rejected");

    check(rejects([&] {
        validateRecKemResponse(
            makeJsonPtr(json_pack(
                "{s:s}", "protected", "!!!not-base64url!!!")).get(),
            defaultExpectations());
    }), "protected header that is not base64url is rejected");
}

static void testDeriveSuite()
{
    std::cerr << "== testDeriveSuite ==\n";
    check(deriveRecKemSuite("ML-KEM-512") == "ECMR+ML-KEM-512",
          "suite for ML-KEM-512");
    check(deriveRecKemSuite("ML-KEM-768") == "ECMR+ML-KEM-768",
          "suite for ML-KEM-768");
    check(deriveRecKemSuite("ML-KEM-1024") == "ECMR+ML-KEM-1024",
          "suite for ML-KEM-1024");
}

int main()
{
    testValidResponse();
    testTamperedSuite();
    testWrongKidEcho();
    testWrongKemKid();
    testWrongMsgDir();
    testUnknownKemVer();
    testMissingFields();
    testCritValidation();
    testMalformedResponses();
    testDeriveSuite();

    if (failures > 0) {
        std::cerr << failures << " test(s) failed\n";
        return 1;
    }
    std::cerr << "All tests passed\n";
    return 0;
}
