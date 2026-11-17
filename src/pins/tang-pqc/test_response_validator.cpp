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

static std::string validProtHeader()
{
    return std::string("{")
        + "\"alg\":\"dir\","
        + "\"enc\":\"A256GCM\","
        + "\"crit\":[\"kem_ver\",\"suite\",\"kid\",\"kem_kid\","
           "\"msg_dir\"],"
        + "\"kem_ver\":\"hybrid-v1\","
        + "\"suite\":\"ECMR+" + KEM_ALG + "\","
        + "\"kid\":\"" + ECMR_KID + "\","
        + "\"kem_kid\":\"" + KEM_KID + "\","
        + "\"msg_dir\":\"tang-to-clevis\""
        + "}";
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

static void testValidResponse()
{
    std::cerr << "== testValidResponse ==\n";
    auto jwe = makeResponseJwe(validProtHeader());
    bool ok = true;
    try {
        validateRecKemResponse(jwe.get(), defaultExpectations());
    } catch (const std::exception& e) {
        std::cerr << "    unexpected error: " << e.what() << "\n";
        ok = false;
    }
    check(ok, "valid response header is accepted");
}

static void testTamperedSuite()
{
    std::cerr << "== testTamperedSuite ==\n";

    // A suite naming a weaker KEM variant (downgrade attempt).
    auto weaker = std::string("{")
        + "\"alg\":\"dir\","
        + "\"enc\":\"A256GCM\","
        + "\"crit\":[\"kem_ver\",\"suite\",\"kid\",\"kem_kid\","
           "\"msg_dir\"],"
        + "\"kem_ver\":\"hybrid-v1\","
        + "\"suite\":\"ECMR+ML-KEM-512\","
        + "\"kid\":\"" + ECMR_KID + "\","
        + "\"kem_kid\":\"" + KEM_KID + "\","
        + "\"msg_dir\":\"tang-to-clevis\""
        + "}";
    check(rejects([&] {
        validateRecKemResponse(
            makeResponseJwe(weaker).get(), defaultExpectations());
    }), "tampered suite (weaker KEM) is rejected");

    // A suite naming a different KEM variant must be rejected too:
    // clevis only accepts the suite it derived locally.
    auto stronger = std::string("{")
        + "\"alg\":\"dir\","
        + "\"enc\":\"A256GCM\","
        + "\"crit\":[\"kem_ver\",\"suite\",\"kid\",\"kem_kid\","
           "\"msg_dir\"],"
        + "\"kem_ver\":\"hybrid-v1\","
        + "\"suite\":\"ECMR+ML-KEM-1024\","
        + "\"kid\":\"" + ECMR_KID + "\","
        + "\"kem_kid\":\"" + KEM_KID + "\","
        + "\"msg_dir\":\"tang-to-clevis\""
        + "}";
    check(rejects([&] {
        validateRecKemResponse(
            makeResponseJwe(stronger).get(), defaultExpectations());
    }), "tampered suite (different KEM) is rejected");

    // A suite that is not an ECMR+ KEM suite at all.
    auto bogus = std::string("{")
        + "\"alg\":\"dir\","
        + "\"enc\":\"A256GCM\","
        + "\"crit\":[\"kem_ver\",\"suite\",\"kid\",\"kem_kid\","
           "\"msg_dir\"],"
        + "\"kem_ver\":\"hybrid-v1\","
        + "\"suite\":\"ECDH+ML-KEM-768\","
        + "\"kid\":\"" + ECMR_KID + "\","
        + "\"kem_kid\":\"" + KEM_KID + "\","
        + "\"msg_dir\":\"tang-to-clevis\""
        + "}";
    check(rejects([&] {
        validateRecKemResponse(
            makeResponseJwe(bogus).get(), defaultExpectations());
    }), "tampered suite (wrong prefix) is rejected");
}

static void testWrongKidEcho()
{
    std::cerr << "== testWrongKidEcho ==\n";
    auto hdr = std::string("{")
        + "\"alg\":\"dir\","
        + "\"enc\":\"A256GCM\","
        + "\"crit\":[\"kem_ver\",\"suite\",\"kid\",\"kem_kid\","
           "\"msg_dir\"],"
        + "\"kem_ver\":\"hybrid-v1\","
        + "\"suite\":\"ECMR+" + KEM_ALG + "\","
        + "\"kid\":\"EVILECMRKIDAAAAAAAAAAAAAAAAAAAA\","
        + "\"kem_kid\":\"" + KEM_KID + "\","
        + "\"msg_dir\":\"tang-to-clevis\""
        + "}";
    check(rejects([&] {
        validateRecKemResponse(
            makeResponseJwe(hdr).get(), defaultExpectations());
    }), "wrong kid echo is rejected");
}

static void testWrongKemKid()
{
    std::cerr << "== testWrongKemKid ==\n";
    auto hdr = std::string("{")
        + "\"alg\":\"dir\","
        + "\"enc\":\"A256GCM\","
        + "\"crit\":[\"kem_ver\",\"suite\",\"kid\",\"kem_kid\","
           "\"msg_dir\"],"
        + "\"kem_ver\":\"hybrid-v1\","
        + "\"suite\":\"ECMR+" + KEM_ALG + "\","
        + "\"kid\":\"" + ECMR_KID + "\","
        + "\"kem_kid\":\"EVILKEMKIDAAAAAAAAAAAAAAAAAAAA\","
        + "\"msg_dir\":\"tang-to-clevis\""
        + "}";
    check(rejects([&] {
        validateRecKemResponse(
            makeResponseJwe(hdr).get(), defaultExpectations());
    }), "wrong kem_kid echo is rejected");
}

static void testWrongMsgDir()
{
    std::cerr << "== testWrongMsgDir ==\n";
    auto hdr = std::string("{")
        + "\"alg\":\"dir\","
        + "\"enc\":\"A256GCM\","
        + "\"crit\":[\"kem_ver\",\"suite\",\"kid\",\"kem_kid\","
           "\"msg_dir\"],"
        + "\"kem_ver\":\"hybrid-v1\","
        + "\"suite\":\"ECMR+" + KEM_ALG + "\","
        + "\"kid\":\"" + ECMR_KID + "\","
        + "\"kem_kid\":\"" + KEM_KID + "\","
        + "\"msg_dir\":\"clevis-to-tang\""
        + "}";
    check(rejects([&] {
        validateRecKemResponse(
            makeResponseJwe(hdr).get(), defaultExpectations());
    }), "wrong msg_dir (reflected request) is rejected");
}

static void testUnknownKemVer()
{
    std::cerr << "== testUnknownKemVer ==\n";
    auto hdr = std::string("{")
        + "\"alg\":\"dir\","
        + "\"enc\":\"A256GCM\","
        + "\"crit\":[\"kem_ver\",\"suite\",\"kid\",\"kem_kid\","
           "\"msg_dir\"],"
        + "\"kem_ver\":\"hybrid-v2\","
        + "\"suite\":\"ECMR+" + KEM_ALG + "\","
        + "\"kid\":\"" + ECMR_KID + "\","
        + "\"kem_kid\":\"" + KEM_KID + "\","
        + "\"msg_dir\":\"tang-to-clevis\""
        + "}";
    check(rejects([&] {
        validateRecKemResponse(
            makeResponseJwe(hdr).get(), defaultExpectations());
    }), "unknown kem_ver is rejected");
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
        std::string hdr = "{\"alg\":\"dir\",\"enc\":\"A256GCM\","
                          "\"crit\":[\"kem_ver\",\"suite\",\"kid\","
                          "\"kem_kid\",\"msg_dir\"]";
        if (std::strcmp(c.first, "kem_ver") != 0)
            hdr += ",\"kem_ver\":\"hybrid-v1\"";
        if (std::strcmp(c.first, "suite") != 0)
            hdr += ",\"suite\":\"ECMR+" + KEM_ALG + "\"";
        if (std::strcmp(c.first, "kid") != 0)
            hdr += ",\"kid\":\"" + ECMR_KID + "\"";
        if (std::strcmp(c.first, "kem_kid") != 0)
            hdr += ",\"kem_kid\":\"" + KEM_KID + "\"";
        if (std::strcmp(c.first, "msg_dir") != 0)
            hdr += ",\"msg_dir\":\"tang-to-clevis\"";
        hdr += "}";

        check(rejects([&] {
            validateRecKemResponse(
                makeResponseJwe(hdr).get(),
                defaultExpectations());
        }), c.second);
    }
}

static void testCritValidation()
{
    std::cerr << "== testCritValidation ==\n";
    // Missing crit entirely.
    auto noCrit = std::string("{")
        + "\"alg\":\"dir\","
        + "\"enc\":\"A256GCM\","
        + "\"kem_ver\":\"hybrid-v1\","
        + "\"suite\":\"ECMR+" + KEM_ALG + "\","
        + "\"kid\":\"" + ECMR_KID + "\","
        + "\"kem_kid\":\"" + KEM_KID + "\","
        + "\"msg_dir\":\"tang-to-clevis\""
        + "}";
    check(rejects([&] {
        validateRecKemResponse(
            makeResponseJwe(noCrit).get(), defaultExpectations());
    }), "missing crit is rejected");

    // crit is not an array.
    auto notArray = std::string("{")
        + "\"alg\":\"dir\","
        + "\"enc\":\"A256GCM\","
        + "\"crit\":\"kem_ver\","
        + "\"kem_ver\":\"hybrid-v1\","
        + "\"suite\":\"ECMR+" + KEM_ALG + "\","
        + "\"kid\":\"" + ECMR_KID + "\","
        + "\"kem_kid\":\"" + KEM_KID + "\","
        + "\"msg_dir\":\"tang-to-clevis\""
        + "}";
    check(rejects([&] {
        validateRecKemResponse(
            makeResponseJwe(notArray).get(), defaultExpectations());
    }), "crit that is not an array is rejected");

    // crit is missing one required entry.
    auto missingEntry = std::string("{")
        + "\"alg\":\"dir\","
        + "\"enc\":\"A256GCM\","
        + "\"crit\":[\"kem_ver\",\"suite\",\"kid\",\"msg_dir\"],"
        + "\"kem_ver\":\"hybrid-v1\","
        + "\"suite\":\"ECMR+" + KEM_ALG + "\","
        + "\"kid\":\"" + ECMR_KID + "\","
        + "\"kem_kid\":\"" + KEM_KID + "\","
        + "\"msg_dir\":\"tang-to-clevis\""
        + "}";
    check(rejects([&] {
        validateRecKemResponse(
            makeResponseJwe(missingEntry).get(),
            defaultExpectations());
    }), "crit missing 'kem_kid' is rejected");

    // crit carries an entry clevis does not understand.
    auto unknownEntry = std::string("{")
        + "\"alg\":\"dir\","
        + "\"enc\":\"A256GCM\","
        + "\"crit\":[\"kem_ver\",\"suite\",\"kid\",\"kem_kid\","
           "\"msg_dir\",\"req_digest\"],"
        + "\"kem_ver\":\"hybrid-v1\","
        + "\"suite\":\"ECMR+" + KEM_ALG + "\","
        + "\"kid\":\"" + ECMR_KID + "\","
        + "\"kem_kid\":\"" + KEM_KID + "\","
        + "\"msg_dir\":\"tang-to-clevis\""
        + "}";
    check(rejects([&] {
        validateRecKemResponse(
            makeResponseJwe(unknownEntry).get(),
            defaultExpectations());
    }), "non-understood crit entry is rejected");

    // crit carries a non-string entry.
    auto nonStringEntry = std::string("{")
        + "\"alg\":\"dir\","
        + "\"enc\":\"A256GCM\","
        + "\"crit\":[\"kem_ver\",\"suite\",\"kid\",\"kem_kid\","
           "\"msg_dir\",42],"
        + "\"kem_ver\":\"hybrid-v1\","
        + "\"suite\":\"ECMR+" + KEM_ALG + "\","
        + "\"kid\":\"" + ECMR_KID + "\","
        + "\"kem_kid\":\"" + KEM_KID + "\","
        + "\"msg_dir\":\"tang-to-clevis\""
        + "}";
    check(rejects([&] {
        validateRecKemResponse(
            makeResponseJwe(nonStringEntry).get(),
            defaultExpectations());
    }), "non-string crit entry is rejected");
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
