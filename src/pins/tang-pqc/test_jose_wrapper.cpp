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
#include "jose_types.h"

#include <cassert>
#include <cstring>
#include <iostream>
#include <string>
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

static void testGenerateEcKey()
{
    std::cerr << "== testGenerateEcKey ==\n";
    auto key = JoseWrapper::generateKey(
        "{\"alg\":\"ECMR\",\"crv\":\"P-256\"}");
    check(key != nullptr, "key generated");

    auto kty = json_string_value(json_object_get(key.get(), "kty"));
    check(kty && std::strcmp(kty, "EC") == 0, "kty is EC");

    auto crv = json_string_value(json_object_get(key.get(), "crv"));
    check(crv && std::strcmp(crv, "P-256") == 0, "crv is P-256");

    auto d = json_object_get(key.get(), "d");
    check(d != nullptr, "private key component present");
}

static void testPublicKey()
{
    std::cerr << "== testPublicKey ==\n";
    auto key = JoseWrapper::generateKey(
        "{\"alg\":\"ECMR\",\"crv\":\"P-256\"}");
    auto pub = JoseWrapper::publicKey(key.get());

    check(pub != nullptr, "public key extracted");

    auto d = json_object_get(pub.get(), "d");
    check(d == nullptr, "private component stripped");

    auto x = json_string_value(json_object_get(pub.get(), "x"));
    check(x != nullptr, "x coordinate present");

    auto y = json_string_value(json_object_get(pub.get(), "y"));
    check(y != nullptr, "y coordinate present");
}

static void testKeyExchange()
{
    std::cerr << "== testKeyExchange ==\n";
    auto keyA = JoseWrapper::generateKey(
        "{\"alg\":\"ECMR\",\"crv\":\"P-256\"}");
    auto keyB = JoseWrapper::generateKey(
        "{\"alg\":\"ECMR\",\"crv\":\"P-256\"}");
    auto pubB = JoseWrapper::publicKey(keyB.get());

    auto result = JoseWrapper::keyExchange(keyA.get(), pubB.get());
    check(result != nullptr, "ECDH succeeds");

    auto x = json_string_value(json_object_get(result.get(), "x"));
    check(x != nullptr, "result has x coordinate");
}

static void testKemRoundTrip()
{
    std::cerr << "== testKemRoundTrip ==\n";
    auto kemKey = JoseWrapper::generateKey(
        "{\"alg\":\"ML-KEM-768\"}");
    check(kemKey != nullptr, "KEM key generated");

    auto kemPub = JoseWrapper::publicKey(kemKey.get());
    check(kemPub != nullptr, "KEM public key extracted");

    auto [ct, ss] = JoseWrapper::encapsulate(kemPub.get());
    check(!ct.empty(), "ciphertext produced");
    check(ss != nullptr, "shared secret produced");

    auto ssK = json_string_value(json_object_get(ss.get(), "k"));
    check(ssK != nullptr, "shared secret has k field");

    auto recovered = JoseWrapper::decapsulate(kemKey.get(), ct);
    check(recovered != nullptr, "decapsulation succeeds");

    auto recK = json_string_value(
        json_object_get(recovered.get(), "k"));
    check(recK != nullptr, "recovered has k field");
    check(std::strcmp(ssK, recK) == 0,
          "encap/decap shared secrets match");
}

static void testBase64RoundTrip()
{
    std::cerr << "== testBase64RoundTrip ==\n";
    std::string original = "Hello, NBDE hybrid PQC!";
    std::vector<uint8_t> data(original.begin(), original.end());

    auto encoded = JoseWrapper::base64UrlEncode(data);
    check(!encoded.empty(), "encoding produces output");

    auto decoded = JoseWrapper::base64UrlDecode(encoded);
    std::string result(decoded.begin(), decoded.end());
    check(result == original, "round trip preserves data");
}

static void testJweRoundTrip()
{
    std::cerr << "== testJweRoundTrip ==\n";
    auto key = JoseWrapper::generateKey(
        "{\"alg\":\"A256GCM\"}");
    check(key != nullptr, "AES key generated");

    std::string plaintext = "secret disk encryption key";
    auto jwe = jsonParse(
        "{\"protected\":{\"alg\":\"dir\",\"enc\":\"A256GCM\"}}");

    bool ok = JoseWrapper::jweEncrypt(
        jwe.get(), key.get(), plaintext.data(), plaintext.size());
    check(ok, "JWE encryption succeeds");

    auto compact = JoseWrapper::jweToCompact(jwe.get());
    check(!compact.empty(), "compact JWE produced");

    auto jwe2 = JoseWrapper::jweFromCompact(compact);
    check(jwe2 != nullptr, "compact JWE parsed back");

    auto recovered = JoseWrapper::jweDecrypt(jwe2.get(), key.get());
    std::string result(recovered.begin(), recovered.end());
    check(result == plaintext, "JWE round trip preserves plaintext");
}

static void testThumbprint()
{
    std::cerr << "== testThumbprint ==\n";
    auto key = JoseWrapper::generateKey(
        "{\"alg\":\"ECMR\",\"crv\":\"P-256\"}");
    auto pub = JoseWrapper::publicKey(key.get());

    auto thp1 = JoseWrapper::thumbprint(pub.get(), "S256");
    check(!thp1.empty(), "thumbprint produced");

    auto thp2 = JoseWrapper::thumbprint(pub.get(), "S256");
    check(thp1 == thp2, "thumbprint is deterministic");

    auto otherKey = JoseWrapper::generateKey(
        "{\"alg\":\"ECMR\",\"crv\":\"P-256\"}");
    auto otherPub = JoseWrapper::publicKey(otherKey.get());
    auto thp3 = JoseWrapper::thumbprint(otherPub.get(), "S256");
    check(thp1 != thp3, "different keys have different thumbprints");
}

static void testThumbprintMatch()
{
    std::cerr << "== testThumbprintMatch ==\n";
    auto key1 = JoseWrapper::generateKey(
        "{\"alg\":\"ECMR\",\"crv\":\"P-256\"}");
    auto key2 = JoseWrapper::generateKey(
        "{\"alg\":\"ECMR\",\"crv\":\"P-256\"}");
    auto pub1 = JoseWrapper::publicKey(key1.get());
    auto pub2 = JoseWrapper::publicKey(key2.get());

    auto thp1 = JoseWrapper::thumbprint(pub1.get(), "S256");

    auto keys = makeJsonPtr(json_array());
    json_array_append(keys.get(), pub1.get());
    json_array_append(keys.get(), pub2.get());

    check(JoseWrapper::thumbprintMatch(keys.get(), thp1, "S256"),
          "matching thumbprint found");

    check(!JoseWrapper::thumbprintMatch(keys.get(), "bogus", "S256"),
          "bogus thumbprint not found");
}

static void testFilterKeysByUse()
{
    std::cerr << "== testFilterKeysByUse ==\n";
    auto excKey = JoseWrapper::generateKey(
        "{\"alg\":\"ECMR\",\"crv\":\"P-256\"}");
    auto pub = JoseWrapper::publicKey(excKey.get());

    auto jwks = makeJsonPtr(json_pack("{s:[O]}", "keys", pub.get()));
    auto filtered = JoseWrapper::filterKeysByUse(
        jwks.get(), "deriveKey");
    check(filtered != nullptr, "filter returns result");
}

int main()
{
    std::cerr << "=== jose_wrapper tests ===\n\n";

    testGenerateEcKey();
    testPublicKey();
    testKeyExchange();
    testKemRoundTrip();
    testBase64RoundTrip();
    testJweRoundTrip();
    testThumbprint();
    testThumbprintMatch();
    testFilterKeysByUse();

    std::cerr << "\n";
    if (failures > 0) {
        std::cerr << failures << " test(s) FAILED\n";
        return 1;
    }
    std::cerr << "All tests passed\n";
    return 0;
}
