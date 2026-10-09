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
#include "key_deriver.h"

#include <cstring>
#include <iostream>
#include <string>

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

static std::string extractK(const json_t* jwk)
{
    auto k = json_string_value(json_object_get(jwk, "k"));
    return k ? std::string(k) : "";
}

static void testDeriveProducesKey()
{
    std::cerr << "== testDeriveProducesKey ==\n";
    auto key = KeyDeriver::deriveEncKey(
        "dGVzdC1lYy14", "dGVzdC1rZW0taw",
        "kid-abc", "kem-kid-xyz");
    check(key != nullptr, "derivation succeeds");

    auto kty = json_string_value(json_object_get(key.get(), "kty"));
    check(kty && std::strcmp(kty, "oct") == 0, "key type is oct");

    auto k = json_string_value(json_object_get(key.get(), "k"));
    check(k != nullptr && std::strlen(k) > 0,
          "key has non-empty k field");
}

static void testDeriveDeterministic()
{
    std::cerr << "== testDeriveDeterministic ==\n";
    auto key1 = KeyDeriver::deriveEncKey(
        "dGVzdC1lYy14", "dGVzdC1rZW0taw",
        "kid-abc", "kem-kid-xyz");
    auto key2 = KeyDeriver::deriveEncKey(
        "dGVzdC1lYy14", "dGVzdC1rZW0taw",
        "kid-abc", "kem-kid-xyz");

    auto k1 = extractK(key1.get());
    auto k2 = extractK(key2.get());
    check(!k1.empty() && k1 == k2,
          "same inputs produce same key");
}

static void testDeriveDifferentEcInput()
{
    std::cerr << "== testDeriveDifferentEcInput ==\n";
    auto key1 = KeyDeriver::deriveEncKey(
        "dGVzdC1lYy14", "dGVzdC1rZW0taw",
        "kid-abc", "kem-kid-xyz");
    auto key2 = KeyDeriver::deriveEncKey(
        "ZGlmZmVyZW50", "dGVzdC1rZW0taw",
        "kid-abc", "kem-kid-xyz");

    auto k1 = extractK(key1.get());
    auto k2 = extractK(key2.get());
    check(!k1.empty() && !k2.empty() && k1 != k2,
          "different EC x produces different key");
}

static void testDeriveDifferentKemInput()
{
    std::cerr << "== testDeriveDifferentKemInput ==\n";
    auto key1 = KeyDeriver::deriveEncKey(
        "dGVzdC1lYy14", "dGVzdC1rZW0taw",
        "kid-abc", "kem-kid-xyz");
    auto key2 = KeyDeriver::deriveEncKey(
        "dGVzdC1lYy14", "ZGlmZmVyZW50",
        "kid-abc", "kem-kid-xyz");

    auto k1 = extractK(key1.get());
    auto k2 = extractK(key2.get());
    check(!k1.empty() && !k2.empty() && k1 != k2,
          "different KEM k produces different key");
}

static void testDeriveDomainSeparation()
{
    std::cerr << "== testDeriveDomainSeparation ==\n";
    auto key1 = KeyDeriver::deriveEncKey(
        "dGVzdC1lYy14", "dGVzdC1rZW0taw",
        "kid-abc", "kem-kid-xyz");
    auto key2 = KeyDeriver::deriveEncKey(
        "dGVzdC1lYy14", "dGVzdC1rZW0taw",
        "kid-DIFFERENT", "kem-kid-xyz");
    auto key3 = KeyDeriver::deriveEncKey(
        "dGVzdC1lYy14", "dGVzdC1rZW0taw",
        "kid-abc", "kem-kid-DIFFERENT");

    auto k1 = extractK(key1.get());
    auto k2 = extractK(key2.get());
    auto k3 = extractK(key3.get());
    check(k1 != k2, "different kid produces different key");
    check(k1 != k3, "different kem_kid produces different key");
    check(k2 != k3, "all three keys are distinct");
}

static void testDeriveWithRealKeys()
{
    std::cerr << "== testDeriveWithRealKeys ==\n";
    auto ecKey = JoseWrapper::generateKey(
        "{\"alg\":\"ECMR\",\"crv\":\"P-256\"}");
    auto ecPub = JoseWrapper::publicKey(ecKey.get());
    auto tangEc = JoseWrapper::generateKey(
        "{\"alg\":\"ECMR\",\"crv\":\"P-256\"}");
    auto tangPub = JoseWrapper::publicKey(tangEc.get());

    auto shared = JoseWrapper::keyExchange(ecKey.get(), tangPub.get());
    auto ecX = json_string_value(
        json_object_get(shared.get(), "x"));
    check(ecX != nullptr, "ECDH x-coordinate obtained");

    auto kemKey = JoseWrapper::generateKey(
        "{\"alg\":\"ML-KEM-768\"}");
    auto kemPub = JoseWrapper::publicKey(kemKey.get());
    auto [ct, ss] = JoseWrapper::encapsulate(kemPub.get());
    auto kemK = json_string_value(
        json_object_get(ss.get(), "k"));
    check(kemK != nullptr, "KEM shared secret obtained");

    auto kid = JoseWrapper::thumbprint(tangPub.get(), "S256");
    auto kemKid = JoseWrapper::thumbprint(kemPub.get(), "S256");

    auto encKey = KeyDeriver::deriveEncKey(ecX, kemK, kid, kemKid);
    check(encKey != nullptr, "derivation with real keys succeeds");

    auto k = json_string_value(json_object_get(encKey.get(), "k"));
    check(k != nullptr && std::strlen(k) > 0,
          "derived key has non-empty k field");
}

int main()
{
    std::cerr << "=== key_deriver tests ===\n\n";

    testDeriveProducesKey();
    testDeriveDeterministic();
    testDeriveDifferentEcInput();
    testDeriveDifferentKemInput();
    testDeriveDomainSeparation();
    testDeriveWithRealKeys();

    std::cerr << "\n";
    if (failures > 0) {
        std::cerr << failures << " test(s) FAILED\n";
        return 1;
    }
    std::cerr << "All tests passed\n";
    return 0;
}
