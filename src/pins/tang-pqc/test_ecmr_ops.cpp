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

#include "ecmr_ops.h"
#include "jose_wrapper.h"
#include "jose_types.h"

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

static void testBlindProducesValidKey()
{
    std::cerr << "== testBlindProducesValidKey ==\n";
    auto clientKey = JoseWrapper::generateKey(
        "{\"alg\":\"ECMR\",\"crv\":\"P-256\"}");
    auto clientPub = JoseWrapper::publicKey(clientKey.get());
    auto ephemeral = JoseWrapper::generateKey(
        "{\"alg\":\"ECMR\",\"crv\":\"P-256\"}");

    auto blinded = EcmrOps::blind(clientPub.get(), ephemeral.get());
    check(blinded != nullptr, "blind produces result");

    auto kty = json_string_value(
        json_object_get(blinded.get(), "kty"));
    check(kty && std::strcmp(kty, "EC") == 0, "result is EC key");

    auto crv = json_string_value(
        json_object_get(blinded.get(), "crv"));
    check(crv && std::strcmp(crv, "P-256") == 0,
          "result preserves curve");
}

static void testBlindedKeyDiffersFromOriginal()
{
    std::cerr << "== testBlindedKeyDiffersFromOriginal ==\n";
    auto clientKey = JoseWrapper::generateKey(
        "{\"alg\":\"ECMR\",\"crv\":\"P-256\"}");
    auto clientPub = JoseWrapper::publicKey(clientKey.get());
    auto ephemeral = JoseWrapper::generateKey(
        "{\"alg\":\"ECMR\",\"crv\":\"P-256\"}");

    auto blinded = EcmrOps::blind(clientPub.get(), ephemeral.get());

    auto origX = json_string_value(
        json_object_get(clientPub.get(), "x"));
    auto blindX = json_string_value(
        json_object_get(blinded.get(), "x"));
    check(std::strcmp(origX, blindX) != 0,
          "blinded x differs from original");
}

static void testEcmrRecoveryMatchesEcdh()
{
    std::cerr << "== testEcmrRecoveryMatchesEcdh ==\n";

    auto clientKey = JoseWrapper::generateKey(
        "{\"alg\":\"ECMR\",\"crv\":\"P-256\"}");
    auto clientPub = JoseWrapper::publicKey(clientKey.get());

    auto serverKey = JoseWrapper::generateKey(
        "{\"alg\":\"ECMR\",\"crv\":\"P-256\"}");
    auto serverPub = JoseWrapper::publicKey(serverKey.get());

    auto directEcdh = JoseWrapper::keyExchange(
        clientKey.get(), serverPub.get());
    auto directX = json_string_value(
        json_object_get(directEcdh.get(), "x"));
    check(directX != nullptr, "direct ECDH produces x");

    auto ephemeral = JoseWrapper::generateKey(
        "{\"alg\":\"ECMR\",\"crv\":\"P-256\"}");

    auto blinded = EcmrOps::blind(clientPub.get(), ephemeral.get());
    check(blinded != nullptr, "blind succeeds");

    auto serverReply = JoseWrapper::ecmrExchange(
        serverKey.get(), blinded.get());
    check(serverReply != nullptr, "server ECMR succeeds");

    auto recovered = EcmrOps::unblind(
        serverReply.get(), ephemeral.get(), serverPub.get());
    check(recovered != nullptr, "unblind succeeds");

    auto recoveredX = json_string_value(
        json_object_get(recovered.get(), "x"));
    check(recoveredX != nullptr, "recovered has x");
    check(std::strcmp(directX, recoveredX) == 0,
          "ECMR recovery matches direct ECDH");
}

static void testMultipleCurvesWork()
{
    std::cerr << "== testMultipleCurvesWork ==\n";
    const char* curves[] = {"P-256", "P-384", "P-521"};

    for (auto crv : curves) {
        std::string spec =
            "{\"alg\":\"ECMR\",\"crv\":\"" + std::string(crv) + "\"}";

        auto clientKey = JoseWrapper::generateKey(spec);
        auto clientPub = JoseWrapper::publicKey(clientKey.get());
        auto serverKey = JoseWrapper::generateKey(spec);
        auto serverPub = JoseWrapper::publicKey(serverKey.get());
        auto ephemeral = JoseWrapper::generateKey(spec);

        auto directEcdh = JoseWrapper::keyExchange(
            clientKey.get(), serverPub.get());

        auto blinded = EcmrOps::blind(
            clientPub.get(), ephemeral.get());
        auto serverReply = JoseWrapper::ecmrExchange(
            serverKey.get(), blinded.get());
        auto recovered = EcmrOps::unblind(
            serverReply.get(), ephemeral.get(), serverPub.get());

        auto directX = json_string_value(
            json_object_get(directEcdh.get(), "x"));
        auto recoveredX = json_string_value(
            json_object_get(recovered.get(), "x"));

        std::string label =
            std::string("ECMR round trip on ") + crv;
        check(directX && recoveredX
              && std::strcmp(directX, recoveredX) == 0,
              label.c_str());
    }
}

static void testDifferentEphemeralsProduceSameResult()
{
    std::cerr << "== testDifferentEphemeralsProduceSameResult ==\n";
    auto clientKey = JoseWrapper::generateKey(
        "{\"alg\":\"ECMR\",\"crv\":\"P-256\"}");
    auto clientPub = JoseWrapper::publicKey(clientKey.get());
    auto serverKey = JoseWrapper::generateKey(
        "{\"alg\":\"ECMR\",\"crv\":\"P-256\"}");
    auto serverPub = JoseWrapper::publicKey(serverKey.get());

    auto eph1 = JoseWrapper::generateKey(
        "{\"alg\":\"ECMR\",\"crv\":\"P-256\"}");
    auto blinded1 = EcmrOps::blind(clientPub.get(), eph1.get());
    auto reply1 = JoseWrapper::ecmrExchange(
        serverKey.get(), blinded1.get());
    auto rec1 = EcmrOps::unblind(
        reply1.get(), eph1.get(), serverPub.get());

    auto eph2 = JoseWrapper::generateKey(
        "{\"alg\":\"ECMR\",\"crv\":\"P-256\"}");
    auto blinded2 = EcmrOps::blind(clientPub.get(), eph2.get());
    auto reply2 = JoseWrapper::ecmrExchange(
        serverKey.get(), blinded2.get());
    auto rec2 = EcmrOps::unblind(
        reply2.get(), eph2.get(), serverPub.get());

    auto x1 = json_string_value(
        json_object_get(rec1.get(), "x"));
    auto x2 = json_string_value(
        json_object_get(rec2.get(), "x"));
    check(x1 && x2 && std::strcmp(x1, x2) == 0,
          "different ephemerals produce same shared secret");
}

int main()
{
    std::cerr << "=== ecmr_ops tests ===\n\n";

    testBlindProducesValidKey();
    testBlindedKeyDiffersFromOriginal();
    testEcmrRecoveryMatchesEcdh();
    testMultipleCurvesWork();
    testDifferentEphemeralsProduceSameResult();

    std::cerr << "\n";
    if (failures > 0) {
        std::cerr << failures << " test(s) FAILED\n";
        return 1;
    }
    std::cerr << "All tests passed\n";
    return 0;
}
