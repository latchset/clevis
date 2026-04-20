/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */
/*
 * Copyright (c) 2026 Red Hat, Inc.
 * Author: Sergio Correia <scorreia@redhat.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "token-to-jwe.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char valid_token[] =
    "{"
    "  \"type\": \"clevis\","
    "  \"keyslots\": [\"1\"],"
    "  \"jwe\": {"
    "    \"protected\": \"eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0\","
    "    \"encrypted_key\": \"\","
    "    \"iv\": \"oB2uB6_a2LCQnhNk\","
    "    \"ciphertext\": \"Gss774jh5EcnMA5NacAxuX8\","
    "    \"tag\": \"6L9KBrn6-R1---wTikJTrA\""
    "  }"
    "}";

static void
test_basic_conversion(void)
{
    pkt_t pkt = {};
    const char *expected =
        "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0"
        "."
        "."
        "oB2uB6_a2LCQnhNk"
        "."
        "Gss774jh5EcnMA5NacAxuX8"
        "."
        "6L9KBrn6-R1---wTikJTrA";

    assert(token_to_jwe(valid_token, &pkt));
    assert(strcmp(pkt.data, expected) == 0);
    fprintf(stderr, "test_basic_conversion: PASS\n");
}

static void
test_used_equals_strlen(void)
{
    pkt_t pkt = {};

    assert(token_to_jwe(valid_token, &pkt));
    assert(pkt.used == (ssize_t) strlen(pkt.data));
    fprintf(stderr, "test_used_equals_strlen: PASS\n");
}

static void
test_invalid_json(void)
{
    pkt_t pkt = {};

    assert(!token_to_jwe(NULL, &pkt));
    assert(!token_to_jwe("not json", &pkt));
    assert(!token_to_jwe("{}", &pkt));
    assert(!token_to_jwe("{\"jwe\":{}}", &pkt));
    assert(!token_to_jwe("{\"jwe\":{\"protected\":\"a\"}}", &pkt));
    fprintf(stderr, "test_invalid_json: PASS\n");
}

static void
test_empty_components(void)
{
    const char *json =
        "{\"jwe\":{"
        "\"protected\":\"\","
        "\"encrypted_key\":\"\","
        "\"iv\":\"\","
        "\"ciphertext\":\"\","
        "\"tag\":\"\""
        "}}";
    pkt_t pkt = {};

    assert(token_to_jwe(json, &pkt));
    assert(strcmp(pkt.data, "....") == 0);
    assert(pkt.used == 4);
    assert(pkt.used == (ssize_t) strlen(pkt.data));
    fprintf(stderr, "test_empty_components: PASS\n");
}

static void
test_single_char_components(void)
{
    const char *json =
        "{\"jwe\":{"
        "\"protected\":\"a\","
        "\"encrypted_key\":\"b\","
        "\"iv\":\"c\","
        "\"ciphertext\":\"d\","
        "\"tag\":\"e\""
        "}}";
    pkt_t pkt = {};

    assert(token_to_jwe(json, &pkt));
    assert(strcmp(pkt.data, "a.b.c.d.e") == 0);
    assert(pkt.used == 9);
    assert(pkt.used == (ssize_t) strlen(pkt.data));
    fprintf(stderr, "test_single_char_components: PASS\n");
}

int
main(void)
{
    test_basic_conversion();
    test_used_equals_strlen();
    test_invalid_json();
    test_empty_components();
    test_single_char_components();

    fprintf(stderr, "All tests passed.\n");
    return EXIT_SUCCESS;
}
