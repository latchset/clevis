/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */
/*
 * Copyright (c) 2015 Red Hat, Inc.
 * Author: Nathaniel McCallum <npmccallum@redhat.com>
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

#include <jansson.h>
#include <stdio.h>
#include <string.h>

bool
token_to_jwe(const char *json, pkt_t *pkt)
{
    json_auto_t *tokn = NULL;
    const json_t *jwe = NULL;
    const char *prt = NULL;
    const char *key = NULL;
    const char *tag = NULL;
    const char *iv = NULL;
    const char *ct = NULL;

    if (!json)
        return false;

    tokn = json_loads(json, 0, NULL);
    if (!tokn)
        return false;

    jwe = json_object_get(tokn, "jwe");
    if (!jwe)
        return false;

    if (json_unpack((json_t *) jwe, "{s:s,s:s,s:s,s:s,s:s}",
                    "protected", &prt, "encrypted_key", &key, "iv", &iv,
                    "ciphertext", &ct, "tag", &tag) < 0)
        return false;

    pkt->used = snprintf(pkt->data, sizeof(pkt->data),
                         "%s.%s.%s.%s.%s", prt, key, iv, ct, tag);
    if (pkt->used < 0 || (size_t) pkt->used >= sizeof(pkt->data))
        return false;

    return true;
}
