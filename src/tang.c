/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */
/*
 * Copyright (c) 2016 Red Hat, Inc.
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

#include "tang.h"
#include <jose/jose.h>
#include <jose/openssl.h>

#include <openssl/rand.h>

#include <string.h>

json_t *
tang_validate(const json_t *jws)
{
    json_auto_t *jwkset = NULL;
    json_t *keys = NULL;
    size_t sigs = 0;

    jwkset = jose_b64_decode_json_load(json_object_get(jws, "payload"));
    if (!jwkset)
        return NULL;

    keys = json_object_get(jwkset, "keys");
    if (!json_is_array(keys))
        return NULL;

    for (size_t i = 0; i < json_array_size(keys); i++) {
        json_t *key = json_array_get(keys, i);

        if (!jose_jwk_allowed(key, true, "verify"))
            continue;

        if (!jose_jws_verify(jws, key, NULL))
            return NULL;

        sigs++;
    }

    if (sigs == 0)
        return NULL;

    return json_incref(keys);
}

bool
tang_bind(json_t *jwe, json_t *cek, const json_t *jwk,
          const char *url, const json_t *adv)
{
    json_auto_t *keys = NULL;
    json_auto_t *rcp = NULL;
    json_auto_t *key = NULL;
    const char *kty = NULL;
    char *kid = NULL;

    if (!jose_jwk_allowed(jwk, true, "deriveKey"))
        return false;

    key = json_deep_copy(jwk);
    if (!key)
        return false;

    /* Remove key_ops to allow use for encryption below. */
    json_object_del(key, "key_ops");

    if (json_unpack(key, "{s:s}", "kty", &kty) < 0)
        return false;

    if (strcmp(kty, "EC") != 0)
        return false;

    keys = tang_validate(adv);
    if (!keys)
        return false;

    kid = jose_jwk_thumbprint(key, NULL);
    if (!kid)
        return false;

    rcp = json_pack("{s:{s:s++,s:O}}", "header",
                    "clevis.tang.url", url, "/rec/", kid,
                    "clevis.tang.adv", keys);
    free(kid);
    if (!rcp)
        return false;

    return jose_jwe_wrap(jwe, cek, key, rcp);
}

static json_t *
add(const json_t *a, const json_t *b, bool inv)
{
    const EC_GROUP *grp = NULL;
    json_t *jwk = NULL;
    BN_CTX *ctx = NULL;
    EC_POINT *p = NULL;
    EC_KEY *ak = NULL;
    EC_KEY *bk = NULL;

    ak = jose_openssl_jwk_to_EC_KEY(a);
    bk = jose_openssl_jwk_to_EC_KEY(b);
    ctx = BN_CTX_new();
    if (!ak || !bk || !ctx)
        goto egress;

    grp = EC_KEY_get0_group(ak);
    if (EC_GROUP_cmp(grp, EC_KEY_get0_group(bk), ctx) != 0)
        goto egress;

    p = EC_POINT_new(grp);
    if (!p)
        goto egress;

    if (EC_POINT_copy(p, EC_KEY_get0_public_key(bk)) < 0)
        goto egress;

    if (inv) {
        if (EC_POINT_invert(grp, p, ctx) < 0)
            goto egress;
    }

    if (EC_POINT_add(grp, p, EC_KEY_get0_public_key(ak), p, ctx) < 0)
        goto egress;

    jwk = jose_openssl_jwk_from_EC_POINT(EC_KEY_get0_group(ak), p, NULL);

egress:
    BN_CTX_free(ctx);
    EC_POINT_free(p);
    EC_KEY_free(ak);
    EC_KEY_free(bk);
    return jwk;
}

bool
tang_prepare(const json_t *jwe, const json_t *rcp, json_t **req, json_t **eph)
{
    json_auto_t *hdr = NULL;
    json_auto_t *esk = NULL;
    json_t *epk = NULL;

    hdr = jose_jwe_merge_header(jwe, rcp);
    if (!hdr)
        return false;

    epk = json_object_get(hdr, "epk");
    if (!epk)
        return false;

    esk = json_pack("{s:O,s:O}",
                    "kty", json_object_get(epk, "kty"),
                    "crv", json_object_get(epk, "crv"));
    if (!esk)
        return false;

    if (!jose_jwk_generate(esk))
        return false;

    *req = add(epk, esk, false);
    if (!*req)
        return false;

    *eph = json_incref(esk);
    return true;
}

json_t *
tang_recover(const json_t *jwe, const json_t *rcp,
             const json_t *eph, const json_t *rep)
{
    json_auto_t *hdr = NULL;
    const char *url = NULL;
    const char *kid = NULL;
    json_t *keys = NULL;
    json_t *key = NULL;
    json_t *epk = NULL;
    size_t i = 0;

    hdr = jose_jwe_merge_header(jwe, rcp);
    if (!hdr)
        return NULL;

    if (json_unpack(hdr, "{s:o,s:o,s:s}", "epk", &epk,
                    "clevis.tang.adv", &keys,
                    "clevis.tang.url", &url) != 0)
        return NULL;

    kid = strrchr(url, '/');
    if (!kid)
        return NULL;
    kid++;

    json_array_foreach(keys, i, key) {
        char thp[jose_jwk_thumbprint_len(NULL) + 1];
        json_auto_t *exc = NULL;
        json_auto_t *rec = NULL;

        memset(thp, 0, sizeof(thp));
        if (!jose_jwk_thumbprint_buf(key, NULL, thp))
            return NULL;

        if (strcmp(thp, kid) != 0)
            continue;

        exc = jose_jwk_exchange(eph, key);
        if (!exc)
            return NULL;

        rec = add(rep, exc, true);
        if (!rec)
            return NULL;

        return jose_jwe_unwrap(jwe, rec, rcp);
    }

    return NULL;
}
