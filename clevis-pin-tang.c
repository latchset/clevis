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

#define _GNU_SOURCE

#include "readall.h"
#include "http.h"
#include "tang.h"

#include <jose/b64.h>
#include <jose/jwk.h>
#include <jose/jwe.h>

#include <string.h>
#include <time.h>

#include <errno.h>

static void
FILE_cleanup(FILE **file)
{
    if (file && *file)
        fclose(*file);
}

static int __attribute__((format(printf, 6, 7)))
http_json(char *type, const json_t *req,
          char *accept, json_t **rep,
          enum http_method method, const char *fmt, ...)
{
    struct http_msg hreq = {
        .head = (struct http_head[]) {
            { "Accept", accept },
            { type ? "Content-Type" : NULL, type ? type : NULL },
            {}
        },
    };

    struct http_msg *hrep = NULL;
    char *url = NULL;
    va_list ap;
    int r = 0;

    if (req) {
        hreq.body = (uint8_t *) json_dumps(req, JSON_SORT_KEYS | JSON_COMPACT);
        if (!hreq.body)
            return -ENOMEM;

        hreq.size = strlen((char *) hreq.body);
    }

    va_start(ap, fmt);
    r = vasprintf(&url, fmt, ap) < 0 ? -errno : 0;
    va_end(ap);
    if (r >= 0)
        r = http(url, method, &hreq, &hrep);
    if (hreq.body)
        memset(hreq.body, 0, hreq.size);
    free(hreq.body);
    free(url);
    if (r != 200) {
        http_msg_free(hrep);
        return r;
    }

    if (hrep->head) {
        for (size_t i = 0; hrep->head[i].key && hrep->head[i].val; i++) {
            if (strcasecmp("Content-Type", hrep->head[i].val) != 0)
                continue;

            if (strcasecmp(accept, hrep->head[i].val) != 0) {
                http_msg_free(hrep);
                return -EBADMSG;
            }
        }
    }

    *rep = json_loadb((char *) hrep->body, hrep->size, 0, NULL);

    http_msg_free(hrep);
    return *rep ? 200 : -EBADMSG;
}

static json_t *
load_adv(const char *filename)
{
    __attribute__((cleanup(FILE_cleanup))) FILE *file = NULL;
    json_auto_t *keys = NULL;
    json_auto_t *adv = NULL;

    file = fopen(filename, "r");
    if (!file)
        return NULL;

    adv = json_loadf(file, 0, NULL);
    keys = tang_validate(adv);
    return keys ? json_incref(adv) : NULL;
}

static json_t *
dnld_adv(const char *url)
{
    __attribute__((cleanup(FILE_cleanup))) FILE *tty = NULL;
    json_auto_t *keys = NULL;
    json_auto_t *adv = NULL;
    json_t *jwk = NULL;
    char yn = 'x';
    size_t i = 0;
    int r = 0;

    r = http_json(NULL, NULL, "application/jose+json", &adv,
                  HTTP_GET, "%s/adv", url);
    if (r != 200)
        return NULL;

    keys = tang_validate(adv);
    if (!keys)
        return NULL;

    tty = fopen("/dev/tty", "a+");
    if (!tty)
        return NULL;

    fprintf(tty, "The advertisement is signed with the following keys:\n");

    json_array_foreach(keys, i, jwk) {
        json_auto_t *kid = NULL;

        if (!jose_jwk_allowed(jwk, true, "verify"))
            continue;

        kid = jose_jwk_thumbprint_json(jwk, NULL);
        if (!kid)
            return NULL;

        fprintf(tty, "\t%s\n", json_string_value(kid));
    }

    while (!strchr("YyNn", yn)) {
        fprintf(tty, "\nDo you wish to trust the advertisement? [yN] ");
        if (fread(&yn, 1, 1, tty) != 1)
            break;
    }

    return strchr("Yy", yn) ? json_incref(adv) : NULL;
}

static json_t *
select_jwk(json_t *jws)
{
    json_auto_t *jwkset = NULL;
    json_t *jwk = NULL;
    size_t i = 0;

    jwkset = jose_b64_decode_json_load(json_object_get(jws, "payload"));
    if (!jwkset)
        return NULL;

    json_array_foreach(json_object_get(jwkset, "keys"), i, jwk) {
        if (jose_jwk_allowed(jwk, true, "deriveKey"))
            return json_incref(jwk);
    }

    return NULL;
}

static int
encrypt(int argc, char *argv[])
{
    jose_buf_auto_t *pt = NULL;
    json_auto_t *cfg = NULL;
    json_auto_t *cek = NULL;
    json_auto_t *jwk = NULL;
    json_auto_t *jwe = NULL;
    json_auto_t *jws = NULL;
    const char *url = NULL;

    jwe = json_pack("{s:{s:s}}", "unprotected", "clevis.pin", "tang");
    cek = json_object();
    if (!jwe || !cek)
        return EXIT_FAILURE;

    cfg = json_loads(argv[2], 0, NULL);
    if (!cfg) {
        fprintf(stderr, "Error parsing configuration!\n");
        return EXIT_FAILURE;
    }

    pt = readall(stdin);
    if (!pt) {
        fprintf(stderr, "Error reading key!\n");
        return EXIT_FAILURE;
    }

    if (json_unpack(cfg, "{s:s,s?o}", "url", &url, "adv", &jws) != 0) {
        fprintf(stderr, "Invalid configuration!\n");
        return EXIT_FAILURE;
    }

    if (json_is_string(jws))
        jws = load_adv(json_string_value(jws));
    else if (!json_is_object(jws))
        jws = dnld_adv(url);
    else {
        json_t *keys = tang_validate(jws);
        json_incref(jws);
        if (!keys) {
            fprintf(stderr, "Specified advertisement is invalid!\n");
            return EXIT_FAILURE;
        }

        json_decref(keys);
    }

    jwk = select_jwk(jws);
    if (!jwk) {
        fprintf(stderr, "Error selecting remote public key!\n");
        return EXIT_FAILURE;
    }

    if (!tang_bind(jwe, cek, jwk, url, jws)) {
        fprintf(stderr, "Error creating binding!\n");
        return EXIT_FAILURE;
    }

    if (!jose_jwe_encrypt(jwe, cek, pt->data, pt->size)) {
        fprintf(stderr, "Error encrypting key!\n");
        return EXIT_FAILURE;
    }

    if (json_dumpf(jwe, stdout, JSON_SORT_KEYS | JSON_COMPACT) != 0)
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}

static int
decrypt(int argc, char *argv[])
{
    json_auto_t *rcps = NULL;
    json_auto_t *jwe = NULL;
    json_t *rcp = NULL;
    size_t i = 0;

    jwe = json_loadf(stdin, 0, NULL);
    if (!jwe)
        return EXIT_FAILURE;

    rcps = json_incref(json_object_get(jwe, "recipients"));
    if (!json_is_array(rcps)) {
        json_decref(rcps);
        rcps = json_pack("[O]", jwe);
    }
    if (!rcps)
        return EXIT_FAILURE;

    json_array_foreach(rcps, i, rcp) {
        jose_buf_auto_t *key = NULL;
        json_auto_t *cek = NULL;
        json_auto_t *eph = NULL;
        json_auto_t *hdr = NULL;
        json_auto_t *rep = NULL;
        json_auto_t *req = NULL;
        const char *url = NULL;
        int r = 0;

        hdr = jose_jwe_merge_header(jwe, rcp);
        if (!hdr)
            return EXIT_FAILURE;

        if (json_unpack(hdr, "{s:s}", "clevis.tang.url", &url) != 0)
            continue;

        if (!tang_prepare(jwe, rcp, &req, &eph))
            continue;

        r = http_json("application/jwk+json", req,
                      "application/jwk+json", &rep,
                      HTTP_POST, "%s", url);
        if (r != 200)
            continue;

        cek = tang_recover(jwe, rcp, eph, rep);
        if (!cek)
            continue;

        key = jose_jwe_decrypt(jwe, cek);
        if (!key)
            return EXIT_FAILURE;

        if (fwrite(key->data, key->size, 1, stdout) != 1)
            return EXIT_FAILURE;

        return EXIT_SUCCESS;
    }

    return EXIT_FAILURE;
}

int
main(int argc, char *argv[])
{
    if (argc == 3 && strcmp(argv[1], "encrypt") == 0)
        return encrypt(argc, argv);

    if (argc == 2 && strcmp(argv[1], "decrypt") == 0)
        return decrypt(argc, argv);

    fprintf(stderr, "Usage: %s encrypt CONFIG\n", argv[0]);
    fprintf(stderr, "   or: %s decrypt\n", argv[0]);
    return EXIT_FAILURE;
}
