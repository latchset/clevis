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

#include "readall.h"
#include "http.h"

#include <jose/b64.h>
#include <jose/jwk.h>
#include <jose/jwe.h>

#include <string.h>

static int
encrypt(int argc, char *argv[])
{
    jose_buf_auto_t *pt = NULL;
    json_auto_t *cfg = NULL;
    json_auto_t *cek = NULL;
    json_auto_t *jwe = NULL;
    int ret = EXIT_FAILURE;
    const char *url = NULL;
    uint8_t ky[32] = {};
    int r = 0;

    struct http_msg *rep = NULL;
    const struct http_msg req = {
        .head = (struct http_head[]) {
            { "Content-Type", "application/octet-stream" },
            {}
        },
        .body = ky,
        .size = sizeof(ky)
    };

    pt = readall(stdin);
    if (!pt)
        return EXIT_FAILURE;

    cfg = json_loads(argv[2], 0, NULL);
    if (!cfg) {
        fprintf(stderr, "Configuration is invalid JSON!\n");
        goto egress;
    }

    if (json_unpack(cfg, "{s:s}", "url", &url) != 0) {
        fprintf(stderr, "Configuration missing 'url' key!\n");
        goto egress;
    }

    cek = json_pack("{s:s,s:i}", "kty", "oct", "bytes", sizeof(ky));
    if (!cek)
        goto egress;

    if (!jose_jwk_generate(cek))
        goto egress;

    jwe = json_pack("{s:{s:s},s:{s:s,s:s}}",
                    "protected",
                        "alg", "dir",
                    "unprotected",
                        "clevis.pin", "http",
                        "clevis.http.url", url);
    if (!jwe)
        goto egress;

    if (!jose_jwe_encrypt(jwe, cek, pt->data, pt->size))
        goto egress;

    if (!jose_b64_decode_json_buf(json_object_get(cek, "k"), ky))
        goto egress;

    r = http(url, HTTP_PUT, &req, &rep);
    if (r < 0) {
        fprintf(stderr, "Error during HTTP request: %s!\n", strerror(-r));
        goto egress;
    } else if (r != 200) {
        fprintf(stderr, "HTTP server returned status %d!\n", r);
        goto egress;
    }

    json_dumpf(jwe, stdout, JSON_SORT_KEYS | JSON_COMPACT);
    fprintf(stdout, "\n");
    ret = EXIT_SUCCESS;

egress:
    http_msg_free(rep);
    return ret;
}

static int
decrypt(int argc, char *argv[])
{
    jose_buf_auto_t *pt = NULL;
    json_auto_t *cek = NULL;
    json_auto_t *jwe = NULL;
    json_auto_t *hdr = NULL;
    int ret = EXIT_FAILURE;
    const char *url = NULL;
    int r = 0;

    struct http_msg *rep = NULL;
    const struct http_msg req = {
        .head = (struct http_head[]) {
            { "Accept", "application/octet-stream" },
            {}
        },
    };

    jwe = json_loadf(stdin, 0, NULL);
    if (!jwe)
        goto egress;

    hdr = jose_jwe_merge_header(jwe, jwe);
    if (!hdr)
        goto egress;

    if (json_unpack(hdr, "{s:s}", "clevis.http.url", &url) != 0)
        goto egress;

    r = http(url, HTTP_GET, &req, &rep);
    if (r < 0) {
        fprintf(stderr, "Error during HTTP request: %s!\n", strerror(-r));
        goto egress;
    } else if (r != 200) {
        fprintf(stderr, "HTTP server returned status %d!\n", r);
        goto egress;
    }

    if (!rep->body || rep->size != 32)
        goto egress;

    for (size_t i = 0; rep->head && rep->head[i].key && rep->head[i].val; i++) {
        if (strcasecmp(rep->head[i].key, "Content-Type") != 0)
            continue;

        if (strcasecmp(rep->head[i].val, "application/octet-stream") != 0)
            goto egress;
    }

    cek = json_pack("{s:s,s:o}", "kty", "oct", "k",
                    jose_b64_encode_json(rep->body, rep->size));
    if (!cek)
        goto egress;

    pt = jose_jwe_decrypt(jwe, cek);
    if (!pt)
        goto egress;

    fwrite(pt->data, pt->size, 1, stdout);
    ret = EXIT_SUCCESS;

egress:
    http_msg_free(rep);
    return ret;
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
