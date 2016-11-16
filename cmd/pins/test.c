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

#include "libreadall.h"
#include <string.h>

static int
encrypt(int argc, char *argv[])
{
    jose_buf_auto_t *pt = NULL;
    json_auto_t *cfg = NULL;
    json_auto_t *cek = NULL;
    json_auto_t *jwe = NULL;

    pt = readall(stdin);
    if (!pt) {
        fprintf(stderr, "Error reading input!\n");
        return EXIT_FAILURE;
    }

    cfg = json_loads(argv[2], 0, NULL);
    if (!cfg) {
        fprintf(stderr, "Error parsing config!\n");
        return EXIT_FAILURE;
    }

    cek = json_pack("{s:s}", "alg", "A128GCM");
    if (!cek)
        return EXIT_FAILURE;

    if (!jose_jwk_generate(cek))
        return EXIT_FAILURE;

    jwe = json_pack("{s:{s:s},s:{s:s}}",
                    "protected", "alg", "dir",
                    "unprotected", "clevis.pin", "test");
    if (!jwe)
        return EXIT_FAILURE;

    if (!json_boolean_value(json_object_get(cfg, "fail"))) {
        json_object_set(json_object_get(jwe, "protected"),
                        "clevis.test.cek", cek);
    }

    if (!jose_jwe_encrypt(jwe, cek, pt->data, pt->size))
        return EXIT_FAILURE;

    json_dumpf(jwe, stdout, JSON_SORT_KEYS | JSON_COMPACT);
    fprintf(stdout, "\n");
    return EXIT_SUCCESS;
}

static int
decrypt(int argc, char *argv[])
{
    jose_buf_auto_t *pt = NULL;
    json_auto_t *jwe = NULL;
    json_auto_t *hdr = NULL;
    json_t *cek = NULL;

    jwe = json_loadf(stdin, 0, NULL);
    if (!jwe)
        return EXIT_FAILURE;

    hdr = jose_jwe_merge_header(jwe, jwe);
    if (!hdr)
        return EXIT_FAILURE;

    cek = json_object_get(hdr, "clevis.test.cek");
    if (!cek)
        return EXIT_FAILURE;

    pt = jose_jwe_decrypt(jwe, cek);
    if (!pt)
        return EXIT_FAILURE;

    if (fwrite(pt->data, pt->size, 1, stdout) != 1)
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
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
