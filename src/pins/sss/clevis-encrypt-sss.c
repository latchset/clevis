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
 *
 * Additional permission under GPLv3 section 7:
 *
 * In the following paragraph, "GPL" means the GNU General Public
 * License, version 3 or any later version, and "Non-GPL Code" means
 * code that is governed neither by the GPL nor a license
 * compatible with the GPL.
 *
 * You may link the code of this Program with Non-GPL Code and convey
 * linked combinations including the two, provided that such Non-GPL
 * Code only links to the code of this Program through those well
 * defined interfaces identified in the file named EXCEPTION found in
 * the source code files (the "Approved Interfaces"). The files of
 * Non-GPL Code may instantiate templates or use macros or inline
 * functions from the Approved Interfaces without causing the resulting
 * work to be covered by the GPL. Only the copyright holders of this
 * Program may make changes or additions to the list of Approved
 * Interfaces.
 */

#define _GNU_SOURCE
#include "sss.h"

#include <openssl/crypto.h>
#include <jose/b64.h>
#include <jose/jwe.h>

#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <libgen.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <unistd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define str_auto_t char __attribute__((cleanup(str_auto)))

static void
str_auto(char **str)
{
    if (!str || !*str)
        return;

    OPENSSL_cleanse(*str, strlen(*str));
    free(*str);
}

static json_int_t
npins(json_t *pins)
{
    const char *key = NULL;
    json_t *val = NULL;
    json_int_t n = 0;

    json_object_foreach(pins, key, val) {
        if (json_is_object(val))
            n++;
        else if (json_is_array(val))
            n += json_array_size(val);
    }

    return n;
}

static json_t *
encrypt_frag(json_t *sss, const char *pin, const json_t *cfg, int assume_yes)
{
    char *args[] = { "clevis", "encrypt", (char *) pin, NULL, NULL, NULL };
    json_auto_t *jwe = json_string("");
    str_auto_t *str = NULL;
    uint8_t *pnt = NULL;
    FILE *pipe = NULL;
    size_t pntl = 0;
    pid_t pid = 0;
    int status = 0;

    str = args[3] = json_dumps(cfg, JSON_SORT_KEYS | JSON_COMPACT);
    if (!str)
        return NULL;

    if (assume_yes) {
        args[4] = "-y";
    }

    pnt = sss_point(sss, &pntl);
    if (!pnt)
        return NULL;

    pipe = call(args, pnt, pntl, &pid);
    OPENSSL_cleanse(pnt, pntl);
    free(pnt);
    if (!pipe)
        return NULL;

    char buf[4096] = {};
    size_t rd = 0;
    json_t *tmp = NULL;
    while (!feof(pipe)) {
        char tmp_buf[4096] = {};
        size_t tmp_rd = 0;

        tmp_rd = fread(tmp_buf, 1, sizeof(tmp_buf), pipe);
        if (ferror(pipe)) {
            fclose(pipe);
            return NULL;
        }
        if (rd + tmp_rd > sizeof(buf)) {
            fclose(pipe);
            fprintf(stderr, "sss: read buffer overflow\n");
            return NULL;
        }
        memcpy(buf + rd, tmp_buf, tmp_rd);
        rd += tmp_rd;
    }
    tmp = json_pack("s+%", json_string_value(jwe), buf, rd);
    if (!tmp) {
        fclose(pipe);
        return NULL;
    }

    json_decref(jwe);
    jwe = tmp;

    fclose(pipe);
    waitpid(pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        return NULL;
    }
    return json_incref(jwe);
}

static json_t *
encrypt_frags(json_int_t t, json_t *pins, int assume_yes)
{
    const char *pname = NULL;
    json_auto_t *sss = NULL;
    json_t *pcfgs = NULL;
    json_t *parr = NULL;

    /* Generate the SSS polynomial. */
    sss = sss_generate(32, t);
    if (!sss) {
        fprintf(stderr, "Error generating SSS!\n");
        return NULL;
    }

    if (json_object_set_new(sss, "jwe", parr = json_array()) < 0)
        return NULL;

    /* Encrypt each key share with a child pin. */
    json_object_foreach(pins, pname, pcfgs) {
        json_t *pcfg = NULL;
        size_t i = 0;

        if (json_is_object(pcfgs))
            pcfgs = json_pack("[O]", pcfgs);
        else if (json_is_array(pcfgs))
            pcfgs = json_incref(pcfgs);
        else
            return NULL;

        if (json_object_set_new(pins, pname, pcfgs) < 0)
            return NULL;

        json_array_foreach(pcfgs, i, pcfg) {
            json_auto_t *jwe = NULL;

            jwe = encrypt_frag(sss, pname, pcfg, assume_yes);
            if (!jwe)
                return NULL;

            if (json_array_append(parr, jwe) < 0)
                return NULL;
        }
    }

    return json_incref(sss);
}

int
main(int argc, char *argv[])
{
    const char *SUMMARY = "Encrypts using a Shamir's Secret Sharing policy";
    jose_io_auto_t *out = NULL;
    jose_io_auto_t *b64 = NULL;
    jose_io_auto_t *enc = NULL;
    json_auto_t *cfg = NULL;
    json_auto_t *jwk = NULL;
    json_auto_t *jwe = NULL;
    json_auto_t *sss = NULL;
    const char *key = NULL;
    const char *prt = NULL;
    const char *tag = NULL;
    const char *iv = NULL;
    json_t *pins = NULL;
    json_int_t t = 1;
    int assume_yes = 0;

    if (argc == 2 && strcmp(argv[1], "--summary") == 0) {
        fprintf(stdout, "%s\n", SUMMARY);
        return EXIT_SUCCESS;
    }

    if (isatty(STDIN_FILENO) || argc != 2) {
        if (argc != 3) {
            goto usage;
        }

        if (strcmp(argv[2], "-y") == 0) {
            assume_yes = 1;
        } else if (strlen(argv[2]) > 0) {
            goto usage;
        }
    }

    /* Parse configuration. */
    cfg = json_loads(argv[1], 0, NULL);
    if (!cfg) {
        fprintf(stderr, "Error parsing config!\n");
        return EXIT_FAILURE;
    }

    if (json_unpack(cfg, "{s?I,s:o}", "t", &t, "pins", &pins) != 0) {
        fprintf(stderr, "Config missing 'pins' attribute!\n");
        return EXIT_FAILURE;
    }

    if (t < 1 || t > npins(pins)) {
        fprintf(stderr, "Invalid threshold (required: 1 <= %lld <= %lld)!\n",
                t, npins(pins));
        return EXIT_FAILURE;
    }

    sss = encrypt_frags(t, pins, assume_yes);
    if (!sss)
        return EXIT_FAILURE;

    /* Perform encryption using the key. */
    if (json_unpack(sss, "{s:[s]}", "e", &key) != 0)
        return EXIT_FAILURE;

    jwk = json_pack("{s:s,s:s,s:s}", "kty", "oct", "k", key, "alg", "A256GCM");
    if (!jwk)
        return EXIT_FAILURE;

    if (json_object_del(sss, "e") != 0)
        return EXIT_FAILURE;

    jwe = json_pack("{s:{s:s,s:{s:s,s:O}}}", "protected", "alg", "dir",
                    "clevis", "pin", "sss", "sss", sss);
    if (!jwe)
        return EXIT_FAILURE;

    out = jose_io_file(NULL, stdout);
    b64 = jose_b64_enc_io(out);
    enc = jose_jwe_enc_cek_io(NULL, jwe, jwk, b64);
    if (!out || !b64 || !enc)
        return EXIT_FAILURE;

    if (json_unpack(jwe, "{s:s,s:s}", "protected", &prt, "iv", &iv) != 0)
        return EXIT_FAILURE;

    if (fprintf(stdout, "%s..%s.", prt, iv) < 0)
        return EXIT_FAILURE;

    while (!feof(stdin)) {
        uint8_t rd[1024] = {};
        size_t r = 0;

        r = fread(rd, 1, sizeof(rd), stdin);
        if (ferror(stdin)) {
            fprintf(stderr, "Error reading plaintext!\n");
            return EXIT_FAILURE;
        }

        if (!enc->feed(enc, rd, r))
            return EXIT_FAILURE;
    }

    if (!enc->done(enc))
        return EXIT_FAILURE;

    if (json_unpack(jwe, "{s:s}", "tag", &tag) != 0)
        return EXIT_FAILURE;

    if (fprintf(stdout, ".%s%s", tag, isatty(STDOUT_FILENO) ? "\n" : "") < 0)
        return EXIT_FAILURE;

    return EXIT_SUCCESS;

usage:
    fprintf(stderr, "\n");
    fprintf(stderr, "Usage: clevis encrypt sss CONFIG [-y] < PLAINTEXT > JWE\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "%s\n", SUMMARY);
    fprintf(stderr, "\n");
    fprintf(stderr, "This command uses the following configuration properties:\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "     t: <integer>  Number of pins required for decryption (REQUIRED)\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "  pins: <object>   Pins used for encrypting fragments (REQUIRED)\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Here is an example configuration for one of two servers:\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "{\n");
    fprintf(stderr, "  \"t\": 1,\n");
    fprintf(stderr, "  \"pins\": {\n");
    fprintf(stderr, "    \"tang\": [\n");
    fprintf(stderr, "      { \"url\": \"http://example.com/tang1\" },\n");
    fprintf(stderr, "      { \"url\": \"http://example.com/tang2\" }\n");
    fprintf(stderr, "    ]\n");
    fprintf(stderr, "  }\n");
    fprintf(stderr, "}\n");
    fprintf(stderr, "\n");

    return EXIT_FAILURE;
}
