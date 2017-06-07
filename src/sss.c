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

#define _GNU_SOURCE
#include "sss.h"
#include <jose/b64.h>
#include <openssl/bn.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>

#define BIGNUM_auto __attribute__((cleanup(BN_cleanup))) BIGNUM
#define BN_CTX_auto __attribute__((cleanup(BN_CTX_cleanup))) BN_CTX

static BIGNUM *
bn_decode(const uint8_t buf[], size_t len)
{
    return BN_bin2bn(buf, len, NULL);
}

static BIGNUM *
bn_decode_json(const json_t *json)
{
    uint8_t *buf = NULL;
    BIGNUM *bn = NULL;
    size_t len;

    len = jose_b64_dec(json, NULL, 0);
    if (len == SIZE_MAX)
        return NULL;

    buf = malloc(len);
    if (!buf)
        return NULL;

    if (jose_b64_dec(json, buf, len) != len) {
        free(bn);
        return NULL;
    }

    bn = bn_decode(buf, len);
    free(buf);
    return bn;
}

static bool
bn_encode(const BIGNUM *bn, uint8_t buf[], size_t len)
{
    int bytes = 0;

    if (!bn)
        return false;

    if (len == 0)
        len = BN_num_bytes(bn);

    bytes = BN_num_bytes(bn);
    if (bytes < 0 || bytes > (int) len)
        return false;

    memset(buf, 0, len);
    return BN_bn2bin(bn, &buf[len - bytes]) > 0;
}

static json_t *
bn_encode_json(const BIGNUM *bn, size_t len)
{
    uint8_t *buf = NULL;
    json_t *out = NULL;

    if (!bn)
        return NULL;

    if (len == 0)
        len = BN_num_bytes(bn);

    if ((int) len < BN_num_bytes(bn))
        return NULL;

    buf = malloc(len);
    if (!buf)
        return NULL;

    if (!bn_encode(bn, buf, len)) {
        free(buf);
        return NULL;
    }

    out = jose_b64_enc(buf, len);
    free(buf);
    return out;
}

static void
BN_CTX_cleanup(BN_CTX **ctx)
{
    if (ctx)
        BN_CTX_free(*ctx);
}

static void
BN_cleanup(BIGNUM **bnp)
{
    if (bnp)
        BN_clear_free(*bnp);
}

json_t *
sss_generate(size_t key_bytes, size_t threshold)
{
    BIGNUM_auto *p = NULL;
    BIGNUM_auto *e = NULL;
    json_t *sss = NULL;

    if (key_bytes == 0 || threshold < 1)
        return NULL;

    p = BN_new();
    e = BN_new();
    if (!p || !e)
        goto error;

    if (!BN_generate_prime_ex(p, key_bytes * 8, 1, NULL, NULL, NULL))
        goto error;

    sss = json_pack("{s:i,s:[],s:o}", "t", threshold, "e", "p",
                    bn_encode_json(p, key_bytes));
    if (!sss)
        goto error;

    for (size_t i = 0; i < threshold; i++) {
        if (BN_rand_range(e, p) <= 0)
            goto error;

        if (json_array_append_new(json_object_get(sss, "e"),
                                  bn_encode_json(e, key_bytes)))
            goto error;
    }

    return sss;

error:
    json_decref(sss);
    return NULL;
}

uint8_t *
sss_point(const json_t *sss, size_t *len)
{
    BN_CTX_auto *ctx = NULL;
    BIGNUM_auto *tmp = NULL;
    BIGNUM_auto *xx = NULL;
    BIGNUM_auto *yy = NULL;
    BIGNUM_auto *pp = NULL;
    uint8_t *key = NULL;
    json_t *e = NULL;
    json_t *p = NULL;
    json_int_t t = 0;

    if (json_unpack((json_t *) sss, "{s:I,s:o,s:o}",
                    "t", &t, "p", &p, "e", &e) != 0)
        return NULL;

    ctx = BN_CTX_new();
    pp = bn_decode_json(p);
    xx = BN_new();
    yy = BN_new();
    tmp = BN_new();
    if (!ctx || !pp || !xx || !yy || !tmp)
        return NULL;

    if (BN_rand_range(xx, pp) <= 0)
        return NULL;

    if (BN_zero(yy) <= 0)
        return NULL;

    for (size_t i = 0; i < json_array_size(e); i++) {
        BIGNUM_auto *ee = NULL;

        ee = bn_decode_json(json_array_get(e, i));
        if (!ee)
            return NULL;

        if (BN_cmp(pp, ee) <= 0)
            return NULL;

        /* y += e[i] * x^i */

        if (BN_set_word(tmp, i) <= 0)
            return NULL;

        if (BN_mod_exp(tmp, xx, tmp, pp, ctx) <= 0)
            return NULL;

        if (BN_mod_mul(tmp, ee, tmp, pp, ctx) <= 0)
            return NULL;

        if (BN_mod_add(yy, yy, tmp, pp, ctx) <= 0)
            return NULL;
    }

    *len = jose_b64_dec(p, NULL, 0);
    if (*len == SIZE_MAX)
        return NULL;
    key = malloc(*len * 2);
    if (!key)
        return NULL;

    if (!bn_encode(xx, key, *len) || !bn_encode(yy, &key[*len], *len)) {
        memset(key, 0, *len * 2);
        free(key);
        return NULL;
    }

    *len *= 2;
    return key;
}

json_t *
sss_recover(const json_t *p, size_t npnts, const uint8_t *pnts[])
{
    BN_CTX_auto *ctx = BN_CTX_new();
    BIGNUM_auto *pp = bn_decode_json(p);
    BIGNUM_auto *acc = BN_new();
    BIGNUM_auto *tmp = BN_new();
    BIGNUM_auto *k = BN_new();
    size_t len = 0;

    if (!ctx || !pp || !acc || !tmp || !k)
        return NULL;

    if (BN_zero(k) <= 0)
        return NULL;

    len = jose_b64_dec(p, NULL, 0);
    if (len == SIZE_MAX)
        return NULL;

    for (size_t i = 0; i < npnts; i++) {
        BIGNUM_auto *xo = NULL; /* Outer X */
        BIGNUM_auto *yo = NULL; /* Outer Y */

        xo = bn_decode(pnts[i], len);
        yo = bn_decode(&pnts[i][len], len);
        if (!xo || !yo)
            return NULL;

        if (BN_one(acc) <= 0)
            return NULL;

        for (size_t j = 0; j < npnts; j++) {
            BIGNUM_auto *xi = NULL; /* Inner X */

            if (i == j)
                continue;

            xi = bn_decode(pnts[j], len);
            if (!xi)
                return NULL;

            /* acc *= (0 - xi) / (xo - xi) */

            if (BN_zero(tmp) <= 0)
                return NULL;

            if (BN_mod_sub(tmp, tmp, xi, pp, ctx) <= 0)
                return NULL;

            if (BN_mod_mul(acc, acc, tmp, pp, ctx) <= 0)
                return NULL;

            if (BN_mod_sub(tmp, xo, xi, pp, ctx) <= 0)
                return NULL;

            if (BN_mod_inverse(tmp, tmp, pp, ctx) != tmp)
                return NULL;

            if (BN_mod_mul(acc, acc, tmp, pp, ctx) <= 0)
                return NULL;
        }

        /* k += acc * y[i] */

        if (BN_mod_mul(acc, acc, yo, pp, ctx) <= 0)
            return NULL;

        if (BN_mod_add(k, k, acc, pp, ctx) <= 0)
            return NULL;
    }

    return bn_encode_json(k, len);
}

enum {
    PIPE_RD = 0,
    PIPE_WR = 1
};

FILE *
call(char *const argv[], const void *buf, size_t len, pid_t *pid)
{
    int dump[2] = { -1, -1 };
    int load[2] = { -1, -1 };
    FILE *out = NULL;
    ssize_t wr = 0;

    *pid = 0;

    if (pipe2(dump, O_CLOEXEC) < 0)
        goto error;

    if (pipe2(load, O_CLOEXEC) < 0)
        goto error;

    *pid = fork();
    if (*pid < 0)
        goto error;

    if (*pid == 0) {
        if (dup2(dump[PIPE_RD], STDIN_FILENO) < 0 ||
            dup2(load[PIPE_WR], STDOUT_FILENO) < 0)
            exit(EXIT_FAILURE);

        execvp(argv[0], argv);
        exit(EXIT_FAILURE);
    }

    for (const uint8_t *tmp = buf; len > 0; tmp += wr, len -= wr) {
        wr = write(dump[PIPE_WR], tmp, len);
        if (wr < 0)
            goto error;
    }

    out = fdopen(load[PIPE_RD], "r");
    if (!out)
        goto error;

    close(dump[PIPE_RD]);
    close(dump[PIPE_WR]);
    close(load[PIPE_WR]);
    return out;

error:
    close(dump[PIPE_RD]);
    close(dump[PIPE_WR]);
    close(load[PIPE_RD]);
    close(load[PIPE_WR]);

    if (*pid > 0) {
        kill(*pid, SIGTERM);
        waitpid(*pid, NULL, 0);
        *pid = 0;
    }

    return NULL;
}
