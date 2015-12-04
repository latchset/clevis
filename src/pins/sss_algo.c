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

#include "sss_algo.h"
#include "../mem.h"

#include <openssl/bn.h>

#include <stdbool.h>

#define BIGNUM_auto __attribute__((cleanup(BN_cleanup))) BIGNUM

struct sss {
  size_t threshold;
  BIGNUM *p;
  BIGNUM *e[];
};

static void
BN_cleanup(BIGNUM **bnp)
{
  if (bnp)
    BN_clear_free(*bnp);
}

static inline buf_t *
bn2buf(const BIGNUM *bn, size_t size)
{
  buf_auto_t *buf = NULL;
  size_t off = 0;
  int r;

  r = BN_num_bytes(bn);
  if (r < 0)
    return NULL;

  if ((size_t) r < size)
    off = size - r;

  buf = buf_new(NULL, size);
  if (!buf)
    return NULL;

  r = BN_bn2bin(bn, &buf->buf[off]);
  if (r < 0)
    return NULL;

  return buf_auto_steal(buf);
}

static inline json_t *
buf2json_new(buf_t *buf)
{
  buf_auto_t *scope = buf;
  return json_binary(scope);
}

static inline bool
json2bn(const json_t *json, BIGNUM *bn)
{
  buf_auto_t *buf = NULL;

  if (!json)
    return false;

  switch (json->type) {
  case JSON_INTEGER:
    return BN_set_word(bn, json_integer_value(json)) > 0;

  case JSON_STRING:
    buf = json_binary_value(json);
    if (!buf)
      return false;

    return BN_bin2bn(buf->buf, buf->len, bn) == bn;

  default:
    return false;
  }
}

sss_t *
sss_generate(json_t *key_bytes, json_t *threshold)
{
  sss_auto_t *sss = NULL;
  json_int_t key = 0;
  json_int_t thr = 0;

  if (!json_is_integer(key_bytes) || !json_is_integer(threshold))
    return NULL;

  key = json_integer_value(key_bytes);
  thr = json_integer_value(threshold);
  if (key < 16 || thr < 1)
    return NULL;

  sss = mem_malloc(offsetof(sss_t, e) + sizeof(BIGNUM *) * thr);
  if (!sss)
    return NULL;
  sss->threshold = thr;

  sss->p = BN_new();
  if (!sss->p)
    return NULL;

  if (!BN_generate_prime(sss->p, key * 8, 1, NULL, NULL, NULL, NULL))
    return NULL;

  for (json_int_t i = 0; i < thr; i++) {
    sss->e[i] = BN_new();
    if (!sss->e[i])
      return NULL;

    if (BN_rand_range(sss->e[i], sss->p) <= 0)
      return NULL;
  }

  return sss_auto_steal(sss);
}

json_t *
sss_k(const sss_t *sss)
{
  return buf2json_new(bn2buf(sss->e[0], BN_num_bytes(sss->p)));
}

json_t *
sss_p(const sss_t *sss)
{
  return buf2json_new(bn2buf(sss->p, BN_num_bytes(sss->p)));
}

buf_t *
sss_y(const sss_t *sss, uint64_t x, BN_CTX *ctx)
{
  BIGNUM_auto *tmp = NULL;
  BIGNUM_auto *xx = NULL;
  BIGNUM_auto *yy = NULL;

  if (x == 0)
    return NULL;

  for (unsigned long i = 0; i < sss->threshold; i++) {
    if (BN_cmp(sss->p, sss->e[i]) <= 0)
      return NULL;
  }

  xx = BN_new();
  yy = BN_new();
  tmp = BN_new();
  if (!xx || !yy || !tmp)
    return NULL;

  if (BN_set_word(xx, x) <= 0)
    return NULL;

  if (BN_zero(yy) <= 0)
    return NULL;

  for (unsigned long i = 0; i < sss->threshold; i++) {

    /* y += e[i] * x^i */

    if (BN_set_word(tmp, i) <= 0)
      return NULL;

    if (BN_mod_exp(tmp, xx, tmp, sss->p, ctx) <= 0)
      return NULL;

    if (BN_mod_mul(tmp, sss->e[i], tmp, sss->p, ctx) <= 0)
      return NULL;

    if (BN_mod_add(yy, yy, tmp, sss->p, ctx) <= 0)
      return NULL;
  }

  return bn2buf(yy, BN_num_bytes(sss->p));
}

void
sss_free(sss_t *sss)
{
  if (sss) {
    BN_clear_free(sss->p);
    for (size_t i = 0; i < sss->threshold; i++)
      BN_clear_free(sss->e[i]);
  }

  mem_free(sss);
}

void
sss_cleanup(sss_t **sssp)
{
  if (sssp)
    sss_free(*sssp);
}

json_t *
sss_recover(const json_t *p, const json_t *points, BN_CTX *ctx)
{
  BIGNUM_auto *acc = NULL;
  BIGNUM_auto *tmp = NULL;
  BIGNUM_auto *pp = NULL;
  BIGNUM_auto *xi = NULL;
  BIGNUM_auto *xj = NULL;
  BIGNUM_auto *yi = NULL;
  BIGNUM_auto *k = NULL;

  if (!json_is_array(points))
    return NULL;

  acc = BN_new();
  tmp = BN_new();
  pp = BN_new();
  xi = BN_new();
  xj = BN_new();
  yi = BN_new();
  k = BN_new();
  if (!acc || !tmp || !pp || !xi || !xj || !yi || !k)
    return NULL;

  if (!json2bn(p, pp))
    return NULL;

  if (BN_zero(k) <= 0)
    return NULL;

  for (unsigned long i = 0; i < json_array_size(points); i++) {
    if (BN_one(acc) <= 0)
      return NULL;

    if (!json2bn(json_array_get(json_array_get(points, i), 0), xi))
      return NULL;
    if (!json2bn(json_array_get(json_array_get(points, i), 1), yi))
      return NULL;

    for (unsigned long j = 0; j < json_array_size(points); j++) {
      if (j == i)
        continue;

      if (!json2bn(json_array_get(json_array_get(points, j), 0), xj))
        return NULL;

      /* acc *= (0 - x[j]) / (x[i] - x[j]) */

      if (BN_zero(tmp) <= 0)
        return NULL;

      if (BN_mod_sub(tmp, tmp, xj, pp, ctx) <= 0)
       	return NULL;

      if (BN_mod_mul(acc, acc, tmp, pp, ctx) <= 0)
        return NULL;

      if (BN_mod_sub(tmp, xi, xj, pp, ctx) <= 0)
        return NULL;

      if (BN_mod_inverse(tmp, tmp, pp, ctx) != tmp)
        return NULL;

      if (BN_mod_mul(acc, acc, tmp, pp, ctx) <= 0)
        return NULL;
    }

    /* k += acc * y[i] */

    if (BN_mod_mul(acc, acc, yi, pp, ctx) <= 0)
      return NULL;

    if (BN_mod_add(k, k, acc, pp, ctx) <= 0)
      return NULL;
  }

  return buf2json_new(bn2buf(k, BN_num_bytes(pp)));
}
