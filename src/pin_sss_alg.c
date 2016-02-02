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

#include "pin_sss_alg.h"

#include <openssl/bn.h>

#include <stdbool.h>
#include <stddef.h>

#define BIGNUM_auto __attribute__((cleanup(BN_cleanup))) BIGNUM

struct sss_t {
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

static inline clevis_buf_t *
bn2buf(const BIGNUM *bn, size_t size)
{
  clevis_buf_t *buf = NULL;
  size_t off = 0;
  int r;

  r = BN_num_bytes(bn);
  if (r < 0)
    return NULL;

  if ((size_t) r < size)
    off = size - r;

  buf = clevis_buf_make(size, NULL);
  if (!buf)
    return NULL;

  r = BN_bn2bin(bn, &buf->buf[off]);
  if (r < 0) {
    clevis_buf_free(buf);
    return NULL;
  }

  return buf;
}

static inline bool
buf2bn(const clevis_buf_t *buf, BIGNUM *bn)
{
  return BN_bin2bn(buf->buf, buf->len, bn) == bn;
}

sss_t *
sss_generate(size_t key_bytes, size_t threshold)
{
  sss_t *sss = NULL;

  if (key_bytes == 0 || threshold < 1)
    return NULL;

  sss = malloc(offsetof(sss_t, e) + sizeof(BIGNUM *) * threshold);
  if (!sss)
    return NULL;
  sss->threshold = threshold;

  sss->p = BN_new();
  if (!sss->p)
    goto error;

  if (!BN_generate_prime(sss->p, key_bytes * 8, 1, NULL, NULL, NULL, NULL))
    goto error;

  for (size_t i = 0; i < threshold; i++) {
    sss->e[i] = BN_new();
    if (!sss->e[i])
      goto error;

    if (BN_rand_range(sss->e[i], sss->p) <= 0)
      goto error;
  }

  return sss;

error:
  sss_free(sss);
  return NULL;
}

clevis_buf_t *
sss_p(const sss_t *sss)
{
  return bn2buf(sss->p, BN_num_bytes(sss->p));
}

clevis_buf_t *
sss_y(const sss_t *sss, size_t x, BN_CTX *ctx)
{
  BIGNUM_auto *tmp = NULL;
  BIGNUM_auto *xx = NULL;
  BIGNUM_auto *yy = NULL;

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

  free(sss);
}

clevis_buf_t *
sss_recover(const clevis_buf_t *p, const list_t *points, BN_CTX *ctx)
{
  BIGNUM_auto *acc = BN_new();
  BIGNUM_auto *tmp = BN_new();
  BIGNUM_auto *pp = BN_new();
  BIGNUM_auto *xo = BN_new(); /* Outer X */
  BIGNUM_auto *yo = BN_new(); /* Outer Y */
  BIGNUM_auto *xi = BN_new(); /* Inner X */
  BIGNUM_auto *k = BN_new();

  if (!acc || !tmp || !pp || !xo || !yo || !xi || !k)
    return NULL;

  if (!buf2bn(p, pp))
    return NULL;

  if (BN_zero(k) <= 0)
    return NULL;

  LIST_FOREACH(points, sss_point_t, pnto, list) {
    if (BN_one(acc) <= 0)
      return NULL;

    if (BN_set_word(xo, pnto->x) <= 0)
      return NULL;
    if (!buf2bn(pnto->y, yo))
      return NULL;

    LIST_FOREACH(points, sss_point_t, pnti, list) {
      if (pnto == pnti)
        continue;

      if (BN_set_word(xi, pnti->x) <= 0)
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

  return bn2buf(k, BN_num_bytes(pp));
}
