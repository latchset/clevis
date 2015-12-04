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

#pragma once

#include <openssl/bn.h>
#include "../json.h"

#define sss_auto_t __attribute__((cleanup(sss_cleanup))) sss_t
#define sss_auto_steal(p) ({ sss_t *__tmp = p; p = NULL; __tmp; })

typedef struct sss sss_t;

sss_t *
sss_generate(json_t *key_bytes, json_t *threshold);

json_t *
sss_k(const sss_t *sss);

json_t *
sss_p(const sss_t *sss);

buf_t *
sss_y(const sss_t *sss, uint64_t x, BN_CTX *ctx);

void
sss_free(sss_t *sss);

void
sss_cleanup(sss_t **sssp);

json_t *
sss_recover(const json_t *p, const json_t *points, BN_CTX *ctx);

