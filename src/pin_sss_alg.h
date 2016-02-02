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

#include "clevis.h"
#include "list.h"
#include <openssl/bn.h>

typedef struct sss_t sss_t;
typedef struct {
  list_t list;
  size_t x;
  clevis_buf_t *y;
} sss_point_t;

sss_t *
sss_generate(size_t key_bytes, size_t threshold);

clevis_buf_t *
sss_p(const sss_t *sss);

clevis_buf_t *
sss_y(const sss_t *sss, size_t x, BN_CTX *ctx);

void
sss_free(sss_t *sss);

clevis_buf_t *
sss_recover(const clevis_buf_t *p, const list_t *points, BN_CTX *ctx);
