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

#include <alloca.h>
#include <stdalign.h>
#include <stddef.h>
#include <stdint.h>

#define buf_auto_t __attribute__((cleanup(buf_cleanup))) buf_t
#define buf_auto_steal(p) ({ buf_t *__tmp = p; p = NULL; __tmp; })

typedef struct {
  size_t len;
  alignas(16) uint8_t buf[];
} buf_t;

buf_t *
buf_new(const uint8_t *data, size_t len);

void
buf_free(buf_t *buf);

void
buf_cleanup(buf_t **bufp);

buf_t *
buf_random(size_t len);
