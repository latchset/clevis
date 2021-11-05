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

#pragma once
#include <jansson.h>
#include <stdint.h>
#include <sys/types.h>

json_t *
sss_generate(size_t key_bytes, size_t threshold);

uint8_t *
sss_point(const json_t *sss, size_t *len);

json_t *
sss_recover(const json_t *p, size_t npnts, const uint8_t *pnts[]);

FILE *
call(char *const argv[], const void *buf, size_t len, pid_t *pid);
