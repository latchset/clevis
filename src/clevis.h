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
#include <stdalign.h>
#include <stdbool.h>
#include <stdint.h>

#define CLEVIS_PIN clevis_pin

typedef struct clevis_provision_f clevis_provision_f;
typedef struct clevis_acquire_f clevis_acquire_f;
typedef struct clevis_buf_f clevis_buf_f;
typedef struct clevis_pin_f clevis_pin_f;

typedef struct clevis_decrypt_result_t clevis_decrypt_result_t;
typedef struct clevis_pwd_t clevis_pwd_t;
typedef struct clevis_buf_t clevis_buf_t;

typedef bool clevis_pwd_vfy(const clevis_buf_t *pwd, clevis_pwd_t *misc);

enum decrypt_result {
  DECRYPT_SUCCESS,
  DECRYPT_FAIL_STOP,
  DECRYPT_FAIL_TRYAGAIN
};

struct clevis_decrypt_result_t {
  enum decrypt_result result;
  clevis_buf_t *pt;
};

struct clevis_provision_f {
  json_t *(*encrypt)(const clevis_buf_t *key, const clevis_buf_t *pt);
};

struct clevis_acquire_f {
  clevis_decrypt_result_t (*decrypt)(const clevis_buf_t *key, const json_t *ct);
  bool (*password)(bool lcl, clevis_pwd_vfy *vfy, clevis_pwd_t *misc);
};

struct clevis_pin_f {
  json_t *(*provision)(const clevis_provision_f *funcs,
		       const json_t *cfg, const clevis_buf_t *key);

  clevis_buf_t *(*acquire)(const clevis_acquire_f *funcs,
			   const json_t *data);
};

struct clevis_buf_t {
  size_t len;
  alignas(16) uint8_t buf[];
};

clevis_buf_t *
clevis_buf_make(size_t len, const uint8_t *raw);

clevis_buf_t *
clevis_buf_rand(size_t len);

void
clevis_buf_free(clevis_buf_t *buf);

json_t *
clevis_buf_encode(const clevis_buf_t *buf);

clevis_buf_t *
clevis_buf_decode(const json_t *json);
