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
#include "clevis.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

struct clevis_pwd_t {
  const clevis_acquire_f *funcs;
  const json_t *data;
  clevis_buf_t *out;
};

static bool
verify(const clevis_buf_t *pwd, clevis_pwd_t *arg)
{
  clevis_decrypt_result_t result = arg->funcs->decrypt(pwd, arg->data);
  if (result.result == DECRYPT_SUCCESS)
    arg->out = result.pt;
  return result.result != DECRYPT_FAIL_TRYAGAIN;
}

static json_t *
provision(const clevis_provision_f *funcs,
          const json_t *cfg, const clevis_buf_t *key)
{
  clevis_buf_t *passwd = NULL;
  const json_t *name = NULL;
  char *prompt = NULL;
  json_t *out = NULL;
  char *pwd = NULL;

  name = json_object_get(cfg, "name");
  if (!json_is_string(name))
    return NULL;

  if (asprintf(&prompt, "Password (%s): ", json_string_value(name)) < 0)
    return NULL;

  pwd = getpass(prompt);
  free(prompt);
  if (!pwd)
    return NULL;

  passwd = clevis_buf_make(strlen(pwd), (uint8_t *) pwd);
  if (!passwd)
    return NULL;

  out = funcs->encrypt(passwd, key);
  clevis_buf_free(passwd);
  return out;
}

static clevis_buf_t *
acquire(const clevis_acquire_f *funcs, const json_t *data)
{
  clevis_pwd_t arg = { funcs, data, NULL };
  clevis_buf_t *key = NULL;

  if (!funcs->password(true, verify, &arg))
    return NULL;

  clevis_buf_free(key);
  return arg.out;
}

clevis_pin_f CLEVIS_PIN = {
  .provision = provision,
  .acquire = acquire
};
