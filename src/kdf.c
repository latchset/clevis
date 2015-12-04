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

#include "kdf.h"

#include <openssl/evp.h>
#include <openssl/objects.h>

#include <strings.h>

static bool
getint(const json_t *obj, const char *name, json_int_t *out)
{
  json_t *tmp;

  tmp = json_object_get(obj, name);
  if (!json_is_integer(tmp))
    return false;

  *out = json_integer_value(tmp);
  return true;
}

static buf_t *
pbkdf2(const json_t *params, const buf_t *key)
{
  const EVP_MD *md = NULL;
  ASN1_OBJECT *obj = NULL;
  buf_auto_t *salt = NULL;
  buf_auto_t *out = NULL;
  json_int_t iter = 0;
  json_int_t size = 0;
  json_t *tmp = NULL;

  if (!json_is_object(params))
    return NULL;

  if (!getint(params, "iter", &iter))
    return NULL;

  if (!getint(params, "size", &size))
    return NULL;

  salt = json_binary_value(json_object_get(params, "salt"));
  if (!salt)
    return NULL;

  tmp = json_object_get(params, "hash");
  if (!tmp || !json_is_string(tmp))
    return NULL;
  obj = OBJ_txt2obj(json_string_value(tmp), 0);
  if (!obj)
    return NULL;
  md = EVP_get_digestbyobj(obj);
  ASN1_OBJECT_free(obj);
  if (!md)
    return NULL;

  out = buf_new(NULL, size);
  if (!out)
    return NULL;

  if (PKCS5_PBKDF2_HMAC((char *) key->buf, key->len, salt->buf, salt->len,
                        iter, md, out->len, out->buf) <= 0)
    return NULL;

  return buf_auto_steal(out);
}

bool
kdf_defaults(json_t *data, size_t size, const char *oid, size_t iter)
{
  buf_auto_t *salt = NULL;

  salt = buf_random(size);
  if (!salt)
    return false;

  if (json_object_default_new(data, "kdf.type", json_string("pbkdf2")) < 0)
    return false;

  if (json_object_default_new(data, "kdf.iter", json_integer(iter)) < 0)
    return false;

  if (json_object_default_new(data, "kdf.hash", json_string(oid)) < 0)
    return false;

  if (json_object_put_new(data, "kdf.salt", json_binary(salt)) < 0)
    return false;

  if (json_object_put_new(data, "kdf.size", json_integer(size)) < 0)
    return false;

  return true;
}

buf_t *
kdf(const json_t *data, const buf_t *in)
{
  json_t *type = NULL;
  json_t *kdf = NULL;

  kdf = json_object_get(data, "kdf");
  if (!json_is_object(kdf))
    return NULL;

  type = json_object_get(kdf, "type");
  if (!json_is_string(type))
    return NULL;

  if (strcasecmp("pbkdf2", json_string_value(type)) == 0)
    return pbkdf2(kdf, in);

  return NULL;
}
