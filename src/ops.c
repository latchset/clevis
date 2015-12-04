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

#include "ops.h"
#include "kdf.h"
#include "mem.h"
#include "wrap.h"

json_t *
ops_provision(const char *branch, const json_t *cfg, const buf_t *key)
{
  json_auto_t *req = NULL;
  json_auto_t *rep = NULL;
  json_auto_t *out = NULL;
  buf_auto_t *ekey = NULL;
  buf_auto_t *ct = NULL;
  size_t key_len = 0;
  json_t *id = NULL;
  pin_t *pin = NULL;
  char *aad = NULL;

  id = json_object_get(cfg, "id");
  if (!id)
    return NULL;

  out = json_object();
  if (!out)
    return NULL;

  key_len = wrap_defaults(out, key->len);
  if (key_len == 0)
    return NULL;

  if (json_object_set(out, "id", id) < 0)
    return NULL;

  if (!kdf_defaults(out, key_len, OID_SHA512, 1024))
    return NULL;

  req = json_object();
  if (!req)
    return NULL;

  if (json_object_set_new(req, "cfg", json_deep_copy(cfg)) < 0)
    return NULL;

  if (json_object_set_new(req, "size", json_integer(key_len)) < 0)
    return NULL;

  pin = pin_start(json_string_value(id), "provision", branch, req);
  if (!pin)
    return NULL;

  rep = pin_finish(&pin);
  if (!json_is_object(rep))
    return NULL;

  ekey = json_binary_value(json_object_get(rep, "key"));
  if (!ekey || ekey->len < key_len)
    return NULL;

  if (json_object_set(out, "data", json_object_get(rep, "data")) < 0)
    return NULL;

  aad = json_dumps(out, JSON_COMPACT | JSON_SORT_KEYS);
  if (!aad)
    return NULL;

  ct = wrap_enc(out, ekey, aad, key);
  mem_free(aad);
  if (!ct)
    return NULL;

  if (json_object_set_new(out, "ct", json_binary(ct)) < 0)
    return NULL;

  return json_incref(out);
}

pin_t *
ops_acquire_start(const char *branch, const json_t *data)
{
  json_t *req = NULL;
  json_t *id = NULL;

  req = json_object_get(data, "data");
  if (!json_is_object(req))
    return NULL;

  id = json_object_get(data, "id");
  if (!json_is_string(id))
    return NULL;

  return pin_start(json_string_value(id), "acquire", branch, req);
}

buf_t *
ops_acquire_finish(pin_t **pin, const json_t *data)
{
  json_auto_t *rep = NULL;
  json_auto_t *tmp = NULL;
  buf_auto_t *ekey = NULL;
  buf_auto_t *ct = NULL;
  buf_t *pt = NULL;
  char *aad = NULL;

  rep = pin_finish(pin);
  ekey = json_binary_value(rep);
  if (!ekey)
    return NULL;

  ct = json_binary_value(json_object_get(data, "ct"));
  if (!ct)
    return NULL;

  tmp = json_deep_copy(data);
  if (!json_is_object(tmp))
    return NULL;

  if (json_object_del(tmp, "ct") < 0)
    return NULL;

  aad = json_dumps(tmp, JSON_COMPACT | JSON_SORT_KEYS);
  if (!aad)
    return NULL;

  pt = wrap_dec(data, ekey, aad, ct);
  mem_free(aad);
  return pt;
}
