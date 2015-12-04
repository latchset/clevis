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

#include "json.h"

#include <string.h>

#include <errno.h>
#include <string.h>

static inline uint8_t
hex2bin(char x)
{
  switch (x) {
  case '0':
  case '1':
  case '2':
  case '3':
  case '4':
  case '5':
  case '6':
  case '7':
  case '8':
  case '9':
    return x - '0';

  case 'a':
  case 'b':
  case 'c':
  case 'd':
  case 'e':
  case 'f':
    return x - 'a' + 10;

  case 'A':
  case 'B':
  case 'C':
  case 'D':
  case 'E':
  case 'F':
    return x - 'A' + 10;

  default:
    return 0xFF;
  }
}

static inline void
bin2hex(uint8_t b, char *h)
{
  for (int i = 1; i >= 0; i--, b >>= 4) {
    unsigned char z = b & 0xF;

    if (z < 0xA)
      h[i] = '0' + z;
    else
      h[i] = 'A' + z - 10;
  }
}

json_t *
json_binary(const buf_t *bin)
{
  char hex[bin->len * 2 + 1];
  json_t *tmp = NULL;

  for (size_t i = 0; i < bin->len; i++)
    bin2hex(bin->buf[i], &hex[i * 2]);

  hex[bin->len * 2] = '\0';

  tmp = json_string(hex);
  memset(hex, 0, sizeof(hex));
  return tmp;
}

buf_t *
json_binary_value(const json_t *val)
{
  buf_auto_t *bin = NULL;
  const char *hex = NULL;

  if (!json_is_string(val))
    return NULL;

  bin = buf_new(NULL, (json_string_length(val) + 1) / 2);
  if (!bin)
    return NULL;

  hex = json_string_value(val);
  for (size_t i = 0; i < bin->len; i++) {
    char c;

    c = hex2bin(hex[i * 2 + 0]);
    if (c > 0xf) return NULL;
    bin->buf[i] = c << 4;

    c = hex2bin(hex[i * 2 + 1]);
    if (c > 0xf) return NULL;
    bin->buf[i] |= c << 0;
  }

  return buf_auto_steal(bin);
}

void
json_cleanup(json_t **val)
{
  if (val)
    json_decref(*val);
}

json_t *
json_object_fetch(const json_t *obj, const char *path)
{
  char seg[strlen(path) + 1];
  json_t *tmp = NULL;

  if (!json_is_object(obj))
    return NULL;

  memset(seg, 0, sizeof(seg));
  for (size_t i = 0; path[i] != '\0' && path[i] != '.'; i++)
    seg[i] = path[i];

  tmp = json_object_get(obj, seg);
  if (path[strlen(seg)] == '.')
    return json_object_fetch(tmp, &path[strlen(seg) + 1]);

  return tmp;
}

int
json_object_put_new(json_t *obj, const char *path, json_t *val)
{
  char seg[strlen(path) + 1];
  json_auto_t *scope = val;

  if (!json_is_object(obj))
    return -1;

  memset(seg, 0, sizeof(seg));
  for (size_t i = 0; path[i] != '\0' && path[i] != '.'; i++)
    seg[i] = path[i];

  if (path[strlen(seg)] == '.') {
    json_t *tmp = json_object_get(obj, seg);
    if (!tmp) {
      tmp = json_object();
      if (!tmp)
        return -1;

      if (json_object_set_new(obj, seg, tmp) < 0)
        return -1;
    }

    return json_object_put_new(tmp, &path[strlen(seg) + 1],
                               json_incref(scope));
  }

  return json_object_set(obj, seg, val);
}

int
json_object_default_new(json_t *obj, const char *path, json_t *def)
{
  char seg[strlen(path) + 1];
  json_auto_t *scope = def;
  json_t *tmp = NULL;

  if (!json_is_object(obj))
    return -1;

  memset(seg, 0, sizeof(seg));
  for (size_t i = 0; path[i] != '\0' && path[i] != '.'; i++)
    seg[i] = path[i];

  if (seg[0] == '\0')
    return -1;

  tmp = json_object_get(obj, seg);
  if (path[strlen(seg)] == '.') {
    if (!tmp) {
      tmp = json_object();
      if (!tmp)
        return -1;

      if (json_object_set_new(obj, seg, tmp) < 0)
        return -1;
    }

    return json_object_default_new(tmp, &path[strlen(seg) + 1],
                                   json_incref(scope));
  }

  return tmp ? 0 : json_object_set(obj, seg, def);
}
