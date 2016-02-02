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

#include "clevis.h"

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/evp.h>

static inline clevis_buf_t *
buf_init(clevis_buf_t *buf, size_t len, const uint8_t *key)
{
  if (buf) {
    buf->len = len;
    if (key)
      memcpy(buf->buf, key, len);
    else
      memset(buf->buf, 0, len);
  }

  return buf;
}

clevis_buf_t *
clevis_buf_make(size_t len, const uint8_t *key)
{
  size_t size = offsetof(clevis_buf_t, buf) + len;
  clevis_buf_t *tmp = NULL;

  tmp = malloc(size);
  if (!tmp)
    return NULL;

  if (mlock(tmp, size) != 0) {
    free(tmp);
    return NULL;
  }

  return buf_init(tmp, len, key);
}

clevis_buf_t *
clevis_buf_rand(size_t len)
{
  clevis_buf_t *tmp = NULL;
  ssize_t r;
  int fd;

  if (len == 0)
    return NULL;

  tmp = clevis_buf_make(len, NULL);
  if (!tmp)
    return NULL;

  fd = open("/dev/urandom", O_RDONLY);
  if (fd < 0) {
    clevis_buf_free(tmp);
    return NULL;
  }

  for (size_t bytes = 0; bytes < tmp->len; ) {
    r = read(fd, &tmp->buf[bytes], tmp->len - bytes);
    if (r <= 0) {
      clevis_buf_free(tmp);
      close(fd);
      return NULL;
    }

    bytes += r;
  }

  close(fd);
  return tmp;
}

void
clevis_buf_free(clevis_buf_t *key)
{
  if (!key)
    return;

  memset(key, 0, key->len + offsetof(clevis_buf_t, buf));
  munlock(key, key->len + offsetof(clevis_buf_t, buf));
  free(key);
}

json_t *
clevis_buf_encode(const clevis_buf_t *buf)
{
  json_t *out = NULL;
  BIO *mem = NULL;
  BIO *b64 = NULL;
  char *c = NULL;
  int r = 0;

  mem = BIO_new(BIO_s_mem());
  if (!mem)
    goto egress;

  b64 = BIO_new(BIO_f_base64());
  if (!b64)
    goto egress;

  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  if (!BIO_push(b64, mem))
    goto egress;

  r = BIO_write(b64, buf->buf, buf->len);
  if (r != (int) buf->len)
    goto egress;

  BIO_flush(b64);

  r = BIO_get_mem_data(mem, &c);
  out = json_stringn(c, r);

egress:
  BIO_free(b64);
  BIO_free(mem);
  return out;
}

clevis_buf_t *
clevis_buf_decode(const json_t *json)
{
  clevis_buf_t *tmp = NULL;
  clevis_buf_t *out = NULL;
  BIO *mem = NULL;
  BIO *b64 = NULL;
  int r = 0;

  if (!json_is_string(json))
    return NULL;

  tmp = clevis_buf_make(json_string_length(json), NULL);
  if (!tmp)
    return NULL;

  mem = BIO_new_mem_buf((void *) json_string_value(json), -1);
  if (!mem)
    goto error;

  b64 = BIO_new(BIO_f_base64());
  if (!b64)
    goto error;

  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  if (!BIO_push(b64, mem))
    goto error;

  r = BIO_read(b64, tmp->buf, tmp->len);
  if ((r + 2) / 3 * 4 != (int) json_string_length(json))
    goto error;

  out = clevis_buf_make(r, tmp->buf);

error:
  clevis_buf_free(tmp);
  BIO_free(b64);
  BIO_free(mem);
  return out;
}
