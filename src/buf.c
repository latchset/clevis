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

#include "buf.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static inline buf_t *
buf_init(buf_t *buf, const uint8_t *data, size_t len)
{
  if (buf) {
    buf->len = len;
    if (data)
      memcpy(buf->buf, data, len);
    else
      memset(buf->buf, 0, len);
  }

  return buf;
}

buf_t *
buf_new(const uint8_t *data, size_t len)
{
  size_t size = offsetof(buf_t, buf) + len;
  return buf_init(malloc(size), data, len);
}

void
buf_free(buf_t *buf)
{
  if (buf)
    memset(buf, 0, buf->len + offsetof(buf_t, buf));

  free(buf);
}

void
buf_cleanup(buf_t **bufp)
{
  if (bufp)
    buf_free(*bufp);
}

buf_t *
buf_random(size_t len)
{
  buf_auto_t *tmp = NULL;
  ssize_t r;
  int fd;

  tmp = malloc(offsetof(buf_t, buf) + len);
  if (!tmp)
    return NULL;
  tmp->len = len;

  fd = open("/dev/urandom", O_RDONLY);
  if (fd < 0)
    return NULL;

  for (size_t bytes = 0; bytes < tmp->len; ) {
    r = read(fd, &tmp->buf[bytes], tmp->len - bytes);
    if (r < 0) {
      r = errno;
      close(fd);
      return NULL;
    } else if (r == 0) {
      close(fd);
      return NULL;
    }

    bytes += r;
  }

  close(fd);
  return buf_auto_steal(tmp);
}
