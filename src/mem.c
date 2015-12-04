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

#include "mem.h"
#include "buf.h"

static inline buf_t *
hdr(void *mem)
{
  intptr_t addr = (intptr_t) mem;
  addr -= offsetof(buf_t, buf);
  return (buf_t *) addr;
}

void *
mem_malloc(size_t size)
{
  buf_t *buf;

  buf = buf_new(NULL, size);
  if (!buf)
    return NULL;

  return buf->buf;
}

void
mem_free(void *mem)
{
  if (mem)
    buf_free(hdr(mem));
}
