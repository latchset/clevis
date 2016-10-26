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

#include "readall.h"
#include <string.h>

jose_buf_t *
readall(FILE *file)
{
    jose_buf_auto_t *out = NULL;

    out = jose_buf(0, JOSE_BUF_FLAG_WIPE);
    if (!out)
        return NULL;

    while (!feof(file)) {
        jose_buf_t *tmp = NULL;
        uint8_t buf[4096];
        size_t r = 0;

        r = fread(buf, 1, sizeof(buf), file);
        if (ferror(file))
            return NULL;

        tmp = jose_buf(out->size + r, JOSE_BUF_FLAG_WIPE);
        if (!tmp)
            return NULL;

        memcpy(tmp->data, out->data, out->size);
        memcpy(&tmp->data[out->size], buf, r);
        jose_buf_decref(out);
        out = tmp;
    }

    return jose_buf_incref(out);
}
