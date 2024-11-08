/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */
/*
 * Copyright (c) 2024 Oldřich Jedlička
 *
 * Author: Oldřich Jedlička <oldium.pro@gmail.com>
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

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define TCSD_NO_PRIVILEGE_DROP_ENV "TCSD_NO_PRIVILEGE_DROP"

static int
no_privilege_drop(void)
{
    char *no_privilege_drop_env = getenv(TCSD_NO_PRIVILEGE_DROP_ENV);
    return (no_privilege_drop_env != NULL
            && no_privilege_drop_env[0] != '\0'
            && no_privilege_drop_env[0] != '0');
}

int
setuid(uid_t uid)
{
    static int (*real_setuid)(uid_t) = NULL;
    if (no_privilege_drop()) {
        return 0;
    } else {
        if (!real_setuid) {
            real_setuid = dlsym(RTLD_NEXT, "setuid");
        }
        return real_setuid(uid);
    }
}

int
setgid(gid_t gid)
{
    static int (*real_setgid)(gid_t) = NULL;
    if (no_privilege_drop()) {
        return 0;
    } else {
        if (!real_setgid) {
            real_setgid = dlsym(RTLD_NEXT, "setgid");
        }
        return real_setgid(gid);
    }
}

static void __attribute ((constructor))
set_line_buffering(void)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
}
