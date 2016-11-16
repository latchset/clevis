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

#define _GNU_SOURCE
#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define _str(x) # x
#define str(x) _str(x)

int
main(int argc, char *argv[])
{
    char path[PATH_MAX] = {};
    char *cmd = NULL;
    char *args[argc];
    int r = 0;

    cmd = secure_getenv("CLEVIS_CMD_DIR");
    if (!cmd)
        cmd = str(CLEVIS_CMD_DIR);

    if (argc < 2) {
        fprintf(stderr, "Usage: %s COMMAND ...\n", argv[0]);
        return EXIT_FAILURE;
    }

    for (size_t i = 0; argv[1][i]; i++) {
        if (!isalnum(argv[1][i]) && argv[1][i] != '-') {
            fprintf(stderr, "Invalid command name: %s\n", argv[1]);
            return EXIT_FAILURE;
        }
    }

    if (!argv[1][0]) {
        fprintf(stderr, "Empty command name\n");
        return EXIT_FAILURE;
    }

    r = snprintf(path, sizeof(path), "%s/%s", cmd, argv[1]);
    if (r < 0 || (size_t) r >= sizeof(path)) {
        fprintf(stderr, "Command name too long: %s\n", argv[1]);
        return EXIT_FAILURE;
    }

    args[0] = path;
    for (int i = 2; i < argc; i++)
        args[i - 1] = argv[i];
    args[argc - 1] = NULL;

    execv(path, args);
    return EXIT_FAILURE;
}
