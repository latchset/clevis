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

#include <jose/jose.h>

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int
main(int argc, char *argv[])
{
    char path[PATH_MAX] = {};
    json_auto_t *jwe = NULL;
    json_auto_t *hdr = NULL;
    const char *pin = NULL;
    int fds[] = { -1, -1 };
    char *end = NULL;
    pid_t pid = 0;

    jwe = json_loadf(stdin, 0, NULL);
    if (!jwe || argc != 1) {
        fprintf(stderr, "Usage: %s < JWE\n", argv[0]);
        return EXIT_FAILURE;
    }

    hdr = jose_jwe_merge_header(jwe, NULL);
    if (!hdr) {
        fprintf(stderr, "Error mergint JWE header!\n");
        return EXIT_FAILURE;
    }

    if (json_unpack(hdr, "{s:s}", "clevis.pin", &pin) != 0) {
        fprintf(stderr, "JWE header missing clevis.pin!\n");
        return EXIT_FAILURE;
    }

    if (readlink("/proc/self/exe", path, sizeof(path) - 1) < 0)
        return EXIT_FAILURE;

    end = strrchr(path, '-');
    if (!end)
        return EXIT_FAILURE;

    end[1] = 0;

    if (strlen(path) + strlen("pin-") + strlen(pin) >= sizeof(path))
        return EXIT_FAILURE;

    strcat(path, "pin-");
    strcat(path, pin);

    if (pipe(fds) < 0)
        return EXIT_FAILURE;

    pid = fork();
    if (pid == 0) {
        FILE *file = NULL;

        file = fdopen(fds[1], "a");
        close(fds[0]);
        if (!file) {
            close(fds[1]);
            return EXIT_FAILURE;
        }

        json_dumpf(jwe, file, JSON_SORT_KEYS | JSON_COMPACT);
        fclose(file);
        return EXIT_SUCCESS;
    }

    dup2(fds[0], STDIN_FILENO);
    close(fds[0]);
    close(fds[1]);
    execl(path, path, "decrypt", NULL);
    return EXIT_FAILURE;
}
