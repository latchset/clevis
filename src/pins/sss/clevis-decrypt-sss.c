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
 *
 * Additional permission under GPLv3 section 7:
 *
 * In the following paragraph, "GPL" means the GNU General Public
 * License, version 3 or any later version, and "Non-GPL Code" means
 * code that is governed neither by the GPL nor a license
 * compatible with the GPL.
 *
 * You may link the code of this Program with Non-GPL Code and convey
 * linked combinations including the two, provided that such Non-GPL
 * Code only links to the code of this Program through those well
 * defined interfaces identified in the file named EXCEPTION found in
 * the source code files (the "Approved Interfaces"). The files of
 * Non-GPL Code may instantiate templates or use macros or inline
 * functions from the Approved Interfaces without causing the resulting
 * work to be covered by the GPL. Only the copyright holders of this
 * Program may make changes or additions to the list of Approved
 * Interfaces.
 */

#define _GNU_SOURCE
#include "sss.h"

#include <jose/b64.h>
#include <jose/jwe.h>

#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <libgen.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <unistd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>

struct pin {
    struct pin *prev;
    struct pin *next;
    uint8_t *pt;
    size_t ptl;
    FILE *file;
    pid_t pid;
};

static size_t
nchldrn(const struct pin *pins, bool response)
{
    size_t n = 0;

    for (const struct pin *p = pins->next; p != pins; p = p->next) {
        if (response && p->pt)
            n++;
        else if (!response)
            n++;
    }

    return n;
}

static json_t *
compact_field(FILE *file)
{
    json_t *str = NULL;
    char *buf = NULL;
    size_t used = 0;
    size_t size = 0;

    for (int c = fgetc(file); c != EOF && c != '.' && !isspace(c); c = fgetc(file)) {
        if (used >= size) {
            char *tmp = NULL;

            size += 4096;
            tmp = realloc(buf, size);
            if (!tmp)
                goto error;

            buf = tmp;
        }

        buf[used++] = c;
    }

    str = json_stringn(buf ? buf : "", buf ? used : 0);

error:
    free(buf);
    return str;
}

static json_t *
compact_jwe(FILE *file)
{
    json_auto_t *jwe = NULL;

    jwe = json_object();
    if (!jwe)
        return NULL;

    if (json_object_set_new(jwe, "protected", compact_field(file)) < 0)
        return NULL;

    if (json_object_set_new(jwe, "encrypted_key", compact_field(file)) < 0)
        return NULL;

    if (json_object_set_new(jwe, "iv", compact_field(file)) < 0)
        return NULL;

    return json_incref(jwe);
}

int
main(int argc, char *argv[])
{
    struct pin chldrn = { &chldrn, &chldrn };
    json_auto_t *pins = NULL;
    json_auto_t *hdr = NULL;
    json_auto_t *jwe = NULL;
    int ret = EXIT_FAILURE;
    json_t *p = NULL;
    json_int_t t = 1;
    int epoll = -1;
    size_t pl = 0;

    if (argc == 2 && strcmp(argv[1], "--summary") == 0)
        return EXIT_FAILURE;

    if (isatty(STDIN_FILENO) || argc != 1)
        goto usage;

    epoll = epoll_create1(EPOLL_CLOEXEC);
    if (epoll < 0)
        return ret;

    jwe = compact_jwe(stdin);
    if (!jwe)
        goto egress;

    hdr = jose_jwe_hdr(jwe, jwe);
    if (!hdr)
        goto egress;

    if (json_unpack(hdr, "{s:{s:{s:I,s:o,s:O}}}",
                    "clevis", "sss", "t", &t, "p", &p, "jwe", &pins) != 0)
        goto egress;

    if (t < 1)
        goto egress;

    pl = jose_b64_dec(p, NULL, 0);
    if (pl == SIZE_MAX)
        goto egress;

    for (size_t i = 0; i < json_array_size(pins); i++) {
        char *args[] = { "clevis", "decrypt", NULL };
        const json_t *val = json_array_get(pins, i);
        struct pin *pin = NULL;

        if (!json_is_string(val))
            goto egress;

        pin = calloc(1, sizeof(*pin));
        if (!pin)
            goto egress;

        chldrn.next->prev = pin;
        pin->next = chldrn.next;
        pin->prev = &chldrn;
        chldrn.next = pin;

        pin->file = call(args, json_string_value(val),
                         json_string_length(val), &pin->pid);
        if (!pin->file)
            goto egress;

        if (epoll_ctl(epoll, EPOLL_CTL_ADD, fileno(pin->file),
                      &(struct epoll_event) {
                          .events = EPOLLIN | EPOLLPRI,
                          .data.fd = fileno(pin->file)
                      }) < 0)
            goto egress;
    }

    json_decref(pins);
    pins = json_array();
    if (!pins)
        goto egress;

    for (struct epoll_event e; true; ) {
        int r = 0;

        r = epoll_wait(epoll, &e, 1, -1);
        if (r != 1)
            break;

        for (struct pin *pin = chldrn.next; pin != &chldrn; pin = pin->next) {
            if (!pin->file || e.data.fd != fileno(pin->file))
                continue;

            if (e.events & (EPOLLIN | EPOLLPRI)) {
                const size_t ptl = pl * 2;

                pin->pt = malloc(ptl);
                if (!pin->pt)
                    goto egress;

                while (!feof(pin->file)) {
                    uint8_t buf[ptl];
                    size_t rd = 0;

                    rd = fread(buf, 1, sizeof(buf), pin->file);
                    if (ferror(pin->file) || pin->ptl + rd > ptl) {
                        pin->ptl = 0;
                        break;
                    }

                    memcpy(&pin->pt[pin->ptl], buf, rd);
                    pin->ptl += rd;
                }

                if (pin->ptl != ptl) {
                    free(pin->pt);
                    pin->pt = NULL;
                    goto egress;
                }
            }

            fclose(pin->file);
            pin->file = NULL;

            waitpid(pin->pid, NULL, 0);
            pin->pid = 0;

            if (!pin->pt) {
                pin->next->prev = pin->prev;
                pin->prev->next = pin->next;
                free(pin);
            }

            break;
        }

        if (nchldrn(&chldrn, false) < (size_t) t ||
            nchldrn(&chldrn, true) >= (size_t) t)
            break;
    }

    if (nchldrn(&chldrn, true) >= (size_t) t) {
        jose_io_auto_t *out = NULL;
        jose_io_auto_t *dec = NULL;
        jose_io_auto_t *b64 = NULL;
        json_auto_t *cek = NULL;
        const uint8_t *xy[t];
        size_t i = 0;

        memset(xy, 0, t * sizeof(uint8_t));
        for (struct pin *pin = chldrn.next; pin != &chldrn; pin = pin->next) {
            if (pin->pt && i < (size_t) t)
                xy[i++] = pin->pt;
        }

        cek = json_pack("{s:s,s:o}", "kty", "oct", "k", sss_recover(p, t, xy));
        if (!cek)
            goto egress;

        out = jose_io_file(NULL, stdout);
        dec = jose_jwe_dec_cek_io(NULL, jwe, cek, out);
        b64 = jose_b64_dec_io(dec);
        if (!out || !dec || !b64)
            goto egress;

        for (int b = fgetc(stdin); b != EOF && b != '.'; b = fgetc(stdin)) {
            char c = b;
            if (!b64->feed(b64, &c, 1))
                goto egress;
        }

        if (json_object_set_new(jwe, "tag", compact_field(stdin)) < 0)
            goto egress;

        if (!b64->done(b64))
            goto egress;

        ret = EXIT_SUCCESS;
    }

egress:
    while (chldrn.next != &chldrn) {
        struct pin *pin = chldrn.next;

        if (pin->file)
            fclose(pin->file);

        if (pin->pid > 0) {
            kill(pin->pid, SIGTERM);
            waitpid(pin->pid, NULL, 0);
        }

        pin->next->prev = pin->prev;
        pin->prev->next = pin->next;
        free(pin->pt);
        free(pin);
    }

    close(epoll);
    return ret;

usage:
    fprintf(stderr, "\n");
    fprintf(stderr, "Usage: clevis decrypt sss < JWE > PLAINTEXT\n");
    fprintf(stderr, "\n");
    return EXIT_FAILURE;
}
