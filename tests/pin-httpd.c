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

#include <http_parser.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct datum {
    char path[4096];
    char head[4096];
    char type[4096];
    char body[4096];
    struct datum *prev;
    struct datum *next;
    size_t blen;
    bool done;
};

struct state {
    struct datum *d;
    int s;
};

static struct datum data = { .prev = &data, .next = &data };

static int
on_url(http_parser *parser, const char *at, size_t length)
{
    struct state *state = parser->data;

    if (!state->d) {
        state->d = calloc(1, sizeof(struct datum));
        if (!state->d)
            return errno;
    }

    if (strlen(state->d->path) + length >= sizeof(state->d->path))
        return EMSGSIZE;

    strncat(state->d->path, at, length);
    return 0;
}

static int
on_header_field(http_parser *parser, const char *at, size_t length)
{
    struct state *state = parser->data;

    if (state->d->done) {
        memset(state->d->head, 0, sizeof(state->d->head));
        state->d->done = false;
    }

    if (strlen(state->d->head) + length >= sizeof(state->d->head))
        return EMSGSIZE;

    strncat(state->d->head, at, length);
    return 0;
}

static int
on_header_value(http_parser *parser, const char *at, size_t length)
{
    struct state *state = parser->data;

    state->d->done = true;
    if (strcasecmp(state->d->head, "Content-Type") != 0)
        return 0;

    if (strlen(state->d->type) + length >= sizeof(state->d->type))
        return EMSGSIZE;

    strncat(state->d->type, at, length);
    return 0;
}

static int
on_body(http_parser *parser, const char *at, size_t length)
{
    struct state *state = parser->data;

    if (state->d->blen + length > sizeof(state->d->type))
        return EMSGSIZE;

    memcpy(&state->d->body[state->d->blen], at, length);
    state->d->blen += length;
    return 0;
}

static int
on_message_complete(http_parser *parser)
{
    struct state *state = parser->data;

    switch (parser->method) {
    case HTTP_PUT:
        for (struct datum *d = data.next; d != &data; d = d->next) {
            if (strcmp(state->d->path, d->path) != 0)
                continue;

            d->prev->next = d->next;
            d->next->prev = d->prev;
            free(d);
            break;
        }

        data.next->prev = state->d;
        state->d->next = data.next;
        state->d->prev = &data;
        data.next = state->d;

        dprintf(state->s,
                "HTTP/1.1 200 OK\r\n"
                "Content-Length: 0\r\n"
                "\r\n");
        state->d = NULL;
        return 0;

    case HTTP_GET:
        for (struct datum *d = data.next; d != &data; d = d->next) {
            if (strcmp(state->d->path, d->path) != 0)
                continue;

            dprintf(state->s,
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Length: %zu\r\n"
                    "Content-Type: %s\r\n"
                    "\r\n", d->blen,
                    d->type[0] ? d->type : "application/octet-stream");

            for (size_t wrtn = 0; wrtn < d->blen; ) {
                ssize_t w = 0;

                w = write(state->s, &d->body[wrtn], d->blen - wrtn);
                if (w < 0)
                    break;

                wrtn += w;
            }

            free(state->d);
            state->d = NULL;
            return 0;
        }

        dprintf(state->s,
                "HTTP/1.1 404 Not Found\r\n"
                "Content-Length: 0\r\n"
                "\r\n");
        free(state->d);
        state->d = NULL;
        return 0;

    default:
        dprintf(state->s,
                "HTTP/1.1 405 Method Not Allowed\r\n"
                "Content-Length: 0\r\n"
                "\r\n");
        free(state->d);
        state->d = NULL;
        return 0;
    }
}

static const http_parser_settings settings = {
    .on_url = on_url,
    .on_header_field = on_header_field,
    .on_header_value = on_header_value,
    .on_body = on_body,
    .on_message_complete = on_message_complete,
};

int
main(int argc, char *argv[])
{
    union {
        struct sockaddr addr;
        struct sockaddr_in inet;
    } addr;
    int sock = -1;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s PORT\n", argv[0]);
        return EXIT_FAILURE;
    }

    addr.inet.sin_family = AF_INET;
    addr.inet.sin_port = htons(atoi(argv[1]));
    if (inet_aton("127.0.0.1", &addr.inet.sin_addr) < 0)
        return EXIT_FAILURE;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
        return EXIT_FAILURE;

    if (bind(sock, &addr.addr, sizeof(addr)) < 0) {
        close(sock);
        return EXIT_FAILURE;
    }

    if (listen(sock, 0) < 0) {
        close(sock);
        return EXIT_FAILURE;
    }

    for (;;) {
        http_parser parser = {};
        struct state state = {};
        char buf[4096] = {};
        ssize_t rcvd = -1;
        size_t have = 0;
        size_t prsd = 0;

        state.s = accept(sock, NULL, NULL);
        if (state.s < 0)
            continue;

        http_parser_init(&parser, HTTP_REQUEST);
        parser.data = &state;

        for (;;) {
            rcvd = recv(state.s, &buf[have], sizeof(buf) - have, 0);
            if (rcvd <= 0) {
                close(state.s);
                break;
            }

            have += rcvd;

            prsd = http_parser_execute(&parser, &settings, buf, have);
            if (parser.http_errno != HPE_OK) {
                close(state.s);
                break;
            }

            memmove(buf, &buf[prsd], have - prsd);
            have -= prsd;
        }
    }

    return EXIT_FAILURE;
}
