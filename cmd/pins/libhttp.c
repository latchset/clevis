/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */
/*
 * Copyright (c) 2016 Red Hat, Inc.
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

#include "libhttp.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

struct packet {
    size_t len;
    char buf[65507];
};

struct url {
    char    *schm;
    char    *host;
    char    *srvc;
    char    *path;
};

struct ctx {
    struct http_msg *msg;
    bool done;
};

static int
on_header_field(http_parser *parser, const char *at, size_t length)
{
    struct ctx *ctx = parser->data;
    char *key = NULL;
    size_t len = 0;

    size_t nkeys = 0;
    size_t nvals = 0;

    while (ctx->msg->head && ctx->msg->head[nkeys].key) {
        nkeys++;
        if (!ctx->msg->head[nvals].val)
            break;
        nvals++;
    }

    if (nkeys > 100)
        return -E2BIG;

    if (nkeys == nvals) {
        struct http_head *head = NULL;

        head = realloc(ctx->msg->head, sizeof(*head) * (nkeys + 2));
        if (!head)
            return -ENOMEM;

        ctx->msg->head = head;
        ctx->msg->head[nkeys].key = NULL;
        ctx->msg->head[nkeys].val = NULL;
        ctx->msg->head[nkeys + 1].key = NULL;
        ctx->msg->head[nkeys + 1].val = NULL;
    } else {
        free(ctx->msg->head[--nkeys].key);
        ctx->msg->head[nkeys].key = NULL;
    }

    len = ctx->msg->head[nkeys].key ? strlen(ctx->msg->head[nkeys].key) : 0;
    if (len + length + 1 > 4096)
        return -E2BIG;

    key = realloc(ctx->msg->head[nkeys].key, len + length + 1);
    if (!key)
        return -ENOMEM;

    strncpy(&key[len], at, length);
    key[len + length] = 0;

    ctx->msg->head[nkeys].key = key;
    return 0;
}

static int
on_header_value(http_parser *parser, const char *at, size_t length)
{
    struct ctx *ctx = parser->data;
    char *val = NULL;
    size_t len = 0;

    size_t nkeys = 0;

    while (ctx->msg->head && ctx->msg->head[nkeys].key)
        nkeys++;

    --nkeys;

    len = ctx->msg->head[nkeys].val ? strlen(ctx->msg->head[nkeys].val) : 0;
    if (len + length + 1 > 4096)
        return -E2BIG;

    val = realloc(ctx->msg->head[nkeys].val, len + length + 1);
    if (!val)
        return -ENOMEM;

    strncpy(&val[len], at, length);
    val[len + length] = 0;

    ctx->msg->head[nkeys].val = val;
    return 0;
}

static int
on_body(http_parser *parser, const char *at, size_t length)
{
    struct ctx *ctx = parser->data;
    uint8_t *body = NULL;

    if (ctx->msg->size + length > 64 * 1024)
        return -E2BIG;

    body = realloc(ctx->msg->body, ctx->msg->size + length);
    if (!body)
        return -ENOMEM;

    memcpy(&body[ctx->msg->size], at, length);
    ctx->msg->size += length;
    ctx->msg->body = body;
    return 0;
}

static int
on_message_complete(http_parser *parser)
{
    struct ctx *ctx = parser->data;
    ctx->done = true;
    return 0;
}

static const http_parser_settings settings = {
    .on_header_field = on_header_field,
    .on_header_value = on_header_value,
    .on_body = on_body,
    .on_message_complete = on_message_complete,
};

#define append(pkt, ...) \
    snprintf(&pkt->buf[pkt->len], sizeof(pkt->buf) - pkt->len, __VA_ARGS__)

static int
mkpkt(struct packet *pkt, const struct url *url,
      const char *method, const struct http_msg *msg)
{
    pkt->len += append(pkt, "%s %s HTTP/1.1\r\n", method, url->path);
    if (pkt->len > sizeof(pkt->buf))
        return E2BIG;

    pkt->len += append(pkt, "Host: %s\r\n", url->host);
    if (pkt->len > sizeof(pkt->buf))
        return E2BIG;

    pkt->len += append(pkt, "Content-Length: %zu\r\n", msg ? msg->size : 0);
    if (pkt->len > sizeof(pkt->buf))
        return E2BIG;

    if (msg && msg->head) {
        for (size_t i = 0; msg->head[i].key && msg->head[i].val; i++) {
            pkt->len += append(pkt, "%s: %s\r\n",
                               msg->head[i].key, msg->head[i].val);
            if (pkt->len > sizeof(pkt->buf))
                return E2BIG;
        }
    }

    pkt->len += append(pkt, "\r\n");
    if (pkt->len > sizeof(pkt->buf))
        return E2BIG;

    if (msg) {
        if (pkt->len + msg->size > sizeof(pkt->buf))
            return E2BIG;

        memcpy(&pkt->buf[pkt->len], msg->body, msg->size);
        pkt->len += msg->size;
    }

    return 0;
}

static void
url_free_contents(struct url *url)
{
    free(url->schm);
    free(url->host);
    free(url->srvc);
    free(url->path);
    memset(url, 0, sizeof(*url));
}

static int
url_parse(const char *url, struct url *out)
{
    static const uint16_t mask = (1 << UF_SCHEMA) | (1 << UF_HOST);
    struct http_parser_url purl = {};

    if (http_parser_parse_url(url, strlen(url), false, &purl) != 0)
        return EINVAL;

    if ((purl.field_set & mask) != mask)
        return EINVAL;

    if (purl.field_data[UF_PATH].len > PATH_MAX)
        return EINVAL;

    out->schm = strndup(&url[purl.field_data[UF_SCHEMA].off],
                        purl.field_data[UF_SCHEMA].len);

    out->host = strndup(&url[purl.field_data[UF_HOST].off],
                        purl.field_data[UF_HOST].len);

    if (purl.field_set & (1 << UF_PATH)) {
        out->path = strndup(&url[purl.field_data[UF_PATH].off],
                            purl.field_data[UF_PATH].len);
    } else {
        out->path = strdup("/");
    }

    if (purl.field_set & (1 << UF_PORT)) {
        out->srvc = strndup(&url[purl.field_data[UF_PORT].off],
                            purl.field_data[UF_PORT].len);
    } else if (out->schm) {
        out->srvc = strdup(out->schm);
    }

    if (!out->schm || !out->host || !out->path || !out->srvc) {
        url_free_contents(out);
        return ENOMEM;
    }

    return 0;
}

void
http_msg_free(struct http_msg *msg)
{
    if (!msg)
        return;

    for (size_t i = 0; msg->head && msg->head[i].key; i++) {
        memset(msg->head[i].key, 0, strlen(msg->head[i].key));
        if (msg->head[i].val)
            memset(msg->head[i].val, 0, strlen(msg->head[i].val));

        free(msg->head[i].key);
        free(msg->head[i].val);
    }

    if (msg->body && msg->size > 0)
        memset(msg->body, 0, msg->size);

    free(msg->head);
    free(msg->body);
    free(msg);
}

int
http(const char *url, enum http_method m,
     const struct http_msg *req, struct http_msg **rep)
{
    struct addrinfo *ais = NULL;
    const char *method = NULL;
    struct packet pkt = {};
    struct url purl = {};
    int sock = -1;
    int r = 0;

    switch (m) {
    case HTTP_DELETE: method = "DELETE"; break;
    case HTTP_GET: method = "GET"; break;
    case HTTP_POST: method = "POST"; break;
    case HTTP_PUT: method = "PUT"; break;
    default: return -ENOTSUP;
    }

    r = url_parse(url, &purl);
    if (r != 0) {
        errno = r;
        goto egress;
    }

    r = mkpkt(&pkt, &purl, method, req);
    if (r != 0) {
        errno = r;
        goto egress;
    }

    r = getaddrinfo(purl.host, purl.srvc,
                    &(struct addrinfo) { .ai_socktype = SOCK_STREAM }, &ais);
    switch (r) {
    case 0: break;
    case EAI_AGAIN:    errno = EAGAIN;  goto egress;
    case EAI_BADFLAGS: errno = EINVAL;  goto egress;
    case EAI_FAMILY:   errno = ENOTSUP; goto egress;
    case EAI_MEMORY:   errno = ENOMEM;  goto egress;
    case EAI_SERVICE:  errno = EINVAL;  goto egress;
    default:           errno = EIO;     goto egress;
    }

    *rep = calloc(1, sizeof(**rep));
    if (!*rep)
        goto egress;

    for (const struct addrinfo *ai = ais; ai; ai = ai->ai_next) {
        struct ctx ctx = { .msg = *rep };
        http_parser parser = {};

        if (sock >= 0)
            close(sock);

        sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (sock < 0)
            continue;

        if (connect(sock, ai->ai_addr, ai->ai_addrlen) != 0)
            continue;

        if (send(sock, pkt.buf, pkt.len, 0) != (ssize_t) pkt.len)
            break;

        http_parser_init(&parser, HTTP_RESPONSE);
        parser.data = &ctx;

        memset(pkt.buf, 0, sizeof(pkt.buf));
        pkt.len = 0;

        for (ssize_t x = 1; x > 0 && !ctx.done; ) {
            size_t sz = 0;

            x = recv(sock, &pkt.buf[pkt.len], sizeof(pkt.buf) - pkt.len, 0);
            if (x < 0)
                break;

            pkt.len += x;

            sz = http_parser_execute(&parser, &settings, pkt.buf, x);
            if (parser.http_errno != 0) {
                fprintf(stderr, "Fatal error: %s: %s\n",
                        http_errno_name(parser.http_errno),
                        http_errno_description(parser.http_errno));
                errno = EINVAL;
                break;
            }

            pkt.len -= sz;
            memmove(pkt.buf, &pkt.buf[sz], pkt.len);
        }

        if (ctx.done)
            errno = -parser.status_code;

        break;
    }

egress:
    if (errno > 0) {
        http_msg_free(*rep);
        *rep = NULL;
    }

    url_free_contents(&purl);
    freeaddrinfo(ais);
    if (sock >= 0)
        close(sock);
    return -errno;
}
