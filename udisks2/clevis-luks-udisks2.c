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

#include <udisks/udisks.h>
#include <glib-unix.h>
#include <luksmeta.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <string.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#define MAX_UDP 65507

typedef char pkt_t[MAX_UDP];

struct context {
    UDisksClient *clt;
    GMainLoop *loop;
    GList *lst;
    int sock;
};

static void
remove_path(GList **lst, const char *path)
{
    GList *i = NULL;

    while ((i = g_list_find_custom(*lst, path, (GCompareFunc) g_strcmp0))) {
        g_free(i->data);
        *lst = g_list_remove(*lst, i->data);
    }
}

#include <libgen.h>

static bool
get_decrypt_path(char *path, size_t pathl)
{
    char tmp[pathl];

    memset(tmp, 0, pathl);
    if (readlink("/proc/self/exe", tmp, sizeof(tmp) - 1) < 0)
        return false;

    if (snprintf(path, pathl, "%s/../bin/clevis-decrypt", dirname(tmp)) < 0)
        return false;

    return true;
}

static char *
unlock_device_slot(struct context *ctx, const char *dev, int slot)
{
    ssize_t len = strlen(dev) + 2;
    char path[PATH_MAX] = {};
    pkt_t pkt = {};
    gint out = -1;
    gint in = -1;

    if (len > (ssize_t) sizeof(pkt) || !get_decrypt_path(path, sizeof(path)))
        return NULL;

    pkt[0] = slot;
    memcpy(&pkt[1], dev, len - 1);

    fprintf(stderr, "%s\tSLOT\t%d\n", dev, slot);

    if (send(ctx->sock, pkt, len, 0) != len) {
        g_main_loop_quit(ctx->loop);
        return NULL;
    }

    len = recv(ctx->sock, pkt, sizeof(pkt), 0);
    if (len < 0) {
        g_main_loop_quit(ctx->loop);
        return NULL;
    }

    fprintf(stderr, "%s\tMETA\t%d\n", dev, (int) len);
    if (len < 0)
        return NULL;

    if (!g_spawn_async_with_pipes(NULL, (gchar *[]) { path, NULL }, NULL,
                                  G_SPAWN_DEFAULT, NULL, NULL, NULL,
                                  &in, &out, NULL, NULL)) {
        fprintf(stderr, "%s\tCHLD\tspawn failure\n", dev);
        return NULL;
    }

    if (write(in, pkt, len) != len) {
        fprintf(stderr, "%s\tCHLD\twrite failure\n", dev);
        close(out);
        close(in);
        return NULL;
    }

    close(in);
    len = read(out, pkt, sizeof(pkt));
    close(out);
    fprintf(stderr, "%s\tCHLD\t%s\n", dev,
            len < 0 ? "read failure" : "success");
    if (len < 0)
        return NULL;

    return strndup(pkt, len);
}

static gboolean
idle(gpointer misc)
{
    struct context *ctx = misc;
    GVariant *options = NULL;

    options = g_variant_new_parsed("@a{sv} { %s: <true> }",
                                   "auth.no_user_interaction");
    if (!options)
        goto error;

    g_variant_ref_sink(options);

    for (GList *i = ctx->lst; i; i = i->next) {
        UDisksEncrypted *enc = NULL;
        const char *path = i->data;
        UDisksObject *uobj = NULL;
        UDisksBlock *block = NULL;
        const char *dev = NULL;

        uobj = udisks_client_peek_object(ctx->clt, path);
        if (!uobj)
            continue;

        enc = udisks_object_peek_encrypted(uobj);
        if (!enc)
            continue;

        block = udisks_object_peek_block(uobj);
        if (!block)
            continue;

        dev = udisks_block_get_device(block);
        if (!dev)
            continue;

        for (int slot = 0; slot < crypt_keyslot_max(CRYPT_LUKS1); slot++) {
            gboolean success = FALSE;
            char *key = NULL;

            key = unlock_device_slot(ctx, dev, slot);
            if (!key)
                continue;

            success = udisks_encrypted_call_unlock_sync(enc, key, options,
                                                        NULL, NULL, NULL);
            memset(key, 0, strlen(key));
            free(key);
            if (success)
                break;
        }
    }

error:
    g_list_free_full(ctx->lst, g_free);
    g_variant_unref(options);
    ctx->lst = NULL;
    return FALSE;
}

static void
oadd(GDBusObjectManager *mgr, GDBusObject *obj, gpointer misc)
{
    struct context *ctx = misc;
    UDisksObject *uobj = NULL;
    const char *path = NULL;
    const char *back = NULL;
    UDisksBlock *ct = NULL;
    UDisksBlock *pt = NULL;
    GList *tmp = NULL;
    char *ptmp = NULL;

    path = g_dbus_object_get_object_path(obj);
    if (!path)
        return;

    uobj = udisks_client_peek_object(ctx->clt, path);
    if (!uobj)
        return;

    ct = udisks_object_peek_block(uobj);
    if (!ct)
        return;

    back = udisks_block_get_crypto_backing_device(ct);
    if (back)
        remove_path(&ctx->lst, back);

    if (!udisks_block_get_hint_auto(ct))
        return;

    if (!udisks_object_peek_encrypted(uobj))
        return;

    pt = udisks_client_get_cleartext_block(ctx->clt, ct);
    if (pt) {
        g_object_unref(pt);
        return;
    }

    ptmp = g_strdup(path);
    if (!ptmp)
        return;

    tmp = g_list_prepend(ctx->lst, ptmp);
    if (!tmp) {
        g_free(ptmp);
        return;
    }

    ctx->lst = tmp;
    g_idle_add(idle, ctx);
}

static void
orem(GDBusObjectManager *mgr, GDBusObject *obj, gpointer misc)
{
    struct context *ctx = misc;
    remove_path(&ctx->lst, g_dbus_object_get_object_path(obj));
}

static gboolean
sockerr(gint fd, GIOCondition cond, gpointer misc)
{
    struct context *ctx = misc;
    close(fd);
    g_main_loop_quit(ctx->loop);
    return FALSE;
}

static int
child_main(int sock)
{
    struct context ctx = { .sock = sock };
    int exit_status = EXIT_FAILURE;
    GDBusObjectManager *mgr = NULL;
    gulong id = 0;

    ctx.loop = g_main_loop_new(NULL, FALSE);
    if (!ctx.loop)
        goto error;

    ctx.clt = udisks_client_new_sync(NULL, NULL);
    if (!ctx.clt)
        goto error;

    mgr = udisks_client_get_object_manager(ctx.clt);
    if (!mgr)
        goto error;

    id = g_signal_connect(mgr, "object-added", G_CALLBACK(oadd), &ctx);
    if (id == 0)
        goto error;

    id = g_signal_connect(mgr, "object-removed", G_CALLBACK(orem), &ctx);
    if (id == 0)
        goto error;

    id = g_unix_fd_add(sock, G_IO_ERR, sockerr, &ctx);
    if (id == 0)
        goto error;

    g_main_loop_run(ctx.loop);

    exit_status = EXIT_SUCCESS;

error:
    g_list_free_full(ctx.lst, g_free);
    g_main_loop_unref(ctx.loop);
    g_object_unref(ctx.clt);
    close(sock);
    return exit_status;
}

/*
 * ==========================================================================
 *           Caution, code below this point runs with euid = 0!
 * ==========================================================================
 */

static int pair[2] = { -1, -1 };

static void
safeclose(int *fd)
{
    if (*fd >= 0)
        close(*fd);
    *fd = -1;
}

static void
on_signal(int sig)
{
    safeclose(&pair[0]);
}

static int
load(const char *dev, int slot, pkt_t pkt)
{
    static const luksmeta_uuid_t CLEVIS_LUKS_UUID = {
        0xcb, 0x6e, 0x89, 0x04, 0x81, 0xff, 0x40, 0xda,
        0xa8, 0x4a, 0x07, 0xab, 0x9a, 0xb5, 0x71, 0x5e
    };

    struct crypt_device *cd = NULL;
    luksmeta_uuid_t uuid = {};
    int r = 0;

    r = crypt_init(&cd, dev);
    if (r < 0)
        goto egress;

    r = crypt_load(cd, CRYPT_LUKS1, NULL);
    if (r < 0)
        goto egress;

    switch (crypt_keyslot_status(cd, slot)) {
    case CRYPT_SLOT_ACTIVE:
    case CRYPT_SLOT_ACTIVE_LAST:
        break;
    default:
        r = -EBADSLT;
        goto egress;
    }

    r = luksmeta_load(cd, slot, uuid, (uint8_t *) pkt, sizeof(pkt_t));
    if (r >= 0 && memcmp(uuid, CLEVIS_LUKS_UUID, sizeof(uuid)) != 0)
        r = -EBADSLT;

egress:
    crypt_free(cd);
    return r;
}

int
main(int argc, char *argv[])
{
    pid_t pid = 0;

    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, pair) == -1)
        return EXIT_FAILURE;

    pid = fork();
    if (pid < 0) {
        safeclose(&pair[0]);
        safeclose(&pair[1]);
        return EXIT_FAILURE;
    }

    if (pid == 0) {
        int status = EXIT_FAILURE;

        safeclose(&pair[0]);

        if (seteuid(getuid()) == 0)
            status = child_main(pair[1]);

        safeclose(&pair[1]);
        return status;
    }

    safeclose(&pair[1]);

    signal(SIGHUP, on_signal);
    signal(SIGINT, on_signal);
    signal(SIGPIPE, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGUSR1, on_signal);
    signal(SIGUSR2, on_signal);
    signal(SIGCHLD, on_signal);

    if (setuid(geteuid()) == -1)
        goto error;

    pkt_t pkt = {};
    int len = 0;
    while (true) {
        len = recv(pair[0], pkt, sizeof(pkt), 0);
        if (len < 2)
            goto error;

        len = load((const char *) &pkt[1], pkt[0], pkt);
        if (len >= 0) {
            len = send(pair[0], pkt, len, 0);
            memset(pkt, 0, sizeof(pkt));
            if (len > 0)
                continue;
        }

        if (send(pair[0], "", 0, 0) != 0)
            goto error;
    }

error:
    safeclose(&pair[0]);
    kill(pid, SIGTERM);
    waitpid(pid, NULL, 0);
    return EXIT_FAILURE;
}
