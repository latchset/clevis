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
#include <jansson.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <string.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <libaudit.h>
#include <getopt.h>
#include <pwd.h>
#include <grp.h>

#define MAX_UDP 65507
#define UERR ((uid_t) -1)
#define GERR ((gid_t) -1)

#define UUID_TMPL \
    "%02hhx%02hhx%02hhx%02hhx-" \
    "%02hhx%02hhx-%02hhx%02hhx-%02hhx%02hhx-" \
    "%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx"

#define UUID_ARGS(u) \
    u[0x0], u[0x1], u[0x2], u[0x3], u[0x4], u[0x5], u[0x6], u[0x7], \
    u[0x8], u[0x9], u[0xa], u[0xb], u[0xc], u[0xd], u[0xe], u[0xf]

typedef struct {
    ssize_t used;
    char data[MAX_UDP];
} pkt_t;

enum {
    PIPE_RD = 0,
    PIPE_WR = 1
};

struct context {
    UDisksClient *clt;
    GMainLoop *loop;
    GList *lst;
    int sock;
};

static const luksmeta_uuid_t CLEVIS_LUKS_UUID = {
    0xcb, 0x6e, 0x89, 0x04, 0x81, 0xff, 0x40, 0xda,
    0xa8, 0x4a, 0x07, 0xab, 0x9a, 0xb5, 0x71, 0x5e
};

static void
remove_path(GList **lst, const char *path)
{
    GList *i = NULL;

    while ((i = g_list_find_custom(*lst, path, (GCompareFunc) g_strcmp0))) {
        *lst = g_list_remove(*lst, i->data);
        g_free(i->data);
    }
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
        pkt_t pkt = {};

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

        pkt.used = strlen(dev) + 1;
        if ((size_t) pkt.used > sizeof(pkt.data))
            continue;

        strcpy(pkt.data, dev);

        if (send(ctx->sock, pkt.data, pkt.used, 0) != pkt.used) {
            g_main_loop_quit(ctx->loop);
            break;
        }

        memset(&pkt, 0, sizeof(pkt));

        pkt.used = recv(ctx->sock, pkt.data, sizeof(pkt.data), 0);
        if (pkt.used == 0)
            continue;
        else if (pkt.used < 0 || (size_t) pkt.used >= sizeof(pkt.data)) {
            g_main_loop_quit(ctx->loop);
            break;
        }

        /* NOTE: pkt.data is now implicitly NULL terminated regardless of
         * whether or not the plaintext inside the JWE was terminated. */

        udisks_encrypted_call_unlock_sync(enc, pkt.data, options,
                                          NULL, NULL, NULL);
        memset(&pkt, 0, sizeof(pkt));
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
pid_t pid = 0;

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
    if (sig == SIGCHLD) {
        if (wait(NULL) != pid)
            return;
        pid = -1;
    }

    safeclose(&pair[0]);
}

static ssize_t
recover_key(const pkt_t *jwe, char *out, size_t max, uid_t uid, gid_t gid)
{
    int push[2] = { -1, -1 };
    int pull[2] = { -1, -1 };
    ssize_t bytes = 0;
    pid_t chld = 0;

    if (pipe(push) != 0)
        goto error;

    if (pipe(pull) != 0)
        goto error;

    chld = fork();
    if (chld < 0)
        goto error;

    if (chld == 0) {
        char *const env[] = { "PATH=" BINDIR, NULL };
        int r = 0;

        if (geteuid() != 0) {
            if (setgroups(1, &gid) != 0) {
                /* Can fail if missing permissions */
            }
        }

        if (setgid(gid) != 0)
            exit(EXIT_FAILURE);

        if (setuid(uid) != 0)
            exit(EXIT_FAILURE);

        r = dup2(push[PIPE_RD], STDIN_FILENO);
        if (r != STDIN_FILENO)
            exit(EXIT_FAILURE);

        r = dup2(pull[PIPE_WR], STDOUT_FILENO);
        if (r != STDOUT_FILENO)
            exit(EXIT_FAILURE);

        safeclose(&push[PIPE_RD]);
        safeclose(&push[PIPE_WR]);
        safeclose(&pull[PIPE_RD]);
        safeclose(&pull[PIPE_WR]);

        execle(BINDIR "/clevis", "clevis", "decrypt", NULL, env);
        exit(EXIT_FAILURE);
    }

    safeclose(&push[PIPE_RD]);
    safeclose(&pull[PIPE_WR]);

    bytes = write(push[PIPE_WR], jwe->data, jwe->used);
    safeclose(&push[PIPE_WR]);
    if (bytes < 0 || bytes != jwe->used) {
        errno = errno == 0 ? EIO : errno;
        kill(chld, SIGTERM);
        goto error;
    }

    bytes = 0;
    for (ssize_t block = 1; block > 0; bytes += block) {
        block = read(pull[PIPE_RD], &out[bytes], max - bytes);
        if (block < 0) {
            kill(chld, SIGTERM);
            goto error;
        }
    }

    safeclose(&pull[PIPE_RD]);
    return bytes;

error:
    safeclose(&push[PIPE_RD]);
    safeclose(&push[PIPE_WR]);
    safeclose(&pull[PIPE_RD]);
    safeclose(&pull[PIPE_WR]);
    return -errno;
}

static bool
log_attempt(int log, struct crypt_device *cd, bool success)
{
    const char *uuid = NULL;
    char msg[4096] = {};
    char *dev = NULL;
    int r = 0;

    uuid = crypt_get_uuid(cd);
    if (!uuid)
        return false;

    dev = audit_encode_nv_string("device", crypt_get_device_name(cd), 0);
    if (!dev)
        return false;

    r = snprintf(msg, sizeof(msg),
                 "op=recovered-key-for uuid=%s %s",
                 uuid, dev);
    free(dev);
    if (r < 0 || r == sizeof(msg))
        return false;

    return audit_log_user_message(log, AUDIT_USER_DEVICE, msg,
                                  NULL, NULL, NULL, success) > 0;
}

static const char *sopts = "hu:g:";
static const struct option lopts[] = {
    { "help",   no_argument,       .val = 'h' },
    { "user",   required_argument, .val = 'u' },
    { "group",  required_argument, .val = 'g' },
    {}
};

static uid_t
usr2uid(const char *usr)
{
    const struct passwd *tmp = getpwnam(usr);
    return tmp ? tmp->pw_uid : UERR;
}

static gid_t
grp2gid(const char *grp)
{
    const struct group *tmp = getgrnam(grp);
    return tmp ? tmp->gr_gid : GERR;
}

static bool
token_to_jwe(const char *json, pkt_t *pkt)
{
    json_auto_t *tokn = NULL;
    const json_t *jwe = NULL;
    const char *prt = NULL;
    const char *key = NULL;
    const char *tag = NULL;
    const char *iv = NULL;
    const char *ct = NULL;

    tokn = json_loads(json, 0, NULL);
    if (!tokn)
        return false;

    jwe = json_object_get(tokn, "jwe");
    if (!jwe)
        return false;

    if (json_unpack((json_t *) jwe, "{s:s,s:s,s:s,s:s,s:s}",
                    "protected", &prt, "encrypted_key", &key, "iv", &iv,
                    "ciphertext", &ct, "tag", &tag) < 0)
        return false;

    pkt->used = snprintf(pkt->data, sizeof(pkt->data),
                         "%s.%s.%s.%s.%s", prt, key, iv, ct, tag);
    if (pkt->used < 0 || (size_t) pkt->used > sizeof(pkt->data))
        return false;

    pkt->used--; /* Remove null terminator. */
    return true;
}

int
main(int argc, char *const argv[])
{
    gid_t recg = grp2gid(CLEVIS_GROUP); /* Recovery group */
    uid_t recu = usr2uid(CLEVIS_USER);  /* Recovery user */
    gid_t unlg = getgid();              /* Unlock group */
    uid_t unlu = getuid();              /* Unlock user */
    int log = -1;

    if (recu == UERR) {
        fprintf(stderr, "Invalid user name '%s'!\n", CLEVIS_USER);
        return EXIT_FAILURE;
    }

    if (recg == GERR) {
        fprintf(stderr, "Invalid group name '%s'!\n", CLEVIS_GROUP);
        return EXIT_FAILURE;
    }

    if (geteuid() != 0) {
        fprintf(stderr, "Root privileges required!\n");
        return EXIT_FAILURE;
    }

    for (int c; (c = getopt_long(argc, argv, sopts, lopts, NULL)) >= 0; ) {
        switch (c) {
        case 'u':
            if (getuid() != 0) {
                fprintf(stderr, "You can only specify the user as root!\n");
                return EXIT_FAILURE;
            }

            unlu = usr2uid(optarg);
            if (unlu == 0 || unlu == UERR) {
                fprintf(stderr, "Invalid user name '%s'!\n", optarg);
                return EXIT_FAILURE;
            }
            break;

        case 'g':
            if (getuid() != 0) {
                fprintf(stderr, "You can only specify the group as root!\n");
                return EXIT_FAILURE;
            }

            unlg = grp2gid(optarg);
            if (unlg == 0 || unlg == GERR) {
                fprintf(stderr, "Invalid group name '%s'!\n", optarg);
                return EXIT_FAILURE;
            }
            break;

        default:
            fprintf(stderr, "Usage: clevis-luks-udisks2 [-u USER -g GROUP]\n");
            return EXIT_FAILURE;
        }
    }

    if (unlu == 0 || unlg == 0) {
        fprintf(stderr, "Either run as SETUID=root or use -u/-g!\n");
        return EXIT_FAILURE;
    }

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

        if (setgid(unlg) == 0 && setegid(unlg) == 0 &&
            setuid(unlu) == 0 && seteuid(unlu) == 0)
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

    if (setgid(0) == -1 || setegid(0) == -1 ||
        setuid(0) == -1 || seteuid(0) == -1)
        goto error;

    log = audit_open();
    if (log < 0)
        goto error;

    for (pkt_t req = {}, jwe = {}, key = {}; ; key = (pkt_t) {}) {
        struct crypt_device *cd = NULL;

        /* Receive a request. Ensure that it is null terminated. */
        req.used = recv(pair[0], req.data, sizeof(req.data), 0);
        if (req.used < 1 || req.data[req.used - 1])
            break;

        if (crypt_init(&cd, req.data) < 0)
            goto next;

        if (crypt_load(cd, CRYPT_LUKS1, NULL) >= 0) {
            const int slotlen = crypt_keyslot_max(CRYPT_LUKS1);
            luksmeta_uuid_t uuid = {};

            for (uint8_t s = 0; s < slotlen && key.used <= 0; s++) {
                fprintf(stderr, "%s\tSLOT\t%hhu\n", req.data, s);
                switch (crypt_keyslot_status(cd, s)) {
                case CRYPT_SLOT_ACTIVE:
                case CRYPT_SLOT_ACTIVE_LAST:
                    break;
                default:
                    continue;
                }

                jwe.used = luksmeta_load(cd, s, uuid, jwe.data, sizeof(jwe.data));
                fprintf(stderr, "%s\tMETA\t%s\n",
                        req.data, strerror(jwe.used < 0 ? -jwe.used : 0));
                if (jwe.used <= 0)
                    continue;

                fprintf(stderr, "%s\tUUID\t" UUID_TMPL "\n",
                        req.data, UUID_ARGS(uuid));
                if (memcmp(uuid, CLEVIS_LUKS_UUID, sizeof(uuid)) != 0)
                    continue;

                /* Recover the key from the JWE. */
                key.used = recover_key(&jwe, key.data, sizeof(key.data), recu, recg);
                fprintf(stderr, "%s\tRCVR\t%s (%zd)\n", req.data,
                        strerror(key.used < 0 ? -key.used : 0), key.used);
            }
        } else if (crypt_load(cd, CRYPT_LUKS2, NULL) >= 0) {
            for (int t = 0; key.used <= 0; t++) {
                const char *json = NULL;
                const char *type = NULL;
                int r = 0;

                r = crypt_token_status(cd, t, &type);
                if (r == CRYPT_TOKEN_INVALID)
                    break;
                else if (r != CRYPT_TOKEN_EXTERNAL_UNKNOWN)
                    continue;

                fprintf(stderr, "%s\tTOKN\t%d\t%s\n", req.data, t, type);
                if (strcmp(type, "clevis") != 0)
                    continue;

                r = crypt_token_json_get(cd, t, &json);
                fprintf(stderr, "%s\tMETA\t%s\n",
                        req.data, strerror(r < 0 ? -r : 0));

                if (!token_to_jwe(json, &jwe))
                    continue;

                /* Recover the key from the JWE. */
                key.used = recover_key(&jwe, key.data, sizeof(key.data), recu, recg);
                fprintf(stderr, "%s\tRCVR\t%s (%zd)\n", req.data,
                        strerror(key.used < 0 ? -key.used : 0), key.used);
            }
        }

        if (key.used < 0)
            key.used = 0;

        /* Don't return the key unless auditing succeeds. */
        if (!log_attempt(log, cd, key.used > 0))
            memset(&key, 0, sizeof(key));

next:
        crypt_free(cd);

        /* Send the key as a reply. */
        if (send(pair[0], key.data, key.used, 0) != key.used)
            break;
    }

error:
    safeclose(&log);
    safeclose(&pair[0]);
    if (pid != -1) {
        kill(pid, SIGTERM);
        waitpid(pid, NULL, 0);
    }
    return EXIT_FAILURE;
}
