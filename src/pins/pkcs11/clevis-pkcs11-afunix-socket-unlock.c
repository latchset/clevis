/*
 * Copyright (c) 2024 Red Hat, Inc.
 * Author: Sergio Arroutbi <sarroutb@redhat.com>
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
#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/prctl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#ifdef GIT_VERSION
const char* VERSION = GIT_VERSION;
#else
const char* VERSION = "v0.0.1";
#endif

#define MAX_DEVICE 1024
#define MAX_ENTRIES 1024
#define MAX_KEY 1024

const uint16_t DEFAULT_MAX_ITERATIONS = 3;
const uint16_t MAX_PATH = 1024;
const uint16_t MAX_CONTROL_MSG = 1024;
const uint8_t WAIT_CONTROL_THREAD_TIMER = 1;

// Time to wait before trying to write key
const uint16_t DEFAULT_START_DELAY = 0;

typedef struct {
    char dev[MAX_DEVICE+1];
    char key[MAX_KEY+1];
} key_entry_t;
key_entry_t keys[MAX_ENTRIES];
uint16_t entry_counter = 0;
volatile sig_atomic_t thread_loop = 1;
volatile sig_atomic_t control_thread_info = 0;
pthread_mutex_t mutex;
FILE* logfile = NULL;
static char g_sock_file[1024];
static char g_sock_control_file[1024];

static int
get_control_socket_name(const char* file_sock, char* control_sock, uint32_t control_sock_len) {
    const char *p = strstr(file_sock, ".sock");
    if (!p) {
        fprintf(stderr, "Socket file must contain '.sock' or -c must be specified\n");
        return -1;
    }
    size_t prefix_length = strlen(file_sock) - strlen(p);
    if (prefix_length + strlen(".control.sock") >= control_sock_len) {
        fprintf(stderr, "Control socket path too long\n");
        return -1;
    }
    memset(control_sock, 0, control_sock_len);
    memcpy(control_sock, file_sock, prefix_length);
    strcat(control_sock + prefix_length, ".control.sock");
    return 0;
}

static const char* get_key(const char* dev) {
    const char *result = NULL;
    pthread_mutex_lock(&mutex);
    for (int e = 0; e < entry_counter; e++) {
        if (strcmp(keys[e].dev, dev) == 0) {
            result = keys[e].key;
            break;
        }
    }
    pthread_mutex_unlock(&mutex);
    return result;
}

static void cleanup_close_fd(void *arg) {
    int fd = *(int *)arg;
    if (fd >= 0)
        close(fd);
}

static void* control_thread(void *targ) {
    struct sockaddr_un control_addr, accept_addr;
    int s, a, r;
    char control_msg[MAX_CONTROL_MSG+1];
    const char* control_sock = (const char*)targ;
    socklen_t len;
    memset(&control_addr, 0, sizeof(control_addr));
    control_addr.sun_family = AF_UNIX;
    strncpy(control_addr.sun_path, control_sock, sizeof(control_addr.sun_path)-1);
    unlink(control_sock);
    s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s == -1) {
        perror("control socket");
        fprintf(logfile, "Control socket error\n");
        pthread_exit("control socket");
    }
    pthread_cleanup_push(cleanup_close_fd, &s);
    if (bind(s, (struct sockaddr *)&control_addr, sizeof(control_addr)) == -1) {
        perror("control bind");
        fprintf(logfile, "Control bind error\n");
        pthread_exit("control bind");
    }
    if (listen(s, SOMAXCONN) == -1) {
        perror("control listen");
        fprintf(logfile, "Control listen error\n");
        pthread_exit("control listen");
    }
    while (thread_loop) {
        len = sizeof(accept_addr);
        a = accept(s, (struct sockaddr *)&accept_addr, &len);
        if (a == -1) {
            perror("control accept");
            fprintf(logfile, "Control accept\n");
            pthread_exit("control accept");
        }
        struct ucred ctrl_cred;
        socklen_t ctrl_cred_len = sizeof(ctrl_cred);
        if (getsockopt(a, SOL_SOCKET, SO_PEERCRED, &ctrl_cred, &ctrl_cred_len) == -1) {
            perror("control getsockopt SO_PEERCRED");
            close(a);
            continue;
        }
        if (ctrl_cred.uid != 0) {
            fprintf(logfile, "Rejected control connection from UID %u\n", ctrl_cred.uid);
            close(a);
            continue;
        }
        memset(control_msg, 0, MAX_CONTROL_MSG);
        if((r = recv(a, control_msg, MAX_CONTROL_MSG, 0)) < 0) {
            perror("recv error");
            fprintf(logfile, "Error on reception\n");
            close(a);
            pthread_exit("control recv");
        } else {
            control_msg[r] = '\0';
        }
        char *sep = strchr(control_msg, ',');
        if (!sep) {
            fprintf(logfile, "Invalid control message (no delimiter)\n");
            close(a);
            continue;
        }
        *sep = '\0';
        fprintf(logfile, "Adding device:%s\n", control_msg);
        pthread_mutex_lock(&mutex);
        if (entry_counter < MAX_ENTRIES) {
            strncpy(keys[entry_counter].dev, control_msg, MAX_DEVICE);
            strncpy(keys[entry_counter].key, sep + 1, MAX_KEY);
            entry_counter++;
            control_thread_info = 1;
        } else {
            fprintf(logfile, "No more entries accepted\n");
        }
        pthread_mutex_unlock(&mutex);
        close(a);
    }
    pthread_cleanup_pop(1);
    return NULL;
}

static int usage(const char* name, uint32_t ecode) {
    printf("\nUsage:\n\t%s -f socket_file [-c control_socket] "
           "[-l logfile] [-t iterations, 3 by default] "
           "[-s start delay, 0s by default] [-v(version)] [-h(help)]\n\n", name);
    exit(ecode);
}

static void dump_version(void) {
    printf("VERSION: [%s]\n", VERSION);
}

static void dump_wide_version(void) {
    printf("\n");
    dump_version();
    printf("\n");
}

static void int_handler(int sig) {
    (void)sig;
    unlink(g_sock_file);
    unlink(g_sock_control_file);
    _exit(EXIT_FAILURE);
}

int main(int argc, char* argv[]) {
    int s, a, opt;
    struct sockaddr_un sock_addr, accept_addr, peer_addr;
    socklen_t pathlen;
    char lfile[MAX_PATH];
    socklen_t len = sizeof(accept_addr);
    uint8_t wait_control_thread = 1;
    uint32_t iterations = DEFAULT_MAX_ITERATIONS;
    uint32_t startdelay = DEFAULT_START_DELAY;
    uint32_t ic = 0;
    uint32_t time = 0;
    memset(lfile, 0, MAX_PATH);
    memset(g_sock_file, 0, sizeof(g_sock_file));
    memset(g_sock_control_file, 0, sizeof(g_sock_control_file));

    struct sigaction sa = { .sa_handler = int_handler, .sa_flags = 0 };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);
    if (prctl(PR_SET_DUMPABLE, 0) == -1) {
        perror("prctl PR_SET_DUMPABLE");
        exit(EXIT_FAILURE);
    }
    for (uint16_t e = 0; e < MAX_ENTRIES; e++) {
        memset(&keys[e], 0, sizeof(key_entry_t));
    }
    while ((opt = getopt(argc, argv, "c:f:i:l:s:t:hv")) != -1) {
        int ret_code = EXIT_FAILURE;
        switch (opt) {
        case 'c':
            strncpy(g_sock_control_file, optarg, sizeof(g_sock_control_file) - 1);
            break;
        case 'f':
            strncpy(g_sock_file, optarg, sizeof(g_sock_file) - 1);
            unlink(g_sock_file);
            break;
        case 'l':
            strncpy(lfile, optarg, MAX_PATH - 1);
            int log_fd = open(lfile, O_WRONLY | O_CREAT | O_TRUNC, 0600);
            if (log_fd >= 0) {
                logfile = fdopen(log_fd, "w");
                if (!logfile)
                    close(log_fd);
            }
            break;
        case 't':
            iterations = strtoul(optarg, 0, 10);
            break;
        case 's':
            startdelay = strtoul(optarg, 0, 10);
            break;
        case 'v':
            dump_wide_version();
            exit(EXIT_SUCCESS);
            break;
        case 'h':
            ret_code = EXIT_SUCCESS;
            __attribute__ ((fallthrough));
        default:
            usage(argv[0], ret_code);
        }
    }
    if(!logfile) {
        logfile = stdout;
        strncpy(lfile, "stdout", MAX_PATH - 1);
    }
    setvbuf(logfile, NULL, _IONBF, 0);
    if(0 == strlen(g_sock_file)) {
        fprintf(logfile, "\nSocket file name must be provided\n");
        usage(argv[0], EXIT_FAILURE);
    }
    if(0 == strlen(g_sock_control_file) ) {
        if (get_control_socket_name(g_sock_file, g_sock_control_file, sizeof(g_sock_control_file)) == -1)
            exit(EXIT_FAILURE);
    }
    fprintf(logfile, "LOG FILE: [%s]\n", lfile);
    fprintf(logfile, "FILE: [%s]\n", g_sock_file);
    fprintf(logfile, "START DELAY: [%u] seconds\n", startdelay);
    fprintf(logfile, "TRY ITERATIONS: [%u]\n", iterations);
    dump_version();

    pthread_t thid;
    void* tret;
    int thread_created = 0;
    umask(0077);
    if (pthread_create(&thid, NULL, control_thread, g_sock_control_file) != 0) {
        perror("pthread_create() error");
        goto efailure;
    }
    thread_created = 1;

    memset(&sock_addr, 0, sizeof(sock_addr));
    sock_addr.sun_family = AF_UNIX;
    strncpy(sock_addr.sun_path, g_sock_file, sizeof(sock_addr.sun_path)-1);
    s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s == -1) {
        perror("socket");
        goto efailure;
    }
    if (bind(s, (struct sockaddr *)&sock_addr, sizeof(sock_addr)) == -1) {
        perror("bind");
        goto efailure;
    }
    if (listen(s, SOMAXCONN) == -1) {
        perror("listen");
        goto efailure;
    }
    while (ic < iterations) {
        if (time++ < startdelay && !control_thread_info) {
            sleep(1);
            fprintf(logfile, "Start time elapsed: [%u/%u] seconds\n",
                    time, startdelay);
            continue;
        }
        if (control_thread_info && wait_control_thread) {
            sleep(WAIT_CONTROL_THREAD_TIMER);
            fprintf(logfile, "Waiting %d second for control thread "
                    "to receive complete information\n",
                    WAIT_CONTROL_THREAD_TIMER);
            wait_control_thread = 0;
        }
        len = sizeof(accept_addr);
        a = accept(s, (struct sockaddr *)&accept_addr, &len);
        if (a == -1) {
            perror("accept");
            goto efailure;
        }
        struct ucred cred;
        socklen_t cred_len = sizeof(cred);
        if (getsockopt(a, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len) == -1) {
            perror("getsockopt SO_PEERCRED");
            close(a);
            continue;
        }
        if (cred.uid != 0) {
            fprintf(logfile, "Rejected connection from UID %u\n", cred.uid);
            close(a);
            continue;
        }
        memset(&peer_addr, 0, sizeof(peer_addr));
        len = sizeof(peer_addr);
        if (getpeername(a, (struct sockaddr *)&peer_addr, &len) == -1) {
            perror("getpeername");
            close(a);
            continue;
        }
        if (len <= offsetof(struct sockaddr_un, sun_path)) {
            fprintf(logfile, "Ignoring unbound client connection\n");
            close(a);
            continue;
        }
        pathlen = len - offsetof(struct sockaddr_un, sun_path);
        char peer[pathlen];
        memset(peer, 0, pathlen);
        strncpy(peer, peer_addr.sun_path + 1, pathlen - 1);
        fprintf(logfile, "Try: [%u/%u]\n", ic, iterations);
        fprintf(logfile, "getpeername sun_path(peer): [%s]\n", peer);
        char *t, *saveptr;
        const char* unlocking_device = "";
        for (t = strtok_r(peer, "/", &saveptr); t;
             t = strtok_r(NULL, "/", &saveptr))
            unlocking_device = t;
        fprintf(logfile, "Trying to unlock device:[%s]\n", unlocking_device);
        // Now we have all the information in peer, something like:
        // \099226072855ae2d8/cryptsetup/luks-6e38d5e1-7f83-43cc-819a-7416bcbf9f84
        // NUL random /cryptsetup/ DEVICE
        // If we need to unencrypt device, pick it from peer information
        // To return the key, just respond to socket returned by accept
        const char* entry_key;
        if((entry_key = get_key(unlocking_device))) {
            if (send(a, entry_key, strlen(entry_key), 0) < 0) {
                perror("key send error");
                goto efailure;
            }
            fprintf(logfile, "Sending passphrase to device:[%s]\n",
                    unlocking_device);
        } else {
            fprintf(logfile, "Device not found: [%s]\n", unlocking_device);
        }
        close(a);
        ic++;
    }
    fprintf(logfile, "Closing (max tries reached)\n");
    thread_loop = 0;
    pthread_cancel(thid);
    if (pthread_join(thid, &tret) != 0) {
        perror("pthread_join error");
        goto efailure;
    }
    unlink(g_sock_file);
    unlink(g_sock_control_file);
    if(logfile && logfile != stdout) {
        fclose(logfile);
    }
    return EXIT_SUCCESS;
efailure:
    if (thread_created) {
        thread_loop = 0;
        pthread_cancel(thid);
        pthread_join(thid, &tret);
    }
    unlink(g_sock_file);
    unlink(g_sock_control_file);
    if(logfile) {
        fclose(logfile);
        logfile = NULL;
    }
    exit(EXIT_FAILURE);
}
