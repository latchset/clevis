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
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/socket.h>
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
uint8_t thread_loop = 1;
uint8_t control_thread_info = 0;
pthread_mutex_t mutex;
FILE* logfile = NULL;

static void
get_control_socket_name(const char* file_sock, char* control_sock, uint32_t control_sock_len) {
    char *p = strstr(file_sock, ".sock");
    size_t prefix_length = strlen(file_sock) - strlen(p);
    memset(control_sock, 0, control_sock_len);
    memcpy(control_sock, file_sock, prefix_length);
    if (prefix_length + strlen(".control.sock") < control_sock_len) {
        strcat(control_sock + prefix_length, ".control.sock");
    }
}

static void insert_device(const char* dev) {
    if(MAX_ENTRIES == entry_counter) {
        perror("No more entries accepted\n");
        return;
    }
    pthread_mutex_lock(&mutex);
    strncpy(keys[entry_counter].dev, dev, MAX_DEVICE);
    pthread_mutex_unlock(&mutex);
}

static void insert_key(const char* key) {
    if(MAX_ENTRIES == entry_counter) {
        perror("No more entries accepted\n");
        return;
    }
    pthread_mutex_lock(&mutex);
    strncpy(keys[entry_counter++].key, key, MAX_KEY);
    pthread_mutex_unlock(&mutex);
}

static const char* get_key(const char* dev) {
    for(int e = 0; e < entry_counter; e++) {
        pthread_mutex_lock(&mutex);
        if(0 == strcmp(keys[e].dev, dev)) {
            pthread_mutex_unlock(&mutex);
            return keys[e].key;
        }
        pthread_mutex_unlock(&mutex);
    }
    return NULL;
}

static void* control_thread(void *targ) {
    // Create a socket to listen on control socket
    struct sockaddr_un control_addr, accept_addr;
    int s = 0, a = 0, r = 0;
    char control_msg[MAX_CONTROL_MSG+1];
    const char* control_sock = (const char*)targ;
    socklen_t len = 0;
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
        a = accept(s, (struct sockaddr *)&accept_addr, &len);
        if (a == -1) {
            perror("control accept");
            fprintf(logfile, "Control accept\n");
            pthread_exit("control accept");
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
        char* t = control_msg;
        int is_device = 1;
        fprintf(logfile, "Received control message:[%s]\n", t);
        while((t = strtok(t, ","))) {
            if (is_device) {
                fprintf(logfile, "Adding device:%s\n", t);
                insert_device(t);
                is_device = 0;
            } else {
                fprintf(logfile, "Adding key:%s\n", t);
                insert_key(t);
                // As long as some key is inserted, we store it
                // in the control_thread_info variable
                control_thread_info = 1;
            }
            t = strtok(NULL, ",");
        }
        close(a);
    }
    return NULL;
}

static int usage(const char* name, uint32_t ecode) {
    printf("\nUsage:\n\t%s -f socket_file [-c control_socket] [-k key] "
           "[-l logfile] [-t iterations, 3 by default]"
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

static void int_handler(int s) {
    if(logfile) {
        fprintf(logfile, "Closing, signal:[%d]\n", s);
        fclose(logfile);
    }
    exit(EXIT_FAILURE);
}

int main(int argc, char* argv[]) {
    int s, a, opt;
    struct sockaddr_un sock_addr, accept_addr, peer_addr;
    socklen_t pathlen;
    char key[MAX_KEY];
    char lfile[MAX_PATH];
    char sock_file[MAX_PATH];
    char sock_control_file[MAX_PATH];
    socklen_t len = sizeof(accept_addr);
    uint8_t wait_control_thread = 1;
    uint32_t iterations = DEFAULT_MAX_ITERATIONS;
    uint32_t startdelay = DEFAULT_START_DELAY;
    uint32_t ic = 0;
    uint32_t time = 0;
    memset(lfile, 0, MAX_PATH);
    memset(sock_file, 0, MAX_PATH);
    memset(sock_control_file, 0, MAX_PATH);
    memset(key, 0, MAX_KEY);

    signal(SIGTERM | SIGKILL, int_handler);
    for (uint16_t e = 0; e < MAX_ENTRIES; e++) {
        memset(&keys[e], 0, sizeof(key_entry_t));
    }
    while ((opt = getopt(argc, argv, "c:f:k:i:l:s:t:hv")) != -1) {
        int ret_code = EXIT_FAILURE;
        switch (opt) {
        case 'c':
            strncpy(sock_control_file, optarg, MAX_PATH - 1);
            break;
        case 'f':
            strncpy(sock_file, optarg, MAX_PATH - 1);
            break;
        case 'k':
            strncpy(key, optarg, MAX_KEY - 1);
            break;
        case 'l':
            strncpy(lfile, optarg, MAX_PATH - 1);
            logfile = fopen(lfile, "w+");
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
    if(0 == strlen(sock_file)) {
        fprintf(logfile, "\nSocket file name must be provided\n");
        usage(argv[0], EXIT_FAILURE);
    }
    if(0 == strlen(sock_control_file) ) {
        get_control_socket_name(sock_file, sock_control_file, MAX_PATH);
    }
    fprintf(logfile, "LOG FILE: [%s]\n", lfile);
    fprintf(logfile, "FILE: [%s]\n", sock_file);
    fprintf(logfile, "KEY: [%s]\n", key);
    fprintf(logfile, "START DELAY: [%u] seconds\n", startdelay);
    fprintf(logfile, "TRY ITERATIONS: [%u]\n", iterations);
    dump_version();

    pthread_t thid;
    void* tret;
    if (pthread_create(&thid, NULL, control_thread, sock_control_file) != 0) {
        perror("pthread_create() error");
        goto efailure;
    }

    memset(&sock_addr, 0, sizeof(sock_addr));
    sock_addr.sun_family = AF_UNIX;
    strncpy(sock_addr.sun_path, sock_file, sizeof(sock_addr.sun_path)-1);
    unlink(sock_file);
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
        a = accept(s, (struct sockaddr *)&accept_addr, &len);
        if (a == -1) {
            perror("accept");
            goto efailure;
        }
        pathlen = len - offsetof(struct sockaddr_un, sun_path);
        len = sizeof(peer_addr);
        if (getpeername(a, (struct sockaddr *)&peer_addr, &len)== -1) {
            perror("getpeername");
            goto efailure;
        }
        pathlen = len - offsetof(struct sockaddr_un, sun_path);
        char peer[pathlen];
        memset(peer, 0, pathlen);
        strncpy(peer, peer_addr.sun_path+1, pathlen-1);
        fprintf(logfile, "Try: [%u/%u]\n", ic, iterations);
        fprintf(logfile, "getpeername sun_path(peer): [%s]\n", peer);
        char* t = peer;
        const char* unlocking_device = "";
        while((t = strtok(t, "/"))) {
            if(t) {
                unlocking_device = t;
            }
            t = strtok(NULL, ",");
        }
        fprintf(logfile, "Trying to unlock device:[%s]\n", unlocking_device);
        // Now we have all the information in peer, something like:
        // \099226072855ae2d8/cryptsetup/luks-6e38d5e1-7f83-43cc-819a-7416bcbf9f84
        // NUL random /cryptsetup/ DEVICE
        // If we need to unencrypt device, pick it from peer information
        // To return the key, just respond to socket returned by accept
        if(strlen(key)) {
            if (send(a, key, strlen(key), 0) < 0) {
                perror("key send error");
                goto efailure;
            }
        } else {
            const char* entry_key;
            if((entry_key = get_key(unlocking_device))) {
                if (send(a, entry_key, strlen(entry_key), 0)< 0) {
                    perror("key entry send error");
                    goto efailure;
                }
                fprintf(logfile, "Sending:[%s] to device:[%s]\n",
                        entry_key, unlocking_device);
            } else {
                fprintf(logfile, "Device not found: [%s]\n", unlocking_device);
            }
        }
        close(a);
        ic++;
    }
    fprintf(logfile, "Closing (max tries reached)\n");
    pthread_kill(thid, SIGKILL);
    thread_loop = 0;
    if (pthread_join(thid, &tret) != 0) {
        perror("pthread_join error");
        goto efailure;
    }
    return EXIT_SUCCESS;
efailure:
    if(logfile) {
        fclose(logfile);
        logfile = NULL;
    }
    exit(EXIT_FAILURE);
}
