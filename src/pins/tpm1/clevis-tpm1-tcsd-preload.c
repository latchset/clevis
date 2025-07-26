#define _GNU_SOURCE

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define TCSD_NO_PRIVILEGE_DROP_ENV "TCSD_NO_PRIVILEGE_DROP"

static int no_privilege_drop(void) {
    char *no_privilege_drop_env = getenv(TCSD_NO_PRIVILEGE_DROP_ENV);
    return (no_privilege_drop_env != NULL
            && no_privilege_drop_env[0] != '\0'
            && no_privilege_drop_env[0] != '0');
}

int setuid(uid_t uid) {
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

int setgid(gid_t gid) {
    static int (*real_setgid)(uid_t) = NULL;
    if (no_privilege_drop()) {
        return 0;
    } else {
        if (!real_setgid) {
            real_setgid = dlsym(RTLD_NEXT, "setgid");
        }
        return real_setgid(gid);
    }
    return 0;
}

static void __attribute ((constructor))
set_line_buffering (void)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
}
