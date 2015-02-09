/* Copyright (c) 2015 The crouton Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * LD_PRELOAD hack to make Xorg happy in a system without VT-switching.
 * gcc -shared -fPIC  -ldl -Wall -O2 freon.c -o croutonfreon.so
 *
 * Powered by black magic.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/input.h>
#include <linux/vt.h>

#define DISPLAY_LOCK_FILE "/tmp/crouton-lock/display"
#define FREON_DBUS_METHOD_CALL(function) \
    system("host-dbus dbus-send --system --dest=org.chromium.LibCrosService " \
           "--type=method_call --print-reply /org/chromium/LibCrosService " \
           "org.chromium.LibCrosServiceInterface." #function)

static int tty0fd = -1;
static int tty7fd = -1;
static int lockfd = -1;

static int (*orig_ioctl)(int d, int request, void* data);
static int (*orig_open)(const char *pathname, int flags, mode_t mode);
static int (*orig_close)(int fd);

static void preload_init() {
    orig_ioctl = dlsym(RTLD_NEXT, "ioctl");
    orig_open = dlsym(RTLD_NEXT, "open");
    orig_close = dlsym(RTLD_NEXT, "close");
}

static int set_display_lock(unsigned int pid) {
    if (lockfd == -1) {
        if (!pid) {
            fprintf(stderr, "No display lock to release.\n");
            return 0;
        }
        lockfd = orig_open(DISPLAY_LOCK_FILE, O_CREAT | O_WRONLY, 0666);
        if (lockfd == -1) {
            fprintf(stderr, "Unable to open display lock file.\n");
            return -1;
        }
        if (flock(lockfd, LOCK_EX) == -1) {
            fprintf(stderr, "Unable to lock display lock file.\n");
            return -1;
        }
    }
    if (ftruncate(lockfd, 0) == -1) {
        fprintf(stderr, "Unable to truncate display lock file.\n");
        return -1;
    }
    char buf[11];
    int len;
    if ((len = snprintf(buf, sizeof(buf), "%d\n", pid)) < 0) {
        fprintf(stderr, "pid sprintf failed.\n");
        return -1;
    }
    if (write(lockfd, buf, len) == -1) {
        fprintf(stderr, "Unable to write to display lock file.\n");
        return -1;
    }
    if (!pid) {
        int ret = orig_close(lockfd);
        lockfd = -1;
        if (ret == -1) {
            fprintf(stderr, "Failure when closing display lock file.\n");
        }
        return ret;
    }
    return 0;
}

int ioctl(int fd, unsigned long int request, ...) {
    if (!orig_ioctl) preload_init();

    int ret = 0;
    va_list argp;
    va_start(argp, request);
    void* data = va_arg(argp, void*);

    if (fd == tty0fd) {
        fprintf(stderr, "ioctl tty0 %d %lx %p\n", fd, request, data);
        if (request == VT_OPENQRY) {
            fprintf(stderr, "OPEN\n");
            *(int*)data = 7;
        }
        ret = 0;
    } else if (fd == tty7fd) {
        fprintf(stderr, "ioctl tty7 %d %lx %p\n", fd, request, data);
        if (request == VT_GETSTATE) {
            fprintf(stderr, "STATE\n");
            struct vt_stat* stat = data;
            stat->v_active = 0;
        }

        if ((request == VT_RELDISP && (long)data == 1) ||
            (request == VT_ACTIVATE && (long)data == 0)) {
            fprintf(stderr, "Telling Chromium OS to regain control\n");
            ret = FREON_DBUS_METHOD_CALL(TakeDisplayOwnership);
            if (set_display_lock(0)) {
                fprintf(stderr, "Failed to release display lock\n");
            }
        } else if ((request == VT_RELDISP && (long)data == 2) ||
                   (request == VT_ACTIVATE && (long)data == 7)) {
            if (!set_display_lock(getpid())) {
                fprintf(stderr, "Telling Chromium OS to drop control\n");
                ret = FREON_DBUS_METHOD_CALL(ReleaseDisplayOwnership);
            } else {
                fprintf(stderr, "Unable to claim display lock\n");
                ret = -1;
            }
        } else {
            ret = 0;
        }
    } else {
        if (request == EVIOCGRAB) {
            fprintf(stderr, "ioctl GRAB %d %lx %p\n", fd, request, data);
            /* Driver requested a grab: assume we have it already and report
             * success */
            ret = 0;
        } else {
            ret = orig_ioctl(fd, request, data);
        }
    }
    va_end(argp);
    return ret;
}

int open(const char *pathname, int flags, ...) {
    if (!orig_open) preload_init();

    va_list argp;
    va_start(argp, flags);
    int mode = va_arg(argp, int);

    fprintf(stderr, "open %s\n", pathname);
    if (!strcmp(pathname, "/dev/tty0")) {
        tty0fd = orig_open("/dev/null", flags, mode);
        return tty0fd;
    } else if (!strcmp(pathname, "/dev/tty7")) {
        tty7fd = orig_open("/dev/null", flags, mode);
        return tty7fd;
    } else {
        const char* event = "/dev/input/event";
        int fd = orig_open(pathname, flags, mode);
        fprintf(stderr, "open %s %d\n", pathname, fd);
        if (!strncmp(pathname, event, strlen(event))) {
            fprintf(stderr, "GRAB\n");
            orig_ioctl(fd, EVIOCGRAB, (void *) 1);
        }
        return fd;
    }
}

int close(int fd) {
    if (!orig_close) preload_init();

    fprintf(stderr, "close %d\n", fd);

    if (fd == tty0fd) {
        tty0fd = -1;
    } else if (fd == tty7fd) {
        tty7fd = -1;
    }
    return orig_close(fd);
}
