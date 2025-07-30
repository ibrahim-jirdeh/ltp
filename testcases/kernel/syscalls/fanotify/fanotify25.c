// SPDX-License-Identifier: GPL-2.0-or-later

/*\
 * Check that fanotify restartable events are handled properly on queue release.
 */

#define _GNU_SOURCE
#include "config.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <string.h>
#include <sys/syscall.h>
#include "tst_test.h"
#include "lapi/syscalls.h"

#ifdef HAVE_SYS_FANOTIFY_H
#include "fanotify.h"

#define BUF_SIZE 256
static char fname[BUF_SIZE];
static volatile int fd_control;
static volatile int fd_queue;

static pid_t child_pid;

static void close_fanotify_fds(void) {
    if (fd_control > 0) {
        SAFE_CLOSE(fd_control);
        fd_control = -1;
    }

    if (fd_queue > 0) {
        SAFE_CLOSE(fd_queue);
        fd_queue = -1;
    }
}

static void generate_event(void)
{
    int fd;

    /*
     * a single FAN_OPEN_PERM event on the watched object.
     */
    fd = SAFE_OPEN(fname, O_RDWR | O_CREAT, 0700);
    SAFE_CLOSE(fd);
}

static void run_child(void)
{
	child_pid = SAFE_FORK();

	if (child_pid == 0) {
		/* Child will generate events now */
		close_fanotify_fds();
		generate_event();
		exit(0);
	}
}

static void check_child(void)
{
	int child_ret;

	SAFE_WAITPID(-1, &child_ret, 0);

	if (WIFEXITED(child_ret) && WEXITSTATUS(child_ret) == 0)
		tst_res(TPASS, "child exited correctly");
	else
		tst_res(TFAIL, "child %s", tst_strstatus(child_ret));
}

static void restart_pending_event(void)
{
    struct fanotify_event_metadata event;
    SAFE_READ(1, fd_queue, &event, sizeof(event));
    if (event.mask != FAN_OPEN_PERM) {
        tst_res(TFAIL,
            "got event: mask=%llx (expected %llx) "
            "pid=%u fd=%d",
            (unsigned long long)event.mask,
            (unsigned long long)FAN_OPEN_PERM,
            (unsigned int)event.pid, event.fd);
    }
    SAFE_CLOSE(event.fd);

    // release queue and repeat read
    SAFE_CLOSE(fd_queue);
    fd_queue = SAFE_FANOTIFY_OPEN_QUEUE(fd_control);
    SAFE_READ(1, fd_queue, &event, sizeof(event));
    if (event.mask != FAN_OPEN_PERM) {
        tst_res(TFAIL,
            "got event: mask=%llx (expected %llx) "
            "pid=%u fd=%d",
            (unsigned long long)event.mask,
            (unsigned long long)FAN_OPEN_PERM,
            (unsigned int)event.pid, event.fd);
    }

    // respond to reissued permission event
    struct fanotify_response resp;
    resp.fd = event.fd;
    resp.response = FAN_ALLOW;
    SAFE_WRITE(SAFE_WRITE_ALL, fd_queue, &resp, sizeof(resp));
    SAFE_CLOSE(event.fd);

    tst_res(TPASS, "Successfully responded to restarted event");
}

static void test_fanotify(void)
{
    fd_control = SAFE_FANOTIFY_INIT(FAN_CLASS_CONTENT |
                                    FAN_RESTARTABLE_EVENTS, O_RDONLY);
    SAFE_FANOTIFY_MARK(fd_control, FAN_MARK_ADD,
                        FAN_OPEN_PERM, AT_FDCWD, fname);
    fd_queue = SAFE_FANOTIFY_OPEN_QUEUE(fd_control);

    run_child();

    restart_pending_event();

    check_child();

    close_fanotify_fds();
}

static void setup(void)
{
    sprintf(fname, "fname_%d", getpid());
    SAFE_FILE_PRINTF(fname, "%s", fname);
    require_fanotify_access_permissions_supported_on_fs(fname);
}

static void cleanup(void)
{
    close_fanotify_fds();
}

static struct tst_test test = {
    .test_all = test_fanotify,
    .setup = setup,
    .cleanup = cleanup,
    .forks_child = 1,
    .needs_root = 1,
};

#else
    TST_TEST_TCONF("system doesn't have required fanotify support");
#endif
