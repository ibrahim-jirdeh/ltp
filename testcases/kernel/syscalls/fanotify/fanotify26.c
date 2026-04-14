// SPDX-License-Identifier: GPL-2.0-or-later

/*\
 * Check that fanotify restartable events are handled properly on queue release.
 *
 * Test 1: Read a permission event, close queue fd to restart it,
 *         reopen queue fd, read the restarted event, and respond.
 *
 * Test 2: Close control fd before queue fd. Read from queue of
 *         shutdown group should fail.
 *
 * Test 3: Generate two events but read/restart only one. After
 *         reopening the queue fd, the first event should be read
 *         first, followed by the second.
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
#include <poll.h>
#include "tst_test.h"
#include "lapi/syscalls.h"

#ifdef HAVE_SYS_FANOTIFY_H
#include "fanotify.h"

#define BUF_SIZE 256
static char fname[BUF_SIZE];
static char fname2[BUF_SIZE];
static int fd_control = -1;
static int fd_queue = -1;

static void close_fanotify_fds(void)
{
	if (fd_queue > 0) {
		SAFE_CLOSE(fd_queue);
		fd_queue = -1;
	}

	if (fd_control > 0) {
		SAFE_CLOSE(fd_control);
		fd_control = -1;
	}
}

static void generate_event(const char *path)
{
	int fd;

	fd = SAFE_OPEN(path, O_RDWR | O_CREAT, 0700);
	SAFE_CLOSE(fd);
}

static pid_t run_child(const char *path)
{
	pid_t pid;

	pid = SAFE_FORK();
	if (pid == 0) {
		close_fanotify_fds();
		generate_event(path);
		exit(0);
	}

	return pid;
}

static void check_child(pid_t pid)
{
	int child_ret;

	SAFE_WAITPID(pid, &child_ret, 0);

	if (WIFEXITED(child_ret) && WEXITSTATUS(child_ret) == 0)
		tst_res(TPASS, "child exited correctly");
	else
		tst_res(TFAIL, "child %s", tst_strstatus(child_ret));
}

static void read_and_verify_event(int queue_fd, const char *desc)
{
	struct fanotify_event_metadata event;

	SAFE_READ(1, queue_fd, &event, sizeof(event));
	if (event.mask != FAN_OPEN_PERM) {
		tst_res(TFAIL,
			"%s: got event mask=%llx (expected %llx) pid=%u fd=%d",
			desc,
			(unsigned long long)event.mask,
			(unsigned long long)FAN_OPEN_PERM,
			(unsigned int)event.pid, event.fd);
		SAFE_CLOSE(event.fd);
		return;
	}
	SAFE_CLOSE(event.fd);
}

static void respond_to_event(int queue_fd)
{
	struct fanotify_event_metadata event;
	struct fanotify_response resp;

	SAFE_READ(1, queue_fd, &event, sizeof(event));
	if (event.mask != FAN_OPEN_PERM) {
		tst_res(TFAIL,
			"respond: got event mask=%llx (expected %llx)",
			(unsigned long long)event.mask,
			(unsigned long long)FAN_OPEN_PERM);
	}

	resp.fd = event.fd;
	resp.response = FAN_ALLOW;
	SAFE_WRITE(SAFE_WRITE_ALL, queue_fd, &resp, sizeof(resp));
	SAFE_CLOSE(event.fd);
}

static void init_group(void)
{
	fd_control = SAFE_FANOTIFY_INIT(FAN_CLASS_CONTENT |
					FAN_RESTARTABLE_EVENTS, O_RDONLY);
	SAFE_FANOTIFY_MARK(fd_control, FAN_MARK_ADD,
			   FAN_OPEN_PERM, AT_FDCWD, fname);
}

/*
 * Test 1: Read event, restart via queue close, read again, respond.
 */
static void test_restart_event(void)
{
	init_group();
	fd_queue = SAFE_FANOTIFY_OPEN_QUEUE(fd_control);

	run_child(fname);

	/* Read event but don't respond */
	read_and_verify_event(fd_queue, "initial read");

	/* Close queue fd to restart the event */
	SAFE_CLOSE(fd_queue);

	/* Reopen queue and read the restarted event */
	fd_queue = SAFE_FANOTIFY_OPEN_QUEUE(fd_control);
	respond_to_event(fd_queue);

	tst_res(TPASS, "Successfully responded to restarted event");

	check_child(-1);
	close_fanotify_fds();
}

/*
 * Test 2: Close control fd before queue fd.
 * Read from queue of shutdown group should fail.
 */
static void test_control_close_before_queue(void)
{
	struct fanotify_event_metadata event;
	int ret;

	init_group();
	fd_queue = SAFE_FANOTIFY_OPEN_QUEUE(fd_control);

	/* Close control fd first — this shuts down the group */
	SAFE_CLOSE(fd_control);
	fd_control = -1;

	/* Read from queue of shutdown group should return EOF */
	ret = read(fd_queue, &event, sizeof(event));
	if (ret == 0)
		tst_res(TPASS, "read returned EOF after control fd closed");
	else if (ret > 0)
		tst_res(TFAIL, "read returned event after control fd closed");
	else
		tst_res(TFAIL | TERRNO, "read failed after control fd closed");

	close_fanotify_fds();
}

/*
 * Test 3: Generate two events, read only the first one, restart.
 * After reopening queue fd, read both events — the first (restarted)
 * event should come before the second.
 */
static void test_partial_restart_ordering(void)
{
	pid_t pid1, pid2;

	init_group();
	SAFE_FANOTIFY_MARK(fd_control, FAN_MARK_ADD,
			   FAN_OPEN_PERM, AT_FDCWD, fname2);

	pid1 = run_child(fname);
	pid2 = run_child(fname2);

	fd_queue = SAFE_FANOTIFY_OPEN_QUEUE(fd_control);

	/* Read first event but don't respond */
	read_and_verify_event(fd_queue, "first event");

	/* Close queue fd to restart the first event */
	SAFE_CLOSE(fd_queue);

	/* Reopen queue fd */
	fd_queue = SAFE_FANOTIFY_OPEN_QUEUE(fd_control);

	/*
	 * First read should get the restarted event,
	 * second read should get the unread event.
	 */
	respond_to_event(fd_queue);
	tst_res(TPASS, "Read and responded to first (restarted) event");

	respond_to_event(fd_queue);
	tst_res(TPASS, "Read and responded to second event");

	check_child(pid1);
	check_child(pid2);

	close_fanotify_fds();
}

static void test_fanotify(unsigned int test_num)
{
	switch (test_num) {
	case 0:
		test_restart_event();
		break;
	case 1:
		test_control_close_before_queue();
		break;
	case 2:
		test_partial_restart_ordering();
		break;
	}
}

static void setup(void)
{
	sprintf(fname, "fname_%d", getpid());
	SAFE_FILE_PRINTF(fname, "%s", fname);
	sprintf(fname2, "fname2_%d", getpid());
	SAFE_FILE_PRINTF(fname2, "%s", fname2);

	REQUIRE_FANOTIFY_INIT_FLAGS_SUPPORTED_ON_FS_PERM(
		FAN_CLASS_CONTENT | FAN_RESTARTABLE_EVENTS, fname);
}

static void cleanup(void)
{
	close_fanotify_fds();
}

static struct tst_test test = {
	.test = test_fanotify,
	.tcnt = 3,
	.setup = setup,
	.cleanup = cleanup,
	.forks_child = 1,
	.needs_root = 1,
};

#else
	TST_TEST_TCONF("system doesn't have required fanotify support");
#endif
