// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include "common.h"

static int mark_task(int fd, int armed)
{
	char value = armed ? '1' : '0', actual[16] = {};
	if (pwrite(fd, &value, 1, 0) != 1 || pread(fd, actual, sizeof(actual) - 1, 0) < 1)
		return -1;
	return atoi(actual) == armed ? 0 : -1;
}

static int wait_until(unsigned long long ns)
{
	struct timespec deadline = { .tv_sec = ns / 1000000000ULL, .tv_nsec = ns % 1000000000ULL };
	int rc;
	do { rc = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &deadline, NULL); } while (rc == EINTR);
	return rc;
}

int main(int argc, char **argv)
{
	unsigned long long start, cookie = 0;
	socklen_t len = sizeof(cookie);
	int fd, peer, actor, mark, one = 1, i;
	if (argc != 6) return 2;
	fd = atoi(argv[1]); actor = atoi(argv[2]); start = strtoull(argv[3], NULL, 10);
	peer = atoi(argv[5]);
	if (actor < 0 || actor > 1 || !start ||
	    (strcmp(argv[4], "txfailure") && strcmp(argv[4], "txunmarked"))) return 2;
	mark = open("/proc/self/make-it-fail", O_RDWR | O_CLOEXEC);
	if (mark < 0 || mark_task(mark, 0) ||
	    getsockopt(fd, SOL_SOCKET, SO_COOKIE, &cookie, &len) || !cookie ||
	    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one))) return 3;
	for (i = 0; i < 8; i++) {
		char payload[128], received[128];
		unsigned long long begin, end;
		int armed = !(i & 1) && (actor == 0 || !strcmp(argv[4], "txfailure"));
		int rc, saved_errno, received_bytes = 0;
		memset(payload, 17 + actor * 8 + i, sizeof(payload));
		if (wait_until(start + i * 100000000ULL) || mark_task(mark, armed)) return 4;
		begin = cis_now_ns(); errno = 0;
		rc = send(fd, payload, sizeof(payload), MSG_DONTWAIT | MSG_NOSIGNAL | MSG_EOR);
		saved_errno = errno; end = cis_now_ns();
		/* Fault selection covers the send only, never logging or recovery. */
		if (mark_task(mark, 0)) return 5;
		if (rc > 0) {
			while (received_bytes < rc) {
				struct pollfd p = { .fd = peer, .events = POLLIN };
				int got;
				if (poll(&p, 1, 100) != 1) return 6;
				got = recv(peer, received + received_bytes, sizeof(received) - received_bytes, MSG_DONTWAIT);
				if (got <= 0) return 6;
				received_bytes += got;
			}
			if (memcmp(payload, received, sizeof(payload))) return 6;
		}
		printf("CIS_NET_TX_FAILURE index=%d armed=%d cookie=%llu begin_ns=%llu end_ns=%llu returned=%d error=%d received=%d restored=1\n",
		       i, armed, cookie, begin, end, rc, saved_errno, received_bytes);
		fflush(stdout);
		if (armed ? (rc != -1 || saved_errno != EAGAIN || received_bytes) :
		    (rc != (int)sizeof(payload) || saved_errno || received_bytes != (int)sizeof(payload))) return 7;
	}
	if (mark_task(mark, 0) || close(mark) || close(fd) || close(peer)) return 8;
	return 0;
}
