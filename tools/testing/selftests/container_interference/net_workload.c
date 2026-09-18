// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include "net_fixture/uapi.h"

static int until(uint64_t ns)
{
	struct timespec t = { .tv_sec = ns / 1000000000ULL, .tv_nsec = ns % 1000000000ULL };
	int error;
	do { error = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &t, NULL); } while (error == EINTR);
	return error;
}

int main(int argc, char **argv)
{
	struct cis_net_test_request r = {0};
	uint64_t start, cookie = 0;
	socklen_t length = sizeof(cookie);
	unsigned int i, actor, swap;
	int device, fd;
	if (argc != 5) return 2;
	fd = atoi(argv[1]); actor = strtoul(argv[2], NULL, 10);
	start = strtoull(argv[3], NULL, 10); swap = !strcmp(argv[4], "switch");
	if (fd < 0 || actor > 1 || (strcmp(argv[4], "shared") && strcmp(argv[4], "private") && !swap)) return 2;
	if (getsockopt(fd, SOL_SOCKET, SO_COOKIE, &cookie, &length) || length != sizeof(cookie) || !cookie) return 3;
	device = open("/dev/cis-net-test", O_RDWR | O_CLOEXEC);
	if (device < 0) return 4;
	for (i = 0; i < 4; i++) {
		unsigned int holder = swap ? i % 2 : 0;
		r = (struct cis_net_test_request) { .fd = fd, .cookie = cookie, .hold_ms = actor == holder ? 30 : 0 };
		if (until(start + i * 100000000ULL + (actor == holder ? 0 : 5000000ULL))) return 5;
		if (ioctl(device, CIS_NET_TEST_HOLD, &r)) { perror("net hold"); return 6; }
		printf("CIS_NET_TRUTH index=%u actor=%u cookie=%llu socket=%llu enter_ns=%llu acquired_ns=%llu release_begin_ns=%llu released_ns=%llu cpu=%u hold_ms=%u scenario=%s\n",
			i, actor, (unsigned long long)cookie, (unsigned long long)r.socket_address,
			(unsigned long long)r.enter_ns, (unsigned long long)r.acquired_ns,
			(unsigned long long)r.release_begin_ns, (unsigned long long)r.released_ns,
			r.cpu, r.hold_ms, argv[4]);
		fflush(stdout);
	}
	/* The inherited socket remains real; this fixture never changes its protocol. */
	return close(device) ? 7 : 0;
}
