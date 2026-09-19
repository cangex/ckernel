// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include "net_fixture/uapi.h"

static uint64_t now(void)
{
	struct timespec t;
	if (clock_gettime(CLOCK_MONOTONIC, &t)) exit(3);
	return (uint64_t)t.tv_sec * 1000000000ULL + t.tv_nsec;
}

static int open_socket(unsigned int actor, unsigned int index, int device)
{
	uint64_t begin = now(), cookie;
	socklen_t length = sizeof(cookie);
	int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	struct cis_net_test_request r = {0};
	if (fd < 0 || getsockopt(fd, SOL_SOCKET, SO_COOKIE, &cookie, &length) ||
	    length != sizeof(cookie) || !cookie) return -1;
	r.fd = fd; r.cookie = cookie;
	if (ioctl(device, CIS_NET_TEST_HOLD, &r)) { close(fd); return -1; }
	printf("CIS_NET_CAPACITY actor=%u index=%u cookie=%llu begin_ns=%llu end_ns=%llu\n",
	       actor, index, (unsigned long long)cookie,
	       (unsigned long long)begin, (unsigned long long)now());
	return fd;
}

int main(int argc, char **argv)
{
	int channel, device, fds[40], result;
	unsigned int actor;
	uint64_t start;
	char byte = 'R';
	struct timespec deadline;
	struct pollfd pollfd;
	if (argc != 5 || strcmp(argv[4], "capacity")) return 2;
	channel = atoi(argv[1]); actor = strtoul(argv[2], NULL, 10);
	start = strtoull(argv[3], NULL, 10);
	if (channel < 3 || actor > 1) return 2;
	device = open("/dev/cis-net-test", O_RDWR | O_CLOEXEC);
	if (device < 0) return 3;
	deadline = (struct timespec){ .tv_sec=start/1000000000ULL, .tv_nsec=start%1000000000ULL };
	do { result = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &deadline, NULL); } while (result == EINTR);
	if (result) return 4;
	for (unsigned int i=0; i<40; i++) {
		fds[i] = open_socket(actor, i, device);
		if (fds[i] < 0) return 5;
	}
	fflush(stdout);
	if (send(channel, &byte, 1, MSG_NOSIGNAL) != 1) return 6;
	pollfd = (struct pollfd){ .fd=channel, .events=POLLIN };
	do { result = poll(&pollfd, 1, 15000); } while (result < 0 && errno == EINTR);
	if (result != 1 || recv(channel, &byte, 1, 0) != 1 || byte != 'D') return 7;
	uint64_t begin = now();
	for (unsigned int i=0; i<40; i++) {
		struct cis_net_test_request r = { .fd=fds[i] };
		socklen_t length = sizeof(r.cookie);
		if (getsockopt(fds[i], SOL_SOCKET, SO_COOKIE, &r.cookie, &length) ||
		    ioctl(device, CIS_NET_TEST_HOLD, &r) || close(fds[i])) return 8;
	}
	printf("CIS_NET_CAPACITY_AFTER actor=%u operations=40 errors=0 begin_ns=%llu end_ns=%llu\n",
	       actor, (unsigned long long)begin, (unsigned long long)now());
	close(device); close(channel);
	return 0;
}
