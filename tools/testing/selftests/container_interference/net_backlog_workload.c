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
	clock_gettime(CLOCK_MONOTONIC, &t);
	return t.tv_sec * 1000000000ULL + t.tv_nsec;
}
static int until(uint64_t ns)
{
	struct timespec t = { .tv_sec = ns / 1000000000ULL, .tv_nsec = ns % 1000000000ULL };
	int error;
	do { error = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &t, NULL); } while (error == EINTR);
	return error;
}
static int transfer(int fd, int sending, unsigned int index)
{
	unsigned char data[128];
	size_t done = 0;
	uint64_t deadline = now() + 1000000000ULL;
	memset(data, sending ? 'a' + index : 0, sizeof(data));
	while (done < sizeof(data)) {
		ssize_t n = sending ? send(fd, data + done, sizeof(data) - done, MSG_NOSIGNAL) :
			recv(fd, data + done, sizeof(data) - done, 0);
		if (n > 0) { done += n; continue; }
		if (!n || now() >= deadline) return -1;
		if (errno == EINTR) continue;
		if (errno != EAGAIN && errno != EWOULDBLOCK) return -1;
		{
			struct pollfd p = { .fd = fd, .events = sending ? POLLOUT : POLLIN };
			if (poll(&p, 1, 50) < 0 && errno != EINTR) return -1;
		}
	}
	if (!sending) for (done = 0; done < sizeof(data); done++)
		if (data[done] != 'a' + index) return -1;
	return 0;
}
int main(int argc, char **argv)
{
	uint64_t start, cookie = 0;
	socklen_t size = sizeof(cookie);
	unsigned int actor, i;
	int fd, device = -1;
	if (argc != 5 || strcmp(argv[4], "backlog")) return 2;
	fd = atoi(argv[1]); actor = strtoul(argv[2], NULL, 10); start = strtoull(argv[3], NULL, 10);
	if (fd < 0 || actor > 1 || getsockopt(fd, SOL_SOCKET, SO_COOKIE, &cookie, &size) || !cookie) return 3;
	if (!actor && (device = open("/dev/cis-net-test", O_RDWR | O_CLOEXEC)) < 0) return 4;
	for (i = 0; i < 4; i++) {
		uint64_t begin, end;
		if (until(start + i * 100000000ULL + (actor ? 5000000ULL : 0))) return 5;
		if (!actor) {
			struct cis_net_test_request r = { .fd = fd, .cookie = cookie, .hold_ms = 30 };
			if (ioctl(device, CIS_NET_TEST_HOLD, &r)) return 6;
			printf("CIS_NET_TRUTH index=%u actor=0 cookie=%llu socket=%llu enter_ns=%llu acquired_ns=%llu release_begin_ns=%llu released_ns=%llu cpu=%u hold_ms=30 scenario=backlog\n",
				i, (unsigned long long)cookie, (unsigned long long)r.socket_address,
				(unsigned long long)r.enter_ns, (unsigned long long)r.acquired_ns,
				(unsigned long long)r.release_begin_ns, (unsigned long long)r.released_ns, r.cpu);
		}
		begin = now();
		if (transfer(fd, actor, i)) return 7;
		end = now();
		printf("CIS_PACKET_TRUTH index=%u actor=%u cookie=%llu begin_ns=%llu end_ns=%llu bytes=128 valid=1\n",
			i, actor, (unsigned long long)cookie, (unsigned long long)begin, (unsigned long long)end);
		fflush(stdout);
	}
	/* A final, ordinary unheld transfer lets NET_RX drain deferred frees.
	 * Receiving payload is not proof that its skb has already been freed. */
	if (until(start + 450000000ULL)) return 9;
	{
		uint64_t begin = now(), end;
		if (transfer(fd, actor, 4)) return 10;
		end = now();
		printf("CIS_PACKET_DRAIN actor=%u cookie=%llu begin_ns=%llu end_ns=%llu bytes=128 valid=1\n",
			actor, (unsigned long long)cookie, (unsigned long long)begin, (unsigned long long)end);
		fflush(stdout);
	}
	return device >= 0 && close(device) ? 8 : 0;
}
