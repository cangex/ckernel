// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
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

int main(int argc, char **argv)
{
	struct cis_net_test_request r = {0};
	socklen_t length = sizeof(r.cookie);
	struct timespec deadline;
	uint64_t start;
	unsigned int actor;
	int device, error;
	if (argc != 3) return 2;
	actor = strtoul(argv[1], NULL, 10);
	start = strtoull(argv[2], NULL, 10);
	if (actor > 1 || !start) return 2;
	device = open("/dev/cis-net-test", O_RDWR | O_CLOEXEC);
	r.fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (device < 0 || r.fd < 0 ||
	    getsockopt(r.fd, SOL_SOCKET, SO_COOKIE, &r.cookie, &length) ||
	    length != sizeof(r.cookie) || !r.cookie) return 3;
	deadline = (struct timespec){.tv_sec=start/1000000000ULL, .tv_nsec=start%1000000000ULL};
	do { error = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &deadline, NULL); } while (error == EINTR);
	if (error) return 4;
	for (unsigned int bucket=0; bucket<8; bucket++) {
		uint64_t begin=now(), operations=0, errors=0;
		uint64_t until=start+(bucket+1)*500000000ULL;
		while (now() < until) {
			if (ioctl(device, CIS_NET_TEST_HOLD, &r)) errors++;
			else operations++;
		}
		printf("CIS_NET_STORM {\"actor\":%u,\"bucket\":%u,\"cookie\":%llu,\"begin_ns\":%llu,\"end_ns\":%llu,\"operations\":%llu,\"errors\":%llu}\n",
		       actor, bucket, (unsigned long long)r.cookie,
		       (unsigned long long)begin, (unsigned long long)now(),
		       (unsigned long long)operations, (unsigned long long)errors);
		fflush(stdout);
		if (errors || !operations) return 5;
	}
	close(r.fd); close(device);
	return 0;
}
