// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include "common.h"
#include "net_fixture/uapi.h"

int main(int argc, char **argv)
{
	struct cis_net_clone_request r = {0}, drop = {0};
	unsigned long long start, send_begin, send_end, close_begin, close_end;
	char data[128] = {0};
	socklen_t len = sizeof(r.cookie);
	struct timespec deadline;
	int fd, actor, device, rc;

	if (argc != 5) return 2;
	fd=atoi(argv[1]); actor=atoi(argv[2]); start=strtoull(argv[3],NULL,10);
	if (fd<0 || actor<0 || actor>1 || !start ||
	    (strcmp(argv[4],"txclone") && strcmp(argv[4],"txplain"))) return 2;
	r.fd=fd; r.clone=!strcmp(argv[4],"txclone");
	if (getsockopt(fd,SOL_SOCKET,SO_COOKIE,&r.cookie,&len) || !r.cookie) return 3;
	device=open("/dev/cis-net-test",O_RDWR|O_CLOEXEC);
	if (device<0) return 4;
	deadline=(struct timespec){.tv_sec=start/1000000000ULL,.tv_nsec=start%1000000000ULL};
	do { rc=clock_nanosleep(CLOCK_MONOTONIC,TIMER_ABSTIME,&deadline,NULL); } while (rc==EINTR);
	if (rc) return 5;
	send_begin=cis_now_ns();
	if (send(fd,data,sizeof(data),MSG_DONTWAIT|MSG_NOSIGNAL|MSG_EOR)!=sizeof(data)) return 6;
	send_end=cis_now_ns();
	if (ioctl(device,CIS_NET_TEST_CLONE,&r)) { perror("inspect/clone"); return 7; }
	close_begin=cis_now_ns();
	if (close(fd)) return 8;
	close_end=cis_now_ns();
	if (r.clone && ioctl(device,CIS_NET_TEST_DROP_CLONE,&drop)) return 9;
	printf("CIS_NET_RELEASE actor=%d cookie=%llu clone=%u original=%llu child=%llu data_refs=%u header_refs=%u send_begin=%llu send_end=%llu inspect_begin=%llu inspect_end=%llu close_begin=%llu close_end=%llu child_begin=%llu child_end=%llu\n",
	       actor,(unsigned long long)r.cookie,r.clone,(unsigned long long)r.original,
	       (unsigned long long)r.child,r.data_refs,r.header_refs,send_begin,send_end,
	       (unsigned long long)r.begin_ns,(unsigned long long)r.end_ns,close_begin,close_end,
	       (unsigned long long)drop.begin_ns,(unsigned long long)drop.end_ns);
	return close(device) ? 10 : 0;
}
