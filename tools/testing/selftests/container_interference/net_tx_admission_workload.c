// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
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
	int fd, actor, channel, i, phase;
	if (argc != 6) return 2;
	fd=atoi(argv[1]); actor=atoi(argv[2]); start=strtoull(argv[3],NULL,10); channel=atoi(argv[5]);
	if (actor<0 || actor>1 || !start || (strcmp(argv[4],"txadmission") && strcmp(argv[4],"txnormal"))) return 2;
	if (getsockopt(fd,SOL_SOCKET,SO_COOKIE,&cookie,&len) || !cookie) return 3;
	for (phase=0;phase<2;phase++) {
		if (phase) {
			char message='R'; struct pollfd p={.fd=channel,.events=POLLIN};
			if (send(channel,&message,1,MSG_NOSIGNAL)!=1 || poll(&p,1,3000)!=1 ||
			    recv(channel,&message,1,0)!=1 || message!='D') return 4;
			start=cis_now_ns();
			printf("CIS_NET_TX_RESTORED actor=%d time_ns=%llu\n",actor,start);
		}
		for (i=0;i<(phase?8:16);i++) {
			char payload[128]; unsigned long long begin,end; int rc,saved_errno;
			memset(payload,42+actor,sizeof(payload));
			if (wait_until(start+i*10000000ULL)) return 5;
			begin=cis_now_ns(); errno=0;
			rc=send(fd,payload,sizeof(payload),MSG_DONTWAIT|MSG_NOSIGNAL|MSG_EOR);
			saved_errno=errno; end=cis_now_ns();
			printf("CIS_NET_TX_ADMISSION actor=%d phase=%d index=%d cookie=%llu begin_ns=%llu end_ns=%llu returned=%d error=%d\n",
			       actor,phase,i,cookie,begin,end,rc,saved_errno);
			fflush(stdout);
			if (rc!=128 && (rc!=-1 || saved_errno!=EAGAIN)) return 6;
			if (phase && (rc!=128 || saved_errno)) return 7;
		}
	}
	/* Repair-mode queued data is intentionally not delivered; close purges it. */
	if (close(fd) || close(channel)) return 8;
	return 0;
}
