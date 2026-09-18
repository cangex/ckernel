// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <unistd.h>
#include "rwsem_fixture/uapi.h"

static void alarm_handler(int signal_number) { (void)signal_number; }

int main(int argc, char **argv)
{
	struct cis_rwsem_test r = {0};
	struct sigaction action = {.sa_handler=alarm_handler};
	struct itimerval timer = {.it_value={.tv_usec=50000}};
	int fd, reset;
	if (argc != 8) return 2;
	reset = !strcmp(argv[1],"reset");
	if (!reset && strcmp(argv[1],"operate")) return 2;
	r.slot=strtoul(argv[2],NULL,10); r.token=strtoull(argv[3],NULL,10);
	r.mode=strtoul(argv[4],NULL,10); r.hold_ms=strtoul(argv[5],NULL,10);
	r.wait_slot=strtoul(argv[6],NULL,10); r.wait_holders=strtoul(argv[7],NULL,10);
	fd=open("/dev/cis-rwsem-test",O_RDWR|O_CLOEXEC);
	if (fd<0) { perror("fixture open"); return 3; }
	if (r.mode==6 && (sigaction(SIGALRM,&action,NULL) || setitimer(ITIMER_REAL,&timer,NULL))) return 4;
	if (ioctl(fd,reset?CIS_RWSEM_RESET:CIS_RWSEM_OPERATE,&r)) { perror("fixture ioctl"); close(fd); return 5; }
	printf("CIS_RWSEM_TRUTH reset=%d slot=%u token=%" PRIu64 " object=0x%" PRIx64 " task=%" PRIu64
	       " mode=%u hold_ms=%u enter_ns=%" PRIu64 " acquired_ns=%" PRIu64 " release_ns=%" PRIu64
	       " end_ns=%" PRIu64 " outcome=%d\n",reset,r.slot,(uint64_t)r.token,(uint64_t)r.address,(uint64_t)r.task,
	       r.mode,r.hold_ms,(uint64_t)r.enter_ns,(uint64_t)r.acquired_ns,(uint64_t)r.release_ns,(uint64_t)r.end_ns,r.outcome);
	close(fd); return 0;
}
