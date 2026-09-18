// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <time.h>
#include <unistd.h>

static unsigned long long now(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts)) exit(3);
	return (unsigned long long)ts.tv_sec*1000000000ULL+ts.tv_nsec;
}

int main(int argc, char **argv)
{
	struct stat st;
	void *buffer=NULL;
	unsigned long long start;
	int fd, role;
	if (argc!=4) return 2;
	fd=atoi(argv[1]); role=atoi(argv[2]); start=strtoull(argv[3],NULL,10);
	if (fd<3 || role<0 || role>1 || fstat(fd,&st) || !S_ISBLK(st.st_mode) ||
	    (fcntl(fd,F_GETFL)&O_DIRECT)==0 || posix_memalign(&buffer,4096,4096)) return 3;
	printf("CIS_BLOCK_BEGIN role=%d major=%u minor=%u start_ns=%llu\n",role,major(st.st_rdev),minor(st.st_rdev),start);
	fflush(stdout);
	for (unsigned i=0;i<4;i++) {
		unsigned long long due=start+i*100000000ULL;
		struct timespec ts={.tv_sec=due/1000000000ULL,.tv_nsec=due%1000000000ULL};
		int rc;
		do {rc=clock_nanosleep(CLOCK_MONOTONIC,TIMER_ABSTIME,&ts,NULL);} while (rc==EINTR);
		if (rc) return 4;
		unsigned char value=(unsigned char)(33+role*17+i);
		off_t offset=(off_t)(1+role*8+i)*4096;
		for (int reading=0;reading<2;reading++) {
			memset(buffer,reading ? 0 : value,4096);
			unsigned long long before=now();
			ssize_t bytes=reading ? pread(fd,buffer,4096,offset) : pwrite(fd,buffer,4096,offset);
			unsigned long long after=now();
			int verified=bytes==4096;
			if (reading && verified) for (size_t j=0;j<4096;j++) if (((unsigned char *)buffer)[j]!=value) {verified=0;break;}
			printf("CIS_BLOCK_IO role=%d iteration=%u op=%s offset=%lld before_ns=%llu after_ns=%llu bytes=%zd verified=%d\n",
			       role,i,reading ? "read" : "write",(long long)offset,before,after,bytes,verified);
			fflush(stdout);
			if (!verified) return 5;
		}
	}
	free(buffer);
	puts("CIS_BLOCK_DONE operations=8 errors=0");
	return 0;
}
