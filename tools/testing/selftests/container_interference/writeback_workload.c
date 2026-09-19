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
	unsigned char buffer[4096];
	unsigned long long start, begin;
	int dir, role, fd, rc;
	if (argc != 5) return 2;
	dir=atoi(argv[1]); role=atoi(argv[2]); start=strtoull(argv[3],NULL,10);
	if (dir<3 || role<0 || role>1 || strchr(argv[4],'/') || !argv[4][0] ||
	    fstat(dir,&st) || !S_ISDIR(st.st_mode)) return 3;
	struct timespec ts={.tv_sec=start/1000000000ULL,.tv_nsec=start%1000000000ULL};
	do { rc=clock_nanosleep(CLOCK_MONOTONIC,TIMER_ABSTIME,&ts,NULL); } while (rc==EINTR);
	if (rc) return 4;
	begin=now();
	fd=openat(dir,argv[4],O_CREAT|O_RDWR|O_NOFOLLOW,0600);
	if (fd<0 || fstat(fd,&st) || !S_ISREG(st.st_mode)) return 5;
	memset(buffer,0x35+role,sizeof(buffer));
	/* Separate page ranges in the shared-inode negative; both actors really
	 * dirty pages, but a wb inode/bio identity is not either actor's full history. */
	for (int i=0;i<32;i++)
		if (pwrite(fd,buffer,sizeof(buffer),(off_t)(role*32+i)*sizeof(buffer))!=sizeof(buffer)) return 6;
	printf("CIS_WRITEBACK_WRITE role=%d begin_ns=%llu end_ns=%llu inode=%llu major=%u minor=%u offset=%u bytes=131072 pattern=%u buffered=1\n",
	       role,begin,now(),(unsigned long long)st.st_ino,major(st.st_dev),minor(st.st_dev),role*131072,0x35+role);
	if (close(fd)) return 7;
	puts("CIS_WRITEBACK_DONE errors=0");
	return 0;
}
