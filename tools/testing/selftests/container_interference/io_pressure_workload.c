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
	return (unsigned long long)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

int main(int argc, char **argv)
{
	unsigned char data[65536], check[65536];
	struct stat directory, st;
	unsigned long long start, begin, written, synced;
	int dir, role, rc, fd, sync_each;
	if (argc != 6) return 2;
	dir=atoi(argv[1]); role=atoi(argv[2]); start=strtoull(argv[3],NULL,10);
	sync_each=!strcmp(argv[5],"sync");
	if (dir<3 || role<0 || role>1 || strchr(argv[4],'/') || !argv[4][0] ||
	    strlen(argv[4])>64 || (!sync_each && strcmp(argv[5],"buffered")) ||
	    fstat(dir,&directory) || !S_ISDIR(directory.st_mode)) return 3;
	memset(data,0x35+role,sizeof(data));
	struct timespec ts={.tv_sec=start/1000000000ULL,.tv_nsec=start%1000000000ULL};
	do { rc=clock_nanosleep(CLOCK_MONOTONIC,TIMER_ABSTIME,&ts,NULL); } while(rc==EINTR);
	if (rc) return 4;
	begin=now(); fd=openat(dir,argv[4],O_CREAT|O_EXCL|O_RDWR|O_NOFOLLOW,0600);
	if (fd<0) return 5;
	for (int i=0;i<128;i++) {
		if (write(fd,data,sizeof(data))!=sizeof(data)) return 6;
		if (sync_each && fdatasync(fd)) return 7;
	}
	written=now();
	if (fdatasync(fd) || fstat(fd,&st) || st.st_size!=8388608) return 8;
	synced=now();
	for (int i=0;i<128;i++)
		if (pread(fd,check,sizeof(check),(off_t)i*sizeof(check))!=sizeof(check) ||
		    memcmp(data,check,sizeof(data))) return 9;
	if (close(fd)) return 10;
	printf("CIS_IO_DONE role=%d begin_ns=%llu written_ns=%llu synced_ns=%llu end_ns=%llu directory_inode=%llu inode=%llu major=%u minor=%u bytes=8388608 sync_each=%d verified=1 errors=0\n",
	       role,begin,written,synced,now(),(unsigned long long)directory.st_ino,
	       (unsigned long long)st.st_ino,major(st.st_dev),minor(st.st_dev),sync_each);
	return 0;
}
