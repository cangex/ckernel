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
	if(clock_gettime(CLOCK_MONOTONIC,&ts)) exit(3);
	return (unsigned long long)ts.tv_sec*1000000000ULL+ts.tv_nsec;
}

int main(int argc,char **argv)
{
	unsigned char data[4096],check[4096];
	struct stat directory,st;
	unsigned long long start,begin;
	int dir,role,rc;
	if(argc!=5) return 2;
	dir=atoi(argv[1]); role=atoi(argv[2]); start=strtoull(argv[3],NULL,10);
	if(dir<3 || role<0 || role>1 || strchr(argv[4],'/') || strlen(argv[4])>64 ||
	   fstat(dir,&directory) || !S_ISDIR(directory.st_mode)) return 3;
	memset(data,0x35+role,sizeof(data));
	struct timespec ts={.tv_sec=start/1000000000ULL,.tv_nsec=start%1000000000ULL};
	do {rc=clock_nanosleep(CLOCK_MONOTONIC,TIMER_ABSTIME,&ts,NULL);} while(rc==EINTR);
	if(rc) return 4;
	begin=now();
	for(int i=0;i<96;i++) {
		char name[96];
		snprintf(name,sizeof(name),"%s-%d",argv[4],i);
		int fd=openat(dir,name,O_CREAT|O_EXCL|O_RDWR|O_NOFOLLOW,0600);
		if(fd<0) return 5;
		for(int j=0;j<16;j++) if(write(fd,data,sizeof(data))!=sizeof(data)) return 6;
		if(fdatasync(fd) || fstat(fd,&st) || st.st_size!=65536 ||
		   pread(fd,check,sizeof(check),0)!=sizeof(check) || memcmp(data,check,sizeof(data))) return 7;
		/* An unlinked but still open, private inode exercises native orphan
		 * handling without making the two actors share a writable object. */
		if(unlinkat(dir,name,0) || close(fd)) return 8;
		struct timespec pace={.tv_nsec=3000000};
		while(nanosleep(&pace,&pace) && errno==EINTR) {}
	}
	if(fsync(dir)) return 9;
	printf("CIS_FILESYSTEM_DONE role=%d begin_ns=%llu end_ns=%llu directory_inode=%llu major=%u minor=%u iterations=96 bytes_per_file=65536 errors=0\n",
		role,begin,now(),(unsigned long long)directory.st_ino,major(directory.st_dev),minor(directory.st_dev));
	return 0;
}
