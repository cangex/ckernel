// SPDX-License-Identifier: GPL-2.0-only
/* Disposable VM filesystem correctness and guest-crash fixture. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int worker(int id)
{
    char dir[128],temp[128],live[128],link[128];
    snprintf(dir,sizeof(dir),"/tmp/ckwb-fs/worker-%d",id);
    snprintf(temp,sizeof(temp),"/tmp/ckwb-fs/worker-%d/temp",id);
    snprintf(live,sizeof(live),"/tmp/ckwb-fs/worker-%d/live",id);
    snprintf(link,sizeof(link),"/tmp/ckwb-fs/worker-%d/link",id);
    if (mkdir(dir,0700)) return 1;
    int dfd=open(dir,O_RDONLY|O_DIRECTORY);if(dfd<0)return 1;
    for(int round=0;round<128;round++) {
        char data[8192],check[8192];memset(data,(id+round)%251,sizeof(data));
        int fd=open(temp,O_CREAT|O_EXCL|O_RDWR,0600);if(fd<0)return 1;
        if(write(fd,data,sizeof(data))!=(ssize_t)sizeof(data)||fsync(fd))return 1;
        if(rename(temp,live)||linkat(AT_FDCWD,live,AT_FDCWD,link,0)||fsync(dfd))return 1;
        struct stat st;if(fstat(fd,&st)||st.st_nlink!=2)return 1;
        int other=open(link,O_RDONLY);if(other<0)return 1;
        if(read(other,check,sizeof(check))!=(ssize_t)sizeof(check)||memcmp(data,check,sizeof(data)))return 1;
        close(other);
        if(unlink(live)||unlink(link)||fstat(fd,&st)||st.st_nlink!=0)return 1;
        if(pread(fd,check,sizeof(check),0)!=(ssize_t)sizeof(check)||memcmp(data,check,sizeof(data)))return 1;
        if(close(fd)||fsync(dfd))return 1;
    }
    close(dfd);return rmdir(dir)!=0;
}

int main(int argc,char **argv)
{
    if(argc!=3)return 1;
    struct timespec now={.tv_sec=strtoll(argv[2],NULL,10),.tv_nsec=0};
    if(now.tv_sec<1700000000||clock_settime(CLOCK_REALTIME,&now))return 1;
    if(!strcmp(argv[1],"verify")) {
        const char expected[]="CKWB_DURABLE_BEFORE_GUEST_CRASH\n";
        char actual[sizeof(expected)];
        int fd=open("/tmp/ckwb-fs/durable",O_RDONLY);
        if(fd<0||read(fd,actual,sizeof(actual))!=(ssize_t)sizeof(expected)-1||
           memcmp(actual,expected,sizeof(expected)-1)||close(fd))return 1;
        puts("W3_RECOVERY_VERIFY_PASS");return 0;
    }
    if(mkdir("/tmp/ckwb-fs",0700))return 1;
    if(!strcmp(argv[1],"crash")) {
        const char marker[]="CKWB_DURABLE_BEFORE_GUEST_CRASH\n";
        int fd=open("/tmp/ckwb-fs/durable",O_CREAT|O_EXCL|O_WRONLY,0600);
        if(fd<0||write(fd,marker,sizeof(marker)-1)!=(ssize_t)sizeof(marker)-1||fsync(fd)||close(fd))return 1;
        fd=open("/tmp/ckwb-fs",O_RDONLY|O_DIRECTORY);if(fd<0||fsync(fd)||close(fd))return 1;
        puts("W3_CRASH_READY");fflush(stdout);
        for(int i=0;;i++) {
            char path[96],data[8192];memset(data,i%251,sizeof(data));
            snprintf(path,sizeof(path),"/tmp/ckwb-fs/churn-%d",i%64);
            fd=open(path,O_CREAT|O_TRUNC|O_WRONLY,0600);if(fd<0)return 1;
            if(write(fd,data,sizeof(data))!=(ssize_t)sizeof(data)||close(fd))return 1;
        }
    }
    pid_t children[8];
    for(int i=0;i<8;i++) {
        children[i]=fork();if(children[i]<0)return 1;
        if(!children[i])_exit(worker(i));
    }
    int failures=0;
    for(int i=0;i<8;i++) {
        int status=0;
        if(waitpid(children[i],&status,0)!=children[i]||!WIFEXITED(status)||WEXITSTATUS(status))failures++;
    }
    if(rmdir("/tmp/ckwb-fs"))failures++;
    printf("W3_FS_END failures=%d workers=8 iterations=1024\n",failures);
    return failures!=0;
}
