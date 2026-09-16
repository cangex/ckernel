// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include "common.h"
#include "../../../container_interference/include/cis.h"
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static struct cis_reply request(unsigned int op,int fd,uint64_t id,uint64_t generation,uint64_t start)
{
	struct sockaddr_un address={.sun_family=AF_UNIX,.sun_path="/run/cis-entry.sock"};
	struct cis_request q={.version=CIS_VERSION,.size=sizeof(q),.command=op,.id=id,.generation=generation,.start_ns=start};
	struct cis_reply r={.error=-EIO};
	struct iovec iov={&q,sizeof(q)};
	char control[CMSG_SPACE(sizeof(int))]={0};
	struct msghdr message={.msg_iov=&iov,.msg_iovlen=1};
	int sock=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0);
	if(sock<0) return r;
	snprintf(q.name,sizeof(q.name),"%s",op==CIS_DIAGNOSE?"lock":"entry-fixture");
	if(connect(sock,(void*)&address,sizeof(address))) goto out;
	if(fd>=0) {
		struct cmsghdr *cm;
		message.msg_control=control; message.msg_controllen=sizeof(control);
		cm=CMSG_FIRSTHDR(&message); cm->cmsg_level=SOL_SOCKET; cm->cmsg_type=SCM_RIGHTS;
		cm->cmsg_len=CMSG_LEN(sizeof(fd)); memcpy(CMSG_DATA(cm),&fd,sizeof(fd));
	}
	if(sendmsg(sock,&message,MSG_NOSIGNAL)!=sizeof(q) || recv(sock,&r,sizeof(r),0)!=sizeof(r)) r.error=-EIO;
out: close(sock); return r;
}
static void until(uint64_t ns)
{
	struct timespec t={ns/1000000000ULL,ns%1000000000ULL};
	while(clock_nanosleep(CLOCK_MONOTONIC,TIMER_ABSTIME,&t,NULL)==EINTR) {}
}
int main(void)
{
	pid_t daemon=-1,children[8]={0};
	struct cis_reply ids[8],r;
	char path[128],slot[32],stamp[32],buffer[4096],ready_text[16];
	int pipes[2],failed=0,cpus=sysconf(_SC_NPROCESSORS_ONLN);
	uint64_t start;
	cpu_set_t mask;
	if(cpus<8 || access("/dev/cis-fixture",R_OK|W_OK)) return 2;
	CPU_ZERO(&mask); CPU_SET(0,&mask); if(sched_setaffinity(0,sizeof(mask),&mask)) return 2;
	if(pipe(pipes)) return 2;
	daemon=fork();
	if(!daemon) {
		close(pipes[0]); snprintf(ready_text,sizeof(ready_text),"%d",pipes[1]);
		execl("/cisd","cisd","--mode","ip","--socket","/run/cis-entry.sock","--bpf","/cis.bpf.o",
		      "--output","/tmp/entry-observer.jsonl","--ready-fd",ready_text,NULL); _exit(127);
	}
	close(pipes[1]);
	if(daemon<0 || read(pipes[0],buffer,1)!=1) { close(pipes[0]); failed=1; goto cleanup; }
	close(pipes[0]);
	for(unsigned int i=0;i<8;i++) {
		int fd;
		snprintf(path,sizeof(path),"/sys/fs/cgroup/cis-entry-%u",i);
		if(mkdir(path,0755)) { failed=1; goto cleanup; }
		fd=open(path,O_RDONLY|O_DIRECTORY); ids[i]=request(CIS_REGISTER,fd,0,0,0); if(fd>=0) close(fd);
		if(ids[i].error) { failed=1; goto cleanup; }
	}
	start=cis_now_ns()+2200000000ULL; snprintf(stamp,sizeof(stamp),"%llu",(unsigned long long)start);
	for(unsigned int i=0;i<8;i++) {
		char *args[]={"/entry_workload",slot,stamp,NULL};
		int output;
		snprintf(slot,sizeof(slot),"%u",i); snprintf(path,sizeof(path),"/tmp/entry-worker-%u.log",i);
		output=open(path,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);
		if(output<0) { failed=1; goto cleanup; }
		snprintf(path,sizeof(path),"/sys/fs/cgroup/cis-entry-%u",i);
		children[i]=cis_container_start_output(path,"/container-root",args,1+i%(cpus-1),output); close(output);
		if(children[i]<0) { children[i]=0; failed=1; goto cleanup; }
	}
	until(start-1000000000ULL);
	r=request(CIS_DIAGNOSE,-1,ids[0].id,ids[0].generation,start);
	if(r.error) { failed=1; goto cleanup; }
	until(start+1800000000ULL);
	r=request(CIS_STATUS,-1,0,0,0);
	printf("CIS_ENTRY_GUARD time_ns=%llu %s\n",(unsigned long long)cis_now_ns(),r.text);
	if(r.error || !strstr(r.text,"capture=0") || !strstr(r.text,"errors=0 ")) failed=1;
	for(unsigned int i=0;i<8;i++) { if(cis_container_wait(children[i])) failed=1; children[i]=0; }
cleanup:
	for(unsigned int i=0;i<8;i++) if(children[i]>0) { kill(children[i],SIGKILL); waitpid(children[i],NULL,0); }
	if(daemon>0) {
		r=request(CIS_STOP,-1,0,0,0);
		if(r.error) kill(daemon,SIGTERM);
		if(cis_container_wait(daemon)) failed=1;
	}
	for(unsigned int i=0;i<8;i++) {
		int fd; ssize_t n;
		snprintf(path,sizeof(path),"/tmp/entry-worker-%u.log",i); fd=open(path,O_RDONLY);
		if(fd>=0) {
			fflush(stdout);
			while((n=read(fd,buffer,sizeof(buffer)))>0) if(write(STDOUT_FILENO,buffer,n)!=n) failed=1;
			close(fd);
		}
		snprintf(path,sizeof(path),"/sys/fs/cgroup/cis-entry-%u",i);
		if(rmdir(path) && errno!=ENOENT) failed=1;
	}
	printf("CIS_ENTRY_STORM_RESULT failures=%d default_limit=200000 targeted_container=sleeping non_targeted_containers=7\n",failed);
	return failed;
}
