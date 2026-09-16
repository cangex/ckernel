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

static uint64_t requested_start_ns;
static struct cis_reply request(unsigned int op,int fd,uint64_t id,uint64_t gen,const char *name)
{
	struct cis_request q={.version=CIS_VERSION,.size=sizeof(q),.command=op,.id=id,.generation=gen,
		.start_ns=op==CIS_DIAGNOSE?requested_start_ns:0};
	struct cis_reply r={.error=-EIO};
	struct sockaddr_un a={.sun_family=AF_UNIX,.sun_path="/run/cis-fleet.sock"};
	char control[CMSG_SPACE(sizeof(fd))]={0};
	struct iovec iov={&q,sizeof(q)};
	struct msghdr m={.msg_iov=&iov,.msg_iovlen=1};
	int s=socket(AF_UNIX,SOCK_SEQPACKET,0);
	snprintf(q.name,sizeof(q.name),"%s",name?name:"");
	if(s<0) return r;
	if(connect(s,(void*)&a,sizeof(a))) goto out;
	if(fd>=0) {
		struct cmsghdr *c;
		m.msg_control=control; m.msg_controllen=sizeof(control); c=CMSG_FIRSTHDR(&m);
		c->cmsg_level=SOL_SOCKET; c->cmsg_type=SCM_RIGHTS; c->cmsg_len=CMSG_LEN(sizeof(fd));
		memcpy(CMSG_DATA(c),&fd,sizeof(fd));
	}
	if(sendmsg(s,&m,MSG_NOSIGNAL)!=sizeof(q) || recv(s,&r,sizeof(r),0)!=sizeof(r)) r.error=-EIO;
out: close(s); return r;
}

static void until(uint64_t ns)
{
	struct timespec t={ns/1000000000ULL,ns%1000000000ULL};
	while(clock_nanosleep(CLOCK_MONOTONIC,TIMER_ABSTIME,&t,NULL)==EINTR) {}
}

static void snapshot(const char *label)
{
	const char *files[]={"/sys/fs/cgroup/cis-monitor/cpu.stat","/sys/fs/cgroup/cis-monitor/memory.current","/proc/stat","/proc/meminfo"};
	char b[8192];
	unsigned int i;
	for(i=0;i<sizeof(files)/sizeof(files[0]);i++) {
		int fd=open(files[i],O_RDONLY); ssize_t n;
		if(fd<0) continue;
		n=read(fd,b,sizeof(b)-1); close(fd);
		if(n>0) { b[n]=0; printf("CIS_SNAPSHOT %s %s\n%sCIS_SNAPSHOT_END\n",label,files[i],b); }
	}
}

int main(int argc,char **argv)
{
	unsigned int count=argc>1?strtoul(argv[1],NULL,10):1;
	const char *mode=argc>2?argv[2]:"off", *work=argc>3?argv[3]:"bench";
	unsigned int seconds=argc>4?strtoul(argv[4],NULL,10):3;
	unsigned int target=argc>5?strtoul(argv[5],NULL,10):0;
	pid_t pids[256]={0},daemon=-1;
	struct cis_reply ids[256];
	int monitored=strcmp(mode,"off"),idle=!strcmp(work,"idle"),ret=0,ready[2];
	int fixture=!strncmp(work,"fixture-",8);
	int async=!strcmp(work,"async-fixture");
	int quota=!strcmp(work,"quota"),compete=!strcmp(work,"cpu-compete"),reclaim=!strcmp(work,"reclaim");
	unsigned int i,cpus=sysconf(_SC_NPROCESSORS_ONLN);
	char path[128],num[32],starttext[32],out[128];
	uint64_t start;
	cpu_set_t mask;
	if(!count||count>256||target>=count||cpus<2||seconds<1||seconds>60) return 2;
	CPU_ZERO(&mask); CPU_SET(0,&mask); if(sched_setaffinity(0,sizeof(mask),&mask)) return 1;
	if(mkdir("/sys/fs/cgroup/cis-monitor",0755)) return 1;
	if(cis_write_text("/sys/fs/cgroup/cis-monitor/memory.max","67108864\n")) return 1;
	if(monitored) {
		if(pipe(ready)) return 1;
		daemon=fork();
		if(!daemon) {
			close(ready[0]); snprintf(num,sizeof(num),"%d",getpid());
			if(cis_write_text("/sys/fs/cgroup/cis-monitor/cgroup.procs",num)) _exit(119);
			snprintf(num,sizeof(num),"%d",ready[1]); snprintf(out,sizeof(out),"/tmp/observer-%d.jsonl",getpid());
			if(getenv("CIS_TEST_PROFILE_LOOP")) {
				execl("/cisd","cisd","--mode",!strcmp(mode,"diag")?"ip":mode,"--socket","/run/cis-fleet.sock","--output",out,"--bpf","/cis.bpf.o","--ready-fd",num,"--profile-loop",NULL);
				_exit(127);
			}
			execl("/cisd","cisd","--mode",!strcmp(mode,"diag")?"ip":mode,"--socket","/run/cis-fleet.sock","--output",out,"--bpf","/cis.bpf.o","--ready-fd",num,NULL); _exit(127);
		}
		close(ready[1]);
		char c;
		if(read(ready[0],&c,1)!=1) { close(ready[0]); waitpid(daemon,NULL,0); return 1; }
		close(ready[0]);
	}
	for(i=0;i<count;i++) {
		snprintf(path,sizeof(path),"/sys/fs/cgroup/cis-fleet-%u",i);
		if(mkdir(path,0755)) { ret=1; goto cleanup; }
		if(quota) {
			char setting[160]; snprintf(setting,sizeof(setting),"%s/cpu.max",path);
			if(cis_write_text(setting,"10000 100000\n")) { ret=1; goto cleanup; }
		}
		if(reclaim) {
			char setting[160]; snprintf(setting,sizeof(setting),"%s/memory.high",path);
			if(cis_write_text(setting,"16777216\n")) { ret=1; goto cleanup; }
			snprintf(setting,sizeof(setting),"%s/memory.max",path);
			if(cis_write_text(setting,"134217728\n")) { ret=1; goto cleanup; }
		}
		if(monitored) {
			int fd=open(path,O_RDONLY|O_DIRECTORY);
			snprintf(num,sizeof(num),"container-%u",i);
			ids[i]=request(CIS_REGISTER,fd,0,0,num); close(fd);
			if(ids[i].error) { ret=1; goto cleanup; }
		}
	}
	start=cis_now_ns()+2000000000ULL+count*20000000ULL;
	snprintf(starttext,sizeof(starttext),"%llu",(unsigned long long)start);
	snprintf(num,sizeof(num),"%u",seconds);
	printf("CIS_FLEET_BEGIN count=%u mode=%s workload=%s duration=%u target=%u start_ns=%llu cpus=%u observer_pid=%d\n",count,mode,work,seconds,target,(unsigned long long)start,cpus,daemon);
	fflush(stdout);
	if(!idle) for(i=0;i<count;i++) {
		char *args[]={"/workload",(char*)work,num,starttext,"2000",NULL};
		if(quota || compete) args[1]="bench";
		char slot[16];
		if(fixture) {
			snprintf(slot,sizeof(slot),"%u",!strcmp(work,"fixture-private")?i%2:0);
			args[1]="fixture"; args[2]=slot;
			if(!strcmp(work,"fixture-reuse")) args[4]="reuse";
		}
		snprintf(path,sizeof(path),"/sys/fs/cgroup/cis-fleet-%u",i);
		snprintf(out,sizeof(out),"/tmp/container-%d-%u.log",getpid(),i);
		int output=open(out,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);
		if(output<0) { ret=1; goto cleanup; }
		pids[i]=cis_container_start_output(path,"/container-root",args,compete?1:1+i%(cpus-1),output);
		close(output);
		if(pids[i]<0) { ret=1; goto cleanup; }
	}
	if((fixture || async) && monitored) {
		until(start-100000000ULL);
		for(i=0;i<count && i<2;i++) {
			struct cis_reply r=request(CIS_DIAGNOSE,-1,ids[i].id,ids[i].generation,async?"work":"lock");
			if(r.error) ret=1;
		}
	}
	if(!strcmp(mode,"diag") && !fixture && !async) {
		until(start-1000000000ULL);
		requested_start_ns=start;
		struct cis_reply r=request(CIS_DIAGNOSE,-1,ids[target].id,ids[target].generation,reclaim?"reclaim":"sched");
		if(r.error) ret=1;
	}
	until(start);
	snapshot("start");
	if(idle) until(start+seconds*1000000000ULL);
	else for(i=0;i<count;i++) { if(cis_container_wait(pids[i])) ret=1; pids[i]=0; }
	snapshot("end");
	if(monitored) {
		struct cis_reply health=request(CIS_STATUS,-1,0,0,"");
		printf("CIS_HEALTH %s\n",health.text);
		if(health.error || ((!strcmp(mode,"ip") || !strcmp(mode,"diag")) && !strstr(health.text,"capture=1"))) ret=1;
		if(!strcmp(mode,"metrics") && !strstr(health.text,"mode=1")) ret=1;
		if(!strstr(health.text,"errors=0 ")) ret=1;
	}
	if(!idle) for(i=0;i<count;i++) {
		char buffer[8192]; ssize_t n;
		snprintf(out,sizeof(out),"/tmp/container-%d-%u.log",getpid(),i);
		int input=open(out,O_RDONLY);
		if(input<0) { ret=1; continue; }
		fflush(stdout);
		while((n=read(input,buffer,sizeof(buffer)))>0) if(write(STDOUT_FILENO,buffer,n)!=n) ret=1;
		close(input);
	}
cleanup:
	for(i=0;i<count;i++) if(pids[i]>0) { kill(pids[i],SIGKILL); waitpid(pids[i],NULL,0); }
	if(monitored && daemon>0) {
		request(CIS_STOP,-1,0,0,NULL);
		if(cis_container_wait(daemon)) ret=1;
	}
	for(i=0;i<count;i++) { snprintf(path,sizeof(path),"/sys/fs/cgroup/cis-fleet-%u",i); if(rmdir(path) && errno!=ENOENT) ret=1; }
	if(rmdir("/sys/fs/cgroup/cis-monitor")) ret=1;
	printf("CIS_FLEET_END result=%s\n",ret?"FAIL":"PASS");
	return ret;
}
