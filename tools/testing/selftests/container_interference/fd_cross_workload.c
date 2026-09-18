// SPDX-License-Identifier: GPL-2.0
/* Explicit CLONE_FILES control, not the normal isolated-container FD model. */
#define _GNU_SOURCE
#include "common.h"
#include "fixture/uapi.h"
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define OPS 16
#define STACK_BYTES (1024 * 1024)
struct child {
	int ready, go, error, cpu, fd, pidns_init;
	unsigned long long start;
	struct cis_fixture_fd truth[OPS];
};

static int work(void *data)
{
	struct child *c = data;
	cpu_set_t set;
	CPU_ZERO(&set); CPU_SET(c->cpu, &set);
	if (prctl(PR_SET_PDEATHSIG, SIGKILL) || sched_setaffinity(0,sizeof(set),&set) ||
	    mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL) ||
	    mount("/container-root","/container-root",NULL,MS_BIND,NULL) ||
	    mount(NULL,"/container-root",NULL,MS_BIND|MS_REMOUNT|MS_RDONLY,NULL) ||
	    chdir("/container-root") || chroot(".") || chdir("/") ||
	    mount("proc","/proc","proc",MS_NOSUID|MS_NODEV|MS_NOEXEC,NULL) ||
	    mount("tmpfs","/tmp","tmpfs",MS_NOSUID|MS_NODEV,"size=16m") ||
	    sethostname("cis-fd-shared",13)) { c->error=errno; return 1; }
	c->pidns_init = getpid()==1;
	__atomic_store_n(&c->ready,1,__ATOMIC_RELEASE);
	/* No exec: Linux exec unshares files_struct and would invalidate this test. */
	while (!__atomic_load_n(&c->go,__ATOMIC_ACQUIRE)) {
		struct timespec pause={.tv_nsec=1000000}; nanosleep(&pause,NULL);
		if (cis_now_ns()>c->start) { c->error=ETIMEDOUT; return 1; }
	}
	struct timespec deadline={.tv_sec=c->start/1000000000,.tv_nsec=c->start%1000000000};
	int rc;
	do { rc=clock_nanosleep(CLOCK_MONOTONIC,TIMER_ABSTIME,&deadline,NULL); } while (rc==EINTR);
	if (rc) { c->error=rc; return 1; }
	for (int i=0;i<OPS;i++) {
		c->truth[i].hold_us=100;
		if (ioctl(c->fd,CIS_FIXTURE_FD,&c->truth[i])) {c->error=errno;return 1;}
	}
	return 0;
}

int main(int argc,char **argv)
{
	if (argc!=6 || access("/cis-disposable-vm",F_OK)) return 2;
	unsigned long long start=strtoull(argv[5],NULL,10);
	if (start<cis_now_ns()+100000000 || start>cis_now_ns()+2000000000) return 2;
	struct child *children=mmap(NULL,2*sizeof(*children),PROT_READ|PROT_WRITE,
				   MAP_SHARED|MAP_ANONYMOUS,-1,0);
	if (children==MAP_FAILED) return 1;
	int fd=open("/dev/cis-fixture",O_RDWR|O_CLOEXEC),failed=0;
	FILE *logs[2]={NULL,NULL}; pid_t pids[2]={0,0}; void *stacks[2]={NULL,NULL};
	if (fd<0) return 1;
	for (int i=0;i<2;i++) {
		logs[i]=fopen(argv[3+i],"wx"); stacks[i]=malloc(STACK_BYTES);
		if (!logs[i] || !stacks[i]) {failed=1;goto done;}
		children[i]=(struct child){.cpu=i*2,.fd=fd,.start=start};
	}
	for (int i=0;i<2;i++) {
		int flags=CLONE_FILES|CLONE_NEWNS|CLONE_NEWPID|CLONE_NEWUTS|
			CLONE_NEWIPC|CLONE_NEWNET|CLONE_NEWCGROUP|SIGCHLD;
		pids[i]=clone(work,(char *)stacks[i]+STACK_BYTES,flags,&children[i]);
		if (pids[i]<0) {failed=1;goto done;}
		char path[512],number[32];
		if (snprintf(path,sizeof(path),"%s/cgroup.procs",argv[1+i])>=(int)sizeof(path)) {failed=1;goto done;}
		snprintf(number,sizeof(number),"%d\n",pids[i]);
		if (cis_write_text(path,number)) {failed=1;goto done;}
	}
	for (int i=0;i<2;i++) {
		while (!__atomic_load_n(&children[i].ready,__ATOMIC_ACQUIRE)) {
			struct timespec pause={.tv_nsec=1000000}; nanosleep(&pause,NULL);
			if (children[i].error || cis_now_ns()>start) {failed=1;goto done;}
		}
		__atomic_store_n(&children[i].go,1,__ATOMIC_RELEASE);
	}
done:
	for (int i=0;i<2;i++) if (pids[i]>0) {
		if (failed) kill(pids[i],SIGKILL);
		if (cis_container_wait(pids[i])) failed=1;
	}
	for (int i=0;i<2;i++) {
		struct child *c=&children[i];
		if (logs[i]) {
			fprintf(logs[i],"CIS_FD_SHARED {\"host_pid\":%d,\"pidns_init\":%d,\"explicit_clone_files\":true,\"error\":%d}\n",pids[i],c->pidns_init,c->error);
			if (!failed) for (int j=0;j<OPS;j++) {
				struct cis_fixture_fd *q=&c->truth[j];
				fprintf(logs[i],"CIS_FD_TRUTH {\"object\":%llu,\"files\":%llu,\"tid\":%llu,\"tgid\":%llu,\"cgroup_id\":%llu,\"begin_ns\":%llu,\"acquired_ns\":%llu,\"release_begin_ns\":%llu,\"released_ns\":%llu}\n",
					q->object,q->files,q->tid,q->tgid,q->cgroup_id,q->begin_ns,q->acquired_ns,q->release_begin_ns,q->released_ns);
			}
			fprintf(logs[i],"CIS_FD_DONE {\"threads\":1,\"operations_per_thread\":16,\"native\":0,\"failed\":%d}\n",failed);
			fclose(logs[i]);
		}
		free(stacks[i]);
	}
	close(fd);munmap(children,2*sizeof(*children));return failed;
}
