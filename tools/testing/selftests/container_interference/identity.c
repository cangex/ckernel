// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include "common.h"
#include "../../../container_interference/include/cis.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
static unsigned int checks,failures;
#define CHECK(name,expr) do { int ok=!!(expr); printf("CIS_CHECK %s %s\n",name,ok?"PASS":"FAIL"); checks++; failures+=!ok; } while(0)
static struct cis_reply call(unsigned int command,int fd,uint64_t id,uint64_t generation,const char *name)
{
	struct sockaddr_un a={.sun_family=AF_UNIX,.sun_path="/run/cis-test.sock"};
	struct cis_request q={.version=CIS_VERSION,.size=sizeof(q),.command=command,.id=id,.generation=generation};
	struct cis_reply r={.error=-EIO};
	char control[CMSG_SPACE(sizeof(int))]={0};
	struct iovec iov={&q,sizeof(q)};
	struct msghdr m={.msg_iov=&iov,.msg_iovlen=1};
	int s=socket(AF_UNIX,SOCK_SEQPACKET,0);
	snprintf(q.name,sizeof(q.name),"%s",name?name:"");
	if(s<0) return r;
	if(connect(s,(void*)&a,sizeof(a))) goto done;
	if(fd>=0) {
		struct cmsghdr *cm;
		m.msg_control=control; m.msg_controllen=sizeof(control); cm=CMSG_FIRSTHDR(&m);
		cm->cmsg_level=SOL_SOCKET; cm->cmsg_type=SCM_RIGHTS; cm->cmsg_len=CMSG_LEN(sizeof(fd)); memcpy(CMSG_DATA(cm),&fd,sizeof(fd));
	}
	if(sendmsg(s,&m,MSG_NOSIGNAL)!=sizeof(q)) goto done;
	if(recv(s,&r,sizeof(r),0)!=sizeof(r)) r.error=-EIO;
done: close(s); return r;
}
static pid_t start(const char *mode)
{
	int pipefd[2];
	pid_t pid;
	char c,fdtext[24],out[128];
	if(pipe(pipefd)) return -1;
	pid=fork();
	if(!pid) {
		close(pipefd[0]); snprintf(fdtext,sizeof(fdtext),"%d",pipefd[1]);
		snprintf(out,sizeof(out),"/tmp/cis-%s-%d.jsonl",mode,getpid());
		execl("/cisd","cisd","--socket","/run/cis-test.sock","--mode",mode,"--bpf","/cis.bpf.o","--ready-fd",fdtext,"--output",out,NULL); _exit(127);
	}
	close(pipefd[1]);
	if(read(pipefd[0],&c,1)!=1) { close(pipefd[0]); waitpid(pid,NULL,0); return -1; }
	close(pipefd[0]); return pid;
}
static int config_change_seen(const char *mode,pid_t daemon,uint64_t id)
{
	char path[128],line[2048],identity[64];
	FILE *f;
	int found=0;
	snprintf(path,sizeof(path),"/tmp/cis-%s-%d.jsonl",mode,daemon);
	snprintf(identity,sizeof(identity),"\"id\":%llu,",(unsigned long long)id);
	f=fopen(path,"r"); if(!f) return 0;
	while(fgets(line,sizeof(line),f))
		if(strstr(line,"\"kind\":\"config_epoch\"") && strstr(line,identity)) found=1;
	fclose(f); return found;
}
int main(int argc,char **argv)
{
	const char *mode=argc>1?argv[1]:"metrics";
	int a,b,child,ordinary,status;
	pid_t daemon,worker;
	struct cis_reply ra,rb,reply,again;
	char *args[]={"/workload","bench","3",NULL};
	if(mkdir("/sys/fs/cgroup/cis-a",0755) || mkdir("/sys/fs/cgroup/cis-b",0755)) return 1;
	a=open("/sys/fs/cgroup/cis-a",O_RDONLY|O_DIRECTORY); b=open("/sys/fs/cgroup/cis-b",O_RDONLY|O_DIRECTORY);
	if(a<0||b<0) return 1;
	daemon=start(mode); CHECK("daemon_start",daemon>0); if(daemon<0) return 1;
	ra=call(CIS_REGISTER,a,0,0,"a"); rb=call(CIS_REGISTER,b,0,0,"b");
	CHECK("register_two",!ra.error && !rb.error && ra.id!=rb.id && ra.generation!=rb.generation);
	reply=call(CIS_REGISTER,a,0,0,"duplicate"); CHECK("duplicate_rejected",reply.error==-EEXIST);
	mkdir("/sys/fs/cgroup/cis-a/child",0755); child=open("/sys/fs/cgroup/cis-a/child",O_RDONLY|O_DIRECTORY);
	reply=call(CIS_REGISTER,child,0,0,"overlap"); CHECK("overlap_rejected",reply.error==-EEXIST);
	ordinary=open("/",O_RDONLY|O_DIRECTORY); reply=call(CIS_REGISTER,ordinary,0,0,"ordinary"); close(ordinary);
	CHECK("non_cgroup_rejected",reply.error==-EOPNOTSUPP);
	CHECK("create_race_root",!mkdir("/sys/fs/cgroup/cis-race",0755));
	ordinary=open("/sys/fs/cgroup/cis-race",O_RDONLY|O_DIRECTORY);
	{
		pid_t racers[8]; unsigned int i,won=0,duplicates=0;
		for(i=0;i<8;i++) {
			racers[i]=fork();
			if(!racers[i]) {
				struct cis_reply response=call(CIS_REGISTER,ordinary,0,0,"race");
				_exit(!response.error?0:response.error==-EEXIST?10:20);
			}
		}
		for(i=0;i<8;i++) if(racers[i]>0 && waitpid(racers[i],&status,0)==racers[i] && WIFEXITED(status)) {
			won+=WEXITSTATUS(status)==0; duplicates+=WEXITSTATUS(status)==10;
		}
		CHECK("concurrent_registration_one_winner",won==1 && duplicates==7);
	}
	close(ordinary); CHECK("remove_race_root",!rmdir("/sys/fs/cgroup/cis-race")); sleep(2);
	reply=call(CIS_UNREGISTER,-1,ra.id,ra.generation+123,""); CHECK("stale_generation_rejected",reply.error==-ENOENT);
	worker=cis_container_start("/sys/fs/cgroup/cis-a/child","/container-root",args,1);
	CHECK("dynamic_descendant_container",worker>0 && !cis_container_wait(worker));
	if(!strcmp(mode,"ip")) {
		char *moving[]={"/workload","bench","3",NULL};
		char pidtext[32];
		worker=cis_container_start("/sys/fs/cgroup/cis-a/child","/container-root",moving,1);
		CHECK("migration_container_started",worker>0);
		if(worker>0) {
			usleep(1000000); snprintf(pidtext,sizeof(pidtext),"%d",worker);
			printf("CIS_MIGRATION_BEGIN tid=%d time_ns=%llu from=%llu to=%llu\n",worker,(unsigned long long)cis_now_ns(),(unsigned long long)ra.id,(unsigned long long)rb.id);
			CHECK("migration_write",!cis_write_text("/sys/fs/cgroup/cis-b/cgroup.procs",pidtext));
			printf("CIS_MIGRATION_END tid=%d time_ns=%llu\n",worker,(unsigned long long)cis_now_ns());
			CHECK("migration_completed",!cis_container_wait(worker));
		}
		reply=call(CIS_DIAGNOSE,-1,ra.id,ra.generation,"sched"); CHECK("diagnostic_queue",!reply.error);
		worker=cis_container_start("/sys/fs/cgroup/cis-a/child","/container-root",args,1);
		CHECK("diagnostic_container",worker>0 && !cis_container_wait(worker));
		reply=call(CIS_STATUS,-1,0,0,"");
		CHECK("diagnostic_deadline_stopped",!reply.error && strstr(reply.text,"diagnostics=0"));
		reply=call(CIS_DIAGNOSE,-1,ra.id,ra.generation,"sched");
		CHECK("diagnostic_cooldown",reply.error==-EAGAIN);
	}
	CHECK("configuration_write",!cis_write_text("/sys/fs/cgroup/cis-a/cpu.max","50000 100000\n"));
	{
		unsigned int attempt;
		for(attempt=0;attempt<70 && !config_change_seen(mode,daemon,ra.id);attempt++) usleep(100000);
		CHECK("configuration_epoch_observed",config_change_seen(mode,daemon,ra.id));
	}
	reply=call(CIS_UNREGISTER,-1,ra.id,ra.generation,""); CHECK("unregister",!reply.error);
	again=call(CIS_REGISTER,a,0,0,"a-new-generation"); CHECK("reregister_generation",!again.error && again.generation!=ra.generation);
	CHECK("v2_rename_rejected_by_kernel",rename("/sys/fs/cgroup/cis-a","/sys/fs/cgroup/cis-renamed")<0);
	reply=call(CIS_REGISTER,child,0,0,"overlap-after-rejected-rename"); CHECK("overlap_still_rejected",reply.error==-EEXIST);
	CHECK("create_deleted_root",!mkdir("/sys/fs/cgroup/cis-deleted",0755));
	ordinary=open("/sys/fs/cgroup/cis-deleted",O_RDONLY|O_DIRECTORY);
	reply=call(CIS_REGISTER,ordinary,0,0,"deleted"); close(ordinary);
	CHECK("register_deleted_root",!reply.error);
	CHECK("remove_registered_empty_root",!rmdir("/sys/fs/cgroup/cis-deleted"));
	sleep(2);
	reply=call(CIS_STATUS,-1,0,0,""); CHECK("deleted_root_retired",!reply.error && strstr(reply.text,"roots=2 "));
	call(CIS_STOP,-1,0,0,""); waitpid(daemon,&status,0); CHECK("daemon_clean_stop",WIFEXITED(status)&&!WEXITSTATUS(status));
	/* Deliberate crash must leave no pinned BPF collectors; new registration is explicit. */
	daemon=start(mode); CHECK("restart",daemon>0);
	if(daemon>0) { reply=call(CIS_REGISTER,b,0,0,"restart-b"); CHECK("restart_register",!reply.error); kill(daemon,SIGKILL); waitpid(daemon,&status,0); unlink("/run/cis-test.sock"); }
	close(child); close(a); close(b);
	CHECK("remove_descendant",!rmdir("/sys/fs/cgroup/cis-a/child"));
	CHECK("remove_roots",!rmdir("/sys/fs/cgroup/cis-a") && !rmdir("/sys/fs/cgroup/cis-b"));
	CHECK("recreate_path",!mkdir("/sys/fs/cgroup/cis-a",0755));
	a=open("/sys/fs/cgroup/cis-a",O_RDONLY|O_DIRECTORY);
	if(a>=0) {
		struct stat st;
		CHECK("new_cgroup_identity",!fstat(a,&st) && (uint64_t)st.st_ino!=ra.id);
		close(a); CHECK("remove_recreated",!rmdir("/sys/fs/cgroup/cis-a"));
	}
	printf("CIS_IDENTITY_RESULT checks=%u failures=%u\n",checks,failures);
	return failures?1:0;
}
