// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include "include/cis.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
int main(int argc,char **argv)
{
	struct sockaddr_un addr={.sun_family=AF_UNIX};
	struct cis_request req={.version=CIS_VERSION,.size=sizeof(req)};
	struct cis_reply rep;
	char control[CMSG_SPACE(sizeof(int))]={0};
	struct iovec iov={&req,sizeof(req)};
	struct msghdr msg={.msg_iov=&iov,.msg_iovlen=1};
	int i=1,fd=-1,sock,ret=1;
	const char *path=CIS_SOCKET;
	if (argc>3 && !strcmp(argv[1],"--socket")) { path=argv[2]; i=3; }
	if (argc<=i) return 2;
	if (!strcmp(argv[i],"register") && argc>i+1) {
		req.command=CIS_REGISTER; fd=open(argv[i+1],O_RDONLY|O_DIRECTORY|O_CLOEXEC);
		if (fd<0) { perror("cgroup"); return 1; }
		snprintf(req.name,sizeof(req.name),"%s",argc>i+2?argv[i+2]:"container");
	} else if ((!strcmp(argv[i],"unregister") || !strcmp(argv[i],"diagnose")) && argc>=i+3) {
		req.command=!strcmp(argv[i],"unregister")?CIS_UNREGISTER:CIS_DIAGNOSE;
		req.id=strtoull(argv[i+1],NULL,10); req.generation=strtoull(argv[i+2],NULL,10);
		if (argc>i+3) snprintf(req.name,sizeof(req.name),"%s",argv[i+3]);
	} else if (!strcmp(argv[i],"status")) req.command=CIS_STATUS;
	else if (!strcmp(argv[i],"stop")) req.command=CIS_STOP;
	else return 2;
	if (strlen(path)>=sizeof(addr.sun_path)) goto out;
	snprintf(addr.sun_path,sizeof(addr.sun_path),"%s",path);
	sock=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0);
	if (sock<0) goto out;
	if (connect(sock,(void*)&addr,sizeof(addr))) { perror("connect"); close(sock); goto out; }
	if (fd>=0) {
		struct cmsghdr *cm;
		msg.msg_control=control; msg.msg_controllen=sizeof(control);
		cm=CMSG_FIRSTHDR(&msg); cm->cmsg_level=SOL_SOCKET; cm->cmsg_type=SCM_RIGHTS; cm->cmsg_len=CMSG_LEN(sizeof(fd));
		memcpy(CMSG_DATA(cm),&fd,sizeof(fd));
	}
	if (sendmsg(sock,&msg,MSG_NOSIGNAL)!=sizeof(req) || recv(sock,&rep,sizeof(rep),0)!=sizeof(rep)) { close(sock); goto out; }
	close(sock);
	printf("error=%d id=%llu generation=%llu %s\n",rep.error,(unsigned long long)rep.id,(unsigned long long)rep.generation,rep.text);
	ret=rep.error?1:0;
out:
	if(fd>=0) close(fd);
	return ret;
}
