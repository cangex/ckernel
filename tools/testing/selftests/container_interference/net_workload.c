// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include "net_fixture/uapi.h"

static int until(uint64_t ns)
{
	struct timespec t = { .tv_sec = ns / 1000000000ULL, .tv_nsec = ns % 1000000000ULL };
	int error;
	do { error = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &t, NULL); } while (error == EINTR);
	return error;
}

static int socket_cookie(int fd, uint64_t *cookie)
{
	socklen_t length=sizeof(*cookie);
	return getsockopt(fd,SOL_SOCKET,SO_COOKIE,cookie,&length) || length!=sizeof(*cookie) || !*cookie;
}

static uint64_t now_ns(void)
{
	struct timespec t;
	if (clock_gettime(CLOCK_MONOTONIC,&t)) return 0;
	return (uint64_t)t.tv_sec*1000000000ULL+t.tv_nsec;
}

static int origin_record(int fd, unsigned int operation, uint64_t begin, uint64_t end)
{
	uint64_t cookie;
	if (fd<0 || socket_cookie(fd,&cookie) || !begin || end<begin) return -1;
	printf("CIS_NET_ORIGIN operation=%u cookie=%llu begin_ns=%llu end_ns=%llu\n",
		operation,(unsigned long long)cookie,(unsigned long long)begin,(unsigned long long)end);
	fflush(stdout);
	return fd;
}

static int create_tcp(void)
{
	uint64_t begin=now_ns();
	int fd=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0);
	uint64_t end=now_ns();
	if (origin_record(fd,1,begin,end)<0) { if(fd>=0) close(fd); return -1; }
	return fd;
}

static int accept_tcp(void)
{
	struct ifreq interface={0};
	struct sockaddr_in addr={.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
	socklen_t length=sizeof(addr);
	int listener=-1,client=-1,accepted=-1;
	uint64_t begin,end;
	listener=create_tcp();
	if (listener<0) goto out;
	memcpy(interface.ifr_name,"lo",3);
	if (ioctl(listener,SIOCGIFFLAGS,&interface)) goto out;
	interface.ifr_flags |= IFF_UP;
	if (ioctl(listener,SIOCSIFFLAGS,&interface) ||
	    bind(listener,(void *)&addr,sizeof(addr)) || listen(listener,1) ||
	    getsockname(listener,(void *)&addr,&length)) goto out;
	client=create_tcp();
	if (client<0 || connect(client,(void *)&addr,sizeof(addr))) goto out;
	begin=now_ns(); accepted=accept4(listener,NULL,NULL,SOCK_CLOEXEC); end=now_ns();
	if (origin_record(accepted,2,begin,end)<0) { if(accepted>=0) close(accepted); accepted=-1; }
out:
	if(client>=0) close(client);
	if(listener>=0) close(listener);
	return accepted;
}

/* A real SCM_RIGHTS transfer, between the already isolated fixture actors. */
static int transfer_socket(int channel, unsigned int actor, int private_socket, int accepted_socket)
{
	union { char bytes[CMSG_SPACE(sizeof(int))]; struct cmsghdr aligned; } control={0};
	char byte='S';
	struct iovec iov={.iov_base=&byte,.iov_len=1};
	struct msghdr msg={.msg_iov=&iov,.msg_iovlen=1,.msg_control=control.bytes,.msg_controllen=sizeof(control)};
	struct cmsghdr *cmsg;
	struct timeval timeout={.tv_sec=2};
	uint64_t sent=0,received=0,used=0,ack=0;
	int fd=-1;
	if(setsockopt(channel,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout)) ||
	   setsockopt(channel,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout))) return -1;
	if(!actor) {
		fd=accepted_socket ? accept_tcp() : create_tcp();
		if(fd<0 || socket_cookie(fd,&sent)) goto fail;
		cmsg=CMSG_FIRSTHDR(&msg); cmsg->cmsg_level=SOL_SOCKET; cmsg->cmsg_type=SCM_RIGHTS;
		cmsg->cmsg_len=CMSG_LEN(sizeof(fd)); memcpy(CMSG_DATA(cmsg),&fd,sizeof(fd));
		if(sendmsg(channel,&msg,MSG_NOSIGNAL)!=1 || recv(channel,&ack,sizeof(ack),0)!=(ssize_t)sizeof(ack) || ack!=sent) goto fail;
	} else {
		if(recvmsg(channel,&msg,MSG_CMSG_CLOEXEC)!=1) goto fail;
		cmsg=CMSG_FIRSTHDR(&msg);
		if(!cmsg || cmsg->cmsg_level!=SOL_SOCKET || cmsg->cmsg_type!=SCM_RIGHTS || cmsg->cmsg_len!=CMSG_LEN(sizeof(fd))) goto fail;
		memcpy(&fd,CMSG_DATA(cmsg),sizeof(fd));
		if(msg.msg_flags&(MSG_CTRUNC|MSG_TRUNC) || CMSG_NXTHDR(&msg,cmsg) || byte!='S' || socket_cookie(fd,&received)) goto fail;
		if(send(channel,&received,sizeof(received),MSG_NOSIGNAL)!=(ssize_t)sizeof(received)) goto fail;
		if(private_socket) {
			close(fd); fd=create_tcp();
			if(fd<0) goto fail;
		}
	}
	if(socket_cookie(fd,&used)) goto fail;
	printf("CIS_NET_RIGHTS actor=%u sent_cookie=%llu received_cookie=%llu used_cookie=%llu private=%d\n",
		actor,(unsigned long long)sent,(unsigned long long)received,(unsigned long long)used,private_socket);
	fflush(stdout); close(channel); return fd;
fail:
	if(fd>=0) close(fd);
	return -1;
}

int main(int argc, char **argv)
{
	struct cis_net_test_request r = {0};
	uint64_t start, cookie = 0;
	socklen_t length = sizeof(cookie);
	unsigned int i, actor, swap, rights, private_socket;
	int device, fd;
	if (argc != 5 && argc != 6) return 2;
	if (argc == 6 && strcmp(argv[5],"origin")) return 2;
	fd = atoi(argv[1]); actor = strtoul(argv[2], NULL, 10);
	start = strtoull(argv[3], NULL, 10);
	rights=!strcmp(argv[4],"rightsShared") || !strcmp(argv[4],"rightsPrivate") || !strcmp(argv[4],"rightsAccept");
	private_socket=!strcmp(argv[4],"rightsPrivate");
	swap = !strcmp(argv[4], "switch") || rights;
	if (fd < 0 || actor > 1 || (strcmp(argv[4], "shared") && strcmp(argv[4], "private") && !swap)) return 2;
	if (argc == 6 && (!rights || start<300000000ULL || until(start-300000000ULL))) return 5;
	if(rights) { fd=transfer_socket(fd,actor,private_socket,!strcmp(argv[4],"rightsAccept")); if(fd<0) { perror("SCM_RIGHTS"); return 8; } }
	if (getsockopt(fd, SOL_SOCKET, SO_COOKIE, &cookie, &length) || length != sizeof(cookie) || !cookie) return 3;
	device = open("/dev/cis-net-test", O_RDWR | O_CLOEXEC);
	if (device < 0) return 4;
	for (i = 0; i < 4; i++) {
		unsigned int holder = swap ? i % 2 : 0;
		r = (struct cis_net_test_request) { .fd = fd, .cookie = cookie, .hold_ms = actor == holder ? 30 : 0 };
		if (until(start + i * 100000000ULL + (actor == holder ? 0 : 5000000ULL))) return 5;
		if (ioctl(device, CIS_NET_TEST_HOLD, &r)) { perror("net hold"); return 6; }
		printf("CIS_NET_TRUTH index=%u actor=%u cookie=%llu socket=%llu enter_ns=%llu acquired_ns=%llu release_begin_ns=%llu released_ns=%llu cpu=%u hold_ms=%u scenario=%s\n",
			i, actor, (unsigned long long)cookie, (unsigned long long)r.socket_address,
			(unsigned long long)r.enter_ns, (unsigned long long)r.acquired_ns,
			(unsigned long long)r.release_begin_ns, (unsigned long long)r.released_ns,
			r.cpu, r.hold_ms, argv[4]);
		fflush(stdout);
	}
	/* The inherited socket remains real; this fixture never changes its protocol. */
	return close(device) ? 7 : 0;
}
