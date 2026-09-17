// SPDX-License-Identifier: GPL-2.0
#include <bpf/bpf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

static int snapshot(void)
{
	unsigned int kind, id, next, count;
	if(geteuid()) return 2;
	printf("{");
	for(kind=0;kind<2;kind++) {
		id=0;count=0;
		printf("%s\"%s\":[",kind?",":"",kind?"programs":"maps");
		for(;;) {
			int rc=kind?bpf_prog_get_next_id(id,&next):bpf_map_get_next_id(id,&next);
			if(rc) { if(errno!=ENOENT) return 2; break; }
			if(++count>4096) return 2;
			printf("%s%u",count>1?",":"",next);id=next;
		}
		printf("]");
	}
	printf("}\n");return 0;
}
int main(int argc,char **argv)
{
	int i,present=0;
	if(argc==2 && !strcmp(argv[1],"--snapshot")) return snapshot();
	for(i=1;i<argc;i++) {
		unsigned int id; char kind,extra; int fd;
		if(sscanf(argv[i],"%c:%u%c",&kind,&id,&extra)!=2 || (kind!='m' && kind!='p')) return 2;
		fd=kind=='m'?bpf_map_get_fd_by_id(id):bpf_prog_get_fd_by_id(id);
		if(fd>=0) { close(fd); present++; }
		else if(errno!=ENOENT) { perror("residue check"); return 2; }
	}
	printf("{\"checked\":%d,\"present_or_reused\":%d}\n",argc-1,present);
	return present?1:0;
}
