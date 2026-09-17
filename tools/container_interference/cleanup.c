// SPDX-License-Identifier: GPL-2.0
#include <bpf/bpf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main(int argc,char **argv)
{
	int i,present=0;
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
