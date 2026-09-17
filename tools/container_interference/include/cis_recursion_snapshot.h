/* SPDX-License-Identifier: GPL-2.0 */
#ifndef CIS_RECURSION_SNAPSHOT_H
#define CIS_RECURSION_SNAPSHOT_H
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CIS_RECURSION_CPUS 512
struct cis_recursion_snapshot {
	uint64_t skipped[CIS_RECURSION_CPUS];
	unsigned char seen[CIS_RECURSION_CPUS];
	unsigned int count;
};

/* Only quiescent snapshots are accepted. No snapshot I/O in a probe/window. */
static int cis_recursion_read(FILE *file, struct cis_recursion_snapshot *s)
{
	char line[512];
	unsigned int version,enabled,active,synchronized,cpu;
	unsigned long long skipped;
	memset(s,0,sizeof(*s));
	if(!file || !fgets(line,sizeof(line),file) ||
	   sscanf(line,"version=%u enabled=%u trace_active=%u synchronized=%u",&version,&enabled,&active,&synchronized)!=4 ||
	   version!=3 || active || synchronized!=1) return -1;
	while(fgets(line,sizeof(line),file)) {
		if(strncmp(line,"cpu=",4)) continue;
		if(sscanf(line,"cpu=%u skipped=%llu",&cpu,&skipped)!=2 ||
		   cpu>=CIS_RECURSION_CPUS || s->seen[cpu]) return -1;
		s->seen[cpu]=1; s->skipped[cpu]=skipped; s->count++;
	}
	return ferror(file) || !s->count ? -1 : 0;
}

static int cis_recursion_delta(const struct cis_recursion_snapshot *a,
		const struct cis_recursion_snapshot *b,uint64_t *delta)
{
	unsigned int i;
	*delta=0;
	for(i=0;i<CIS_RECURSION_CPUS;i++) {
		uint64_t d;
		if(a->seen[i]!=b->seen[i] || b->skipped[i]<a->skipped[i]) return -1;
		d=b->skipped[i]-a->skipped[i];
		if(UINT64_MAX-*delta<d) return -1;
		*delta+=d;
	}
	return a->count && a->count==b->count ? 0 : -1;
}
#endif
