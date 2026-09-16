// SPDX-License-Identifier: GPL-2.0
#include "include/cis.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define SYMBOL_CAP 65536
struct symbol { uint64_t address; char name[128]; };
struct symbols { unsigned int count; struct symbol entries[SYMBOL_CAP]; };
static int order(const void *a,const void *b)
{
	uint64_t x=((const struct symbol*)a)->address,y=((const struct symbol*)b)->address;
	return (x>y)-(x<y);
}
int cis_symbols_load(struct cis_context *ctx)
{
	struct symbols *s=calloc(1,sizeof(*s));
	FILE *f;
	char line[512],type,name[128],detail[160];
	unsigned long long address;
	unsigned int dropped=0;
	if(!s) return -1;
	f=fopen("/proc/kallsyms","r");
	if(!f) { free(s); return -1; }
	while(fgets(line,sizeof(line),f)) {
		if(strchr(line,'[') || sscanf(line,"%llx %c %127s",&address,&type,name)!=3 || !address || !strchr("tTwW",type)) continue;
		if(s->count==SYMBOL_CAP) { dropped++; continue; }
		s->entries[s->count].address=address;
		snprintf(s->entries[s->count].name,sizeof(s->entries[s->count].name),"%s",name); s->count++;
	}
	fclose(f);
	qsort(s->entries,s->count,sizeof(s->entries[0]),order); ctx->symbols=s;
	snprintf(detail,sizeof(detail),"symbols=%u excluded_over_cap=%u allocated_bytes=%zu kernel_text_only=1",s->count,dropped,sizeof(*s));
	cis_report(ctx,"symbol_coverage",NULL,detail);
	return s->count?0:-1;
}
const char *cis_symbol(struct cis_context *ctx,uint64_t ip)
{
	struct symbols *s=ctx->symbols;
	unsigned int lo=0,hi;
	if(!s || !s->count || ip<s->entries[0].address) return "unknown";
	hi=s->count;
	while(lo<hi) { unsigned int mid=lo+(hi-lo)/2; if(s->entries[mid].address<=ip) lo=mid+1; else hi=mid; }
	/* Do not turn holes, unloaded modules, or addresses beyond the table into a symbol. */
	if(!lo || ip-s->entries[lo-1].address>65536) return "unknown";
	return s->entries[lo-1].name;
}
void cis_symbols_free(struct cis_context *ctx) { free(ctx->symbols); ctx->symbols=NULL; }
