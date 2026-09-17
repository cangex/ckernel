// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../../../container_interference/include/cis_recursion_snapshot.h"

static int parse(const char *text,struct cis_recursion_snapshot *s)
{
	FILE *file=fmemopen((void *)text,strlen(text),"r");
	int rc=cis_recursion_read(file,s);
	fclose(file);
	return rc;
}

int main(void)
{
	struct cis_recursion_snapshot a,b;
	uint64_t delta;
	assert(!parse("version=3 enabled=0 trace_active=0 synchronized=1\ncpu=0 skipped=4 sync=0\ncpu=1 skipped=9\n",&a));
	assert(!parse("version=3 enabled=0 trace_active=0 synchronized=1\ncpu=0 skipped=4\ncpu=1 skipped=10\n",&b));
	assert(!cis_recursion_delta(&a,&b,&delta) && delta==1);
	assert(parse("version=3 enabled=0 trace_active=1 synchronized=1\ncpu=0 skipped=0\n",&b));
	assert(parse("version=2 enabled=0 trace_active=0\ncpu=0 skipped=0\n",&b));
	assert(parse("version=3 enabled=0 trace_active=0 synchronized=0\ncpu=0 skipped=0\n",&b));
	assert(parse("version=3 enabled=0 trace_active=0 synchronized=1\ncpu=0 skipped=0\ncpu=0 skipped=0\n",&b));
	assert(parse("version=3 enabled=0 trace_active=0 synchronized=1\ncpu=512 skipped=0\n",&b));
	assert(parse("version=3 enabled=0 trace_active=0 synchronized=1\n",&b));
	assert(!parse("version=3 enabled=0 trace_active=0 synchronized=1\ncpu=0 skipped=0\ncpu=1 skipped=10\n",&b));
	assert(cis_recursion_delta(&a,&b,&delta));
	assert(!parse("version=3 enabled=0 trace_active=0 synchronized=1\ncpu=0 skipped=4\n",&b));
	assert(cis_recursion_delta(&a,&b,&delta));
	puts("recursion_snapshot_test: PASS");
	return 0;
}
