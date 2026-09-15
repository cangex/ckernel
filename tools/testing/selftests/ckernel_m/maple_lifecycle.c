// SPDX-License-Identifier: GPL-2.0
#include "common.h"
#include <sched.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>

static int shared_mm(void *arg)
{
	*(volatile int *)arg = 42;
	return 0;
}

int test_main(int argc, char **argv)
{
	long page = sysconf(_SC_PAGESIZE);
	char *v, *w;
	void *stack;
	int round, j, value = 0;
	pid_t child;

	(void)argc; (void)argv;
	for (round = 0; round < 32; round++) {
		v = mmap(NULL, page * 512, PROT_READ | PROT_WRITE,
			 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		CHECK(v != MAP_FAILED);
		/* Alternate permissions to force VMA splits, not merged mmap calls. */
		for (j = 1; j < 512; j += 2)
			CHECK(!mprotect(v + j * page, page, PROT_READ));
		v[0] = 17;
		child = fork();
		if (!child)
			_exit(v[0] == 17 && !munmap(v, page * 512) ? 0 : 1);
		CHECK(!child_result(child) && v[0] == 17);
		CHECK(!mprotect(v, page * 512, PROT_READ | PROT_WRITE));
		w = mremap(v, page * 512, page * 1024, MREMAP_MAYMOVE);
		CHECK(w != MAP_FAILED && w[0] == 17);
		CHECK(!munmap(w, page * 1024));
	}
	stack = mmap(NULL, 65536, PROT_READ | PROT_WRITE,
		     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	CHECK(stack != MAP_FAILED);
	child = clone(shared_mm, (char *)stack + 65536, CLONE_VM | SIGCHLD, &value);
	CHECK(!child_result(child) && value == 42);
	munmap(stack, 65536);
	w = sbrk(0);
	CHECK(sbrk(page) == w);
	memset(w, 0, page);
	CHECK(!brk(w));
	return 0;
}
