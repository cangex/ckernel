#include <linux/ckernel.h>
#include <linux/fs.h>
#include "ckernel_driver.h"

/*
 * Skip handler: indicate ckernel does not handle accounting.
 * Caller should fallback to original cgroup logic.
 */
int ck_skip_file_inc(u64 n)
{
	return -1;
}

/*
 * Try to charge file descriptors to ckernel.
 *
 * Return:
 *   1  - success (charged)
 *   0  - handled but failed (limit exceeded)
 *  -1  - not handled (fallback)
 */
int ck_do_file_inc(u64 n)
{
	struct ckernel *ck = current->ckernel;
	long max;
	long new;

	if (!ck)
		return -1;

	max = atomic_long_read(&ck->file_max);

	if (unlikely(n > max))
		return 0;

	/*
	 * D_COUNT_MAX is the normal, effectively unbounded configuration. No
	 * observable usage interface consumes this count, so avoid touching a
	 * shared cacheline for every dup/open operation.
	 */
	if (likely(max == D_COUNT_MAX)) {
		if (unlikely(!READ_ONCE(ck->file_accounting_started)))
			WRITE_ONCE(ck->file_accounting_started, true);
		return 1;
	}

	new = atomic_long_add_return_relaxed(n, &ck->file_usage);
	if (unlikely(new < 0 || new > max)) {
		atomic_long_sub(n, &ck->file_usage);
		return 0;
	}

	WRITE_ONCE(ck->file_accounting_started, true);
	return 1;
}

int ck_skip_file_dec(u64 n)
{
	return -1;
}

/*
 * Release file descriptor usage from ckernel.
 *
 * Always succeeds if handled.
 */
int ck_do_file_dec(u64 n)
{
	struct ckernel *ck = current->ckernel;
	long old;

	if (!ck)
		return -1;

	/* Descriptors inherited before ckernel attachment stay legacy-charged. */
	if (unlikely(!READ_ONCE(ck->file_accounting_started)))
		return -1;

	if (likely(atomic_long_read(&ck->file_max) == D_COUNT_MAX))
		return 1;

	old = atomic_long_fetch_sub_relaxed(n, &ck->file_usage);
	if (unlikely(old < 0 || (u64)old < n)) {
		/* Inherited descriptors remain charged to the legacy cgroup. */
		atomic_long_add(n, &ck->file_usage);
		return -1;
	}

	return 1;
}
