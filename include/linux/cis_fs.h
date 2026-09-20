/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_CIS_FS_H
#define _LINUX_CIS_FS_H
#include <linux/types.h>
enum cis_fs_operation {
	CIS_FS_COMMIT_WAIT = 1, CIS_FS_TRANSACTION_WAIT, CIS_FS_ALLOC_GROUP,
	CIS_FS_ORPHAN_ADD, CIS_FS_ORPHAN_DEL, CIS_FS_ORPHAN_FILE,
};
struct cis_fs_sample {
	u64 begin_ns, acquired_ns, end_ns, lease, cgroup_id;
	u64 resource, value, count;
	u32 dev, operation, sample_shift, flags;
	s32 error;
};
#ifdef CONFIG_CIS_OBSERVE_FS
#include <linux/ktime.h>
#include <linux/tracepoint-defs.h>
DECLARE_TRACEPOINT(cis_fs_state);
void __cis_fs_begin(struct cis_fs_sample *, dev_t, const void *, u32, u64);
void __cis_fs_end(struct cis_fs_sample *, u64, int);
int cis_fs_register(void);
void cis_fs_unregister(void);
bool cis_fs_active(void);
static inline bool cis_fs_source_enabled(void) { return tracepoint_enabled(cis_fs_state); }
static inline void cis_fs_begin(struct cis_fs_sample *s, dev_t dev,
		const void *resource, u32 operation, u64 value)
{
	s->begin_ns = 0;
	if (tracepoint_enabled(cis_fs_state))
		__cis_fs_begin(s, dev, resource, operation, value);
}
static inline void cis_fs_acquired(struct cis_fs_sample *s)
{
	if (s->begin_ns)
		s->acquired_ns = ktime_get_ns();
}
static inline void cis_fs_end(struct cis_fs_sample *s, u64 count, int error)
{
	if (s->begin_ns)
		__cis_fs_end(s, count, error);
}
#else
static inline bool cis_fs_active(void) { return false; }
static inline bool cis_fs_source_enabled(void) { return false; }
static inline void cis_fs_begin(struct cis_fs_sample *s, dev_t dev,
		const void *resource, u32 operation, u64 value) { s->begin_ns = 0; }
static inline void cis_fs_acquired(struct cis_fs_sample *s) { }
static inline void cis_fs_end(struct cis_fs_sample *s, u64 count, int error) { }
#endif
#endif
