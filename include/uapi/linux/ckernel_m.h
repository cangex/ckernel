/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_CKERNEL_M_H
#define _UAPI_LINUX_CKERNEL_M_H
#include <linux/ioctl.h>
#include <linux/types.h>

#define CKM_ABI_VERSION 1
#define CKM_FEATURE_MAPLE 1U
#define CKM_FEATURE_VFS 2U
#define CKM_FEATURE_VFS_OPEN 4U
#define CKM_FEATURE_SECURITY 8U
#define CKM_FEATURE_FD 16U
#define CKM_FEATURE_NET 32U
#define CKM_NET_MAX_SOCKETS 64U
#define CKM_FD_MAX_IDLE 64U
#define CKM_SECURITY_MAX_LABELS 8U
#define CKM_VFS_MAX_ENTRIES 16U
#define CKM_ACTIVE 0U
#define CKM_REVOKING 1U
#define CKM_DRAINING 2U
#define CKM_DEAD 3U

/* Mutually exclusive reasons for node requests left to native SLUB. */
enum ckm_fallback_reason {
	CKM_FB_NONE,
	CKM_FB_NOT_READY,
	CKM_FB_GFP,
	CKM_FB_INACTIVE,
	CKM_FB_TASK_OWNER,
	CKM_FB_CPU_MASK,
	CKM_FB_MEMPOLICY,
	CKM_FB_ACTIVE_MEMCG,
	CKM_FB_NODE_MASK,
	CKM_FB_CPUSET,
	CKM_FB_CGROUP,
	CKM_FB_OBJCG,
	CKM_FB_BUDGET,
	CKM_FB_RECORD_ALLOC,
	CKM_FB_RECORD_CHARGE,
	CKM_FB_NUMA_ALLOC,
	CKM_FB_NUMA_CHARGE,
	CKM_FB_NUMA_INDEX,
	CKM_FB_NODE_CHARGE,
	CKM_FB_POST_NODE,
	CKM_FB_POST_LOCALITY,
	CKM_FB_POST_CHARGE,
	/* Remaining requests were batched, not individually rechecked. */
	CKM_FB_BULK_REMAINDER,
	CKM_FB_COUNT
};

/* Additive, read-only diagnostic ABI; existing QUERY layout is unchanged. */
struct ckm_diagnostics {
	__u32 version, size;
	__aligned_u64 reasons[CKM_FB_COUNT];
	__aligned_u64 bulk_calls, bulk_requested, bulk_completed, bulk_failed;
	__aligned_u64 registered, alloc_failed, dispose_inactive, dispose_full;
	__aligned_u64 reserved[4];
};

struct ckm_create {
	__u32 version;
	__u32 size;
	__u32 features;
	__u32 max_nodes;
	__u32 reserved[4];
};

/* Capacity is fixed and independent of Maple's max_nodes. */
struct ckm_security_query {
	__u32 version, size;
	__aligned_u64 signal_hits, signal_native;
	__aligned_u64 label_hits, label_native, label_released, open_borrowed, label_learned;
	__aligned_u64 full, contended, stale;
	__aligned_u64 management_bytes;
	__aligned_u64 reserved[4];
};

#define CKM_IOC_SECURITY_QUERY _IOWR('M', 0x48, struct ckm_security_query)

struct ckm_fd_query {
	__u32 version, size;
	__u32 capacity, idle, stopped, pad;
	__aligned_u64 local_alloc, local_free, native_alloc, refill, rescue, drained, contended;
	__aligned_u64 management_bytes;
	__aligned_u64 reserved[4];
};
#define CKM_IOC_FD_QUERY _IOWR('M', 0x49, struct ckm_fd_query)

struct ckm_net_query {
	__u32 version, size;
	__u32 capacity, live, retiring, stopped;
	__aligned_u64 created, cloned, released, send_hits, recv_hits;
	__aligned_u64 native, missing, subject, stale, mediated, full, contended;
	__aligned_u64 owner_search_steps, management_bytes;
	__aligned_u64 reserved[4];
};
#define CKM_IOC_NET_QUERY _IOWR('M', 0x4a, struct ckm_net_query)

struct ckm_query {
	__u32 version;
	__u32 size;
	__aligned_u64 cookie;
	__u32 state;
	__u32 features;
	__u32 max_nodes;
	__u32 tasks;
	__u32 mms;
	__u32 nodes;
	__aligned_u64 hits_cpu;
	__aligned_u64 hits_numa;
	__aligned_u64 misses;
	__aligned_u64 fallbacks;
	__aligned_u64 returned;
	__aligned_u64 cached;
	__aligned_u64 borrowed;
	__aligned_u64 retired;
	__aligned_u64 metadata_bytes;
	__aligned_u64 node_bytes;
	__aligned_u64 pending_metadata;
	__aligned_u64 reserved[3];
};

struct ckm_vfs_root {
	__u32 version, size;
	__s32 fd;
	__u32 capacity;
	__u32 reserved[4];
};

struct ckm_vfs_query {
	__u32 version, size;
	__u32 capacity, cached;
	__u32 registered, stopped;
	__aligned_u64 hits, retries, native, full;
	__aligned_u64 metadata_payload_bytes;
	__aligned_u64 reserved[4];
};

struct ckm_vfs_open_query {
	__u32 version, size;
	__aligned_u64 hits, native, released;
	__aligned_u64 reserved[4];
};

/* CREATE returns an O_CLOEXEC instance fd, not a cookie-as-capability. */
#define CKM_IOC_CREATE _IOW('M', 0x40, struct ckm_create)
#define CKM_IOC_BIND _IO('M', 0x41)
#define CKM_IOC_QUERY _IOWR('M', 0x42, struct ckm_query)
#define CKM_IOC_REVOKE _IO('M', 0x43)
#define CKM_IOC_DIAGNOSTICS _IOWR('M', 0x44, struct ckm_diagnostics)
#define CKM_IOC_VFS_ROOT _IOW('M', 0x45, struct ckm_vfs_root)
#define CKM_IOC_VFS_QUERY _IOWR('M', 0x46, struct ckm_vfs_query)
#define CKM_IOC_VFS_OPEN_QUERY _IOWR('M', 0x47, struct ckm_vfs_open_query)
#endif
