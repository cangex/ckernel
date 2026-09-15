/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_CKERNEL_M_H
#define _UAPI_LINUX_CKERNEL_M_H
#include <linux/ioctl.h>
#include <linux/types.h>

#define CKM_ABI_VERSION 1
#define CKM_FEATURE_MAPLE 1U
#define CKM_ACTIVE 0U
#define CKM_REVOKING 1U
#define CKM_DRAINING 2U
#define CKM_DEAD 3U

struct ckm_create {
	__u32 version;
	__u32 size;
	__u32 features;
	__u32 max_nodes;
	__u32 reserved[4];
};

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

/* CREATE returns an O_CLOEXEC instance fd, not a cookie-as-capability. */
#define CKM_IOC_CREATE _IOW('M', 0x40, struct ckm_create)
#define CKM_IOC_BIND _IO('M', 0x41)
#define CKM_IOC_QUERY _IOWR('M', 0x42, struct ckm_query)
#define CKM_IOC_REVOKE _IO('M', 0x43)
#endif
