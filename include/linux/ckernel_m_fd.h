/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_CKERNEL_M_FD_H
#define _LINUX_CKERNEL_M_FD_H
#include <linux/types.h>
struct ckm_instance;
struct ckm_fd_pool;
struct ckm_fd_query;
struct page_counter;
struct cgroup_subsys_state;
#ifdef CONFIG_CKERNEL_M_FD
int ckm_fd_init(struct ckm_instance *i);
void ckm_fd_drain(struct ckm_instance *i);
void ckm_fd_destroy(struct ckm_instance *i);
void ckm_fd_query(struct ckm_instance *i, struct ckm_fd_query *q);
int ckm_fd_register(struct ckm_instance *i, struct cgroup_subsys_state *css,
		    struct page_counter *counter);
int files_cgroup_ckm_prepare(struct ckm_instance *i);
bool files_cg_ckm_legacy(void);
bool ckm_fd_alloc(struct page_counter *counter, unsigned long n);
bool ckm_fd_free(struct page_counter *counter, unsigned long n);
unsigned long ckm_fd_quiesce_begin(void);
void ckm_fd_quiesce_end(unsigned long flags);
void ckm_fd_disable_locked(void);
int ckm_fd_set_max(struct page_counter *counter, unsigned long maximum);
#else
static inline int ckm_fd_init(struct ckm_instance *i) { return 0; }
static inline void ckm_fd_drain(struct ckm_instance *i) {}
static inline void ckm_fd_destroy(struct ckm_instance *i) {}
static inline unsigned long ckm_fd_quiesce_begin(void) { return 0; }
static inline void ckm_fd_quiesce_end(unsigned long flags) {}
static inline void ckm_fd_disable_locked(void) {}
#endif
#endif
