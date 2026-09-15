/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_CKERNEL_M_H
#define _LINUX_CKERNEL_M_H
struct task_struct;
struct mm_struct;
struct ckm_instance;
#ifdef CONFIG_CKERNEL_M
void ckm_task_fork(struct task_struct *task, struct task_struct *parent);
void ckm_task_free(struct task_struct *task);
void ckm_mm_init(struct mm_struct *mm, struct task_struct *task);
void ckm_mm_exit(struct mm_struct *mm);
#else
static inline void ckm_task_fork(struct task_struct *t, struct task_struct *p) {}
static inline void ckm_task_free(struct task_struct *t) {}
static inline void ckm_mm_init(struct mm_struct *m, struct task_struct *t) {}
static inline void ckm_mm_exit(struct mm_struct *m) {}
#endif
#endif
