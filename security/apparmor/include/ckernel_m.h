/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __AA_CKERNEL_M_H
#define __AA_CKERNEL_M_H
#include <linux/types.h>
struct aa_label;
struct aa_file_ctx;
struct aa_ckm_entry;
struct file;
struct task_struct;
struct cred;
#ifdef CONFIG_CKERNEL_M_SECURITY
bool aa_ckm_self_subject(struct task_struct *target, const struct cred *cred);
bool aa_ckm_self_signal(struct task_struct *target, const struct cred *cred);
void aa_ckm_file_init(struct aa_file_ctx *ctx, struct aa_label *label);
void aa_ckm_file_drop(struct aa_file_ctx *ctx, struct aa_label *label);
bool aa_ckm_file_open_label(struct file *file, struct aa_label **label);
#else
static inline bool aa_ckm_self_signal(struct task_struct *t, const struct cred *c)
{
	return false;
}
static inline bool aa_ckm_file_open_label(struct file *f, struct aa_label **l)
{
	return false;
}
#endif
#endif
