/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_CKERNEL_M_SECURITY_H
#define _LINUX_CKERNEL_M_SECURITY_H
struct ckm_instance;
struct ckm_security_state;
struct ckm_security_query;
#ifdef CONFIG_CKERNEL_M_SECURITY
int ckm_security_init(struct ckm_instance *inst);
void ckm_security_drain(struct ckm_instance *inst);
void ckm_security_destroy(struct ckm_instance *inst);
void ckm_security_query(struct ckm_instance *inst, struct ckm_security_query *q);
#else
static inline int ckm_security_init(struct ckm_instance *i) { return 0; }
static inline void ckm_security_drain(struct ckm_instance *i) {}
static inline void ckm_security_destroy(struct ckm_instance *i) {}
#endif
#endif
