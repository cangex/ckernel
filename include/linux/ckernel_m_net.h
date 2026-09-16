/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_CKERNEL_M_NET_H
#define _LINUX_CKERNEL_M_NET_H
#include <linux/types.h>
struct ckm_instance;
struct ckm_net_query;
struct sock;
#ifdef CONFIG_CKERNEL_M_NET
int ckm_net_init(struct ckm_instance *i);
void ckm_net_drain(struct ckm_instance *i);
void ckm_net_destroy(struct ckm_instance *i);
void ckm_net_query(struct ckm_instance *i, struct ckm_net_query *q);
void aa_ckm_net_created(struct sock *sk);
void aa_ckm_net_clone(const struct sock *old, struct sock *new);
void aa_ckm_net_free(struct sock *sk);
bool aa_ckm_net_allowed(struct sock *sk, u32 request);
#else
static inline int ckm_net_init(struct ckm_instance *i) { return 0; }
static inline void ckm_net_drain(struct ckm_instance *i) {}
static inline void ckm_net_destroy(struct ckm_instance *i) {}
static inline void ckm_net_query(struct ckm_instance *i, struct ckm_net_query *q) {}
static inline void aa_ckm_net_created(struct sock *sk) {}
static inline void aa_ckm_net_clone(const struct sock *old, struct sock *new) {}
static inline void aa_ckm_net_free(struct sock *sk) {}
static inline bool aa_ckm_net_allowed(struct sock *sk, u32 request) { return false; }
#endif
#endif
