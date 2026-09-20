/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_CIS_NET_H
#define _LINUX_CIS_NET_H
#include <linux/types.h>
struct sock;
struct sk_buff;
enum cis_net_phase {
	CIS_CN_WAIT = 1, CIS_CN_ACQUIRED, CIS_CN_RELEASED,
	CIS_CN_FAST_ACQUIRED, CIS_CN_FAST_RELEASED,
	CIS_CN_QUEUED, CIS_CN_SERVICE_BEGIN, CIS_CN_SERVICE_END,
	CIS_CN_SKB_RELEASE,
	CIS_CN_CREATED, CIS_CN_ACCEPTED,
	CIS_CN_SKB_RELEASE_END,
};
enum cis_net_release_flags {
	CIS_RELEASE_BACKEND = 1, CIS_RELEASE_DATA_RETAINED = 2,
	CIS_RELEASE_PAIR_RETAINED = 4, CIS_RELEASE_CLONED = 8,
	CIS_RELEASE_GSO = 16, CIS_RELEASE_NONLINEAR = 32,
	CIS_RELEASE_FCLONE_ORIG = 64, CIS_RELEASE_FCLONE_CLONE = 128,
	CIS_RELEASE_DATA_RETURNED = 256, CIS_RELEASE_HEADER_RETURNED = 512,
};
struct cis_net_sample {
	u64 time_ns, cookie;
	struct sock *sk;
	struct sk_buff *skb;
	u32 phase, context, netns, bytes, backlog_bytes, flags;
	u64 release_start_ns, release_backend_ns;
};
struct cis_net_tx_sample {
	u64 start_ns, alloc_ns, backend_ns, time_ns, cookie;
	struct sock *sk;
	struct sk_buff *skb;
	u32 phase, netns, gfp, requested;
};
/* BACKEND precedes memory admission and any rejection-triggered free. */
enum cis_net_tx_phase {
	CIS_TX_BACKEND = 1, CIS_TX_ADMITTED, CIS_TX_REJECTED, CIS_TX_FAILED,
	CIS_TX_BEGIN = 6,
};
#ifdef CONFIG_CIS_OBSERVE_NET
#include <linux/tracepoint-defs.h>
DECLARE_TRACEPOINT(cis_net_state);
DECLARE_TRACEPOINT(cis_net_skb_release);
DECLARE_TRACEPOINT(cis_net_tx);
void __cis_net_tx_begin(struct cis_net_tx_sample *, struct sock *, u32, u32);
void __cis_net_tx_step(struct cis_net_tx_sample *, struct sk_buff *, u32);
void __cis_net_event(struct sock *, struct sk_buff *, u32);
void __cis_net_skb_release(struct sk_buff *, struct cis_net_sample *);
void __cis_net_skb_release_end(struct cis_net_sample *, bool);
static inline void cis_net_event(struct sock *sk, struct sk_buff *skb, u32 phase)
{
	if (tracepoint_enabled(cis_net_state))
		__cis_net_event(sk, skb, phase);
}
static inline void cis_net_skb_release(struct sk_buff *skb, struct cis_net_sample *sample)
{
	if (sample)
		sample->release_start_ns = 0;
	if (tracepoint_enabled(cis_net_skb_release))
		__cis_net_skb_release(skb, sample);
}
static inline void cis_net_skb_release_end(struct cis_net_sample *sample, bool freed)
{
	if (sample->release_start_ns && tracepoint_enabled(cis_net_skb_release))
		__cis_net_skb_release_end(sample, freed);
}
static inline void cis_net_tx_begin(struct cis_net_tx_sample *sample,
				   struct sock *sk, u32 gfp, u32 requested)
{
	sample->start_ns = 0;
	if (tracepoint_enabled(cis_net_tx))
		__cis_net_tx_begin(sample, sk, gfp, requested);
}
static inline void cis_net_tx_step(struct cis_net_tx_sample *sample,
				  struct sk_buff *skb, u32 phase)
{
	if (sample->start_ns && tracepoint_enabled(cis_net_tx))
		__cis_net_tx_step(sample, skb, phase);
}
#else
static inline void cis_net_event(struct sock *sk, struct sk_buff *skb, u32 phase) { }
static inline void cis_net_skb_release(struct sk_buff *skb, struct cis_net_sample *sample) { }
static inline void cis_net_skb_release_end(struct cis_net_sample *sample, bool freed) { }
static inline void cis_net_tx_begin(struct cis_net_tx_sample *sample,
				   struct sock *sk, u32 gfp, u32 requested) { }
static inline void cis_net_tx_step(struct cis_net_tx_sample *sample,
				  struct sk_buff *skb, u32 phase) { }
#endif
#endif
