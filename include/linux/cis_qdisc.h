/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_CIS_QDISC_H
#define _LINUX_CIS_QDISC_H
#include <linux/types.h>
struct Qdisc;
struct netdev_queue;
struct sk_buff;
enum cis_qdisc_operation { CIS_QDISC_ADMISSION = 1, CIS_QDISC_SERVICE };
struct cis_qdisc_sample {
	u64 begin_ns, acquired_ns, end_ns, lease;
	u64 qdisc, txq, dev, skb, actor_cgroup, socket_cgroup;
	u64 txq_state;
	u32 netns, ifindex, queue, handle, operation, sample_shift;
	u32 qlen_begin, qlen_end, backlog_begin, backlog_end;
	u32 length, context, flags, packets;
	s32 result;
};
#ifdef CONFIG_CIS_OBSERVE_QDISC
#include <linux/ktime.h>
#include <linux/tracepoint-defs.h>
DECLARE_TRACEPOINT(cis_qdisc_state);
void __cis_qdisc_begin(struct cis_qdisc_sample *, struct Qdisc *, struct netdev_queue *, struct sk_buff *, u32);
void __cis_qdisc_end(struct cis_qdisc_sample *, struct Qdisc *, int, u32);
void cis_qdisc_invalidate(struct Qdisc *);
int cis_qdisc_register(void);
void cis_qdisc_unregister(void);
bool cis_qdisc_active(void);
static inline bool cis_qdisc_source_enabled(void) { return tracepoint_enabled(cis_qdisc_state); }
static inline void cis_qdisc_begin(struct cis_qdisc_sample *s, struct Qdisc *q,
		struct netdev_queue *txq, struct sk_buff *skb, u32 op)
{
	s->begin_ns = 0;
	if (tracepoint_enabled(cis_qdisc_state))
		__cis_qdisc_begin(s, q, txq, skb, op);
}
static inline void cis_qdisc_acquired(struct cis_qdisc_sample *s)
{
	if (s->begin_ns)
		s->acquired_ns = ktime_get_ns();
}
static inline void cis_qdisc_end(struct cis_qdisc_sample *s, struct Qdisc *q, int rc, u32 packets)
{
	if (s->begin_ns)
		__cis_qdisc_end(s, q, rc, packets);
}
#else
static inline bool cis_qdisc_source_enabled(void) { return false; }
static inline bool cis_qdisc_active(void) { return false; }
static inline void cis_qdisc_invalidate(struct Qdisc *q) { }
static inline void cis_qdisc_begin(struct cis_qdisc_sample *s, struct Qdisc *q,
		struct netdev_queue *txq, struct sk_buff *skb, u32 op) { s->begin_ns = 0; }
static inline void cis_qdisc_acquired(struct cis_qdisc_sample *s) { }
static inline void cis_qdisc_end(struct cis_qdisc_sample *s, struct Qdisc *q, int rc, u32 packets) { }
#endif
#endif
