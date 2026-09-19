/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM cis
#if !defined(_TRACE_CIS_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_CIS_H
#include <linux/tracepoint.h>
#include <linux/cis_counter.h>
#include <linux/cis_alloc.h>
#include <linux/cis_maple.h>
#include <linux/cis_net.h>
struct task_struct;
int cis_observe_register(void);
void cis_observe_unregister(void);
int cis_fd_observe_register(void);
void cis_fd_observe_unregister(void);
int cis_slub_observe_register(void);
void cis_slub_observe_unregister(void);
int cis_rwsem_observe_register(void);
void cis_rwsem_observe_unregister(void);
DECLARE_EVENT_CLASS(cis_net_class,
	TP_PROTO(const struct cis_net_sample *sample),
	TP_ARGS(sample),
	TP_STRUCT__entry(
		__field(u64, cookie)
		__field(unsigned int, phase)
		__field(void *, skb)
	),
	TP_fast_assign(
		__entry->cookie = sample->cookie; __entry->phase = sample->phase;
		__entry->skb = sample->skb;
	),
	TP_printk("cookie=%llu phase=%u skb=%p", __entry->cookie,
		__entry->phase, __entry->skb)
);
DEFINE_EVENT(cis_net_class, cis_net_state,
	TP_PROTO(const struct cis_net_sample *sample), TP_ARGS(sample));
DEFINE_EVENT(cis_net_class, cis_net_skb_release,
	TP_PROTO(const struct cis_net_sample *sample), TP_ARGS(sample));

TRACE_EVENT(cis_net_tx,
	TP_PROTO(const struct cis_net_tx_sample *sample), TP_ARGS(sample),
	TP_STRUCT__entry(__field(u64, time_ns) __field(u32, phase)),
	TP_fast_assign(__entry->time_ns = sample->time_ns; __entry->phase = sample->phase;),
	TP_printk("time_ns=%llu phase=%u", __entry->time_ns, __entry->phase)
);
TRACE_EVENT(cis_maple_alloc,
	TP_PROTO(const struct cis_maple_sample *sample),
	TP_ARGS(sample),
	TP_STRUCT__entry(
		__field(void *, tree)
		__field(u64, begin_ns)
		__field(unsigned int, phase)
	),
	TP_fast_assign(
		__entry->tree = sample->tree; __entry->begin_ns = sample->begin_ns;
		__entry->phase = sample->phase;
	),
	TP_printk("tree=%p begin_ns=%llu phase=%u", __entry->tree,
		__entry->begin_ns, __entry->phase)
);
TRACE_EVENT(cis_alloc_step,
	TP_PROTO(const struct cis_alloc_sample *sample),
	TP_ARGS(sample),
	TP_STRUCT__entry(
		__field(void *, cache)
		__field(unsigned int, stage)
		__field(unsigned int, ordinal)
	),
	TP_fast_assign(
		__entry->cache = sample->cache; __entry->stage = sample->stage;
		__entry->ordinal = sample->ordinal;
	),
	TP_printk("cache=%p stage=%u ordinal=%u", __entry->cache,
		__entry->stage, __entry->ordinal)
);
TRACE_EVENT(cis_alloc_release,
	TP_PROTO(const struct cis_alloc_release_sample *sample),
	TP_ARGS(sample),
	TP_STRUCT__entry(
		__field(void *, cache)
		__field(void *, object)
		__field(unsigned int, context)
	),
	TP_fast_assign(
		__entry->cache = sample->cache; __entry->object = sample->object;
		__entry->context = sample->context;
	),
	TP_printk("cache=%p object=%p context=%u", __entry->cache,
		__entry->object, __entry->context)
);
TRACE_EVENT(cis_counter_step,
	TP_PROTO(const struct cis_counter_sample *sample),
	TP_ARGS(sample),
	TP_STRUCT__entry(
		__field(void *, leaf)
		__field(void *, counter)
		__field(unsigned int, op)
		__field(unsigned int, stage)
		__field(unsigned int, ordinal)
	),
	TP_fast_assign(
		__entry->leaf = sample->leaf; __entry->counter = sample->counter;
		__entry->op = sample->op; __entry->stage = sample->stage;
		__entry->ordinal = sample->ordinal;
	),
	TP_printk("leaf=%p counter=%p op=%u stage=%u ordinal=%u",
		__entry->leaf, __entry->counter, __entry->op,
		__entry->stage, __entry->ordinal)
);
TRACE_EVENT_FN(cis_lock_state,
	TP_PROTO(void *object, unsigned int kind, unsigned int phase,
		 struct task_struct *owner, unsigned long flags, unsigned long skipped),
	TP_ARGS(object, kind, phase, owner, flags, skipped),
	TP_STRUCT__entry(
		__field(void *, object)
		__field(unsigned int, kind)
		__field(unsigned int, phase)
		__field(void *, owner)
		__field(unsigned long, flags)
		__field(unsigned long, skipped)
	),
	TP_fast_assign(
		__entry->object=object; __entry->kind=kind; __entry->phase=phase;
		__entry->owner=owner; __entry->flags=flags; __entry->skipped=skipped;
	),
	TP_printk("object=%p kind=%u phase=%u owner=%p flags=%lu skipped=%lu",
		__entry->object, __entry->kind, __entry->phase, __entry->owner,
		__entry->flags, __entry->skipped),
	cis_observe_register, cis_observe_unregister
);
TRACE_EVENT_FN(cis_fdlock_state,
	TP_PROTO(void *object, unsigned int kind, unsigned int phase,
		 struct task_struct *owner, unsigned long flags, unsigned long skipped),
	TP_ARGS(object, kind, phase, owner, flags, skipped),
	TP_STRUCT__entry(
		__field(void *, object)
		__field(unsigned int, kind)
		__field(unsigned int, phase)
		__field(void *, owner)
		__field(unsigned long, flags)
		__field(unsigned long, skipped)
	),
	TP_fast_assign(
		__entry->object=object; __entry->kind=kind; __entry->phase=phase;
		__entry->owner=owner; __entry->flags=flags; __entry->skipped=skipped;
	),
	TP_printk("object=%p kind=%u phase=%u owner=%p flags=%lu skipped=%lu",
		__entry->object, __entry->kind, __entry->phase, __entry->owner,
		__entry->flags, __entry->skipped),
	cis_fd_observe_register, cis_fd_observe_unregister
);
TRACE_EVENT_FN(cis_slublock_state,
	TP_PROTO(void *object, unsigned int kind, unsigned int phase,
		 struct task_struct *owner, unsigned long flags, unsigned long skipped),
	TP_ARGS(object, kind, phase, owner, flags, skipped),
	TP_STRUCT__entry(
		__field(void *, object)
		__field(unsigned int, kind)
		__field(unsigned int, phase)
		__field(void *, owner)
		__field(unsigned long, flags)
		__field(unsigned long, skipped)
	),
	TP_fast_assign(
		__entry->object=object; __entry->kind=kind; __entry->phase=phase;
		__entry->owner=owner; __entry->flags=flags; __entry->skipped=skipped;
	),
	TP_printk("object=%p kind=%u phase=%u owner=%p cache=%lx skipped=%lu",
		__entry->object, __entry->kind, __entry->phase, __entry->owner,
		__entry->flags, __entry->skipped),
	cis_slub_observe_register, cis_slub_observe_unregister
);
TRACE_EVENT_FN(cis_rwsem_state,
	TP_PROTO(void *object, unsigned int phase, unsigned long skipped),
	TP_ARGS(object, phase, skipped),
	TP_STRUCT__entry(
		__field(void *, object)
		__field(unsigned int, phase)
		__field(unsigned long, skipped)
	),
	TP_fast_assign(
		__entry->object = object; __entry->phase = phase;
		__entry->skipped = skipped;
	),
	TP_printk("object=%p phase=%u skipped=%lu",
		__entry->object, __entry->phase, __entry->skipped),
	cis_rwsem_observe_register, cis_rwsem_observe_unregister
);
#endif
#include <trace/define_trace.h>
