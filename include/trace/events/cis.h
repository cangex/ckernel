/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM cis
#if !defined(_TRACE_CIS_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_CIS_H
#include <linux/tracepoint.h>
struct task_struct;
TRACE_EVENT(cis_lock_state,
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
		__entry->flags, __entry->skipped)
);
#endif
#include <trace/define_trace.h>
