/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM cis_qdisc
#if !defined(_TRACE_CIS_QDISC_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_CIS_QDISC_H
#include <linux/tracepoint.h>
#include <linux/cis_qdisc.h>
TRACE_EVENT_FN(cis_qdisc_state,
	TP_PROTO(const struct cis_qdisc_sample *s), TP_ARGS(s),
	TP_STRUCT__entry(__field(u64, lease) __field(u32, operation)),
	TP_fast_assign(__entry->lease = s->lease; __entry->operation = s->operation;),
	TP_printk("lease=%llu operation=%u", __entry->lease, __entry->operation),
	cis_qdisc_register, cis_qdisc_unregister
);
#endif
#include <trace/define_trace.h>
