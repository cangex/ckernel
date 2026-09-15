/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM ckernel_m
#if !defined(_TRACE_CKERNEL_M_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_CKERNEL_M_H
#include <linux/tracepoint.h>
TRACE_EVENT(ckm_lifecycle,
	TP_PROTO(u64 cookie, unsigned int state),
	TP_ARGS(cookie, state),
	TP_STRUCT__entry(__field(u64, cookie) __field(unsigned int, state)),
	TP_fast_assign(__entry->cookie = cookie; __entry->state = state;),
	TP_printk("cookie=%llu state=%u", __entry->cookie, __entry->state)
);
/* Record identity is diagnostic only; it is not a reference or owner lookup. */
TRACE_EVENT(ckm_maple_record,
	TP_PROTO(u64 cookie, const void *record, unsigned int before, unsigned int after),
	TP_ARGS(cookie, record, before, after),
	TP_STRUCT__entry(__field(u64, cookie) __field(const void *, record)
			__field(unsigned int, before) __field(unsigned int, after)),
	TP_fast_assign(__entry->cookie = cookie; __entry->record = record;
		       __entry->before = before; __entry->after = after;),
	TP_printk("cookie=%llu record=%p before=%u after=%u", __entry->cookie,
		  __entry->record, __entry->before, __entry->after)
);
#endif
#include <trace/define_trace.h>
