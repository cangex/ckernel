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
#endif
#include <trace/define_trace.h>
