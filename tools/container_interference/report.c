// SPDX-License-Identifier: GPL-2.0
#include "include/cis.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void escape(char *dst, size_t cap, const char *s)
{
	size_t i = 0;
	for (; *s && i+7 < cap; s++) {
		unsigned char c = *s;
		if (c == '"' || c == '\\') { dst[i++] = '\\'; dst[i++] = c; }
		else if (c < 32) { i += snprintf(dst+i, cap-i, "\\u%04x", c); }
		else dst[i++] = c;
	}
	dst[i] = 0;
}

void cis_report_flush(struct cis_context *ctx)
{
	if (!ctx->report_used || ctx->output_error) return;
	if (write(ctx->output_fd,ctx->report_buffer,ctx->report_used)!=(ssize_t)ctx->report_used) {
		ctx->output_error=errno?errno:EIO;ctx->dropped++;return;
	}
	ctx->report_used=0;
}

void cis_report(struct cis_context *ctx, const char *kind, const struct cis_root *r, const char *detail)
{
	char b[2048], text[1200], name[384];
	int n;
	escape(text, sizeof(text), detail); escape(name, sizeof(name), r ? r->name : "host");
	n = snprintf(b, sizeof(b), "{\"version\":1,\"session_id\":%llu,\"time_ns\":%llu,\"kind\":\"%s\",\"id\":%llu,\"generation\":%llu,\"name\":\"%s\",\"state\":\"%s\",\"detail\":\"%s\"}\n",
		(unsigned long long)ctx->session_id, (unsigned long long)cis_clock_ns(), kind, (unsigned long long)(r?r->id:0),
		(unsigned long long)(r?r->generation:0), name, r?cis_state_name(r->state):"HOST", text);
	if (ctx->output_error) return;
	if (n < 0 || (size_t)n >= sizeof(b)) { ctx->output_error=EOVERFLOW; ctx->dropped++; return; }
	if (ctx->output_limit && (uint64_t)n>ctx->output_limit-ctx->output_bytes) {
		ctx->output_error=EFBIG; ctx->dropped++; return;
	}
	if (ctx->session_collector==17) {
		/* Preserve every JSON record; batch only the worker's file writes.
		 * Each poll flushes during CAPTURING, not deferred past its budget. */
		if ((size_t)n>sizeof(ctx->report_buffer)-ctx->report_used) cis_report_flush(ctx);
		if (ctx->output_error) return;
		memcpy(ctx->report_buffer+ctx->report_used,b,n);ctx->report_used+=n;ctx->output_bytes+=n;
	} else if (write(ctx->output_fd,b,n)!=n) { ctx->output_error=errno?errno:EIO; ctx->dropped++; }
	else ctx->output_bytes+=n;
}
