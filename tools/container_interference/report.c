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

void cis_report(struct cis_context *ctx, const char *kind, const struct cis_root *r, const char *detail)
{
	char b[2048], text[1200], name[384];
	int n;
	escape(text, sizeof(text), detail); escape(name, sizeof(name), r ? r->name : "host");
	n = snprintf(b, sizeof(b), "{\"version\":1,\"time_ns\":%llu,\"kind\":\"%s\",\"id\":%llu,\"generation\":%llu,\"name\":\"%s\",\"state\":\"%s\",\"detail\":\"%s\"}\n",
		(unsigned long long)cis_clock_ns(), kind, (unsigned long long)(r?r->id:0),
		(unsigned long long)(r?r->generation:0), name, r?cis_state_name(r->state):"HOST", text);
	if (n < 0 || (size_t)n >= sizeof(b) || write(ctx->output_fd, b, n) != n) ctx->dropped++;
}
