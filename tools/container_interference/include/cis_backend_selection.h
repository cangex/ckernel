/* SPDX-License-Identifier: GPL-2.0 */
#ifndef CIS_BACKEND_SELECTION_H
#define CIS_BACKEND_SELECTION_H
#include <stdio.h>
#include <string.h>

static inline int cis_parse_backend(const char *input, char output[160])
{
	const char *colon, *p;
	unsigned int nodes[8], count=0, value, i;
	size_t length;
	if (strncmp(input,"a:",2)) return -1;
	input+=2; colon=strchr(input,':');
	if (!colon || colon==input || (length=colon-input)>=64) return -1;
	for (p=input;p<colon;p++)
		if (!((*p>='a' && *p<='z') || (*p>='A' && *p<='Z') ||
		      (*p>='0' && *p<='9') || *p=='_' || *p=='-')) return -1;
	p=colon+1;
	if (strcmp(p,"*")) {
		while (*p) {
			if (count==8 || *p<'0' || *p>'9') return -1;
			if (*p=='0' && p[1]>='0' && p[1]<='9') return -1;
			value=0;
			do { value=value*10+*p++-'0'; if (value>=1024) return -1; }
			while (*p>='0' && *p<='9');
			for (i=0;i<count;i++) if (nodes[i]==value) return -1;
			nodes[count++]=value;
			if (!*p) break;
			if (*p++!=',' || !*p) return -1;
		}
		if (!count) return -1;
	}
	if (snprintf(output,160,"%.*s %s\n",(int)length,input,colon+1)>=160) return -1;
	return 0;
}
#endif
