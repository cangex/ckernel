/* SPDX-License-Identifier: GPL-2.0 */
#ifndef CIS_OBJECT_SELECTION_H
#define CIS_OBJECT_SELECTION_H
#include <stdint.h>
#include <string.h>
#define CIS_SELECTED_OBJECTS 8

/* Canonical hexadecimal values are comparison keys, never dereferenced. */
static inline int cis_parse_objects(const char *s, uint64_t *objects)
{
	unsigned int count=0, i, j;
	if (strncmp(s,"o:",2)) return -1;
	s+=2;
	while (*s) {
		uint64_t value=0;
		if (count==CIS_SELECTED_OBJECTS || strlen(s)<16) return -1;
		for (i=0;i<16;i++) {
			unsigned int digit;
			if (s[i]>='0' && s[i]<='9') digit=s[i]-'0';
			else if (s[i]>='a' && s[i]<='f') digit=s[i]-'a'+10;
			else return -1;
			value=(value<<4)|digit;
		}
		if (!value || value%8) return -1;
		for (j=0;j<count;j++) if (objects[j]==value) return -1;
		objects[count++]=value; s+=16;
		if (!*s) break;
		if (*s++!=',' || !*s) return -1;
	}
	return count ? (int)count : -1;
}
#endif
