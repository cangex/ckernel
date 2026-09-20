/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_CIS_BACKEND_H
#define _LINUX_CIS_BACKEND_H
#include <linux/errno.h>
#include <linux/types.h>
#ifdef CONFIG_CIS_OBSERVE_ALLOC
int cis_backend_register(void);
void cis_backend_unregister(void);
bool cis_backend_active(void);
bool cis_backend_allows(const char *name);
bool cis_backend_node_allows(const char *name, void *const *nodes, void *node);
#else
static inline int cis_backend_register(void) { return -ENODEV; }
static inline void cis_backend_unregister(void) { }
static inline bool cis_backend_active(void) { return false; }
#endif
#endif
