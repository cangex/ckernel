/* SPDX-License-Identifier: GPL-2.0 */
#ifndef CIS_TEST_COMMON_H
#define CIS_TEST_COMMON_H
#include <stdint.h>
#include <sys/types.h>
uint64_t cis_now_ns(void);
int cis_write_text(const char *path, const char *text);
pid_t cis_container_start(const char *cg, const char *root, char *const argv[], int cpu);
pid_t cis_container_start_output(const char *cg, const char *root, char *const argv[], int cpu, int output);
int cis_container_wait(pid_t pid);
#endif
