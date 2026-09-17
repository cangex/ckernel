/* SPDX-License-Identifier: GPL-2.0 */
#ifndef CIS_METRICS_SCHEDULE_H
#define CIS_METRICS_SCHEDULE_H
#include <stdint.h>
/* Forty stable buckets preserve the one-second freshness without 256 wakeups. */
static inline uint64_t cis_metric_first(uint64_t now,uint64_t serial)
{
	uint64_t due=now-now%1000000000ULL+(serial*17%40)*25000000ULL;
	return due>now?due:due+1000000000ULL;
}
static inline uint64_t cis_metric_next(uint64_t due,uint64_t now)
{
	return due>now?due:due+((now-due)/1000000000ULL+1)*1000000000ULL;
}
#endif
