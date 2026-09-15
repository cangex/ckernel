// SPDX-License-Identifier: GPL-2.0
#include "internal.h"

void ckm_query_diagnostics(struct ckm_instance *i, struct ckm_diagnostics *q)
{
	int cpu, reason;

	q->version = CKM_ABI_VERSION;
	q->size = sizeof(*q);
	for_each_possible_cpu(cpu) {
		struct ckm_counters *c = per_cpu_ptr(i->stats, cpu);

		for (reason = 0; reason < CKM_FB_COUNT; reason++)
			q->reasons[reason] += READ_ONCE(c->reasons[reason]);
#define CKM_SUM(field) q->field += READ_ONCE(c->field)
		CKM_SUM(bulk_calls);
		CKM_SUM(bulk_requested);
		CKM_SUM(bulk_completed);
		CKM_SUM(bulk_failed);
		CKM_SUM(registered);
		CKM_SUM(alloc_failed);
		CKM_SUM(dispose_inactive);
		CKM_SUM(dispose_full);
#undef CKM_SUM
	}
}

void ckm_query_instance(struct ckm_instance *i, struct ckm_query *q)
{
	int cpu;

	q->version = CKM_ABI_VERSION;
	q->size = sizeof(*q);
	q->cookie = i->cookie;
	q->state = atomic_read(&i->state);
	q->features = i->features;
	q->max_nodes = i->max_nodes;
	q->tasks = atomic_read(&i->tasks);
	q->mms = atomic_read(&i->mms);
	q->nodes = atomic_read(&i->nodes);
	for_each_possible_cpu(cpu) {
		struct ckm_counters *c = per_cpu_ptr(i->stats, cpu);

		q->hits_cpu += READ_ONCE(c->hits_cpu);
		q->hits_numa += READ_ONCE(c->hits_numa);
		q->misses += READ_ONCE(c->misses);
		q->fallbacks += READ_ONCE(c->fallbacks);
		q->returned += READ_ONCE(c->returned);
	}
	q->metadata_bytes = sizeof(*i) + sizeof(struct ckm_counters) * num_possible_cpus();
	ckm_maple_snapshot(i, q);
}
