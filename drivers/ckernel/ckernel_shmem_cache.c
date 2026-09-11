#include <linux/ckernel.h>
#include <linux/cpu.h>
#include <linux/hash.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/percpu.h>
#include <linux/slab.h>

/* Four ways absorb metadata-path collisions without unbounded folio pinning. */
#define CK_SHMEM_CACHE_SET_BITS 4
#define CK_SHMEM_CACHE_SETS (1U << CK_SHMEM_CACHE_SET_BITS)
#define CK_SHMEM_CACHE_WAYS 4

struct ck_shmem_cache_slot {
	struct address_space *mapping;
	pgoff_t index;
	struct folio *folio;
};

struct ck_shmem_cpu_cache {
	struct ck_shmem_cache_slot slots[CK_SHMEM_CACHE_SETS][CK_SHMEM_CACHE_WAYS];
	u8 next_way[CK_SHMEM_CACHE_SETS];
	unsigned long hits;
	unsigned long misses;
	unsigned long stale;
	unsigned long fills;
	unsigned long evictions;
};

struct ck_shmem_cache_domain {
	struct ck_shmem_cpu_cache __percpu *pcpu;
};

static unsigned int ck_shmem_cache_set(struct address_space *mapping,
				       pgoff_t index)
{
	unsigned long key = ((unsigned long)mapping >> 6) ^ (unsigned long)index;

	return hash_long(key, CK_SHMEM_CACHE_SET_BITS);
}

static struct folio *ck_shmem_cache_lookup(struct ckernel *ck,
					    struct address_space *mapping,
					    pgoff_t index)
{
	struct ck_shmem_cache_domain *domain;
	struct ck_shmem_cache_slot *slot;
	struct ck_shmem_cpu_cache *cache;
	struct folio *folio = NULL;
	unsigned int set;
	unsigned int way;

	domain = READ_ONCE(ck->shmem_hot_cache_domain);
	if (!domain)
		return NULL;

	cache = get_cpu_ptr(domain->pcpu);
	set = ck_shmem_cache_set(mapping, index);
	for (way = 0; way < CK_SHMEM_CACHE_WAYS; way++) {
		slot = &cache->slots[set][way];
		if (slot->mapping != mapping || slot->index != index)
			continue;
		folio = slot->folio;
		if (!folio || READ_ONCE(folio->mapping) != mapping ||
		    index < folio->index || index >= folio_next_index(folio)) {
			folio = NULL;
			cache->stale++;
			break;
		}
		folio_get(folio);
		cache->hits++;
		break;
	}
	if (way == CK_SHMEM_CACHE_WAYS)
		cache->misses++;
	put_cpu_ptr(domain->pcpu);

	return folio;
}

static void ck_shmem_cache_insert(struct ckernel *ck,
				  struct address_space *mapping,
				  pgoff_t index, struct folio *folio)
{
	struct ck_shmem_cache_domain *domain;
	struct ck_shmem_cache_slot *slot;
	struct ck_shmem_cpu_cache *cache;
	struct folio *old;
	unsigned int set;
	unsigned int way;

	domain = READ_ONCE(ck->shmem_hot_cache_domain);
	if (!domain || READ_ONCE(folio->mapping) != mapping)
		return;

	folio_get(folio);
	cache = get_cpu_ptr(domain->pcpu);
	set = ck_shmem_cache_set(mapping, index);
	slot = NULL;
	for (way = 0; way < CK_SHMEM_CACHE_WAYS; way++) {
		struct ck_shmem_cache_slot *candidate = &cache->slots[set][way];

		if (candidate->mapping == mapping && candidate->index == index) {
			if (candidate->folio == folio) {
				put_cpu_ptr(domain->pcpu);
				folio_put(folio);
				return;
			}
			slot = candidate;
			break;
		}
		if (!slot && !candidate->folio)
			slot = candidate;
	}
	if (!slot) {
		/* Per-CPU round robin avoids a shared replacement lock. */
		way = cache->next_way[set]++ % CK_SHMEM_CACHE_WAYS;
		slot = &cache->slots[set][way];
	}

	old = slot->folio;
	slot->mapping = mapping;
	slot->index = index;
	slot->folio = folio;
	cache->fills++;
	if (old)
		cache->evictions++;
	put_cpu_ptr(domain->pcpu);
	if (old)
		folio_put(old);
}

int ck_shmem_cache_init(struct ckernel *ck, bool enabled)
{
	struct ck_shmem_cache_domain *domain;

	ck->shmem_hot_cache_enabled = false;
	ck->shmem_hot_cache_domain = NULL;
	ck->ck_shmem_cache_lookup = NULL;
	ck->ck_shmem_cache_insert = NULL;
	atomic_long_set(&ck->shmem_hot_cache_hits, 0);
	atomic_long_set(&ck->shmem_hot_cache_misses, 0);
	atomic_long_set(&ck->shmem_hot_cache_stale, 0);
	atomic_long_set(&ck->shmem_hot_cache_fills, 0);
	atomic_long_set(&ck->shmem_hot_cache_evictions, 0);
	if (!enabled)
		return 0;

	domain = kzalloc(sizeof(*domain), GFP_KERNEL);
	if (!domain)
		return -ENOMEM;
	domain->pcpu = alloc_percpu(struct ck_shmem_cpu_cache);
	if (!domain->pcpu) {
		kfree(domain);
		return -ENOMEM;
	}

	ck->shmem_hot_cache_domain = domain;
	ck->ck_shmem_cache_lookup = ck_shmem_cache_lookup;
	ck->ck_shmem_cache_insert = ck_shmem_cache_insert;
	ck->shmem_hot_cache_enabled = true;
	return 0;
}

void ck_shmem_cache_refresh_stats(struct ckernel *ck)
{
	struct ck_shmem_cache_domain *domain;
	unsigned long hits = 0;
	unsigned long misses = 0;
	unsigned long stale = 0;
	unsigned long fills = 0;
	unsigned long evictions = 0;
	int cpu;

	domain = READ_ONCE(ck->shmem_hot_cache_domain);
	if (!domain)
		return;

	for_each_possible_cpu(cpu) {
		struct ck_shmem_cpu_cache *cache = per_cpu_ptr(domain->pcpu, cpu);

		hits += READ_ONCE(cache->hits);
		misses += READ_ONCE(cache->misses);
		stale += READ_ONCE(cache->stale);
		fills += READ_ONCE(cache->fills);
		evictions += READ_ONCE(cache->evictions);
	}
	atomic_long_set(&ck->shmem_hot_cache_hits, hits);
	atomic_long_set(&ck->shmem_hot_cache_misses, misses);
	atomic_long_set(&ck->shmem_hot_cache_stale, stale);
	atomic_long_set(&ck->shmem_hot_cache_fills, fills);
	atomic_long_set(&ck->shmem_hot_cache_evictions, evictions);
}

void ck_shmem_cache_destroy(struct ckernel *ck)
{
	struct ck_shmem_cache_domain *domain;
	int cpu;

	ck_shmem_cache_refresh_stats(ck);
	domain = READ_ONCE(ck->shmem_hot_cache_domain);
	WRITE_ONCE(ck->shmem_hot_cache_enabled, false);
	WRITE_ONCE(ck->shmem_hot_cache_domain, NULL);
	ck->ck_shmem_cache_lookup = NULL;
	ck->ck_shmem_cache_insert = NULL;
	if (!domain)
		return;

	for_each_possible_cpu(cpu) {
		struct ck_shmem_cpu_cache *cache = per_cpu_ptr(domain->pcpu, cpu);
		unsigned int set;
		unsigned int way;

		for (set = 0; set < CK_SHMEM_CACHE_SETS; set++)
			for (way = 0; way < CK_SHMEM_CACHE_WAYS; way++)
				if (cache->slots[set][way].folio)
					folio_put(cache->slots[set][way].folio);
	}
	free_percpu(domain->pcpu);
	kfree(domain);
}
