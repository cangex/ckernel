// SPDX-License-Identifier: GPL-2.0
#include <kunit/test.h>
#include <linux/ckernel_m_maple.h>
#include "internal.h"

/* A constructor prevents merging this fixture with unrelated slab caches. */
static void ckm_test_ctor(void *object)
{
	memset(object, 0, sizeof(struct maple_node));
}

static void ckm_tracking_failure(struct kunit *test, struct ckm_instance *i,
				 void *node)
{
	kunit_err(test, "CPU node=%d allocated node=%d compatible=%d misses=%llu fallback=%llu\n",
		  numa_node_id(), page_to_nid(virt_to_page(node)),
		  ckm_locality_compatible(i, numa_node_id(), GFP_KERNEL),
		  (unsigned long long)this_cpu_read(i->stats->misses),
		  (unsigned long long)this_cpu_read(i->stats->fallbacks));
}

static void ckm_pool_roundtrip(struct kunit *test)
{
	struct ckm_create req = { .features = CKM_FEATURE_MAPLE, .max_nodes = 2 };
	struct ckm_instance *i, *saved = current->ckm_instance;
	struct kmem_cache *cache;
	struct maple_tree mt;
	struct ckm_query q = {};
	void *a = NULL, *b = NULL, *overflow = NULL;

	cache = kmem_cache_create("ckm_kunit_maple", sizeof(struct maple_node),
				 sizeof(struct maple_node), 0, ckm_test_ctor);
	KUNIT_ASSERT_NOT_NULL(test, cache);
	i = ckm_create_instance(&req);
	if (IS_ERR(i)) {
		KUNIT_FAIL(test, "instance allocation failed");
		kmem_cache_destroy(cache);
		return;
	}
	mt_init(&mt);
	mt.ma_ckm_owner = i;
	current->ckm_instance = i;
	migrate_disable();
	a = ckm_maple_alloc(&mt, cache, GFP_KERNEL);
	KUNIT_EXPECT_NOT_NULL(test, a);
	if (!a)
		goto out;
	memset(a, 0xab, sizeof(struct maple_node));
	if (!ckm_maple_free(a)) {
		ckm_tracking_failure(test, i, a);
		kmem_cache_free(cache, a);
		KUNIT_FAIL(test, "eligible node was not tracked");
		a = NULL;
		goto out;
	}
	a = NULL;
	b = ckm_maple_alloc(&mt, cache, GFP_KERNEL | __GFP_ZERO);
	KUNIT_EXPECT_NOT_NULL(test, b);
	if (!b)
		goto out;
	KUNIT_EXPECT_PTR_EQ(test, memchr_inv(b, 0, sizeof(struct maple_node)), NULL);
	ckm_query_instance(i, &q);
	KUNIT_EXPECT_GT(test, q.hits_cpu + q.hits_numa, 0ULL);
	KUNIT_EXPECT_LE(test, q.nodes, req.max_nodes);
	a = ckm_maple_alloc(&mt, cache, GFP_KERNEL);
	KUNIT_EXPECT_NOT_NULL(test, a);
	if (!a)
		goto out;
	overflow = ckm_maple_alloc(&mt, cache, GFP_KERNEL);
	KUNIT_EXPECT_NOT_NULL(test, overflow);
	if (overflow) {
		bool tracked = ckm_maple_free(overflow);

		KUNIT_EXPECT_FALSE(test, tracked);
		if (!tracked)
			kmem_cache_free(cache, overflow);
		overflow = NULL;
	}
	KUNIT_EXPECT_EQ(test, atomic_read(&i->nodes), (int)req.max_nodes);
	ckm_maple_retire(b);
	ckm_revoke(i);
	flush_work(&i->revoke_work);
	KUNIT_EXPECT_EQ(test, atomic_read(&i->state), (int)CKM_DRAINING);
	/* Test invokes the free only after its simulated reader exclusion. */
	synchronize_rcu();
	if (!ckm_maple_free(b))
		kmem_cache_free(cache, b);
	b = NULL;
out:
	migrate_enable();
	current->ckm_instance = saved;
	if (a && !ckm_maple_free(a))
		kmem_cache_free(cache, a);
	if (b && !ckm_maple_free(b))
		kmem_cache_free(cache, b);
	ckm_revoke(i);
	flush_work(&i->revoke_work);
	rcu_barrier();
	KUNIT_EXPECT_EQ(test, atomic_read(&i->nodes), 0);
	ckm_put(i);
	kmem_cache_destroy(cache);
}

static void ckm_two_owners(struct kunit *test)
{
	struct ckm_create req = { .features = CKM_FEATURE_MAPLE, .max_nodes = 2 };
	struct ckm_instance *owners[2] = {}, *saved = current->ckm_instance;
	struct maple_tree trees[2];
	struct kmem_cache *cache;
	struct ckm_query q = {};
	void *nodes[2] = {};
	bool pinned = false;
	int n;

	cache = kmem_cache_create("ckm_kunit_owners", sizeof(struct maple_node),
				 sizeof(struct maple_node), 0, ckm_test_ctor);
	KUNIT_ASSERT_NOT_NULL(test, cache);
	for (n = 0; n < 2; n++) {
		owners[n] = ckm_create_instance(&req);
		if (IS_ERR(owners[n])) {
			owners[n] = NULL;
			KUNIT_FAIL(test, "owner allocation failed");
			goto out;
		}
		mt_init(&trees[n]);
		trees[n].ma_ckm_owner = owners[n];
	}
	migrate_disable();
	pinned = true;
	for (n = 0; n < 2; n++) {
		current->ckm_instance = owners[n];
		nodes[n] = ckm_maple_alloc(&trees[n], cache, GFP_KERNEL);
		if (!nodes[n]) {
			KUNIT_FAIL(test, "node allocation failed");
			goto out;
		}
		if (!ckm_maple_free(nodes[n])) {
			ckm_tracking_failure(test, owners[n], nodes[n]);
			kmem_cache_free(cache, nodes[n]);
			KUNIT_FAIL(test, "node not tracked");
			goto out;
		}
	}
	KUNIT_EXPECT_PTR_NE(test, nodes[0], nodes[1]);
	for (n = 0; n < 2; n++) {
		void *again;

		ckm_query_instance(owners[n], &q);
		KUNIT_EXPECT_EQ(test, q.cached, 1ULL);
		current->ckm_instance = owners[n];
		again = ckm_maple_alloc(&trees[n], cache, GFP_KERNEL);
		KUNIT_EXPECT_PTR_EQ(test, again, nodes[n]);
		if (again && !ckm_maple_free(again))
			kmem_cache_free(cache, again);
		memset(&q, 0, sizeof(q));
	}
out:
	current->ckm_instance = saved;
	if (pinned)
		migrate_enable();
	for (n = 0; n < 2; n++)
		if (owners[n]) {
			ckm_revoke(owners[n]);
			flush_work(&owners[n]->revoke_work);
		}
	rcu_barrier();
	for (n = 0; n < 2; n++)
		if (owners[n]) {
			KUNIT_EXPECT_EQ(test, atomic_read(&owners[n]->nodes), 0);
			ckm_put(owners[n]);
		}
	kmem_cache_destroy(cache);
}

static void ckm_bulk_paths(struct kunit *test)
{
	struct ckm_create req = { .features = CKM_FEATURE_MAPLE, .max_nodes = 2 };
	struct ckm_instance *i, *saved = current->ckm_instance;
	struct ckm_diagnostics d = {};
	struct ckm_query q = {};
	struct kmem_cache *cache;
	struct maple_tree mt;
	void *nodes[8];
	unsigned int n, pass;
	u64 sum = 0;
	int count;

	cache = kmem_cache_create("ckm_kunit_bulk", sizeof(struct maple_node),
				 sizeof(struct maple_node), 0, ckm_test_ctor);
	KUNIT_ASSERT_NOT_NULL(test, cache);
	i = ckm_create_instance(&req);
	if (IS_ERR(i)) {
		kmem_cache_destroy(cache);
		KUNIT_FAIL(test, "instance allocation failed");
		return;
	}
	mt_init(&mt);
	mt.ma_ckm_owner = i;
	current->ckm_instance = i;
	migrate_disable();
	for (pass = 0; pass < 3; pass++) {
		/* Unsupported GFP, mixed tracked/native, and revoked owner. */
		if (pass == 2) {
			ckm_revoke(i);
			flush_work(&i->revoke_work);
		}
		count = ckm_maple_alloc_bulk(&mt, cache,
				pass ? GFP_KERNEL : GFP_ATOMIC, ARRAY_SIZE(nodes), nodes);
		KUNIT_EXPECT_EQ(test, count, (int)ARRAY_SIZE(nodes));
		for (n = 0; n < count; n++) {
			KUNIT_EXPECT_NOT_NULL(test, nodes[n]);
			if (!ckm_maple_free(nodes[n]))
				kmem_cache_free(cache, nodes[n]);
		}
	}
	migrate_enable();
	current->ckm_instance = saved;
	ckm_revoke(i);
	flush_work(&i->revoke_work);
	rcu_barrier();
	ckm_query_instance(i, &q);
	ckm_query_diagnostics(i, &d);
	for (n = 0; n < CKM_FB_COUNT; n++)
		sum += d.reasons[n];
	KUNIT_EXPECT_EQ(test, sum, q.fallbacks);
	KUNIT_EXPECT_GT(test, d.reasons[CKM_FB_GFP], 0ULL);
	KUNIT_EXPECT_GT(test, d.reasons[CKM_FB_BUDGET], 0ULL);
	KUNIT_EXPECT_GT(test, d.reasons[CKM_FB_INACTIVE], 0ULL);
	KUNIT_EXPECT_EQ(test, d.bulk_calls, 3ULL);
	KUNIT_EXPECT_EQ(test, d.bulk_requested, d.bulk_completed);
	KUNIT_EXPECT_EQ(test, d.bulk_failed, 0ULL);
	KUNIT_EXPECT_EQ(test, q.nodes, 0U);
	ckm_put(i);
	kmem_cache_destroy(cache);
}

static void ckm_empty_refill(struct kunit *test)
{
	struct ckm_create req = { .features = CKM_FEATURE_MAPLE, .max_nodes = 3 };
	struct ckm_instance *i, *saved = current->ckm_instance;
	struct kmem_cache *cache;
	struct maple_tree mt;
	struct ckm_query q = {};
	void *nodes[3] = {};
	unsigned int n, pass;

	cache = kmem_cache_create("ckm_kunit_refill", sizeof(struct maple_node),
				 sizeof(struct maple_node), 0, ckm_test_ctor);
	KUNIT_ASSERT_NOT_NULL(test, cache);
	i = ckm_create_instance(&req);
	if (IS_ERR(i)) {
		kmem_cache_destroy(cache);
		KUNIT_FAIL(test, "instance allocation failed");
		return;
	}
	mt_init(&mt);
	mt.ma_ckm_owner = i;
	current->ckm_instance = i;
	migrate_disable();
	/* Two CPU slots and one NUMA entry: consume, refill and consume again. */
	for (pass = 0; pass < 3; pass++) {
		/* The fixture constructor initializes cold objects. ZERO is tested
		 * on reuse, not passed to a cold constructor-backed SLUB cache.
		 */
		gfp_t gfp = GFP_KERNEL | (pass ? __GFP_ZERO : 0);

		for (n = 0; n < ARRAY_SIZE(nodes); n++) {
			nodes[n] = ckm_maple_alloc(&mt, cache, gfp);
			if (!nodes[n]) {
				KUNIT_FAIL(test, "node allocation failed");
				goto out;
			}
			KUNIT_EXPECT_PTR_EQ(test, memchr_inv(nodes[n], 0, sizeof(struct maple_node)), NULL);
		}
		for (n = 0; n < ARRAY_SIZE(nodes); n++) {
			memset(nodes[n], 0xaa, sizeof(struct maple_node));
			if (!ckm_maple_free(nodes[n])) {
				kmem_cache_free(cache, nodes[n]);
				KUNIT_FAIL(test, "eligible node was not tracked");
			}
			nodes[n] = NULL;
		}
	}
	ckm_query_instance(i, &q);
	KUNIT_EXPECT_EQ(test, q.nodes, 3U);
	KUNIT_EXPECT_EQ(test, q.cached, 3ULL);
	KUNIT_EXPECT_GE(test, q.hits_cpu, 4ULL);
	KUNIT_EXPECT_GE(test, q.hits_numa, 2ULL);
out:
	migrate_enable();
	current->ckm_instance = saved;
	for (n = 0; n < ARRAY_SIZE(nodes); n++)
		if (nodes[n] && !ckm_maple_free(nodes[n]))
			kmem_cache_free(cache, nodes[n]);
	ckm_revoke(i);
	flush_work(&i->revoke_work);
	rcu_barrier();
	KUNIT_EXPECT_EQ(test, atomic_read(&i->nodes), 0);
	ckm_put(i);
	kmem_cache_destroy(cache);
}

static struct kunit_case ckm_pool_cases[] = {
	KUNIT_CASE(ckm_pool_roundtrip),
	KUNIT_CASE(ckm_two_owners),
	KUNIT_CASE(ckm_bulk_paths),
	KUNIT_CASE(ckm_empty_refill),
	{}
};
static struct kunit_suite ckm_pool_suite = {
	.name = "ckernel-m-maple",
	.test_cases = ckm_pool_cases,
};
kunit_test_suite(ckm_pool_suite);
MODULE_LICENSE("GPL");
