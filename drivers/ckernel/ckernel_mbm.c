#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/jiffies.h>
#include <linux/math64.h>
#include <linux/slab.h>
#include <linux/minmax.h>
#include <linux/ckernel.h>
#include <linux/resctrl.h>

#include "ckernel_driver.h"

static struct kernfs_node *mbm_online_kn;
static struct kernfs_node *mbm_offline_kn;

/* ================= 数据结构 ================= */

struct ema_state {
	int ema;
	int prev_ema;
	int inited;
};

struct mon_data {
	u64 mbm_total[4];
	unsigned int sche_bw[4];
};

/* ================= 参数 ================= */

static int alpha_num = 3;
static int alpha_den = 10;
static int horizon_s = 3;
static int safety_margin = 60;
static int hysteresis_steps = 3;
static int cooldown_s = 5;
static int step_limit = 10;
static int bw2_min = 1;

static unsigned int bw_GB_s = 10;

/* ================= 线程 ================= */

static struct task_struct *adjust_thread;

/* ================= 工具函数 ================= */

static int schemata_bw_write(struct kernfs_node *kn,
			    unsigned int bw1, unsigned int bw2,
			    unsigned int bw3, unsigned int bw4)
{
	char sche_str[32];

	snprintf(sche_str, sizeof(sche_str),
		 "MB:0=%u;1=%u;2=%u;3=%u",
		 bw1, bw2, bw3, bw4);

	return ck_rdtgroup_schemata_write(kn, sche_str);
}

static inline unsigned int quantize10(unsigned int x)
{
	return ((x + 3) / 5) * 5;
}

static inline int clamp_int(int x, int lo, int hi)
{
	return x < lo ? lo : (x > hi ? hi : x);
}

/* ================= EMA ================= */

static void ema_update(struct ema_state *st, unsigned int u1_percent)
{
	int u1k = (int)u1_percent * 1000;

	if (!st->inited) {
		st->ema = u1k;
		st->prev_ema = u1k;
		st->inited = 1;
		return;
	}

	st->prev_ema = st->ema;
	st->ema = (alpha_num * u1k +
		  (alpha_den - alpha_num) * st->ema) / alpha_den;
}

/* ================= MBM 转换 ================= */

static unsigned int mbm_delta_to_percent(u64 delta_bytes,
					 unsigned int seconds)
{
	u64 delta_bps;
	u64 ref_bps;

	delta_bps = seconds ? div64_u64(delta_bytes, seconds)
			    : delta_bytes;

	ref_bps = (u64)bw_GB_s * 1024ULL;

	if (!ref_bps)
		return 0;

	delta_bps = div64_u64(delta_bps * 100ULL, ref_bps);

	return min_t(u64, delta_bps, 100);
}

/* ================= BW 调整 ================= */

static int bw_adjust(struct ema_state *st,
		     int bw2_cur,
		     int *drift_counter,
		     unsigned long *last_change_bw_ts)
{
	int ema = st->ema / 1000;
	int prev = st->prev_ema / 1000;
	int slope = ema - prev;

	int pred0 = ema + horizon_s * slope;
	int safety_val = safety_margin * ema / 100;

	int reserve = clamp_int(pred0 * 2 + safety_val, 0, 100);

	int bw2_desired = 100 - reserve;
	bw2_desired = quantize10(
		clamp_int(bw2_desired, bw2_min, 100));

	int diff = bw2_desired - bw2_cur;

	if (abs(diff) >= 5)
		(*drift_counter)++;
	else
		*drift_counter = 0;

	if (time_before(jiffies,
		*last_change_bw_ts + cooldown_s * HZ))
		return bw2_cur;

	if (*drift_counter >= hysteresis_steps) {
		int step = clamp_int(diff,
				     -(step_limit * 5),
				     step_limit);

		step = quantize10(abs(step)) *
		       (step < 0 ? -1 : 1);

		*drift_counter = 0;
		*last_change_bw_ts = jiffies;

		return clamp_int(bw2_cur + step,
				 bw2_min, 100);
	}

	return bw2_cur;
}

/* ================= 核心线程 ================= */

static int adjust_thread_fn(void *arg)
{
	struct kernfs_node *online_kn = mbm_online_kn;
	struct kernfs_node *offline_kn = mbm_offline_kn;

	struct mon_data on = {0}, off = {0};
	struct ema_state ema = {0};

	unsigned long last_change_bw_ts = 0;
	int drift_counter = 0;

	if (!online_kn || !offline_kn)
		return -ENODEV;

	while (!kthread_should_stop()) {
		unsigned int u1 = 0, u2 = 0;
		int bw2_cur, bw2_new;
		u64 delta_on = 0, delta_off = 0;

		ck_mpam_rdtgroup_mondata_show_mbm(
			online_kn, on.mbm_total);
		ck_mpam_rdtgroup_mondata_show_mbm(
			offline_kn, off.mbm_total);
		ck_rdtgroup_schemata_show_bw(
			offline_kn, off.sche_bw);

		for (int i = 0; i < 4; i++) {
			delta_on += on.mbm_total[i];
			delta_off += off.mbm_total[i];
		}

		u1 = mbm_delta_to_percent(delta_on, 1);
		u2 = mbm_delta_to_percent(delta_off, 1);

		ema_update(&ema, u1);

		bw2_cur = off.sche_bw[0];
		bw2_new = bw_adjust(&ema, bw2_cur,
				    &drift_counter,
				    &last_change_bw_ts);

		int bw2_numa0 = bw2_new;
		int bw2_numa1 = bw2_new;
		int bw2_numa2 = bw2_new;
		int bw2_numa3 = bw2_new;

		if (on.mbm_total[0]!=0)
			bw2_numa0 = 1;
		if (on.mbm_total[1]!=0)
			bw2_numa1 = 1;
		if (on.mbm_total[2]!=0)
			bw2_numa2 = 1;
		if (on.mbm_total[3]!=0)
			bw2_numa3 = 1;

		if ((bw2_numa0 != bw2_cur) ||
		    (bw2_numa1 != bw2_cur) ||
		    (bw2_numa2 != bw2_cur) ||
		    (bw2_numa3 != bw2_cur))
			if (schemata_bw_write(offline_kn,
					      bw2_numa0, bw2_numa1,
					      bw2_numa2, bw2_numa3)) {
				pr_warn("ckernel: stop mbm adjust thread after schemata write failure\n");
				break;
			}

		ssleep(1);
	}

	return 0;
}

/* ================= 对外接口 ================= */

int ckernel_mbm_start(struct kernfs_node *online_kn,
                      struct kernfs_node *offline_kn)
{
	if (!online_kn || !offline_kn)
		return -EINVAL;

	mbm_online_kn = online_kn;
	mbm_offline_kn = offline_kn;

	if (adjust_thread)
		return 0;

	adjust_thread = kthread_run(adjust_thread_fn,
				    NULL, "ck_mbm_thr");

	if (IS_ERR(adjust_thread))
		return PTR_ERR(adjust_thread);

	return 0;
}

void ckernel_mbm_stop(void)
{
	if (adjust_thread) {
		kthread_stop(adjust_thread);
		msleep(2000);
		mbm_online_kn = NULL;
		mbm_offline_kn = NULL;
		adjust_thread = NULL;
	}
}
