/* SPDX-License-Identifier: GPL-2.0 */
struct { __uint(type,BPF_MAP_TYPE_HASH); __uint(max_entries,8); __type(key,__u32); __type(value,__u8); } cpu_selected SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries,1); __type(key,__u32); __type(value,struct cis_cpu_irq_state); } cpu_irq_totals SEC(".maps");

static __always_inline void cpu_actor(struct task_struct *t, struct cis_cpu_actor *a)
{
	struct cis_identity id = {};
	a->tid = ((__u64)BPF_CORE_READ(t,tgid)<<32) | (__u32)BPF_CORE_READ(t,pid);
	a->start = BPF_CORE_READ(t,start_boottime);
	if (a->tid && identity(t,&id)) { a->id=id.id; a->generation=id.generation; }
}

static __always_inline int cpu_admit(struct cis_cpu_event *e, __u32 phase, int migration)
{
	__u32 zero=0, cpu=bpf_get_smp_processor_id();
	struct session_window *w=bpf_map_lookup_elem(&session_window,&zero);
	struct cis_bpf_stats *s=statistics();
	__u64 now=bpf_ktime_get_ns();
	COUNT(s,received);
	if (!w || now<w->start_ns || now>=w->end_ns) { COUNT(s,expired); return 0; }
	/* Migration is emitted globally so a task leaving selected CPUs cannot
	 * leave a falsely continuous pending runnable interval behind. */
	if (!migration && !bpf_map_lookup_elem(&cpu_selected,&cpu)) return 0;
	e->base.type=CIS_CPU_EVENT; e->base.time_ns=now; e->base.cpu=cpu;
	e->base.stack_id=-1; e->phase=phase;
	return 1;
}

static __always_inline int cpu_output(void *ctx, struct cis_cpu_event *e)
{
	struct cis_bpf_stats *s=statistics();
	__u32 zero=0;
	struct cis_cpu_irq_state *irq=bpf_map_lookup_elem(&cpu_irq_totals,&zero);
	if(irq) {
		__u64 sequence=irq->sequence;
		e->irq_ns=irq->total_ns; e->irq_entries=irq->entries; e->irq_errors=irq->errors;
		e->irq_valid=!(sequence&1) && !irq->depth && sequence==irq->sequence;
	}
	if(bpf_perf_event_output(ctx,&events,BPF_F_CURRENT_CPU,e,sizeof(*e))) COUNT(s,lost);
	else COUNT(s,emitted);
	return 0;
}

SEC("raw_tp/sched_switch")
int cpu_switch(struct bpf_raw_tracepoint_args *ctx)
{
	struct cis_cpu_event e={};
	if(!cpu_admit(&e,1,0)) return 0;
	cpu_actor((void*)ctx->args[1],&e.actor); cpu_actor((void*)ctx->args[2],&e.next);
	e.value=ctx->args[3]; e.base.flags=!!ctx->args[0];
	return cpu_output(ctx,&e);
}
SEC("raw_tp/sched_migrate_task")
int cpu_migrate(struct bpf_raw_tracepoint_args *ctx)
{
	struct cis_cpu_event e={};
	if(!cpu_admit(&e,2,1)) return 0;
	cpu_actor((void*)ctx->args[0],&e.actor); e.destination=ctx->args[1];
	return cpu_output(ctx,&e);
}
SEC("raw_tp/sched_stat_wait")
int cpu_wait(struct bpf_raw_tracepoint_args *ctx)
{
	struct cis_cpu_event e={};
	if(!cpu_admit(&e,3,0)) return 0;
	cpu_actor((void*)ctx->args[0],&e.actor); e.value=ctx->args[1];
	return cpu_output(ctx,&e);
}
static __always_inline int cpu_interrupt(void *ctx,__u32 phase,__u64 vector)
{
	struct cis_cpu_event e={};
	struct cis_cpu_irq_state *irq;
	__u32 zero=0,depth;
	(void)ctx;
	if(!cpu_admit(&e,phase,0)) return 0;
	irq=bpf_map_lookup_elem(&cpu_irq_totals,&zero);
	if(!irq) return 0;
	/* Never emit perf records from IRQ callbacks: perf's irq_work notification
	 * would itself create observable IRQs and a self-amplifying event stream. */
	__sync_fetch_and_add(&irq->sequence,1);
	depth=irq->depth;
	if(phase==4 || phase==6) {
		irq->entries++;
		if(!depth) irq->begin_ns=e.base.time_ns;
		if(depth<8) { irq->kinds[depth]=phase; irq->vectors[depth]=vector; }
		else irq->errors++;
		irq->depth=depth+1;
	} else if(!depth) irq->errors++;
	else {
		depth--; irq->depth=depth;
		if(depth<8 && (irq->kinds[depth]!=phase-1 || irq->vectors[depth]!=vector)) irq->errors++;
		if(!depth && e.base.time_ns>=irq->begin_ns) irq->total_ns+=e.base.time_ns-irq->begin_ns;
	}
	__sync_fetch_and_add(&irq->sequence,1);
	return 0;
}
SEC("raw_tp/irq_handler_entry")
int cpu_irq_begin(struct bpf_raw_tracepoint_args *ctx) { return cpu_interrupt(ctx,4,ctx->args[0]); }
SEC("raw_tp/irq_handler_exit")
int cpu_irq_end(struct bpf_raw_tracepoint_args *ctx) { return cpu_interrupt(ctx,5,ctx->args[0]); }
SEC("raw_tp/softirq_entry")
int cpu_soft_begin(struct bpf_raw_tracepoint_args *ctx) { return cpu_interrupt(ctx,6,ctx->args[0]); }
SEC("raw_tp/softirq_exit")
int cpu_soft_end(struct bpf_raw_tracepoint_args *ctx) { return cpu_interrupt(ctx,7,ctx->args[0]); }
static __always_inline int cpu_work(void *ctx,__u32 phase,struct work_struct *work,void *function)
{
	struct cis_cpu_event e={};
	if(!cpu_admit(&e,phase,0)) return 0;
	cpu_actor((void*)bpf_get_current_task(),&e.actor);
	e.base.object=(__u64)work; e.function=(__u64)function;
	return cpu_output(ctx,&e);
}
SEC("raw_tp/workqueue_execute_start")
int cpu_work_begin(struct bpf_raw_tracepoint_args *ctx)
{
	struct work_struct *work=(void*)ctx->args[0];
	return cpu_work(ctx,8,work,(void*)BPF_CORE_READ(work,func));
}
SEC("raw_tp/workqueue_execute_end")
int cpu_work_end(struct bpf_raw_tracepoint_args *ctx)
{
	/* The callback may have freed work; use the tracepoint's saved function. */
	return cpu_work(ctx,9,(void*)ctx->args[0],(void*)ctx->args[1]);
}
