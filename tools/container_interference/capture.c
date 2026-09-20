// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include "include/cis.h"
#include "include/cis_trigger.h"
#include "include/cis_capture_profile.h"
#include "include/cis_prog_info.h"
#include <linux/types.h>
#include "include/cis_event.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/perf_event.h>
#include <limits.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>
#define CIS_CPU_CAP 512
#define CIS_DIAGNOSTIC_LINKS 47
#include "include/cis_backend_selection.h"
#include <sys/sysmacros.h>
#include <sys/stat.h>
#include <sys/socket.h>
struct capture {
	struct cis_context *ctx;
	struct bpf_object *object;
	struct perf_buffer *ring;
	struct bpf_link *diagnostic_links[CIS_DIAGNOSTIC_LINKS];
	int perf_fds[CIS_CPU_CAP], ncpu, roots, targets, pending, stacks, stats;
	void *perf_pages[CIS_CPU_CAP];
	size_t perf_page_size;
	uint64_t perf_lost, perf_throttle, perf_unthrottle, perf_bad_records;
	unsigned int active_kinds;
	uint64_t last_stats_ns, last_received;
	uint64_t counter_enabled[CIS_CPU_CAP],counter_running[CIS_CPU_CAP],counter_read_ns[CIS_CPU_CAP];
	unsigned int counter_cursor;
	uint64_t next_counter_ns, next_full_consume_ns;
	struct cis_bpf_stats *cpu_stats;
	int possible_cpus;
	int quiesced, stop_error;
	int rwsem_filter_fd;
	int backend_filter_fd;
	int filesystem_filter_fd;
	unsigned long long filesystem_before[6];
	int filesystem_audit_ready;
	uint64_t filesystem_poll_ns,filesystem_poll_entries;
	int queue_filter_fd;
	char queue_readback[256];
	unsigned long long queue_before[6];
	int queue_audit_ready;
	uint64_t queue_poll_ns,queue_poll_entries;
};

static int source_audit(const char *path,unsigned long long sum[6])
{
	FILE *f=fopen(path,"r");
	char line[512];
	unsigned char seen[CIS_CPU_CAP]={0};
	unsigned int cpu,ncpu=0;
	unsigned long long values[6];
	int i,rc=-EINVAL;
	memset(sum,0,6*sizeof(*sum));
	if(!f) return -errno;
	if(!fgets(line,sizeof(line),f) || strncmp(line,"version=1 ",10)) goto out;
	while(fgets(line,sizeof(line),f)) {
		if(sscanf(line,"cpu=%u entries=%llu filtered=%llu sampled=%llu emitted=%llu expired=%llu recursive=%llu",
			&cpu,&values[0],&values[1],&values[2],&values[3],&values[4],&values[5])!=7 || cpu>=CIS_CPU_CAP || seen[cpu]) goto out;
		seen[cpu]=1; ncpu++;
		for(i=0;i<6;i++) sum[i]+=values[i];
	}
	if(!ferror(f) && ncpu) rc=0;
out:
	fclose(f); return rc;
}

static int filesystem_audit(unsigned long long sum[6])
{
	return source_audit("/sys/kernel/debug/cis_fs_audit",sum);
}

static int queue_audit(unsigned long long sum[6])
{
	return source_audit("/sys/kernel/debug/cis_queue_audit",sum);
}

static int queue_readback_valid(struct capture *c)
{
	char actual[256];
	ssize_t n=pread(c->queue_filter_fd,actual,sizeof(actual)-1,0);
	if(n<=0) return 0;
	actual[n]=0;
	return !strcmp(actual,c->queue_readback);
}

static int prepare_queue_filter(struct capture *c)
{
	struct cis_context *ctx=c->ctx;
	struct stat self,init;
	unsigned long long lease,qdisc;
	unsigned int valid,netns,ifindex,queue,handle;
	char wanted[96],detail[384];
	int fd,n,used=0;
	ssize_t got;
	if(ctx->session_collector!=16) return 0;
	if(stat("/proc/self/ns/net",&self) || stat("/proc/1/ns/net",&init) ||
	   self.st_ino!=init.st_ino || self.st_dev!=init.st_dev) return -EPERM;
	fd=socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0);
	if(fd<0) return -errno;
	c->queue_filter_fd=open("/sys/kernel/debug/cis_queue_filter",O_RDWR|O_CLOEXEC);
	if(c->queue_filter_fd<0) { close(fd); return -errno; }
	n=snprintf(wanted,sizeof(wanted),"%d %u %u\n",fd,ctx->queue_ifindex,ctx->queue_index);
	got=write(c->queue_filter_fd,wanted,n); close(fd);
	if(got!=n) return -EIO;
	got=pread(c->queue_filter_fd,c->queue_readback,sizeof(c->queue_readback)-1,0);
	if(got<=0) return -EIO;
	c->queue_readback[got]=0;
	if(sscanf(c->queue_readback,"version=1 lease=%llu valid=%u netns=%u ifindex=%u queue=%u handle=%u qdisc=%llu\n%n",
		&lease,&valid,&netns,&ifindex,&queue,&handle,&qdisc,&used)!=7 || used!=got ||
	   !lease || !qdisc || valid!=1 || netns!=self.st_ino || ifindex!=ctx->queue_ifindex || queue!=ctx->queue_index) return -EINVAL;
	snprintf(detail,sizeof(detail),"protocol=1 lease=%llu valid=1 netns=%u ifindex=%u queue=%u handle=%u qdisc=%llu pinned=1 readback=1",
		lease,netns,ifindex,queue,handle,qdisc);
	cis_report(ctx,"queue_source_filter",NULL,detail);
	if(queue_audit(c->queue_before)) return -EIO;
	c->queue_audit_ready=1;
	c->queue_poll_ns=cis_clock_ns(); c->queue_poll_entries=c->queue_before[0];
	return 0;
}

static int prepare_filesystem_filter(struct capture *c)
{
	struct cis_context *ctx=c->ctx;
	struct stat st;
	unsigned long long lease;
	unsigned int dev,maj,min;
	char wanted[24],actual[160],detail[256];
	int n,consumed=0;
	ssize_t got;
	if(ctx->session_collector!=15) return 0;
	if(ctx->filesystem_fd<0 || fstat(ctx->filesystem_fd,&st) || !S_ISDIR(st.st_mode)) return -EINVAL;
	c->filesystem_filter_fd=open("/sys/kernel/debug/cis_fs_filter",O_RDWR|O_CLOEXEC);
	if(c->filesystem_filter_fd<0) return -errno;
	n=snprintf(wanted,sizeof(wanted),"%d\n",ctx->filesystem_fd);
	if(write(c->filesystem_filter_fd,wanted,n)!=n) return -EIO;
	got=read(c->filesystem_filter_fd,actual,sizeof(actual)-1);
	if(got<=0) return -EIO;
	actual[got]=0;
	if(sscanf(actual,"version=1 lease=%llu dev=%u major=%u minor=%u\n%n",&lease,&dev,&maj,&min,&consumed)!=4 ||
	   consumed!=got || !lease || maj!=major(st.st_dev) || min!=minor(st.st_dev)) return -EINVAL;
	snprintf(detail,sizeof(detail),"protocol=1 lease=%llu dev=%u major=%u minor=%u pinned=1 readback=1",lease,dev,maj,min);
	cis_report(ctx,"filesystem_source_filter",NULL,detail);
	if(filesystem_audit(c->filesystem_before)) return -EIO;
	c->filesystem_audit_ready=1;
	c->filesystem_poll_ns=cis_clock_ns(); c->filesystem_poll_entries=c->filesystem_before[0];
	return 0;
}

static int prepare_backend_filter(struct capture *c)
{
	struct cis_context *ctx=c->ctx;
	char wanted[160], actual[160], argument[164], cache[68], detail[240];
	FILE *file;
	size_t length;
	ssize_t got;
	if (ctx->session_collector!=8 && ctx->session_collector!=12 && ctx->session_collector!=13 && ctx->session_collector!=14) return 0;
	c->backend_filter_fd=open("/sys/kernel/debug/cis_backend_filter",O_RDWR|O_CLOEXEC);
	if (c->backend_filter_fd<0) {
		if (errno==ENOENT && !ctx->backend_selection[0] && ctx->session_collector!=14) {
			cis_report(ctx,"backend_source_filter",NULL,"protocol=1 lease=0 legacy_boot_selection=1");
			return 0;
		}
		return -errno;
	}
	if (ctx->backend_selection[0]) memcpy(wanted,ctx->backend_selection,sizeof(wanted));
	else if (ctx->session_collector==14) strcpy(wanted,"page_zone *\n");
	else {
		file=fopen("/sys/module/cis_observe/parameters/alloc_cache","r");
		if (!file) return -errno;
		if (!fgets(cache,sizeof(cache),file)) { fclose(file); return -EIO; }
		fclose(file); cache[strcspn(cache,"\n")]=0;
		snprintf(argument,sizeof(argument),"a:%s:*",cache);
		if (cis_parse_backend(argument,wanted)) return -EINVAL;
	}
	length=strlen(wanted);
	if (write(c->backend_filter_fd,wanted,length)!=(ssize_t)length) return -EIO;
	got=read(c->backend_filter_fd,actual,sizeof(actual));
	if (got!=(ssize_t)length || memcmp(actual,wanted,length)) return -EIO;
	wanted[length-1]=0;
	{
		char *nodes=strchr(wanted,' '); *nodes++=0;
		snprintf(detail,sizeof(detail),"protocol=1 lease=1 readback=1 cache=%s nodes=%s node_scope=%s allocation_release_scope=%s",wanted,nodes,
			ctx->session_collector==14?"page_zone":"slub_lock_only",ctx->session_collector==14?"not_tracked":"whole_selected_cache");
	}
	cis_report(ctx,"backend_source_filter",NULL,detail);
	return 0;
}

static int prepare_rwsem_filter(struct capture *c)
{
	struct cis_context *ctx=c->ctx;
	char wanted[256], actual[256], detail[128];
	size_t length=0;
	unsigned int i;
	ssize_t got;
	if(!ctx->selected_object_count || ctx->selected_object_count>8) return -EINVAL;
	for(i=0;i<ctx->selected_object_count;i++)
		length+=snprintf(wanted+length,sizeof(wanted)-length,"%s0x%llx",i?" ":"",
			(unsigned long long)ctx->selected_objects[i]);
	wanted[length++]='\n';
	c->rwsem_filter_fd=open("/sys/kernel/debug/cis_rwsem_filter",O_RDWR|O_CLOEXEC);
	if(c->rwsem_filter_fd<0) return -errno;
	if(write(c->rwsem_filter_fd,wanted,length)!=(ssize_t)length) return -EIO;
	got=read(c->rwsem_filter_fd,actual,sizeof(actual));
	if(got!=(ssize_t)length || memcmp(actual,wanted,length)) return -EIO;
	for(i=0;i<ctx->selected_object_count;i++) {
		snprintf(detail,sizeof(detail),"index=%u count=%u object=0x%llx readback=1 lease=1",
			i,ctx->selected_object_count,(unsigned long long)ctx->selected_objects[i]);
		cis_report(ctx,"rwsem_source_filter",NULL,detail);
	}
	return 0;
}

static int mapfd(struct capture *c,const char *name)
{
	return bpf_object__find_map_fd_by_name(c->object,name);
}

static int fd_memlock(int fd,unsigned long long *bytes)
{
	char path[64],line[256];
	FILE *file;
	snprintf(path,sizeof(path),"/proc/self/fdinfo/%d",fd);
	file=fopen(path,"r");
	if(!file) return -1;
	while(fgets(line,sizeof(line),file)) if(sscanf(line,"memlock: %llu",bytes)==1) {
		fclose(file); return 0;
	}
	fclose(file); return -1;
}

static void memory_inventory(struct capture *c,int pages)
{
	struct bpf_map *map;
	struct bpf_program *program;
	unsigned long long maps=0,programs=0,value;
	unsigned int missing=0;
	char detail[600];
	bpf_object__for_each_map(map,c->object) {
		struct bpf_map_info info={0}; __u32 size=sizeof(info);
		int valid,info_valid;
		if (!bpf_map__autocreate(map)) continue;
		value=0; valid=!fd_memlock(bpf_map__fd(map),&value);
		if(!valid) missing++;
		else maps+=value;
		info_valid=!bpf_obj_get_info_by_fd(bpf_map__fd(map),&info,&size);
		snprintf(detail,sizeof(detail),"object_type=map object_id=%u info_valid=%d fdinfo_valid=%d fdinfo_bytes=%llu map_type=%u key_bytes=%u value_bytes=%u max_entries=%u map_flags=%u allocation_upper_bound_known=0",
			info.id,info_valid,valid,value,info.type,info.key_size,info.value_size,info.max_entries,info.map_flags);
		cis_report(c->ctx,"kernel_object_inventory",NULL,detail);
	}
	bpf_object__for_each_program(program,c->object) {
		struct bpf_prog_info info={0}; __u32 size=sizeof(info);
		int valid,info_valid;
		if (!bpf_program__autoload(program)) continue;
		value=0; valid=!fd_memlock(bpf_program__fd(program),&value);
		if(!valid) missing++;
		else programs+=value;
		info_valid=!bpf_obj_get_info_by_fd(bpf_program__fd(program),&info,&size);
		snprintf(detail,sizeof(detail),"object_type=program object_id=%u info_valid=%d fdinfo_valid=%d fdinfo_bytes=%llu jit_code_bytes=%u xlated_bytes=%u btf_id=%u nr_map_ids=%u allocation_upper_bound_known=0",
			info.id,info_valid,valid,value,info.jited_prog_len,info.xlated_prog_len,info.btf_id,info.nr_map_ids);
		cis_report(c->ctx,"kernel_object_inventory",NULL,detail);
	}
	snprintf(detail,sizeof(detail),"bpf_maps_fdinfo_bytes=%llu bpf_program_pages_bytes=%llu perf_output_mapping_bytes=%llu ip_mapping_bytes=%llu missing_fdinfo=%u rss_overlap_do_not_sum=1 excludes=jit_aux_btf_perf_objects_psi_workers total_complete=0",
		maps,programs,(unsigned long long)(pages+1)*4096*c->possible_cpus,
		(unsigned long long)2*4096*c->ncpu,missing);
	cis_report(c->ctx,"kernel_memory_inventory",NULL,detail);
}

static void event(void *opaque,int cpu,void *data,__u32 size)
{
	struct capture *c=opaque;
	struct cis_context *ctx=c->ctx;
	struct cis_event *e=data;
	struct cis_root *r;
	char detail[768];
	const char *symbol;
	(void)cpu;
	if(size>=sizeof(struct cis_cpu_event) && size<=sizeof(struct cis_cpu_event)+7 && e->type==CIS_CPU_EVENT) {
		struct cis_cpu_event *v=data;
		snprintf(detail,sizeof(detail),"protocol=2 time_ns=%llu cpu=%u phase=%u tid=%llu task_start=%llu actor_id=%llu actor_generation=%llu next_tid=%llu next_start=%llu next_id=%llu next_generation=%llu value=%llu flags=%u destination=%u object=%llu function=%llu irq_ns=%llu irq_entries=%llu irq_errors=%llu irq_valid=%u",
			(unsigned long long)e->time_ns,e->cpu,v->phase,
			(unsigned long long)v->actor.tid,(unsigned long long)v->actor.start,
			(unsigned long long)v->actor.id,(unsigned long long)v->actor.generation,
			(unsigned long long)v->next.tid,(unsigned long long)v->next.start,
			(unsigned long long)v->next.id,(unsigned long long)v->next.generation,
			(unsigned long long)v->value,e->flags,v->destination,
			(unsigned long long)e->object,(unsigned long long)v->function,
			(unsigned long long)v->irq_ns,(unsigned long long)v->irq_entries,
			(unsigned long long)v->irq_errors,v->irq_valid);
		cis_report(ctx,"CPU_POINT",NULL,detail); return;
	}
	if(size>=sizeof(struct cis_qdisc_event) && size<=sizeof(struct cis_qdisc_event)+7 && e->type==CIS_QDISC_EVENT) {
		struct cis_qdisc_event *v=data;
		struct cis_qdisc_data *s=&v->sample;
		char d[1200];
		int n=snprintf(d,sizeof(d),"protocol=1 begin_ns=%llu acquired_ns=%llu end_ns=%llu lease=%llu qdisc=%llu txq=%llu dev=%llu skb=%llu actor_cgroup=%llu socket_cgroup=%llu txq_state=%llu netns=%u ifindex=%u queue=%u handle=%u operation=%u sample_shift=%u qlen_begin=%u qlen_end=%u backlog_begin=%u backlog_end=%u length=%u context=%u flags=%u packets=%u result=%d actor_id=%llu actor_generation=%llu socket_id=%llu socket_generation=%llu tid=%llu task_start=%llu cpu=%u",
			(unsigned long long)s->begin_ns,(unsigned long long)s->acquired_ns,(unsigned long long)s->end_ns,
			(unsigned long long)s->lease,(unsigned long long)s->qdisc,(unsigned long long)s->txq,
			(unsigned long long)s->dev,(unsigned long long)s->skb,(unsigned long long)s->actor_cgroup,
			(unsigned long long)s->socket_cgroup,(unsigned long long)s->txq_state,s->netns,s->ifindex,s->queue,
			s->handle,s->operation,s->sample_shift,s->qlen_begin,s->qlen_end,s->backlog_begin,s->backlog_end,
			s->length,s->context,s->flags,s->packets,s->result,(unsigned long long)v->actor_id,
			(unsigned long long)v->actor_generation,(unsigned long long)v->socket_id,
			(unsigned long long)v->socket_generation,(unsigned long long)e->tid,(unsigned long long)v->task_start,e->cpu);
		if(n<0 || n>=(int)sizeof(d)) { ctx->errors++; return; }
		cis_report(ctx,"QDISC",NULL,d); return;
	}
	if(size>=sizeof(struct cis_block_pool_event) && size<=sizeof(struct cis_block_pool_event)+7 && e->type==CIS_BLOCK_POOL_EVENT) {
		struct cis_block_pool_event *v=data;
		r=cis_registry_lookup(ctx,e->id,e->generation);
		if(!r) {ctx->unknown++;return;}
		snprintf(detail,sizeof(detail),"protocol=1 sample_time_ns=%llu request=0x%llx episode_ns=%llu queue=0x%llx pool=0x%llx kind=%u tag=%u depth=%u reserved_tags=%u pool_depth=%u dev_major=%u dev_minor=%u",
			(unsigned long long)e->time_ns,(unsigned long long)e->object,(unsigned long long)e->sequence_ns,
			(unsigned long long)v->queue,(unsigned long long)v->pool,v->kind,v->tag,v->depth,v->reserved_tags,
			v->pool_depth,v->dev_major,v->dev_minor);
		cis_report(ctx,"BLOCK_POOL",r,detail);return;
	}
	if(size>=sizeof(struct cis_dirty_pause_event) && size<=sizeof(struct cis_dirty_pause_event)+7 && e->type==CIS_DIRTY_PAUSE_EVENT) {
		struct cis_dirty_pause_event *v=data;
		char d[1100];
		r=cis_registry_lookup(ctx,e->id,e->generation);
		if(!r) {ctx->unknown++;return;}
		snprintf(d,sizeof(d),"protocol=1 begin_ns=%llu end_ns=%llu tid=%llu task_start=%llu cgroup_id=%llu wb=0x%llx bdi=0x%llx bdi_id=%llu wb_memcg=%llu wb_owner_id=%llu wb_owner_generation=%llu dirty=%llu threshold=%llu wb_dirty=%llu wb_threshold=%llu requested_jiffies=%lld remaining_jiffies=%lld cpu=%u stack_id=%d",
			(unsigned long long)e->sequence_ns,(unsigned long long)e->time_ns,(unsigned long long)e->tid,
			(unsigned long long)v->task_start,(unsigned long long)v->cgroup_id,(unsigned long long)v->wb,
			(unsigned long long)v->bdi,(unsigned long long)v->bdi_id,(unsigned long long)v->wb_memcg,
			(unsigned long long)v->wb_owner_id,(unsigned long long)v->wb_owner_generation,
			(unsigned long long)v->dirty,(unsigned long long)v->threshold,(unsigned long long)v->wb_dirty,
			(unsigned long long)v->wb_threshold,(long long)v->requested_jiffies,(long long)v->remaining_jiffies,
			e->cpu,e->stack_id);
		cis_report(ctx,"DIRTY_PAUSE",r,d);return;
	}
	if(size>=sizeof(struct cis_writeback_event) && size<=sizeof(struct cis_writeback_event)+7 && e->type==CIS_WRITEBACK_EVENT) {
		struct cis_writeback_event *v=data;
		char d[1100];
		r=cis_registry_lookup(ctx,e->id,e->generation);
		if(!r) {ctx->unknown++;return;}
		snprintf(d,sizeof(d),"protocol=1 sample_time_ns=%llu episode_ns=%llu phase=%u inode=0x%llx ino=%llu inode_generation=%u dev_major=%u dev_minor=%u folio_index=%llu tid=%llu task_start=%llu actor_id=%llu actor_generation=%llu wbc=0x%llx memcg=%llu wb_owner_id=%llu wb_owner_generation=%llu request=0x%llx request_episode=%llu",
			(unsigned long long)e->time_ns,(unsigned long long)e->sequence_ns,e->reserved,
			(unsigned long long)e->object,(unsigned long long)e->ip,e->flags,e->nesting>>20,e->nesting&((1U<<20)-1),
			(unsigned long long)e->weight,(unsigned long long)e->tid,(unsigned long long)v->task_start,
			(unsigned long long)v->actor_id,(unsigned long long)v->actor_generation,(unsigned long long)v->wbc,
			(unsigned long long)v->memcg,(unsigned long long)v->wb_owner_id,(unsigned long long)v->wb_owner_generation,
			(unsigned long long)v->request,(unsigned long long)v->request_episode);
		cis_report(ctx,"WRITEBACK",r,d);return;
	}
	if(size>=sizeof(struct cis_block_link_event) && size<=sizeof(struct cis_block_link_event)+7 && e->type==CIS_BLOCK_LINK_EVENT) {
		struct cis_block_link_event *v=data;
		r=cis_registry_lookup(ctx,e->id,e->generation);
		if(!r) {ctx->unknown++;return;}
		snprintf(detail,sizeof(detail),"protocol=1 sample_time_ns=%llu request=0x%llx episode_ns=%llu queue=0x%llx victim=0x%llx victim_episode_ns=%llu bio=0x%llx merge_kind=%u before_bytes=%u added_bytes=%u",
			(unsigned long long)e->time_ns,(unsigned long long)e->object,(unsigned long long)e->sequence_ns,
			(unsigned long long)v->queue,(unsigned long long)v->victim,(unsigned long long)v->victim_episode,
			(unsigned long long)v->bio,v->kind,v->before_bytes,v->added_bytes);
		cis_report(ctx,"BLOCK_LINK",r,detail);return;
	}
	if(size>=sizeof(struct cis_block_bio_event) && size<=sizeof(struct cis_block_bio_event)+7 && e->type==CIS_BLOCK_BIO_EVENT) {
		struct cis_block_bio_event *v=data;
		r=cis_registry_lookup(ctx,e->id,e->generation);
		if(!r) {ctx->unknown++;return;}
		snprintf(detail,sizeof(detail),"protocol=1 sample_time_ns=%llu request=0x%llx episode_ns=%llu bio=0x%llx index=%u bytes=%u remaining=%u more=%u bio_cgroup=%llu bio_owner_id=%llu bio_owner_generation=%llu bio_origin_overdepth=%u",
			(unsigned long long)e->time_ns,(unsigned long long)e->object,(unsigned long long)e->sequence_ns,
			(unsigned long long)v->bio,v->index,v->bytes,v->remaining,v->more,
			(unsigned long long)v->cgroup,(unsigned long long)v->owner_id,(unsigned long long)v->owner_generation,v->overdepth);
		cis_report(ctx,"BLOCK_BIO",r,detail);return;
	}
	if(size>=sizeof(struct cis_block_tag_event) && size<=sizeof(struct cis_block_tag_event)+7 && e->type==CIS_BLOCK_TAG_EVENT) {
		struct cis_block_tag_event *v=data;
		char d[1000];
		r=cis_registry_lookup(ctx,e->id,e->generation);
		if(!r) {ctx->unknown++;return;}
		snprintf(d,sizeof(d),"protocol=1 sample_time_ns=%llu episode_ns=%llu tid=%llu task_start=%llu queue=0x%llx pool=0x%llx phase=%u alloc_flags=%u tag=%d dev_major=%u dev_minor=%u actor_id=%llu actor_generation=%llu cpu=%u stack_id=%d",
			(unsigned long long)e->time_ns,(unsigned long long)e->sequence_ns,
			(unsigned long long)e->tid,(unsigned long long)v->task_start,
			(unsigned long long)v->queue,(unsigned long long)e->object,
			v->phase,v->alloc_flags,v->tag,v->dev_major,v->dev_minor,
			(unsigned long long)v->actor_id,(unsigned long long)v->actor_generation,e->cpu,e->stack_id);
		cis_report(ctx,"BLOCK_TAG",r,d);return;
	}
	if(size>=sizeof(struct cis_block_event) && size<=sizeof(struct cis_block_event)+7 && e->type==CIS_BLOCK_EVENT) {
		struct cis_block_event *v=data;
		char d[1400];
		r=cis_registry_lookup(ctx,e->id,e->generation);
		if(!r) {ctx->unknown++;return;}
		snprintf(d,sizeof(d),"protocol=3 sample_time_ns=%llu request=0x%llx episode_ns=%llu submitter_tid=%llu submitter_start=%llu queue=0x%llx bio=0x%llx phase=%u dev_major=%u dev_minor=%u remaining=%u completed=%u operation=%u multi_bio=%u context=%u status=%u actor_tid=%llu actor_start=%llu actor_id=%llu actor_generation=%llu cpu=%u stack_id=%d bio_cgroup=%llu bio_owner_id=%llu bio_owner_generation=%llu bio_bytes=%u bio_origin_overdepth=%u admission=%u submitter_id=%llu submitter_generation=%llu submitter_flags=%u",
			(unsigned long long)e->time_ns,(unsigned long long)e->object,(unsigned long long)e->sequence_ns,
			(unsigned long long)e->tid,(unsigned long long)v->submitter_start,(unsigned long long)v->queue,
			(unsigned long long)v->bio,v->phase,v->dev_major,v->dev_minor,v->remaining,v->completed,
			v->operation,v->multi_bio,v->context,v->status,(unsigned long long)v->actor_tid,
			(unsigned long long)v->actor_start,(unsigned long long)v->actor_id,(unsigned long long)v->actor_generation,
			e->cpu,e->stack_id,(unsigned long long)v->bio_cgroup,(unsigned long long)v->bio_owner_id,
			(unsigned long long)v->bio_owner_generation,v->bio_bytes,v->bio_origin_overdepth,e->reserved,
			(unsigned long long)e->ip,(unsigned long long)e->weight,e->flags);
		cis_report(ctx,"BLOCK",r,d);return;
	}
	if(size>=sizeof(struct cis_net_tx_event) && size<=sizeof(struct cis_net_tx_event)+7 && e->type==CIS_NET_TX_EVENT) {
		struct cis_net_tx_event *v=data;
		char d[1100];
		r=cis_registry_lookup(ctx,e->id,e->generation);
		if(!r) {ctx->unknown++;return;}
		snprintf(d,sizeof(d),"protocol=3 sample_time_ns=%llu begin_ns=%llu alloc_ns=%llu backend_ns=%llu tid=%llu task_start=%llu skb=0x%llx cookie=%llu socket=0x%llx phase=%u context=%u actor_tid=%llu actor_start=%llu actor_id=%llu actor_generation=%llu cpu=%u netns=%u gfp=%u requested=%u stack_id=%d release_ns=%llu release_backend_ns=%llu release_flags=%u",
			(unsigned long long)e->time_ns,(unsigned long long)e->sequence_ns,(unsigned long long)e->duration_ns,(unsigned long long)v->backend_ns,
			(unsigned long long)e->tid,(unsigned long long)v->task_start,(unsigned long long)e->object,
			(unsigned long long)v->cookie,(unsigned long long)v->socket,v->phase,e->flags,
			(unsigned long long)v->actor_tid,(unsigned long long)v->actor_start,(unsigned long long)v->actor_id,
			(unsigned long long)v->actor_generation,e->cpu,v->netns,v->gfp,v->requested,e->stack_id,
			(unsigned long long)v->release_ns,(unsigned long long)v->release_backend_ns,v->release_flags);
		cis_report(ctx,"NET_TX",r,d);return;
	}
	if(size>=sizeof(struct cis_net_event) && size<=sizeof(struct cis_net_event)+7 && e->type==CIS_NET_EVENT) {
		struct cis_net_event *v=data;
		char d[1100];
		r=cis_registry_lookup(ctx,e->id,e->generation);
		if(!r) {ctx->unknown++;return;}
		snprintf(d,sizeof(d),"protocol=1 sample_time_ns=%llu cookie=%llu socket=0x%llx skb=0x%llx queue_ns=%llu phase=%u context=%u actor_tid=%llu actor_start=%llu actor_id=%llu actor_generation=%llu cpu=%u netns=%u bytes=%u backlog_bytes=%u packet_flags=%u stack_id=%d",
			(unsigned long long)e->time_ns,(unsigned long long)v->cookie,(unsigned long long)e->object,
			(unsigned long long)v->skb,(unsigned long long)e->sequence_ns,v->phase,e->flags,
			(unsigned long long)e->tid,(unsigned long long)v->actor_start,(unsigned long long)v->actor_id,
			(unsigned long long)v->actor_generation,e->cpu,v->netns,v->bytes,v->backlog_bytes,v->packet_flags,e->stack_id);
		cis_report(ctx,"NET",r,d);return;
	}
	if(size>=sizeof(struct cis_alloc_release_event) && size<=sizeof(struct cis_alloc_release_event)+7 && e->type==CIS_ALLOC_RELEASE_EVENT) {
		struct cis_alloc_release_event *v=data;
		char d[1100];
		r=cis_registry_lookup(ctx,e->id,e->generation);
		if(!r) {ctx->unknown++;return;}
		snprintf(d,sizeof(d),"protocol=1 sample_time_ns=%llu call_ns=%llu allocation_time_ns=%llu allocation_ordinal=%u tid=%llu task_start=%llu cpu=%u cache=0x%llx object=0x%llx context=%u caller=0x%llx stack_id=%d executor_tid=%llu executor_start=%llu executor_id=%llu executor_generation=%llu",
			(unsigned long long)e->time_ns,(unsigned long long)e->sequence_ns,
			(unsigned long long)e->weight,e->nesting,(unsigned long long)e->tid,
			(unsigned long long)v->allocation_task_start,e->cpu,(unsigned long long)v->cache,
			(unsigned long long)e->object,e->flags,(unsigned long long)e->ip,e->stack_id,
			(unsigned long long)e->executor_tid,(unsigned long long)v->executor_start,
			(unsigned long long)v->executor_id,(unsigned long long)v->executor_generation);
		cis_report(ctx,"ALLOC_RELEASE",r,d);return;
	}
	if(size>=sizeof(struct cis_maple_event) && size<=sizeof(struct cis_maple_event)+7 && e->type==CIS_MAPLE_EVENT) {
		struct cis_maple_event *v=data;
		char d[700];
		r=cis_registry_lookup(ctx,e->id,e->generation);
		if(!r) {ctx->unknown++;return;}
		snprintf(d,sizeof(d),"protocol=1 sample_time_ns=%llu begin_ns=%llu call_ns=%llu tid=%llu task_start=%llu cpu=%u tree=0x%llx cache=0x%llx operation=%u gfp=%llu requested=%llu count=%llu",
			(unsigned long long)e->time_ns,(unsigned long long)e->sequence_ns,(unsigned long long)e->weight,
			(unsigned long long)e->tid,(unsigned long long)v->task_start,e->cpu,
			(unsigned long long)e->object,(unsigned long long)v->cache,v->operation,
			(unsigned long long)v->gfp,(unsigned long long)v->requested,(unsigned long long)v->count);
		cis_report(ctx,"MAPLE_ALLOC",r,d);return;
	}
	if(size>=sizeof(struct cis_alloc_event) && size<=sizeof(struct cis_alloc_event)+7 && e->type==CIS_ALLOC_EVENT) {
		struct cis_alloc_event *v=data;
		char d[1100];
		r=cis_registry_lookup(ctx,e->id,e->generation);
		if(!r) {ctx->unknown++;return;}
		snprintf(d,sizeof(d),"protocol=1 sample_time_ns=%llu call_ns=%llu tid=%llu task_start=%llu cpu=%u cache=0x%llx object=0x%llx resource=0x%llx operation=%u stage=%u ordinal=%u gfp=%llu requested=%llu count=%llu requested_node=%d observed_node=%d sample_shift=%u stack_id=%d",
			(unsigned long long)e->time_ns,(unsigned long long)e->sequence_ns,
			(unsigned long long)e->tid,(unsigned long long)v->task_start,e->cpu,
			(unsigned long long)v->cache,(unsigned long long)e->object,(unsigned long long)v->resource,
			v->operation,v->stage,v->ordinal,(unsigned long long)v->gfp,
			(unsigned long long)v->requested,(unsigned long long)v->count,
			v->requested_node,v->observed_node,v->sample_shift,e->stack_id);
		cis_report(ctx,"ALLOCATOR",r,d);return;
	}
	if(size>=sizeof(struct cis_rwsem_event) && size<=sizeof(struct cis_rwsem_event)+7 && e->type==CIS_RWSEM_EVENT) {
		struct cis_rwsem_event *v=data;
		char d[700];
		r=cis_registry_lookup(ctx,e->id,e->generation);
		if(!r) {ctx->unknown++;return;}
		snprintf(d,sizeof(d),"protocol=1 sample_time_ns=%llu object=0x%llx init_ns=%llu phase=%u actor_tid=%llu actor_start=%llu actor_id=%llu actor_generation=%llu cpu=%u skipped=%llu stack_id=%d",
			(unsigned long long)e->time_ns,(unsigned long long)e->object,
			(unsigned long long)e->sequence_ns,v->phase,(unsigned long long)e->tid,
			(unsigned long long)v->actor_start,(unsigned long long)v->actor_id,
			(unsigned long long)v->actor_generation,e->cpu,(unsigned long long)v->skipped,e->stack_id);
		cis_report(ctx,"RWSEM",r,d);return;
	}
	if(size>=sizeof(struct cis_filesystem_event) && size<=sizeof(struct cis_filesystem_event)+7 && e->type==CIS_FILESYSTEM_EVENT) {
		struct cis_filesystem_event *v=data;
		char d[900];
		r=cis_registry_lookup(ctx,e->id,e->generation);
		if(!r) {ctx->unknown++;return;}
		snprintf(d,sizeof(d),"protocol=1 begin_ns=%llu acquired_ns=%llu end_ns=%llu tid=%llu task_start=%llu cgroup_id=%llu cpu=%u resource=0x%llx lease=%llu dev=%u operation=%u sample_shift=%u value=%llu count=%llu error=%d stack_id=%d",
			(unsigned long long)e->sequence_ns,(unsigned long long)v->acquired_ns,(unsigned long long)e->time_ns,
			(unsigned long long)e->tid,(unsigned long long)v->task_start,(unsigned long long)v->cgroup_id,
			e->cpu,(unsigned long long)e->object,(unsigned long long)v->lease,v->dev,v->operation,v->sample_shift,
			(unsigned long long)v->value,(unsigned long long)v->count,v->error,e->stack_id);
		cis_report(ctx,"FILESYSTEM",r,d);return;
	}
	if(size>=sizeof(struct cis_page_event) && size<=sizeof(struct cis_page_event)+7 && e->type==CIS_PAGE_BACKEND_EVENT) {
		struct cis_page_event *v=data;
		char d[900];
		r=cis_registry_lookup(ctx,e->id,e->generation);
		if(!r) {ctx->unknown++;return;}
		snprintf(d,sizeof(d),"protocol=1 begin_ns=%llu acquired_ns=%llu releasing_ns=%llu end_ns=%llu tid=%llu task_start=%llu cgroup_id=%llu cpu=%u zone=0x%llx node=%d zone_index=%d order=%d operation=%u sample_shift=%u requested_pages=%llu completed_pages=%llu stack_id=%d",
			(unsigned long long)e->sequence_ns,(unsigned long long)v->acquired_ns,
			(unsigned long long)v->releasing_ns,(unsigned long long)e->time_ns,
			(unsigned long long)e->tid,(unsigned long long)v->task_start,(unsigned long long)v->cgroup_id,
			e->cpu,(unsigned long long)e->object,v->node,v->zone_index,v->order,v->operation,v->sample_shift,
			(unsigned long long)v->requested_pages,(unsigned long long)v->completed_pages,e->stack_id);
		cis_report(ctx,"PAGE_BACKEND",r,d);return;
	}
	if(size>=sizeof(struct cis_counter_event) && size<=sizeof(struct cis_counter_event)+7 && e->type==CIS_COUNTER_EVENT) {
		struct cis_counter_event *v=data;
		char d[1100];
		r=cis_registry_lookup(ctx,e->id,e->generation);
		if(!r) {ctx->unknown++;return;}
		snprintf(d,sizeof(d),"protocol=3 sample_time_ns=%llu call_ns=%llu tid=%llu task_start=%llu cpu=%u leaf=0x%llx object=0x%llx parent=0x%llx operation=%u stage=%u depth=%u ordinal=%u pages=%llu usage=%lld limit_snapshot=%llu sample_shift=%u stack_id=%d leaf_generation=%llu object_generation=%llu parent_generation=%llu owner_cgroup=%llu resource_kind=%u",
			(unsigned long long)e->time_ns,(unsigned long long)e->sequence_ns,
			(unsigned long long)e->tid,(unsigned long long)v->task_start,e->cpu,
			(unsigned long long)v->leaf,(unsigned long long)e->object,(unsigned long long)v->parent,
			v->operation,v->stage,v->depth,v->ordinal,(unsigned long long)v->pages,
			(long long)v->usage,(unsigned long long)v->limit,v->sample_shift,e->stack_id,
			(unsigned long long)v->leaf_generation,(unsigned long long)v->object_generation,
			(unsigned long long)v->parent_generation,(unsigned long long)e->ip,e->flags);
		cis_report(ctx,"COUNTER",r,d);return;
	}
	if(size>=sizeof(struct cis_owner_event) && size<=sizeof(struct cis_owner_event)+7 && e->type==CIS_OWNER_EVENT) {
		struct cis_owner_event *o=data;
		char d[1100];
		r=cis_registry_lookup(ctx,e->id,e->generation);
		if(!r) {ctx->unknown++;return;}
		snprintf(d,sizeof(d),"protocol=2 sample_time_ns=%llu object=0x%llx epoch=%llu phase=%u resource=%u actor_tid=%llu actor_start=%llu actor_id=%llu actor_generation=%llu holder_tid=%llu holder_start=%llu holder_id=%llu holder_generation=%llu cpu=%u flags=%u skipped=%llu stack_id=%d attempt_ns=%llu result=%d cache=0x%llx",
			(unsigned long long)e->time_ns,(unsigned long long)e->object,(unsigned long long)e->sequence_ns,o->phase,o->resource,
			(unsigned long long)e->tid,(unsigned long long)o->actor_start,(unsigned long long)o->actor_id,(unsigned long long)o->actor_generation,
			(unsigned long long)o->holder_tid,(unsigned long long)o->holder_start,(unsigned long long)o->holder_id,(unsigned long long)o->holder_generation,
			e->cpu,e->flags,(unsigned long long)o->skipped,e->stack_id,
			(unsigned long long)o->attempt_ns,o->phase==12?(int)e->flags:0,
			(unsigned long long)(o->resource==4?e->ip:0));
		cis_report(ctx,"OWNER",r,d);return;
	}
	/* PERF_SAMPLE_RAW includes trailing alignment bytes in its reported size. */
	if(size<sizeof(*e) || size>sizeof(*e)+7) {
		if(!ctx->errors) {
			snprintf(detail,sizeof(detail),"payload_bytes=%u expected=%zu",size,sizeof(*e));
			cis_report(ctx,"sample_schema_error",NULL,detail);
		}
		ctx->errors++; return;
	}
	r=cis_registry_lookup(ctx,e->id,e->generation);
	if(!r) { ctx->unknown++; return; }
	symbol=cis_symbol(ctx,e->ip);
	if(e->type==CIS_IP) {
		r->ip_samples++;
		if(strstr(symbol,"mutex") || strstr(symbol,"spin_lock") || strstr(symbol,"rwsem")) {
			r->lock_samples++;
			if(ctx->fast_alert && cis_fast_lock_candidate_symbol(symbol)) {
				if(e->time_ns<r->fast_lock_start_ns || e->time_ns-r->fast_lock_start_ns>250000000ULL) {
					r->fast_lock_start_ns=e->time_ns; r->fast_lock_samples=0;
				}
				r->fast_lock_samples++;
				if(r->fast_lock_samples==3 && r->state!=CIS_DIAGNOSING && r->state!=CIS_COOLDOWN) {
					cis_report(ctx,"FAST_LOCK_CANDIDATE",r,"three sampled lock slowpath IPs within 250ms; not owner proof; request bounded diagnostic");
					r->pending=1; r->manual_diagnostic=0; r->requested_start_ns=0;
					r->diagnostic_kind=CIS_DIAG_OWNER; r->state=CIS_SUSPECT;
				}
			}
		}
		if(strstr(symbol,"reclaim") || strstr(symbol,"shrink_")) r->reclaim_samples++;
	}
	snprintf(detail,sizeof(detail),"sample_time_ns=%llu type=%u tid=%llu cpu=%u object=0x%llx duration_ns=%llu ip=0x%llx weight=%llu stack_id=%d flags=%u executor_tid=%llu sequence_ns=%llu symbol=%s owner=unknown execution_context=task_or_irq_unresolved",
		(unsigned long long)e->time_ns,e->type,(unsigned long long)e->tid,e->cpu,
		(unsigned long long)e->object,(unsigned long long)e->duration_ns,(unsigned long long)e->ip,
		(unsigned long long)e->weight,e->stack_id,e->flags,(unsigned long long)e->executor_tid,(unsigned long long)e->sequence_ns,symbol);
	cis_report(ctx,e->type==CIS_IP?"IP":(e->type>=CIS_WORK_QUEUED && e->type<=CIS_WORK_UNRESOLVED)?"async_submitter":"E1",r,detail);
}

static void lost(void *opaque,int cpu,__u64 count)
{
	struct capture *c=opaque;
	char detail[128];
	c->ctx->dropped=count>UINT_MAX-c->ctx->dropped?UINT_MAX:c->ctx->dropped+count;
	snprintf(detail,sizeof(detail),"cpu=%d lost=%llu per_cpu_buffer_full=1",cpu,(unsigned long long)count);
	cis_report(c->ctx,"buffer_loss",NULL,detail);
}

static int fault_at(struct cis_context *ctx,const char *stage,unsigned int ordinal)
{
	char detail[160];
	if(!ctx->fault_stage || strcmp(ctx->fault_stage,stage) || ++ctx->fault_seen!=ordinal) return 0;
	snprintf(detail,sizeof(detail),"stage=%s ordinal=%u kind=injected_boundary_failure errno=%d",stage,ordinal,ENOMEM);
	cis_report(ctx,"fault_injection",NULL,detail);
	errno=ENOMEM;
	return 1;
}

static int attach(struct capture *c,const char *name,struct bpf_link **slot)
{
	struct bpf_program *p=bpf_object__find_program_by_name(c->object,name);
	if(!p) return -ENOENT;
	if(fault_at(c->ctx,"owner_attach",2)) return -ENOMEM;
	*slot=bpf_program__attach(p);
	if(libbpf_get_error(*slot)) { *slot=NULL; return -EIO; }
	return 0;
}

static int configure_links(struct capture *c,unsigned int kinds)
{
	static const struct { const char *name; unsigned int mask; } links[]={
		{"sched_wait",1},{"lock_begin",2},{"lock_end",2},
		{"reclaim_begin",4},{"reclaim_end",4},
		{"work_queue",8},{"work_start",8},{"work_end",8},
		{"work_cancel_begin",8},{"work_cancel_end",8},
		{"memcg_begin",4},{"memcg_end",4},
		{"owner_state",16},{"owner_switch",16},{"counter_step",32},
		{"alloc_step",64},{"alloc_release",64},{"maple_context",64},{"net_state",128},{"net_release",128},{"net_tx",128},
		{"block_start",256},{"block_insert",256},{"block_issue",256},
		{"block_requeue",256},{"block_complete",256},{"block_merge",256},{"block_remap",256},
		{"block_tag",256},{"block_link",256},
		{"wb_dirty",256},{"wb_begin",256},{"wb_end",256},{"wb_pause",256},
		{"rwsem_state",512},{"page_backend",1024},{"filesystem",2048},{"qdisc_state",4096},
		{"cpu_switch",8192},{"cpu_migrate",8192},{"cpu_wait",8192},
		{"cpu_irq_begin",8192},{"cpu_irq_end",8192},{"cpu_soft_begin",8192},{"cpu_soft_end",8192},
		{"cpu_work_begin",8192},{"cpu_work_end",8192}};
	_Static_assert(sizeof(links)/sizeof(links[0]) == CIS_DIAGNOSTIC_LINKS, "diagnostic links");
	unsigned int i;
	for(i=0;i<CIS_DIAGNOSTIC_LINKS;i++) {
		if(!(kinds&links[i].mask) || !cis_profile_program(c->ctx->session_collector,links[i].name)) {
			bpf_link__destroy(c->diagnostic_links[i]); c->diagnostic_links[i]=NULL;
		}
		else if(!c->diagnostic_links[i] && attach(c,links[i].name,&c->diagnostic_links[i])) return -EIO;
	}
	if(c->active_kinds!=kinds) {
		char detail[256];
		unsigned int count=0;
		for(i=0;i<CIS_DIAGNOSTIC_LINKS;i++) count+=!!c->diagnostic_links[i];
		snprintf(detail,sizeof(detail),"collector_mask=%u attached_links=%u owner_protocol=2",kinds,count);
		cis_report(c->ctx,"diagnostic_links",NULL,detail);
	}
	c->active_kinds=kinds; return 0;
}

int cis_capture_root(struct cis_context *ctx,struct cis_root *r,int add)
{
	struct capture *c=ctx->capture;
	struct cis_identity id={r->id,r->generation};
	if(!c) return 0;
	return add?bpf_map_update_elem(c->roots,&r->id,&id,BPF_NOEXIST):bpf_map_delete_elem(c->roots,&r->id);
}

static void unfinished(struct capture *c,struct cis_root *r)
{
	struct cis_pending_key key,next;
	struct cis_event value;
	unsigned int visited=0;
	int present=bpf_map_get_next_key(c->pending,NULL,&key);
	while(!present && visited++<CIS_INFLIGHT*2) {
		int end=bpf_map_get_next_key(c->pending,&key,&next);
		if(!bpf_map_lookup_elem(c->pending,&key,&value) && value.id==r->id && value.generation==r->generation) {
			char detail[256];
			snprintf(detail,sizeof(detail),"tid=%llu object=0x%llx begin_ns=%llu type=%u; end unobserved",
				(unsigned long long)value.tid,(unsigned long long)value.object,(unsigned long long)value.time_ns,value.type);
			cis_report(c->ctx,"incomplete",r,detail);
			bpf_map_delete_elem(c->pending,&key);
		}
		if(end) break;
		key=next;
	}
	if(visited>=CIS_INFLIGHT*2) cis_report(c->ctx,"incomplete_scan_limited",r,"bounded scan under concurrent map updates; residual remains auditable at shutdown");
}

static void export_stacks(struct capture *c,struct cis_root *r)
{
	struct bpf_map *map = bpf_object__find_map_by_name(c->object,"stacks");
	__u32 key,next;
	__u64 ips[CIS_STACK_DEPTH];
	int err=bpf_map_get_next_key(c->stacks,NULL,&key);
	unsigned int visited=0, capacity=map?bpf_map__max_entries(map):0;
	if(!capacity || capacity>4096) { c->ctx->errors++; return; }
	while(!err && visited++<capacity*2) {
		unsigned int i;
		char detail[1200];
		size_t n=snprintf(detail,sizeof(detail),"stack_id=%u ips=",key);
		if(!bpf_map_lookup_elem(c->stacks,&key,ips)) {
			for(i=0;i<CIS_STACK_DEPTH && ips[i] && n+20<sizeof(detail);i++)
				n+=snprintf(detail+n,sizeof(detail)-n,"%s%llx",i?",":"",(unsigned long long)ips[i]);
			cis_report(c->ctx,"stack",r,detail);
			n=snprintf(detail,sizeof(detail),"stack_id=%u leaf_to_root=",key);
			for(i=0;i<CIS_STACK_DEPTH && ips[i];i++) {
				const char *name=cis_symbol(c->ctx,ips[i]);
				if(n+strlen(name)+20>=sizeof(detail)) {
					snprintf(detail+n,sizeof(detail)-n,";truncated=1");
					break;
				}
				n+=snprintf(detail+n,sizeof(detail)-n,"%s%s",i?">":"",name);
			}
			cis_report(c->ctx,"stack_symbols",r,detail);
		}
		err=bpf_map_get_next_key(c->stacks,&key,&next); key=next;
	}
	if(!err) cis_report(c->ctx,"stack_scan_limited",r,"concurrent updates exceeded bounded export; stack coverage incomplete");
}

static void unfinished_work(struct capture *c,struct cis_root *r)
{
	int fd=mapfd(c,"work_items"),ret;
	__u64 key,next;
	struct cis_work_state state;
	unsigned int visited=0;
	ret=bpf_map_get_next_key(fd,NULL,&key);
	while(!ret && visited++<256) {
		int end=bpf_map_get_next_key(fd,&key,&next);
		if(!bpf_map_lookup_elem(fd,&key,&state)) {
			struct cis_event *e=state.active_valid?&state.active:&state.queued;
			if(e->id==r->id && e->generation==r->generation) {
				char detail[256];
				snprintf(detail,sizeof(detail),"object=0x%llx sequence_ns=%llu queued=%u active=%u cancellation/requeue/lifetime unresolved",
					(unsigned long long)key,(unsigned long long)e->sequence_ns,state.queued_valid,state.active_valid);
				cis_report(c->ctx,"async_incomplete",r,detail);
				bpf_map_delete_elem(fd,&key);
			}
		}
		if(end) break;
		key=next;
	}
}

static void clear_watches(struct capture *c,struct cis_root *r)
{
	struct cis_object_key key,next;
	struct cis_watch value;
	int fd=mapfd(c,"watched"),ret=bpf_map_get_next_key(fd,NULL,&key);
	unsigned int visited=0;
	while(!ret && visited++<128) {
		int end=bpf_map_get_next_key(fd,&key,&next);
		if(!bpf_map_lookup_elem(fd,&key,&value) && value.id==r->id && value.generation==r->generation)
			bpf_map_delete_elem(fd,&key);
		if(end) break;
		key=next;
	}
	if(visited>=128) cis_report(c->ctx,"owner_cleanup_limited",r,"bounded watch cleanup; expired entries remain rejected by time/target");
	{
		struct cis_pending_key attempt,next_attempt;
		struct cis_attempt a;
		fd=mapfd(c,"owner_attempts"); visited=0;
		ret=bpf_map_get_next_key(fd,NULL,&attempt);
		while(!ret && visited++<CIS_INFLIGHT*2) {
			int end=bpf_map_get_next_key(fd,&attempt,&next_attempt);
			if(!bpf_map_lookup_elem(fd,&attempt,&a) && a.id==r->id && a.generation==r->generation) {
				char detail[256];
				snprintf(detail,sizeof(detail),"tid=%llu object=0x%llx attempt_ns=%llu end_unobserved=1",
					(unsigned long long)attempt.tid,(unsigned long long)attempt.object,(unsigned long long)a.start_ns);
				cis_report(c->ctx,"owner_incomplete",r,detail);
				bpf_map_delete_elem(fd,&attempt);
			}
			if(end) break;
			attempt=next_attempt;
		}
	}
}

int cis_capture_diagnostic(struct cis_context *ctx,struct cis_root *r,int enable)
{
	struct capture *c=ctx->capture;
	struct cis_target target={.generation=r->generation,.kind=r->diagnostic_kind};
	unsigned int kinds=enable?r->diagnostic_kind:0,i;
	unsigned int previous_kinds;
	if(!c) return enable?-EOPNOTSUPP:0;
	previous_kinds=c->active_kinds;
	for(i=0;i<CIS_MAX_ROOTS;i++)
		if(&ctx->roots[i]!=r && ctx->roots[i].used && ctx->roots[i].state==CIS_DIAGNOSING) kinds|=ctx->roots[i].diagnostic_kind;
	if(enable) {
		if(configure_links(c,kinds)) { configure_links(c,previous_kinds); return -EOPNOTSUPP; }
		target.start_ns=cis_clock_ns();
		if(r->requested_start_ns) {
			if(r->requested_start_ns<=target.start_ns) { configure_links(c,previous_kinds); return -ETIME; }
			target.start_ns=r->requested_start_ns;
		}
		target.deadline_ns=target.start_ns+ctx->window_ms*1000000ULL;
		if(bpf_map_update_elem(c->targets,&r->id,&target,BPF_NOEXIST)) { configure_links(c,previous_kinds); return -errno; }
		r->diagnostic_start_ns=target.start_ns; r->deadline_ns=target.deadline_ns;
	} else {
		bpf_map_delete_elem(c->targets,&r->id);
		configure_links(c,kinds);
		clear_watches(c,r);
		/* poll() may see no wakeup for a partially filled low-rate buffer. */
		perf_buffer__consume(c->ring); unfinished(c,r); unfinished_work(c,r); export_stacks(c,r);
	}
	return 0;
}

int cis_capture_prepare(struct cis_context *ctx,const char *path)
{
	struct capture *c=calloc(1,sizeof(*c));
	struct bpf_program *p;
	struct bpf_map *map;
	int i,prog_fd,pages=CIS_BUFFER_PAGES;
	struct rlimit limit={RLIM_INFINITY,RLIM_INFINITY};
	char detail[256];
	const char *stage="memlock_limit";
	if(!c) return -ENOMEM;
	/* The audited kernel-memory reserve assumes 4 KiB perf pages. */
	if(sysconf(_SC_PAGESIZE)!=4096) {
		cis_report(ctx,"capture_failure",NULL,"unsupported_page_size: kernel-memory budget not validated");
		free(c); return -EOPNOTSUPP;
	}
	c->ctx=ctx; ctx->capture=c; c->rwsem_filter_fd=-1; c->backend_filter_fd=-1; c->filesystem_filter_fd=-1; c->queue_filter_fd=-1;
	stage="queue_selection";
	if(prepare_queue_filter(c)) goto fail;
	stage="filesystem_selection";
	if(prepare_filesystem_filter(c)) goto fail;
	for(i=0;i<CIS_CPU_CAP;i++) c->perf_fds[i]=-1;
	stage="backend_selection";
	if (prepare_backend_filter(c)) goto fail;
	stage="memlock_limit";
	if(setrlimit(RLIMIT_MEMLOCK,&limit)) goto fail;
	stage="object_open";
	c->object=bpf_object__open_file(path,NULL);
	if(libbpf_get_error(c->object)) { c->object=NULL; goto fail; }
	/* Exclude unused collectors before verification/map allocation, not merely
	 * from attachment. IP sessions cannot silently prepare owner machinery. */
	bpf_object__for_each_program(p,c->object)
		if(bpf_program__set_autoload(p,cis_profile_program(ctx->session_collector,bpf_program__name(p)))) goto fail;
	bpf_object__for_each_map(map,c->object)
		if(bpf_map__set_autocreate(map,cis_profile_map(ctx->session_collector,bpf_map__name(map)))) goto fail;
	if(ctx->session_collector==7) {
		map=bpf_object__find_map_by_name(c->object,"counter_sums");
		if(!map || bpf_map__set_max_entries(map,ctx->selected_object_count ? ctx->selected_object_count*12 : 1)) goto fail;
	}
	stage="object_load";
	if(fault_at(ctx,stage,1)) goto fail;
	if(bpf_object__load(c->object)) goto fail;
	c->roots=mapfd(c,"roots"); c->targets=mapfd(c,"targets"); c->pending=mapfd(c,"pending");
	c->stacks=mapfd(c,"stacks"); c->stats=mapfd(c,"stats");
	if(ctx->session_collector==17) {
		int fd=mapfd(c,"cpu_selected");
		__u8 selected=1,readback;
		stage="cpu_selection";
		if(!ctx->selected_cpu_count || ctx->selected_cpu_count>8 || fd<0) goto fail;
		for(i=0;i<(int)ctx->selected_cpu_count;i++) {
			char path[128];
			FILE *online;
			int value=1;
			snprintf(path,sizeof(path),"/sys/devices/system/cpu/cpu%u",ctx->selected_cpus[i]);
			if(access(path,F_OK)) goto fail;
			snprintf(path,sizeof(path),"/sys/devices/system/cpu/cpu%u/online",ctx->selected_cpus[i]);
			online=fopen(path,"r");
			if(online) { int ok=fscanf(online,"%d",&value)==1; fclose(online); if(!ok || value!=1) goto fail; }
			else if(errno!=ENOENT) goto fail;
			if(bpf_map_update_elem(fd,&ctx->selected_cpus[i],&selected,BPF_NOEXIST) ||
			   bpf_map_lookup_elem(fd,&ctx->selected_cpus[i],&readback) || readback!=1) goto fail;
			snprintf(detail,sizeof(detail),"cpu=%u count=%u readback=1",ctx->selected_cpus[i],ctx->selected_cpu_count);
			cis_report(ctx,"cpu_selection",NULL,detail);
		}
	}
	if(ctx->session_collector==7 && ctx->selected_object_count) {
		int fd=mapfd(c,"counter_selected"), actors=mapfd(c,"counter_actors");
		__u32 slot, readback;
		stage="counter_selection";
		if(ctx->selected_object_count>8 || fd<0 || actors<0) goto fail;
		for(slot=0;slot<ctx->selected_object_count;slot++) {
			if(bpf_map_update_elem(fd,&ctx->selected_objects[slot],&slot,BPF_NOEXIST) ||
			   bpf_map_lookup_elem(fd,&ctx->selected_objects[slot],&readback) || readback!=slot) goto fail;
			snprintf(detail,sizeof(detail),"index=%u count=%u object=0x%llx readback=1",
				slot,ctx->selected_object_count,(unsigned long long)ctx->selected_objects[slot]);
			cis_report(ctx,"counter_selection",NULL,detail);
		}
		for(i=0,slot=0;i<CIS_MAX_ROOTS;i++) if(ctx->roots[i].used && ctx->roots[i].session_target) {
			struct cis_counter_actor actor={.generation=ctx->roots[i].generation,.slot=slot++}, actual;
			if(slot>2 || bpf_map_update_elem(actors,&ctx->roots[i].id,&actor,BPF_NOEXIST) ||
			   bpf_map_lookup_elem(actors,&ctx->roots[i].id,&actual) || memcmp(&actor,&actual,sizeof(actor))) goto fail;
		}
	}
	if(ctx->session_collector==11) {
		int fd=mapfd(c,"rwsem_selected");
		__u8 selected=1, readback=0;
		stage="rwsem_selection";
		if(prepare_rwsem_filter(c)) goto fail;
		if(!ctx->selected_object_count || ctx->selected_object_count>8 || fd<0) goto fail;
		for(i=0;i<(int)ctx->selected_object_count;i++) {
			if(bpf_map_update_elem(fd,&ctx->selected_objects[i],&selected,BPF_NOEXIST) ||
			   bpf_map_lookup_elem(fd,&ctx->selected_objects[i],&readback) || readback!=1) goto fail;
			snprintf(detail,sizeof(detail),"index=%d count=%u object=0x%llx readback=1",
				i,ctx->selected_object_count,(unsigned long long)ctx->selected_objects[i]);
			cis_report(ctx,"rwsem_selection",NULL,detail);
		}
	}
	c->possible_cpus=libbpf_num_possible_cpus();
	if(c->possible_cpus<1 || c->possible_cpus>CIS_CPU_CAP) goto fail;
	stage="cpu_stats";
	if(fault_at(ctx,stage,1)) goto fail;
	c->cpu_stats=calloc(c->possible_cpus,sizeof(*c->cpu_stats));
	if(!c->cpu_stats) goto fail;
	/* More burst room on small systems, still <=4 MiB of payload globally. */
	pages=cis_profile_buffer_pages(ctx->session_collector,c->possible_cpus);
	if(!pages) goto fail;
	stage="output_perf_buffer";
	if(fault_at(ctx,stage,1)) goto fail;
	c->ring=perf_buffer__new(mapfd(c,"events"),pages,event,lost,c,NULL);
	if(libbpf_get_error(c->ring)) { c->ring=NULL; goto fail; }
	snprintf(detail,sizeof(detail),"pages_per_cpu=%d possible_cpus=%d payload_bytes=%llu cap_bytes=4194304",pages,c->possible_cpus,(unsigned long long)pages*4096*c->possible_cpus);
	cis_report(ctx,"buffer_budget",NULL,detail);
	if(ctx->session_collector>=2) { memory_inventory(c,pages); return 0; }
	p=bpf_object__find_program_by_name(c->object,"sample_ip");
	if(!p) goto fail;
	prog_fd=bpf_program__fd(p);
	c->ncpu=sysconf(_SC_NPROCESSORS_CONF);
	if(c->ncpu<1 || c->ncpu>CIS_CPU_CAP || ctx->ip_hz<(unsigned int)c->ncpu) goto fail;
	for(i=0;i<c->ncpu;i++) {
		struct perf_event_attr attr={.size=sizeof(attr),.type=PERF_TYPE_HARDWARE,.config=PERF_COUNT_HW_CPU_CYCLES,
			.read_format=PERF_FORMAT_TOTAL_TIME_ENABLED|PERF_FORMAT_TOTAL_TIME_RUNNING,
			.sample_period=4000000000ULL/(ctx->ip_hz/c->ncpu),.exclude_user=1,.exclude_hv=1,.disabled=1};
		int fd;
		stage="ip_perf_fd";
		if(fault_at(ctx,stage,2)) goto fail;
		fd=syscall(__NR_perf_event_open,&attr,-1,i,-1,PERF_FLAG_FD_CLOEXEC);
		if(fd<0 && (errno==ENOENT || errno==EOPNOTSUPP || errno==EINVAL)) {
			attr.type=PERF_TYPE_SOFTWARE; attr.config=PERF_COUNT_SW_CPU_CLOCK;
			attr.sample_period=1000000000ULL/(ctx->ip_hz/c->ncpu);
			fd=syscall(__NR_perf_event_open,&attr,-1,i,-1,PERF_FLAG_FD_CLOEXEC);
			cis_report(ctx,"pmu_fallback",NULL,"hardware kernel cycles unavailable: software kernel CPU-clock IP sampling, not cycles");
		}
		if(fd<0 && errno==ENODEV) continue;
		if(fd<0) goto fail;
		c->perf_fds[i]=fd;
		snprintf(detail,sizeof(detail),"cpu=%d unit=%s sample_period=%llu",i,
			attr.type==PERF_TYPE_SOFTWARE?"kernel_cpu_clock_ns":"kernel_cycles",
			(unsigned long long)attr.sample_period);
		cis_report(ctx,"ip_event",NULL,detail);
		c->perf_page_size=sysconf(_SC_PAGESIZE);
		stage="ip_perf_mmap";
		if(fault_at(ctx,stage,2)) goto fail;
		c->perf_pages[i]=mmap(NULL,2*c->perf_page_size,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
		if(c->perf_pages[i]==MAP_FAILED) { c->perf_pages[i]=NULL; goto fail; }
		stage="ip_perf_attach";
		if(fault_at(ctx,stage,2)) goto fail;
		if(ioctl(fd,PERF_EVENT_IOC_SET_BPF,prog_fd)) goto fail;
	}
	snprintf(detail,sizeof(detail),"configured_cpus=%d per_cpu_budget_hz=%u nominal_total_budget_hz=%u per_cpu_buffer_pages=%u inflight_limit=%u fixed_period_at_4GHz_bound=1 no_idle_period_shrinking=1",
		c->ncpu,ctx->ip_hz/c->ncpu,(ctx->ip_hz/c->ncpu)*c->ncpu,(unsigned int)pages,CIS_INFLIGHT);
	cis_report(ctx,"capture_ready",NULL,detail);
	cis_report(ctx,"buffer_policy",NULL,"ready_buffers_each_loop=1 ambient_full_consume_interval_ms=100 diagnostic_full_consume_each_loop=1 sampling_budget_unchanged=1");
	memory_inventory(c,pages);
	return 0;
fail:
	snprintf(detail,sizeof(detail),"stage=%s cleanup_required=1",stage);
	cis_report(ctx,"prepare_failure",NULL,detail);
	cis_capture_stop(ctx); return -EIO;
}

int cis_capture_inventory(struct cis_context *ctx,char *out,size_t cap)
{
	struct capture *c=ctx->capture;
	struct bpf_map *m;
	struct bpf_program *p;
	size_t n=0;
	unsigned int count=0;
	if(!c) return -EINVAL;
	if(cap<256) return -EOVERFLOW;
	n+=snprintf(out+n,cap-n,"{\"schema\":\"cis-loaded-inventory-v1\",\"profile\":%u,\"maps\":[",ctx->session_collector);
	bpf_object__for_each_map(m,c->object) {
		struct bpf_map_info info={0}; __u32 size=sizeof(info);
		if(!bpf_map__autocreate(m)) continue;
		if(bpf_obj_get_info_by_fd(bpf_map__fd(m),&info,&size) || cap-n<64) return -EIO;
		n+=snprintf(out+n,cap-n,"%s%u",count++?",":"",info.id);
	}
	n+=snprintf(out+n,cap-n,"],\"programs\":["); count=0;
	bpf_object__for_each_program(p,c->object) {
		struct bpf_prog_info info={0}; __u32 size=sizeof(info);
		if(!bpf_program__autoload(p)) continue;
		if(bpf_obj_get_info_by_fd(bpf_program__fd(p),&info,&size) || cap-n<64) return -EIO;
		n+=snprintf(out+n,cap-n,"%s%u",count++?",":"",info.id);
	}
	n+=snprintf(out+n,cap-n,"],\"map_names\":["); count=0;
	bpf_object__for_each_map(m,c->object) {
		if(!bpf_map__autocreate(m)) continue;
		if(cap-n<128) return -EOVERFLOW;
		n+=snprintf(out+n,cap-n,"%s\"%s\"",count++?",":"",bpf_map__name(m));
	}
	n+=snprintf(out+n,cap-n,"],\"program_names\":["); count=0;
	bpf_object__for_each_program(p,c->object) {
		if(!bpf_program__autoload(p)) continue;
		if(cap-n<128) return -EOVERFLOW;
		n+=snprintf(out+n,cap-n,"%s\"%s\"",count++?",":"",bpf_program__name(p));
	}
	n+=snprintf(out+n,cap-n,"],\"ip_perf_cpus\":%d}",c->ncpu);
	return n<cap?0:-EOVERFLOW;
}

int cis_capture_arm(struct cis_context *ctx,uint64_t start,uint64_t end)
{
	struct capture *c=ctx->capture;
	struct { __u64 session_id,start_ns,end_ns; } window={ctx->session_id,start,end};
	__u32 zero=0;
	int i;
	uint64_t first=cis_clock_ns();
	char detail[256];
	if(!c) return -EINVAL;
	if(fault_at(ctx,"window_map",1)) return -ENOMEM;
	if(ctx->session_id && bpf_map_update_elem(mapfd(c,"session_window"),&zero,&window,BPF_ANY)) return -errno;
	for(i=0;i<c->ncpu;i++) if(c->perf_fds[i]>=0 && ioctl(c->perf_fds[i],PERF_EVENT_IOC_ENABLE,0)) return -errno;
	snprintf(detail,sizeof(detail),"first_enable_ns=%llu last_enable_ns=%llu window_start_ns=%llu window_end_ns=%llu",
		(unsigned long long)first,(unsigned long long)cis_clock_ns(),(unsigned long long)start,(unsigned long long)end);
	cis_report(ctx,"armed",NULL,detail);
	return 0;
}

int cis_capture_start(struct cis_context *ctx,const char *path)
{
	int err=cis_capture_prepare(ctx,path);
	if(!err) err=cis_capture_arm(ctx,0,0);
	if(err) cis_capture_stop(ctx);
	return err;
}

static void perf_ring(struct capture *c,int cpu)
{
	struct perf_event_mmap_page *meta=c->perf_pages[cpu];
	uint64_t head,tail;
	unsigned int n=0;
	if(!meta) return;
	head=__atomic_load_n(&meta->data_head,__ATOMIC_ACQUIRE);
	tail=meta->data_tail;
	while(tail<head && n++<256) {
		struct perf_event_header h;
		unsigned char *data=(void*)((char*)meta+c->perf_page_size);
		unsigned int j;
		for(j=0;j<sizeof(h);j++) ((unsigned char*)&h)[j]=data[(tail+j)%c->perf_page_size];
		if(h.size<sizeof(h) || h.size>c->perf_page_size || tail+h.size>head) { c->perf_bad_records++; tail=head; break; }
		if(h.type==PERF_RECORD_THROTTLE) c->perf_throttle++;
		else if(h.type==PERF_RECORD_UNTHROTTLE) c->perf_unthrottle++;
		else if(h.type==PERF_RECORD_LOST && h.size>=sizeof(h)+16) {
			uint64_t lost=0;
			for(j=0;j<8;j++) ((unsigned char*)&lost)[j]=data[(tail+sizeof(h)+8+j)%c->perf_page_size];
			c->perf_lost+=lost;
		}
		tail+=h.size;
	}
	__atomic_store_n(&meta->data_tail,tail,__ATOMIC_RELEASE);
}

int cis_capture_poll(struct cis_context *ctx)
{
	struct capture *c=ctx->capture;
	uint64_t now=cis_clock_ns(),received=0;
	struct cis_bpf_stats total={0};
	__u32 zero=0;
	int i,ret;
	char detail[512];
	if(!c) return 0;
	/* Count native selection/sampling entry cost, including callers that
	 * never reach BPF. A source budget stop detaches the real producer. */
	if(c->queue_audit_ready && now-c->queue_poll_ns>=100000000ULL) {
		unsigned long long values[6];
		if(!queue_readback_valid(c) || queue_audit(values) || values[0]<c->queue_poll_entries) return -EIO;
		if((values[0]-c->queue_poll_entries)*1000000000.0/(now-c->queue_poll_ns)>ctx->entry_rate_limit) {
			snprintf(detail,sizeof(detail),"configured_limit=%u delta_entries=%llu interval_ns=%llu source=qdisc_native detaching_collectors=1",
				ctx->entry_rate_limit,values[0]-(unsigned long long)c->queue_poll_entries,
				(unsigned long long)(now-c->queue_poll_ns));
			cis_report(ctx,"entry_budget_disable",NULL,detail); return -E2BIG;
		}
		c->queue_poll_ns=now; c->queue_poll_entries=values[0];
	}
	if(c->filesystem_audit_ready && now-c->filesystem_poll_ns>=100000000ULL) {
		unsigned long long values[6];
		if(filesystem_audit(values) || values[0]<c->filesystem_poll_entries) return -EIO;
		if((values[0]-c->filesystem_poll_entries)*1000000000.0/(now-c->filesystem_poll_ns)>ctx->entry_rate_limit) {
			snprintf(detail,sizeof(detail),"configured_limit=%u delta_entries=%llu interval_ns=%llu source=filesystem_native detaching_collectors=1",
				ctx->entry_rate_limit,values[0]-(unsigned long long)c->filesystem_poll_entries,
				(unsigned long long)(now-c->filesystem_poll_ns));
			cis_report(ctx,"entry_budget_disable",NULL,detail); return -E2BIG;
		}
		c->filesystem_poll_ns=now; c->filesystem_poll_entries=values[0];
	}
	ret=perf_buffer__poll(c->ring,0);
	if(ret<0 && ret!=-EINTR) return ret;
	/* Ready buffers stay prompt; periodically drain records below the wakeup watermark. */
	if(ctx->diagnostic || now>=c->next_full_consume_ns) {
		ret=perf_buffer__consume(c->ring);
		if(ret<0 && ret!=-EINTR) return ret;
		c->next_full_consume_ns=now+100000000;
	}
	/* Spread perf reads across one second rather than sending an all-CPU burst. */
	if(now>=c->next_counter_ns) {
		unsigned int batch=(c->ncpu+9)/10,j;
		for(j=0;j<batch;j++) {
			unsigned int cpu=c->counter_cursor++%c->ncpu;
			struct { uint64_t value,enabled,running; } counter;
			if(c->perf_fds[cpu]<0) continue;
			perf_ring(c,cpu);
			if(read(c->perf_fds[cpu],&counter,sizeof(counter))!=sizeof(counter)) { ctx->errors++; continue; }
			c->counter_enabled[cpu]=counter.enabled; c->counter_running[cpu]=counter.running;
			c->counter_read_ns[cpu]=now;
		}
		c->next_counter_ns=now+100000000;
	}
	if(now-c->last_stats_ns<1000000000) return 0;
	{
		uint64_t enabled=0,running=0,max_age=0;
		unsigned int unread=0;
		for(i=0;i<c->ncpu;i++) if(c->perf_fds[i]>=0) {
			perf_ring(c,i);
			enabled+=c->counter_enabled[i]; running+=c->counter_running[i];
			if(!c->counter_read_ns[i]) unread++;
			else if(now-c->counter_read_ns[i]>max_age) max_age=now-c->counter_read_ns[i];
		}
		snprintf(detail,sizeof(detail),"enabled_ns=%llu running_ns=%llu lost=%llu throttle=%llu unthrottle=%llu invalid_records=%llu staggered=1 unread_cpus=%u max_counter_age_ns=%llu",
			(unsigned long long)enabled,(unsigned long long)running,(unsigned long long)c->perf_lost,
			(unsigned long long)c->perf_throttle,(unsigned long long)c->perf_unthrottle,(unsigned long long)c->perf_bad_records,
			unread,(unsigned long long)max_age);
		cis_report(ctx,"perf_quality",NULL,detail);
	}
	if(bpf_map_lookup_elem(c->stats,&zero,c->cpu_stats)) return -EIO;
	for(i=0;i<c->possible_cpus;i++) {
		struct cis_bpf_stats *s=&c->cpu_stats[i];
		total.received+=s->received; total.emitted+=s->emitted; total.lost+=s->lost;
		total.unknown+=s->unknown; total.overdepth+=s->overdepth; total.unmatched+=s->unmatched;
		total.nested+=s->nested; total.rejected+=s->rejected; total.expired+=s->expired;
		total.phase_changes+=s->phase_changes;
		total.irq_context+=s->irq_context;
		total.owner_skipped+=s->owner_skipped;
	}
	received=total.received;
	snprintf(detail,sizeof(detail),"received=%llu emitted=%llu lost=%llu unknown=%llu overdepth=%llu unmatched=%llu nested=%llu rejected=%llu expired=%llu phase_changes=%llu irq_context=%llu",
		(unsigned long long)total.received,(unsigned long long)total.emitted,(unsigned long long)total.lost,
		(unsigned long long)total.unknown,(unsigned long long)total.overdepth,(unsigned long long)total.unmatched,
		(unsigned long long)total.nested,(unsigned long long)total.rejected,(unsigned long long)total.expired,(unsigned long long)total.phase_changes,(unsigned long long)total.irq_context);
	cis_report(ctx,"coverage",NULL,detail);
	if(total.owner_skipped) {
		snprintf(detail,sizeof(detail),"skipped=%llu scope=collector_lifetime incomplete_owner_evidence=1",(unsigned long long)total.owner_skipped);
		cis_report(ctx,"owner_gap",NULL,detail);
	}
	if(c->last_stats_ns && (received-c->last_received)*1000000000.0/(now-c->last_stats_ns)>ctx->entry_rate_limit) {
		snprintf(detail,sizeof(detail),"configured_limit=%u delta_entries=%llu interval_ns=%llu detaching_collectors=1",
			ctx->entry_rate_limit,(unsigned long long)(received-c->last_received),(unsigned long long)(now-c->last_stats_ns));
		cis_report(ctx,"entry_budget_disable",NULL,detail); return -E2BIG;
	}
	c->last_stats_ns=now; c->last_received=received;
	return 0;
}

int cis_capture_fd(struct cis_context *ctx)
{
	struct capture *c=ctx->capture;
	return c && ctx->diagnostic?perf_buffer__epoll_fd(c->ring):-1;
}

static void terminal_program_audit(struct capture *c)
{
	struct bpf_program *program;
	struct cis_context *ctx = c->ctx;
	unsigned int missing = 0;
	char detail[256];
	if (!c->object)
		return;
	bpf_object__for_each_program(program, c->object) {
		struct cis_prog_recursion_info info = {0};
		__u32 size = sizeof(info);
		int valid;
		if (!bpf_program__autoload(program))
			continue;
		ctx->program_audit_count++;
		valid = !bpf_obj_get_info_by_fd(bpf_program__fd(program), &info, &size) &&
			size >= sizeof(info);
		if (!valid)
			missing++;
		else
			ctx->program_recursion_misses += info.recursion_misses;
		snprintf(detail, sizeof(detail), "program=%s id=%u valid=%d recursion_misses=%llu fresh_object=1 producers_detached=%d",
			bpf_program__name(program), info.id, valid,
			(unsigned long long)info.recursion_misses, c->quiesced);
		cis_report(ctx, "terminal_program", NULL, detail);
	}
	ctx->program_audit_valid = !missing && ctx->program_audit_count > 0;
	if (ctx->session_id && ctx->session_collector >= 2 &&
	    (!ctx->program_audit_valid || ctx->program_recursion_misses))
		ctx->errors++;
}

static void export_counter_sums(struct capture *c)
{
	struct cis_context *ctx=c->ctx;
	struct cis_counter_sum *cpus;
	struct cis_root *actors[2]={0};
	unsigned int n=0,obj,actor,op;
	int i,j,fd;
	char detail[1180];
	if(ctx->session_collector!=7 || !ctx->selected_object_count || !c->quiesced) return;
	fd=mapfd(c,"counter_sums");
	if(fd<0 || c->possible_cpus<1) return;
	cpus=calloc(c->possible_cpus,sizeof(*cpus));
	if(!cpus) {ctx->errors++; return;}
	for(i=0;i<CIS_MAX_ROOTS;i++) if(ctx->roots[i].used && ctx->roots[i].session_target && n<2) actors[n++]=&ctx->roots[i];
	for(obj=0;obj<ctx->selected_object_count;obj++) for(actor=0;actor<n;actor++) for(op=0;op<6;op++) {
		__u32 key=(obj*2+actor)*6+op;
		struct cis_counter_sum total={0};
		if(bpf_map_lookup_elem(fd,&key,cpus)) {ctx->errors++; continue;}
		for(i=0;i<c->possible_cpus;i++) {
			struct cis_counter_sum *v=&cpus[i];
			if(!v->first_ns) continue;
			if(!total.first_ns) {total.generation=v->generation;total.shift=v->shift;total.min_depth=v->min_depth;}
			if(total.generation!=v->generation || total.shift!=v->shift) total.tainted=1;
			total.tainted|=v->tainted;
			if(!total.first_ns || v->first_ns<total.first_ns) total.first_ns=v->first_ns;
			if(v->last_ns>total.last_ns) total.last_ns=v->last_ns;
			if(v->min_depth<total.min_depth) total.min_depth=v->min_depth;
			if(v->max_depth>total.max_depth) total.max_depth=v->max_depth;
			for(j=0;j<7;j++) {
				if(~total.counts[j]<v->counts[j] || ~total.pages[j]<v->pages[j]) total.tainted=1;
				else {total.counts[j]+=v->counts[j];total.pages[j]+=v->pages[j];}
			}
			for(j=0;j<8;j++) total.offset_hist[j]+=v->offset_hist[j];
		}
		if(!total.first_ns) continue;
		snprintf(detail,sizeof(detail),"protocol=1 object=0x%llx object_generation=%llu operation=%u first_ns=%llu last_ns=%llu sample_shift=%u tainted=%u min_depth=%u max_depth=%u producers_detached=1",
			(unsigned long long)ctx->selected_objects[obj],(unsigned long long)total.generation,op+1,
			(unsigned long long)total.first_ns,(unsigned long long)total.last_ns,total.shift,total.tainted,total.min_depth,total.max_depth);
		for(j=0;j<7;j++) {
			size_t len=strlen(detail);
			snprintf(detail+len,sizeof(detail)-len," n%d=%llu q%d=%llu",j+2,(unsigned long long)total.counts[j],j+2,(unsigned long long)total.pages[j]);
		}
		for(j=0;j<8;j++) {
			size_t len=strlen(detail);
			snprintf(detail+len,sizeof(detail)-len," h%d=%llu",j,(unsigned long long)total.offset_hist[j]);
		}
		cis_report(ctx,"counter_sum",actors[actor],detail);
	}
	snprintf(detail,sizeof(detail),"objects=%u targets=%u buckets=%u possible_cpus=%d value_bytes=%zu producers_detached=1",
		ctx->selected_object_count,n,ctx->selected_object_count*12,c->possible_cpus,sizeof(*cpus));
	cis_report(ctx,"counter_sum_audit",NULL,detail);
	free(cpus);
}

void cis_capture_stop(struct cis_context *ctx)
{
	struct capture *c=ctx->capture;
	int i;
	if(!c) return;
	cis_capture_quiesce(ctx);
	if(ctx->session_id) for(i=0;i<c->ncpu;i++) if(c->perf_fds[i]>=0) {
		struct { uint64_t value,enabled,running; } counter;
		char detail[256];
		perf_ring(c,i);
		if(read(c->perf_fds[i],&counter,sizeof(counter))!=sizeof(counter)) { ctx->errors++; continue; }
		snprintf(detail,sizeof(detail),"cpu=%d value=%llu enabled_ns=%llu running_ns=%llu producers_disabled=1",
			i,(unsigned long long)counter.value,(unsigned long long)counter.enabled,(unsigned long long)counter.running);
		cis_report(ctx,"terminal_perf",NULL,detail);
	}
	if(c->ring) perf_buffer__consume(c->ring);
	terminal_program_audit(c);
	export_counter_sums(c);
	/* Keep immutable identities and watches until buffered records are interpreted. */
	if(ctx->session_id && ctx->session_collector!=1 && c->object) for(i=0;i<CIS_MAX_ROOTS;i++) if(ctx->roots[i].used) {
		struct cis_root *r=&ctx->roots[i];
		if(!r->session_target) continue;
		if(c->pending>=0) unfinished(c,r);
		if(mapfd(c,"work_items")>=0) unfinished_work(c,r);
		if(c->stacks>=0) export_stacks(c,r);
		if(mapfd(c,"watched")>=0) clear_watches(c,r);
		bpf_map_delete_elem(c->targets,&r->id);
	}
	if(c->cpu_stats) {
		__u32 zero=0;
		__u64 lost_count=0,skipped=0;
		if(!bpf_map_lookup_elem(c->stats,&zero,c->cpu_stats)) {
			char detail[256];
			__u64 received=0,emitted=0,rejected=0;
			__u64 owner_entries=0,sched_entries=0,target_waits=0,watch_events=0;
			__u64 watch_races=0,watch_failed=0,holder_failed=0,attempt_failed=0;
			__u64 unknown=0,overdepth=0,unmatched=0,nested=0,expired=0,irq_context=0;
			for(i=0;i<c->possible_cpus;i++) {lost_count+=c->cpu_stats[i].lost;skipped+=c->cpu_stats[i].owner_skipped;}
			snprintf(detail,sizeof(detail),"lost=%llu owner_skipped=%llu",(unsigned long long)lost_count,(unsigned long long)skipped);
			cis_report(ctx,"terminal_coverage",NULL,detail);
			for(i=0;i<c->possible_cpus;i++) {received+=c->cpu_stats[i].received;emitted+=c->cpu_stats[i].emitted;rejected+=c->cpu_stats[i].rejected;}
			snprintf(detail,sizeof(detail),"received=%llu emitted=%llu rejected=%llu",(unsigned long long)received,(unsigned long long)emitted,(unsigned long long)rejected);
			cis_report(ctx,"terminal_counters",NULL,detail);
			for(i=0;i<c->possible_cpus;i++) {
				unknown+=c->cpu_stats[i].unknown;
				overdepth+=c->cpu_stats[i].overdepth;
				unmatched+=c->cpu_stats[i].unmatched;
				nested+=c->cpu_stats[i].nested;
				expired+=c->cpu_stats[i].expired;
				irq_context+=c->cpu_stats[i].irq_context;
			}
			snprintf(detail,sizeof(detail),"unknown=%llu overdepth=%llu unmatched=%llu nested=%llu expired=%llu irq_context=%llu counters_overlap=1",
				(unsigned long long)unknown,(unsigned long long)overdepth,
				(unsigned long long)unmatched,(unsigned long long)nested,
				(unsigned long long)expired,(unsigned long long)irq_context);
			cis_report(ctx,"terminal_scope",NULL,detail);
			for(i=0;i<c->possible_cpus;i++) {
				owner_entries+=c->cpu_stats[i].owner_entries;
				sched_entries+=c->cpu_stats[i].owner_sched_entries;
				target_waits+=c->cpu_stats[i].owner_target_waits;
				watch_events+=c->cpu_stats[i].owner_watch_events;
				watch_races+=c->cpu_stats[i].owner_watch_races;
				watch_failed+=c->cpu_stats[i].owner_watch_failed;
				holder_failed+=c->cpu_stats[i].owner_holder_failed;
				attempt_failed+=c->cpu_stats[i].owner_attempt_failed;
			}
			snprintf(detail,sizeof(detail),"owner_entries=%llu sched_entries=%llu target_waits=%llu watch_events=%llu counters_overlap=1",
				(unsigned long long)owner_entries,(unsigned long long)sched_entries,
				(unsigned long long)target_waits,(unsigned long long)watch_events);
			cis_report(ctx,"owner_entry_stages",NULL,detail);
			snprintf(detail,sizeof(detail),"watch_races=%llu watch_failed=%llu holder_failed=%llu attempt_failed=%llu",
				(unsigned long long)watch_races,(unsigned long long)watch_failed,
				(unsigned long long)holder_failed,(unsigned long long)attempt_failed);
			cis_report(ctx,"owner_map_updates",NULL,detail);
			ctx->terminal_valid=1;
			ctx->terminal_received=received; ctx->terminal_emitted=emitted;
			ctx->terminal_rejected=rejected; ctx->terminal_lost=lost_count;
			ctx->terminal_owner_skipped=skipped;
			if(ctx->session_id && (lost_count || skipped || rejected)) ctx->errors++;
		}
		else if(ctx->session_id) ctx->errors++;
	}
	for(i=0;i<CIS_CPU_CAP;i++) if(c->perf_fds[i]>=0) {
		if(c->perf_pages[i]) munmap(c->perf_pages[i],2*c->perf_page_size);
		close(c->perf_fds[i]);
	}
	perf_buffer__free(c->ring); bpf_object__close(c->object); free(c->cpu_stats); free(c);
	ctx->capture=NULL; ctx->diagnostic=0;
	for(i=0;i<CIS_MAX_ROOTS;i++) if(ctx->roots[i].used && ctx->roots[i].state==CIS_DIAGNOSING) {
		ctx->roots[i].state=CIS_COOLDOWN; ctx->roots[i].last_diag_ns=cis_clock_ns();
	}
}

int cis_capture_quiesce(struct cis_context *ctx)
{
	struct capture *c=ctx->capture;
	int i;
	if(!c) return 0;
	if(c->quiesced) return c->stop_error;
	for(i=0;i<c->ncpu;i++) if(c->perf_fds[i]>=0 && ioctl(c->perf_fds[i],PERF_EVENT_IOC_DISABLE,0)) c->stop_error=-errno;
	for(i=0;i<CIS_DIAGNOSTIC_LINKS;i++) if(c->diagnostic_links[i]) {
		int ret=bpf_link__destroy(c->diagnostic_links[i]);
		if(ret) c->stop_error=ret;
		c->diagnostic_links[i]=NULL;
	}
	if(ctx->session_collector==17 && c->object && c->possible_cpus>0) {
		int fd=mapfd(c,"cpu_irq_totals");
		__u32 zero=0;
		struct cis_cpu_irq_state *all=calloc(c->possible_cpus,sizeof(*all));
		if(fd<0 || !all || bpf_map_lookup_elem(fd,&zero,all)) c->stop_error=-EIO;
		else for(i=0;i<(int)ctx->selected_cpu_count;i++) {
			unsigned int cpu=ctx->selected_cpus[i];
			char detail[256];
			struct cis_cpu_irq_state *s;
			if(cpu>=(unsigned int)c->possible_cpus) { c->stop_error=-EIO; break; }
			s=&all[cpu];
			snprintf(detail,sizeof(detail),"protocol=2 cpu=%u total_ns=%llu entries=%llu errors=%llu depth=%u sequence=%llu detached=1",
				cpu,(unsigned long long)s->total_ns,(unsigned long long)s->entries,
				(unsigned long long)s->errors,s->depth,(unsigned long long)s->sequence);
			cis_report(ctx,"cpu_irq_audit",NULL,detail);
		}
		free(all);
	}
	if(c->rwsem_filter_fd>=0) {
		if(close(c->rwsem_filter_fd)) c->stop_error=-errno;
		c->rwsem_filter_fd=-1;
		cis_report(ctx,"rwsem_source_filter_closed",NULL,"lease=0 close_after_detach=1");
	}
	if(c->backend_filter_fd>=0) {
		if(close(c->backend_filter_fd)) c->stop_error=-errno;
		c->backend_filter_fd=-1;
		cis_report(ctx,"backend_source_filter_closed",NULL,"lease=0 close_after_detach=1");
	}
	if(c->queue_filter_fd>=0) {
		int valid=queue_readback_valid(c);
		cis_report(ctx,"queue_source_terminal",NULL,valid?"valid=1 unchanged=1":"valid=0 unchanged=0");
		if(!valid) c->stop_error=-EIO;
		if(close(c->queue_filter_fd)) c->stop_error=-errno;
		c->queue_filter_fd=-1;
		cis_report(ctx,"queue_source_filter_closed",NULL,"lease=0 close_after_detach=1");
	}
	if(c->queue_audit_ready) {
		unsigned long long values[6];
		char detail[384];
		int i,valid=!queue_audit(values);
		for(i=0;i<6 && valid;i++) if(values[i]<c->queue_before[i]) valid=0;
		if(valid) {
			for(i=0;i<6;i++) values[i]-=c->queue_before[i];
			snprintf(detail,sizeof(detail),"valid=1 entries=%llu filtered=%llu sampled=%llu emitted=%llu expired=%llu recursive=%llu endpoint_snapshot=1 unfinished_unknown=1",
				values[0],values[1],values[2],values[3],values[4],values[5]);
			cis_report(ctx,"queue_native_audit",NULL,detail);
			if(values[5]) c->stop_error=-EIO;
		} else c->stop_error=-EIO;
	}
	if(c->filesystem_filter_fd>=0) {
		if(close(c->filesystem_filter_fd)) c->stop_error=-errno;
		c->filesystem_filter_fd=-1;
		cis_report(ctx,"filesystem_source_filter_closed",NULL,"lease=0 close_after_detach=1");
	}
	if(c->filesystem_audit_ready) {
		unsigned long long values[6];
		char detail[384];
		int valid=!filesystem_audit(values);
		for(i=0;i<6 && valid;i++) if(values[i]<c->filesystem_before[i]) valid=0;
		if(valid) {
			for(i=0;i<6;i++) values[i]-=c->filesystem_before[i];
			snprintf(detail,sizeof(detail),"valid=1 entries=%llu filtered=%llu sampled=%llu emitted=%llu expired=%llu recursive=%llu endpoint_snapshot=1 unfinished_unknown=1",
				values[0],values[1],values[2],values[3],values[4],values[5]);
			cis_report(ctx,"filesystem_native_audit",NULL,detail);
			if(values[5]) c->stop_error=-EIO;
		} else c->stop_error=-EIO;
	}
	if(ctx->session_collector==15 && ctx->filesystem_fd>=0) {
		if(close(ctx->filesystem_fd)) c->stop_error=-errno;
		ctx->filesystem_fd=-1;
	}
	c->quiesced=1;
	return c->stop_error;
}
