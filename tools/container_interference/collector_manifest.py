# SPDX-License-Identifier: GPL-2.0
"""Versioned bounded collector contract, checked before ARM acknowledgement.

This is a loading/interpretation contract, not a coverage or performance receipt.
Historical sessions without this contract remain readable by their old readers.
"""
from copy import deepcopy
import hashlib
from pathlib import Path

from periodic_plan import digest

SCHEMA = 'cis-collector-v1'
COMMON_MAPS = ['session_window', 'roots', 'events', 'stats']
COLLECTORS = {
    'ip': dict(profile=1, programs=['sample_ip'], maps=COMMON_MAPS,
               relation='sampled_execution', clock='sample_period', contexts=['task_or_interrupt_unknown'],
               object_kinds=[], source_filter='registered cgroup ancestors; executor is not async owner'),
    'owner': dict(profile=2, programs=['owner_state', 'owner_switch'],
                  maps=COMMON_MAPS + ['targets', 'stacks', 'watched', 'holders', 'holder_tasks', 'owner_attempts'],
                  relation='holder_waiter', clock='monotonic_wall_ns', contexts=['synchronous_task'],
                  object_kinds=['mutex', 'lockref'],
                  source_filter='cis_lock_state only; target opens watch; lockref prefix 64 events; FD static key stays disabled'),
    'fd': dict(profile=6, programs=['owner_state', 'owner_switch'],
               maps=COMMON_MAPS + ['targets', 'stacks', 'watched', 'holders', 'holder_tasks', 'owner_attempts'],
               relation='holder_waiter', clock='monotonic_wall_ns', contexts=['synchronous_task'],
               object_kinds=['files_struct_lock_requires_CONFIG_CIS_OBSERVE_FD'],
               source_filter='cis_fdlock_state only; target opens prefix-64 watch; mutex/lockref static key stays disabled'),
    'slub': dict(profile=12, programs=['owner_state', 'owner_switch'],
                 maps=COMMON_MAPS + ['targets', 'stacks', 'watched', 'holders', 'holder_tasks', 'owner_attempts'],
                 relation='holder_waiter', clock='monotonic_wall_ns', contexts=['synchronous_non_rt_task'],
                 object_kinds=['kmem_cache_node_list_lock'],
                 source_filter='cis_slublock_state only; exact boot-selected cache; target opens prefix-64 watch; node reset/retire boundaries; observed inner hold overlap, not pure spin time; IRQ and unobserved holders unknown'),
    'sched': dict(profile=3, programs=['sched_wait'], maps=COMMON_MAPS + ['targets'],
                  relation='scheduler_wait', clock='monotonic_wall_ns', contexts=['event_task'],
                  object_kinds=[], source_filter='event task cgroup, not current'),
    'reclaim': dict(profile=4, programs=['reclaim_begin', 'reclaim_end', 'memcg_begin', 'memcg_end'],
                    maps=COMMON_MAPS + ['targets', 'stacks', 'pending'], relation='reclaim_interval',
                    clock='monotonic_wall_ns', contexts=['synchronous_task'], object_kinds=[],
                    source_filter='target begin, original identity retained to end'),
    'sync': dict(profile=5, programs=['lock_begin', 'lock_end'],
                 maps=COMMON_MAPS + ['targets', 'stacks', 'pending'], relation='lock_wait_candidates',
                 clock='monotonic_wall_ns', contexts=['synchronous_task'], object_kinds=['untyped_lock_address'],
                 source_filter='existing contention pairs; partial slowpath coverage, holder/lifetime unknown'),
    'counter': dict(profile=7, programs=['counter_step'],
                    maps=COMMON_MAPS + ['targets', 'stacks', 'pending', 'counter_selected', 'counter_actors', 'counter_sums'], relation='counter_updates',
                    clock='monotonic_wall_ns', contexts=['synchronous_task'],
                    object_kinds=['page_counter_usage', 'children_min_usage', 'children_low_usage'],
                    source_filter='independent sampled calls with first 64 steps; actual traversal, no synthetic ancestor walk; protocol 2 native init generation, legacy or zero generation unknown'),
    'allocator': dict(profile=8, programs=['alloc_step','alloc_release'],
                    maps=COMMON_MAPS + ['targets', 'stacks', 'pending','alloc_live'], relation='allocation_stages',
                    clock='monotonic_wall_ns', contexts=['synchronous_allocation','release_task_or_irq_executor_separate'],
                    object_kinds=['kmem_cache_address', 'kmem_cache_node_list_lock_address', 'sampled_allocation'],
                    source_filter='one exact boot-selected cache; per-CPU allocation sampling and first 64 stages; tracked releases before reuse, bounded 1024 live objects, free batch cap rejects lifetime evidence; no inferred holder or cache lifetime'),
    'net': dict(profile=9, programs=['net_state','net_release'],
                maps=COMMON_MAPS+['targets','stacks','net_watched','net_skb','net_service'],
                relation='socket_ownership_and_backlog',clock='monotonic_wall_ns',
                contexts=['task_actor','irq_executor_unknown'],
                object_kinds=['native_tcp_socket_cookie','observed_backlog_skb_episode'],
                source_filter='boot-frozen native cookie selection; target opens 64 socket watches from use, post-create or accept; 256 skb and service records; creator/acceptor distinct from transferred user; release entry not completion; packet origin and unobserved holders unknown'),
    'block': dict(profile=10,programs=['block_start','block_insert','block_issue','block_requeue','block_complete','block_merge','block_remap'],
                  maps=COMMON_MAPS+['targets','stacks','block_watched'],relation='block_request_episodes',
                  clock='monotonic_wall_ns',contexts=['submission_task','completion_executor_separate'],
                  object_kinds=['observed_blk_mq_request_episode','queue_and_device'],
                  source_filter='native block_io_start opens 256 bounded watches; all registered target starts, no inference from bare request address; partial completion, merge and remap explicit; no unique blocking tenant claim'),
    'rwsem': dict(profile=11, programs=['rwsem_state'], maps=COMMON_MAPS+['targets','stacks','rwsem_watched','rwsem_selected'],
                  relation='rwsem_observed_holders', clock='monotonic_wall_ns', contexts=['synchronous_non_rt_task'],
                  object_kinds=['rw_semaphore_observed_initialization'],
                  source_filter='manual 1..8 administrator-selected addresses; BPF comparison before watch, identity and stack, source callback entry still paid; target init/attempt opens watches, 1024 events/object; observed init required for E2; eight-reader analysis; pre-window and non-owner use unknown'),
}


LEGACY_BLOCK = deepcopy(COLLECTORS['block'])
LEGACY_COUNTER = deepcopy(COLLECTORS['counter'])
COLLECTORS['counter']['source_filter'] += '; protocol 3 optional immutable native owning cgroup and memory/swap/kmem/tcpmem kind; absent bindings remain unknown, no inferred holder or cache-line latency'
LEGACY_FD = deepcopy(COLLECTORS['fd'])
COLLECTORS['fd']['source_filter'] = 'cis_fdlock_state only; target opens prefix-128 watch; mutex/lockref static key stays disabled; prefix omissions retained in full-call population, not complete window coverage'
LEGACY_ALLOCATOR = deepcopy(COLLECTORS['allocator'])
LEGACY_NET = deepcopy(COLLECTORS['net'])
LEGACY_NET_USE_ONLY = deepcopy(LEGACY_NET)
LEGACY_NET_USE_ONLY['source_filter'] = 'boot-frozen native cookie selection; target opens 64 socket watches; 256 skb and service records; release entry not completion; packet origin and unobserved holders unknown'
COLLECTORS['net']['programs'].append('net_tx')
COLLECTORS['net']['maps'] += ['net_tx_live', 'net_tx_pending']
COLLECTORS['net']['source_filter'] += '; protocol 2 entry-frozen TCP send requester and 256 original skb-header lifetimes; fclone backend clock after identity callback, memory admission and release executor separate; no packet payload origin, clone lineage or allocator lock holder inference'
LEGACY_NET_TX = deepcopy(COLLECTORS['net'])
COLLECTORS['net']['source_filter'] += '; TCP send allocation begins are process-context only; IRQ-only entries separately counted as outside scope; true recursion and admitted-lifetime gaps still reject quality'
LEGACY_NET_PROCESS = deepcopy(COLLECTORS['net'])
COLLECTORS['net']['maps'].append('net_tx_free')
COLLECTORS['net']['source_filter'] += '; protocol 3 bounded original-header __kfree_skb backend-return tokens; shared data and fclone retention explicit; bulk/NAPI/morph entry alone never implies backend completion'
COLLECTORS['allocator']['programs'].append('maple_context')
COLLECTORS['allocator']['maps'].append('maple_pending')
COLLECTORS['allocator']['source_filter'] += '; 256 task-start keyed Maple allocation brackets join sampled backend calls to destination tree addresses; no lifetime across brackets or inferred tree owner'
COLLECTORS['alloc_backend'] = deepcopy(LEGACY_ALLOCATOR)
COLLECTORS['alloc_backend']['profile'] = 13
COLLECTORS['alloc_backend']['source_filter'] += '; independent backend-only bundle; no Maple context program, map or source activation'
LEGACY_RWSEM = deepcopy(COLLECTORS['rwsem'])
COLLECTORS['rwsem']['source_filter'] = 'manual 1..8 administrator-selected addresses; exclusive immutable kernel filter lease before BPF; all actors on selected objects remain visible; target init/attempt opens watches, 1024 events/object; observed init required for E2; eight-reader analysis; pre-window and non-owner use unknown'
COLLECTORS['block']['programs'].append('block_tag')
COLLECTORS['block']['maps'].append('tag_pending')
COLLECTORS['block']['source_filter'] += '; 256 task-start keyed tag-wait episodes before request creation; no inferred tag holder'
LEGACY_TAG_BLOCK = deepcopy(COLLECTORS['block'])
COLLECTORS['block']['programs'].append('block_link')
COLLECTORS['block']['source_filter'] += '; successful native merge links before transfer; issue-time snapshot of at most eight bios with blkcg byte weights, remainder unknown, never inferred blockers'
LEGACY_MERGE_BLOCK = deepcopy(COLLECTORS['block'])
COLLECTORS['block']['source_filter'] += '; protocol 3 also admits selected bio billing roots, independently retaining real submitter and unknown dirtier/inode owner'
LEGACY_BILLING_BLOCK = deepcopy(COLLECTORS['block'])
COLLECTORS['block']['programs'] += ['wb_dirty','wb_begin','wb_end']
COLLECTORS['block']['maps'].append('wb_pending')
COLLECTORS['block']['source_filter'] += '; native folio dirty observations and 256 task-start keyed inode writeback contexts; closed synchronous contexts link request submission, not exclusive dirtying ownership or a causal blocker'
LEGACY_WRITEBACK_BLOCK = deepcopy(COLLECTORS['block'])
COLLECTORS['block']['programs'].append('wb_pause')
COLLECTORS['block']['source_filter'] += '; at most two issue-time driver/scheduler tag pool snapshots, not tag lifetimes; native dirty pause brackets retain accounting and executor separately; same-pool wait overlap is an association, never an exclusive blocker'

LEGACY_BACKEND_SELECTION = {name:deepcopy(COLLECTORS[name]) for name in ('allocator','alloc_backend','slub')}
for _name in LEGACY_BACKEND_SELECTION:
    COLLECTORS[_name]['source_filter'] += '; Y2 kernel requires immutable administrative cache lease; optional up-to-eight SLUB lock nodes, allocation/release lifetimes retain all nodes; older kernels accept boot default only, never explicit session override'

COLLECTORS['page_backend']=dict(profile=14,programs=['page_backend'],maps=COMMON_MAPS+['targets','stacks'],
    relation='page_zone_operation',clock='monotonic_wall_ns',contexts=['synchronous_task_completion'],
    object_kinds=['selected_numa_zone'],
    source_filter='immutable page_zone node lease; per-CPU sampled PCP refill/drain and buddy allocate/free brackets; timestamps inside native zone lock, one callback after unlock; no page lifetime tracking, inferred holder or pure spin time; preemption/IRQ and unobserved zone operations remain outside causal coverage')


COLLECTORS['filesystem']=dict(profile=15,programs=['filesystem'],maps=COMMON_MAPS+['targets','stacks'],
    relation='selected_filesystem_public_operations',clock='monotonic_wall_ns',contexts=['synchronous_task_completion'],
    object_kinds=['pinned_ext4_filesystem','journal_transaction','allocation_group','legacy_orphan_mutex','orphan_file'],
    source_filter='exclusive pinned directory lease; one ext4 device; native JBD2 commit/switch brackets and 1/16 ext4 allocation/orphan samples; no private inode lock tracing; group use is not lock contention, journal waits do not identify a unique blocking tenant; endpoints require same registered cgroup')


COLLECTORS['qdisc']=dict(profile=16,programs=['qdisc_state'],maps=COMMON_MAPS+['targets'],
    relation='selected_public_queue_samples',clock='monotonic_wall_ns',
    contexts=['process_actor','socket_accounting','irq_or_unresolved_unknown'],
    object_kinds=['pinned_netns_device_txq_qdisc_epoch'],
    source_filter='exclusive host-netns device transmit-queue lease; native 1/16 per-CPU admission brackets and first-head service points; no socket watch or packet lifetime map; exact socket billing root only, descendant billing unknown; occupancy snapshots are not blockers or wire completion; qdisc configuration frozen for lease')


def contract(name, legacy_block=False, legacy_rwsem=False):
    if name not in COLLECTORS:
        raise ValueError('unsupported collector')
    value = deepcopy(LEGACY_BLOCK if legacy_block and name=='block' else
                     LEGACY_RWSEM if legacy_rwsem and name=='rwsem' else COLLECTORS[name])
    value.update(schema=SCHEMA, name=name, event_abi=1, bundle=name+'.bpf.o',
                 configuration='fixed OLK ARM64 non-RT; runtime capability check required',
                 limits=dict(window_ms=2000, targets=2, registered_roots=4,
                             entry_rate_per_s=200000, output_bytes=16 << 20,
                             memory_policy_bytes=64 << 20, total_memory_proven=False),
                 stop_protocol=['disable producers', 'quiesce callbacks', 'drain records',
                                'read terminal counters', 'destroy maps/programs', 'verify absent'],
                 audit=['entries', 'filter_rejections', 'lost', 'unknown_identity',
                        'unmatched', 'nested', 'window_truncation', 'object_reuse', 'capacity'],
                 unsupported='unreported counters are unknown, not zero; no automatic causal claim')
    return value


def bundle_manifest(bpf_path):
    return dict(schema='cis-collector-bundle-v1',
                objects={name+'.bpf.o': hashlib.sha256(object_path(bpf_path,name).read_bytes()).hexdigest()
                         for name in COLLECTORS},
                collectors={name: contract(name) for name in COLLECTORS})


def object_path(anchor, name):
    return Path(anchor).parent / contract(name)['bundle']


def validate_inventory(name, inventory):
    expected = contract(name)
    return _validate_inventory(expected,inventory)


def validate_record_inventory(record):
    """Historical reads only; live admission always requires the current maps."""
    name=record['collector']; expected=contract(name); inventory=record.get('inventory')
    if name in LEGACY_BACKEND_SELECTION and record.get('collector_contract_sha256') not in (None,digest(expected)):
        candidate=contract(name); candidate.update(deepcopy(LEGACY_BACKEND_SELECTION[name]))
        if record['collector_contract_sha256']==digest(candidate): expected=candidate
    if name=='counter' and record.get('collector_contract_sha256') not in (None,digest(expected)):
        candidate=contract(name); candidate.update(deepcopy(LEGACY_COUNTER))
        legacy_maps=COMMON_MAPS+['targets','stacks','pending']
        if isinstance(inventory,dict) and set(inventory.get('map_names',[]))==set(legacy_maps):
            candidate['maps']=legacy_maps
        if record['collector_contract_sha256']!=digest(candidate):
            raise ValueError('unproven historical counter contract')
        expected=candidate
    if name=='fd' and record.get('collector_contract_sha256') not in (None,digest(expected)):
        candidate=contract(name); candidate.update(deepcopy(LEGACY_FD))
        if record['collector_contract_sha256']!=digest(candidate):
            raise ValueError('unproven historical FD contract')
        expected=candidate
    if name=='net' and record.get('collector_contract_sha256')!=digest(expected) and record.get('collector_contract_sha256') is not None:
        for historical in (LEGACY_NET_PROCESS,LEGACY_NET_TX,LEGACY_NET,LEGACY_NET_USE_ONLY):
            candidate=contract(name)
            for key,value in historical.items(): candidate[key]=deepcopy(value)
            if record.get('collector_contract_sha256')==digest(candidate):
                expected=candidate; break
        else: raise ValueError('unproven historical network contract')
    if name=='allocator' and isinstance(inventory,dict) and 'maple_context' not in inventory.get('program_names',[]):
        for key,value in LEGACY_ALLOCATOR.items(): expected[key]=deepcopy(value)
        if record.get('collector_contract_sha256')!=digest(expected):
            raise ValueError('unproven historical allocator contract')
    if name=='rwsem' and record.get('collector_contract_sha256')==digest(contract(name,legacy_rwsem=True)):
        expected=contract(name,legacy_rwsem=True)
    if name=='block' and isinstance(inventory,dict) and 'tag_pending' not in inventory.get('map_names',[]):
        expected=contract(name,legacy_block=True)
        if record.get('collector_contract_sha256')!=digest(expected):
            raise ValueError('unproven historical block contract')
    elif name=='block' and isinstance(inventory,dict) and 'block_link' not in inventory.get('program_names',[]):
        expected=contract(name)
        for key,value in LEGACY_TAG_BLOCK.items(): expected[key]=deepcopy(value)
        if record.get('collector_contract_sha256')!=digest(expected):
            raise ValueError('unproven historical tag block contract')
    elif name=='block' and record.get('collector_contract_sha256')!=digest(expected):
        for historical in (LEGACY_MERGE_BLOCK,LEGACY_BILLING_BLOCK,LEGACY_WRITEBACK_BLOCK):
            candidate=contract(name)
            for key,value in historical.items(): candidate[key]=deepcopy(value)
            if record.get('collector_contract_sha256')==digest(candidate):
                expected=candidate; break
        else: raise ValueError('unproven historical merge/billing block contract')
    legacy=COMMON_MAPS+['targets','stacks','pending']
    if (name=='counter' and isinstance(inventory,dict) and set(inventory.get('map_names',[]))==set(legacy)):
        expected['maps']=legacy
        if record.get('selected_objects') or record.get('collector_contract_sha256')!=digest(expected):
            raise ValueError('unproven historical counter contract')
    return _validate_inventory(expected,inventory)


def _validate_inventory(expected, inventory):
    if not isinstance(inventory, dict) or inventory.get('schema') != 'cis-loaded-inventory-v1':
        raise ValueError('versioned loaded inventory required')
    if inventory.get('profile') != expected['profile']:
        raise ValueError('collector profile mismatch')
    for kind in ('maps', 'programs'):
        names, ids = inventory.get(kind[:-1] + '_names'), inventory.get(kind)
        if (not isinstance(names, list) or not all(isinstance(x, str) for x in names)
                or len(names) != len(set(names)) or set(names) != set(expected[kind])
                or not isinstance(ids, list) or len(ids) != len(names)
                or any(type(x) is not int or x <= 0 for x in ids) or len(ids) != len(set(ids))):
            raise ValueError('unexpected loaded ' + kind)
    cpus = inventory.get('ip_perf_cpus')
    if type(cpus) is not int or not 0 <= cpus <= 512 or (cpus > 0) != (expected['name'] == 'ip'):
        raise ValueError('unexpected PMU collector activity')
    return digest(expected)
