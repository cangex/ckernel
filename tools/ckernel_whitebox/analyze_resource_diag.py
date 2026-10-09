"""Bounded trace interpretation; no holder inference or elapsed-time attribution."""
import argparse
from collections import Counter, defaultdict
from decimal import Decimal
import json
from pathlib import Path
import re

LINE=re.compile(r'^\s*.+-(\d+)\s+(?:\(.*?\)\s+)?\[(\d+)\]\s+(\S+)\s+(\d+\.\d+):\s+(\w+):\s*(.*)$')

def events(lines):
    for line in lines:
        m=LINE.match(line)
        if m:
            pid,cpu,flags,ts,kind,body=m.groups()
            yield dict(pid=int(pid),cpu=int(cpu),flags=flags,
                ns=int(Decimal(ts)*1000000000),kind=kind,body=body)

def summarize(sequence,seeds,start,end,objects,copy_windows):
    owners=dict(seeds);pending=defaultdict(list);counts=Counter();rows={}
    for e in sequence:
        pid,kind,ns=e['pid'],e['kind'],e['ns']
        body=e['body']
        if kind=='sched_process_fork':
            p=re.search(r'\bpid=(\d+)\s+child_comm=.*?\s+child_pid=(\d+)',body)
            if p:
                parent,child=map(int,p.groups())
                owners.pop(child,None)
                if parent in owners: owners[child]=owners[parent]
                if pending.pop(child,[]): counts['pid_reuse_pending']+=1
            continue
        if kind=='sched_process_exit':
            owners.pop(pid,None)
            counts['exit_with_pending']+=len(pending.pop(pid,[]))
            continue
        if ns < start: continue
        if ns > end: break
        if kind=='slow':
            m=re.search(r'\block=(?:0x)?([0-9a-fA-F]+)',body)
            if not m:
                counts['undecoded_entry']+=1;continue
            # ftrace's third flag is hardirq/softirq context. Never attribute
            # interrupted task identity as IRQ resource ownership.
            irq=len(e['flags'])>2 and e['flags'][2] in 'hHsS'
            pending[pid].append((ns,int(m.group(1),16),None if irq else owners.get(pid),irq))
            counts['entries']+=1
        elif kind=='slow_end':
            if not pending[pid]: counts['unmatched_return']+=1;continue
            begin,address,owner,irq=pending[pid].pop()
            if ns<begin: counts['negative_interval']+=1;continue
            category=objects.get(address,'unidentified_lock')
            key=(category,address,owner,irq)
            row=rows.setdefault(key,dict(resource=category,address=hex(address),slot=owner,
                irq_or_softirq=irq,count=0,observed_wait_ns=0,max_observed_wait_ns=0,
                within_copy_business_count=0,within_copy_business_wait_ns=0,callers={}))
            row['count']+=1;row['observed_wait_ns']+=ns-begin
            row['max_observed_wait_ns']=max(row['max_observed_wait_ns'],ns-begin)
            window=copy_windows.get(owner)
            caller=re.search(r'\(([^+\s()]+).*?\s+<-',body)
            if caller:
                name=caller.group(1);row['callers'][name]=row['callers'].get(name,0)+1
            if window and window[0]<=begin<=ns<=window[1]:
                row['within_copy_business_count']+=1
                row['within_copy_business_wait_ns']+=ns-begin
    counts['unfinished_entries']=sum(map(len,pending.values()))
    return {'pair_audit':dict(counts),'objects':sorted(rows.values(),key=lambda r:-r['observed_wait_ns'])}

def main():
    p=argparse.ArgumentParser();p.add_argument('run');p.add_argument('--output',default='summary.json');args=p.parse_args()
    d=Path(args.run);out=d/'diagnostic';text=(d/'console.log').read_text()
    result=json.loads((d/'result.json').read_text());assert result['status']=='PASS'
    start=int(re.search(r'W1_MATRIX_RELEASE (\d+)',text)[1])
    seeded_at=int(re.search(r'W1_OWNER_SNAPSHOT (\d+)',text)[1])
    end=max(c['action_intervals'][-1]['end_ns'] for c in result['per_copy'])
    windows={c['slot']:(c['action_intervals'][0]['start_ns'],c['action_intervals'][-1]['end_ns']) for c in result['per_copy']}
    seeds={}
    for slot,body in re.findall(r'W1_SNAPSHOT owner-procs (\d+) BEGIN\r?\n(.*?)\r?\nW1_SNAPSHOT owner-procs \1 END',text,re.S):
        for pid in body.split(): seeds[int(pid)]=int(slot)
    assert seeds,'missing ownership seed'
    layout=json.loads(re.search(r'CKWB_LAYOUT (\{[^\r\n]+\})',text)[1])
    symbols={}
    for line in (out/'kallsyms').read_text().splitlines():
        a=line.split()
        if len(a)>=3:symbols[a[2]]=int(a[0],16)
    objects={}
    backend_match=re.search(r'CKWB_OBJECTS (\{[^\r\n]+\})',text)
    backend=json.loads(backend_match[1]) if backend_match else None
    if backend:
        objects[int(backend['buffer_mapping_lock'],16)]='blockdev_buffer_mapping_private_lock'
        journal=int(backend['journal_list_lock'],16)
        if journal: objects[journal]='jbd2_journal_list_lock'
        base=int(backend['blockgroup_locks'],16)
        for i in range(layout['bgl_count']):
            objects[base+i*layout['bgl_entry_size']]='ext4_blockgroup_lock_bucket'
    if 'inode_hash_lock' in symbols:objects[symbols['inode_hash_lock']]='inode_hash'
    if 'inode_hash_locks' in symbols:
        # Stride/size must be verified from the matching image, not assumed.
        layoutfile=out/'inode-stripes.json'
        assert layoutfile.exists(),'need compiled stripe size/count'
        stripes=json.loads(layoutfile.read_text())
        for i in range(stripes['count']):objects[symbols['inode_hash_locks']+i*stripes['stride']]='inode_hash_stripe'
    with (out/'trace').open() as f:
        tables={int(m.group(1),16) for e in events(f) if start<=e['ns']<=end and e['kind']=='sid_put'
            for m in [re.search(r'\btable=(?:0x)?([0-9a-fA-F]+)',e['body'])] if m}
    for table in tables:objects[table+layout['sidtab_cache_lock']]='sidtab_cache_lock'
    with (out/'trace').open() as f:
        summary=summarize((e for e in events(f) if e['ns']>=seeded_at),seeds,start,end,objects,windows)
    stats=(out/'buffer-stats').read_text()
    dropped=sum(int(n) for n in re.findall(r'^(?:overrun|commit overrun|dropped events):\s*(\d+)',stats,re.M))
    missed=0
    for line in (out/'kprobe-profile').read_text().splitlines():
        fields=line.split()
        if len(fields)==3:missed+=int(fields[2])
    summary.update(workload=result['workload'],variant=result['variant'],copies=result['copies'],
        backend_identity=backend,
        buffer_loss=dropped,kretprobe_missed=missed,window_ns=[start,end],
        identity_assumption='fixed-policy diagnostic guest; no policy reload or cgroup migration during business',
        limits=['wait intervals are wall time, not pure spinning CPU','no owner/holder causality',
                'diagnostic observer overhead not a business performance result',
                'unknown object/owner remains unknown; overlapping waits are not elapsed business cost'])
    bad=any(summary['pair_audit'].get(k,0) for k in ('negative_interval','undecoded_entry','pid_reuse_pending'))
    summary['exact_total_claim_allowed']=False
    summary['quality']='INCOMPLETE' if dropped or missed or bad else 'OBSERVED_INTERVALS_ONLY'
    assert Path(args.output).name==args.output
    target=out/args.output;assert not target.exists();target.write_text(json.dumps(summary,indent=2))
    print(json.dumps({k:v for k,v in summary.items() if k!='objects'}))

if __name__=='__main__':main()
