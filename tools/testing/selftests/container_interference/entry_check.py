#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
import argparse
import json
import pathlib
import re

FIELDS=re.compile(r'(\w+)=([^ ;]+)')


def check(text):
    work, containers, guard, detach, policies = {}, {}, None, [], []
    duplicates = []
    for line in text.splitlines():
        f=dict(FIELDS.findall(line))
        if line.startswith('CIS_ENTRY_WORKLOAD '):
            if int(f['slot']) in work:
                duplicates.append(line)
            work[int(f['slot'])]=f
        if line.startswith('CIS_ENTRY_CONTAINER '):
            if int(f['slot']) in containers:
                duplicates.append(line)
            containers[int(f['slot'])]=f
        if line.startswith('CIS_ENTRY_GUARD '):
            guard=f
        if line.startswith('{'):
            try: e=json.loads(line)
            except ValueError: continue
            if e.get('kind')=='entry_budget_disable':
                detach.append(dict(FIELDS.findall(e['detail'])))
            if e.get('kind')=='capture_policy':
                policies.append(dict(FIELDS.findall(e['detail'])))
    rates=[int(d['delta_entries'])*1e9/int(d['interval_ns']) for d in detach]
    identities=(set(containers)==set(range(8)) and all(c.get('pid')=='1' and
                c.get('host')=='cis-container' and c.get('readonly_root')=='1' and
                c.get('cgroup')==f'0::/cis-entry-{i}' for i,c in containers.items()))
    business=(set(work)==set(range(8)) and all(int(w['errors'])==0 for w in work.values()) and
              all(int(work[i]['calls'])>0 for i in range(1,8)))
    safe=bool(guard and guard.get('capture')=='0' and guard.get('errors')=='0')
    default=bool(policies and all(p.get('entry_rate_limit')=='200000' for p in policies) and
                 detach and all(d.get('configured_limit')=='200000' for d in detach))
    continuation=bool(guard and all(int(work[i]['end_ns'])>int(guard['time_ns']) for i in work))
    warnings=re.findall(r'^.*(?:BUG:|WARNING:|KASAN:|Kernel panic|soft lockup|hard LOCKUP).*$',text,re.M)
    passed=(identities and not duplicates and not warnings and business and safe and default and continuation and any(r>200000 for r in rates) and
            'CIS_ENTRY_STORM_RESULT failures=0 ' in text and 'CIS_ENTRY_STORM_FAILURES=0' in text)
    return {'pass':passed,'container_identities_verified':identities,'duplicates':duplicates,'kernel_warnings':warnings,
            'business_completed':business,'capture_detached_before_completion':safe and continuation,
            'production_limit_used':default,'measured_entry_rates_per_second':rates,'workers':work,
            'scope':'isolated-VM bounded spinlock entry storm from seven non-target containers; one sleeping diagnostic target',
            'limits':['Safety/entry-budget test, not a <=3% diagnostic overhead claim.',
                      'Does not claim lock ownership or spin-cycle attribution.']}


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('input',type=pathlib.Path);p.add_argument('output',type=pathlib.Path)
    a=p.parse_args(); result=check(a.input.read_text())
    with a.output.open('x') as f:json.dump(result,f,indent=2)
    print(json.dumps(result,indent=2));raise SystemExit(0 if result['pass'] else 1)
