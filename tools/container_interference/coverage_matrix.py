#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Replay pinned evidence; never convert a narrow cohort into complete coverage."""
import argparse
import hashlib
import importlib
import json
import os
from pathlib import Path

CONTRACT={
    'sync': dict(name='泛型spinlock/rwsem线索',collector='sync',
        discovered='已观测慢路径等待、对象地址和调用栈',object='窗口内地址，生命周期未知',
        participants='仅等待任务；不得推断持有者',pending=['任意锁的完整对象生命周期；rwsem专项另列']),
    'rwsem': dict(name='rwsem有界持有者专项',collector='rwsem',
        discovered='公共非RT接口的尝试、获取、释放、降级和中止',object='本窗实际初始化事件与对象地址',
        participants='已观察写者或至多8个读者；集合不保证完整',
        pending=['窗口前对象仍为E1','non-owner使用和读者溢出不得提升归因','选定对象rwsem未计入普通应用十专项联合矩阵']),
    'rwsem_joint': dict(name='rwsem与四容器业务联合真值',collector='rwsem',
        discovered='普通文件/VMA负载覆盖诊断窗口，独立rwsem正反例同时执行',
        object='受控公共rwsem接口及本窗初始化代次',
        participants='目标轮换，真实尝试/持有区间独立核对，不从热点推断持有者',
        pending=['受控rwsem不代表所有混合资源来源','完整异步后台与内核内存成本','真实应用竞争发生率']),
    'fd': dict(name='FD表锁',collector='fd',discovered='已选定files_struct锁路径',
        object='对象地址、RETIRE及新watch边界',participants='观察到的持有/等待任务及容器',
        pending=['固定fixture调用分母已有独立统计；不等于真实阻塞关系召回','64事件前缀之外的覆盖与密集路径入口成本']),
    'counter': dict(name='page_counter',collector='counter',discovered='实际叶/祖先更新与限额回滚',
        object='初始化代次、地址和字段',participants='共同更新者，不是锁持有者',
        pending=['选定祖先汇总已做采样事件级验证；高事件率待测','全量更新计数不由采样推算','硬件cacheline证据（条件项）']),
    'allocator': dict(name='SLUB/Maple',collector='allocator',discovered='指定cache的分配阶段和释放入口',
        object='cache/节点/已观测分配代次',participants='分配请求方与释放执行方；后端锁持有者未知',
        pending=['允许节点放置、原生failslab拒绝及fail_page_alloc部分回滚已有专项；并发策略变化和真实压力待验证','SLUB节点锁关系由独立专项核验；其余后端锁仍未知','Maple树归属']),
    'slub': dict(name='SLUB节点锁专项',collector='slub',discovered='指定cache的实际节点锁尝试、获取、释放与回收边界',
        object='完整cache指针、节点锁地址和watch代次',participants='已观察持有者与等待者；不含窗口前或中断持有者',
        pending=['受控节点锁不代表生产发生率','普通分配路径没有独立持有者召回分母','其他SLUB锁与Maple树归属','完整入口及后台成本与联合回归']),
    'net': dict(name='Socket逻辑锁',collector='net',discovered='选定TCP Socket逻辑锁的获取、等待和释放',
        object='原生Socket cookie与netns',participants='已观察逻辑持有者与等待者，不代表TCP全部锁',
        pending=['窗口内用户Socket创建与accept已区分；窗口前/内核创建者仍未知','SCM_RIGHTS来源与持有者有专项真值，不等于报文来源','更多协议/短锁覆盖']),
    'backlog': dict(name='backlog/skb',collector='net',discovered='入队、服务及skb释放入口',
        object='Socket cookie、skb地址及入队epoch',participants='执行者独立记录，报文原始归属未知',
        pending=['skb分配来源和后端成本','clone/GSO/GRO来源变换']),
    'block': dict(name='块I/O',collector='block',discovered='直接I/O请求形成、排队、下发与完成',
        object='请求episode、设备/队列、head-bio blkcg',participants='初始提交者与bio归属；不推断唯一阻塞方',
        pending=['tag等待由独立专项核验','重排队/部分完成及bio/request合并由独立专项核验，不代表任意设备','buffered writeback多源归属']),
    'block_tag': dict(name='块请求槽位等待',collector='block',discovered='原生tag慢分配、io_schedule及NOWAIT拒绝',
        object='调用episode、队列与本次bitmap地址',participants='等待任务；未推断占用槽位的请求或唯一阻塞容器',
        pending=['API fixture不代表真实设备负载覆盖','多硬件队列迁移与reserved池运行验证','槽位持有请求的完整生命周期']),
    'block_merge': dict(name='bio合并与字节来源',collector='block',
        discovered='原生bio前向/后向合并、mq-deadline请求转移、下发时有界bio列表和blkcg字节权重',
        object='请求episode、合并转移和每次下发快照，最多8个bio',
        participants='请求提交者与bio计费来源分开，超限和未知来源保留，不推断设备阻塞方',
        pending=['合并真值仅限独立内存设备，非生产发生率','buffered writeback脏页来源','bio拆分及取消运行反例','高事件率与普通应用联合成本']),
    'writeback': dict(name='缓冲写回计费与执行分离',collector='block',
        discovered='原生ext4后台提交的请求、bio计费容器与实际执行线程',
        object='请求episode和bio计费身份，不是完整inode生命周期',
        participants='已注册计费根与真实kworker分别记录；共享inode不推断唯一脏化者或阻塞方',
        pending=['脏化到inode再到bio的受限闭环','多写入者、归属切换和回收并发','写回节流及完整后台成本']),
    'writeback_inode': dict(name='原生inode回写与请求上下文',collector='block',
        discovered='容器脏化事件、闭合inode回写调用与其同步提交的请求',
        object='I_SYNC调用边界、inode观测属性、任务代次与请求episode',
        participants='脏化执行者、memcg回写归属、bio计费根及后台执行者分开；不推断唯一写入者或阻塞方',
        pending=['脏化事件到回写之前的完整inode生命周期未闭合','异步脱离调用的提交与合并内容不推断inode','写回节流及完整后台成本']),
    'routing': dict(name='有界专项调度',collector='controller',discovered='真实巡检候选到单槽专项',
        object='配置epoch、目标代次及候选来源会话',participants='按目标轮转，候选不是因果认定',
        pending=['四容器混合来源联合验收']),
    'joint': dict(name='四容器普通应用联合成本',collector='joint',
        discovered='OFF/IP/专项的固定轮次、角色切换与等到达率响应',object='逐容器操作窗口、实际采集对象与源码绑定',
        participants='无完整应用真值时不伪造召回；安静专项不算正例',
        pending=['新增采集器与新内核回归','各资源强制正反例仍须分别通过','完整后台与内核内存成本']),
    'control': dict(name='加载与清理',collector='controller',discovered='独立采集器加载、共享预算、停止与恢复',
        object='真实程序/map ID及源开关',participants='不作业务竞争归因',pending=['新版本故障矩阵回归'])}

VERIFIERS={
    'sync': ('sync_vm_check','sync',{}), 'fd':('fd_vm_check','fd',{}),
    'counter':('counter_vm_check','counter',{}),
    'allocator':('allocator_vm_check','allocator',{}),
    'allocator_fixture':('allocator_vm_check','allocator',dict(fixture=True)),
    'allocator_placement':('allocator_vm_check','allocator',dict(placement=True)),
    'allocator_failure':('allocator_vm_check','allocator',dict(failure=True)),
    'allocator_rollback':('allocator_vm_check','allocator',dict(rollback=True)),
    'slub':('slub_vm_check','slub',{}),
    'net':('net_vm_check','net',{}), 'backlog':('net_vm_check','backlog',{}),
    'block':('block_vm_check','block',{}), 'block_tag':('tag_vm_check','block_tag',{}),
    'block_merge':('block_vm_check','block_merge',{}),
    'writeback':('writeback_vm_check','writeback',{}),
    'writeback_inode':('writeback_vm_check','writeback_inode',{}),
    'routing':('diagnosis_vm_check','routing',{}),
    'control':('x0_check','control',{}), 'rwsem':('rwsem_vm_check','rwsem',{}),
    'rwsem_joint':('rwsem_vm_check','rwsem_joint',dict(joint=True)),
    'joint':('joint_vm_check','joint',{})}


def validate_index(index):
    if not isinstance(index,dict) or set(index)!={'schema','cohorts'} or index['schema']!='cis-coverage-input-v1':
        raise ValueError('versioned evidence index required')
    rows=index['cohorts']; names=set()
    if not isinstance(rows,list) or not 1<=len(rows)<=64: raise ValueError('bounded nonempty evidence required')
    for row in rows:
        if (set(row)!={'name','verifier','serial','sha256'} or row['verifier'] not in VERIFIERS or
                not isinstance(row['name'],str) or not row['name'].isascii() or
                not row['name'].replace('-','').isalnum() or len(row['name'])>80 or row['name'] in names or
                not isinstance(row['serial'],str) or len(row['serial'])>4096 or
                not isinstance(row['sha256'],str) or len(row['sha256'])!=64 or
                any(c not in '0123456789abcdef' for c in row['sha256'])):
            raise ValueError('invalid cohort identity, verifier or hash')
        names.add(row['name'])
    return rows


def replay(index,base,output):
    rows=validate_index(index); output.mkdir(mode=0o700); evidence=[]
    for row in rows:
        serial=(base/row['serial']).resolve()
        if not serial.is_file() or serial.stat().st_size>128<<20: raise ValueError('bounded serial file required')
        data=serial.read_bytes()
        if hashlib.sha256(data).hexdigest()!=row['sha256']: raise ValueError('evidence hash mismatch: '+row['name'])
        module,key,options=VERIFIERS[row['verifier']]; implementation=importlib.import_module(module)
        try:
            if key in ('routing','control'):
                checked=implementation.check(data.decode())
            elif key in ('rwsem','rwsem_joint','joint','slub'):
                checked=implementation.check(serial,output/row['name'],**options)
            else: checked=implementation.verify(serial,output/row['name'],**options)
            # A logical-lock cohort cannot be relabelled as backlog coverage.
            labels=[r.get('label','') for r in checked.get('states',[])]
            if key=='backlog' and not labels or (key=='backlog' and not all(v.startswith('backlog-') for v in labels)):
                raise ValueError('backlog cohort required')
            if key=='net' and labels and all(v.startswith('backlog-') for v in labels):
                raise ValueError('logical ownership cohort required')
            if key=='block_merge' and checked.get('fixture') not in ('merge','merge-scheduler'):
                raise ValueError('native merge truth cohort required')
            if key=='writeback_inode':
                states=checked.get('states',[])
                selected=[v for v in states if '-block-' in v.get('label','')]
                if len(selected)!=6 or any(v.get('result',{}).get('inode_request_link')!='CLOSED_NATIVE_CONTEXT' or
                        len(v.get('result',{}).get('dirty_transition_actors',[]))!=2 for v in selected):
                    raise ValueError('closed inode context and two observed dirtying actors required')
            error=None; passed=checked.get('status') in ('PASS','PASS_SCOPED') and not checked.get('errors') and not checked.get('defects')
        except (ValueError,KeyError,AssertionError) as exc:
            checked={}; error=type(exc).__name__+': '+str(exc); passed=False
        evidence.append(dict(name=row['name'],capability=key,status='PASS_SCOPED' if passed else 'FAIL',
            verifier=module,verifier_sha256=hashlib.sha256(Path(implementation.__file__).read_bytes()).hexdigest(),
            serial=str(serial),serial_sha256=row['sha256'],checked=checked,error=error))
    matrix=[]
    for key,contract in CONTRACT.items():
        cohort=[e for e in evidence if e['capability']==key]
        matrix.append(dict(key=key,**contract,implementation='IMPLEMENTED_PARTIAL',
            cohort_status='FAIL' if any(e['status']=='FAIL' for e in cohort) else 'PASS_SCOPED' if cohort else 'UNVERIFIED',
            evidence=[e['name'] for e in cohort],causal='NOT_ESTABLISHED',production='NOT_ACCEPTED'))
    return dict(schema='cis-coverage-matrix-v1',status='INCOMPLETE',rows=matrix,evidence=evidence,
        x7_complete=False,remaining_joint=['四容器混合来源的独立真值','新内核与新增专项的普通应用及成本回归',
            '强制保护和故障反例','逐资源最低覆盖合同中的未通过项'],
        interpretation='PASS_SCOPED仅证明对应原始批次及支持范围；不继承为未来版本通过，不将unknown算PASS')


def markdown(result):
    lines=['# 原型覆盖与缺口','','各证据均重新读取原始日志核验。PASS_SCOPED不代表整类问题已完全覆盖。','',
        '| 来源 | 实际发现/对象 | 参与者边界 | 本批验证 | 待完成 |','|---|---|---|---|---|']
    for row in result['rows']:
        lines.append('| %s | %s；%s | %s | %s | %s |'%(row['name'],row['discovered'],row['object'],row['participants'],row['cohort_status'],'；'.join(row['pending'])))
    lines+=['','X7状态：尚未完成。逐批源码绑定、原始日志哈希及复核结果见JSON。']
    return '\n'.join(lines)+'\n'


if __name__=='__main__':
    os.umask(0o077)
    p=argparse.ArgumentParser(); p.add_argument('index',type=Path); p.add_argument('output',type=Path); a=p.parse_args()
    if a.index.stat().st_size>65536: raise ValueError('index size')
    result=replay(json.loads(a.index.read_text()),a.index.parent,a.output)
    (a.output/'coverage.json').write_text(json.dumps(result,ensure_ascii=False,indent=2))
    (a.output/'coverage.md').write_text(markdown(result))
    print(json.dumps(dict(status=result['status'],cohorts=len(result['evidence']),failed=sum(e['status']=='FAIL' for e in result['evidence']))))
