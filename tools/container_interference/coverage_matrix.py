#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Replay pinned evidence; never convert a narrow cohort into complete coverage."""
import argparse
import hashlib
import importlib
import json
import os
from pathlib import Path
from prototype_contract import assess as assess_prototype

CONTRACT={
    'sync': dict(name='泛型spinlock/rwsem线索',collector='sync',
        discovered='已观测慢路径等待、对象地址和调用栈',object='窗口内地址，生命周期未知',
        participants='仅等待任务；不得推断持有者',pending=['任意锁的完整对象生命周期；rwsem专项另列']),
    'rwsem': dict(name='rwsem有界持有者专项',collector='rwsem',
        discovered='公共非RT接口的尝试、获取、释放、降级和中止',object='本窗实际初始化事件与对象地址',
        participants='已观察写者或至多8个读者；集合不保证完整',
        pending=['窗口前对象仍为E1','non-owner使用和读者溢出不得提升归因','选定对象rwsem联合验证单列，不借用安静十专项结果']),
    'rwsem_joint': dict(name='rwsem与四容器业务联合真值',collector='rwsem',
        discovered='普通文件/VMA负载覆盖诊断窗口，独立rwsem正反例同时执行',
        object='受控公共rwsem接口及本窗初始化代次',
        participants='目标轮换，真实尝试/持有区间独立核对，不从热点推断持有者',
        pending=['受控rwsem不代表所有混合资源来源','完整异步后台与内核内存成本','真实应用竞争发生率']),
    'fd': dict(name='FD表锁',collector='fd',discovered='已选定files_struct锁路径',
        object='对象地址、RETIRE及新watch边界',participants='观察到的持有/等待任务及容器',
        pending=['固定fixture调用分母已有独立统计；不等于真实阻塞关系召回','版本化有界前缀之外的覆盖与密集路径入口成本']),
    'fd_guard': dict(name='FD高事件率采集保护',collector='fd',
        discovered='超过固定源入口预算后卸载采集，独立验证两侧业务继续',
        object='FD专项源开关和拒收的截断会话，不是持有者正例',
        participants='保护通过不等于密集FD关系采集可用',
        pending=['不代表所有容量路径','完整源端和异步后台成本']),
    'fd_relations': dict(name='FD独立申请与持有区间重叠覆盖',collector='fd',
        discovered='全部独立调用真值先生成关系分母，再核对原始采集关系',
        object='同files_struct、不同任务、窗口内完整调用及退役边界',
        participants='有界全部关系核验，摘要省略不能充当完整检查',
        pending=['不是纯自旋或因果阻塞召回','普通应用无完整独立分母','超出有界前缀仍可遗漏']),
    'counter': dict(name='page_counter',collector='counter',discovered='实际叶/祖先更新与限额回滚',
        object='初始化代次、地址和字段',participants='共同更新者，不是锁持有者',
        pending=['选定祖先汇总已做采样事件级验证；高事件率待测','全量更新计数不由采样推算','硬件cacheline证据（条件项）']),
    'allocator': dict(name='SLUB/Maple',collector='allocator',discovered='指定cache的分配阶段和释放入口',
        object='cache/节点/已观测分配代次',participants='分配请求方与释放执行方；后端锁持有者未知',
        pending=['允许节点放置、原生failslab拒绝及fail_page_alloc部分回滚已有专项；并发策略变化和真实压力待验证','SLUB节点锁关系由独立专项核验；其余后端锁仍未知','Maple申请到目标树的关联另列，不等于完整树所有权']),
    'maple_context': dict(name='Maple请求与分配后端关联',collector='allocator',
        discovered='原生申请闭合边界、目标树、SLUB调用与已采样节点释放入口',
        object='树地址仅在一次申请内有效；节点分配代次独立保留',
        participants='请求容器、目标树与释放执行者分开；复制使用目标树，不推断锁持有者',
        pending=['不将跨申请同地址当作完整树生命周期','预分配节点实际安装位置未追踪','完整后端释放和RCU耗时仍未知']),
    'slub': dict(name='SLUB节点锁专项',collector='slub',discovered='指定cache的实际节点锁尝试、获取、释放与回收边界',
        object='完整cache指针、节点锁地址和watch代次',participants='已观察持有者与等待者；不含窗口前或中断持有者',
        pending=['受控节点锁不代表生产发生率','普通分配路径没有独立持有者召回分母','其他SLUB锁与完整Maple树归属','完整入口及后台成本未知；普通应用联合回归另列']),
    'net': dict(name='Socket逻辑锁',collector='net',discovered='选定TCP Socket逻辑锁的获取、等待和释放',
        object='原生Socket cookie与netns',participants='已观察逻辑持有者与等待者，不代表TCP全部锁',
        pending=['窗口内用户Socket创建与accept已区分；窗口前/内核创建者仍未知','SCM_RIGHTS来源与持有者有专项真值，不等于报文来源','更多协议/短锁覆盖']),
    'net_reuse': dict(name='Socket关闭后地址复用反例',collector='net',
        discovered='实际close/create、原生cookie与活对象地址独立核验',
        object='关闭先于新建，地址复用但cookie必须不同',
        participants='每个新对象的创建与使用者独立匹配，不继承旧持有者',
        pending=['仅验证实际发生复用的受限原生TCP路径','非任意协议或设备生命周期']),
    'net_isolation': dict(name='CPU配额与Socket命名空间反例',collector='net',
        discovered='真实cgroup限流及原生Socket/任务namespace FD独立核对',
        object='独立Socket cookie和原生网络命名空间inode',
        participants='限流容器不是另一私有Socket的持有者；转移FD不改变Socket归属',
        pending=['受控CPU配额反例不代表所有网络背压','不量化CPU限流对生产吞吐的因果贡献']),
    'backlog': dict(name='backlog/skb',collector='net',discovered='入队、服务及skb释放入口',
        object='Socket cookie、skb地址及入队epoch',participants='执行者独立记录，报文原始归属未知',
        pending=['TCP发送原始头部分配另列net_tx；收包分配与完整释放后端仍缺失','clone/GSO/GRO来源变换']),
    'net_capacity': dict(name='网络对象表容量保护',collector='net',
        discovered='80个原生Socket触发64项watch上限，拒收不完整归因并核对卸载后业务继续',
        object='独立Socket cookie集合及窗口内watch容量',
        participants='保护通过不表示截断窗口可用于持有者归因',
        pending=['该测试不是高事件率或ring满验收','未证明所有网络元数据容量路径']),
    'net_guard': dict(name='网络高事件率采集保护',collector='net',
        discovered='独立Socket高频原生操作，停止采集并验证同一业务继续',
        object='私有Socket cookie和真实源开关，不是跨容器竞争正例',
        participants='截断窗口不得输出持有者关系，保护通过不等于密集采集可用',
        pending=['按实际触发的保护原因分别留证','不代表所有采集器或所有容量路径','完整源端CPU与后台成本']),
    'net_tx': dict(name='TCP发送缓冲区申请与释放',collector='net',
        discovered='原生fclone申请、内存准入与原始skb头部释放入口',
        object='Socket cookie、请求任务代次与分配边界；原始头部地址不代表共享数据页',
        participants='申请容器与释放执行者分开；不是分配器锁持有关系或报文内容所有权',
        pending=['接收与clone/GSO/GRO来源变换不在此闭环','后端经过时间不是独占CPU','原始头部释放后端、原生分配失败与内存准入拒绝由独立专项核验']),
    'net_tx_failure': dict(name='TCP发送分配失败与恢复',collector='net',
        discovered='任务与cache限定的原生failslab失败、系统调用返回及同Socket恢复',
        object='私有Socket cookie、请求任务代次与实际send调用边界',
        participants='失败请求归属与正常旁观容器分开，不推断分配器持有者',
        pending=['受控故障不是生产失败发生率','内存准入失败与真实内存压力另行验证','原始头部释放入口不是全部数据后端释放']),
    'net_tx_admission': dict(name='TCP内存准入拒绝与恢复',collector='net',
        discovered='原生修复模式队列、TCP预算耗尽与恢复后的同Socket发送准入',
        object='Socket cookie、申请调用边界及释放先于拒绝的原始头部',
        participants='申请容器与管理面压力条件分开，不推断设备阻塞方或分配器持有者',
        pending=['修复模式仅验证队列接收，不代表数据已上网','真实业务压力发生率与其他失败来源','全部释放后端和转换后的skb来源']),
    'net_release': dict(name='原始TCP头部释放后端与克隆保留',collector='net',
        discovered='原生发送分配、关闭时释放后端返回及真实skb_clone保留反例',
        object='原始头部episode与释放前冻结的地址/时间token，非转换后报文所有权',
        participants='申请者与释放执行者分开；共享数据与fclone引用保留不标为回收完成',
        pending=['不支持转换后子skb的全生命周期归属','bulk/NAPI/morph保留入口级证据','后端wall时间不是纯CPU或其他容器阻塞时间']),
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
        pending=['合并真值仅限独立内存设备，非生产发生率','buffered writeback脏页来源','拆分/提交前取消另列；生产父子bio生命周期和在途取消仍未闭合','高事件率与普通应用联合成本']),
    'block_lifecycle': dict(name='拆分请求、错误完成与提交前取消反例',collector='block',
        discovered='原生bio按设备限制拆分后的请求及其完成状态、字节守恒',
        object='请求episode；原始bio关系仅由独立fixture核验，不冒充生产采集能力',
        participants='提交任务与bio计费身份；取消未提交时不得出现请求或阻塞关系',
        pending=['驱动在途终止由独立专项核验，不代表任意取消接口与叠加设备拆分','完整生产bio父子生命周期未知','固定设备错误不等于真实硬件故障覆盖']),
    'block_inflight': dict(name='驱动已接收请求的终止与正常完成',collector='block',
        discovered='实际started请求、提交返回、终止前未完成与最终错误或成功完成',
        object='请求episode与独立驱动真值，不是通用取消意图采集',
        participants='提交任务及bio计费身份；终止意图仅由fixture证明，不推断设备阻塞方',
        pending=['设备驱动终止不代表任意io_uring/AIO取消','完整生产bio父子生命周期未知','不推断真实设备内部服务或故障原因']),
    'writeback': dict(name='缓冲写回计费与执行分离',collector='block',
        discovered='原生ext4后台提交的请求、bio计费容器与实际执行线程',
        object='请求episode和bio计费身份，不是完整inode生命周期',
        participants='已注册计费根与真实kworker分别记录；共享inode不推断唯一脏化者或阻塞方',
        pending=['脏化与inode同步回写请求关联另列，不是完整数据所有权','多写入者、归属切换和回收并发','写回节流及完整后台成本']),
    'writeback_inode': dict(name='原生inode回写与请求上下文',collector='block',
        discovered='容器脏化事件、闭合inode回写调用与其同步提交的请求',
        object='I_SYNC调用边界、inode观测属性、任务代次与请求episode',
        participants='脏化执行者、memcg回写归属、bio计费根及后台执行者分开；不推断唯一写入者或阻塞方',
        pending=['脏化事件到回写之前的完整inode生命周期未闭合','异步脱离调用的提交与合并内容不推断inode','写回节流及完整后台成本']),
    'routing': dict(name='有界专项调度',collector='controller',discovered='真实巡检候选到单槽专项',
        object='配置epoch、目标代次及候选来源会话',participants='按目标轮转，候选不是因果认定',
        pending=['四容器混合来源另列；真实周期等待不等于解释生成耗时']),
    'mixed': dict(name='网络与块I/O混合来源独立真值',collector='joint',
        discovered='四容器普通文件/VMA覆盖同窗网络锁和直接I/O，OFF/IP/NET/BLOCK轮换',
        object='Socket cookie、请求episode和独立工作负载时间括号',
        participants='网络持有者/等待者与I/O提交/计费身份分开；私有反例及角色轮换',
        pending=['受控TCP逻辑锁和虚拟块设备不代表生产发生率','单采集器窗口不代表多采集器并发','完整异步后台和内核内存成本']),
    'joint': dict(name='四容器普通应用联合成本',collector='joint',
        discovered='OFF/IP/专项的固定轮次、角色切换与等到达率响应',object='逐容器操作窗口、实际采集对象与源码绑定',
        participants='无完整应用真值时不伪造召回；安静专项不算正例',
        pending=['按实际源码绑定限定回归，不继承为未来版本通过','各资源强制正反例单列，安静应用不代替正例','完整后台与内核内存成本']),
    'control': dict(name='加载与清理',collector='controller',discovered='独立采集器加载、共享预算、停止与恢复',
        object='真实程序/map ID及源开关',participants='不作业务竞争归因',pending=['仅证明已运行版本的故障与清理，不自动认证未来版本'])}

VERIFIERS={
    'sync': ('sync_vm_check','sync',{}), 'fd':('fd_vm_check','fd',{}),
    'fd_guard':('fd_guard_check','fd_guard',{}),
    'fd_relations':('fd_vm_check','fd_relations',{}),
    'counter':('counter_vm_check','counter',{}),
    'allocator':('allocator_vm_check','allocator',{}),
    'maple_context':('allocator_vm_check','maple_context',dict(maple=True)),
    'allocator_fixture':('allocator_vm_check','allocator',dict(fixture=True)),
    'allocator_placement':('allocator_vm_check','allocator',dict(placement=True)),
    'allocator_failure':('allocator_vm_check','allocator',dict(failure=True)),
    'allocator_rollback':('allocator_vm_check','allocator',dict(rollback=True)),
    'slub':('slub_vm_check','slub',{}),
    'net':('net_vm_check','net',{}), 'backlog':('net_vm_check','backlog',{}),
    'net_isolation':('net_vm_check','net_isolation',{}),
    'net_reuse':('net_vm_check','net_reuse',{}),
    'net_tx':('net_vm_check','net_tx',{}),
    'net_tx_failure':('net_vm_check','net_tx_failure',{}),
    'net_tx_admission':('net_vm_check','net_tx_admission',{}),
    'net_release':('net_vm_check','net_release',{}),
    'net_capacity':('net_vm_check','net_capacity',{}),
    'net_guard':('net_guard_check','net_guard',{}),
    'block':('block_vm_check','block',{}), 'block_tag':('tag_vm_check','block_tag',{}),
    'block_merge':('block_vm_check','block_merge',{}),
    'block_lifecycle':('block_vm_check','block_lifecycle',{}),
    'block_inflight':('block_vm_check','block_inflight',{}),
    'writeback':('writeback_vm_check','writeback',{}),
    'writeback_inode':('writeback_vm_check','writeback_inode',{}),
    'routing':('diagnosis_vm_check','routing',{}),
    'control':('x0_check','control',{}), 'rwsem':('rwsem_vm_check','rwsem',{}),
    'rwsem_joint':('rwsem_vm_check','rwsem_joint',dict(joint=True)),
    'joint':('joint_vm_check','joint',{}), 'mixed':('mixed_vm_check','mixed',{})}


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
            if key=='net' and labels and all(v.startswith(('reuse-','private-','backlog-','capacity-','storm-','txfailure-','txunmarked-','txadmission-','txnormal-','txplain-','txclone-')) for v in labels):
                raise ValueError('logical ownership cohort required')
            if key=='net_reuse':
                selected=[v for v in checked.get('states',[]) if '-net' in v.get('label','')]
                if (len(selected)!=3 or any(not v['label'].startswith('reuse-') or
                        v.get('result',{}).get('matched')!=16 or
                        len(v['result'].get('reused_boundaries',[]))!=2 or
                        any(not b for b in v['result']['reused_boundaries']) for v in selected)):
                    raise ValueError('native reused addresses and fresh Socket cookies required')
            if key=='net_isolation':
                selected=[v for v in checked.get('states',[]) if '-net' in v.get('label','')]
                if (len(selected)!=3 or any(not v['label'].startswith('private-') or
                        v.get('result',{}).get('namespace_validation',{}).get('status')!='PASS' or
                        v['result'].get('quota_validation',{}).get('status')!='PASS' or
                        v['result'].get('eligible')!=0 or v['result'].get('captured')!=0 for v in selected)):
                    raise ValueError('observed private sockets and real CPU quota negative required')
            if key=='net_capacity':
                selected=[v for v in checked.get('states',[]) if '-net' in v.get('label','')]
                if (len(selected)!=3 or any(not v['label'].startswith('capacity-') or
                        v.get('result',{}).get('native_cookies')!=80 or
                        v.get('result',{}).get('quality',{}).get('status')!='FAIL' for v in selected)):
                    raise ValueError('native watch overflow and rejected observation required')
            if key=='net_guard':
                selected=[v for v in checked.get('states',[]) if '-net' in v.get('label','')]
                if (len(selected)!=3 or any(not v['label'].startswith('storm-') or
                        v.get('result',{}).get('reason') not in ('ENTRY_RATE_LIMIT','WORKER_CPU_LIMIT','COMBINED_PROCESS_CPU_CAPTURING','DATA_LIMIT','QUALITY') or
                        len(v['result'].get('post_detach_operations',[]))!=2 or
                        min(v['result']['post_detach_operations'])<=0 for v in selected)):
                    raise ValueError('rejected dense capture and continued business required')
            if key=='fd_guard':
                selected=checked.get('cases',[])
                if (len(selected)!=3 or {v.get('label') for v in selected}!={'storm0','storm1','storm2'} or
                        any(v.get('capture_status')!='PARTIAL' or len(v.get('rates',[]))!=1 or
                            v['rates'][0].get('configured_limit')!=200000 or
                            len(v.get('post_detach_operations',[]))!=2 or
                            min(v['post_detach_operations'])<=0 for v in selected)):
                    raise ValueError('rejected FD entry-rate capture and continued business required')
            if key=='fd_relations':
                selected=[v for v in checked.get('cases',[]) if v.get('label','').startswith(('threads','cross','reuse'))]
                if (len(selected) not in (3,6) or any(
                        v.get('relationships',{}).get('design')!='PREDECLARED' or
                        v['relationships'].get('threshold_status')!='PASS' or
                        v['relationships'].get('eligible',0)<=0 or
                        v['relationships'].get('capture_ratio',0)<.90 or
                        v['relationships'].get('true_blocking_recall') is not None for v in selected)):
                    raise ValueError('predeclared independent FD overlap population required')
            if key=='net_tx':
                selected=[v for v in checked.get('states',[]) if '-net' in v.get('label','')]
                if len(selected)!=3 or any(not v.get('result',{}).get('tx') or
                        v['result']['tx'].get('status')!='PASS' or not v['result']['tx'].get('matches') for v in selected):
                    raise ValueError('send requester, cookie, bracket and release truth required')
            if key=='net_tx_failure':
                selected=[v for v in checked.get('states',[]) if '-net' in v.get('label','')]
                if (len(selected)!=6 or {v['label'].split('-')[0] for v in selected}!={'txfailure','txunmarked'} or
                        any(len(v.get('result',{}).get('participants',[]))!=2 or
                            any(p.get('eligible')!=8 or p.get('captured')!=8 for p in v['result']['participants'])
                            for v in selected)):
                    raise ValueError('native allocation failure, recovery and unmarked task control required')
            if key=='net_tx_admission':
                selected=[v for v in checked.get('states',[]) if '-net' in v.get('label','')]
                if (len(selected)!=6 or {v['label'].split('-')[0] for v in selected}!={'txadmission','txnormal'} or
                        any(len(v.get('result',{}).get('participants',[]))!=2 or
                            any(p.get('eligible')!=24 or p.get('captured')!=24 or p.get('recovery_sends')!=8 or
                                (v['label'].startswith('txadmission-') and p.get('admission_rejected',0)<=0)
                                for p in v['result']['participants']) for v in selected)):
                    raise ValueError('native memory admission rejection and restored-budget recovery required')
            if key=='net_release':
                selected=[v for v in checked.get('states',[]) if '-net' in v.get('label','')]
                if (len(selected)!=6 or {v['label'].split('-')[0] for v in selected}!={'txplain','txclone'} or
                        any(v.get('result',{}).get('matched')!=2 or
                            len(v['result'].get('truth',[]))!=2 or
                            any(t.get('clone')!=int(v['label'].startswith('txclone-')) for t in v['result']['truth'])
                            for v in selected)):
                    raise ValueError('independent native queue/close/retained-clone truth required')
            if key=='block_merge' and checked.get('fixture') not in ('merge','merge-scheduler'):
                raise ValueError('native merge truth cohort required')
            if key=='block_lifecycle' and checked.get('fixture')!='lifecycle':
                raise ValueError('native split/error/presubmit cancellation truth required')
            if key=='block_inflight':
                selected=[v for v in checked.get('states',[]) if '-block-' in v.get('label','')]
                if (checked.get('fixture')!='inflight' or len(selected)!=6 or
                        any(v.get('result',{}).get('driver_requests')!=2 or
                            v['result'].get('canceled_before_submit') is not False or
                            v['result'].get('driver_aborted_inflight') != v['label'].startswith('abort-') or
                            v['result'].get('deferred_normal_completion') != v['label'].startswith('drain-')
                            for v in selected)):
                    raise ValueError('started pending request termination and normal drain required')
            if key=='writeback_inode':
                states=checked.get('states',[])
                selected=[v for v in states if '-block-' in v.get('label','')]
                if len(selected)!=6 or any(v.get('result',{}).get('inode_request_link')!='CLOSED_NATIVE_CONTEXT' or
                        len(v.get('result',{}).get('dirty_transition_actors',[]))!=2 for v in selected):
                    raise ValueError('closed inode context and two observed dirtying actors required')
            if key=='maple_context':
                selected=[v for v in checked.get('states',[]) if v.get('label','').startswith('allocator')]
                if len(selected)!=3 or any(len(v.get('result',{}).get('participants',[]))!=2 or
                        any(not p.get('joins') or not p.get('release_entries') for p in v['result']['participants']) for v in selected):
                    raise ValueError('Maple destination and release truth required')
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
    prototype=assess_prototype(evidence)
    return dict(schema='cis-coverage-matrix-v1',status=prototype['status'],rows=matrix,evidence=evidence,
        x7_complete=prototype['x7_complete'],prototype_contract=prototype,
        remaining_joint=[name+': '+item for name,stage in prototype['stages'].items() for item in stage['missing']],
        interpretation='PASS_SCOPED仅证明对应原始批次及支持范围；不继承为未来版本通过，不将unknown算PASS')


def markdown(result):
    lines=['# 原型覆盖与缺口','','各证据均重新读取原始日志核验。PASS_SCOPED不代表整类问题已完全覆盖。','',
        '| 来源 | 实际发现/对象 | 参与者边界 | 本批验证 | 边界与后续扩展 |','|---|---|---|---|---|']
    for row in result['rows']:
        lines.append('| %s | %s；%s | %s | %s | %s |'%(row['name'],row['discovered'],row['object'],row['participants'],row['cohort_status'],'；'.join(row['pending'])))
    lines+=['',('X7状态：限定原型合同通过，不代表完整内核覆盖或生产验收。' if result.get('x7_complete') else
                'X7状态：尚未完成。')+'逐批源码绑定、原始日志哈希及复核结果见JSON。']
    return '\n'.join(lines)+'\n'


if __name__=='__main__':
    os.umask(0o077)
    p=argparse.ArgumentParser(); p.add_argument('index',type=Path); p.add_argument('output',type=Path); a=p.parse_args()
    if a.index.stat().st_size>65536: raise ValueError('index size')
    result=replay(json.loads(a.index.read_text()),a.index.parent,a.output)
    (a.output/'coverage.json').write_text(json.dumps(result,ensure_ascii=False,indent=2))
    (a.output/'coverage.md').write_text(markdown(result))
    print(json.dumps(dict(status=result['status'],cohorts=len(result['evidence']),failed=sum(e['status']=='FAIL' for e in result['evidence']))))
