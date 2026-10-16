"""Small lifecycle validation, not Go correctness/performance admission."""
# SPDX-License-Identifier: GPL-2.0
import argparse
import errno
import json
import os
from pathlib import Path
import subprocess
import time
import re
import uuid
from fs_domain_lifecycle import Manager,run,save

CODE='''import os,errno,json,concurrent.futures
from pathlib import Path
p=Path('/work')
def worker(i):
 d=p/str(i);d.mkdir()
 for n in range(32):
  f=d/str(n);f.write_bytes(bytes([n])*4096);os.link(f,d/(str(n)+'.link'))
  assert f.stat().st_ino==(d/(str(n)+'.link')).stat().st_ino
  f.rename(d/(str(n)+'.renamed'))
  assert (d/(str(n)+'.link')).read_bytes()==bytes([n])*4096
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as e:list(e.map(worker,range(4)))
f=os.open(p/'durable',os.O_CREAT|os.O_WRONLY|os.O_EXCL,0o600)
os.write(f,b'ckernel-fs-domain-persistence');os.fsync(f);os.close(f)
d=os.open(p,os.O_RDONLY|os.O_DIRECTORY);os.fsync(d);os.close(d)
f=os.open(p/'fill',os.O_CREAT|os.O_WRONLY|os.O_EXCL,0o600);full=False
try:
 for i in range(256):os.write(f,b'x'*(1024*1024))
except OSError as e:
 if e.errno!=errno.ENOSPC:raise
 full=True
finally:os.close(f)
assert full,'bounded image did not exhaust';os.unlink(p/'fill')
assert (p/'durable').read_bytes()==b'ckernel-fs-domain-persistence'
print(json.dumps(dict(status='PASS',enospc=True,workers=4,files=128)))
'''

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--image',required=True,help='Existing ARM64 image ID with python3; no pull')
    parser.add_argument('--cpus',required=True)
    parser.add_argument('--memory-node',type=int,required=True)
    args=parser.parse_args()
    if not re.fullmatch(r'sha256:[0-9a-f]{64}',args.image):parser.error('immutable image ID required')
    if not re.fullmatch(r'[0-9]+(?:[-,][0-9]+)*',args.cpus) or args.memory_node<0:parser.error('CPU/node syntax')
    ROOT=args.root.absolute();IMAGE=args.image;LABEL='ckfs-smoke-'+uuid.uuid4().hex[:12]
    if ROOT!=ROOT.resolve():parser.error('symlink root path')
    os.umask(0o077);ROOT.mkdir(mode=0o700)
    if run(['getenforce']).strip()!='Enforcing':raise RuntimeError('security')
    identity=json.loads(run(['docker','image','inspect',IMAGE]))[0]
    if identity['Architecture']!='arm64':raise RuntimeError('image platform')
    boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    result=dict(status='FAIL',scope='lifecycle only; not Go admission',image=IMAGE,boot=boot,cases=[])
    m=None;ids=[];begin=time.monotonic_ns()
    specs=[dict(index=i,bytes=128*1024**2,inodes=2048,journal_mib=16) for i in range(2)]
    def create(name,path,code,entry='python3'):
        cid=run(['docker','create','--name',name,'--label','wb.native='+LABEL,'--runtime=runc',
            '--network=none','--cap-drop=ALL','--security-opt=no-new-privileges','--cpuset-cpus='+args.cpus,
            '--cpuset-mems='+str(args.memory_node),'--memory=256m','--memory-swap=256m','--pids-limit=64',
            '-v',str(path)+':/work:Z','--entrypoint',entry,IMAGE,'-c',code]).strip()
        ids.append(cid);return cid
    def remove(cid):
        info=json.loads(run(['docker','inspect',cid]))[0]
        if info['Config']['Labels'].get('wb.native')!=LABEL:raise RuntimeError('foreign container')
        if info['State']['Running']:run(['docker','stop','--time','2',cid])
        run(['docker','rm',cid]);ids.remove(cid)
    try:
        m=Manager(ROOT/'volumes',True);m.create_volumes(specs)
        dirs=[m.private_directory(i,i) for i in range(2)]
        if dirs[0].stat().st_dev==dirs[1].stat().st_dev:raise RuntimeError('same filesystem')
        workers=[create(LABEL+'-'+str(i),d,CODE) for i,d in enumerate(dirs)]
        for cid in workers:run(['docker','start',cid])
        for cid in workers:
            rc=run(['docker','wait',cid]).strip();logs=run(['docker','logs',cid])
            info=json.loads(run(['docker','inspect',cid]))[0]
            if rc!='0' or info['State']['OOMKilled'] or ':container_t:' not in info['ProcessLabel']:raise RuntimeError('container test '+logs)
            result['cases'].append(dict(name='parallel-io-enospc',result=json.loads(logs),security=info['ProcessLabel']))
        try:m.assert_unused(m.state['volumes'][0])
        except RuntimeError as e:
            if 'container still references mount' not in str(e):raise
            result['cases'].append(dict(name='stopped-reference-refusal',status='PASS'))
        else:raise RuntimeError('reference not refused')
        for cid in list(workers):remove(cid)
        m.teardown(False);m.remount()
        for d in dirs:
            if (d/'durable').read_bytes()!=b'ckernel-fs-domain-persistence':raise RuntimeError('remount persistence')
        result['cases'].append(dict(name='clean-unmount-fsck-remount',status='PASS'))
        cid=create(LABEL+'-bad-start',dirs[0],'','/ckfs-no-such-program')
        p=subprocess.run(['docker','start',cid],capture_output=True,text=True)
        if not p.returncode:raise RuntimeError('bad entrypoint accepted')
        result['cases'].append(dict(name='start-failure',rc=p.returncode,stderr=p.stderr[-700:]));remove(cid)
        cid=create(LABEL+'-bad-exit',dirs[1],"import sys;sys.exit(17)")
        run(['docker','start',cid]);rc=run(['docker','wait',cid]).strip()
        if rc!='17':raise RuntimeError('exit fixture')
        result['cases'].append(dict(name='abnormal-exit',expected_rc=17,status='PASS'));remove(cid)
        m.teardown(True);m.close();m=None
        broken=Manager(ROOT/'injected-mount-failure',True)
        original=broken.command
        def injected(args,timeout=120):
            if args[0]=='mount':raise RuntimeError('injected mount failure before mount')
            return original(args,timeout)
        broken.command=injected
        try:
            try:broken.create_volumes(specs[:1])
            except RuntimeError as e:
                if str(e)!='injected mount failure before mount':raise
            else:raise RuntimeError('fault not injected')
            broken.command=original;broken.teardown(True)
            result['cases'].append(dict(name='mount-failure-recovery',status='PASS'))
        finally:broken.close()
        result['status']='PASS'
    except BaseException as e:result['error']=repr(e);raise
    finally:
        for cid in list(ids):remove(cid)
        if m:
            try:m.teardown(True)
            finally:m.close()
        result.update(elapsed_ns=time.monotonic_ns()-begin,
            environment_unchanged=boot==Path('/proc/sys/kernel/random/boot_id').read_text().strip() and run(['getenforce']).strip()=='Enforcing',
            remaining_containers=run(['docker','ps','-aq','--filter','label=wb.native='+LABEL]).split(),
            loop_devices=json.loads(run(['losetup','--json','--list'])))
        save(ROOT/'result.json',result);print(json.dumps(result))

if __name__=='__main__':main()
