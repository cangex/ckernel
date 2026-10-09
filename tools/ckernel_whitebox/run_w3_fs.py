"""Disposable guest crash is not a physical-device power-loss test."""
import fcntl
import json
from pathlib import Path
import shutil
import subprocess
import time
from prepare_business_core import W, run, sha

S=Path(__file__).resolve().parent
B=Path('/home/ckernel-whitebox-w3-build-r1')
D=W/'w3-fs-r4'

def check_fsck(args, code, output):
    assert code in ((0,1) if 'journal_only' in args else (0,)),(args,code,output)
    assert not any(x in output for x in ('Fix?','wrong','corrupted','IGNORED','still has errors')),output

def main():
    lock=(W/'direct-fixture.lock').open('a')
    fcntl.flock(lock.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
    assert shutil.disk_usage('/').free>8*1024**3
    build=json.loads((B/'status.json').read_text())
    D.mkdir()
    record={'status':'RUNNING','runs':{},'host_deployed':False}
    run(['gcc','-static','-O2','-Wall','-Wextra','-Werror',str(S/'w3_fs_test.c'),'-o',str(D/'test')])
    guest=D/'guest.ext4'
    run(['cp','--sparse=always',str(W/'matrix-r5/core/guest.ext4'),str(guest)])
    files={'/init':S/'w3_fs_init.sh','/tests/w3-fs-test':D/'test'}
    recipe=[]
    for target,source in files.items():
        recipe.extend(['rm '+target,f'write {source} {target}',f'set_inode_field {target} mode 0100755'])
    (D/'debugfs.txt').write_text('\n'.join(recipe)+'\n')
    run(['debugfs','-w','-f',str(D/'debugfs.txt'),str(guest)])
    for i,(target,source) in enumerate(files.items()):
        verify=D/f'verify-{i}'
        run(['debugfs','-R',f'dump {target} {verify}',str(guest)])
        assert sha(source)==sha(verify)
    try:
        for variant in ('baseline','candidate'):
            meta=build['builds'][variant]
            assert sha(meta['image'])==meta['image_sha256']
            for mode in ('clean','crash'):
                name=variant+'-'+mode
                overlay=D/(name+'.qcow2'); logpath=D/(name+'.log')
                run(['qemu-img','create','-f','qcow2','-F','raw','-b',str(guest),str(overlay)])
                command=['taskset','-c','112-115','qemu-system-aarch64','-machine','virt,accel=kvm,gic-version=3',
                    '-cpu','host','-smp','8','-m','2048','-nographic','-no-reboot','-nic','none','-kernel',meta['image'],
                    '-drive',f'file={overlay},format=qcow2,if=none,id=root','-device','virtio-blk-device,drive=root',
                    '-append','console=ttyAMA0 root=/dev/vda rw init=/init panic=-1 lsm=capability,selinux selinux=1 enforcing=1 w3mode='+mode+' w3epoch='+str(int(time.time()))]
                with logpath.open('w') as out:
                    p=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=out,stderr=subprocess.STDOUT)
                    try:
                        deadline=time.monotonic()+180
                        while p.poll() is None:
                            log=logpath.read_text(errors='replace')
                            if mode=='crash' and 'W3_CRASH_READY' in log:
                                time.sleep(0.2);p.kill();p.wait();break
                            if time.monotonic()>deadline:raise TimeoutError(name)
                            time.sleep(0.1)
                    finally:
                        if p.poll() is None:p.kill();p.wait()
                log=logpath.read_text(errors='replace')
                assert 'capability,selinux' in log
                assert not any(x in log for x in ('BUG:','WARNING:','Kernel panic','avc:  denied'))
                if mode=='clean':
                    assert p.returncode==0 and 'W3_FS_END failures=0' in log and 'W3_GUEST_END failures=0' in log
                else:
                    assert 'W3_CRASH_READY' in log
                    recovery=command.copy()
                    recovery[-1]=recovery[-1].replace('w3mode=crash','w3mode=verify')
                    recovery_log=run(recovery,timeout=180)
                    (D/(name+'-recovery.log')).write_text(recovery_log)
                    assert 'W3_RECOVERY_VERIFY_PASS' in recovery_log and 'W3_GUEST_END failures=0' in recovery_log
                    assert not any(x in recovery_log for x in ('BUG:','WARNING:','Kernel panic','avc:  denied','W3_REMOUNT_FAILED'))
                raw=D/(name+'.ext4')
                run(['qemu-img','convert','-O','raw',str(overlay),str(raw)])
                checks=[]
                for args in [['e2fsck','-E','journal_only','-p',str(raw)],['e2fsck','-f','-n',str(raw)]]:
                    q=subprocess.run(args,stdin=subprocess.DEVNULL,capture_output=True,text=True)
                    checks.append({'command':args,'exit':q.returncode,'output':q.stdout+q.stderr})
                    check_fsck(args,q.returncode,q.stdout+q.stderr)
                if mode=='crash':
                    marker=D/(name+'.marker')
                    run(['debugfs','-R',f'dump /tmp/ckwb-fs/durable {marker}',str(raw)])
                    assert marker.read_bytes()==b'CKWB_DURABLE_BEFORE_GUEST_CRASH\n'
                record['runs'][name]={'status':'PASS','image_sha256':meta['image_sha256'],'log_sha256':sha(logpath),'fsck':checks}
                raw.unlink();overlay.unlink()
                (D/'status.json').write_text(json.dumps(record,indent=2))
        record['status']='PASS'
    finally:
        if record['status']!='PASS':record['status']='FAIL'
        (D/'status.json').write_text(json.dumps(record,indent=2))
        print(json.dumps(record),flush=True)

if __name__=='__main__':main()
