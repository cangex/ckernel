"""Freeze one persistent-storage CORE guest; never run host business replay."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

W = Path('/root/ckernel-whitebox-20261009')
D = W / 'business-core-r2'
S = Path(__file__).resolve().parent
IMAGE = 'sha256:a6c098184d57a4cb8149f259e53544e2d150775f453eb74bb2f36fd59624e16d'
LABEL = 'ckwb.business=core-preparation-20261009-r1'

def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda: f.read(4*1024*1024), b''):
            h.update(block)
    return h.hexdigest()

def run(args, timeout=180):
    q = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout)
    if q.returncode:
        raise RuntimeError(str(args[:3]) + ': ' + q.stderr[-3000:])
    return q.stdout

def main():
    assert shutil.disk_usage('/').free > 6*1024**3 + 10*1024**3
    os.sched_setaffinity(0, {112,113,114,115})
    D.mkdir(exist_ok=False)
    state = {'status': 'PREPARING', 'image': IMAGE}
    cid = None
    try:
        info = json.loads(run(['docker','image','inspect',IMAGE]))[0]
        assert info['Architecture'] == 'arm64'
        env = info['Config']['Env']
        allowed = {'HTTPS_PROXY','HTTP_PROXY','http_proxy','https_proxy','PATH','LANG',
                   'GPG_KEY','PYTHON_VERSION','PYTHON_SHA256'}
        assert all(x.split('=',1)[0] in allowed for x in env), 'unreviewed image environment'
        cid = run(['docker','create','--name','ckwb-core-spec-20261009-r1','--label',LABEL,
                   '--runtime','runc','--network','none','--cpuset-cpus','112-115',
                   '--memory','4g','--memory-swap','4g','--pids-limit','128',
                   '--security-opt','no-new-privileges',IMAGE,'/bin/sleep','180']).strip()
        # Only a sleeping runtime fixture starts on the host to obtain its resolved seccomp rules.
        run(['docker','start',cid])
        specinfo = json.loads(run(['ctr','--address','/run/containerd/containerd.sock',
                                  '--namespace','moby','containers','info',cid]))
        spec = specinfo.get('Spec', specinfo.get('spec'))
        assert isinstance(spec, dict), list(specinfo)
        seccomp = spec['linux']['seccomp']
        assert seccomp['defaultAction'] == 'SCMP_ACT_ERRNO'
        (D/'docker-source-spec.json').write_text(json.dumps(spec,indent=2))
        run(['docker','stop','--time','2',cid])
        run(['docker','export','-o',str(D/'rootfs.tar'),cid])
        stage = D/'stage';stage.mkdir()
        lower = stage/'lower';lower.mkdir()
        run(['tar','--numeric-owner','-xf',str(D/'rootfs.tar'),'-C',str(lower)])
        freeze = W/'workload-freeze-r1'
        manifest = json.loads((freeze/'manifest.json').read_text())
        for name, expected in manifest['core']['inputs'].items():
            assert sha(lower/'opt/replay'/name) == expected
        assert not (lower/'workspace/results').exists()
        # Docker's marker is runtime metadata, not a business input.
        (lower/'.dockerenv').touch(exist_ok=True)
        for name in ('corebench.py','task.json','core-official-grade.py'):
            (lower/'grade').mkdir(exist_ok=True)
            shutil.copyfile(freeze/'core-grading'/name, lower/'grade'/name)
        shutil.copyfile(S/'core-historical-actions.json',lower/'grade/historical-actions.json')
        shutil.copyfile(S/'business_core_entry.py',lower/'business_core_entry.py')
        shutil.copyfile(S/'admission_checks.py',lower/'admission_checks.py')
        for name in ('upper','work','bundle/rootfs'):
            (stage/name).mkdir(parents=True)
        for name in ('proc','dev','sys','dev/pts','dev/shm'):
            (lower/name).mkdir(parents=True,exist_ok=True)
        config = json.loads((W/'runtime-input-r6/runtime_config.json').read_text())
        config['root']['readonly'] = False
        config['hostname'] = 'w1-core'
        config['process'].update(args=['python','/business_core_entry.py'],cwd='/workspace',
             env=env+['PIP_NO_INDEX=1','PIP_FIND_LINKS=/wheelhouse','TIKTOKEN_CACHE_DIR=/tiktoken-cache',
                      'HTTP_PROXY=','HTTPS_PROXY=','http_proxy=','https_proxy='],
             capabilities=spec['process']['capabilities'])
        config['linux']['seccomp'] = seccomp
        config['linux']['cgroupsPath'] = '/w1-core'
        config['linux']['resources']['memory'] = {'limit':4*1024**3,'swap':4*1024**3}
        config['linux']['resources']['pids']['limit'] = 128
        config['linux']['devices'] = []
        for name, minor in [('null',3),('zero',5),('full',7),('random',8),('urandom',9),('tty',0)]:
            major = 5 if name == 'tty' else 1
            config['linux']['devices'].append(dict(path='/dev/'+name,type='c',major=major,minor=minor,fileMode=438,uid=0,gid=0))
        config['linux']['resources']['devices'] = spec['linux']['resources']['devices']
        (stage/'bundle/config.json').write_text(json.dumps(config,indent=2))
        disk = D/'business.ext4'
        with disk.open('xb') as f:f.truncate(6*1024**3)
        run(['mke2fs','-q','-t','ext4','-F','-d',str(stage),str(disk)],timeout=300)
        guest = D/'guest.ext4'
        run(['cp','--sparse=always',str(W/'runtime-probe-r6/guest.ext4'),str(guest)])
        run(['gcc','-O2','-Wall','-Wextra','-Werror',str(S/'business_service.c'),'-lselinux','-o',str(D/'business-service')])
        recipe = D/'debugfs.txt'
        recipe.write_text('rm /init\nwrite '+str(S/'business_init.sh')+' /init\nset_inode_field /init mode 0100755\nwrite '+str(D/'business-service')+' /tests/business-service\nset_inode_field /tests/business-service mode 0100755\n')
        run(['debugfs','-w','-f',str(recipe),str(guest)])
        run(['debugfs','-R','dump /init '+str(D/'init-readback'),str(guest)])
        assert sha(D/'init-readback') == sha(S/'business_init.sh')
        state.update(status='PREPARED_NOT_ADMITTED', rootfs_export_sha256=sha(D/'rootfs.tar'),
                     guest_sha256=sha(guest), business_disk_sha256=sha(disk), config=config,
                     free_bytes=shutil.disk_usage('/').free)
    except Exception as exc:
        state['status']='FAILED';state['error']=repr(exc)
        raise
    finally:
        if cid:
            check=json.loads(run(['docker','inspect',cid]))[0]
            assert check['Config']['Labels'].get('ckwb.business')=='core-preparation-20261009-r1'
            if check['State']['Running']:run(['docker','stop','--time','2',cid])
            run(['docker','rm',cid])
        (D/'prepare-status.json').write_text(json.dumps(state,indent=2))
        print(json.dumps({'status':state['status'],'error':state.get('error')}),flush=True)

if __name__ == '__main__':main()
