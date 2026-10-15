# SPDX-License-Identifier: GPL-2.0
"""Narrow, evidence-based recovery; ambiguous thin metadata remains quarantined."""
from mount_guard import inventory


def reconcile_drained_namespace(store,backend,branch_id):
    obj=store.data['branches'][branch_id]
    if store.data['pending'] or store.data['boot']!=store.boot():
        raise RuntimeError('ambiguous operation or changed boot')
    if not obj.get('mounted') or not obj.get('active') or obj['state'] not in ('READY','ATTACHED','RUNNING','DRAINING'):
        raise RuntimeError('not a lost mounted branch')
    # Namespace inode numbers can be recycled after the controller exits.
    # The complete current device/mount/FD graph, not inode equality, decides
    # whether the registered filesystem is drained.
    backend.verify_pool()
    if inventory(obj['dev']):raise RuntimeError('filesystem still mounted')
    backend.assert_no_references(obj)
    if backend.verify_mapping(obj)['open']:raise RuntimeError('device remains open')
    backend.operation('recover_drained_namespace',obj,
        lambda:backend.run(['e2fsck','-fn','/dev/mapper/'+obj['name']]),lambda:backend.fs_header(obj))
    if backend.fs_header(obj).get('Filesystem state')!='clean':raise RuntimeError('filesystem not clean')
    obj['mounted']=False;store.save()
    backend.remove_mapping(obj)
    obj['state']='SEALED'
    obj['recovery']=dict(kind='registered filesystem unmounted; all references absent and fsck passed',
        retained_result=True,not_replayed=['create_snap','mount','delete'])
    store.save();return obj['recovery']
