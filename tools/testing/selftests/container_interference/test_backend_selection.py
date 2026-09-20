# SPDX-License-Identifier: GPL-2.0
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from collector_audit import audit
from session import validate
from source_switches import expected_fields
import test_prototype


class BackendSelection(unittest.TestCase):
    def test_control_scope_and_bounds(self):
        req=dict(version=1,op='start',collector='slub',targets=['1:2'],nonce='test',
                 backend=dict(cache='dentry',nodes=[0,1]))
        self.assertEqual(validate(req),req)
        for b in (None,{},dict(cache='../dentry',nodes=[]),dict(cache='x'*64,nodes=[]),
                  dict(cache='dentry',nodes=[True]),dict(cache='dentry',nodes=[0,0]),
                  dict(cache='dentry',nodes=[1024]),dict(cache='dentry',nodes=list(range(9)))):
            with self.assertRaises(ValueError): validate(dict(req,backend=b))
        for collector in ('counter','ip','alloc_backend','allocator'):
            with self.assertRaises(ValueError): validate(dict(req,collector=collector))
        self.assertEqual(validate(dict(req,collector='alloc_backend',backend=dict(cache='filp',nodes=[])))['backend']['cache'],'filp')

    def test_worker_canonical_parser(self):
        include=Path(__file__).resolve().parents[3]/'container_interference/include'
        code=r'''
#include <assert.h>
#include "cis_backend_selection.h"
int main(void) {
    char output[160];
    assert(!cis_parse_backend("a:kmalloc-192:*",output));
    assert(!strcmp(output,"kmalloc-192 *\n"));
    assert(!cis_parse_backend("a:dentry:0,7",output));
    assert(!strcmp(output,"dentry 0,7\n"));
    const char *bad[]={"a:","a::0","a:a:","a:a:0,","a:a:00","a:a:+0",
        "a:a:-1","a:a:1024","a:a:0,0","a:../a:*","a:a:*\n", "a:a:1e1",
        "a:a:0,1,2,3,4,5,6,7,8","a:a:999999999999999999999"};
    for (unsigned i=0;i<sizeof(bad)/sizeof(bad[0]);i++) assert(cis_parse_backend(bad[i],output));
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as d:
            binary=str(Path(d)/'selection')
            subprocess.run([os.environ.get('CC','cc'),'-Wall','-Wextra','-Werror','-I'+str(include),'-x','c','-','-o',binary],input=code,text=True,check=True)
            subprocess.run([binary],check=True)

    def test_readback_required_and_cannot_silently_use_boot_default(self):
        r=test_prototype.Explanations().record()
        r.update(collector='slub',backend_selection=dict(cache='dentry',nodes=[0]))
        def run(details):
            raw='\n'.join(json.dumps(dict(session_id=r['session_id'],kind=k,detail=v)) for k,v in details).encode()
            return audit(r,raw)
        selected='protocol=1 lease=1 readback=1 cache=dentry nodes=0 node_scope=slub_lock_only allocation_release_scope=whole_selected_cache'
        rows=[('backend_source_filter',selected),('backend_source_filter_closed','lease=0 close_after_detach=1')]
        self.assertNotIn('backend_selection_invalid',run(rows)['errors'])
        for wrong in (rows[:1],rows+rows,[(rows[0][0],selected.replace('cache=dentry','cache=filp')),rows[1]],
                      [('backend_source_filter','protocol=1 lease=0 legacy_boot_selection=1')]):
            self.assertIn('backend_selection_invalid',run(wrong)['errors'])

    def test_actual_source_filter_must_be_absent_at_idle(self):
        self.assertEqual(expected_fields('15',None)['backend_filter'],'0')
        for name in ('slub','allocator','alloc_backend'):
            self.assertEqual(expected_fields('15',name)['backend_filter'],'1')
        self.assertEqual(expected_fields('15','counter')['backend_filter'],'0')
