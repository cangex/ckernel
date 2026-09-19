# SPDX-License-Identifier: GPL-2.0
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from session import validate


class ObjectSelection(unittest.TestCase):
    def test_control_requires_explicit_bounded_selection(self):
        req=dict(version=1,op='start',collector='rwsem',targets=['1:2'],nonce='test',objects=[0xffff000000001000])
        self.assertEqual(validate(req),req)
        for value in (None,[],[True],[0],[7],[-8],[2**64],[8,8],list(range(8,81,8))):
            with self.assertRaises(ValueError): validate(dict(req,objects=value))
        with self.assertRaises(ValueError): validate({k:v for k,v in req.items() if k!='objects'})
        with self.assertRaises(ValueError): validate(dict(req,collector='ip'))
        self.assertEqual(validate(dict(req,collector='counter'))['objects'],req['objects'])
        plain={k:v for k,v in dict(req,collector='counter').items() if k!='objects'}
        self.assertEqual(validate(plain),plain)
        with self.assertRaises(ValueError): validate(dict(req,collector='counter',objects=[]))

    def test_canonical_worker_parser(self):
        include=Path(__file__).resolve().parents[3]/'container_interference/include'
        code=r'''
#include <assert.h>
#include "cis_object_selection.h"
int main(void) {
    uint64_t objects[8]={0};
    assert(cis_parse_objects("o:ffff000000001000,ffff000000002000",objects)==2);
    assert(objects[0]==UINT64_C(0xffff000000001000));
    assert(objects[1]==UINT64_C(0xffff000000002000));
    assert(cis_parse_objects("o:",objects)<0);
    assert(cis_parse_objects("o:0000000000000000",objects)<0);
    assert(cis_parse_objects("o:ffffffffffffffff",objects)<0);
    assert(cis_parse_objects("o:-000000000000008",objects)<0);
    assert(cis_parse_objects("o:0000000000000008,",objects)<0);
    assert(cis_parse_objects("o:0000000000000008,0000000000000008",objects)<0);
    assert(cis_parse_objects("o:0000000000000008z",objects)<0);
    assert(cis_parse_objects("o:0000000000000008,0000000000000010,0000000000000018,0000000000000020,0000000000000028,0000000000000030,0000000000000038,0000000000000040,0000000000000048",objects)<0);
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as d:
            binary=str(Path(d)/'selection')
            subprocess.run([os.environ.get('CC','cc'),'-Wall','-Wextra','-Werror','-I'+str(include),'-x','c','-','-o',binary],input=code,text=True,check=True)
            subprocess.run([binary],check=True)
