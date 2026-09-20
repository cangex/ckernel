# SPDX-License-Identifier: GPL-2.0
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

class BoundedReportBatch(unittest.TestCase):
    def test_exact_records_flush_and_fail_closed(self):
        source=Path(__file__).resolve().parents[3]/'container_interference'
        code=r'''
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cis.h"
uint64_t cis_clock_ns(void) { return 123; }
const char *cis_state_name(enum cis_state s) { (void)s;return "TEST"; }
int main(void) {
    struct cis_context *a=calloc(1,sizeof(*a)),*b=calloc(1,sizeof(*b));
    FILE *fa=tmpfile(),*fb=tmpfile();char x[512],y[512];int nx,ny;
    assert(a && b && fa && fb);a->output_fd=fileno(fa);b->output_fd=fileno(fb);
    b->session_collector=17;a->output_limit=b->output_limit=1<<20;
    for(int i=0;i<300;i++) {
        char detail[100];snprintf(detail,sizeof(detail),"i=%d quoted=\"value\"",i);
        cis_report(a,"CPU_POINT",NULL,detail);cis_report(b,"CPU_POINT",NULL,detail);
        if(i%9==0) cis_report_flush(b);
    }
    cis_report_flush(b);assert(!a->output_error && !b->output_error && !b->report_used);
    assert(a->output_bytes==b->output_bytes);rewind(fa);rewind(fb);
    do {nx=fread(x,1,sizeof(x),fa);ny=fread(y,1,sizeof(y),fb);assert(nx==ny && !memcmp(x,y,nx));} while(nx);
    b->output_fd=-1;cis_report(b,"CPU_POINT",NULL,"tail");cis_report_flush(b);
    assert(b->output_error==EBADF && b->dropped==1);
    memset(b,0,sizeof(*b));b->session_collector=17;b->output_fd=fileno(fb);b->output_limit=1;
    cis_report(b,"CPU_POINT",NULL,"oversized");assert(b->output_error==EFBIG && !b->report_used && !b->output_bytes);
    fclose(fa);fclose(fb);free(a);free(b);return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            binary=str(Path(directory)/'report-batch')
            subprocess.run([os.environ.get('CC','cc'),'-Wall','-Wextra','-Werror','-I'+str(source/'include'),
                '-x','c','-',str(source/'report.c'),'-o',binary],input=code,text=True,check=True)
            subprocess.run([binary],check=True)
