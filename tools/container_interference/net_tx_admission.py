# SPDX-License-Identifier: GPL-2.0
"""Bounded VM-only native TCP queue pressure, no mutation of socket fields."""
import json
from pathlib import Path
import socket
import time


def repair(sock, budget):
    sock.setsockopt(socket.SOL_SOCKET,32,budget)  # SO_SNDBUFFORCE, test administrator only
    sock.setsockopt(socket.IPPROTO_TCP,19,1)  # TCP_REPAIR_ON
    sock.setsockopt(socket.IPPROTO_TCP,20,2)  # TCP_SEND_QUEUE


class NativeTxAdmission:
    def __init__(self,output,pair_factory):
        if not Path('/cis-disposable-vm').exists(): raise ValueError('VM-only TCP pressure')
        self.output=output; self.path=Path('/proc/sys/net/ipv4/tcp_mem')
        self.original=self.path.read_text().strip(); self.sockets=[]; self.prepared=False
        if len(self.original.split())!=3 or any(int(v)<=0 for v in self.original.split()):
            raise ValueError('unexpected TCP budget')
        (output/'tx-memory-original.json').write_text(json.dumps(dict(tcp_mem=self.original)))
        self.pair_factory=pair_factory

    def prepare(self):
        # Surpass native per-CPU accounting reserve using real retained queue memory.
        client,server=self.pair_factory(); self.sockets=[client,server]
        repair(server,16<<20); data=b'x'*65536
        for _ in range(64):
            if server.send(data,socket.MSG_DONTWAIT)!=len(data): raise ValueError('bounded native queue seed')
        stat=Path('/proc/net/sockstat').read_text()
        row=next(v.split()[1:] for v in stat.splitlines() if v.startswith('TCP:'))
        values=dict(zip(row[::2],map(int,row[1::2])))
        if values.get('mem',0)<=0: raise ValueError('TCP global budget accounting not visible')
        self.prepared=True
        (self.output/'tx-memory-seed.json').write_text(json.dumps(dict(bytes=4<<20,sockstat=stat,
            native_repair_queue=True,delivery_claim=False,tcp_mem=self.original),indent=2))

    def limit(self,enabled):
        if not self.prepared: raise ValueError('queue seed required')
        value='0 0 0' if enabled else self.original
        self.path.write_text(value)
        actual=self.path.read_text().strip()
        if actual.split()!=value.split(): raise ValueError('TCP budget readback')
        return dict(time_ns=time.monotonic_ns(),tcp_mem=actual,limited=enabled)

    def restore(self):
        self.path.write_text(self.original)
        actual=self.path.read_text().strip()
        for sock in self.sockets: sock.close()
        self.sockets.clear()
        (self.output/'tx-memory-restored.json').write_text(json.dumps(dict(tcp_mem=actual)))
        if actual.split()!=self.original.split(): raise ValueError('TCP budget restoration')
