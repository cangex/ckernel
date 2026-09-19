# SPDX-License-Identifier: GPL-2.0
"""VM-only native failslab configuration with exact readback and restoration."""
import json
from pathlib import Path
from allocator_failure_check import SETTINGS


class NativeTxFault:
    def __init__(self, output):
        if not Path('/cis-disposable-vm').exists(): raise ValueError('VM-only fault injection')
        self.output = output
        self.root = Path('/sys/kernel/debug/failslab')
        self.cache = Path('/sys/kernel/slab/skbuff_fclone_cache/failslab')
        self.original = self.snapshot()
        if self.original['settings']['probability'] != '0' or self.original['cache'] not in ('0','1'):
            raise ValueError('preexisting fault configuration')
        if self.original['cache']=='1':
            command=Path('/proc/cmdline').read_text().split()
            aliases=Path('/sys/kernel/slab/skbuff_fclone_cache/aliases').read_text().strip()
            self.save('cache-config',dict(command=command,aliases=aliases))
            if 'slub_debug=A,skbuff_fclone_cache' not in command or aliases!='0':
                raise ValueError('preselected cache requires explicit unmerged VM boot configuration')
        self.save('original', self.original)

    def snapshot(self):
        return dict(settings={k: (self.root / k).read_text().strip() for k in SETTINGS},
                    cache=self.cache.read_text().strip())

    def save(self, name, value):
        (self.output / ('tx-failslab-' + name + '.json')).write_text(json.dumps(value, indent=2))

    def enable(self):
        for k, v in SETTINGS.items():
            if k != 'probability': (self.root / k).write_text(v)
        if self.cache.read_text().strip()!='1': self.cache.write_text('1')
        (self.root / 'probability').write_text(SETTINGS['probability'])
        actual = self.snapshot(); self.save('active', actual)
        if actual != dict(settings=SETTINGS, cache='1'): raise ValueError('fault configuration readback')

    def restore(self):
        (self.root / 'probability').write_text('0')
        if self.cache.read_text().strip()!=self.original['cache']:
            self.cache.write_text(self.original['cache'])
        for k, v in self.original['settings'].items():
            if k != 'probability': (self.root / k).write_text(v)
        (self.root / 'probability').write_text(self.original['settings']['probability'])
        actual = self.snapshot(); self.save('restored', actual)
        if actual != self.original: raise ValueError('fault restoration readback')
