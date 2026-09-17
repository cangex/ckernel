#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""A release is bound to collectors, not the word DIAG in an old log."""
import hashlib
import json
import math
import re

REQUIRED = {'metrics', 'kernel_ip', 'psi_alert', 'owner_mutex', 'owner_dentry'}


def fingerprint(profile):
    return hashlib.sha256(json.dumps(profile, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def collector_gate(report, profile, diagnostic=False):
    if not isinstance(report, dict) or not isinstance(profile, dict) or profile.get('version') != 1:
        return False
    collectors = profile.get('collectors')
    if (not isinstance(collectors, list) or any(not isinstance(x, str) for x in collectors) or
            len(set(collectors)) != len(collectors) or not REQUIRED <= set(collectors)):
        return False
    if report.get('profile_sha256') != fingerprint(profile):
        return False
    required = set(profile['collectors']) if diagnostic else {'metrics', 'kernel_ip', 'psi_alert'}
    recall = profile.get('eligible_end_to_end_recall', 0.9)
    if not isinstance(recall, (int, float)) or not math.isfinite(recall) or not 0 < recall <= 1:
        return False
    coverage = report.get('collector_coverage', {})
    if not isinstance(coverage, dict):
        return False
    for name in required:
        c = coverage.get(name, {})
        if (not isinstance(c, dict) or
                any(type(c.get(k)) is not int or c[k] < 0 for k in
                    ('eligible_episodes', 'observed_episodes', 'wrong_relations', 'evidence_protocol')) or
                c.get('status') != 'PASS' or
                c.get('eligible_episodes', 0) <= 0 or c.get('observed_episodes', 0) <= 0 or
                not recall <= c['observed_episodes']/c['eligible_episodes'] <= 1 or
                c.get('wrong_relations', 1) != 0 or c.get('evidence_protocol') != 2 or
                not isinstance(c.get('raw_sha256'), str) or not re.fullmatch('[0-9a-f]{64}', c['raw_sha256'])):
            return False
        if (diagnostic and name.startswith('owner_') and
                (type(c.get('paired_terminal_events')) is not int or c['paired_terminal_events'] <= 0)):
            return False
    return True
