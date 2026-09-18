# SPDX-License-Identifier: GPL-2.0
"""Keep evidence quality, safe cleanup and budget policy as separate results."""


def assess(record):
    receipt = record.get('receipt') or {}
    terminal = receipt.get('terminal') or {}
    missing, defects = [], []
    if record.get('collector_contract_error'):
        defects.append('collector_contract')
    counters = ('received', 'emitted', 'rejected', 'lost', 'owner_skipped')
    if terminal.get('valid') is not True:
        missing.append('terminal_counters')
    for key in counters:
        if type(terminal.get(key)) is not int or terminal[key] < 0:
            missing.append('terminal.' + key)
    for key in ('stop_error', 'capture_error', 'dropped', 'errors', 'output_error'):
        if type(receipt.get(key)) is not int:
            missing.append(key)
        elif receipt[key]:
            defects.append(key)
    for key in ('rejected', 'lost', 'owner_skipped'):
        if type(terminal.get(key)) is int and terminal[key] > 0:
            defects.append('terminal.' + key)
    if record.get('collector') in ('owner', 'fd', 'sched', 'reclaim', 'sync', 'counter', 'allocator', 'net'):
        producer = receipt.get('producer_recursion') or {}
        if producer.get('required') is not True or producer.get('valid') is not True:
            missing.append('producer_recursion')
        if type(producer.get('skipped')) is not int or producer['skipped'] < 0:
            missing.append('producer_recursion.skipped')
        elif producer['skipped']:
            defects.append('producer_recursion.skipped')
    budget = (record.get('budget_reason') or
              (record.get('process_cpu_budget') or {}).get('violation'))
    reason = receipt.get('reason')
    policy = reason in ('ENTRY_RATE_LIMIT', 'WORKER_CPU_LIMIT', 'DATA_LIMIT') or bool(budget)
    if record.get('objects_absent') is not True or receipt.get('stop_error') not in (None, 0):
        defects.append('cleanup_not_verified')
    if record.get('result') != 'COMPLETE' or receipt.get('result') != 'COMPLETE':
        defects.append('incomplete_window')
    if policy:
        defects.append('budget_abort')
    return dict(status='FAIL' if defects else 'BLOCKED' if missing else 'PASS',
                missing=missing, defects=defects, budget_abort=bool(policy),
                cleanup_verified=record.get('objects_absent') is True,
                terminal=terminal, reason=reason,
                interpretation='safe cleanup and policy stops do not imply complete evidence')
