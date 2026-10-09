"""Strict action and paired-environment checks; never substitute for official grading."""
import re

CORE_ERRORS = {
    'call_4': ('InterpreterError:', 'Import from inspect_file_as_text is not allowed'),
    'call_24': ('InterpreterError:', "Cannot assign to name 'final_answer'"),
}


def check_actions(workload, actions, historical):
    issues = []
    count = 19 if workload == 'core' else 6
    if len(actions) != count or len(historical) != count:
        return ['unexpected action count']
    previous_end = None
    for actual, expected in zip(actions, historical):
        if actual.get('id') != expected.get('id') or actual.get('kind') != expected.get('kind'):
            issues.append('action identity/order mismatch')
        start, end = actual.get('start_ns'), actual.get('end_ns')
        if type(start) is not int or type(end) is not int or end <= start:
            issues.append('invalid action interval')
        elif previous_end is not None and start < previous_end:
            issues.append('overlapping sequential actions')
        if type(end) is int:
            previous_end = end
        if workload == 'core':
            if 'error' not in actual or not isinstance(actual.get('logs'), str):
                issues.append('missing interpreter evidence')
            tokens = CORE_ERRORS.get(expected['id'])
            error = actual.get('error')
            if tokens:
                if not isinstance(error, str) or not all(t in error for t in tokens):
                    issues.append('wrong expected error: ' + expected['id'])
            elif error is not None:
                issues.append('unexpected interpreter error: ' + expected['id'])
            if actual.get('matched') is not True:
                issues.append('replayer rejected action')
            actual_codes = re.findall(r'Exit Code: (\d+)', actual.get('logs', ''))
            expected_codes = re.findall(r'Exit Code: (\d+)', expected.get('logs', ''))
            if actual_codes != expected_codes:
                issues.append('nested shell exit mismatch: ' + expected['id'])
        elif workload == 'go':
            if expected.get('kind') == 'execute_bash':
                if actual.get('source_command') != expected.get('source_command'):
                    issues.append('source command changed')
                if actual.get('exit_code') != expected.get('exit_code'):
                    issues.append('unexpected shell exit')
                if expected.get('exit_code') == 127 and 'command not found' not in actual.get('output', ''):
                    issues.append('127 without missing-command evidence')
        else:
            raise ValueError('unsupported workload')
    return issues


def check_pair(baseline, candidate):
    issues = []
    for key in ('config_sha256', 'runtime_sha256', 'image_id', 'trace_sha256',
                'layout_sha256', 'initial_state_sha256', 'storage_backend', 'cpu_budget',
                'memory_budget', 'security_policy_sha256'):
        if not baseline.get(key) or baseline.get(key) != candidate.get(key):
            issues.append('missing or unequal ' + key)
    for record in (baseline, candidate):
        if record.get('selinux') != 'Enforcing' or record.get('apparmor') is not False:
            issues.append('wrong security state')
        if record.get('oom') is not False or type(record.get('exit_code')) is not int or record['exit_code'] != 0:
            issues.append('execution unsuccessful or unknown')
        if record.get('official_grade') != 'PASS':
            issues.append('official grading not passed')
        if record.get('capacity_admitted') is not True:
            issues.append('capacity not admitted')
    return issues
