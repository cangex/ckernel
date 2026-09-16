AppArmor policy fixtures
========================

Use only in the disposable diagnostic guest. Do not load these permissive
test profiles on a host or reuse them as container security policy.

security.profile is compiled against the running guest's native feature ABI.
Its file-only profile intentionally denies signals; an absent explicit rule
is not evidence that the signal class is unmediated.

security-legacy.profile and security-reload-initial.profile use the explicit
compile feature fixture features.nopolicydb. This file is copied unmodified
from the upstream AppArmor v2.13.6 parser test suite:

https://gitlab.com/apparmor/apparmor/-/raw/v2.13.6/parser/tst/features_files/features.nopolicydb

The parser option is ``--compile-features features.nopolicydb``. Native
reference execution must first confirm the legacy fixture's allow behavior.
Replacing ckm_s_reload with security-replace.profile uses the modern guest
feature ABI and must revoke the old qualification. This tests compatibility
and invalidation, not a recommendation to downgrade production policy.

The test runner must verify actual AUDIT events for ckm_s_audit. Suppressed
console records are missing evidence, not an audit pass. Any printk rate
limit changes in the supplied harness apply only inside the disposable VM.
