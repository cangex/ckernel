Network watch capacity protection
================================

Tools 2a8e1e92b77d87a16017c3583ac9a5ecbab7dfff ran on the unchanged
7897796a3 Image in the dedicated eight-vCPU ARM64 KVM guest. The test adds no
production hooks, changes no map/CPU/output limit and does not inject fake
trace events. Two container processes each create forty distinct native TCP
sockets, then exercise the existing native logical-lock fixture with zero
intentional hold delay. Independent cookie and operation brackets are retained.

The fixed OFF/NET matrix alternates order for three rounds: six states,
three captures. Each NET capture observed the first 64 cookies, emitted 192
records, and retained 48 rejected events after the map capacity was reached.
These are event counts, not counts of missing sockets or a population recall
estimate. All eighty cookies are independently present in the workload truth.

Every full-map capture retained PARTIAL with reason QUALITY and a FAIL
evidence-quality verdict. Lifecycle cleanup completed, not the observation.
No socket relationships are admitted by the
specialist or unified report. The capacity protection result is PASS only
because rejection is explicit, cleanup is verified and the same two processes
each execute forty additional successful operations after source detach.
Native source counters do not increase during those post-detach operations.

Maximum combined-process CAPTURING CPU was 10235170ns, below the unchanged
40000000ns guard. Maximum process CPU through reporting was 119504550ns,
and peak combined RSS was 36655104 bytes. These do not account for all
business-context callbacks or asynchronous kernel work.

Independent replay passed all six states. This validates the Socket watch-map
capacity boundary, not the skb/pending maps, event-rate guard or ring overflow.
It does not establish dense-network profiling acceptance. No CPU guard waiver,
source-data alteration or discarded failure was needed.

The new static workload compiled with -Wall -Wextra -Werror. Linux tests passed
618 cases (590+21+7) at the runtime revision. Prior origin/SCM_RIGHTS (18 states)
and backlog/TX (6 states) raw evidence also replays successfully with the
extended checker; those remain historical runs, not fresh runtime matrices.

Serial SHA256:
08c5f1c450ef2ec1d867f4fe8d1bbed6a9fac6b67fedd4af754eaaf844963eb9.

Remote evidence:
/dev/shm/cis-x-20260919/evidence/net-capacity-2a8e1e92b-20260920.

Use the dedicated ``net_capacity`` coverage key. Its scoped protection PASS
must not be relabelled as ``net`` ownership coverage. X7 remains incomplete
pending its other applicable resource/failure and cost-boundary validations.
