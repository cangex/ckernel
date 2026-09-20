Socket namespace and CPU-quota negative
======================================

This extends the X4 test oracle, not the production kernel algorithm.  Socket
identity remains its native cookie plus the observed socket namespace.  A task
using an FD received with SCM_RIGHTS must not replace the socket namespace with
its current network namespace.

Independent namespace truth
---------------------------

Each container reads its own network namespace FD and the socket namespace FD
returned by SIOCGSKNS, then records their inode numbers alongside SO_COOKIE.
No CIS hook supplies these values.  Fresh origin cohorts require both observed
actors and the actual socket namespace to match this independent record.
Transferred sockets retain the creator/acceptor namespace; private replacement
sockets belong to the receiving container's namespace.  Legacy cohorts without
this oracle remain readable and do not acquire namespace-validation credit.

Private-socket CPU-quota cohort
------------------------------

The frozen matrix is three paired OFF/NET rounds, with opposite order in the
middle round.  Actor0 uses cpu.max=20000/100000 and actor1 is unlimited.  Both
use distinct pre-existing TCP sockets.  Actor0 spends 80 ms of measured thread
CPU before the existing four bounded private-lock operations.  This burn never
holds a socket lock.  Its wall duration must remain below 1.2 seconds.  All work
must finish inside the original two-second observation window.

The verifier requires native throttling counters to increase only for actor0,
the measured CPU work to occur inside the window, both private sockets and both
actors to be observed, and no false cross-container lock relationship.  An
empty report cannot pass.  The cohort is labelled net_isolation, not a positive
Socket-lock recall test.  It does not claim to cover arbitrary network
backpressure or to prove the cause of production throughput loss.

No CPU guard, source limit, sampling rate, kernel algorithm or production
container quota changes.  Quota configuration exists only inside the dedicated
disposable test VM.  Build and runtime results are recorded separately.
