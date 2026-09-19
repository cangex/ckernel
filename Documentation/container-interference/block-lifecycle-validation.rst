Block lifecycle negative validation
===================================

The disposable-VM ``lifecycle`` fixture adds four frozen scenarios, each with
three alternating OFF/BLOCK pairs and two container actors on separate test
devices. The native queue limit is 4096 bytes, with merges disabled. The fixture
submits a real 8192-byte bio for ``split`` and ``error``; the native block layer,
not the fixture, performs the split. The driver logs its own request address,
bio address, sector, size, entry/exit interval and status. The original bio endio
is checked once, after both children complete. Data bytes are independently
verified. No fixture calls an observation trace hook.

``plain`` submits 4096 bytes and must have one request per actor. ``split`` must
have two 4096-byte requests, two different bio heads and conserved sectors and
bytes. Request memory may be reused sequentially; matching requires the actual
request episode and driver interval, not address alone. ``error`` completes both
requests with IOERR and must preserve that status, not claim successful I/O.
``cancel`` disposes of the constructed bio BEFORE submit_bio. It must generate
neither a request nor a false waiting/blocking relation. This is explicitly NOT
an in-flight driver cancellation test.

The production collector does not gain an exact parent/child bio lifetime merely
because this fixture knows it. It continues to report request episodes, selected
billing roots, real submitters and error completions. The driver truth validates
that native splitting neither loses nor double-counts these observed requests.
It establishes no unique device blocker, physical isolation, device-saturation
causality or real-hardware service time.

The fixture serializes its own test jobs per device only to protect independent
truth buffers. That test mutex is not a measured production contention source.
Only the dedicated VM memory device is touched; no host block device is opened.
Runtime results remain UNVERIFIED until the frozen 24-state cohort passes
``block_vm_check`` and normal source-off, cleanup, CPU and memory guards.
