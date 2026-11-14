# tracing/rr

Reserved for rr deterministic-replay assets.

**Why empty:** rr/DynamoRIO require hardware performance counters (MSR);
spike S3 verified this host has `paranoid=0` and HW counters open but **no
MSR** — so the deterministic-replay route cannot run here. The verdict
(ROADMAP M0/S3): Frida is the FR-3 tracer on this host; rr assets land here
when a suitable host is available.
