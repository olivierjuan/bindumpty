# tracing/frida

Reserved for standalone Frida agent scripts (the FR-3 production route).

**Why empty:** the working agent lives inline in `../record_frida.py`
(`AGENT_TEMPLATE`) — it needs no separate file to run. On this host, calling
functions in a *parked main PIE* via Frida `NativeFunction` faults (2026-11-14,
Frida 17.26.3; see `../README.md` Host note), so the in-place route is
re-exercised at M2+ against a real normally-loaded binary. When it is, the
agent generalizes here (per-ABI call templates, memory-write capture for
FR-9).
