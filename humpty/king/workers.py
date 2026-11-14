"""humpty.king.workers — stateless worker pools (FR-14/FR-17, M3).

A worker is a *stateless* loop: claim a job from the FR-14 queue, run it,
write results + events through the DB, exit or continue. No worker owns
in-memory pipeline state; everything coordinating lives in the DB (the
whitepaper's single-source-of-truth rule). Any worker can die at any point —
the queue's attempts/max_attempts re-queues the job.

Kinds:
    develop  — one ready function needs candidates (FR-4; LLM seam injected)
    fix      — one divergent candidate needs repair (FR-5, humpty.men.fixer)
    fuzz     — one candidate needs a differential campaign (FR-6, harness)

The fuzzer runs the libFuzzer binary as a subprocess (it must — it is a C
harness); develop/fix call the injected LLM seam. All three run the same
``Worker.run_forever`` shape, so SLURM array jobs template over kind.
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
from typing import Callable

from humpty.db.session import session_scope
from humpty.king.metrics import json_logger
from humpty.king.queue import Queue, QueueError

__all__ = ["Worker", "run_fuzz_job"]

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class Worker:
    def __init__(self, *, url: str, worker_id: str, llm_source=None,
                 fuzz_budget_s: int = 30, poll_interval_s: float = 1.0,
                 log=None):
        from humpty.king.queue import Queue  # deferred: queue needs url
        self.queue = Queue(sessionmaker=None, worker_id=worker_id, url=url)
        self._S = __import__("sqlalchemy").orm.sessionmaker(bind=__import__(
            "sqlalchemy").create_engine(url))
        self._url = url
        self.llm_source = llm_source
        self.fuzz_budget_s = fuzz_budget_s
        self.poll_interval_s = poll_interval_s
        self.log = log or json_logger(f"worker:{worker_id}")

    def handle(self, kind: str, payload: dict) -> None:
        """Dispatch one claimed job. Public so tests can drive one job."""
        if kind == "fuzz":
            run_fuzz_job(payload, budget_s=self.fuzz_budget_s, log=self.log)
        elif kind == "fix":
            from humpty.men.fixer import fix
            with session_scope(self._sf()) as s:
                fix(s, function_id=payload["function_id"],
                    llm_source=self.llm_source)
        elif kind == "develop":
            # the developer seam is injected; the mechanical path (stub) is
            # cegis.stub_develop — production wires Pydantic AI here.
            raise NotImplementedError(
                "develop worker requires an injected llm_source (gateway "
                "currently down; the deterministic path runs leaf_loop)")
        else:
            raise QueueError(f"unknown job kind {kind!r}")

    def _sf(self):
        return self._S()

    def run_forever(self, kinds=("develop", "fix", "fuzz")) -> None:
        while True:
            claim = self.queue.claim(kinds=kinds)
            if claim is None:
                time.sleep(self.poll_interval_s)
                continue
            self.log("claimed", kind=claim.kind, job=claim.job_id,
                     attempt=claim.attempt)
            try:
                self.handle(claim.kind, claim.payload)
                self.queue.complete(claim.job_id)
            except Exception as e:  # noqa: BLE001 — worker must survive
                self.log("failed", kind=claim.kind, job=claim.job_id,
                         error=str(e)[:300])
                self.queue.fail(claim.job_id, str(e))


def run_fuzz_job(payload: dict, *, budget_s: int, log) -> None:
    """One fuzz campaign against the candidate .so (FR-6). Persists the
    FuzzRun row + counterexamples via harness_driver."""
    sys.path.insert(0, os.path.join(ROOT, "horses", "src"))
    import harness_driver as hd  # noqa: E402

    src = payload.get("candidate_src")
    if src:
        hd.write_candidate(src)
    r = hd.run_fuzz(budget_s=budget_s)
    for ce in r.counterexamples:
        hd.persist_counterexample(ce.as_input())
    log("fuzz_done", divergent=r.divergent, execs=r.execs,
        wall_s=round(r.wall_s, 1))
