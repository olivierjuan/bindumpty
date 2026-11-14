"""humpty.king.worker_main — entry point for one stateless worker process.

The SLURM array template (sandbox/slurm/worker_array.sbatch) runs
``python -m humpty.king.worker_main --kind fix --worker-id slurm-...``.
The worker claims from the FR-14 queue, runs its jobs, and exits when the
queue drains (SLURM re-launches via the array).

Develop jobs need an LLM endpoint; when ANTHROPIC_* env is absent the
worker refuses develop jobs (the deterministic path is leaf_loop).
"""
from __future__ import annotations

import argparse
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--kind", required=True, choices=["develop", "fix", "fuzz"])
    ap.add_argument("--worker-id", required=True)
    ap.add_argument("--max-jobs", type=int, default=0, help="0 = run until queue drains")
    args = ap.parse_args()

    url = os.environ.get("HUMPTY_DB_URL")
    if not url:
        print("worker_main: HUMPTY_DB_URL is required", file=sys.stderr)
        return 2

    from humpty.king.workers import Worker

    llm_source = None
    if args.kind == "develop":
        token = os.environ.get("ANTHROPIC_AUTH_TOKEN")
        base = os.environ.get("ANTHROPIC_BASE_URL")
        if not (token and base):
            print("develop worker: no ANTHROPIC_* env — refusing develop jobs",
                  file=sys.stderr)
            return 2
        from humpty.men.develop import make_llm_source
        llm_source = make_llm_source()

    w = Worker(url=url, worker_id=args.worker_id, llm_source=llm_source)
    log = w.log
    log("worker_start", kind=args.kind, worker=args.worker_id)
    n = 0
    while args.max_jobs == 0 or n < args.max_jobs:
        claim = w.queue.claim(kinds=(args.kind,))
        if claim is None:
            break
        try:
            w.handle(claim.kind, claim.payload)
            w.queue.complete(claim.job_id)
            n += 1
        except Exception as e:  # noqa: BLE001
            log("job_failed", job=claim.job_id, error=str(e)[:300])
            w.queue.fail(claim.job_id, str(e))
            break
    log("worker_done", processed=n)
    return 0


if __name__ == "__main__":
    sys.exit(main())
