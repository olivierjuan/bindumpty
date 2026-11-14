"""Integration: the FR-14 queue's SQLite fallback (BEGIN IMMEDIATE claim).

The orchestration queue must run without a PostgreSQL server too: SQLite's
single-writer model makes a `BEGIN IMMEDIATE` claim atomic (SKIP LOCKED is
meaningless with one writer), and the bus poller replaces LISTEN/NOTIFY.
This suite pins that fallback: correctness under concurrency, priority
order, retry, and the fail path.
"""
import os
import sys
import threading

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from humpty.king.queue import Queue


@pytest.fixture()
def queue(tmp_path):
    url = f"sqlite:///{tmp_path}/q.db"
    eng = create_engine(url, connect_args={"timeout": 30,
                                           "check_same_thread": False})
    q = Queue(sessionmaker(bind=eng), worker_id="seed", url=url)
    q.ensure_schema(eng)
    return q, eng


def test_priority_order(queue):
    q, eng = queue
    with sessionmaker(bind=eng)() as s:
        q.push(s, kind="fuzz", payload={"n": 1}, priority=10)
        q.push(s, kind="develop", payload={"n": 2}, priority=5)
        s.commit()
    c1 = q.claim()
    assert c1.kind == "develop"  # lower priority value first


def test_fail_requeues_until_max_attempts(queue):
    q, eng = queue
    from humpty.king.queue import Job
    with sessionmaker(bind=eng)() as s:
        j = Job(kind="fuzz", payload_json="{}", max_attempts=2)
        s.add(j)
        s.commit()
        jid = j.id
    c1 = q.claim(kinds=("fuzz",))
    assert c1 is not None and c1.attempt == 1
    q.fail(c1.job_id, "first failure")
    c = q.claim(kinds=("fuzz",))
    assert c is not None and c.attempt == 2  # re-queued with incremented attempt
    q.fail(c.job_id, "second failure")
    assert q.claim(kinds=("fuzz",)) is None  # exhausted -> failed
    with sessionmaker(bind=eng)() as s:
        from humpty.king.queue import Job as J
        assert s.get(J, jid).status == "failed"


def test_concurrent_claims_no_dupes(queue):
    q, eng = queue
    with sessionmaker(bind=eng)() as s:
        for i in range(50):
            q.push(s, kind="fuzz", payload={"n": i})
        s.commit()

    claimed, lock = [], threading.Lock()

    def worker(wid):
        qw = Queue(sessionmaker(bind=eng), worker_id=wid, url=q._url)
        while True:
            c = qw.claim(kinds=("fuzz",))
            if c is None:
                break
            with lock:
                claimed.append(c.job_id)
            qw.complete(c.job_id)

    ts = [threading.Thread(target=worker, args=(f"w{i}",)) for i in range(8)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert len(claimed) == 50, f"lost jobs: {len(claimed)}"
    assert len(set(claimed)) == 50, "duplicate claims!"
