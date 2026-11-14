"""Tests for humpty.men.cache — NFR-6 response cache.

The invariant under test: the cache is content-addressed by
(model, seed, normalized prompt); identical triples roundtrip, any changed
component misses, disabled mode never persists or serves, and concurrent
puts (M3 workers) all survive in the shared file.
"""
import hashlib
import json
import threading

import pytest

from humpty.men.cache import LLMResponseCache
from humpty.men.fixer import normalize_source


def _expected_key(prompt: str, model: str, seed: int | str) -> str:
    return hashlib.sha256(
        f"{model}\x00{seed}\x00{normalize_source(prompt)}".encode()
    ).hexdigest()


def test_put_get_roundtrip(tmp_path):
    cache = LLMResponseCache(tmp_path)
    cache.put("def f():\n    return 1", "api/strong", 7, "RESP")
    assert cache.get("def f():\n    return 1", "api/strong", 7) == "RESP"
    # A fresh instance over the same dir reads the persisted file.
    assert LLMResponseCache(tmp_path).get(
        "def f():\n    return 1", "api/strong", 7) == "RESP"


def test_key_ignores_prompt_whitespace(tmp_path):
    # Same key contract: normalization strips per-line indentation and blank
    # lines (intra-line spacing is significant).
    cache = LLMResponseCache(tmp_path)
    cache.put("def f():\n    return 1", "api/strong", 7, "RESP")
    assert cache.get("\n\ndef f():\n        return 1\n", "api/strong", 7) == "RESP"


def test_different_seed_miss(tmp_path):
    cache = LLMResponseCache(tmp_path)
    cache.put("def f():\n    return 1", "api/strong", 7, "RESP")
    assert cache.get("def f():\n    return 1", "api/strong", 8) is None


def test_different_model_miss(tmp_path):
    cache = LLMResponseCache(tmp_path)
    cache.put("def f():\n    return 1", "api/strong", 7, "RESP")
    assert cache.get("def f():\n    return 1", "api/cheap", 7) is None


def test_different_prompt_miss(tmp_path):
    cache = LLMResponseCache(tmp_path)
    cache.put("def f():\n    return 1", "api/strong", 7, "RESP")
    assert cache.get("def g():\n    return 2", "api/strong", 7) is None


def test_disabled_mode_noop(tmp_path):
    cache = LLMResponseCache(tmp_path, enabled=False)
    cache.put("def f():\n    return 1", "api/strong", 7, "RESP")
    assert cache.get("def f():\n    return 1", "api/strong", 7) is None
    # Nothing was written to disk.
    assert not (tmp_path / "responses.json").exists()


def test_on_disk_layout_is_model_seed_normalized_prompt(tmp_path):
    cache = LLMResponseCache(tmp_path)
    cache.put("def f():\n    return 1", "api/strong", 7, "RESP")
    entries = json.loads((tmp_path / "responses.json").read_text())
    assert entries == {
        _expected_key("def f():\n    return 1", "api/strong", 7): "RESP"
    }


def test_concurrent_puts_all_persisted(tmp_path):
    n_threads = 10
    cache = LLMResponseCache(tmp_path)
    barrier = threading.Barrier(n_threads)

    def worker(i: int) -> None:
        barrier.wait()
        cache.put(f"def f{i}():\n    return {i}", "api/strong", i, f"RESP-{i}")

    threads = [threading.Thread(target=worker, args=(i,))
               for i in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    entries = json.loads((tmp_path / "responses.json").read_text())
    assert len(entries) == n_threads
    for i in range(n_threads):
        assert cache.get(f"def f{i}():\n    return {i}", "api/strong", i) == f"RESP-{i}"
