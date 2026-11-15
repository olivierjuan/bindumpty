"""humpty.men.cache — NFR-6: the LLM response cache.

The CEGIS loop is deterministic given (model, seed, prompt): a repeat call
with the same triple must return the same response, so paying for it twice is
pure waste. This cache is content-addressed — the key is

    sha256(model + "\\x00" + seed + "\\x00" + normalize_source(prompt))

reusing the fixer's whitespace-insensitive source identity (NFR-6), so a
prompt that differs only in indentation or trailing blank lines hits the same
entry. The response itself is the value.

Storage is a single JSON file under a caller-supplied directory (default
``./.llm_cache``, gitignored): loaded under the lock on first use, rewritten
atomically on every put, so concurrent workers (M3) can share one instance
safely. ``enabled=False`` (or ``Config().llm_cache`` off) makes both
operations no-ops: ``get`` always misses, ``put`` discards — nothing is read
or written.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
from pathlib import Path

from humpty.men.fixer import normalize_source

__all__ = ["LLMResponseCache"]

def _default_cache_dir() -> Path:
    """The LLM cache lives in the project tree (humpty.project); the
    legacy .llm_cache is migrated on first use."""
    try:
        from humpty.project import llm_cache_dir, migrate_legacy
        migrate_legacy()
        return llm_cache_dir()
    except Exception:  # noqa: BLE001 — project dir may be unwritable
        return Path(".llm_cache")


DEFAULT_CACHE_DIR = _default_cache_dir()


class LLMResponseCache:
    """Durable, thread-safe, content-addressed LLM response cache."""

    def __init__(self, directory: str | os.PathLike | None = None,
                 enabled: bool | None = None) -> None:
        self._dir = Path(directory) if directory is not None else DEFAULT_CACHE_DIR
        if enabled is None:
            from humpty.config import Config
            enabled = Config().llm_cache
        self._enabled = enabled
        self._lock = threading.Lock()
        self._path = self._dir / "responses.json"
        self._entries: dict[str, str] | None = None

    @property
    def enabled(self) -> bool:
        """False → get() always misses and put() is a no-op."""
        return self._enabled

    def get(self, prompt: str, model: str, seed: int | str) -> str | None:
        """Return the cached response for (prompt, model, seed), or None."""
        if not self._enabled:
            return None
        with self._lock:
            entries = self._load()
            return entries.get(_key(prompt, model, seed))

    def put(self, prompt: str, model: str, seed: int | str,
            response: str) -> None:
        """Persist a response under the (prompt, model, seed) key."""
        if not self._enabled:
            return
        with self._lock:
            entries = self._load()
            entries[_key(prompt, model, seed)] = response
            self._save(entries)

    # --- internal (caller must hold self._lock) --------------------------

    def _load(self) -> dict[str, str]:
        if self._entries is None:
            try:
                self._entries = json.loads(self._path.read_text())
                if not isinstance(self._entries, dict):
                    self._entries = {}  # corrupt file: start empty
            except (OSError, ValueError):
                self._entries = {}
        return self._entries

    def _save(self, entries: dict[str, str]) -> None:
        # Atomic rewrite so a reader never sees a truncated file.
        self._dir.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(entries))
        os.replace(tmp, self._path)


def _key(prompt: str, model: str, seed: int | str) -> str:
    """sha256 of model, seed, and the normalized prompt, NUL-separated."""
    normalized = normalize_source(prompt)
    return hashlib.sha256(
        f"{model}\x00{seed}\x00{normalized}".encode()
    ).hexdigest()
