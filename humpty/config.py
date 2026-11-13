"""humpty.config — pipeline configuration.

Typed config with sane defaults. The pipeline must run with *no* config file
(every key has a default); ``config/config.yaml`` (or ``HUMPTY_CONFIG``)
overrides them. Secrets are never here — the DB DSN comes from the
``HUMPTY_DB_URL`` environment variable (see humpty.db.session / alembic env).

Open decisions (WHITEPAPERS.md §9) are exposed as explicit knobs with a
documented default, so the "decide by Mx" deadline becomes a config edit plus
an ADR, not a code change.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

import yaml

__all__ = ["Config", "load_config", "ConfigError"]


class ConfigError(ValueError):
    """The config file failed validation."""


@dataclass(slots=True)
class Config:
    # --- database -------------------------------------------------------
    # Defaults to a local SQLite file; production sets HUMPTY_DB_URL
    # (PostgreSQL) — the env var always wins over this field.
    db_url: str = "sqlite:///./humpty.db"

    # --- CEGIS budget / LLM cost (NFR-6) --------------------------------
    # Cap K: max repair iterations per function before it goes FAILED
    # (the "couldn't put Humpty back again" fallback, NFR-7).
    max_iterations_k: int = 8
    # N: candidates the developer samples per ready function (FR-4).
    candidate_count_n: int = 3
    # Fuzz budget for one campaign, in executions (the "N minutes without
    # divergence" becomes a run-count; coverage plateau is an M1 refinement).
    fuzz_budget_exec: int = 100_000

    # --- "trusted" operational threshold (open decision, decide by M1) --
    # Minimum clean executions and a coverage-plateau flag before a candidate
    # can move Fuzzing -> Trusted. A divergence at any point overrides this.
    trusted_min_exec: int = 50_000
    trusted_min_coverage: float = 0.0  # fraction; 0.0 = no coverage floor in M0

    # --- memory diff (open decision, decide by M2) ----------------------
    # all_written | regions_under_this
    memory_diff_granularity: str = "all_written"

    # --- SCC / recursion (open decision, decide by M2) ------------------
    # indivisible | unroll
    scc_policy: str = "indivisible"

    # --- graveyard (open decision, decide by M3) ------------------------
    # Pareto score weights: higher is better. simplicity = lower cyclomatic
    # complexity / fewer tokens. Retention: keep the Pareto front, drop
    # dominated entries beyond this many per function.
    graveyard_pareto_weights: dict[str, float] = field(
        default_factory=lambda: {
            "trace_pass_rate": 1.0,
            "fuzz_divergence_rate": -1.0,  # lower is better
            "simplicity": 0.5,
        }
    )
    graveyard_max_per_function: int = 32

    # --- LLM ------------------------------------------------------------
    # Provider-agnostic; the client is resolved in humpty.llm. Sampling model
    # (local, vLLM) produces N candidates; the fixer model is the stronger one.
    llm_sampling_model: str = "local/vllm"
    llm_fixer_model: str = "api/strong"
    llm_cache: bool = True  # cache keyed by hash(prompt, model, seed) (NFR-6)

    # --- observability (NFR-5) ------------------------------------------
    log_level: str = "info"

    # --- validation -------------------------------------------------------
    def validate(self) -> None:
        if self.max_iterations_k < 1:
            raise ConfigError("max_iterations_k must be >= 1")
        if self.candidate_count_n < 1:
            raise ConfigError("candidate_count_n must be >= 1")
        if self.fuzz_budget_exec < 1:
            raise ConfigError("fuzz_budget_exec must be >= 1")
        if self.memory_diff_granularity not in ("all_written", "regions_under_this"):
            raise ConfigError("memory_diff_granularity: all_written | regions_under_this")
        if self.scc_policy not in ("indivisible", "unroll"):
            raise ConfigError("scc_policy: indivisible | unroll")
        if not 0.0 <= self.trusted_min_coverage <= 1.0:
            raise ConfigError("trusted_min_coverage must be in [0, 1]")


def _from_dict(cfg: Config, data: dict[str, Any]) -> None:
    valid = {f.name for f in fields(Config)}
    for key, value in data.items():
        if key not in valid:
            raise ConfigError(f"unknown config key: {key!r}")
        setattr(cfg, key, value)


def load_config(path: str | os.PathLike | None = None) -> Config:
    """Load config from ``path`` (or ``HUMPTY_CONFIG``) over the defaults.

    An absent file is not an error — the defaults stand. The returned config
    is validated.
    """
    cfg = Config()
    explicit = Path(path) if path is not None else Path(os.environ.get("HUMPTY_CONFIG", ""))
    if explicit and explicit.exists():
        data = yaml.safe_load(explicit.read_text()) or {}
        if not isinstance(data, dict):
            raise ConfigError(f"config root must be a mapping: {explicit}")
        _from_dict(cfg, data)
    # HUMPTY_DB_URL always overrides the DSN (secret out of the file).
    if os.environ.get("HUMPTY_DB_URL"):
        cfg.db_url = os.environ["HUMPTY_DB_URL"]
    cfg.validate()
    return cfg
