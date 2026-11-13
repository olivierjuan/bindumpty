"""Tests for humpty.config — defaults, override, and validation.

The invariant under test: the pipeline runs with *no* config file (every key
defaults), an override file only narrows the space, unknown keys are rejected
(a typo'd key must not silently vanish), and HUMPTY_DB_URL always wins.
"""
import os

import pytest
import yaml

from humpty.config import Config, ConfigError, load_config


def test_defaults_load_without_file(tmp_path, monkeypatch):
    monkeypatch.delenv("HUMPTY_CONFIG", raising=False)
    monkeypatch.delenv("HUMPTY_DB_URL", raising=False)
    # A nonexistent path must not be an error — defaults stand.
    cfg = load_config(tmp_path / "does_not_exist.yaml")
    assert cfg.max_iterations_k == 8
    assert cfg.candidate_count_n == 3
    assert cfg.memory_diff_granularity == "all_written"
    assert cfg.scc_policy == "indivisible"
    assert cfg.graveyard_max_per_function == 32


def test_override_applies(tmp_path, monkeypatch):
    monkeypatch.delenv("HUMPTY_DB_URL", raising=False)
    p = tmp_path / "c.yaml"
    p.write_text(yaml.safe_dump({"max_iterations_k": 3, "scc_policy": "unroll"}))
    cfg = load_config(p)
    assert cfg.max_iterations_k == 3
    assert cfg.scc_policy == "unroll"
    # Untouched keys keep defaults.
    assert cfg.candidate_count_n == 3


def test_unknown_key_rejected(tmp_path, monkeypatch):
    monkeypatch.delenv("HUMPTY_DB_URL", raising=False)
    p = tmp_path / "c.yaml"
    p.write_text(yaml.safe_dump({"max_iterations_ks": 3}))  # typo
    with pytest.raises(ConfigError, match="unknown config key"):
        load_config(p)


def test_env_db_url_wins(tmp_path, monkeypatch):
    p = tmp_path / "c.yaml"
    p.write_text(yaml.safe_dump({"db_url": "sqlite:///./file.db"}))
    monkeypatch.setenv("HUMPTY_DB_URL", "postgresql://h/db")
    cfg = load_config(p)
    assert cfg.db_url == "postgresql://h/db"


def test_humpty_config_env_respected(tmp_path, monkeypatch):
    p = tmp_path / "c.yaml"
    p.write_text(yaml.safe_dump({"candidate_count_n": 5}))
    monkeypatch.setenv("HUMPTY_CONFIG", str(p))
    monkeypatch.delenv("HUMPTY_DB_URL", raising=False)
    cfg = load_config()  # no explicit path -> reads HUMPTY_CONFIG
    assert cfg.candidate_count_n == 5


def test_invalid_value_rejected(tmp_path, monkeypatch):
    monkeypatch.delenv("HUMPTY_DB_URL", raising=False)
    p = tmp_path / "c.yaml"
    p.write_text(yaml.safe_dump({"memory_diff_granularity": "bogus"}))
    with pytest.raises(ConfigError, match="memory_diff_granularity"):
        load_config(p)


def test_negative_budget_rejected(tmp_path, monkeypatch):
    monkeypatch.delenv("HUMPTY_DB_URL", raising=False)
    p = tmp_path / "c.yaml"
    p.write_text(yaml.safe_dump({"fuzz_budget_exec": 0}))
    with pytest.raises(ConfigError, match="fuzz_budget_exec"):
        load_config(p)


def test_graveyard_weights_default_signs():
    # trace pass rate rewards, fuzz divergence rate penalizes, simplicity
    # mildly rewards.
    cfg = Config()
    w = cfg.graveyard_pareto_weights
    assert w["trace_pass_rate"] > 0
    assert w["fuzz_divergence_rate"] < 0
    assert w["simplicity"] > 0
