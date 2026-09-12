# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Unit tests for SprintConfig dataclass and from_env factory method."""

import pytest
from prismpath.orchestration.run_sprint import SprintConfig


def test_sprint_config_explicit_instantiation(tmp_path):
    proj_dir = str(tmp_path / "test_proj")
    config = SprintConfig(
        proj=proj_dir,
        nudge="build a feature",
        seconds=120,
        max_new=5000,
        extend=True,
    )
    assert config.proj == proj_dir
    assert config.nudge == "build a feature"
    assert config.seconds == 120
    assert config.max_new == 5000
    assert config.extend is True
    assert config.gate == "browser"


def test_sprint_config_from_env(tmp_path, monkeypatch):
    proj_dir = str(tmp_path / "env_proj")
    monkeypatch.setenv("SPRINT_PROJ", proj_dir)
    monkeypatch.setenv("SPRINT_NUDGE", "environment goal")
    monkeypatch.setenv("SPRINT_GATE", "browser")
    monkeypatch.setenv("SPRINT_SECONDS", "300")
    monkeypatch.setenv("SPRINT_EXTEND", "1")
    monkeypatch.setenv("SPRINT_LEDGER", "1")
    monkeypatch.setenv("LLM_MODEL", "custom-gemma")

    config = SprintConfig.from_env()
    assert config.proj == proj_dir
    assert config.nudge == "environment goal"
    assert config.seconds == 300
    assert config.extend is True
    assert config.ledger is True
    assert config.llm_model == "custom-gemma"


def test_sprint_config_from_env_missing_proj_raises_key_error(monkeypatch):
    monkeypatch.delenv("SPRINT_PROJ", raising=False)
    with pytest.raises(KeyError):
        SprintConfig.from_env()
