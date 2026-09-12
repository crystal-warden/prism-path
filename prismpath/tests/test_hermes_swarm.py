# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Tests for hermes_swarm module."""

import subprocess
import pytest
from prismpath.orchestration import hermes_swarm


def test_roles_dict():
    assert isinstance(hermes_swarm.ROLES, dict)
    expected_roles = {"architect", "coder", "test-author", "fixer", "critic"}
    assert expected_roles.issubset(set(hermes_swarm.ROLES.keys()))
    for role, text in hermes_swarm.ROLES.items():
        assert isinstance(text, str) and len(text) > 0


def test_role_home(tmp_path, monkeypatch):
    roles_dir = tmp_path / "hermes_roles"
    monkeypatch.setattr(hermes_swarm, "ROLES_DIR", roles_dir)
    assert hermes_swarm.role_home("coder") == roles_dir / "coder"


def test_remember_and_recall(tmp_path, monkeypatch):
    roles_dir = tmp_path / "hermes_roles"
    monkeypatch.setattr(hermes_swarm, "ROLES_DIR", roles_dir)

    assert hermes_swarm.recall("coder") == ""

    hermes_swarm.remember("coder", "Always check edge cases in helper functions")
    mem = hermes_swarm.recall("coder")
    assert "Always check edge cases in helper functions" in mem

    # Duplicate insertion should be deduped
    hermes_swarm.remember("coder", "Always check edge cases in helper functions")
    mem2 = hermes_swarm.recall("coder")
    assert mem2.count("Always check edge cases") == 1


def test_setup_roles(tmp_path, monkeypatch):
    roles_dir = tmp_path / "hermes_roles"
    monkeypatch.setattr(hermes_swarm, "ROLES_DIR", roles_dir)

    res = hermes_swarm.setup_roles(["coder", "architect"])
    assert res == ["coder", "architect"]
    assert (roles_dir / "coder" / "SOUL.md").exists()
    assert (roles_dir / "architect" / "SOUL.md").exists()


def test_dispatch_unknown_role():
    with pytest.raises(ValueError, match="unknown role"):
        hermes_swarm.dispatch("nonexistent_role_12345", "hello")


def test_dispatch_successful_run(tmp_path, monkeypatch):
    roles_dir = tmp_path / "hermes_roles"
    monkeypatch.setattr(hermes_swarm, "ROLES_DIR", roles_dir)

    def mock_run(cmd, env=None, capture_output=True, text=True, timeout=None):
        return subprocess.CompletedProcess(cmd, 0, stdout="Mock dispatch output", stderr="")

    monkeypatch.setattr(subprocess, "run", mock_run)
    res = hermes_swarm.dispatch("coder", "implement feature X")
    assert res == "Mock dispatch output"


def test_dispatch_failure_raises(tmp_path, monkeypatch):
    roles_dir = tmp_path / "hermes_roles"
    monkeypatch.setattr(hermes_swarm, "ROLES_DIR", roles_dir)

    def mock_run(cmd, env=None, capture_output=True, text=True, timeout=None):
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="hermes agent error details")

    monkeypatch.setattr(subprocess, "run", mock_run)
    with pytest.raises(RuntimeError, match="hermes\\[coder\\] failed rc=1"):
        hermes_swarm.dispatch("coder", "implement feature X")


def test_reflect(tmp_path, monkeypatch):
    roles_dir = tmp_path / "hermes_roles"
    monkeypatch.setattr(hermes_swarm, "ROLES_DIR", roles_dir)

    def mock_dispatch(role, prompt, timeout=150, _reflecting=False):
        return "Keep functions under twenty lines."

    monkeypatch.setattr(hermes_swarm, "dispatch", mock_dispatch)

    lesson = hermes_swarm.reflect("coder", "The file was too long")
    assert lesson == "Keep functions under twenty lines."
    assert "Keep functions under twenty lines." in hermes_swarm.recall("coder")
