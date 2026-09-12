# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Tests for the terminal-with-body lint rule (warning when a terminal node has a non-trivial instruction body)."""
import os
import pytest

from prismpath.kernel.parser import parse_file
from prismpath.kernel import analysis

from prismpath.tests._repo import repo_file

HERE = os.path.dirname(__file__)
REPO_ROOT = os.path.dirname(os.path.dirname(HERE))

FIXTURE_PATH = os.path.join(HERE, "fixtures", "broken", "terminal_with_body.md")
WAZUH_TRIAGE_PATH = os.path.join(REPO_ROOT, "prismpath", "flows", "wazuh_triage.md")


def test_terminal_with_body_fires_on_broken_fixture():
    g = parse_file(FIXTURE_PATH)
    findings = [f for f in analysis.analyze(g) if f.code == "terminal-with-body"]
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "warning"
    assert f.node == "end_node"
    assert "end_node" in str(f)
    assert "threshold > 200 chars" in f.message


def test_terminal_with_body_does_not_fire_on_wazuh_triage():
    g = parse_file(WAZUH_TRIAGE_PATH)
    findings = [f for f in analysis.analyze(g) if f.code == "terminal-with-body"]
    assert len(findings) == 0


def test_terminal_with_body_does_not_fire_on_alert_router():
    alert_router_path = str(repo_file("prismpath", "examples", "code_nodes_gemma", "alert_router.md"))
    g = parse_file(alert_router_path)
    findings = [f for f in analysis.analyze(g) if f.code == "terminal-with-body"]
    assert len(findings) == 0
