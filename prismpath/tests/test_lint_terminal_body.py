# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Tests for the terminal-with-body lint rule (warning when a terminal node has a non-trivial instruction body)."""
import os

from prismpath.kernel.parser import parse_file
from prismpath.kernel import analysis


HERE = os.path.dirname(__file__)
REPO_ROOT = os.path.dirname(os.path.dirname(HERE))

FIXTURE_PATH = os.path.join(HERE, "fixtures", "broken", "terminal_with_body.md")
WAZUH_TRIAGE_PATH = os.path.join(REPO_ROOT, "prismpath", "flows", "wazuh_triage.md")


def test_terminal_with_body_fires_on_broken_fixture():
    graph = parse_file(FIXTURE_PATH)
    findings = [finding for finding in analysis.analyze(graph) if finding.code == "terminal-with-body"]
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == "warning"
    assert finding.node == "end_node"
    assert "end_node" in str(finding)
    assert "threshold > 200 chars" in finding.message


def test_terminal_with_body_does_not_fire_on_wazuh_triage():
    graph = parse_file(WAZUH_TRIAGE_PATH)
    findings = [finding for finding in analysis.analyze(graph) if finding.code == "terminal-with-body"]
    assert len(findings) == 0


def test_terminal_with_body_does_not_fire_on_alert_router():
    alert_router_path = os.path.join(HERE, "fixtures", "alert_router.md")
    graph = parse_file(alert_router_path)
    findings = [finding for finding in analysis.analyze(graph) if finding.code == "terminal-with-body"]
    assert len(findings) == 0
