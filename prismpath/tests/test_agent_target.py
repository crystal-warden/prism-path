# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""`prismpath policy compile --target agent` runs the governed agent's own checks at compile time, on the line each
one is about (prismpath/agent/target.py)."""
import re
import subprocess
import sys
from pathlib import Path

import pytest

from prismpath.agent import target
from prismpath.kernel import policy_source as ps

ROOT = Path(__file__).resolve().parents[2]
GUIDE = ROOT / "docs" / "guides" / "writing-agent-rules.md"
FIELDS = ("---\nfield.tool: category\nfield.path_scope: category\nfield.command_class: category\nfield.git_op: category\n"
          "field.path_control: bool\nfield.net_dest: category\n---\n## core_decision\n")
SAFE = ('-> refuse agent:control-write: when path_control\n'
        '-> refuse agent:net-refused: when tool == "connect" or net_dest != "none"\n')


def _found(text):
    compiled = ps.compile_full(text)
    return [(target.line_of(where, compiled.field_lines, compiled.rule_lines), message)
            for where, message in target.check(compiled.image)]


def test_a_policy_that_refuses_control_changes_and_connections_passes():
    assert _found(FIELDS + SAFE + '-> allow: when tool == "read_file" and path_scope == "workspace"\n') == []


def test_a_value_outside_the_reading_domain_is_named_on_its_rule_line():
    found = _found(FIELDS + SAFE + '-> allow: when tool == "readfile" and path_scope == "workspace"\n'
                   '-> allow: when path_scope == "workspce"\n')
    assert found == [(12, "a rule names tool 'readfile', which is outside the field's reading domain "
                          "(policy:out-of-domain)"),
                     (13, "a rule names path_scope 'workspce', which is outside the field's reading domain "
                          "(policy:out-of-domain)")]


def test_a_field_the_classifier_does_not_read_is_named_on_its_declaration():
    text = FIELDS.replace("field.path_control: bool", "field.path_controll: bool") + SAFE.replace(
        "when path_control", "when path_controll") + "-> allow: always\n"
    found = _found(text)
    assert (6, "the agent's classifier reads no field path_controll, so every call would be refused as a contract "
               "violation (route:contract-violation)") in found
    assert any(line == 0 and "declares no path_control field" in message for line, message in found)


def test_a_field_of_another_kind_is_named():
    found = _found(FIELDS.replace("field.path_control: bool", "field.path_control: category") +
                   '-> refuse agent:control-write: when path_control == "yes"\n-> allow: never\n')
    assert (6, "the agent's classifier gives path_control as a bool, not a category") in found


def test_a_policy_that_lets_a_control_change_or_a_connection_through_is_named_on_its_field():
    found = _found(FIELDS + '-> allow: when tool == "write_file" and path_scope == "workspace"\n'
                   '-> allow: when tool == "connect"\n')
    assert [line for line, _m in found] == [6, 7]
    assert "does not refuse a change to a control file" in found[0][1] and "agent:control-write" in found[0][1]
    assert "does not refuse a connection" in found[1][1] and "agent:net-refused" in found[1][1]


def test_missing_required_fields_are_each_named():
    found = _found("---\nfield.tool: category\n---\n## core_decision\n-> allow: when tool == \"read_file\"\n")
    named = [re.search(r"declares no (\w+) field", message).group(1) for _line, message in found]
    assert named == ["path_scope", "command_class", "git_op", "path_control", "net_dest"]


def test_a_route_the_agent_does_not_act_on_is_named_on_its_rule():
    found = _found(FIELDS + SAFE + "-> elsewhere: always\n")
    assert found == [(12, "the agent acts on allow, refuse and escalate only, not the route elsewhere")]


def test_a_starter_passes():
    text = (ROOT / "prismpath" / "agent" / "policy" / "agent_review.rules.md").read_text(encoding="utf-8")
    assert target.check(ps.compile_source(text)) == []


@pytest.mark.skipif(not GUIDE.is_file(), reason="the guide is not in this tree")
def test_the_guides_first_example_passes(tmp_path):
    text = GUIDE.read_text(encoding="utf-8").split("## The file", 1)[1].split("```\n", 2)[1]
    source = tmp_path / "my_rules.rules.md"
    source.write_text(text, encoding="utf-8")
    out = tmp_path / "my_rules.core.json"
    run = subprocess.run([sys.executable, "-m", "prismpath", "policy", "compile", "--target", "agent", str(source),
                          "-o", str(out)], capture_output=True, text=True, cwd=ROOT)
    assert run.returncode == 0, run.stderr
    assert out.read_bytes() == ps.compile_source(text) + b"\n"


def test_the_command_line_writes_nothing_when_a_check_fails(tmp_path):
    source = tmp_path / "bad.rules.md"
    source.write_text(FIELDS + SAFE + '-> allow: when tool == "readfile"\n', encoding="utf-8")
    out = tmp_path / "bad.core.json"
    run = subprocess.run([sys.executable, "-m", "prismpath", "policy", "compile", "--target", "agent", str(source),
                          "-o", str(out)], capture_output=True, text=True, cwd=ROOT)
    assert run.returncode == 2 and not out.exists()
    assert f"{source}:12: a rule names tool 'readfile'" in run.stderr
    plain = subprocess.run([sys.executable, "-m", "prismpath", "policy", "compile", str(source), "-o", str(out)],
                           capture_output=True, text=True, cwd=ROOT)
    assert plain.returncode == 0 and out.exists()
