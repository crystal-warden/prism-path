# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The agent's field vocabulary is said in five places, and they agree.

The classifier's docstring lists each field and its values, `profile.KNOWN_CATEGORIES` is the reading domain a
policy is loaded against, the oracle's tuples in prismpath/agent/policy.py walk the same values, the session fields
are in prismpath/agent/session_state.py, and prismpath/agent/fields.py is the reference the guide's table is
generated from (tools/gen_rules_reference.py). The cause table of the guide is the registry's routing class.
"""
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from prismpath.agent import classifier, fields, policy, profile, session_state
from prismpath.kernel import causes
from prismpath.kernel import policy_source as ps

ROOT = Path(__file__).resolve().parents[2]
STARTERS = sorted((ROOT / "prismpath" / "agent" / "policy").glob("*.rules.md"))


def _docstring_fields():
    """{name: values or None} from the field list at the top of classifier.py."""
    out = {}
    for line in classifier.__doc__.splitlines():
        match = re.match(r"^  ([a-z_]+)\s{2,}(.*)$", line)
        if match:
            rest = match.group(2)
            values = re.match(r"^([a-z_]+(?: \| [a-z_]+)+)", rest)
            out[match.group(1)] = tuple(values.group(1).split(" | ")) if values else None
    return out


def test_the_reference_lists_every_classifier_field_with_its_values():
    documented = _docstring_fields()
    session = set(session_state.FIELDS)
    assert [name for name, _k, _m in fields.FIELDS if name not in session] == list(documented)
    for name, kind, _meaning in fields.FIELDS:
        if kind == "category":
            expected = documented.get(name) or session_state.VALUES[name]
            assert fields.values(name) == expected, name
        elif name in documented:
            assert documented[name] is None, name


def test_the_reading_domain_agrees_with_the_oracle_tuples_and_the_session_fields():
    known = profile.KNOWN_CATEGORIES
    assert known["tool"] == policy._TOOLS and known["path_scope"] == policy._SCOPES
    assert known["command_class"] == policy._COMMANDS and known["git_op"] == policy._GIT_OPS
    assert known["remote_class"] == policy._REMOTES and known["net_dest"] == policy._NET_DESTS
    assert known["proc_class"] == policy._PROC_CLASSES
    for name in session_state.FIELDS:
        assert known[name] == session_state.VALUES[name]
    categories = {name for name, kind, _m in fields.FIELDS if kind == "category"}
    assert categories == set(known)
    assert set(policy._FLAGS) | {"path_control"} == {name for name, kind, _m in fields.FIELDS if kind == "bool"}


def test_every_field_a_starter_declares_is_in_the_reference_and_the_required_ones_in_every_starter():
    declared = set()
    for path in STARTERS:
        doc = ps.compile_full(path.read_text(encoding="utf-8"), str(path)).doc
        declared |= set(doc["fields"])
        for name, _why in fields.REQUIRED:
            assert name in doc["fields"], (path.name, name)
        for name, text in doc["fields"].items():
            assert fields.by_name()[name][0] == text.split()[0], (path.name, name)
    assert declared == set(fields.by_name())


def test_every_cause_a_shipped_source_names_is_one_a_rule_names():
    names = {name for _c, name, _k, _d in ps.cause_rows()}
    sources = STARTERS + sorted((ROOT / "prismpath" / "gateway" / "policy").glob("*.rules.md"))
    sources += sorted((ROOT / "integrations").glob("**/*.rules.md"))
    for path in sources:
        for cause in re.findall(r"^-> (?:refuse|escalate) (\S+?):\s", path.read_text(encoding="utf-8"), re.M):
            assert cause in names, (path.name, cause)


def test_a_rule_that_names_a_cause_a_policy_does_not_decide_compiles_with_a_warning():
    head = "---\nfield.tool: category\n---\n## core_decision\n"
    compiled = ps.compile_full(head + '-> refuse sig:missing: when tool == "x"\n-> allow: always\n')
    assert compiled.warnings == [(5, "sig:missing is a cause of the authority class, not one a policy decides, so a "
                                     "receipt would name a check that never ran. `prismpath policy causes` lists "
                                     "the causes a rule names")]
    assert ps.compile_full(head + '-> refuse agent:network: when tool == "x"\n-> allow: always\n').warnings == []


def test_policy_causes_lists_the_routing_class_and_all_with_all():
    run = lambda *extra: subprocess.run([sys.executable, "-m", "prismpath", "policy", "causes", *extra],
                                        capture_output=True, text=True, check=True).stdout
    listed = json.loads(run("--json"))
    assert {row["class"] for row in listed} == {"routing"}
    assert [row["code"] for row in listed] == sorted(code for code, (_n, k, _d) in causes.CODES.items() if k == "routing")
    assert len(json.loads(run("--all", "--json"))) == len(causes.CODES)
    assert re.search(r"^ 128  agent:control-write\s+routing\s+an agent call", run(), re.M)


TOOL = ROOT / "tools" / "gen_rules_reference.py"


@pytest.mark.skipif(not TOOL.is_file(), reason="tools/gen_rules_reference.py is not in this tree")
def test_the_guide_tables_are_the_code():
    spec = importlib.util.spec_from_file_location("gen_rules_reference", TOOL)
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    text = Path(gen.GUIDE).read_text(encoding="utf-8")
    assert gen.build(text) == text, "run: python tools/gen_rules_reference.py"
