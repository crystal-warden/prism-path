# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The five evidence facts of the Context Cloud gate tracer as fields of information points (A5): each point declares its
fields, reads every one at its restrictive value when it cannot answer, and a policy that reads one is refused at compile
unless the point is bound."""
import json
import sqlite3
import sys
from pathlib import Path

import pytest

from prismpath.agent import fields as agent_fields
from prismpath.agent import policy as agent_policy
from prismpath.agent import profile, target
from prismpath.information import catalog, indexstatement
from prismpath.information.parsefacts import ParseFacts
from prismpath.information.projecttests import ProjectTests, TestConfig
from prismpath.information.protectedfacts import ProtectedFacts
from prismpath.kernel import policy_source as ps
from prismpath.ports.information import Change, Edit, InformationPoint

POINTS = [ParseFacts(), ProjectTests(Path("."), None), ProtectedFacts(["pkg.core"])]


def _edit(old, new, relative="pkg/mod.py"):
    return Change("pkg/mod.py", None, Edit(relative, old, new))


# --------------------------------------------------------------------------------------- the catalog
@pytest.mark.parametrize("point", POINTS, ids=lambda p: p.name)
def test_every_point_has_the_port_shape_and_a_restrictive_value_for_each_field(point):
    assert isinstance(point, InformationPoint)
    assert set(point.restrictive) == set(point.fields)
    assert all(point.restrictive[f] in point.fields[f] for f in point.fields)


def test_the_five_facts_are_fields_of_three_points_and_no_name_is_declared_twice():
    found = catalog.evidence_fields()
    assert {n: f.point for n, f in found.items()} == {
        "edit_kind": "parse", "behaviour_preserving": "parse", "tests_pass": "tests",
        "touches_protected": "cc_graph", "adds_protected_reference": "cc_graph"}
    assert sum(len(c.fields) for c in catalog.POINTS.values()) == len(found)
    assert not set(found) & set(agent_fields.by_name())


def test_the_restrictive_values_are_the_listed_ones():
    assert {n: (f.kind, f.values, f.restrictive) for n, f in catalog.evidence_fields().items()} == {
        "edit_kind": ("category", ("comment", "docstring", "annotation", "code"), "code"),
        "behaviour_preserving": ("bool", (False, True), False),
        "tests_pass": ("category", ("true", "false", "not_run"), "false"),
        "touches_protected": ("bool", (False, True), True),
        "adds_protected_reference": ("bool", (False, True), True)}


def test_a_name_that_is_no_point_is_refused():
    with pytest.raises(ValueError, match="no information point is called nope"):
        catalog.fields_of(["nope"])


# ------------------------------------------------------------------------------------ the parse point
@pytest.mark.parametrize("old,new,kind,preserved", [
    ("x = 1\n", "x = 1  # note\n", "comment", True),
    ("def f():\n    '''a'''\n    return 1\n", "def f():\n    '''b'''\n    return 1\n", "docstring", True),
    ("def f(a):\n    return a\n", "def f(a: int) -> int:\n    return a\n", "annotation", True),
    ("def f(a):\n    return a\n", "def f(a):\n    return a + 1\n", "code", False),
    ("def f():\n    t = 1\n    return t\n", "def f():\n    u = 1\n    return u\n", "code", True),   # a local renamed
    ("def f(a):\n    return a\n", "def f(b):\n    return b\n", "code", False),                      # a parameter renamed
    ("import doctest\ndef f():\n    '''a'''\n", "import doctest\ndef f():\n    '''b'''\n", "docstring", False),
])
def test_the_parse_facts_read_the_two_texts(old, new, kind, preserved):
    evidence = ParseFacts().facts(_edit(old, new), 0.1)
    assert evidence.readings == {"edit_kind": kind, "behaviour_preserving": preserved}


@pytest.mark.parametrize("change", [
    Change("a.py", None),                                         # an edit that could not be applied
    _edit("x = 1\n", "x = (\n"),                                  # the edited file does not parse
    _edit("x = (\n", "x = 1\n"),                                  # the current file does not parse
    _edit("x = 1\n", "x = 2\n", relative="notes.md"),            # not Python
    _edit("x = 1\n", "x = 1\x00\n"),                              # a null byte
    _edit(b"x = 1\n", "x = 2\n"),                                 # not text
    _edit("x = 1\n", "x = " + "(" * 5000 + "1" + ")" * 5000 + "\n"),   # too deep to read
])
def test_the_parse_point_reads_its_restrictive_values_when_it_cannot_answer(change):
    evidence = ParseFacts().facts(change, 0.1)
    assert evidence.readings == ParseFacts.restrictive and evidence.why


def test_the_parse_point_never_raises():
    class Hostile:
        raw_path = "a.py"
        config = None

        @property
        def edit(self):
            raise RuntimeError("no")

    assert ParseFacts().facts(Hostile(), 0.1).readings == ParseFacts.restrictive


# ----------------------------------------------------------------------------------- the tests point
def _project(tmp_path, body):
    root = tmp_path / "proj"
    (root / "pkg").mkdir(parents=True)
    (root / "pkg" / "mod.py").write_text("VALUE = 1\n")
    (root / "check.py").write_text(body)
    return root


def _config(timeout=30):
    return TestConfig(command=[sys.executable, "check.py"], timeout=timeout)


def test_a_point_with_no_gate_runs_nothing_and_reads_not_run(tmp_path):
    root = _project(tmp_path, "raise SystemExit(1)\n")
    evidence = ProjectTests(root, _config()).facts(_edit("a\n", "b\n"), 0.1)
    assert evidence.readings == {"tests_pass": "not_run"}


def test_the_tests_run_on_a_copy_with_the_edit_applied(tmp_path):
    root = _project(tmp_path, "import sys\nsys.path.insert(0, '.')\nfrom pkg import mod\nraise SystemExit(0 if mod.VALUE == 2 else 1)\n")
    point = ProjectTests(root, _config(), should_run=lambda change: True)
    assert point.facts(_edit("VALUE = 1\n", "VALUE = 2\n"), 0.1).readings == {"tests_pass": "true"}
    assert point.facts(_edit("VALUE = 1\n", "VALUE = 3\n"), 0.1).readings == {"tests_pass": "false"}
    assert (root / "pkg" / "mod.py").read_text() == "VALUE = 1\n"       # the project itself is never touched


def test_every_way_the_tests_cannot_be_run_reads_false(tmp_path):
    root = _project(tmp_path, "import time\ntime.sleep(30)\n")
    gate = lambda change: True      # noqa: E731
    cases = [
        ProjectTests(root, _config(timeout=1), should_run=gate).facts(_edit("a", "b"), 0.1),            # a timeout
        ProjectTests(root, TestConfig(command=["/no/such/program"]), should_run=gate).facts(_edit("a", "b"), 0.1),
        ProjectTests(root, None, should_run=gate).facts(_edit("a", "b"), 0.1),                           # no command
        ProjectTests(root, _config(), should_run=gate).facts(Change("a.py", None), 0.1),                 # no edit
        ProjectTests(root, _config(), should_run=gate).facts(_edit("a", "b", relative="../escape.py"), 0.1),
        ProjectTests(root, _config(), should_run=gate).facts(_edit("a", "b", relative="/abs.py"), 0.1),
        ProjectTests(tmp_path / "missing", _config(), should_run=gate).facts(_edit("a", "b"), 0.1),       # no project
        ProjectTests(root, _config(), should_run=lambda change: 1 / 0).facts(_edit("a", "b"), 0.1),      # the gate fails
        ProjectTests(root, _config(), should_run=gate, run=lambda *a: 1 / 0).facts(_edit("a", "b"), 0.1),  # the run fails
    ]
    assert [c.readings for c in cases] == [{"tests_pass": "false"}] * len(cases)
    assert not (tmp_path / "escape.py").exists()


def test_a_run_that_says_ok_with_anything_but_true_is_false(tmp_path):
    class Odd:
        ok = "yes"
        summary = "x"
        seconds = 0.0

    point = ProjectTests(tmp_path, _config(), should_run=lambda c: True, run=lambda *a: Odd())
    assert point.facts(_edit("a", "b"), 0.1).readings == {"tests_pass": "false"}


def test_a_gate_that_answers_anything_but_true_does_not_run_the_tests(tmp_path):
    ran = []
    point = ProjectTests(tmp_path, _config(), should_run=lambda c: "yes", run=lambda *a: ran.append(1))
    assert point.facts(_edit("a", "b"), 0.1).readings == {"tests_pass": "not_run"} and not ran


# ------------------------------------------------------------------------------- the cc_graph point
OLD = "def safe():\n    return 1\n\n\ndef guarded():\n    return 2\n\n\nclass K:\n    x = 1\n\n    def m(self):\n        return 3\n"


class Graph:
    def __init__(self, protected=(), path=(), inits=None):
        self.p, self.path, self.i = set(protected), set(path), inits or {}

    def is_protected(self, name):
        return name in self.p

    def on_protected_path(self, name):
        return name in self.path

    def class_inits(self, name):
        return self.i.get(name, [])


def _cc(protected=("pkg.mod.guarded", "pkg.mod.K"), refs=lambda change: [], graph=None, module="pkg.mod"):
    return ProtectedFacts(protected, module_of=lambda rel: module, references=refs, graph=graph)


@pytest.mark.parametrize("new,touches", [
    (OLD.replace("return 1", "return 10"), False),                  # an unprotected function
    (OLD.replace("return 2", "return 20"), True),                   # a protected function
    (OLD.replace("    x = 1\n", "    x = 9\n"), True),                # a line of a protected class outside its functions
    (OLD.replace("return 3", "return 30"), True),                   # a method under a protected class
    (OLD + "\nOTHER = 1\n", False),                                  # a new module level line
    (OLD.replace("def guarded", "def renamed"), True),             # the old side holds the protected function
])
def test_touches_protected_reads_the_changed_lines_against_the_protected_names(new, touches):
    evidence = _cc().facts(_edit(OLD, new), 0.1)
    assert evidence.readings["touches_protected"] is touches


def test_a_change_in_a_protected_module_touches():
    assert _cc(protected=("pkg.mod",)).facts(_edit(OLD, OLD + "\nOTHER = 1\n"), 0.1).readings["touches_protected"] is True


def test_every_failure_to_read_what_an_edit_touches_reads_true():
    cases = [
        ProtectedFacts(["pkg.mod.guarded"]).facts(_edit(OLD, OLD), 0.1),                       # no module name
        ProtectedFacts(["pkg.mod.guarded"], module_of=lambda rel: None).facts(_edit(OLD, OLD), 0.1),
        ProtectedFacts(["pkg.mod.guarded"], module_of=lambda rel: 1 / 0).facts(_edit(OLD, OLD), 0.1),
        _cc().facts(Change("a.py", None), 0.1),                                                 # no edit
        _cc().facts(_edit(OLD, "def (:\n"), 0.1),                                               # does not parse
        _cc().facts(_edit("def (:\n", OLD), 0.1),
        _cc(protected=()).facts(_edit(OLD, OLD), 0.1),                                          # no protected set
    ]
    assert all(c.readings["touches_protected"] is True and c.why for c in cases)


def test_adds_protected_reference_follows_the_graph_in_both_directions():
    refs = lambda change: [{"resolved": "function", "targets": ["lib.f"]}]           # noqa: E731
    point = lambda graph: _cc(refs=refs, graph=graph).facts(_edit(OLD, OLD), 0.1).readings["adds_protected_reference"]   # noqa: E731
    assert point(Graph(protected=["lib.f"])) is True
    assert point(Graph(path=["lib.f"])) is True
    assert point(Graph()) is False
    assert point(None) is True                                                      # no graph: any resolved reference
    refs2 = lambda change: [{"resolved": "class", "targets": ["lib.C"]}]            # noqa: E731
    assert _cc(refs=refs2, graph=Graph(protected=["lib.C.__init__"], inits={"lib.C": ["lib.C.__init__"]})
               ).facts(_edit(OLD, OLD), 0.1).readings["adds_protected_reference"] is True
    assert _cc(refs=lambda c: [{"resolved": "unresolved", "targets": ["x"]}], graph=None
               ).facts(_edit(OLD, OLD), 0.1).readings["adds_protected_reference"] is False


def test_every_failure_to_read_the_added_references_reads_true():
    def boom(change):
        raise RuntimeError("no")

    cases = [
        ProtectedFacts(["a"], module_of=lambda r: "m").facts(_edit("x=1\n", "x=2\n"), 0.1),      # no reading of references
        _cc(refs=lambda c: None).facts(_edit(OLD, OLD), 0.1),
        _cc(refs=boom).facts(_edit(OLD, OLD), 0.1),
        _cc(refs=lambda c: [object()]).facts(_edit(OLD, OLD), 0.1),                             # a reference that is not one
        _cc(refs=lambda c: 5).facts(_edit(OLD, OLD), 0.1),
        _cc(refs=lambda c: [{"resolved": "function", "targets": ["a"]}], graph=Graph()).facts(_edit(OLD, OLD), 0.1)
        if False else _cc(refs=lambda c: [{"resolved": "function", "targets": ["a"]}],
                          graph=type("G", (), {"is_protected": lambda s, n: 1 / 0})()).facts(_edit(OLD, OLD), 0.1),
    ]
    assert all(c.readings["adds_protected_reference"] is True for c in cases)


# ------------------------------------------------------------------------ the domain and the compile
FIELDS = ("---\nfield.tool: category\nfield.path_scope: category\nfield.command_class: category\nfield.git_op: category\n"
          "field.path_control: bool\nfield.net_dest: category\n{extra}---\n## core_decision\n")
SAFE = ('-> refuse agent:control-write: when path_control\n'
        '-> refuse agent:net-refused: when tool == "connect" or net_dest != "none"\n')


def _source(extra, rules):
    return FIELDS.format(extra=extra) + SAFE + rules


def _found(text, points=()):
    compiled = ps.compile_full(text)
    return [(target.line_of(where, compiled.field_lines, compiled.rule_lines), message)
            for where, message in target.check_listed(compiled.values) + target.check(compiled.image, points)]


TESTS_RULES = '-> allow: when tool == "write_file" and tests_pass == "true"\n-> allow: when tool == "read_file"\n'
TESTS_FIELD = "field.tests_pass: category true|false|not_run\n"


def test_a_policy_that_names_tests_pass_with_no_point_bound_is_refused_with_its_line():
    found = _found(_source(TESTS_FIELD, TESTS_RULES))
    assert [(line, "information point tests" in message) for line, message in found] == [(8, True)]
    assert "`--point tests`" in found[0][1] and "policy.points: tests" in found[0][1]


def test_the_same_policy_passes_when_its_point_is_bound():
    assert _found(_source(TESTS_FIELD, TESTS_RULES), ("tests",)) == []


def test_another_point_does_not_supply_the_field():
    assert [line for line, _m in _found(_source(TESTS_FIELD, TESTS_RULES), ("parse",))] == [8]


def test_a_point_that_does_not_exist_is_refused():
    assert _found(_source(TESTS_FIELD, TESTS_RULES), ("tests", "nope"))[0][1].startswith("no information point is called nope")


def test_a_field_declared_as_another_kind_or_with_other_values_is_named():
    assert "gives tests_pass as a category, not a bool" in _found(
        _source("field.tests_pass: bool\n", '-> allow: when tests_pass\n'), ("tests",))[0][1]
    listed = _found(_source("field.tests_pass: category true|false\n", TESTS_RULES), ("tests",))
    assert listed == [(8, "tests_pass lists true|false, but the agent's classifier gives true|false|not_run")]


def test_a_value_outside_a_points_field_is_out_of_domain_on_its_rule_line():
    found = _found(_source("field.tests_pass: category\n", '-> allow: when tests_pass == "passed"\n'), ("tests",))
    assert [line for line, _m in found] == [13] and "policy:out-of-domain" in found[0][1]


def test_the_domain_is_the_classifiers_plus_the_fields_of_the_points_named():
    assert profile.agent_domain() is profile.AGENT_DOMAIN
    domain = profile.agent_domain(("parse", "tests"))
    assert domain.categories["edit_kind"] == ("comment", "docstring", "annotation", "code")
    assert domain.categories["tests_pass"] == ("true", "false", "not_run") and "behaviour_preserving" not in domain.categories
    assert domain.defaults == {**profile.AGENT_DOMAIN.defaults, "edit_kind": "code", "behaviour_preserving": False,
                               "tests_pass": "false"}
    assert "tests_pass" not in profile.AGENT_DOMAIN.categories and "edit_kind" not in profile.AGENT_DOMAIN.defaults
    assert domain.categories["tool"] == profile.AGENT_DOMAIN.categories["tool"]


def test_a_reading_that_lacks_an_evidence_field_is_given_its_restrictive_value():
    compiled = ps.compile_full(_source("field.touches_protected: bool\n",
                                       '-> allow: when tool == "write_file" and not touches_protected\n'))
    policy = agent_policy.Policy(compiled.image, ("cc_graph",))
    reading = json.loads(policy.reading_bytes({"tool": "write_file", "path_scope": "workspace", "command_class": "none",
                                               "git_op": "none", "path_control": False, "net_dest": "none"}))
    assert reading["touches_protected"] is True
    assert not policy.decide(policy.reading_bytes({"tool": "write_file", "path_scope": "workspace",
                                                   "command_class": "none", "git_op": "none", "path_control": False,
                                                   "net_dest": "none"})).runs
    assert policy.decide(policy.reading_bytes({"tool": "write_file", "path_scope": "workspace", "command_class": "none",
                                               "git_op": "none", "path_control": False, "net_dest": "none",
                                               "touches_protected": False})).runs


def test_a_policy_with_no_evidence_field_loads_and_compiles_as_it_always_did():
    text = _source("", '-> allow: when tool == "read_file"\n')
    assert _found(text) == [] == _found(text, ("parse",))
    compiled = ps.compile_full(text)
    assert agent_policy.Policy(compiled.image).domain is profile.AGENT_DOMAIN


def test_the_compile_command_takes_the_points(tmp_path, capsys):
    from prismpath import cli
    source = tmp_path / "p.rules.md"
    source.write_text(_source(TESTS_FIELD, TESTS_RULES))
    assert cli.main(["policy", "compile", str(source), "--target", "agent"]) == 2
    assert f"{source}:8:" in capsys.readouterr().err
    assert cli.main(["policy", "compile", str(source), "--target", "agent", "--point", "tests"]) == 0
    assert cli.main(["policy", "compile", str(source), "--point", "tests"]) == 2


# --------------------------------------------------------------------------- the manifest and F12
def test_the_manifest_grammar_has_a_points_key():
    from prismpath.kernel import policy_manifest
    assert policy_manifest.KEYS["points"] == ("list:token", False)


def test_the_protected_set_is_the_union_of_the_zone_file_and_the_manifest():
    assert indexstatement.effective_protected(["b.x", "a"], ["a", "c"]) == ("a", "b.x", "c")
    assert indexstatement.effective_protected([], []) == ()
    assert indexstatement.effective_protected(["a"], []) == ("a",) == indexstatement.effective_protected([], ["a"])


STATEMENT = {"format": "prismpath.cc-index/1", "schema": "contextcloud-sqlite/1", "index": ".contextcloud/index.sqlite",
             "program": {"path": "/opt/cc/bin/contextcloud", "package": "/opt/cc/lib/contextcloud"}}


def _statement(**changes):
    doc = {**STATEMENT, **changes}
    return json.dumps(doc).encode()


def test_an_index_statement_names_the_index_and_the_program():
    statement = indexstatement.parse(_statement())
    assert (statement.index, statement.program_path) == (".contextcloud/index.sqlite", "/opt/cc/bin/contextcloud")
    zone = {"project": "/w/p", "index": "/w/p/.contextcloud/index.sqlite", "program": STATEMENT["program"]}
    assert indexstatement.matches(statement, zone) is None
    assert "another Context Cloud program" in indexstatement.matches(statement, {**zone, "program": {"path": "/x", "package": "/y"}})
    assert "index is /w/p/other.sqlite" in indexstatement.matches(statement, {**zone, "index": "/w/p/other.sqlite"})
    assert indexstatement.matches(statement, {}) is not None


@pytest.mark.parametrize("data", [
    b"", b"[]", b"{", _statement(format="x"), _statement(schema="x"), _statement(index="/abs"), _statement(index="a/../b"),
    _statement(index=""), _statement(index="a\\b"), _statement(index="a//b"), _statement(program={"path": "x", "package": "/y"}),
    _statement(program={"path": "/x"}), json.dumps({**STATEMENT, "extra": 1}).encode(), b"x" * 5000, "é".encode("latin-1")])
def test_a_malformed_index_statement_is_refused(data):
    with pytest.raises(ValueError, match="index statement"):
        indexstatement.parse(data)


def test_the_index_schema_and_age_are_checked_without_writing(tmp_path):
    path = tmp_path / "i.sqlite"
    db = sqlite3.connect(path)
    db.execute("CREATE TABLE files (file TEXT, module TEXT, sha256 TEXT, tier TEXT)")
    assert not indexstatement.schema_ok(str(path))
    db.execute("CREATE TABLE symbols (file TEXT, symbol TEXT, symbol_kind TEXT, tier TEXT)")
    db.commit()
    db.close()
    assert indexstatement.schema_ok(str(path)) and not indexstatement.schema_ok(str(tmp_path / "none.sqlite"))
    import os
    now = os.stat(path).st_mtime + 100
    assert indexstatement.fresh(str(path), 200, now) and not indexstatement.fresh(str(path), 50, now)
    assert not indexstatement.fresh(str(path), 200, now - 1000) and not indexstatement.fresh(str(tmp_path / "none"), 9, now)


def _manifest(points, rules_text):
    import hashlib
    from prismpath.kernel import policy_manifest as pm
    compiled = ps.compile_full(rules_text, "a.rules.md")
    sha = lambda data: hashlib.sha256(data).hexdigest()    # noqa: E731
    keys = {"id": "r-1", "stream": "s", "seq": "1", "targets": "agent", "rules": "a.rules.md",
            "rules_sha256": sha(rules_text.encode()), "image": "a.core.json", "image_sha256": sha(compiled.image),
            "widens": "yes", "valid_days": "30"}
    if points is not None:
        keys["points"] = points
    front = "\n".join(f"policy.{k}: {v}" for k, v in keys.items())
    manifest = pm.parse(f"---\n{front}\n---\n## manifest\nNotes.\n{pm.FIXED_RULE}\n", "m.policy.md")
    files = {"a.rules.md": rules_text.encode(), "a.core.json": compiled.image + b"\n"}
    return manifest, pm.Signature(True, (), manifest.sha256, None), files.get


def test_a_manifest_that_names_the_point_holds_and_one_that_does_not_is_refused_on_the_field_line():
    from prismpath.kernel import policy_manifest as pm
    rules = _source(TESTS_FIELD, TESTS_RULES)
    manifest, signature, read = _manifest("tests", rules)
    assert pm.check(manifest, signature, read, point_findings=target.evidence_findings) == []
    manifest, signature, read = _manifest(None, rules)
    found = pm.check(manifest, signature, read, point_findings=target.evidence_findings)
    assert [(f.code, f.message.startswith("a.rules.md:8: tests_pass is a field of the information point tests"))
            for f in found] == [("points", True)]
    manifest, signature, read = _manifest("tests | nope", rules)
    assert [f.code for f in pm.check(manifest, signature, read, point_findings=target.evidence_findings)] == ["points"]


def test_a_manifest_without_evidence_fields_is_unchanged_by_the_check():
    from prismpath.kernel import policy_manifest as pm
    rules = _source("", '-> allow: when tool == "read_file"\n')
    manifest, signature, read = _manifest(None, rules)
    assert pm.check(manifest, signature, read, point_findings=target.evidence_findings) == pm.check(manifest, signature, read) == []
