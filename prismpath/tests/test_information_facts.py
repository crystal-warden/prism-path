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

POINTS = [ParseFacts(), ProjectTests(Path("."), None, lambda c: False), ProtectedFacts(["pkg.core"])]


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
    ("import doctest\ndef f():\n    '''a'''\n", "import doctest\ndef f():\n    '''b'''\n", "code", False),
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
OK_LINE = "print('1 passed in 0.01s')\n"


def _project(tmp_path, body):
    root = tmp_path / "proj"
    (root / "pkg").mkdir(parents=True)
    (root / "pkg" / "mod.py").write_text("VALUE = 1\n")
    (root / "check.py").write_text(body)
    return root


def _config(timeout=30, **kwargs):
    return TestConfig(command=[sys.executable, "check.py"], timeout=timeout, **kwargs)


def _never(change):
    return False


def _always(change):
    return True


def test_a_point_that_is_not_asked_runs_nothing_and_reads_not_run(tmp_path):
    root = _project(tmp_path, "raise SystemExit(1)\n")
    assert ProjectTests(root, _config(), _never).facts(_edit("a\n", "b\n"), 0.1).readings == {"tests_pass": "not_run"}


def test_should_run_is_required():
    with pytest.raises(TypeError):
        ProjectTests(Path("."), None)


def test_the_tests_run_on_a_copy_with_the_edit_applied(tmp_path):
    root = _project(tmp_path, "import sys\nsys.path.insert(0, '.')\nfrom pkg import mod\n"
                              "if mod.VALUE == 2:\n    print('1 passed in 0.01s')\nelse:\n    raise SystemExit(1)\n")
    point = ProjectTests(root, _config(), _always)
    assert point.facts(_edit("VALUE = 1\n", "VALUE = 2\n"), 0.1).readings == {"tests_pass": "true"}
    assert point.facts(_edit("VALUE = 1\n", "VALUE = 3\n"), 0.1).readings == {"tests_pass": "false"}
    assert (root / "pkg" / "mod.py").read_text() == "VALUE = 1\n"       # the project itself is never touched


def test_an_exit_of_zero_without_a_pass_summary_is_false(tmp_path):
    for number, body in enumerate(("pass\n", "print('0 passed in 0.01s')\n", "print('1 passed, 1 failed in 0.01s')\n",
                 "print('1 passed, 1 error in 0.01s')\n", "import os\nprint('1 passed')\nprint('done')\n")):
        root = _project(tmp_path / str(number), body)
        assert ProjectTests(root, _config(), _always).facts(_edit("a", "b"), 0.1).readings == {"tests_pass": "false"}


@pytest.mark.parametrize("relative", ["conftest.py", "pkg/conftest.py", "tests/test_a.py", "pkg/test_x.py", "pkg/x_test.py",
                                      "pytest.ini", "pyproject.toml", "sitecustomize.py", ".hidden.py"])
def test_an_edit_to_a_test_file_or_configuration_is_not_run(tmp_path, relative):
    root = _project(tmp_path, OK_LINE)
    evidence = ProjectTests(root, _config(), _always).facts(_edit("a", "b", relative=relative), 0.1)
    assert evidence.readings == {"tests_pass": "false"} and "test file" in evidence.why


def test_every_way_the_tests_cannot_be_run_reads_false(tmp_path):
    root = _project(tmp_path, "import time\ntime.sleep(30)\n")
    gate = _always
    cases = [
        ProjectTests(root, _config(timeout=1), gate).facts(_edit("a", "b"), 0.1),            # a timeout
        ProjectTests(root, TestConfig(command=["/no/such/program"]), gate).facts(_edit("a", "b"), 0.1),
        ProjectTests(root, None, gate).facts(_edit("a", "b"), 0.1),                           # no command
        ProjectTests(root, _config(), gate).facts(Change("a.py", None), 0.1),                 # no edit
        ProjectTests(root, _config(), gate).facts(_edit("a", "b", relative="../escape.py"), 0.1),
        ProjectTests(root, _config(), gate).facts(_edit("a", "b", relative="/abs.py"), 0.1),
        ProjectTests(root, _config(), gate).facts(_edit("a", "b", relative="nodir/x.py"), 0.1),
        ProjectTests(tmp_path / "missing", _config(), gate).facts(_edit("a", "b"), 0.1),       # no project
        ProjectTests(root, _config(), lambda change: 1 / 0).facts(_edit("a", "b"), 0.1),      # the gate fails
        ProjectTests(root, _config(), gate, run=lambda *a: 1 / 0).facts(_edit("a", "b"), 0.1),  # the run fails
    ]
    assert [c.readings for c in cases] == [{"tests_pass": "false"}] * len(cases)
    assert not (tmp_path / "escape.py").exists()


def test_an_edit_cannot_be_written_through_a_link_into_the_project_or_outside_it(tmp_path):
    root = _project(tmp_path, OK_LINE)
    (root / ".venv" / "lib").mkdir(parents=True)
    (root / ".venv" / "lib" / "site.py").write_text("ORIGINAL\n")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "t.py").write_text("ORIGINAL\n")
    (root / "abslink").symlink_to(outside)
    (root / "pkg" / "filelink.py").symlink_to(outside / "t.py")
    point = ProjectTests(root, _config(link=(".venv",)), _always)
    for relative in (".venv/lib/site.py", "abslink/t.py", "pkg/filelink.py"):
        assert point.facts(_edit("a", "PWNED\n", relative=relative), 0.1).readings == {"tests_pass": "false"}
    assert (root / ".venv" / "lib" / "site.py").read_text() == "ORIGINAL\n"
    assert (outside / "t.py").read_text() == "ORIGINAL\n"


def test_the_command_gets_a_minimal_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("A5_SECRET_MARKER", "leak")
    body = "import os\nprint('1 passed in 0.01s' if 'A5_SECRET_MARKER' not in os.environ else 'leaked')\n"
    root = _project(tmp_path, body)
    assert ProjectTests(root, _config(), _always).facts(_edit("a", "b"), 0.1).readings == {"tests_pass": "true"}
    assert ProjectTests(root, _config(inherit_env=True), _always).facts(_edit("a", "b"), 0.1).readings == {"tests_pass": "false"}


def test_a_project_too_big_to_copy_reads_false(tmp_path, monkeypatch):
    from prismpath.information import projecttests as pt
    monkeypatch.setattr(pt, "MAX_COPY_FILES", 1)
    root = _project(tmp_path, OK_LINE)
    assert ProjectTests(root, _config(), _always).facts(_edit("a", "b"), 0.1).readings == {"tests_pass": "false"}


def test_a_run_that_says_ok_with_anything_but_true_is_false(tmp_path):
    class Odd:
        ok = "yes"
        summary = "x"
        seconds = 0.0

    point = ProjectTests(tmp_path, _config(), _always, run=lambda *a: Odd())
    assert point.facts(_edit("a", "b"), 0.1).readings == {"tests_pass": "false"}


def test_a_gate_that_answers_anything_but_true_does_not_run_the_tests(tmp_path):
    ran = []
    point = ProjectTests(tmp_path, _config(), lambda c: "yes", run=lambda *a: ran.append(1))
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
    (OLD + "\nOTHER = 1\n", True),                                   # module code can rebind a protected name
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
    assert _cc(refs=lambda c: [{"resolved": "builtin", "targets": []}], graph=None
               ).facts(_edit(OLD, OLD), 0.1).readings["adds_protected_reference"] is False
    assert _cc(refs=lambda c: [], graph=None).facts(_edit(OLD, OLD), 0.1).readings["adds_protected_reference"] is False


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
    manifest = pm.parse(f"---\nname: s\n{front}\n---\n## manifest\nNotes.\n{pm.FIXED_RULE}\n", "m.policy.md")
    files = {"a.rules.md": rules_text.encode(), "a.core.json": compiled.image + b"\n"}
    return manifest, pm.Signature(True, (), manifest.sha256, None), files.get


def test_a_manifest_that_names_the_point_holds_and_one_that_does_not_is_refused_on_the_field_line():
    from prismpath.kernel import policy_manifest as pm
    rules = _source(TESTS_FIELD, TESTS_RULES)
    manifest, signature, read = _manifest("tests", rules)
    assert pm.check(manifest, signature, read, known_targets={"agent"}, point_findings=target.evidence_findings) == []
    manifest, signature, read = _manifest(None, rules)
    found = pm.check(manifest, signature, read, known_targets={"agent"}, point_findings=target.evidence_findings)
    # the agent's own compile checks (`policy compile --target agent`, run by the check since A4b) refuse it too
    assert ("points", True) in [(f.code, f.message.startswith("a.rules.md:8: tests_pass is a field of the information "
                                                              "point tests")) for f in found]
    assert {f.code for f in found} == {"points", "target-check"}
    manifest, signature, read = _manifest("tests | nope", rules)
    assert "points" in [f.code for f in pm.check(manifest, signature, read, known_targets={"agent"},
                                                 point_findings=target.evidence_findings)]


def test_a_manifest_without_evidence_fields_is_unchanged_by_the_check():
    from prismpath.kernel import policy_manifest as pm
    rules = _source("", '-> allow: when tool == "read_file"\n')
    manifest, signature, read = _manifest(None, rules)
    assert pm.check(manifest, signature, read, known_targets={"agent"}, point_findings=target.evidence_findings) == pm.check(manifest, signature, read, known_targets={"agent"}) == []


# ------------------------------------------------------------------------------------ the review's probes
UTF7_NEW = "# coding: utf-7\nx = 1  # +AAo-print(+ACI-PWNED+ACI-)\n"


@pytest.mark.parametrize("old,new", [
    ("x = 1\n", UTF7_NEW),
    (UTF7_NEW, "x = 1\n"),
    ("x = 1\n", "﻿x = 1\n"),
    ("x = 1\n", "# coding: latin-1\nx = 1\n"),
    ("# coding: utf-8\nx = 1\n", "# coding: cp1252\nx = 1\n"),
])
def test_a_changed_source_encoding_reads_code_false_and_touching(old, new):
    evidence = ParseFacts().facts(_edit(old, new), 0.1)
    assert evidence.readings == {"edit_kind": "code", "behaviour_preserving": False}
    assert _cc().facts(_edit(old, new), 0.1).readings["touches_protected"] is True


def test_the_utf7_example_really_does_run_a_statement_from_disk(tmp_path):
    import subprocess
    path = tmp_path / "m7.py"
    path.write_bytes(UTF7_NEW.encode("utf-8"))
    done = subprocess.run([sys.executable, "-I", str(path)], capture_output=True, text=True)
    assert "PWNED" in done.stdout


def test_a_plain_utf8_declaration_is_still_a_comment_edit():
    old, new = "# coding: utf-8\nx = 1\n", "# coding: utf-8\nx = 1  # note\n"
    assert ParseFacts().facts(_edit(old, new), 0.1).readings == {"edit_kind": "comment", "behaviour_preserving": True}


@pytest.mark.parametrize("old,new", [
    ("def f(x: int):\n    return x\n", "def f(x: __import__('os').getcwd()):\n    return x\n"),
    ("class M(BaseModel):\n    x: int = 0\n", "class M(BaseModel):\n    x: str = 0\n"),
    ("import ply\ndef t(t):\n    '''a'''\n", "import ply\ndef t(t):\n    '''b'''\n"),
    ("def f():\n    '''a'''\n    return __doc__\n", "def f():\n    '''b'''\n    return __doc__\n"),
])
def test_an_annotation_or_docstring_is_named_only_when_the_edit_is_behaviour_preserving(old, new):
    evidence = ParseFacts().facts(_edit(old, new), 0.1)
    assert evidence.readings == {"edit_kind": "code", "behaviour_preserving": False}


@pytest.mark.parametrize("ref", [
    {"resolved": "unresolved", "targets": ["pkg.core.f"]}, {"resolved": "outside", "targets": ["x"]},
    {"resolved": "function", "targets": []}, {"resolved": "function"}, {"resolved": "function", "targets": "pkg.core.f"},
    {"resolved": "function", "targets": [1]}, {"resolved": "class", "targets": ["m.C"]}, {"targets": ["m.f"]}, {}])
def test_a_reference_off_the_closed_safe_list_reads_true(ref):
    point = _cc(refs=lambda c: [ref], graph=Graph(protected=["pkg.core.f"]))
    assert point.facts(_edit(OLD, OLD), 0.1).readings["adds_protected_reference"] is True


def test_unparseable_new_text_reads_true_whatever_the_adapter_says():
    assert _cc(refs=lambda c: []).facts(_edit(OLD, "def (:\n"), 0.1).readings["adds_protected_reference"] is True


def test_module_level_rebinding_of_a_protected_name_touches():
    for tail in ("\nguarded = lambda: 2\n", "\nglobals()['guarded'] = print\n"):
        assert _cc().facts(_edit(OLD, OLD + tail), 0.1).readings["touches_protected"] is True
    other = _cc(protected=("pkg.elsewhere.f",))
    assert other.facts(_edit(OLD, OLD + "\nOTHER = 1\n"), 0.1).readings["touches_protected"] is False


def test_a_file_that_is_not_python_touches():
    point = _cc()
    for relative in ("pkg/core_settings.toml", "pkg/mod.PY", "pkg/mod.pyi", "pkg/run.sh"):
        assert point.facts(_edit("", "", relative=relative), 0.1).readings["touches_protected"] is True


def test_a_protected_span_that_changed_is_found_by_its_text_by_name():
    old = "def a():\n    return 1\n\n\ndef guarded():\n    return 1\n"
    new = "def a():\n    return 1\n\n\ndef guarded():\n    return 2\n"
    assert _cc().facts(_edit(old, new), 0.1).readings["touches_protected"] is True
    gone = "def a():\n    return 1\n"
    assert _cc().facts(_edit(old, gone), 0.1).readings["touches_protected"] is True


def test_a_big_text_or_a_spent_budget_reads_the_restrictive_values():
    big = "x = 1\n" * 30_000
    assert ParseFacts().facts(_edit(big, big + "y = 2\n"), 5).readings == ParseFacts.restrictive
    assert _cc().facts(_edit(big, big + "y = 2\n"), 5).readings["touches_protected"] is True
    assert ParseFacts().facts(_edit(OLD, OLD + "# c\n"), -1).readings == ParseFacts.restrictive
    assert _cc().facts(_edit(OLD, OLD), -1).readings == {"touches_protected": True, "adds_protected_reference": True}


def test_schema_ok_escapes_the_path(tmp_path):
    path = tmp_path / "a?b#c.sqlite"
    db = sqlite3.connect(path)
    db.execute("CREATE TABLE files (file TEXT, module TEXT, sha256 TEXT, tier TEXT)")
    db.execute("CREATE TABLE symbols (file TEXT, symbol TEXT, symbol_kind TEXT, tier TEXT)")
    db.commit()
    db.close()
    assert indexstatement.schema_ok(str(path))


# ---------------------------------------------------------- the compile checks of the review (F5, F11, F13)
def test_a_rule_that_refuses_only_on_false_and_allows_the_rest_is_refused_at_compile():
    rules = '-> refuse agent:network: when tests_pass == "false"\n-> allow: when tool == "write_file"\n'
    found = _found(_source(TESTS_FIELD, rules), ("tests",))
    assert [line for line, _m in found] == [8]
    assert "'not_run'" in found[0][1] and "'false'" in found[0][1]
    assert _found(_source(TESTS_FIELD, '-> refuse agent:network: when tests_pass == "false"\n'
                          '-> allow: when tool == "write_file" and tests_pass == "true"\n'), ("tests",)) == []
    assert [line for line, _m in _found(_source(TESTS_FIELD, '-> allow: when tool == "write_file" and tests_pass != "false"\n'),
                                        ("tests",))] == [8]


def test_a_rule_that_allows_only_on_true_passes_the_monotone_check():
    assert _found(_source(TESTS_FIELD, TESTS_RULES), ("tests",)) == []


def test_loading_a_policy_that_reads_an_evidence_field_with_no_point_is_a_load_error():
    from prismpath.kernel.decision import OutsideDomain
    compiled = ps.compile_full(_source(TESTS_FIELD, TESTS_RULES))
    with pytest.raises(OutsideDomain, match="information point tests"):
        agent_policy.Policy(compiled.image)
    assert agent_policy.Policy(compiled.image, ("tests",)).domain.name == "agent+tests"


def test_an_evidence_field_named_like_a_classifier_bool_or_int_is_a_clash(monkeypatch):
    from prismpath.information import catalog
    fake = catalog.EvidenceField("path_control", "parse", "bool", (False, True), False)
    monkeypatch.setattr(catalog, "fields_of", lambda names: {"path_control": fake})
    with pytest.raises(ValueError, match="also a field of the classifier"):
        profile.agent_domain(("parse",))
