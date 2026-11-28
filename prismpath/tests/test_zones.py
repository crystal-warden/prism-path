# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Zones (prismpath/agent/zones.py): the reading field `zone_reach`, the starters' rule about it
(cause 132), the signed zone file and the Context Cloud adapter.

The adapter is tested twice. Against a stand-in `contextcloud` program and a small index built here (always), and against
the real Context Cloud and the PyJWT demo index at ~/contextcloud-demo when they exist (skipped otherwise). The proof
(formal/Classifier/Zone.lean) holds for every information point; these tests hold the Python point to what it says.
"""
import hashlib
import json
import os
import sqlite3
import stat
import sys
import time
from pathlib import Path

import pytest

from prismpath.agent import claude_code, classifier, commands, session_state, zones
from prismpath.agent.policy import STARTERS, Policy, starter_path

DEMO = Path.home() / "contextcloud-demo"
DEMO_CC = DEMO / "venv" / "bin" / "contextcloud"
HOOK_INPUT = {"session_id": "s1", "transcript_path": "/tmp/t.jsonl", "hook_event_name": "PreToolUse",
              "tool_use_id": "toolu_1"}


def _call(tool, **args):
    return {"tool": tool, "args": args}


def _read(point, call, workspace="/ws"):
    config = classifier.Config.for_workspace(workspace, zones=point) if point is not None else \
        classifier.Config.for_workspace(workspace, zones=None)
    return classifier.classify(call, config)


class Table:
    """A point that answers per path, `unknown` for a path it was not given."""

    def __init__(self, **answers):
        self.answers, self.asked = answers, []

    def reach(self, raw, config=None):
        self.asked.append(raw)
        return self.answers.get(raw, "unknown")


# ----------------------------------------------------------------------------------------- the reading
CHANGES = [_call("write_file", path="src/a.py", content=""), _call("delete_path", path="src/a.py"),
           _call("run_command", argv=["rm", "src/a.py"]), _call("run_command", argv=["mv", "a", "b"]),
           _call("run_command", argv=["mkdir", "newdir"])]
NO_CHANGES = [_call("read_file", path="src/a.py"), _call("list_dir", path="src"), _call("run_command", argv=["ls", "src"]),
              _call("run_command", argv=["cat", "src/a.py"]), _call("git", subcommand="status"),
              _call("connect", host="api.anthropic.com", port=443), {"tool": "nope", "args": {}}]


@pytest.mark.parametrize("call", CHANGES, ids=lambda c: json.dumps(c)[:50])
def test_with_no_information_point_every_changing_call_reads_unknown(call):
    assert _read(None, call)["zone_reach"] == "unknown"
    assert _read(zones.UNKNOWN_ZONES, call)["zone_reach"] == "unknown"


@pytest.mark.parametrize("call", NO_CHANGES, ids=lambda c: json.dumps(c)[:50])
def test_a_call_that_changes_no_file_reads_none_whatever_the_point(call):
    for point in (None, zones.UNKNOWN_ZONES, zones.fixed("protected"), zones.NO_ZONES):
        assert _read(point, call)["zone_reach"] == "none"


def test_the_default_point_of_a_workspace_declares_no_zone_so_nothing_is_protected():
    config = classifier.Config.for_workspace("/ws")
    assert config.zones is zones.NO_ZONES
    assert classifier.classify(CHANGES[0], config)["zone_reach"] == "none"
    assert classifier.Config(Path("/ws"), ()).zones is None          # built by hand: no point at all, so unknown
    assert classifier.classify(CHANGES[0], classifier.Config(Path("/ws"), ()))["zone_reach"] == "unknown"


def test_the_paths_of_a_call_are_joined_protected_then_unknown_then_none():
    rm = _call("run_command", argv=["rm", "a", "b", "c"])
    assert _read(Table(a="none", b="none", c="none"), rm)["zone_reach"] == "none"
    assert _read(Table(a="none", b="none"), rm)["zone_reach"] == "unknown"          # c was not answered
    assert _read(Table(a="none", b="protected", c="unknown"), rm)["zone_reach"] == "protected"
    assert _read(Table(a="unknown", b="none", c="none"), rm)["zone_reach"] == "unknown"


def test_a_changing_call_that_names_no_path_the_check_passes_reads_unknown():
    table = Table()
    assert _read(table, _call("run_command", argv=["rm", "-f"]))["zone_reach"] == "unknown"
    assert _read(table, _call("write_file", path="a\x00b", content=""))["zone_reach"] == "unknown"
    assert table.asked == []                                                        # the point was not asked


def test_an_answer_outside_the_three_or_an_error_is_unknown():
    class Odd:
        def __init__(self, answer):
            self.answer = answer

        def reach(self, raw, config=None):
            if isinstance(self.answer, Exception):
                raise self.answer
            return self.answer

    for answer in ("maybe", None, 3, "none ", RuntimeError("x")):
        assert _read(Odd(answer), CHANGES[0])["zone_reach"] == "unknown", answer
    assert _read(Odd("none"), CHANGES[0])["zone_reach"] == "none"


def test_the_other_fields_do_not_change_with_the_point():
    for call in CHANGES + NO_CHANGES:
        a, b = _read(zones.fixed("none"), call), _read(zones.fixed("protected"), call)
        a.pop("zone_reach"), b.pop("zone_reach")
        assert a == b


# ----------------------------------------------------------------------------------------- the starters
def _decide(name, reading):
    policy = Policy.load(starter_path(name))
    return policy.decide(policy.reading_bytes({**session_state.FRESH, **reading} if policy.stateful else reading))   # a fresh session


@pytest.mark.parametrize("name", sorted(STARTERS))
def test_a_write_that_reaches_a_zone_or_whose_reach_is_unknown_asks_with_cause_132(name):
    for answer in ("protected", "unknown"):
        decision = _decide(name, _read(zones.fixed(answer), _call("write_file", path="src/a.py", content="")))
        assert (decision.kind, decision.cause_code) == ("escalate", 132), (name, answer)
        decision = _decide(name, _read(zones.fixed(answer), _call("delete_path", path="src/a.py")))
        assert (decision.kind, decision.cause_code) == ("escalate", 132), (name, answer)


@pytest.mark.parametrize("name,verdict", [("strict", ("allow", None)), ("default", ("allow", None)),
                                          ("review", ("escalate", 127))])
def test_a_write_that_reaches_no_zone_keeps_its_old_verdict(name, verdict):
    decision = _decide(name, _read(zones.fixed("none"), _call("write_file", path="src/a.py", content="")))
    assert (decision.kind, decision.cause_code) == verdict


@pytest.mark.parametrize("name,none_verdict", [("default", ("escalate", 125)), ("review", ("escalate", 127)),
                                               ("strict", ("refuse", 112))])
def test_a_file_changing_command_keeps_its_old_verdict_unless_it_reaches_a_zone(name, none_verdict):
    rm = _call("run_command", argv=["rm", "src/a.py"])
    decision = _decide(name, _read(zones.fixed("none"), rm))
    assert (decision.kind, decision.cause_code) == none_verdict
    decision = _decide(name, _read(zones.fixed("protected"), rm))
    # strict refuses every file changing command, with or without a zone: its rule never turns a refusal into a question
    assert (decision.kind, decision.cause_code) == (("refuse", 112) if name == "strict" else ("escalate", 132))


@pytest.mark.parametrize("name", sorted(STARTERS))
def test_with_no_point_the_starters_ask_about_every_write_and_never_allow_one(name):
    for call in CHANGES:
        decision = _decide(name, _read(None, call))
        assert decision.kind != "allow", (name, call)


@pytest.mark.parametrize("name", sorted(STARTERS))
def test_an_earlier_refusal_is_not_softened_by_the_zone_rule(name):
    outside = _decide(name, _read(zones.fixed("unknown"), _call("write_file", path="/etc/x", content="")))
    assert outside.kind == "refuse" and outside.cause_code in (107, 111)       # a toolchain path, or outside the workspace
    traversal = _decide(name, _read(zones.fixed("protected"), _call("write_file", path="../x", content="")))
    assert (traversal.kind, traversal.cause_code) == ("refuse", 109)


@pytest.mark.parametrize("name", sorted(STARTERS))
def test_reads_are_decided_as_before_whatever_the_point(name):
    for call in NO_CHANGES[:5]:
        a = _decide(name, _read(None, call))
        b = _decide(name, _read(zones.fixed("none"), call))
        assert (a.kind, a.cause) == (b.kind, b.cause)


# ----------------------------------------------------------------------------------------- the zone file
@pytest.fixture()
def home(tmp_path):
    home = tmp_path / "config"
    home.mkdir(mode=0o700)
    for role in commands.KEY_ROLES:
        commands._ensure_key(home, role)
    return home


@pytest.fixture()
def image():
    return starter_path("default").read_bytes().rstrip(b"\n")


def _signed(home, image, project, names=("pkg.secure.check",), index=None):
    zones.sign(home, zones.zone_document(names, project, index, image))


def test_a_signed_zone_file_is_read_back_and_bound_to_the_policy_and_the_project(home, image, tmp_path):
    project = tmp_path / "proj"
    project.mkdir()
    _signed(home, image, project, ("b.two", "a.one"))
    doc = zones.load(home, image, project)
    assert doc["protected"] == ["a.one", "b.two"] and doc["project"] == str(project.resolve())
    with pytest.raises(zones.ZoneError, match="another policy"):
        zones.load(home, image + b" ", project)                 # the recorded policy changed
    with pytest.raises(zones.ZoneError, match="another project"):
        zones.load(home, image, tmp_path)
    assert zones.load(tmp_path / "empty", image) is None        # nothing declared


def test_an_edited_zone_file_or_a_foreign_signature_does_not_verify(home, image, tmp_path):
    project = tmp_path / "proj"
    project.mkdir()
    _signed(home, image, project)
    path = home / zones.ZONES_FILE
    good = path.read_bytes()
    path.write_bytes(good.replace(b"pkg.secure.check", b"pkg.secure.other"))
    with pytest.raises(zones.ZoneError):
        zones.load(home, image, project)
    path.write_bytes(good)
    zones.load(home, image, project)
    other = tmp_path / "other-home"                       # a file signed by another authority key
    other.mkdir(mode=0o700)
    for role in commands.KEY_ROLES:
        commands._ensure_key(other, role)
    _signed(other, image, project)
    (home / zones.ATTESTATION_FILE).write_bytes((other / zones.ATTESTATION_FILE).read_bytes())
    with pytest.raises(zones.ZoneError):
        zones.load(home, image, project)


def test_a_zone_file_must_name_valid_dotted_names(image, tmp_path):
    for bad in ([], ["a b"], ["a,b"], [""], ["x" * 600]):
        with pytest.raises(zones.ZoneError):
            zones.zone_document(bad, tmp_path, None, image)


def test_the_hook_point_is_none_for_no_zone_file_and_unknown_for_a_declared_one_it_cannot_use(home, image, tmp_path,
                                                                                           monkeypatch):
    project = tmp_path / "proj"
    project.mkdir()
    assert zones.information_point(home, image, project, {}) is zones.NO_ZONES
    _signed(home, image, project)
    monkeypatch.delenv("CONTEXTCLOUD", raising=False)
    env = {"PATH": str(tmp_path / "nowhere")}
    point = zones.information_point(home, image, project, env)
    assert point.reach("a.py", None) == "unknown" and "not installed" in point.why          # declared, Context Cloud absent
    with_cc = {**env, "CONTEXTCLOUD": str(tmp_path / "fake")}
    (tmp_path / "fake").write_text("#!/bin/sh\n")
    (tmp_path / "fake").chmod(0o755)
    point = zones.information_point(home, image, project, with_cc)
    assert point.reach("a.py", None) == "unknown" and "no Context Cloud index" in point.why   # and no index
    assert zones.information_point(home, image + b"x", project, with_cc).reach("a.py", None) == "unknown"
    assert zones.status(home, image, project, env) == {"declared": True, "point": "unknown",
                                                       "detail": point_why(home, image, project, env)}


def point_why(home, image, project, env):
    return zones.information_point(home, image, project, env).why


def test_the_hook_asks_about_every_write_when_a_zone_is_declared_and_context_cloud_is_absent(home, image, tmp_path,
                                                                                         monkeypatch):
    """The end to end case of the plan: a declared zone, no Context Cloud, a write is asked about and never allowed."""
    project = tmp_path / "proj"
    (project / "src").mkdir(parents=True)
    _signed(home, image, project)
    monkeypatch.delenv("CONTEXTCLOUD", raising=False)
    monkeypatch.setenv("PATH", str(tmp_path / "nowhere"))
    policy = Policy(image)
    hook = {**HOOK_INPUT, "cwd": str(project), "tool_name": "Write",
            "tool_input": {"file_path": "src/a.py", "content": "x"}}
    result = claude_code.evaluate(hook, {"CLAUDE_PROJECT_DIR": str(project)}, policy,
                                  lambda ws: zones.information_point(home, image, Path(ws), os.environ))
    assert result.reading["zone_reach"] == "unknown"
    assert (result.decision.kind, result.decision.cause_code) == ("escalate", 132)
    assert result.answer["hookSpecificOutput"]["permissionDecision"] == "ask"
    # the same write with no zone declared at all is what it was
    result = claude_code.evaluate(hook, {"CLAUDE_PROJECT_DIR": str(project)}, policy)
    assert result.reading["zone_reach"] == "none" and result.decision.kind == "allow"


# ----------------------------------------------------------------------------------------- the adapter, hermetic
FAKE = """#!{python}
import json, os, shutil, sys, time
if sys.argv[1] == "index":      # a rebuild: the index a test saved is put where --index says
    shutil.copy({index_src!r}, sys.argv[sys.argv.index("--index") + 1])
    sys.exit(0)
name = sys.argv[2]
log = {log!r}
if log:
    open(log, "a").write(name + "\\n")
answers = json.load(open({answers!r}))
answer = answers.get(name, "no")
if answer == "error":
    sys.stderr.write("no function named")
    sys.exit(2)
if answer == "slow":
    time.sleep(10)
print(json.dumps({{"command": "reaches", "certainty": answer}}))
"""


class World:
    """A small project, an index of it in the shape Context Cloud writes, and a stand-in `contextcloud`."""

    def __init__(self, tmp_path, monkeypatch, home, image):
        self.project = tmp_path / "proj"
        (self.project / "pkg").mkdir(parents=True)
        self.index = tmp_path / "index.sqlite"
        self.home, self.image = home, image
        self.answers = tmp_path / "answers.json"
        self.log = tmp_path / "calls.log"
        self.exe = tmp_path / "contextcloud"
        self.pkg = tmp_path / "ccpackage"
        self.pkg.mkdir()
        self.index_src = tmp_path / "saved-index.sqlite"
        self.exe.write_text(FAKE.format(python=sys.executable, answers=str(self.answers), log=str(self.log),
                                        index_src=str(self.index_src)))
        self.exe.chmod(self.exe.stat().st_mode | stat.S_IXUSR)
        self.answers.write_text("{}")
        monkeypatch.setenv("FAKE_CC_ANSWERS", str(self.answers))
        monkeypatch.setenv("FAKE_CC_LOG", str(self.log))
        self.db = sqlite3.connect(self.index)
        self.db.execute("CREATE TABLE files (file TEXT, tier TEXT, module TEXT, sha256 TEXT)")
        self.db.execute("CREATE TABLE symbols (file TEXT, tier TEXT, symbol TEXT, symbol_kind TEXT)")

    def add(self, rel, text, functions, module=None, index_text=None):
        path = self.project / rel
        path.write_text(text)
        sha = hashlib.sha256((text if index_text is None else index_text).encode()).hexdigest()
        module = module or rel[:-3].replace("/", ".")
        self.db.execute("INSERT INTO files VALUES (?, 'saved', ?, ?)", (rel, module, sha))
        for name in functions:
            self.db.execute("INSERT INTO symbols VALUES (?, 'saved', ?, 'function')", (rel, f"{module}.{name}"))
        self.db.commit()

    def answer(self, **by_name):
        self.answers.write_text(json.dumps({k.replace("__", "."): v for k, v in by_name.items()}))

    def calls(self):
        return self.log.read_text().split() if self.log.exists() else []

    def point(self, protected=("pkg.secure.check",), budget=2.0):
        doc = zones.zone_document(protected, self.project, self.index, self.image,
                                  program={"path": os.path.realpath(self.exe), "package": str(self.pkg)})
        return zones.ContextCloudZones(doc, self.home, str(self.exe), budget_s=budget)

    def config(self):
        return classifier.Config.for_workspace(self.project)


@pytest.fixture()
def world(tmp_path, monkeypatch, home, image):
    return World(tmp_path, monkeypatch, home, image)


def test_a_file_that_defines_protected_code_is_protected_without_asking(world):
    world.add("pkg/secure.py", "def check(): pass\n", ["check", "other"])
    world.add("pkg/mod.py", "def f(): pass\n", ["f"])
    point = world.point(("pkg.secure",))                      # a whole module
    assert point.reach("pkg/secure.py", world.config()) == "protected"
    assert point.reach("pkg/mod.py", world.config()) == "none"
    assert world.calls() == ["pkg.mod.f"]                    # only the file that is not protected by name was looked up
    assert world.point(("pkg.secure.check",)).reach("pkg/secure.py", world.config()) == "protected"
    assert world.point(("pkg.secure.Klass",)).reach("pkg/secure.py", world.config()) in ("none", "unknown")


def test_a_function_that_reaches_the_zone_makes_its_file_protected_and_the_certainties_map(world):
    world.add("pkg/a.py", "def f(): pass\ndef g(): pass\n", ["f", "g"])
    cfg = world.config()
    for said, want in (("no", "none"), ("certain", "protected"), ("likely", "protected"), ("unknown", "unknown"),
                       ("error", "unknown")):
        world.answer(pkg__a__g=said)
        (world.home / zones.CACHE_FILE).unlink(missing_ok=True)          # each answer is asked, not remembered
        assert world.point().reach("pkg/a.py", cfg) == want, said
    (world.home / zones.CACHE_FILE).unlink(missing_ok=True)
    world.answer(pkg__a__f="unknown", pkg__a__g="certain")
    assert world.point().reach("pkg/a.py", cfg) == "protected"           # protected beats unknown


def test_the_adapter_never_reads_none_from_anything_it_cannot_check(world, tmp_path):
    world.add("pkg/a.py", "def f(): pass\n", ["f"])
    world.add("pkg/stale.py", "def f(): pass\n", ["f"], index_text="an older version\n")
    (world.project / "README.md").write_text("x")
    point, cfg = world.point(), world.config()
    assert point.reach("README.md", cfg) == "unknown"                     # not a Python file
    assert point.reach("pkg/new.py", cfg) == "unknown"                    # not on the disk yet
    (world.project / "pkg" / "unindexed.py").write_text("def h(): pass\n")
    assert point.reach("pkg/unindexed.py", cfg) == "unknown"              # the index does not hold it
    assert point.reach("pkg/stale.py", cfg) == "unknown"                  # the index holds another version of it
    assert point.reach("../outside.py", cfg) == "unknown"                 # not inside the project
    assert point.reach("pkg/a.py", cfg) == "none"                         # and the one case that can be checked
    (tmp_path / "gone").write_text("")
    broken = zones.ContextCloudZones(zones.zone_document(["pkg.x"], world.project, tmp_path / "no.sqlite", world.image,
                                                         program={"path": os.path.realpath(world.exe), "package": str(world.pkg)}),
                                     world.home, str(world.exe))
    assert broken.reach("pkg/a.py", cfg) == "unknown"                     # no index at all


def test_a_lookup_that_is_too_slow_reads_unknown_and_is_not_cached(world):
    world.add("pkg/a.py", "def f(): pass\ndef g(): pass\n", ["f", "g"])
    world.answer(pkg__a__g="slow")
    point = world.point(budget=0.4)
    started = time.monotonic()
    assert point.reach("pkg/a.py", world.config()) == "unknown"
    assert time.monotonic() - started < 2.0
    world.answer()
    assert world.point(budget=2.0).reach("pkg/a.py", world.config()) == "none"      # nothing wrong was remembered


def test_a_fact_is_cached_per_file_version_index_version_and_zone_file(world):
    world.add("pkg/a.py", "def f(): pass\n", ["f"])
    cfg = world.config()
    point = world.point()
    assert point.reach("pkg/a.py", cfg) == "none" and world.calls() == ["pkg.a.f"]
    second = world.point()
    assert second.reach("pkg/a.py", cfg) == "none" and world.calls() == ["pkg.a.f"]            # a hit: no new lookup
    assert second.stats["cached"] is True and point.stats["cached"] is False
    world.answer(pkg__a__f="certain")                                                           # the answer would change
    assert world.point().reach("pkg/a.py", cfg) == "none"                                       # but the cache holds
    world.point(("pkg.other.thing",))                                                           # another zone file misses
    assert world.point(("pkg.other.thing",)).reach("pkg/a.py", cfg) == "protected"
    world.db.execute("UPDATE files SET sha256 = ?", (hashlib.sha256(b"def f(): pass\n# x\n").hexdigest(),))
    world.db.commit()
    (world.project / "pkg" / "a.py").write_text("def f(): pass\n# x\n")
    assert world.point().reach("pkg/a.py", cfg) == "protected"                                  # the file changed: asked again


def test_warm_computes_every_file_so_a_later_hook_answers_from_the_cache(world):
    world.add("pkg/a.py", "def f(): pass\n", ["f"])
    world.add("pkg/b.py", "def g(): pass\n", ["g"])
    world.answer(pkg__b__g="certain")
    assert world.point().warm() == {"pkg/a.py": "none", "pkg/b.py": "protected"}
    before = len(world.calls())
    point = world.point()
    assert point.reach("pkg/a.py", world.config()) == "none" and point.reach("pkg/b.py", world.config()) == "protected"
    assert len(world.calls()) == before


def test_the_starters_ask_about_a_write_that_reaches_a_zone_and_leave_the_others(world):
    world.add("pkg/a.py", "def f(): pass\n", ["f"])
    world.add("pkg/b.py", "def g(): pass\n", ["g"])
    world.answer(pkg__b__g="certain")
    config = classifier.Config.for_workspace(world.project, zones=world.point())
    for name in sorted(STARTERS):
        reaches = _decide(name, classifier.classify(_call("write_file", path="pkg/b.py", content=""), config))
        quiet = _decide(name, classifier.classify(_call("write_file", path="pkg/a.py", content=""), config))
        assert (reaches.kind, reaches.cause_code) == ("escalate", 132), name
        assert (quiet.kind, quiet.cause_code) == (("escalate", 127) if name == "review" else ("allow", None)), name


def test_the_zones_command_records_reports_and_warms(world, home, image, monkeypatch, tmp_path):
    import io
    monkeypatch.setattr(commands, "config_dir", lambda env=None: home)
    (home / commands.POLICY_FILE).write_bytes(image)
    (home / commands.ATTESTATION_FILE).write_bytes(commands._attestation(home, image))
    world.add("pkg/a.py", "def f(): pass\n", ["f"])
    world.add("pkg/b.py", "def g(): pass\n", ["g"])
    world.answer(pkg__b__g="certain")
    monkeypatch.setenv("CONTEXTCLOUD", str(world.exe))
    monkeypatch.setattr(zones, "find_program", lambda exe, home, run=None: {"path": os.path.realpath(exe), "package": str(world.pkg)})
    saved = tmp_path / "saved-index.sqlite"
    saved.write_bytes(world.index.read_bytes())
    monkeypatch.setenv("FAKE_CC_INDEX_SRC", str(saved))

    def run(*args):
        out = io.StringIO()
        assert commands.zones_cmd(*args, as_json=True, out=out) == 0
        return json.loads(out.getvalue())

    assert run("status", world.project, None, None, None)["declared"] is False
    recorded = run("set", world.project, ["pkg.secure.check,pkg.x"], None, str(world.index))
    assert recorded["protected"] == ["pkg.secure.check", "pkg.x"] and recorded["recorded"] is True
    status = run("status", world.project, None, None, None)
    assert status["point"] == "contextcloud" and status["protected"] == recorded["protected"]
    assert os.path.exists(world.index)                                 # deleted and rebuilt after the zone file was signed
    assert run("warm", world.project, None, None, None)["by_fact"] == {"none": 1, "protected": 1, "unknown": 0}
    with pytest.raises(commands.AgentError):
        commands.zones_cmd("set", world.project, ["a b"], None, None, True, io.StringIO())


# ----------------------------------------------------------------------------------------- the real Context Cloud
real = pytest.mark.skipif(not DEMO_CC.exists() or not (DEMO / ".contextcloud" / "index.sqlite").exists()
                          or not (DEMO / "protected.txt").exists(), reason="the PyJWT demo is not at ~/contextcloud-demo")


@pytest.fixture()
def demo(tmp_path, home, image, monkeypatch):
    """The demo's index copied (the lookups open it), the demo project, its protected list: PyJWT's signature checks."""
    index = tmp_path / "index.sqlite"
    index.write_bytes((DEMO / ".contextcloud" / "index.sqlite").read_bytes())
    names = [line.strip() for line in (DEMO / "protected.txt").read_text().split("\n") if line.strip()]
    doc = zones.zone_document(names, DEMO / "pyjwt", index, image, program=zones.find_program(str(DEMO_CC), home))
    return zones.ContextCloudZones(doc, home, str(DEMO_CC)), classifier.Config.for_workspace(DEMO / "pyjwt")


@real
def test_an_edit_that_reaches_hmacalgorithm_verify_asks_and_one_that_does_not_keeps_its_old_verdict(demo):
    point, config = demo
    config.zones = point
    point.warm(["jwt/utils.py", "jwt/api_jwt.py"])       # a hook answers from the cache; the first lookups take longer than its budget
    for name in ("default", "strict"):
        defines = _decide(name, classifier.classify(_call("write_file", path="jwt/algorithms.py", content=""), config))
        reaches = _decide(name, classifier.classify(_call("write_file", path="jwt/api_jwt.py", content=""), config))
        quiet = _decide(name, classifier.classify(_call("write_file", path="jwt/utils.py", content=""), config))
        assert (defines.kind, defines.cause_code) == ("escalate", 132)       # HMACAlgorithm.verify is defined here
        assert (reaches.kind, reaches.cause_code) == ("escalate", 132)       # PyJWT.decode reaches it through PyJWS.decode
        assert (quiet.kind, quiet.cause_code) == ("allow", None)             # the old verdict
    assert _read(point, _call("write_file", path="jwt/algorithms.py", content=""))["zone_reach"] in ("unknown", "protected")


@real
def test_the_real_lookup_is_cached_and_a_warm_answer_is_fast(demo):
    point, config = demo
    cold_started = time.monotonic()
    first = point.reach("jwt/utils.py", config, budget_s=30.0)
    cold = time.monotonic() - cold_started
    warm_started = time.monotonic()
    second = point.reach("jwt/utils.py", config)
    warm = time.monotonic() - warm_started
    assert first == second == "none"
    assert point.stats["cached"] is True
    print(f"\nzone lookup of jwt/utils.py (12 functions): cold {cold * 1000:.0f} ms, warm {warm * 1000:.1f} ms")
    assert warm < 0.05


# ------------------------------------------------------------------ certainty and engine agreement as fields (A6)
from prismpath.ports.information import Change as _Change      # noqa: E402


def _facts(point, cfg, rel="pkg/a.py"):
    return point.facts(_Change(rel, cfg), 0.5)


def _point_with(world, **requirements):
    doc = zones.zone_document(("pkg.secure.check",), world.project, world.index, world.image,
                              program={"path": os.path.realpath(world.exe), "package": str(world.pkg)})
    return zones.ContextCloudZones(doc, world.home, str(world.exe), budget_s=2.0, **requirements)


def test_the_point_declares_the_two_fields_with_closed_lists_and_restrictive_values():
    point = zones.ContextCloudZones
    assert point.fields["cc_certainty"] == ("none", "likely", "certain", "unknown")
    assert point.fields["cc_engine_agreement"] == tuple(range(64))
    assert point.restrictive["cc_certainty"] == "unknown" and point.restrictive["cc_engine_agreement"] == 0
    assert all(point.restrictive[f] in point.fields[f] for f in point.fields)


@pytest.mark.parametrize("said,certainty,default,strict", [
    ("no", "none", "none", "none"), ("certain", "certain", "protected", "protected"),
    ("likely", "likely", "protected", "unknown"), ("unknown", "unknown", "unknown", "unknown"),
    ("error", "unknown", "unknown", "unknown"), ("surely", "unknown", "unknown", "unknown")])
def test_the_required_certainty_decides_what_a_likely_answer_reads(world, said, certainty, default, strict):
    world.add("pkg/a.py", "def f(): pass\n", ["f"])
    cfg = world.config()
    world.answer(pkg__a__f=said)
    for required, want in (("likely", default), ("certain", strict)):
        got = _facts(_point_with(world, required_certainty=required), cfg).readings
        assert got == {"zone_reach": want, "cc_certainty": certainty, "cc_engine_agreement": 0}, (said, required)
        assert (got["zone_reach"] == "none") == (certainty == "none")     # a likely answer is never read as none
        (world.home / zones.CACHE_FILE).unlink(missing_ok=True)


def test_the_default_requirement_is_what_the_point_always_read(world):
    world.add("pkg/a.py", "def f(): pass\ndef g(): pass\n", ["f", "g"])
    cfg = world.config()
    for said, want in (("no", "none"), ("certain", "protected"), ("likely", "protected"), ("unknown", "unknown")):
        world.answer(pkg__a__g=said)
        (world.home / zones.CACHE_FILE).unlink(missing_ok=True)
        assert _point_with(world).reach("pkg/a.py", cfg) == want == world.point().reach("pkg/a.py", cfg)


def test_a_file_reads_its_strongest_function_and_a_file_that_defines_protected_code_reads_certain(world):
    world.add("pkg/a.py", "def f(): pass\ndef g(): pass\ndef h(): pass\n", ["f", "g", "h"])
    world.add("pkg/secure.py", "def check(): pass\n", ["check"])
    cfg = world.config()
    strict = _point_with(world, required_certainty="certain")
    for answers, certainty, reach in (
            (dict(pkg__a__f="likely", pkg__a__g="certain", pkg__a__h="unknown"), "certain", "protected"),
            (dict(pkg__a__f="likely", pkg__a__g="unknown", pkg__a__h="no"), "likely", "unknown"),
            (dict(pkg__a__f="no", pkg__a__g="error", pkg__a__h="no"), "unknown", "unknown"),
            (dict(pkg__a__f="no", pkg__a__g="no", pkg__a__h="no"), "none", "none")):
        world.answer(**answers)
        (world.home / zones.CACHE_FILE).unlink(missing_ok=True)
        got = _facts(strict, cfg).readings
        assert (got["cc_certainty"], got["zone_reach"]) == (certainty, reach), answers
    defined = _facts(strict, cfg, "pkg/secure.py")
    assert defined.readings["cc_certainty"] == "certain" and defined.readings["zone_reach"] == "protected"
    assert defined.names == frozenset({"pkg.secure.check"})


def test_a_likely_answer_that_does_not_meet_the_requirement_names_no_protected_name(world):
    world.add("pkg/secure.py", "def check(): pass\n", ["check"])
    cfg = world.config()
    point = _point_with(world, engine_agreement=2)
    assert point.reach_names("pkg/secure.py", cfg) == ("unknown", frozenset()) and point.names == frozenset()


def test_an_engine_agreement_of_two_is_never_met_while_context_cloud_reports_none(world):
    world.add("pkg/a.py", "def f(): pass\n", ["f"])
    cfg = world.config()
    for said, want in (("certain", "unknown"), ("likely", "unknown"), ("no", "none"), ("unknown", "unknown")):
        world.answer(pkg__a__f=said)
        (world.home / zones.CACHE_FILE).unlink(missing_ok=True)
        got = _facts(_point_with(world, engine_agreement=2), cfg).readings
        assert got["zone_reach"] == want and got["cc_engine_agreement"] == 0, said
    assert _point_with(world, engine_agreement=1)._engines() == 0
    world.answer(pkg__a__f="certain")
    assert _facts(_point_with(world, engine_agreement=1), cfg).readings["zone_reach"] == "protected"


@pytest.mark.parametrize("required,agreement", [("strict", 1), (None, 1), ("", 1), ("Certain", 1), (["certain"], 1),
                                                ("likely", 0), ("likely", 65), ("likely", True), ("likely", "2"),
                                                ("likely", 1.0), ("likely", None), ("likely", -1)])
def test_a_requirement_the_grammar_does_not_allow_makes_every_path_read_the_restrictive_values(world, required, agreement):
    world.add("pkg/a.py", "def f(): pass\n", ["f"])
    world.add("pkg/secure.py", "def check(): pass\n", ["check"])
    world.answer(pkg__a__f="certain")
    point = _point_with(world, required_certainty=required, engine_agreement=agreement)
    assert point.why and "required" in point.why
    for rel in ("pkg/a.py", "pkg/secure.py"):
        evidence = _facts(point, world.config(), rel)
        assert evidence.readings == dict(point.restrictive) | {} and evidence.why == point.why
        assert evidence.names == frozenset()
    assert world.calls() == []                                    # nothing was asked


def test_every_error_path_reads_the_restrictive_values_of_both_fields(world, tmp_path):
    world.add("pkg/a.py", "def f(): pass\n", ["f"])
    world.add("pkg/stale.py", "def f(): pass\n", ["f"], index_text="an older version\n")
    (world.project / "README.md").write_text("x")
    cfg, point = world.config(), world.point()
    restrictive = dict(point.restrictive)
    # a file the index does not hold, a stale file, a file that is not Python, a path outside the project, a missing file
    for rel in ("pkg/none.py", "pkg/stale.py", "README.md", "../outside.py", "pkg/gone.py"):
        (world.project / "pkg" / "none.py").write_text("x = 1\n") if rel == "pkg/none.py" else None
        assert _facts(point, cfg, rel).readings == restrictive, rel
    # a lookup that fails, answers nonsense, or is too slow
    for said in ("error", "slow", "surely", ["certain"], {"certainty": "certain"}, 7, None):
        world.answer(pkg__a__f=said)
        (world.home / zones.CACHE_FILE).unlink(missing_ok=True)
        fast = world.point(budget=0.5)
        assert _facts(fast, cfg).readings == restrictive, said
    # a point that cannot answer at all: no host_path, an untrusted program, a raising path function
    doc = zones.zone_document(("pkg.x",), world.project, world.index, world.image,
                              program={"path": os.path.realpath(world.exe), "package": str(world.pkg)})
    from prismpath.information import contextcloud as _cc

    def boom(raw, config):
        raise RuntimeError("no")
    for blind in (_cc.ContextCloudZones(doc, world.home, str(world.exe)),
                  _cc.ContextCloudZones(doc, world.home, str(world.exe), host_path=boom)):
        assert _facts(blind, cfg).readings == restrictive
    other = dict(doc, program={"path": "/usr/bin/elsewhere", "package": str(world.pkg)})
    assert _facts(zones.ContextCloudZones(other, world.home, str(world.exe)), cfg).readings == restrictive


def test_a_cache_entry_from_before_the_certainty_was_kept_is_not_believed(world):
    point = world.point()
    point._cache_put("k", "protected")
    assert point._cache_get("k") is None
    point._cache_put("k", "likely")
    assert point._cache_get("k") == "likely"


def test_a_zone_reach_of_none_is_exactly_a_cc_certainty_of_none_for_every_requirement(world):
    world.add("pkg/a.py", "def f(): pass\n", ["f"])
    cfg = world.config()
    for said in ("no", "certain", "likely", "unknown", "error"):
        world.answer(pkg__a__f=said)
        for required in ("likely", "certain"):
            for agreement in (1, 2, 64):
                (world.home / zones.CACHE_FILE).unlink(missing_ok=True)
                got = _facts(_point_with(world, required_certainty=required, engine_agreement=agreement), cfg).readings
                assert (got["zone_reach"] == "none") == (got["cc_certainty"] == "none"), (said, required, agreement)
                if got["cc_certainty"] != "none":
                    assert got["zone_reach"] in ("protected", "unknown")
