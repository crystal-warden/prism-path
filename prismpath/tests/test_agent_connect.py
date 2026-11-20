# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The classifier's connect call, its `net_dest` and `proc_class` fields, and what the starters decide about them
(docs/design/spec-verified-classifier.md, section 4.4; the Lean model is formal/Classifier/Net.lean and the differential
harness formal/diff/classifier_diff.py holds the Python to it)."""
import itertools
import random
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from prismpath.agent import classifier, mcp_map  # noqa: E402
from prismpath.agent.policy import STARTERS, Policy, net_gap, starter_path  # noqa: E402
from prismpath.kernel import canon2  # noqa: E402

CONFIG = classifier.Config(Path("/"), (), (), ("docs.example.org", "1.2.3.4"))


def _dest(host, port=443, config=CONFIG):
    return classifier.classify({"tool": "connect", "args": {"host": host, "port": port}}, config)["net_dest"]


@pytest.mark.parametrize("host,port,want", [
    ("api.anthropic.com", 443, "model_api"), ("platform.claude.com", 443, "model_api"),
    ("api.anthropic.com", 80, "other"), ("api.anthropic.com", 8443, "other"),
    ("docs.example.org", 443, "allowed_host"), ("docs.example.org", 80, "other"), ("1.2.3.4", 443, "allowed_host"),
    ("example.com", 443, "other"), ("api.anthropic.com.evil.example", 443, "other"), ("evil-api.anthropic.com", 443, "other"),
    ("8.8.8.8", 443, "other"), ("127.0.0.1", 443, "other"), ("a", 443, "other"), ("xn--e1afmkfd.example", 443, "other"),
    # not read: case, dots, userinfo, ports and paths in the host, short and odd IP forms, brackets, limits, non ASCII
    ("API.ANTHROPIC.COM", 443, "unknown"), ("Api.anthropic.com", 443, "unknown"), ("api.anthropic.com.", 443, "unknown"),
    (".api.anthropic.com", 443, "unknown"), ("api..anthropic.com", 443, "unknown"),
    ("api.anthropic.com@evil.example", 443, "unknown"), ("evil.example@api.anthropic.com", 443, "unknown"),
    ("api.anthropic.com:443", 443, "unknown"), ("https://api.anthropic.com", 443, "unknown"),
    ("api.anthropic.com/x", 443, "unknown"), ("api.anthropic.com\x00", 443, "unknown"), ("", 443, "unknown"),
    ("127.1", 443, "unknown"), ("2130706433", 443, "unknown"), ("0x7f.0.0.1", 443, "unknown"),
    ("0x7f000001", 443, "unknown"), ("0177.0.0.1", 443, "unknown"), ("1.2.3", 443, "unknown"),
    ("1.2.3.4.5", 443, "unknown"), ("256.1.1.1", 443, "unknown"), ("01.2.3.4", 443, "unknown"),
    ("[::1]", 443, "unknown"), ("::1", 443, "unknown"), ("fe80::1%eth0", 443, "unknown"),
    ("-a.example", 443, "unknown"), ("a-.example", 443, "unknown"), ("a b.example", 443, "unknown"),
    ("a" * 63 + ".com", 443, "other"), ("a" * 64 + ".com", 443, "unknown"),
    (".".join(["a" * 63, "a" * 63, "a" * 63, "a" * 61]), 443, "other"),
    (".".join(["a" * 63, "a" * 63, "a" * 63, "a" * 62]), 443, "unknown"), ("b" * 253, 443, "unknown"),
    ("\xe9.example", 443, "unknown"),
    ("аpi.anthropic.com", 443, "unknown"),
    # the port
    ("api.anthropic.com", 0, "unknown"), ("api.anthropic.com", 65536, "unknown"), ("api.anthropic.com", -443, "unknown"),
    ("api.anthropic.com", 2 ** 64, "unknown"), ("example.com", 1, "other"), ("example.com", 65535, "other"),
])
def test_the_class_of_a_host_and_port(host, port, want):
    assert _dest(host, port) == want


def test_a_connect_reads_nothing_but_its_class():
    reading = classifier.classify({"tool": "connect", "args": {"host": "api.anthropic.com", "port": 443}}, CONFIG)
    assert reading == {**classifier.base_reading(), "tool": "connect", "net_dest": "model_api"}
    assert reading["classifier_version"] == 2 == classifier.CLASSIFIER_VERSION


@pytest.mark.parametrize("call", [
    {"tool": "connect"}, {"tool": "connect", "args": {}}, {"tool": "connect", "args": {"host": "a.example"}},
    {"tool": "connect", "args": {"port": 443}}, {"tool": "connect", "args": {"host": "a.example", "port": True}},
    {"tool": "connect", "args": {"host": "a.example", "port": 443.0}}, {"tool": "connect", "args": {"host": "a.example", "port": "443"}},
    {"tool": "connect", "args": {"host": 1, "port": 443}}, {"tool": "connect", "args": {"host": "a.example", "port": 443, "x": 1}},
    {"tool": "Connect", "args": {"host": "a.example", "port": 443}}, {"tool": "connect", "args": {"host": "a\ud800", "port": 443}},
])
def test_a_connect_call_that_does_not_fit_the_schema_reads_unknown(call):
    assert classifier.classify(call, CONFIG) == classifier.unknown_reading()


def test_nothing_but_a_connect_has_a_destination_and_a_server_tool_named_connect_is_not_one():
    for call in ({"tool": "run_command", "args": {"argv": ["ls"]}}, {"tool": "git", "args": {"subcommand": "status"}},
                 {"tool": "read_file", "args": {"path": "a"}}, {"tool": "unknown", "args": {}}):
        assert classifier.classify(call, CONFIG)["net_dest"] == "none"
    params = {"name": "connect", "arguments": {"host": "api.anthropic.com", "port": 443}}
    assert mcp_map.classifier_call(params, "/srv") == {"tool": "unknown", "args": {}}
    assert "connect" not in classifier.TOOLS


@pytest.mark.parametrize("argv,want", [
    (["ls"], "single"), (["cat", "a"], "single"), (["rm", "a"], "single"), (["git", "status"], "single"), (["curl", "x"], "single"),
    (["/usr/bin/ls"], "single"), (["make"], "tree"), (["pytest", "-n", "4"], "tree"), (["npm", "test"], "tree"),
    (["cargo", "build"], "tree"), (["pip", "install", "x"], "tree"), (["python3", "x.py"], "tree"), (["sh", "-c", "x"], "tree"),
    (["env", "ls"], "tree"), (["find", ".", "-exec", "ls", "{}", ";"], "tree"), (["find", ".", "-name", "a"], "single"),
    (["find", ".", "-delete"], "single"), (["./tool"], "unknown"), (["/opt/x/tool"], "unknown"), (["sudo", "ls"], "unknown"),
    (["mytool"], "unknown"), (["/usr/bin/"], "unknown"),
])
def test_proc_class_of_a_command(argv, want):
    assert classifier.classify({"tool": "run_command", "args": {"argv": argv}}, classifier.Config(Path("/")))["proc_class"] == want


def test_a_command_the_classifier_cannot_read_has_an_unknown_process_class_and_other_tools_have_none():
    config = classifier.Config(Path("/"))
    assert classifier.classify({"tool": "run_command", "args": {"argv": []}}, config)["proc_class"] == "unknown"
    assert classifier.classify({"tool": "run_command", "args": {"argv": [1]}}, config)["proc_class"] == "unknown"
    assert classifier.classify({"tool": "read_file", "args": {"path": "a"}}, config)["proc_class"] == "none"


# ------------------------------------------------------------------------------------------ the starters
def _decide(policy, reading):
    return policy.decide(canon2.dumps(reading))


@pytest.mark.parametrize("name", sorted(STARTERS))
def test_every_starter_allows_the_model_api_and_refuses_every_other_destination_with_cause_130(name):
    policy = Policy.load(starter_path(name))
    for host, port, want in [("api.anthropic.com", 443, "allow"), ("platform.claude.com", 443, "allow"),
                             ("docs.example.org", 443, "refuse"), ("example.com", 443, "refuse"),
                             ("api.anthropic.com", 80, "refuse"), ("API.ANTHROPIC.COM", 443, "refuse"),
                             ("api.anthropic.com", 0, "refuse"), ("127.0.0.1", 443, "refuse")]:
        reading = classifier.classify({"tool": "connect", "args": {"host": host, "port": port}}, CONFIG)
        decision = _decide(policy, reading)
        assert decision.kind == want, (host, port, decision)
        if want == "refuse":
            assert decision.cause == "agent:net-refused" and decision.cause_code == 130


@pytest.mark.parametrize("name", sorted(STARTERS))
def test_a_connect_reading_that_names_no_class_is_refused_too(name):
    policy = Policy.load(starter_path(name))
    reading = {**classifier.base_reading(), "tool": "connect", "net_dest": "none"}
    assert _decide(policy, reading).cause_code == 130


@pytest.mark.parametrize("name", sorted(STARTERS))
def test_the_starters_pass_the_python_form_of_the_network_check(name):
    assert net_gap(Policy.load(starter_path(name))) is None


def test_a_policy_that_lets_another_destination_through_is_named_by_the_check():
    doc = canon2.loads(Policy.load(starter_path("default")).image)
    doc["rules"] = [r for r in doc["rules"] if r["target"] != "refuse_130"]
    gap = net_gap(Policy(canon2.dumps(doc)))
    assert gap is not None and "does not refuse a connection" in gap
    older = Policy((Path(__file__).parent / "fixtures" / "agent_old_starters" / "default-ccf2f60.core.json").read_bytes())
    assert "no net_dest field" in net_gap(older)


def test_existing_readings_keep_their_verdicts_under_the_new_starters():
    """Every reading a call that is not a connect can make (net_dest none, any proc_class) is decided as the starter
    from before the connect rule decided it, for a seeded sample of the whole space."""
    old_dir = Path(__file__).parent / "fixtures" / "agent_old_starters"
    old = {"default": "default-ccf2f60", "review": "review-ccf2f60", "strict": "strict-ccf2f60"}
    flags = ("kill_by_pattern", "path_control", "path_in_toolchain", "path_glob", "path_traversal", "path_symlink")
    rng = random.Random(20261120)
    space = list(itertools.product(
        ("list_dir", "read_file", "write_file", "delete_path", "run_command", "git", "unknown"),
        ("none", "workspace", "outside", "unknown"), ("none", "read_only", "mutating", "network", "git", "unknown"),
        ("none", "local_read", "local_write", "mutating", "push", "network", "unknown"), ("none", "allowed", "other")))
    for name, stem in old.items():
        before = Policy((old_dir / f"{stem}.core.json").read_bytes())
        after = Policy.load(starter_path(name))
        for tool, scope, command, git_op, remote in rng.sample(space, 600):
            hazards = {flag: rng.random() < 0.3 for flag in flags}
            reading = {"tool": tool, "path_scope": scope, "command_class": command, "git_op": git_op,
                       "remote_class": remote, **hazards}
            was = _decide(before, {"classifier_version": 1, **reading})
            now = _decide(after, {"classifier_version": 2, "net_dest": "none",
                                  "proc_class": rng.choice(("none", "single", "tree", "unknown")), **reading})
            assert (now.kind, now.cause) == (was.kind, was.cause), (name, reading)
