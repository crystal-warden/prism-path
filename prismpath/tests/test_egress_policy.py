# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The compile and the proxy read the policy.

`compile_profile(image, role)` gives the agent role a `net` state from the image's allow set, and the egress proxy
decides each CONNECT by classifying it into a connect reading and deciding it under the same attested image,
writing a receipt in a run. These tests hold the two to the Lean oracle over the finite connect domain, and check
the receipts the proxy writes with `prismpath agent verify` and `prismpath agent rules`. No name is resolved and no
real connection is made: the proxy's resolver and connect are stand-ins."""
import itertools
import json
import os
import socket
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if not (ROOT / "formal" / "diff" / "core_diff.py").exists():
    pytest.skip("formal/diff is not beside this package (an installed wheel)", allow_module_level=True)
sys.path.insert(0, str(ROOT / "formal" / "diff"))
import core_diff  # noqa: E402
from prismpath.agent import classifier, commands, egress, egress_policy  # noqa: E402
from prismpath.agent.policy import STARTERS, Policy, starter_path  # noqa: E402
from prismpath.agent.profile import FORMAT, FORMAT_NET, Profile, ProfileError, compile_profile  # noqa: E402
from prismpath.kernel import canon2  # noqa: E402
from prismpath.tests.test_agent_cli import _agent_dir, _cli, _init, world  # noqa: E402,F401
from prismpath.tests.test_agent_egress import Echo, answer, connect_line, status, talk  # noqa: E402

PUBLIC = "93.184.216.34"
STARTER_BASH_HASH = "767dd3c8"
MODEL = "api.anthropic.com"
ALLOWED = "docs.example.com"
NET_DESTS = ("none", "model_api", "allowed_host", "other", "unknown")

ODD_HOSTS = [
    "API.ANTHROPIC.COM:443", "Api.Anthropic.Com:443", "api.anthropic.com.:443", "api.anthropic.com..:443",
    "api.anthropic.com@evil.example:443", "evil.example@api.anthropic.com:443", "user:pw@api.anthropic.com:443",
    "127.0.0.1:443", "0177.0.0.1:443", "2130706433:443", "0x7f000001:443", "127.1:443", "[::1]:443",
    "[::ffff:127.0.0.1]:443", "93.184.216.34:443", "api.anthropic.com", "api.anthropic.com:", "api.anthropic.com:0",
    "api.anthropic.com:65536", "api.anthropic.com:+443", "api.anthropic.com:443:443", "api.anthropic.com:80",
    "-api.anthropic.com:443", "api..anthropic.com:443", "api.anthropic.comé:443", "DOCS.EXAMPLE.COM:443",
    "docs.example.com.:443", "docs.example.com:8443", "other.example:443", ":443", "a:b:443",
]


def image(name):
    return starter_path(name).read_bytes()


def with_rules(starter, *rules):
    doc = canon2.loads(image(starter).rstrip(b"\n"))
    doc["rules"] = list(rules) + doc["rules"]
    return canon2.dumps(doc)


def _connect(target, *dests):
    """A rule for a connect the way the classifier reads one (no command, no git operation, no path)."""
    return {"target": target, "when": ["and", ["cmp", "tool", "==", ["str", "connect"]],
                                       ["in", "net_dest", [["str", d] for d in dests]],
                                       ["cmp", "command_class", "==", ["str", "none"]],
                                       ["cmp", "git_op", "==", ["str", "none"]],
                                       ["cmp", "path_scope", "==", ["str", "none"]]]}


ALLOW_HOST = _connect("allow", "allowed_host")
ALLOW_OTHER = _connect("allow", "other")
ALLOW_UNKNOWN = _connect("allow", "unknown")
REFUSE_MODEL = {"target": "refuse_130", "when": ["and", ["cmp", "tool", "==", ["str", "connect"]],
                                                 ["cmp", "net_dest", "==", ["str", "model_api"]]]}


# ----------------------------------------------------------------------------------------- the compile
@pytest.mark.parametrize("starter", sorted(STARTERS))
def test_starter_agent_role_is_proxy_model_and_bash_role_is_none(starter):
    agent, bash = compile_profile(image(starter), "agent"), compile_profile(image(starter), "bash")
    assert agent.net == "proxy_model" and bash.net == "none"
    assert compile_profile(image(starter)) == bash                      # bash is the default role
    assert bash.hash().startswith(STARTER_BASH_HASH)                    # the starter bash profile keeps its bytes
    assert bash.to_object()["format"] == FORMAT and "net" not in bash.to_object()
    assert agent.to_object()["format"] == FORMAT_NET == "prismpath.profile/2" and agent.to_object()["net"] == "proxy_model"
    assert agent.ro_mounts == ("/usr",) and not agent.network and not agent.host_write   # the fixed mounts


def test_an_image_allowing_allowed_host_gives_proxy_allow_for_the_agent_and_none_for_bash():
    raw = with_rules("default", ALLOW_HOST)
    assert compile_profile(raw, "agent").net == "proxy_allow"
    assert compile_profile(raw, "bash").net == "none"
    assert compile_profile(raw, "bash").hash().startswith(STARTER_BASH_HASH)


def test_other_and_unknown_never_give_a_state_and_an_image_with_no_connect_gives_none():
    assert compile_profile(with_rules("default", ALLOW_OTHER, ALLOW_UNKNOWN, REFUSE_MODEL), "agent").net == "none"
    assert compile_profile(with_rules("default", REFUSE_MODEL), "agent").net == "none"
    assert compile_profile(with_rules("default", ALLOW_OTHER, ALLOW_UNKNOWN), "agent").net == "proxy_model"


def test_the_agent_role_needs_the_net_fields_and_the_role_is_checked():
    doc = canon2.loads(image("default").rstrip(b"\n"))
    del doc["fields"]["net_dest"]
    doc["rules"] = [r for r in doc["rules"] if "net_dest" not in json.dumps(r["when"])]
    old = canon2.dumps(doc)
    with pytest.raises(ProfileError, match="net_dest"):
        compile_profile(old, "agent")
    with pytest.raises(ProfileError, match="role"):
        compile_profile(image("default"), "root")


def test_the_same_image_twice_gives_the_same_agent_profile_bytes():
    raw = with_rules("default", ALLOW_HOST)
    assert compile_profile(raw, "agent").canonical() == compile_profile(Policy(raw), "agent").canonical()


# ------------------------------------------------------------------------------- the oracle differential
def _grid(policy):
    """Every connect reading over net_dest, command_class, git_op, path_scope, remote_class and kill_by_pattern, the
    rest at the classifier's default for a connect (the path flags only matter to a write, which a connect is not)."""
    base = classifier.base_reading()
    base["tool"] = "connect"
    bools = ("kill_by_pattern",)
    axes = {"net_dest": NET_DESTS, "command_class": classifier.KNOWN_COMMANDS if hasattr(classifier, "KNOWN_COMMANDS")
            else ("none", "read_only", "mutating", "network", "git", "unknown"),
            "git_op": ("none", "local_read", "local_write", "mutating", "push", "network", "unknown"),
            "path_scope": ("none", "workspace", "outside", "unknown"), "remote_class": ("none", "allowed", "other")}
    for name in bools:
        axes[name] = (False, True)
    names = sorted(axes)
    for combo in itertools.product(*(axes[n] for n in names)):
        yield {**base, **dict(zip(names, combo))}


def _oracle_allows(raw_image, readings):
    policy = Policy(raw_image)
    case = {"id": "x", "image": raw_image.rstrip(b"\n"), "readings": [policy.reading_bytes(r) for r in readings]}
    rows = core_diff.lean_leg([case])["x"]["readings"]
    return [row["verdict"] == "route" and row["target"] == "allow" for row in rows]


@pytest.fixture(scope="module")
def oracle():
    if not core_diff.ORACLE.exists():
        if os.environ.get("PRISMPATH_REQUIRE_CORE_ORACLE"):
            pytest.fail(f"PRISMPATH_REQUIRE_CORE_ORACLE is set and {core_diff.ORACLE} is not built")
        pytest.skip("the core oracle is not built (cd formal && lake build)")


IMAGES = {
    "default": image("default"), "review": image("review"), "strict": image("strict"),
    "allow_host": with_rules("default", ALLOW_HOST),
    "allow_host_only": with_rules("default", REFUSE_MODEL, ALLOW_HOST),
    "allow_other": with_rules("default", ALLOW_OTHER, ALLOW_UNKNOWN),
    "refuse_model": with_rules("default", REFUSE_MODEL),
}


@pytest.mark.parametrize("name", sorted(IMAGES))
def test_the_compiled_net_state_agrees_with_the_oracle_over_every_connect_reading(oracle, name):
    readings = list(_grid(Policy(IMAGES[name])))
    allowed = _oracle_allows(IMAGES[name], readings)
    classes = {r["net_dest"] for r, ok in zip(readings, allowed) if ok}
    expected = "proxy_allow" if "allowed_host" in classes else "proxy_model" if "model_api" in classes else "none"
    assert compile_profile(IMAGES[name], "agent").net == expected
    assert compile_profile(IMAGES[name], "bash").net == "none"
    assert not classes & {"other", "unknown", "none"} or name == "allow_other"   # only the image that says so


@pytest.mark.parametrize("name", sorted(IMAGES))
def test_the_proxy_gate_agrees_with_the_oracle_and_lets_nothing_the_oracle_refuses_through(oracle, name, tmp_path):
    raw = IMAGES[name]
    policy, profile = Policy(raw), compile_profile(raw, "agent")
    gate = egress_policy.PolicyGate(policy, _MemoryStore(), "s", tmp_path, profile, allowed_hosts=(ALLOWED,))
    authorities = [f"{MODEL}:443", "platform.claude.com:443", f"{ALLOWED}:443", "other.example:443", *ODD_HOSTS]
    readings = [gate.reading(a) for a in authorities]
    allowed = _oracle_allows(raw, readings)
    for authority, reading, oracle_allows in zip(authorities, readings, allowed):
        passed, reason = gate(authority)
        assert reading["tool"] == "connect"
        if passed:
            assert oracle_allows, (authority, reading)        # never a reading the oracle refuses
            assert reading["net_dest"] in egress_policy.PROXY_CLASSES[profile.net]
        elif oracle_allows:
            assert reason == "profile-net"                    # stricter than the oracle only where the net state is
        else:
            assert reason.startswith(("refused-", "escalated-")), (authority, reason)
    if name == "default":
        assert [gate(a)[0] for a in (f"{MODEL}:443", f"{ALLOWED}:443")] == [True, False]
        assert not any(gate(a)[0] for a in ODD_HOSTS)


class _MemoryStore:
    """A store that keeps appended readings, for the oracle leg (the run-backed tests use the real store)."""
    class _Run:
        def __init__(self):
            self.entries = []

        def append(self, reading, verdict, decider=None, sandbox_profile=None):
            self.entries.append((reading, verdict, sandbox_profile))
            return len(self.entries) - 1

    def open(self, session, image):
        return self._Run()


# ---------------------------------------------------------------------- receipts and the real proxy
def _recorded(world):
    _init(world)
    return commands.load_checked(_agent_dir(world["home"]))


def _proxy(tmp_path, gate, echo):
    sock_dir = tmp_path / "sock"
    sock_dir.mkdir(exist_ok=True)
    return egress.EgressProxy(sock_dir / "e.sock", sock_dir / "e.log", gate=gate, resolver=lambda name: [PUBLIC],
                              connect=lambda address, port, timeout: socket.create_connection(("127.0.0.1", echo.port), timeout=timeout))


def _gate(world, tmp_path):
    policy, store = _recorded(world)
    profile = compile_profile(policy, "agent")
    return egress_policy.PolicyGate(policy, store, "egress-test", world["ws"], profile, allowed_hosts=(ALLOWED,))


def test_a_refused_connect_has_a_receipt_that_verify_accepts_and_rules_counts_under_the_network_refusal(world, tmp_path):
    echo = Echo()
    gate = _gate(world, tmp_path)
    with _proxy(tmp_path, gate, echo) as proxy:
        refused = answer(talk(proxy, connect_line("evil.example:443")))
        assert status(refused) == 403 and b"refused-130" in refused
        allowed = talk(proxy, connect_line(f"{MODEL}:443"))
        assert status(answer(allowed)) == 200
        allowed.close()
    echo.server.close()
    home = world["home"]
    verify = _cli(home, "agent", "verify", "--json")
    assert verify.returncode == 0, verify.stderr
    report = json.loads(verify.stdout)
    rows = {row["session"]: row for row in (report["runs"] if isinstance(report, dict) else report)}
    assert rows["egress-test"]["receipts"] == 2
    rules = json.loads(_cli(home, "agent", "rules", "--json").stdout)
    hits = lambda target: sum(row["hits"] for row in rules["rules"] if row["target"] == target)  # noqa: E731
    assert hits("refuse_130") == 1 and hits("allow") == 1
    assert rules["receipts"]["counted"] >= 2 and rules["receipts"]["not_verified"] == 0
    # the journal line carries the agent profile's hash, and the reading carries classes and no host
    run = gate.run
    lines = [json.loads(line) for line in (run.dir / "journal.jsonl").read_text().splitlines()]
    assert {line["sandbox"]["profile_sha256"] for line in lines} == {gate.profile.hash()}
    assert all(MODEL not in line["reading"] and "evil" not in bytes.fromhex(line["reading"]).decode() for line in lines)
    refusal = next(line for line in lines if json.loads(bytes.fromhex(line["reading"]))["net_dest"] == "other")
    assert refusal["receipt"]["decision"] == "route" and refusal["receipt"]["target"] == "refuse_130"   # cause 130


def test_the_odd_host_corpus_is_refused_at_the_proxy_with_the_classifiers_reading(world, tmp_path):
    echo = Echo()
    gate = _gate(world, tmp_path)
    with _proxy(tmp_path, gate, echo) as proxy:
        for authority in ODD_HOSTS:
            if authority == f"{MODEL}:443" or not authority.isascii():   # a non ASCII request line is malformed before any gate
                continue
            expected = gate.reading(authority)["net_dest"]
            reply = answer(talk(proxy, connect_line(authority)))
            assert status(reply) in (400, 403), (authority, reply)
            if expected in ("other", "unknown"):
                assert b"refused-130" in reply, (authority, reply)
    echo.server.close()
    readings = [json.loads(bytes.fromhex(json.loads(line)["reading"]))
                for line in (gate.run.dir / "journal.jsonl").read_text().splitlines()]
    kinds = {r["net_dest"] for r in readings}
    assert kinds <= {"other", "unknown", "allowed_host"} and {"other", "unknown"} <= kinds
    unknown = {gate.reading(a)["net_dest"] for a in ("API.ANTHROPIC.COM:443", "api.anthropic.com.:443",
                                                     "api.anthropic.com@evil.example:443", "0x7f000001:443",
                                                     "[::1]:443", "api.anthropic.com:65536", "api.anthropic.com")}
    assert unknown == {"unknown"}
    assert gate.reading("api.anthropic.com:80")["net_dest"] == "other"
    assert gate.reading("127.0.0.1:443")["net_dest"] == "other"          # a dotted quad is a well formed host to the classifier, and the policy refuses it


def test_a_gate_that_cannot_write_its_receipt_refuses(world, tmp_path):
    gate = _gate(world, tmp_path)

    class Broken:
        def open(self, session, image):
            raise OSError("disk full")
    gate.store = Broken()
    assert gate(f"{MODEL}:443") == (False, "receipt-error")


def test_an_escalation_is_a_refusal_at_the_proxy(tmp_path):
    raw = with_rules("default", _connect("escalate_124", "model_api"))
    gate = egress_policy.PolicyGate(Policy(raw), _MemoryStore(), "s", tmp_path, Profile(net="proxy_model"))
    assert gate(f"{MODEL}:443") == (False, "escalated-124")
