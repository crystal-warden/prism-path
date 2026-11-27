# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The golden capture the refactor packages rest on.

With fixed keys, a fixed clock and a fixed `time_us` it seals one envelope of every artifact kind, decides a fixed
list of readings through the hook, the action floor, the MCP proxy, the egress proxy and the gateway, seals the run
that the hook wrote, and builds one state record that carries a heartbeat body. It compares the SHA-256 of each
output with `fixtures/refactor_golden.json`.

A refactor package moves, renames or routes, so every digest here stays as it is. The fixture is a frozen path
(`tools/frozen_paths.txt`), so a refactor branch cannot change it. To write it again, which only a feature package
that changes bytes on purpose does, run `python -m prismpath.tests.test_refactor_golden --write`.

What is left out, because it is not the same bytes twice, is named in `LEFT_OUT` and in `test_the_left_out_list`.
"""
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

pytest.importorskip("cryptography")
pytest.importorskip("fcntl")

from prismpath import canon  # noqa: E402
from prismpath.agent import classifier, commands, egress_policy, mcp_proxy, profile  # noqa: E402
from prismpath.agent import policy as policymod  # noqa: E402
from prismpath.agent.run import RunStore  # noqa: E402
from prismpath.distribution import envelope as env  # noqa: E402
from prismpath.distribution import floor as floors  # noqa: E402
from prismpath.distribution import heartbeat, install, kinds, state_record  # noqa: E402
from prismpath.gateway import cli as gateway_cli, proxy as gateway_proxy, reading as gateway_reading  # noqa: E402
from prismpath.tests import _dist  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "refactor_golden.json"
GEN = _dist.GEN

NOW = _dist.NOW                              # the fixed clock, seconds
TIME_US = (NOW + 7) * 1_000_000              # the fixed time_us of every seal
STREAM = _dist.STREAM

# Outputs that are not the same bytes in two processes, so they are not in the fixture and nothing here changed
# the code to make them so.
LEFT_OUT = {
    "the attestation file of a home": "it seals a policy.core with the wall clock, so it differs from one second to the next",
    "the answer to an allowed shell call": "it carries the sandbox rewrite, which names this interpreter and the temporary directories, "
                                           "and it exists only where a sandbox does, so the capture decides no allowed shell call",
    "the session id of a gateway made with no id": "it carries the wall clock and a random suffix, so the capture names its session",
}


# ------------------------------------------------------------------------------------------------ fixed keys
def fixed_key(name: str):
    """The Ed25519 key whose seed is the SHA-256 of a fixed phrase. Ed25519 signatures are deterministic."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(f"prismpath refactor golden key {name}".encode()).digest())


def write_key_pair(directory: Path, role: str) -> None:
    """`<role>.key` as PKCS8 PEM and `<role>.pub` as the 32 raw bytes, the file shapes `keygen` writes."""
    from cryptography.hazmat.primitives import serialization as ser
    private = fixed_key(role)
    directory.mkdir(parents=True, exist_ok=True)
    pem = private.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption())
    fd = os.open(directory / f"{role}.key", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(pem)
    (directory / f"{role}.pub").write_bytes(private.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw))


def sha(data) -> str:
    return hashlib.sha256(data if isinstance(data, bytes) else data.encode("utf-8")).hexdigest()


def digest_of(value) -> str:
    """The digest of a JSON value as canon/2 bytes."""
    return sha(canon.canon2_bytes(value))


# ------------------------------------------------------------------------------- one envelope of every kind
GENERIC_META = {"fields": {"x": "int"}, "wcet_cycles": 7, "qualification": "golden-qualification",
                "counts": {"atoms": 1, "nodes": 1, "edges": 1, "prog_words": 1, "max_steps": 1, "max_stack": 1},
                "compiler": 1, "flow_sha256": "ab" * 32, "names_sha256": "cd" * 32}
HOSTS = canon.canon2_bytes(["api.example.com"])
CORE = policymod.starter_path("default").read_bytes().rstrip(b"\n")


def _meta(kind: str) -> dict:
    required = kinds.ARTIFACTS[kind].meta_required
    return {name: GENERIC_META[name] for name in sorted(required)}


def sealed_envelope(kind: str) -> bytes:
    """One sealed envelope of the artifact kind `kind` over a fixed body, signed by the fixed test key A."""
    body = f"golden body of {kind}".encode()
    trust = kind in kinds.TRUST_ARTIFACTS
    on_trust = kind in kinds.ON_TRUST_STREAM
    if kind in kinds.INSTALL_ARTIFACTS:
        stream_name, zero = STREAM, env.ZERO_HASH
        if kind in ("install.trust", kinds.INSTALL_CHANGE):
            raw = env.build(kind, body, stream=stream_name, seq=1, targets=("agent",), not_before=_dist.NOT_BEFORE,
                            expires=0, policy_sha256=zero, release=zero, meta={})
        else:
            named = kinds.POLICY_LIST if kind == "install.ceiling" else "egress.hosts"
            raw = env.build(kind, HOSTS, stream=stream_name, seq=1, targets=("agent",), not_before=_dist.NOT_BEFORE,
                            expires=0, policy_sha256=canon.sha256_hex(HOSTS) if named == kinds.POLICY_LIST else zero,
                            release=env.install_release_id([("egress.hosts", canon.sha256_hex(HOSTS))]),
                            meta={"as": named} if named == kinds.POLICY_LIST else {"as": "egress.hosts"})
        return env.seal(raw, [GEN.test_key("N1")])
    if kind == kinds.ANSWER:
        raw = env.build(kind, body, stream=STREAM, seq=1, targets=("agent",), not_before=_dist.NOT_BEFORE,
                        expires=_dist.NOT_BEFORE + 300, policy_sha256=canon.sha256_hex(body), release=env.ZERO_HASH,
                        meta={})
        return env.seal(raw, [GEN.test_key("O1")])
    raw = env.build(kind, body, stream=env.TRUST_STREAM if on_trust else STREAM, seq=1, targets=("host",),
                    not_before=_dist.NOT_BEFORE, expires=0 if trust else _dist.EXPIRES,
                    policy_sha256=env.ZERO_HASH if on_trust else canon.sha256_hex(body),
                    release=env.ZERO_HASH if on_trust else (env.ZERO_HASH if trust else env.release_id([(kind, canon.sha256_hex(body))])),
                    meta=_meta(kind))
    return env.seal(raw, [GEN.test_key("A")])


def envelope_digests() -> dict:
    return {f"envelope/{kind}": sha(sealed_envelope(kind)) for kind in sorted(kinds.ARTIFACTS)}


# -------------------------------------------------------------------------------------- the fixed readings
def agent_readings(count: int = 6):
    """Readings of the default policy's domain, one per class combination in order, the first `count`."""
    import itertools
    policy = policymod.Policy(CORE)
    names, constant, groups = profile.domain_classes([policy.doc])
    combos = itertools.islice(itertools.product(*groups), count)
    return [dict(zip(names, (group[0] for group in combo)), **constant) for combo in combos]


HOOK_CALLS = [
    ("Read", {"file_path": "notes.txt"}),
    ("Read", {"file_path": "/etc/hostname"}),
    ("Grep", {"pattern": "note"}),
    ("Bash", {"command": "touch made.txt", "description": "make a file"}),
    ("Bash", {"command": "curl http://example.com"}),
    ("Write", {"file_path": "out.txt", "content": "x"}),
    ("Glob", {"pattern": "*.txt"}),
]
MCP_CALLS = [
    {"name": "echo", "arguments": {"text": "hello"}},
    {"name": "read_file", "arguments": {"path": "/etc/passwd"}},
    {"name": "write_file", "arguments": {"path": "out.txt", "content": "x"}},
    {"name": "git_push", "arguments": {"remote": "origin"}},
]
EGRESS_AUTHORITIES = ["api.anthropic.com:443", "docs.example.com:443", "other.example:443", "127.0.0.1:443",
                      "API.ANTHROPIC.COM:443", "docs.example.com:8443"]
GATEWAY_REQUESTS = [
    ("GET", "/api/orders/7?x=1", {}, 0), ("POST", "/api/orders", {"content-type": ["application/json"]}, 12),
    ("DELETE", "/admin/users/1", {}, 0), ("GET", "/health", {}, 0), ("GET", "/a/../b", {}, 0),
    ("PURGE", "/api/orders/9", {}, 0),
]
FLOOR_FIELDS = ("tool", "path_scope", "command_class", "path_control", "zone_reach", "zone_name")


def _floor_image() -> bytes:
    from prismpath.kernel.policy_source import compile_source
    head = "".join(f"field.{name}: {'bool' if name == 'path_control' else 'category'}\n" for name in FLOOR_FIELDS)
    return compile_source("---\nname: floor\nstart: core_decision\n" + head + "---\n## core_decision\n"
                          '-> allow: when tool == "list_dir" and path_scope == "workspace"\n'
                          '-> allow: when tool == "read_file" and path_scope == "workspace"\n')


FLOOR_REQUESTS = [
    {"reading": {"tool": tool, "path_scope": scope, "command_class": "none", "path_control": False,
                 "zone_reach": "none", "zone_name": ""}}
    for tool, scope in (("list_dir", "workspace"), ("read_file", "workspace"), ("delete_path", "workspace"),
                        ("read_file", "outside"), ("unknown", "unknown"))] + [{"host": "api.example.com"}, {"host": "evil.example"}]


# ------------------------------------------------------------------------------------------ the five points
def make_agent_home(home: Path, image: bytes = None) -> Path:
    """An agent directory as `agent init` leaves it, with the fixed authority and instance keys."""
    commands._make_dir(home)
    for role in commands.KEY_ROLES:
        write_key_pair(home, role)
        commands._ensure_key(home, role)
    image = image or policymod.Policy.load(policymod.POLICY_PATH).image
    (home / commands.POLICY_FILE).write_bytes(image)
    (home / commands.ATTESTATION_FILE).write_bytes(commands._attestation(home, image))
    return home


def journal_digest(run) -> str:
    """The journal of a run is canon/2 lines with no clock in them."""
    return sha((run.dir / "journal.jsonl").read_bytes())


def hook_digests(tmp: Path) -> dict:
    out = {}
    root = tmp / "hook-root"
    home = make_agent_home(root / ".config" / "prismpath" / "agent")
    workspace = tmp / "workspace"
    workspace.mkdir()
    (workspace / "notes.txt").write_text("a note\n")
    env_ = {"HOME": str(root)}
    kinds_seen = []
    for number, (tool, tool_input) in enumerate(HOOK_CALLS):
        if "file_path" in tool_input and not tool_input["file_path"].startswith("/"):
            tool_input = {**tool_input, "file_path": str(workspace / tool_input["file_path"])}
        raw = json.dumps({"session_id": "golden-hook", "cwd": str(workspace), "hook_event_name": "PreToolUse",
                          "tool_name": tool, "tool_input": tool_input, "tool_use_id": f"toolu_golden{number}"}).encode()
        answer = commands.hook(raw, env_)["hookSpecificOutput"]
        kinds_seen.append([answer["permissionDecision"], answer.get("permissionDecisionReason")])
    store = RunStore(home / commands.RUNS_DIR)
    run = store.get("golden-hook")
    out["hook/decisions"] = digest_of(kinds_seen)
    out["hook/journal"] = journal_digest(run)
    keys = tmp / "seal-keys"
    write_key_pair(keys, "authority")
    write_key_pair(keys, "instance")
    manifest = run.seal(keys, time_us=TIME_US)
    out["seal/manifest"] = digest_of(manifest)
    for name in ("run.json", "cases.jsonl", "images.jsonl", "receipts.jsonl", "receipts.roots.jsonl", "authority.pub",
                 "instance.pub"):
        out[f"seal/{name}"] = sha((run.dir / name).read_bytes())
    return out


def floor_digests() -> dict:
    image = _floor_image()
    answers = []
    for request in FLOOR_REQUESTS:
        answer = floors.ask("agent", {"policy.core": image, "egress.hosts": canon.canon2_bytes(["api.example.com"])},
                            request, floor=True)
        answers.append(answer.document(canon.sha256_hex(image)) | {"rule": answer.rule, "allow_only": answer.allow_only})
    return {"floor/answers": digest_of(answers), "floor/image": sha(image)}


def mcp_digests(tmp: Path) -> dict:
    home = make_agent_home(tmp / "mcp-home")
    workspace = tmp / "mcp-ws"
    workspace.mkdir()
    governor = mcp_proxy.Governor(home, tmp / "mcp-runs", "golden-mcp", workspace, str(workspace))
    outcomes = []
    for params in MCP_CALLS:
        outcome = governor.decide(params)
        outcomes.append([outcome.kind, outcome.cause, outcome.code, outcome.receipt, outcome.failure])
    run = RunStore(tmp / "mcp-runs").get("golden-mcp")
    return {"mcp/outcomes": digest_of(outcomes), "mcp/journal": journal_digest(run)}


def egress_digests(tmp: Path) -> dict:
    home = make_agent_home(tmp / "egress-home")
    policy, store = commands.load_checked(home)
    store = RunStore(tmp / "egress-runs")
    workspace = tmp / "egress-ws"
    workspace.mkdir()
    prof = profile.compile_profile(policy.image, "agent")
    gate = egress_policy.PolicyGate(policy, store, "golden-egress", workspace, prof, allowed_hosts=("docs.example.com",))
    answers = [list(gate(authority)) for authority in EGRESS_AUTHORITIES]
    return {"egress/answers": digest_of(answers), "egress/journal": journal_digest(store.get("golden-egress"))}


def gateway_digests(tmp: Path) -> dict:
    home = tmp / "gateway-home"
    commands._make_dir(home)
    for role in commands.KEY_ROLES:
        write_key_pair(home, role)
    gateway_cli.init(home, None, out=io.StringIO())
    routes = gateway_reading.Routes.load(gateway_cli.DEMO_ROUTES)
    gateway = gateway_proxy.Gateway("http://127.0.0.1:9", routes, home, session="golden-gateway")
    outcomes = []
    for method, target, headers, length in GATEWAY_REQUESTS:
        reading = gateway_reading.read_request(method, target, headers, routes, length)
        outcome = gateway.decide(reading)
        outcomes.append([outcome.kind, outcome.cause, outcome.code, outcome.receipt, outcome.failure])
    return {"gateway/outcomes": digest_of(outcomes), "gateway/journal": journal_digest(gateway.run)}


def state_record_digests() -> dict:
    key = _dist.instance_key("I")
    readings = agent_readings(6)
    body = heartbeat.body(CORE, readings)
    record = state_record.StateRecord(
        event="beat", state="active", cause=None, pep_id=state_record.pep_id(key.public_raw), counter=7, time=NOW,
        stream=state_record.stream_prefix(STREAM), active_policy=state_record.prefix(canon.sha256_hex(CORE)),
        active_release=state_record.prefix(canon.sha256_hex(b"release")), active_seq=1, floor=1, body=body)
    signed = state_record.build(record, key)
    return {"state_record/heartbeat_body": sha(body), "state_record/record": sha(signed)}


# ------------------------------------------------------------------------------------------------ the capture
def capture(tmp: Path) -> dict:
    """Every digest, by name. `tmp` is a directory this run owns."""
    tmp = Path(tmp)
    out = {}
    out.update(envelope_digests())
    out.update(hook_digests(tmp))
    out.update(floor_digests())
    out.update(mcp_digests(tmp))
    out.update(egress_digests(tmp))
    out.update(gateway_digests(tmp))
    out.update(state_record_digests())
    return dict(sorted(out.items()))


def write_fixture() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        out = capture(Path(tmp))
    FIXTURE.write_text(json.dumps(out, indent=2, sort_keys=True) + "\n")
    print(f"wrote {len(out)} digests to {FIXTURE}")


# ----------------------------------------------------------------------------------------------------- tests
def test_the_capture_matches_the_fixture(tmp_path):
    expected = json.loads(FIXTURE.read_text())
    got = capture(tmp_path)
    assert sorted(got) == sorted(expected), "the capture names other outputs than the fixture"
    changed = [name for name in expected if got[name] != expected[name]]
    assert changed == [], f"a refactor changes no byte, and these outputs changed: {changed}"


def test_the_capture_is_the_same_in_another_process_and_another_directory(tmp_path):
    """Passes twice in a row in separate processes, with a different process id and a different temporary directory."""
    code = ("import json, sys; from pathlib import Path; from prismpath.tests import test_refactor_golden as g; "
            "print(json.dumps(g.capture(Path(sys.argv[1])), sort_keys=True))")
    runs = []
    for number in range(2):
        work = tmp_path / f"process-{number}"
        work.mkdir()
        done = subprocess.run([sys.executable, "-c", code, str(work)], capture_output=True, text=True,
                              env=dict(os.environ, PYTHONPATH=str(REPO)), cwd=str(work), timeout=600)
        assert done.returncode == 0, done.stderr
        runs.append(json.loads(done.stdout.strip().splitlines()[-1]))
    assert runs[0] == runs[1] == json.loads(FIXTURE.read_text())


def test_every_artifact_kind_has_an_envelope_in_the_fixture():
    expected = json.loads(FIXTURE.read_text())
    assert {name for name in expected if name.startswith("envelope/")} == {f"envelope/{kind}" for kind in kinds.ARTIFACTS}


def test_the_left_out_list():
    assert LEFT_OUT, "an output that is left out is named, with the reason"


if __name__ == "__main__":
    if sys.argv[1:] == ["--write"]:
        write_fixture()
    else:
        sys.exit("python -m prismpath.tests.test_refactor_golden --write")
