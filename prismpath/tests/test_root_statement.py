# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Root statements: the instance key's signed, chained statement of an audit log's Merkle root.

A receipt is a leaf; a statement signs the root over the first N leaves and names the statement
before it. Pinned here: the statement round trip, every way a log or its statements can be changed
after signing (truncation, a rewritten receipt, a wrong key, a broken chain, a statement whose root
does not match), the separation of the instance key from the policy authority key, an unsigned log
from before signing, one receipt checked offline on its own, and the one line a missing signing
extra prints."""
import json
import os
import subprocess
import sys

import pytest

pytest.importorskip("cryptography")

import prismpath  # noqa: E402
from prismpath import cli  # noqa: E402
from prismpath.ledgers import audit_log, ledger_ots, root_statement as rs  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(prismpath.__file__)))
INSTALL_LINE = "needs cryptography (the signing extra): pip install 'prismpath[signing]'"

FLOW = """---
name: t
start: a
---

## a
Do the thing.
-> b: when tests_pass

## b
Done.
"""


def _cli(*argv, block=(), cwd=None):
    """The command line in a fresh interpreter, with `block` made unimportable as a plain install leaves it."""
    script = ("import sys\n"
              f"for name in {list(block)!r}:\n"
              "    sys.modules[name] = None\n"
              "from prismpath.cli import main\n"
              "raise SystemExit(main(sys.argv[1:]))\n")
    env = {**os.environ, "PYTHONPATH": REPO_ROOT + os.pathsep + os.environ.get("PYTHONPATH", "")}
    env.pop(rs.INSTANCE_KEY_ENV, None)
    return subprocess.run([sys.executable, "-c", script, *argv], capture_output=True, text=True, env=env, cwd=cwd)


# ------------------------------------------------------------------ the parts that need no key

def test_merkle_root_is_the_ledger_root():
    leaves = [rs.canon.sha256_hex(bytes([index])) for index in range(11)]
    for count in range(len(leaves) + 1):
        expected = ledger_ots.merkle_root_and_paths(leaves[:count])[0] or ""
        assert rs.merkle_root(leaves[:count]) == expected


def test_the_accumulator_is_the_same_root_for_every_count():
    leaves = [rs.canon.sha256_hex(bytes([index % 256, index // 256])) for index in range(300)]
    accumulator = rs.MerkleAccumulator()
    assert accumulator.root() == ""
    for count, leaf in enumerate(leaves, start=1):
        accumulator.add(leaf)
        assert accumulator.count == count
        assert accumulator.root() == rs.merkle_root(leaves[:count]), count
    assert rs.MerkleAccumulator(leaves).root() == rs.merkle_root(leaves)


def test_prefix_roots_answer_every_count_in_one_pass():
    leaves = [rs.canon.sha256_hex(bytes([index])) for index in range(40)]
    roots = rs.prefix_roots(leaves, [40, 0, 7, 7, 33, 41, -1, "x"])
    assert roots == {count: rs.merkle_root(leaves[:count]) for count in (0, 7, 33, 40)}


def test_statements_sit_beside_the_log():
    assert rs.statements_path_for("run.audit.jsonl") == "run.audit.roots.jsonl"
    assert rs.statements_path_for("state/swaps.log") == "state/swaps.log.roots.jsonl"


def test_an_unsigned_log_reads_as_unsigned_not_failed(tmp_path):
    log = audit_log.AuditLog(str(tmp_path / "old.audit.jsonl"))
    for index in range(3):
        log.append("gate", "decision", {"seq": index, "cause": 0})
    report = audit_log.AuditLog(log.path).verify_statements()
    assert report["status"] == rs.UNSIGNED and report["findings"] == [] and report["unsigned_tail"] == 3
    assert audit_log.AuditLog(log.path).verify_log() is True


def test_an_unsigned_log_needs_no_signing_extra(tmp_path):
    log = audit_log.AuditLog(str(tmp_path / "old.audit.jsonl"))
    log.append("gate", "decision", {"seq": 0, "cause": 0})
    res = _cli("trail", log.path, block=["cryptography"])
    assert res.returncode == 0, res.stderr
    assert "signing: unsigned" in res.stdout


# ------------------------------------------------------------------ keys

@pytest.fixture()
def keys(tmp_path):
    return rs.keygen(str(tmp_path / "keys"))


@pytest.fixture()
def key(keys):
    return rs.InstanceKey.load(keys["private"])


def _signed_log(tmp_path, key, runs=((3, "run-end"), (2, "run-end"), (4, "checkpoint"))):
    log = audit_log.AuditLog(str(tmp_path / "run.audit.jsonl"), instance_key=key)
    seq = 0
    for count, trigger in runs:
        for _ in range(count):
            log.append("engine", "decision", {"seq": seq, "node": "a", "target": "b", "cause": 0})
            seq += 1
        log.checkpoint(trigger, {"flow_sha256": "ab" * 32})
    return log


def _reopen(log, **kw):
    return audit_log.AuditLog(log.path, **kw)


def test_keygen_writes_a_private_key_only_its_owner_reads(keys):
    assert os.stat(keys["private"]).st_mode & 0o777 == 0o600
    assert len(open(keys["public"], "rb").read()) == 32
    assert keys["fingerprint"] == keys["key_id"][:16] and keys["role"] == "instance"
    assert "PRIVATE" not in json.dumps(keys)


def test_keygen_refuses_to_replace_a_key(keys, tmp_path):
    before = open(keys["private"], "rb").read()
    with pytest.raises(FileExistsError):
        rs.keygen(str(tmp_path / "keys"))
    assert open(keys["private"], "rb").read() == before


def test_a_loaded_key_never_shows_its_private_half(key):
    assert repr(key) == f"InstanceKey(fingerprint={key.fingerprint!r})"
    assert "PRIVATE" not in repr(key) and "-----" not in str(key)


# ------------------------------------------------------------------ a statement

def test_statement_round_trip(key, tmp_path):
    signer = rs.RootSigner(key, str(tmp_path / "x.roots.jsonl"))
    first = signer.sign("aa" * 32, 4, "checkpoint", {"flow_sha256": "cd" * 32})
    second = signer.sign("bb" * 32, 6, "run-end")
    statements, findings = rs.read_statements(signer.path)
    assert findings == [] and statements == [first, second]
    assert first["format"] == rs.STATEMENT_FORMAT and first["seq"] == 0 and first["prev"] == ""
    assert second["prev"] == rs.statement_hash(first) and second["seq"] == 1
    assert first["key_id"] == key.key_id and first["public_key"] == key.public_raw.hex()
    assert first["policy"] == {"flow_sha256": "cd" * 32} and first["time"].endswith("Z")
    assert rs.signed_bytes(first).startswith(rs.SIGNING_DOMAIN)
    # The hash covers the signature: the same body with another signature is another statement.
    forged = dict(first, sig="00" * 64)
    assert rs.statement_hash(forged) != rs.statement_hash(first)
    # A new signer over the same file continues the chain.
    third = rs.RootSigner(key, signer.path).sign("cc" * 32, 7, "run-end")
    assert third["seq"] == 2 and third["prev"] == rs.statement_hash(second)


def test_a_signed_log_verifies_under_its_pinned_key(key, keys, tmp_path):
    log = _signed_log(tmp_path, key)
    report = _reopen(log).verify_statements([rs.load_public(keys["public"])])
    assert report["status"] == rs.SIGNED and report["findings"] == []
    assert report["statements"] == 3 and report["signed_leaves"] == 9 == report["log_leaves"]
    assert report["keys"] == [key.fingerprint]
    unpinned = _reopen(log).verify_statements()
    assert unpinned["status"] == rs.SIGNED_UNPINNED and unpinned["pinned"] is False


def test_receipts_after_the_last_statement_are_an_unsigned_tail(key, tmp_path):
    log = _signed_log(tmp_path, key)
    log.append("engine", "decision", {"seq": 99, "cause": 0})
    report = _reopen(log).verify_statements([key.public_raw])
    assert report["status"] == rs.SIGNED and report["unsigned_tail"] == 1


def _findings(report):
    return [finding["finding"] for finding in report["findings"]]


def test_truncation_is_detected(key, tmp_path):
    log = _signed_log(tmp_path, key)
    lines = open(log.path).read().splitlines()
    open(log.path, "w").write("\n".join(lines[:-2]) + "\n")       # two receipts gone from the end
    report = _reopen(log).verify_statements([key.public_raw])
    assert report["status"] == rs.INVALID and "log_truncated" in _findings(report)
    truncated = [finding for finding in report["findings"] if finding["finding"] == "log_truncated"][0]
    assert truncated["signed_leaves"] == 9 and truncated["log_leaves"] == 7


def test_a_rewritten_receipt_is_detected_and_located(key, tmp_path):
    log = _signed_log(tmp_path, key)
    lines = open(log.path).read().splitlines()
    event = json.loads(lines[4]); event["data"]["target"] = "z"; lines[4] = json.dumps(event)
    open(log.path, "w").write("\n".join(lines) + "\n")
    reopened = _reopen(log)
    assert reopened.verify_log() is True                          # the tree is consistent with itself
    report = reopened.verify_statements([key.public_raw])
    assert report["status"] == rs.INVALID
    mismatches = [finding for finding in report["findings"] if finding["finding"] == "root_mismatch"]
    assert [finding["statement"] for finding in mismatches] == [1, 2]
    assert mismatches[0]["leaf_range"] == [3, 4]                  # receipt idx 4 lies in the second run


def test_a_wrong_key_is_detected(key, tmp_path):
    log = _signed_log(tmp_path, key)
    other = rs.keygen(str(tmp_path / "other"))
    report = _reopen(log).verify_statements([rs.load_public(other["public"])])
    assert report["status"] == rs.INVALID and set(_findings(report)) == {"unpinned_key"}


def test_a_log_resigned_by_another_key_does_not_pass_the_pin(key, tmp_path):
    log = _signed_log(tmp_path, key)
    lines = open(log.path).read().splitlines()
    event = json.loads(lines[0]); event["data"]["target"] = "z"; lines[0] = json.dumps(event)
    open(log.path, "w").write("\n".join(lines) + "\n")
    os.remove(log.statements_path)
    intruder = rs.InstanceKey.load(rs.keygen(str(tmp_path / "intruder"))["private"])
    _reopen(log, instance_key=intruder).checkpoint()              # a consistent new root, freshly signed
    assert _reopen(log).verify_statements()["status"] == rs.SIGNED_UNPINNED
    pinned = _reopen(log).verify_statements([key.public_raw])
    assert pinned["status"] == rs.INVALID and "unpinned_key" in _findings(pinned)


def test_a_broken_statement_chain_is_detected(key, tmp_path):
    log = _signed_log(tmp_path, key)
    lines = open(log.statements_path).read().splitlines()
    open(log.statements_path, "w").write(lines[0] + "\n" + lines[2] + "\n")   # the middle one removed
    report = _reopen(log).verify_statements([key.public_raw])
    assert report["status"] == rs.INVALID and "chain_broken" in _findings(report)
    open(log.statements_path, "w").write(lines[1] + "\n" + lines[0] + "\n" + lines[2] + "\n")   # reordered
    assert "chain_broken" in _findings(_reopen(log).verify_statements([key.public_raw]))


def test_an_edited_statement_fails_its_signature(key, tmp_path):
    log = _signed_log(tmp_path, key)
    lines = open(log.statements_path).read().splitlines()
    statement = json.loads(lines[2]); statement["leaves"] = 5
    lines[2] = json.dumps(statement)
    open(log.statements_path, "w").write("\n".join(lines) + "\n")
    report = _reopen(log).verify_statements([key.public_raw])
    assert report["status"] == rs.INVALID and "bad_signature" in _findings(report)


def test_a_statement_whose_root_does_not_match_is_detected(key, tmp_path):
    log = _signed_log(tmp_path, key, runs=((3, "run-end"),))
    rs.RootSigner(key, log.statements_path).sign("ee" * 32, 3, "checkpoint")   # validly signed, wrong root
    report = _reopen(log).verify_statements([key.public_raw])
    assert report["status"] == rs.INVALID
    assert [finding["statement"] for finding in report["findings"] if finding["finding"] == "root_mismatch"] == [1]


def test_a_statement_with_fewer_leaves_than_the_one_before_is_detected(key, tmp_path):
    log = _signed_log(tmp_path, key, runs=((3, "run-end"),))
    rs.RootSigner(key, log.statements_path).sign(log.root_at(2), 2, "checkpoint")
    assert "leaf_count_regressed" in _findings(_reopen(log).verify_statements([key.public_raw]))


def test_a_pinned_key_and_no_statements_is_invalid(key, tmp_path):
    log = _signed_log(tmp_path, key)
    os.remove(log.statements_path)
    report = _reopen(log).verify_statements([key.public_raw])
    assert report["status"] == rs.INVALID and _findings(report) == ["no_statements"]


def test_a_torn_final_statement_is_reported_and_the_chain_continues(key, tmp_path):
    log = _signed_log(tmp_path, key)
    with open(log.statements_path, "a") as handle:
        handle.write('{"format": "prismpath-root-sta')             # a crash mid write
    report = _reopen(log).verify_statements([key.public_raw])
    assert report["status"] == rs.SIGNED and _findings(report) == ["interrupted_statement"]
    reopened = _reopen(log, instance_key=key)
    reopened.append("engine", "decision", {"seq": 100, "cause": 0})
    assert reopened.checkpoint()["seq"] == 3
    after = _reopen(log).verify_statements([key.public_raw])
    assert after["status"] == rs.SIGNED and after["findings"] == []


# ------------------------------------------------------------------ the instance key is not the authority key

def test_a_statement_signature_is_not_a_manifest_signature(key, tmp_path):
    """Domain separation: the signed bytes start with a prefix no canonical JSON manifest has, so a
    root statement signature never verifies as a signature over the same fields as a manifest."""
    statement = rs.RootSigner(key, str(tmp_path / "s.roots.jsonl")).sign("aa" * 32, 1, "checkpoint")
    body = {name: statement[name] for name in statement if name != "sig"}
    from cryptography.exceptions import InvalidSignature
    with pytest.raises(InvalidSignature):
        key._private.public_key().verify(bytes.fromhex(statement["sig"]), rs.canon.canonical_compact(body))


def test_check_separation_refuses_an_authority_key(key):
    rs.check_separation(key, ["00" * 32])
    rs.check_separation(None, [key.key_id])
    with pytest.raises(ValueError, match="also a policy authority key"):
        rs.check_separation(key, [key.key_id])


def test_a_policy_host_refuses_its_authority_key_as_instance_key(tmp_path):
    from prismpath.hotswap import policy_host, policy_pack
    authority = policy_pack.keygen(str(tmp_path / "authority"))
    env = policy_pack.build_envelope("env1", {"temp": "int"}, None, authority["private"], authority["public"],
                                     str(tmp_path / "env"))
    as_instance = rs.InstanceKey.load(authority["private"])
    with pytest.raises(ValueError, match="also a policy authority key"):
        policy_host.PolicyHost(str(tmp_path / "state"), [authority["public"]], env, instance_key=as_instance)


def test_a_policy_host_signs_after_every_audit_event(key, tmp_path):
    from prismpath.hotswap import policy_host, policy_pack
    authority = policy_pack.keygen(str(tmp_path / "authority"))
    env = policy_pack.build_envelope("env1", {"temp": "int"}, None, authority["private"], authority["public"],
                                     str(tmp_path / "env"))
    host = policy_host.PolicyHost(str(tmp_path / "state"), [authority["public"]], env, instance_key=key)
    host.swap(str(tmp_path / "missing.ppt"))                         # refused, and audited
    host.attest()
    report = audit_log.AuditLog(host.audit.path).verify_statements([key.public_raw])
    assert report["status"] == rs.SIGNED and report["statements"] == len(host.audit.events) == 2


def test_a_log_signed_after_every_event_verifies_in_linear_time(key, tmp_path, monkeypatch):
    """A few thousand events with a statement after each: the work is counted in hash operations, not
    seconds, so the test does not depend on the machine. Rebuilding the tree once per statement would
    cost about n squared over two (more than three million here), against under fifty thousand."""
    count = 2500
    hashes = {"calls": 0}
    original = ledger_ots._h

    def counting(payload):
        hashes["calls"] += 1
        return original(payload)

    monkeypatch.setattr(ledger_ots, "_h", counting)
    log = audit_log.AuditLog(str(tmp_path / "long.audit.jsonl"), instance_key=key, sign_appends=True)
    for index in range(count):
        log.append("engine", "decision", {"seq": index, "cause": 0})
    assert hashes["calls"] < 20 * count                      # signing is linear too
    hashes["calls"] = 0
    reopened = audit_log.AuditLog(log.path)
    report = reopened.verify_statements([key.public_raw])
    assert report["status"] == rs.SIGNED and report["statements"] == count and report["unsigned_tail"] == 0
    assert hashes["calls"] < 20 * count, hashes["calls"]
    # and a receipt rewritten early is still found, with the range it bounds
    lines = open(log.path).read().splitlines()
    event = json.loads(lines[10]); event["data"]["cause"] = 99; lines[10] = json.dumps(event)
    open(log.path, "w").write("\n".join(lines) + "\n")
    hashes["calls"] = 0
    bad = audit_log.AuditLog(log.path).verify_statements([key.public_raw])
    assert bad["status"] == rs.INVALID
    assert next(f for f in bad["findings"] if f["finding"] == "root_mismatch")["leaf_range"] == [10, 10]
    assert hashes["calls"] < 20 * count


def test_a_statement_signed_by_a_key_that_signed_a_pack_is_flagged(key, tmp_path):
    log = audit_log.AuditLog(str(tmp_path / "swaps.log"), instance_key=key, sign_appends=True)
    log.append("policy_host", "swap", {"to_hash": "ab" * 32, "version": 1, "key_id": key.key_id, "result": "accepted"})
    report = audit_log.AuditLog(log.path).verify_statements([key.public_raw])
    assert report["status"] == rs.INVALID and "authority_key" in _findings(report)


# ------------------------------------------------------------------ one receipt, offline

def test_one_receipt_checks_offline(key, tmp_path):
    log = _signed_log(tmp_path, key)
    bundle = json.loads(json.dumps(_reopen(log).receipt_bundle(4)))     # as a reader would receive it
    assert bundle["statement"]["seq"] == 1                              # the first statement that covers it
    result = rs.verify_receipt_bundle(bundle, [key.public_raw])
    assert result["ok"] and all(result["checks"].values())
    edited = json.loads(json.dumps(bundle)); edited["receipt"]["data"]["target"] = "z"
    assert rs.verify_receipt_bundle(edited, [key.public_raw])["checks"]["leaf"] is False
    other = rs.InstanceKey.load(rs.keygen(str(tmp_path / "other"))["private"])
    wrong = rs.verify_receipt_bundle(bundle, [other.public_raw])
    assert wrong["ok"] is False and wrong["checks"]["pinned"] is False


def test_a_receipt_no_statement_covers_says_so(key, tmp_path):
    log = _signed_log(tmp_path, key, runs=((2, "run-end"),))
    log.append("engine", "decision", {"seq": 2, "cause": 0})
    with pytest.raises(LookupError, match="no root statement covers receipt 2"):
        _reopen(log).receipt_bundle(2)


# ------------------------------------------------------------------ the epoch journal

def test_an_epoch_journal_signs_each_seal(key, tmp_path):
    from prismpath.telemetry import epoch_journal
    journal = epoch_journal.EpochJournal(str(tmp_path / "journal"), block_bits=8, instance_key=key)
    for bits in ("10110011", "0110", "111"):
        journal.seal(bits)
    report = journal.verify_statements([key.public_raw])
    assert report["status"] == rs.SIGNED and report["statements"] == 3 and report["signed_leaves"] == 3
    chain_path = tmp_path / "journal" / "chain.jsonl"
    lines = chain_path.read_text().splitlines()
    chain_path.write_text("\n".join(lines[:-1]) + "\n")             # the newest sealed epoch forgotten
    reopened = epoch_journal.EpochJournal(str(tmp_path / "journal"), block_bits=8)
    assert "log_truncated" in _findings(reopened.verify_statements([key.public_raw]))
    unsigned = epoch_journal.EpochJournal(str(tmp_path / "plain"), block_bits=8)
    unsigned.seal("1011")
    assert unsigned.verify_statements()["status"] == rs.UNSIGNED


# ------------------------------------------------------------------ the command line

def _run(capsys, *argv):
    code = cli.main(list(argv))
    out = capsys.readouterr()
    return code, out.out, out.err


def test_run_signs_its_receipts_and_trail_checks_them(keys, tmp_path, capsys, monkeypatch):
    monkeypatch.delenv(rs.INSTANCE_KEY_ENV, raising=False)
    flow = tmp_path / "flow.md"
    flow.write_text(FLOW)
    audit = str(tmp_path / "run.audit.jsonl")
    code, out, _err = _run(capsys, "run", str(flow), "--audit-log", audit, "--instance-key", keys["private"])
    assert code == 0
    assert "Receipts: 1 appended" in out and f"by instance key {keys['fingerprint']}" in out
    statement = rs.read_statements(rs.statements_path_for(audit))[0][0]
    assert statement["trigger"] == "run-end" and statement["policy"]["flow_sha256"] == rs.canon.sha256_hex(flow.read_bytes())
    receipt = json.loads(open(audit).readline())
    assert receipt["action"] == "decision" and receipt["data"]["target"] == "b"
    assert receipt["data"]["policy"]["flow_sha256"] == statement["policy"]["flow_sha256"]

    code, out, _err = _run(capsys, "trail", audit, "--pub", keys["public"], "--receipt", "0")
    assert code == 0 and "signing: signed by instance key" in out and "(pinned)" in out
    assert "receipt 0: verifies" in out

    lines = open(audit).read().splitlines()
    event = json.loads(lines[0]); event["data"]["target"] = "a"; lines[0] = json.dumps(event)
    open(audit, "w").write("\n".join(lines) + "\n")
    code, out, _err = _run(capsys, "trail", audit, "--pub", keys["public"])
    assert code == 1 and "signing: INVALID: root does not match at statement 0" in out


def test_a_run_that_refuses_leaves_a_receipt_with_its_cause(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv(rs.INSTANCE_KEY_ENV, raising=False)
    flow = tmp_path / "flow.md"
    flow.write_text(FLOW.replace("when tests_pass", "when ok"))     # the mock worker never emits ok
    audit = str(tmp_path / "stuck.audit.jsonl")
    code, _out, _err = _run(capsys, "run", str(flow), "--audit-log", audit)
    receipt = json.loads(open(audit).readline())["data"]
    assert code == 0 and receipt["outcome"] == "stuck" and receipt["cause"] == 36 and receipt["node"] == "a"


def test_run_says_plainly_when_it_is_not_signing(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv(rs.INSTANCE_KEY_ENV, raising=False)
    monkeypatch.delenv("PRISMPATH_STATE_DIR", raising=False)
    monkeypatch.chdir(tmp_path)
    flow = tmp_path / "flow.md"
    flow.write_text(FLOW)
    code, out, _err = _run(capsys, "run", str(flow), "--audit-log", str(tmp_path / "a.audit.jsonl"))
    assert code == 0 and "Not signed: no instance key" in out
    assert not os.path.exists(tmp_path / "a.audit.roots.jsonl")


def test_run_signs_by_default_with_the_key_in_the_state_directory(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv(rs.INSTANCE_KEY_ENV, raising=False)
    monkeypatch.delenv("PRISMPATH_STATE_DIR", raising=False)
    monkeypatch.chdir(tmp_path)
    made = rs.keygen(str(tmp_path / ".prismpath"))
    (tmp_path / "flow.md").write_text(FLOW)
    code, out, _err = _run(capsys, "run", "flow.md", "--audit-log", "d.audit.jsonl")
    assert code == 0 and "Signed: root statement 0" in out
    assert f"Signing with the deployment's instance key {made['fingerprint']}, found at " in out
    code, out, _err = _run(capsys, "trail", "d.audit.jsonl", "--pub", made["public"])
    assert code == 0 and "(pinned)" in out


def test_run_takes_the_instance_key_from_the_environment(keys, tmp_path, capsys, monkeypatch):
    monkeypatch.setenv(rs.INSTANCE_KEY_ENV, keys["private"])
    flow = tmp_path / "flow.md"
    flow.write_text(FLOW)
    code, out, _err = _run(capsys, "run", str(flow), "--audit-log", str(tmp_path / "e.audit.jsonl"))
    assert code == 0 and "Signed: root statement 0" in out


def test_run_refuses_an_instance_key_with_nothing_to_sign(keys, tmp_path, capsys):
    flow = tmp_path / "flow.md"
    flow.write_text(FLOW)
    code, _out, err = _run(capsys, "run", str(flow), "--instance-key", keys["private"])
    assert code == 2 and err.strip() == "prismpath run: --instance-key signs the run's receipts; pass --audit-log PATH as well"


ASKING = """---
name: asking
start: a
---

## a
Go.
-> b: when always

## b
Ask.
-> c: when tests_pass
-> d: else

## c
Done.

## d
Other.
"""


def _suspended(tmp_path, name="s.json", crash=False):
    """A checkpoint for ASKING: parked for a human at b (or, with crash, cut off at b), one step taken."""
    from prismpath.ledgers import checkpoint
    flow = tmp_path / "asking.md"
    flow.write_text(ASKING)

    def agent(node, instruction, state):
        if node == "b":
            if crash:
                raise RuntimeError("worker died")
            return {"needs_human": True}
        return {"always": True}

    path = str(tmp_path / name)
    if crash:
        with pytest.raises(RuntimeError):
            checkpoint.run_durable(str(flow), agent, path)
    else:
        assert checkpoint.run_durable(str(flow), agent, path).stopped == "needs_human"
    return str(flow), path


def test_resume_writes_receipts_for_the_steps_it_took_and_signs_them(keys, tmp_path, capsys, monkeypatch):
    monkeypatch.delenv(rs.INSTANCE_KEY_ENV, raising=False)
    flow, checkpoint_path = _suspended(tmp_path)
    audit = str(tmp_path / "resumed.audit.jsonl")
    code, out, _err = _run(capsys, "resume", checkpoint_path, "--choose", "c", "--audit-log", audit,
                           "--instance-key", keys["private"])
    assert code == 0 and "Path: ['a', 'b', 'c']" in out
    assert "Receipts: 1 appended" in out and f"by instance key {keys['fingerprint']}" in out
    receipts = [json.loads(line)["data"] for line in open(audit)]
    assert len(receipts) == 1                                   # the human's choice; a -> b was run's, before the suspension
    assert receipts[0]["node"] == "b" and receipts[0]["target"] == "c" and receipts[0]["how"] == "human"
    assert receipts[0]["seq"] == 1 and receipts[0]["resumed"] is True and receipts[0]["prior_steps"] == 1
    assert receipts[0]["policy"]["flow_sha256"] == rs.canon.sha256_hex(open(flow, "rb").read())
    statement = rs.read_statements(rs.statements_path_for(audit))[0][0]
    assert statement["trigger"] == "resume-end" and statement["policy"] == receipts[0]["policy"]
    code, out, _err = _run(capsys, "trail", audit, "--pub", keys["public"], "--receipt", "0")
    assert code == 0 and "(pinned)" in out and "receipt 0: verifies" in out


def test_resume_after_a_crash_records_the_steps_taken_since(keys, tmp_path, capsys, monkeypatch):
    monkeypatch.delenv(rs.INSTANCE_KEY_ENV, raising=False)
    _flow, checkpoint_path = _suspended(tmp_path, crash=True)
    audit = str(tmp_path / "crash.audit.jsonl")
    code, out, _err = _run(capsys, "resume", checkpoint_path, "--audit-log", audit, "--instance-key", keys["private"])
    receipt = json.loads(open(audit).readline())["data"]
    assert code == 0 and receipt["node"] == "b" and receipt["target"] == "c" and receipt["how"] == "deterministic"
    assert receipt["seq"] == 1 and receipt["prior_steps"] == 1


def test_resume_signs_by_default_with_the_key_in_the_state_directory(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv(rs.INSTANCE_KEY_ENV, raising=False)
    monkeypatch.delenv("PRISMPATH_STATE_DIR", raising=False)
    monkeypatch.chdir(tmp_path)
    made = rs.keygen(str(tmp_path / ".prismpath"))
    _flow, checkpoint_path = _suspended(tmp_path)
    code, out, _err = _run(capsys, "resume", checkpoint_path, "--choose", "d", "--audit-log", "d.audit.jsonl")
    assert code == 0 and "Signed: root statement 0" in out
    assert f"Signing with the deployment's instance key {made['fingerprint']}, found at " in out
    assert _run(capsys, "trail", "d.audit.jsonl", "--pub", made["public"])[0] == 0


def test_resume_says_plainly_when_it_is_not_signing(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv(rs.INSTANCE_KEY_ENV, raising=False)
    monkeypatch.delenv("PRISMPATH_STATE_DIR", raising=False)
    monkeypatch.chdir(tmp_path)
    _flow, checkpoint_path = _suspended(tmp_path)
    code, out, _err = _run(capsys, "resume", checkpoint_path, "--choose", "c", "--audit-log", "u.audit.jsonl")
    assert code == 0 and "Not signed: no instance key" in out
    assert not os.path.exists(tmp_path / "u.audit.roots.jsonl")


def test_resume_with_a_key_and_no_audit_log_says_so(keys, tmp_path, capsys, monkeypatch):
    monkeypatch.delenv(rs.INSTANCE_KEY_ENV, raising=False)
    _flow, checkpoint_path = _suspended(tmp_path)
    code, _out, err = _run(capsys, "resume", checkpoint_path, "--choose", "c", "--instance-key", keys["private"])
    assert code == 2 and err.strip() == "prismpath resume: --instance-key signs the run's receipts; pass --audit-log PATH as well"
    monkeypatch.setenv(rs.INSTANCE_KEY_ENV, keys["private"])
    code, out, _err = _run(capsys, "resume", checkpoint_path, "--choose", "c")
    assert code == 0 and "Not signed: no receipts were written" in out


def test_resume_that_cannot_resume_writes_no_receipt(keys, tmp_path, capsys, monkeypatch):
    monkeypatch.delenv(rs.INSTANCE_KEY_ENV, raising=False)
    _flow, checkpoint_path = _suspended(tmp_path)
    audit = str(tmp_path / "none.audit.jsonl")
    code, out, _err = _run(capsys, "resume", checkpoint_path, "--choose", "zzz", "--audit-log", audit,
                           "--instance-key", keys["private"])
    assert code == 1 and "cannot resume" in out and not os.path.exists(audit)


def test_resume_that_refuses_leaves_a_signed_refusal_receipt(keys, tmp_path, capsys, monkeypatch):
    from prismpath.hotswap import policy_pack
    monkeypatch.delenv(rs.INSTANCE_KEY_ENV, raising=False)
    authority = policy_pack.keygen(str(tmp_path / "authority"))
    _flow, checkpoint_path = _suspended(tmp_path)
    audit = str(tmp_path / "refused.audit.jsonl")
    code, out, err = _run(capsys, "resume", checkpoint_path, "--choose", "c", "--audit-log", audit,
                          "--instance-key", keys["private"], "--require-authorization", "--authority-pub",
                          authority["public"], "--state-dir", str(tmp_path / "state"))
    assert code == 2 and "Path:" not in out
    assert err.strip() == "prismpath resume: refused: the flow is not authorized: sig:missing (cause 1)"
    receipt = json.loads(open(audit).readline())["data"]
    assert receipt["outcome"] == "refused" and receipt["cause"] == 1 and receipt["node"] == "b"
    assert receipt["resumed"] is True and receipt["policy"]["authorization"] == "unauthorized"
    assert audit_log.AuditLog(audit).verify_statements([rs.load_public(keys["public"])])["status"] == rs.SIGNED
    from prismpath.ledgers import checkpoint
    assert checkpoint.load_checkpoint(checkpoint_path)["stopped"] == "needs_human"      # nothing ran


def test_ledger_keygen_and_its_refusal(tmp_path, capsys):
    code, out, _err = _run(capsys, "ledger", "keygen", "--out", str(tmp_path / "k"))
    made = json.loads(out)
    assert code == 0 and made["role"] == "instance" and os.path.exists(made["private"])
    code, _out, err = _run(capsys, "ledger", "keygen", "--out", str(tmp_path / "k"))
    assert code == 2 and "refusing to replace an existing key" in err and len(err.strip().splitlines()) == 1


def test_ledger_anchor_stamps_the_statement_hashes(key, tmp_path, capsys, monkeypatch):
    log = _signed_log(tmp_path, key)
    statements = rs.read_statements(log.statements_path)[0]
    seen = {}
    monkeypatch.setattr("shutil.which", lambda program: f"/usr/bin/{program}")
    monkeypatch.setattr(ledger_ots, "anchor", lambda hashes, out, label: seen.update(hashes=hashes) or {"stamped": True})
    code, _out, _err = _run(capsys, "ledger", "anchor", "--statements", log.path, "--out", str(tmp_path / "proofs"))
    assert code == 0 and seen["hashes"] == [rs.statement_hash(statement) for statement in statements]


@pytest.mark.parametrize("argv", [["ledger", "keygen", "--out", "k"], ["trail", "run.audit.jsonl"],
                                  ["run", "flow.md", "--audit-log", "x.audit.jsonl", "--instance-key", "keys/instance.key"],
                                  ["resume", "s.json", "--choose", "c", "--audit-log", "x.audit.jsonl",
                                   "--instance-key", "keys/instance.key"]])
def test_no_cryptography_is_one_install_line(argv, key, keys, tmp_path):
    _signed_log(tmp_path, key)
    (tmp_path / "flow.md").write_text(FLOW)
    _suspended(tmp_path)
    res = _cli(*argv, block=["cryptography"], cwd=tmp_path)
    assert res.returncode == 2
    assert res.stderr.strip() == f"prismpath {argv[0]}: {INSTALL_LINE}"
