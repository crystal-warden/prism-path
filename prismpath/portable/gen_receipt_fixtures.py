# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Freeze cross-language RECEIPT-VERIFICATION vectors: signed root statements, audit logs, receipt
bundles, flow manifests and the canonical JSON they are all computed over, with every expected verdict
produced by RUNNING the Python reference (`prismpath.ledgers.audit_log`, `root_statement`,
`ledger_ots`, `prismpath.hotswap.flow_authority`, `prismpath.canon`). The Rust verifier
(`prismpath-hotswap-rs`) is measured against what Python actually decides, finding names included.

    python prismpath/portable/gen_receipt_fixtures.py   ->  conformance/receipts.json

Unlike `gen_hotswap_fixtures.py` this is byte-for-byte reproducible: the keys are derived from fixed
labels (Ed25519 signatures are deterministic), clocks are fixed, and no private key is written. A test
(`prismpath/tests/test_receipt_vectors.py`) regenerates the set and refuses drift, then replays every
case through the live Python verifiers.

Case kinds (each carries its `name` and its `expect`):

    canon        raw JSON text -> the canonical compact bytes (as text)
    merkle       leaves -> root, and the inclusion path of every leaf
    trail        an audit log's text + its statements file's text + pinned keys -> the full report
                 `AuditLog.verify_statements` returns (status, counts, keys, findings)
    bundle       a receipt bundle + pinned keys -> `verify_receipt_bundle`'s result, or {"error": true}
                 where the reference raises
    flow         a flow's bytes, manifest text, signature, trusted keys, revoked key ids and the version
                 floor -> `verify_flow`'s (ok, causes) plus the manifest hash and recorded authorization
    floor        manifests accepted in order -> `admits` before each and the floor file afterwards
    separation   an instance key id and the authority key ids -> whether `check_separation` refuses
"""
from __future__ import annotations

import copy
import hashlib
import json
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(REPO))

from cryptography.hazmat.primitives import serialization                        # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from prismpath import canon                                  # noqa: E402
from prismpath.hotswap import flow_authority as fa           # noqa: E402
from prismpath.hotswap import policy_pack as pp              # noqa: E402
from prismpath.ledgers import audit_log, ledger_ots as merkle, root_statement as rs  # noqa: E402

OUT = HERE / "conformance" / "receipts.json"
FORMAT_VERSION = 1

T0 = "2026-11-04T12:00:{sec:02d}.250Z"


# ------------------------------------------------------------------ keys, deterministic

def seeded(label: str):
    """A private key derived from a label: the same on every run, never stored."""
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"prismpath-receipt-vectors/" + label.encode()).digest())


def raw_public(private) -> bytes:
    return private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def instance_key(label: str) -> rs.InstanceKey:
    private = seeded(label)
    return rs.InstanceKey(private, raw_public(private))


INSTANCE = instance_key("instance")
INSTANCE_B = instance_key("instance-b")          # a second instance key (rotation)
INTRUDER = instance_key("intruder")              # a key nobody pinned
AUTHORITY_PRIV = seeded("authority")
AUTHORITY_PUB = raw_public(AUTHORITY_PRIV)
AUTHORITY_ID = canon.sha256_hex(AUTHORITY_PUB)
STRANGER_PRIV = seeded("stranger")
STRANGER_PUB = raw_public(STRANGER_PRIV)


# ------------------------------------------------------------------ audit logs

def make_events(count: int, start: int = 0) -> list:
    """Receipts as `AuditLog.append` writes them, with fixed timestamps and the value shapes real
    receipts carry: float timestamps, a non-ASCII string (BMP and astral), booleans, null, a nested list
    and the floats whose Python spelling is not Rust's default (exponents, integral values)."""
    events = []
    for index in range(start, start + count):
        data = {"seq": index, "node": "a", "target": "b", "cause": 0}
        if index % 3 == 0:
            data["note"] = "café ☃ \U0001d11e \"quoted\" \\ \t"
        if index % 4 == 1:
            data.update({"ok": True, "skipped": None, "scores": [1, 2.5, "x"], "ratio": 1e-07,
                         "big": 1.5e+20, "whole": 100.0, "tiny": 5e-324, "edge": 1e16, "fixed": 1e15})
        events.append({"idx": index, "id": f"{index}", "ts": round(1730800000.0 + index * 1.2345678, 7),
                       "actor": "engine", "action": "decision", "data": data})
    return events


def log_text(events: list) -> str:
    return "".join(json.dumps(event) + "\n" for event in events)


def leaf_of(event) -> str:
    return canon.sha256_hex(canon.canonical_compact(event))


def statements_text(statements: list) -> str:
    return "".join(json.dumps(statement, sort_keys=True) + "\n" for statement in statements)


def stamp(seq: int) -> str:
    return T0.format(sec=seq)


class Run:
    """An audit log and the chain of statements signed over it, built the way `AuditLog.checkpoint` and
    `RootSigner` build them, with a fixed clock."""

    def __init__(self, key=INSTANCE, runs=((3, "run-end"), (2, "run-end"), (4, "checkpoint")),
                 policy=None):
        self.key = key
        self.events = []
        self.statements = []
        self.policy = {"flow_sha256": "ab" * 32} if policy is None else policy
        for count, trigger in runs:
            self.extend(count)
            self.sign(trigger)

    def extend(self, count: int, start=None) -> None:
        self.events += make_events(count, len(self.events) if start is None else start)

    @property
    def leaves(self) -> list:
        return [leaf_of(event) for event in self.events]

    def sign(self, trigger="checkpoint", key=None, leaves=None, root=None, policy="default", **override):
        key = key or self.key
        leaves = self.leaves if leaves is None else leaves
        count = len(leaves)
        statement = rs.make_statement(
            key, log=rs.LOG_AUDIT, seq=len(self.statements), root=rs.merkle_root(leaves) if root is None else root,
            leaves=count, prev=rs.statement_hash(self.statements[-1]) if self.statements else "",
            trigger=trigger, policy=self.policy if policy == "default" else policy,
            time=stamp(len(self.statements)))
        if override:
            statement = {**statement, **override}
        self.statements.append(statement)
        return statement

    @property
    def log(self) -> str:
        return log_text(self.events)

    @property
    def roots(self) -> str:
        return statements_text(self.statements)


def reference_trail(log: str, roots, pinned_raw) -> dict:
    """The Python reference's verdict on a log and its statements file."""
    with tempfile.TemporaryDirectory(prefix="pp_receipt_fx_") as tmp:
        path = Path(tmp) / "run.audit.jsonl"
        path.write_bytes(log.encode("utf-8"))
        if roots is not None:
            Path(rs.statements_path_for(str(path))).write_bytes(roots.encode("utf-8"))
        return audit_log.AuditLog(str(path)).verify_statements(pinned_raw or None)


def trail_case(name, log, roots, pinned=(), note=None):
    pinned_raw = [bytes(raw) for raw in pinned]
    case = {"kind": "trail", "name": name, "log_text": log, "statements_text": roots,
            "pinned": [raw.hex() for raw in pinned_raw],
            "expect": reference_trail(log, roots, pinned_raw)}
    if note:
        case["note"] = note
    return case


def lines_of(text: str) -> list:
    return text.splitlines()


def join(lines: list) -> str:
    return "\n".join(lines) + "\n"


def edit_line(text: str, index: int, change) -> str:
    lines = lines_of(text)
    record = json.loads(lines[index])
    change(record)
    lines[index] = json.dumps(record)
    return join(lines)


def trail_cases() -> list:
    cases = []
    run = Run()
    pin = [INSTANCE.public_raw]

    cases.append(trail_case("signed_pinned", run.log, run.roots, pin))
    cases.append(trail_case("signed_unpinned", run.log, run.roots))
    cases.append(trail_case("signed_pinned_to_two_keys", run.log, run.roots, [INTRUDER.public_raw, INSTANCE.public_raw]))
    cases.append(trail_case("unsigned_log_before_signing", run.log, None))
    cases.append(trail_case("empty_log_and_no_statements", "", None))
    cases.append(trail_case("empty_log_and_no_statements_pinned", "", None, pin))
    cases.append(trail_case("pinned_and_no_statements", run.log, None, pin))
    cases.append(trail_case("empty_statements_file", run.log, "", pin))

    longer = Run()
    longer.extend(1, start=99)
    cases.append(trail_case("unsigned_tail", longer.log, longer.roots, pin))

    lines = lines_of(run.log)
    cases.append(trail_case("truncated_log", join(lines[:-2]), run.roots, pin))
    cases.append(trail_case("truncated_log_to_nothing", "", run.roots, pin))
    short = Run(runs=((3, "run-end"), (2, "run-end")))
    cases.append(trail_case("tail_deleted_with_its_statements_still_verifies", short.log, short.roots, pin,
                            note="a shorter log under a shorter chain verifies; only a statement held elsewhere shows more existed"))

    cases.append(trail_case("rewritten_leaf", edit_line(run.log, 4, lambda e: e["data"].update(target="z")), run.roots, pin))
    cases.append(trail_case("rewritten_first_leaf", edit_line(run.log, 0, lambda e: e["data"].update(target="z")), run.roots, pin))
    cases.append(trail_case("rewritten_last_leaf", edit_line(run.log, 8, lambda e: e["data"].update(target="z")), run.roots, pin))
    swapped = lines_of(run.log)
    swapped[1], swapped[2] = swapped[2], swapped[1]
    cases.append(trail_case("reordered_leaves", join(swapped), run.roots, pin))
    cases.append(trail_case("rewritten_float_timestamp", edit_line(run.log, 5, lambda e: e.update(ts=e["ts"] + 1e-06)), run.roots, pin))
    with_junk = lines_of(run.log)
    with_junk.insert(3, "not json at all")
    cases.append(trail_case("log_line_not_json_is_skipped_and_reported", join(with_junk), run.roots, pin))
    cases.append(trail_case("blank_lines_in_the_log_are_ignored", run.log.replace("\n", "\n\n"), run.roots, pin))
    cases.append(trail_case("crlf_log", run.log.replace("\n", "\r\n"), run.roots, pin))

    wrong = instance_key("someone-else")
    cases.append(trail_case("wrong_pinned_key", run.log, run.roots, [wrong.public_raw]))

    forged = Run(key=INTRUDER)                   # the intruder rewrote the log and signed a consistent chain
    cases.append(trail_case("resigned_by_an_intruder_unpinned", forged.log, forged.roots))
    cases.append(trail_case("resigned_by_an_intruder_fails_the_pin", forged.log, forged.roots, pin))

    status = lines_of(run.roots)
    cases.append(trail_case("middle_statement_removed", run.log, join([status[0], status[2]]), pin))
    cases.append(trail_case("statements_reordered", run.log, join([status[1], status[0], status[2]]), pin))
    cases.append(trail_case("first_statement_removed", run.log, join(status[1:]), pin))
    cases.append(trail_case("statement_duplicated", run.log, join([status[0], status[0], status[1], status[2]]), pin))

    cases.append(trail_case("edited_statement_fails_its_signature",
                            run.log, join(status[:2] + [json.dumps({**json.loads(status[2]), "leaves": 5})]), pin))
    cases.append(trail_case("edited_trigger_fails_its_signature",
                            run.log, join([json.dumps({**json.loads(status[0]), "trigger": "other"})] + status[1:]), pin))
    cases.append(trail_case("edited_policy_fails_its_signature",
                            run.log, join([json.dumps({**json.loads(status[0]), "policy": None})] + status[1:]), pin))
    cases.append(trail_case("signature_zeroed",
                            run.log, join([json.dumps({**json.loads(status[0]), "sig": "00" * 64})] + status[1:]), pin))
    cases.append(trail_case("key_id_altered_is_a_key_id_mismatch",
                            run.log, join([json.dumps({**json.loads(status[0]), "key_id": "ee" * 32})] + status[1:]), pin))
    cases.append(trail_case("key_id_altered_unpinned",
                            run.log, join([json.dumps({**json.loads(status[0]), "key_id": "ee" * 32})] + status[1:])))
    swap_key = json.loads(status[1])
    swap_key.update(public_key=INTRUDER.public_raw.hex(), key_id=INTRUDER.key_id)
    cases.append(trail_case("public_key_swapped_for_another_consistent_one",
                            run.log, join([status[0], json.dumps(swap_key), status[2]]), pin))

    # Validly signed statements that disagree with the log.
    bad_root = Run(runs=((3, "run-end"),))
    bad_root.sign("checkpoint", root="ee" * 32, leaves=bad_root.leaves)
    cases.append(trail_case("validly_signed_wrong_root", bad_root.log, bad_root.roots, pin))
    regress = Run(runs=((3, "run-end"),))
    regress.sign("checkpoint", leaves=regress.leaves[:2])
    cases.append(trail_case("leaf_count_regressed", regress.log, regress.roots, pin))
    over = Run(runs=((3, "run-end"),))
    over.sign("checkpoint", leaves=over.leaves + [leaf_of(make_events(1, 50)[0])] * 4)
    cases.append(trail_case("signed_more_leaves_than_the_log_holds", over.log, over.roots, pin))
    negative = Run(runs=((3, "run-end"),))
    neg = rs.make_statement(INSTANCE, log=rs.LOG_AUDIT, seq=1, root="ab" * 32, leaves=-1,
                            prev=rs.statement_hash(negative.statements[0]), trigger="checkpoint",
                            policy=None, time=stamp(1))
    negative.statements.append(neg)
    cases.append(trail_case("negative_leaf_count", negative.log, negative.roots, pin))
    empty = Run(runs=())
    empty.sign("checkpoint", leaves=[], root="")
    cases.append(trail_case("zero_leaf_statement_over_an_empty_log", "", empty.roots, pin))
    cases.append(trail_case("zero_leaf_statement_over_a_log_that_has_grown", run.log, empty.roots, pin))

    # Stale root with a later honest statement: the first mismatching statement bounds the edit.
    cases.append(trail_case("leaf_range_stays_at_the_first_mismatch",
                            edit_line(run.log, 3, lambda e: e["data"].update(target="q")), run.roots, pin))

    # Key rotation: two instance keys sign one chain.
    rotated = Run(runs=((2, "run-end"), (2, "run-end")))
    rotated.key = INSTANCE_B
    rotated.extend(2)
    rotated.sign("run-end")
    cases.append(trail_case("rotated_instance_key_pinned_to_both", rotated.log, rotated.roots, [INSTANCE.public_raw, INSTANCE_B.public_raw]))
    cases.append(trail_case("rotated_instance_key_pinned_to_the_old_one", rotated.log, rotated.roots, pin))

    # Malformed statements.
    base = json.loads(status[0])
    for field in ("format", "log", "seq", "root", "leaves", "prev", "time", "trigger", "key_id", "public_key", "policy", "sig"):
        broken = {key: value for key, value in base.items() if key != field}
        cases.append(trail_case(f"statement_without_{field}", run.log, join([json.dumps(broken)] + status[1:]), pin))
    variants = {
        "wrong_format_string": {"format": "prismpath-root-statement/2"},
        "wrong_log_field": {"log": "epoch-chain"},
        "seq_is_a_string": {"seq": "0"},
        "seq_is_a_float": {"seq": 0.0},
        "leaves_is_a_float": {"leaves": 3.0},
        "root_is_a_number": {"root": 7},
        "prev_is_null": {"prev": None},
        "key_id_is_a_number": {"key_id": 7},
        "public_key_is_short": {"public_key": "ab" * 31},
        "public_key_is_not_hex": {"public_key": "zz" * 32},
        "public_key_is_a_number": {"public_key": 7},
        "sig_is_short": {"sig": "ab" * 63},
        "sig_is_not_hex": {"sig": "zz" * 64},
        "sig_is_null": {"sig": None},
    }
    for label, change in variants.items():
        cases.append(trail_case(f"statement_with_{label}", run.log, join([json.dumps({**base, **change})] + status[1:]), pin))
    cases.append(trail_case("statement_with_an_extra_field_fails_the_hash_chain",
                            run.log, join([json.dumps({**base, "extra": 1})] + status[1:]), pin))
    cases.append(trail_case("statement_is_not_an_object", run.log, join(["[1, 2]"] + status[1:]), pin))
    cases.append(trail_case("statement_line_not_json_in_the_middle", run.log, join([status[0], "{ not json", status[2]]), pin))
    cases.append(trail_case("blank_line_in_the_middle_of_the_statements", run.log, join([status[0], "", status[1], status[2]]), pin))
    cases.append(trail_case("torn_final_statement", run.log, run.roots + '{"format": "prismpath-root-sta', pin))
    cases.append(trail_case("torn_final_statement_alone", run.log, '{"format": "prismpath-root-sta', pin))
    cases.append(trail_case("statements_file_with_crlf", run.log, run.roots.replace("\n", "\r\n"), pin))
    cases.append(trail_case("statements_file_without_final_newline", run.log, run.roots.rstrip("\n"), pin))

    # A key that also authorizes policy.
    swaps = Run(runs=())
    swaps.events.append({"idx": 0, "id": "0", "ts": 1730800000.5, "actor": "policy_host", "action": "swap",
                         "data": {"to_hash": "ab" * 32, "version": 1, "key_id": INSTANCE.key_id, "result": "accepted"}})
    swaps.sign("append")
    cases.append(trail_case("statement_signed_by_an_authority_key", swaps.log, swaps.roots, pin))
    other_swap = copy.deepcopy(swaps)
    other_swap.events[0]["data"]["key_id"] = AUTHORITY_ID
    other_swap.statements = []
    other_swap.sign("append")
    cases.append(trail_case("swap_by_a_different_authority_is_fine", other_swap.log, other_swap.roots, pin))
    notswap = copy.deepcopy(swaps)
    notswap.events[0]["action"] = "decision"
    notswap.statements = []
    notswap.sign("append")
    cases.append(trail_case("only_swap_events_name_authority_keys", notswap.log, notswap.roots, pin))
    cases.append(trail_case("authority_key_flagged_without_a_pin", swaps.log, swaps.roots))

    # Policy field shapes.
    authz = Run(runs=((2, "run-end"),), policy={"manifest_sha256": "cd" * 32, "key_id": AUTHORITY_ID, "version": 3})
    cases.append(trail_case("policy_names_a_flow_authorization", authz.log, authz.roots, pin))
    null_policy = Run(runs=((2, "run-end"),))
    null_policy.statements = []
    null_policy.sign("run-end", policy=None)
    cases.append(trail_case("policy_is_null", null_policy.log, null_policy.roots, pin))
    return cases


# ------------------------------------------------------------------ receipt bundles

def bundle_for(run: Run, index: int) -> dict:
    return json.loads(json.dumps(rs.receipt_bundle(run.events[index], run.leaves, index, run.statements)))


def reference_bundle(bundle: dict, pinned_raw) -> dict:
    try:
        return rs.verify_receipt_bundle(json.loads(json.dumps(bundle)), pinned_raw or None)
    except (KeyError, ValueError, TypeError, AttributeError):
        return {"error": True}


def bundle_case(name, bundle, pinned=(), note=None):
    pinned_raw = [bytes(raw) for raw in pinned]
    case = {"kind": "bundle", "name": name, "bundle": bundle, "pinned": [raw.hex() for raw in pinned_raw],
            "expect": reference_bundle(bundle, pinned_raw)}
    if note:
        case["note"] = note
    return case


def bundle_cases() -> list:
    cases = []
    run = Run()
    pin = [INSTANCE.public_raw]
    good = bundle_for(run, 4)
    cases.append(bundle_case("valid_pinned", good, pin))
    cases.append(bundle_case("valid_unpinned", good))
    for index in (0, 3, 8):
        cases.append(bundle_case(f"valid_receipt_{index}", bundle_for(run, index), pin))
    single = Run(runs=((1, "run-end"),))
    cases.append(bundle_case("single_leaf_has_an_empty_path", bundle_for(single, 0), pin))
    seven = Run(runs=((7, "run-end"),))
    cases.append(bundle_case("odd_tree_duplicates_the_last_leaf", bundle_for(seven, 6), pin))
    cases.append(bundle_case("receipt_with_float_and_unicode_values", bundle_for(run, 5), pin))

    def edit_of(source, change):
        copy_ = copy.deepcopy(source)
        change(copy_)
        return copy_

    def edit(change):
        return edit_of(good, change)

    cases.append(bundle_case("receipt_edited", edit(lambda b: b["receipt"]["data"].update(target="z")), pin))
    cases.append(bundle_case("receipt_float_edited_in_the_last_digit", edit(lambda b: b["receipt"].update(ts=b["receipt"]["ts"] + 1e-06)), pin))
    cases.append(bundle_case("leaf_replaced_but_receipt_unchanged", edit(lambda b: b.update(leaf="ab" * 32)), pin))
    cases.append(bundle_case("path_sibling_flipped", edit(lambda b: b["path"][0].__setitem__(1, "ab" * 32)), pin))
    cases.append(bundle_case("path_side_swapped", edit_of(bundle_for(run, 1), lambda b: b["path"][0].__setitem__(0, "L" if b["path"][0][0] == "R" else "R")), pin))
    cases.append(bundle_case("path_side_unknown_counts_as_left", edit_of(bundle_for(run, 1), lambda b: b["path"][0].__setitem__(0, "X")), pin))
    cases.append(bundle_case("path_side_swapped_on_the_unpaired_leaf_changes_nothing", edit(lambda b: b["path"][0].__setitem__(0, "L")), pin,
                             note="receipt 4 is the odd leaf of its tree, so its first sibling is itself and the side does not matter"))
    cases.append(bundle_case("path_truncated", edit(lambda b: b.update(path=b["path"][:-1])), pin))
    cases.append(bundle_case("path_extended", edit(lambda b: b.update(path=b["path"] + [["R", "ab" * 32]])), pin))
    cases.append(bundle_case("statement_root_replaced", edit(lambda b: b["statement"].update(root="ab" * 32)), pin))
    cases.append(bundle_case("statement_signature_zeroed", edit(lambda b: b["statement"].update(sig="00" * 64)), pin))
    cases.append(bundle_case("statement_edited_after_signing", edit(lambda b: b["statement"].update(trigger="other")), pin))
    cases.append(bundle_case("statement_key_id_altered", edit(lambda b: b["statement"].update(key_id="ee" * 32)), pin))
    cases.append(bundle_case("statement_without_a_signature", edit(lambda b: b["statement"].pop("sig")), pin))
    cases.append(bundle_case("statement_without_a_root", edit(lambda b: b["statement"].pop("root")), pin))
    cases.append(bundle_case("statement_for_another_log", edit(lambda b: b["statement"].update(log="epoch-chain")), pin))
    cases.append(bundle_case("wrong_pinned_key", good, [INTRUDER.public_raw]))
    cases.append(bundle_case("pinned_to_two_keys_one_right", good, [INTRUDER.public_raw, INSTANCE.public_raw]))
    forged = Run(key=INTRUDER)
    cases.append(bundle_case("bundle_from_an_intruders_log_unpinned", bundle_for(forged, 4)))
    cases.append(bundle_case("bundle_from_an_intruders_log_pinned", bundle_for(forged, 4), pin))
    # Where the reference raises, the verifier reports an error and not a verdict.
    cases.append(bundle_case("leaf_not_hex_is_an_error", edit(lambda b: b.update(leaf="zz")), pin))
    cases.append(bundle_case("path_sibling_not_hex_is_an_error", edit(lambda b: b["path"][0].__setitem__(1, "zz")), pin))
    cases.append(bundle_case("no_statement_is_an_error", edit(lambda b: b.pop("statement")), pin))
    cases.append(bundle_case("no_receipt_is_an_error", edit(lambda b: b.pop("receipt")), pin))
    cases.append(bundle_case("path_entry_not_a_pair_is_an_error", edit(lambda b: b.update(path=[["R"]])), pin))
    cases.append(bundle_case("statement_not_an_object_is_an_error", edit(lambda b: b.update(statement=[1])), pin))
    return cases


# ------------------------------------------------------------------ canonical JSON and the Merkle tree

CANON_TEXTS = [
    "null", "true", "false", "0", "-1", "42", "9223372036854775807", "18446744073709551615",
    "-9223372036854775808", "1.0", "0.5", "-0.25", "100.0", "1e2", "1E2", "1.5e3", "0.1", "0.30000000000000004",
    "1e-05", "0.0001", "0.00001", "1e-07", "5e-324", "2.2250738585072014e-308", "1.7976931348623157e+308",
    "1e15", "1e16", "1e17", "1.5e+20", "123456789012345680000", "1234567890123456.0", "12345678901234567.0",
    "1730800001.2345679", "1730800002.4691358", "4.35", "2.675",
    '""', '"plain"', '"caf\\u00e9"', '"café"', '"\\u2603"', '"\U0001d11e"', '"\\ud834\\udd1e"',
    '"\\"\\\\\\/"', '"\\b\\f\\n\\r\\t"', '"\\u0000\\u001f\\u007f\\u0080"', '"tab\there"'.replace("\t", "\\t"),
    "[]", "{}", "[1, 2.5, \"x\", null, true]", '{"b": 1, "a": 2}', '{"a": {"c": 1, "b": [1, {"z": 0, "y": 1}]}}',
    '{"\\u00e9": 1, "e": 2, "z": 3, "\\ud834\\udd1e": 4, "\\uffff": 5}', '{"b": 1, "b": 2}',
    '{"": 0, " ": 1, "A": 2, "a": 3, "_": 4}',
    '{"idx": 3, "id": "3", "ts": 1730800003.7037034, "actor": "engine", "action": "decision", '
    '"data": {"seq": 3, "cause": 0, "ratio": 1e-07, "big": 1.5e+20, "whole": 100.0}}',
]


def canon_cases() -> list:
    return [{"kind": "canon", "name": f"canon_{index:02d}", "json": text,
             "expect": canon.canonical_compact(json.loads(text)).decode("ascii")}
            for index, text in enumerate(CANON_TEXTS)]


def merkle_cases() -> list:
    cases = []
    for count in (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 15, 16, 17, 33):
        leaves = [canon.sha256_hex(f"leaf-{index}".encode()) for index in range(count)]
        root, paths = merkle.merkle_root_and_paths(leaves)
        assert (root or "") == rs.merkle_root(leaves)
        cases.append({"kind": "merkle", "name": f"merkle_{count}_leaves", "leaves": leaves, "root": rs.merkle_root(leaves),
                      "paths": [[list(step) for step in path] for path in paths]})
    return cases


# ------------------------------------------------------------------ flow manifests

FLOW = """---
name: triage
start: a
---

## a
Do the thing.
-> b: when tests_pass

## b
Done.
"""

FLOW_UNICODE = FLOW.replace("name: triage", "name: triage-café").replace("Do the thing.", "Do the thing ☃ \U0001d11e.")

FLOW_DEFINED = """---
name: defined
start: start
field.load: fixed scale=100 unit=ratio rounding=floor min=0 max=100
---
## start
-> hot: when load >= 0.9
-> cold: else
## hot
## cold
"""

FLOW_CREATED = "2026-11-04T12:00:00+00:00"


class _FixedClock:
    """Stands in for `flow_authority.datetime` so `sign_flow` stamps a fixed `created`."""

    @staticmethod
    def now(tz=None):
        import datetime
        return datetime.datetime(2026, 11, 4, 12, 0, 0, tzinfo=datetime.timezone.utc)


def pem(private) -> bytes:
    return private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def sign_with_the_reference(flow_bytes: bytes, version: int, private=AUTHORITY_PRIV) -> tuple:
    """Run the real `fa.sign_flow` in a scratch directory; returns (manifest_text, sig_bytes, manifest)."""
    real = fa.datetime
    fa.datetime = _FixedClock
    try:
        with tempfile.TemporaryDirectory(prefix="pp_receipt_fx_") as tmp:
            tmp = Path(tmp)
            (tmp / "flow.md").write_bytes(flow_bytes)
            (tmp / "authority.key").write_bytes(pem(private))
            (tmp / "authority.pub").write_bytes(raw_public(private))
            manifest = fa.sign_flow(str(tmp / "flow.md"), version, str(tmp / "authority.key"), str(tmp / "authority.pub"))
            json_path, sig_path = fa.manifest_paths(str(tmp / "flow.md"))
            return Path(json_path).read_text(), Path(sig_path).read_bytes(), manifest
    finally:
        fa.datetime = real


def resign(manifest: dict, private=AUTHORITY_PRIV) -> tuple:
    """A manifest edited and then properly signed, as an authority (or someone holding its key) would."""
    return json.dumps(manifest, indent=1, sort_keys=True) + "\n", private.sign(pp.canonical_bytes(manifest))


def reference_flow(flow_bytes, manifest_text, sig, pubs, revoked, floor) -> dict:
    with tempfile.TemporaryDirectory(prefix="pp_receipt_fx_") as tmp:
        tmp = Path(tmp)
        flow_path = tmp / "flow.md"
        flow_path.write_bytes(flow_bytes)
        json_path, sig_path = fa.manifest_paths(str(flow_path))
        if manifest_text is not None:
            Path(json_path).write_text(manifest_text)
        if sig is not None:
            Path(sig_path).write_bytes(sig)
        pub_paths = []
        for index, raw in enumerate(pubs):
            (tmp / f"key{index}.pub").write_bytes(raw)
            pub_paths.append(str(tmp / f"key{index}.pub"))
        floor_obj = None
        if floor is not None:
            (tmp / "flow_versions.json").write_text(json.dumps(floor))
            floor_obj = fa.VersionFloor(str(tmp / "flow_versions.json"))
        ok, causes, manifest = fa.verify_flow(str(flow_path), pub_paths, frozenset(revoked), floor=floor_obj)
        return {"ok": ok, "causes": causes,
                "manifest_sha256": fa.manifest_sha256(manifest) if isinstance(manifest, dict) else None,
                "authorization": fa.authorization_of(manifest, ok)}


def flow_case(name, flow, manifest_text, sig, pubs=(AUTHORITY_PUB,), revoked=(), floor=None, note=None):
    flow_bytes = flow.encode("utf-8") if isinstance(flow, str) else flow
    case = {"kind": "flow", "name": name, "flow_text": flow_bytes.decode("utf-8"),
            "manifest_text": manifest_text, "sig_hex": None if sig is None else sig.hex(),
            "pubs": [bytes(raw).hex() for raw in pubs], "revoked": list(revoked), "floor": floor,
            "expect": reference_flow(flow_bytes, manifest_text, sig, [bytes(raw) for raw in pubs], revoked, floor)}
    if note:
        case["note"] = note
    return case


def flow_cases() -> list:
    cases = []
    text, sig, manifest = sign_with_the_reference(FLOW.encode(), 3)
    sha = manifest["flow_sha256"]
    cases.append(flow_case("valid", FLOW, text, sig))
    cases.append(flow_case("valid_with_two_trusted_keys_second_signs", FLOW, text, sig, pubs=(STRANGER_PUB, AUTHORITY_PUB)))
    cases.append(flow_case("valid_with_the_floor_empty", FLOW, text, sig, floor={}))
    t_unicode, s_unicode, _ = sign_with_the_reference(FLOW_UNICODE.encode("utf-8"), 1)
    cases.append(flow_case("valid_flow_name_and_text_with_non_ascii", FLOW_UNICODE, t_unicode, s_unicode))
    t_def, s_def, m_def = sign_with_the_reference(FLOW_DEFINED.encode(), 2)
    assert "fields" in m_def
    cases.append(flow_case("valid_flow_that_defines_its_fields", FLOW_DEFINED, t_def, s_def))
    cases.append(flow_case("valid_after_checkout_turned_lf_into_crlf", FLOW.replace("\n", "\r\n"), text, sig))
    cases.append(flow_case("valid_with_a_lone_cr_read_as_lf", FLOW.replace("\n", "\r"), text, sig))
    cases.append(flow_case("valid_with_mixed_line_endings", FLOW.replace("\n", "\r\n", 3), text, sig))

    # Nothing to verify.
    cases.append(flow_case("no_manifest", FLOW, None, sig))
    cases.append(flow_case("no_signature", FLOW, text, None))
    cases.append(flow_case("neither_manifest_nor_signature", FLOW, None, None))

    # The manifest is not a manifest.
    cases.append(flow_case("manifest_not_json", FLOW, "{ not json", sig))
    cases.append(flow_case("manifest_empty_file", FLOW, "", sig))
    cases.append(flow_case("manifest_is_an_array", FLOW, "[1, 2]\n", sig))
    cases.append(flow_case("manifest_is_a_string", FLOW, '"manifest"\n', sig))
    bad_format = dict(manifest, format="prismpath-flow-manifest/2")
    cases.append(flow_case("manifest_wrong_format_string_even_if_signed", FLOW, *resign(bad_format)))
    no_format = {key: value for key, value in manifest.items() if key != "format"}
    cases.append(flow_case("manifest_without_format", FLOW, *resign(no_format)))
    cases.append(flow_case("manifest_version_is_a_string", FLOW, *resign(dict(manifest, version="3"))))
    cases.append(flow_case("manifest_version_is_a_float", FLOW, *resign(dict(manifest, version=3.0))))
    cases.append(flow_case("manifest_without_version", FLOW, *resign({k: v for k, v in manifest.items() if k != "version"})))

    # The signature does not verify.
    edited = dict(manifest, version=9)
    cases.append(flow_case("manifest_edited_after_signing", FLOW, json.dumps(edited, indent=1, sort_keys=True) + "\n", sig))
    cases.append(flow_case("manifest_with_an_extra_field_after_signing", FLOW, json.dumps(dict(manifest, extra=1), indent=1, sort_keys=True) + "\n", sig))
    cases.append(flow_case("manifest_reformatted_but_unchanged_still_verifies", FLOW, json.dumps(manifest, sort_keys=True), sig))
    cases.append(flow_case("signature_truncated", FLOW, text, sig[:63]))
    cases.append(flow_case("signature_too_long", FLOW, text, sig + b"\x00"))
    cases.append(flow_case("signature_empty", FLOW, text, b""))
    cases.append(flow_case("signature_zeroed", FLOW, text, bytes(64)))
    flipped = bytearray(sig); flipped[10] ^= 1
    cases.append(flow_case("signature_one_bit_flipped", FLOW, text, bytes(flipped)))
    cases.append(flow_case("unknown_key", FLOW, text, sig, pubs=(STRANGER_PUB,)))
    cases.append(flow_case("no_trusted_keys", FLOW, text, sig, pubs=()))
    s_text, s_sig = resign(manifest, STRANGER_PRIV)
    cases.append(flow_case("signed_by_a_stranger_with_the_authoritys_key_id", FLOW, s_text, s_sig))

    # The instance key is not the authority key.
    i_manifest = dict(manifest, key_id=INSTANCE.key_id)
    i_text, i_sig = resign(i_manifest, INSTANCE._private)
    cases.append(flow_case("signed_by_the_instance_key_but_only_the_authority_is_trusted", FLOW, i_text, i_sig,
                           note="an instance key presented as an authority: the authority's trust list does not hold it"))
    cases.append(flow_case("signed_by_the_instance_key_and_trusted_by_mistake", FLOW, i_text, i_sig, pubs=(INSTANCE.public_raw,),
                           note="verify_flow alone does not know which key is the instance key; hosts call check_separation first"))

    # Revocation and key binding.
    cases.append(flow_case("revoked_key", FLOW, text, sig, revoked=(AUTHORITY_ID,)))
    cases.append(flow_case("another_key_revoked_does_not_matter", FLOW, text, sig, revoked=(INSTANCE.key_id,)))
    cases.append(flow_case("revoked_key_is_reported_before_a_changed_flow", FLOW + " ", text, sig, revoked=(AUTHORITY_ID,)))
    cases.append(flow_case("revoked_key_with_a_bad_signature_is_invalid_first", FLOW, text, bytes(64), revoked=(AUTHORITY_ID,)))
    mismatch = dict(manifest, key_id=STRANGER_PUB.hex()[:8] + "ee" * 28)
    cases.append(flow_case("manifest_names_another_key_though_signed_by_the_authority", FLOW, *resign(mismatch)))
    cases.append(flow_case("key_id_mismatch_is_reported_before_a_changed_flow", FLOW + " ", *resign(mismatch)))

    # The flow changed after signing.
    cases.append(flow_case("flow_edited_by_one_byte", FLOW.replace("Do the thing.", "Do the thing!"), text, sig))
    cases.append(flow_case("flow_with_a_trailing_space", FLOW + " ", text, sig))
    cases.append(flow_case("flow_with_a_trailing_blank_line", FLOW + "\n", text, sig))
    cases.append(flow_case("flow_with_a_byte_order_mark", "﻿" + FLOW, text, sig))
    cases.append(flow_case("flow_with_trailing_whitespace_on_a_line", FLOW.replace("Done.", "Done. "), text, sig))
    cases.append(flow_case("flow_is_empty", "", text, sig))
    wrong_hash = dict(manifest, flow_sha256="ab" * 32)
    cases.append(flow_case("manifest_names_another_flow_hash", FLOW, *resign(wrong_hash)))
    no_hash = {key: value for key, value in manifest.items() if key != "flow_sha256"}
    cases.append(flow_case("manifest_without_a_flow_hash", FLOW, *resign(no_hash)))
    cases.append(flow_case("flow_hash_in_upper_case_does_not_match", FLOW, *resign(dict(manifest, flow_sha256=sha.upper()))))

    # The version floor.
    entry = {"version": 3, "flow_sha256": sha, "manifest_sha256": fa.manifest_sha256(manifest)}
    cases.append(flow_case("floor_at_the_same_version_with_the_same_flow", FLOW, text, sig, floor={"triage": entry}))
    cases.append(flow_case("floor_below_the_manifest_version", FLOW, text, sig, floor={"triage": dict(entry, version=2)}))
    cases.append(flow_case("floor_above_the_manifest_version_is_a_replay", FLOW, text, sig, floor={"triage": dict(entry, version=4)}))
    cases.append(flow_case("floor_at_the_same_version_with_another_flow_is_a_replay", FLOW, text, sig,
                           floor={"triage": dict(entry, flow_sha256="cd" * 32)}))
    cases.append(flow_case("floor_for_a_different_flow_name_does_not_apply", FLOW, text, sig, floor={"other": dict(entry, version=99)}))
    t_old, s_old, _ = sign_with_the_reference(FLOW.encode(), 1)
    cases.append(flow_case("old_version_replayed_after_a_newer_one", FLOW, t_old, s_old, floor={"triage": entry}))
    t_v4, s_v4, _ = sign_with_the_reference(FLOW.encode(), 4)
    cases.append(flow_case("newer_version_passes_the_floor", FLOW, t_v4, s_v4, floor={"triage": entry}))
    other_flow = FLOW.replace("Done.", "Done differently.")
    t_other, s_other, _ = sign_with_the_reference(other_flow.encode(), 3)
    cases.append(flow_case("second_flow_at_the_same_version_is_a_replay", other_flow, t_other, s_other, floor={"triage": entry}))
    cases.append(flow_case("version_replay_is_reported_last_after_a_changed_flow", FLOW + " ", text, sig, floor={"triage": dict(entry, version=4)}))
    cases.append(flow_case("floor_is_not_consulted_when_the_signature_fails", FLOW, text, bytes(64), floor={"triage": dict(entry, version=4)}))
    t_nameless, s_nameless = resign({key: value for key, value in manifest.items() if key != "flow"})
    cases.append(flow_case("manifest_without_a_flow_name_is_checked_against_the_floor_entry_none", FLOW, t_nameless, s_nameless,
                           floor={"None": entry}))
    return cases


def floor_cases() -> list:
    """Manifests accepted in order; `admits` before each and the floor file after."""
    cases = []
    a1 = sign_with_the_reference(FLOW.encode(), 1)[2]
    a3 = sign_with_the_reference(FLOW.encode(), 3)[2]
    a3_other = sign_with_the_reference(FLOW.replace("Done.", "Done differently.").encode(), 3)[2]
    a2 = sign_with_the_reference(FLOW.encode(), 2)[2]
    b1 = sign_with_the_reference(FLOW_UNICODE.encode("utf-8"), 1)[2]
    sequences = {
        "ascending_versions": [a1, a2, a3],
        "descending_versions_keep_the_highest": [a3, a2, a1],
        "same_version_twice": [a3, a3],
        "same_version_other_flow_is_not_accepted_over_the_first": [a3, a3_other],
        "two_flows_are_kept_apart": [a3, b1, a1],
        "empty": [],
    }
    for name, sequence in sequences.items():
        with tempfile.TemporaryDirectory(prefix="pp_receipt_fx_") as tmp:
            floor = fa.VersionFloor(str(Path(tmp) / "flow_versions.json"))
            steps = []
            for manifest in sequence:
                admitted = floor.admits(manifest)
                floor.accept(manifest)
                steps.append({"manifest": manifest, "admits": admitted})
            cases.append({"kind": "floor", "name": f"floor_{name}", "steps": steps,
                          "expect": {"admits": [step["admits"] for step in steps], "entries": floor.entries}})
    return cases


def separation_cases() -> list:
    cases = []
    for name, instance, authorities in (
        ("distinct_keys", INSTANCE.key_id, [AUTHORITY_ID]),
        ("no_authority_keys", INSTANCE.key_id, []),
        ("instance_key_is_an_authority_key", INSTANCE.key_id, [AUTHORITY_ID, INSTANCE.key_id]),
        ("only_authority_key_is_the_instance_key", AUTHORITY_ID, [AUTHORITY_ID]),
        ("no_instance_key", None, [AUTHORITY_ID]),
    ):
        key = None if instance is None else rs.InstanceKey(None, b"\x00" * 32)
        if key is not None:
            key.key_id, key.fingerprint = instance, rs.fingerprint(instance)
        try:
            rs.check_separation(key, authorities)
            expect = {"ok": True}
        except ValueError:
            expect = {"ok": False}
        cases.append({"kind": "separation", "name": name, "instance_key_id": instance,
                      "authority_key_ids": authorities, "expect": expect})
    return cases


# ------------------------------------------------------------------ the document

def build() -> dict:
    cases = (canon_cases() + merkle_cases() + trail_cases() + bundle_cases() + flow_cases() + floor_cases()
             + separation_cases())
    names = [(case["kind"], case["name"]) for case in cases]
    assert len(names) == len(set(names)), "duplicate case names"
    return {
        "version": FORMAT_VERSION,
        "note": "Cross-language receipt verification vectors. Keys are derived from fixed labels and clocks are "
                "fixed, so regenerating this file is byte-identical. Every expected verdict was produced by "
                "running the Python reference; a verifier must reproduce each one exactly: status, counts, "
                "finding names and fields, check results, refusal causes. Private keys are not stored.",
        "instance_pub_hex": INSTANCE.public_raw.hex(),
        "instance_key_id": INSTANCE.key_id,
        "authority_pub_hex": AUTHORITY_PUB.hex(),
        "authority_key_id": AUTHORITY_ID,
        "cases": cases,
    }


def render() -> str:
    return json.dumps(build(), indent=1, sort_keys=True) + "\n"


def main() -> int:
    OUT.write_text(render())
    kinds = {}
    for case in json.loads(OUT.read_text())["cases"]:
        kinds[case["kind"]] = kinds.get(case["kind"], 0) + 1
    print(f"wrote {OUT.relative_to(REPO)}: " + ", ".join(f"{count} {kind}" for kind, count in sorted(kinds.items())))
    return 0


if __name__ == "__main__":
    sys.exit(main())
