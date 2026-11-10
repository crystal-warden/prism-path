# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Freeze cross-language POLICY HOST TRACES: a list of operations goes in, and what the Python
`PolicyHost` and `AuditLog` did comes out, so a port is measured against the on disk protocol and not
against a reading of it.

    python prismpath/portable/gen_host_trace_fixtures.py   ->  conformance/host_trace.json

Each case is a fresh state directory and a list of operations (`open` a host as a new process would,
`swap`, `rollback`, `attest`, `verify`, `prove`, `snapshot`, and `fs` edits that damage or move the
files the host owns). `swap` and `rollback` can carry a `fault`: the commit stops with an exception before one named
step, which is how a process that dies between two steps looks to the next one. A path or text in an `fs`
edit may name a pack's image digest as `{sha:NAME}`, which is how a case names the content addressed
image `active-<sha256>.ppt`; `copy_pack` writes a pack's image bytes to a file. What the case
records is the result of every operation, and at the end the persisted log read fresh (events,
leaves, Merkle root, skipped line numbers, both verifications) and the state directory's files.

Determinism. The authority key is derived from a fixed seed, so every signature is reproducible. The
clock is a counter: the Nth `time.time()` the audit log reads is `BASE_EPOCH + 0.25 * N` and the Nth
`_now()` of the host is `BASE_ISO + N` seconds, so the timestamps in events, leaves and the
`active_policy.json` record are part of the expected bytes. The one thing that cannot be frozen is the
absolute path of the work directory: `ppt_path` in `active_policy.json` is `abspath` of the pack, so
the work directory is written as `@ROOT@` in every recorded file.

Left out on purpose: the free text of `record:unreadable:<error>` in an `active_unreadable` event for a
record that is not JSON at all (Python's JSON decoder wording; the Rust port has its own test for that
branch), and a pack whose manifest file holds a non finite number (both hosts audit a rejection
`manifest:bad-format` and activate nothing, and each has its own test:
`prismpath/tests/test_policy_host.py`, `tests/test_host_corners.rs`). An active record that holds NaN or a
number beyond the double range is tested on both sides the same way.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import sys
import tempfile
import types
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "prismpath-hw"))

from prismpath import canon  # noqa: E402
from prismpath.hotswap import policy_host as ph  # noqa: E402
from prismpath.hotswap import policy_pack as pp  # noqa: E402
import ppt_compile as pc  # noqa: E402
from prismpath.kernel.parser import parse  # noqa: E402
from prismpath.ledgers import audit_log as al  # noqa: E402

OUT = HERE / "conformance" / "host_trace.json"
BASE_EPOCH = 1760000000.0
EPOCH_STEP = 0.25
BASE_ISO = 1767225600          # 2026-01-01T00:00:00Z
FIELDS = {"temp": "int"}
UNICODE_ENVELOPE = "env-é☃\U0001F600"
STEPS = ["intent", "floor", "evidence", "active_image", "active_record", "clear"]
ROLLBACK_STEPS = [step for step in STEPS if step != "floor"]       # a rollback never moves the floor
SEED = hashlib.sha256(b"prismpath host trace authority").digest()
ROOT_MARK = "@ROOT@"

b64 = lambda raw: base64.b64encode(raw).decode()


class InjectedFault(Exception):
    """Raised before one named commit step to stand for a process that died between two steps."""


def _flow(hot_thresh):
    return f"""# f
## start
-> hot: when temp >= {hot_thresh}
-> cold: else
## hot
-> end
## cold
-> end
## end
"""


def _image(hot):
    return pc.compile_flow(parse(_flow(hot))).serialize()


def _write_keys(directory):
    from cryptography.hazmat.primitives import serialization as ser
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    os.makedirs(directory, exist_ok=True)
    priv = Ed25519PrivateKey.from_private_bytes(SEED)
    priv_path, pub_path = os.path.join(directory, "authority.key"), os.path.join(directory, "authority.pub")
    with open(priv_path, "wb") as handle:
        handle.write(priv.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()))
    raw = priv.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
    with open(pub_path, "wb") as handle:
        handle.write(raw)
    return priv_path, pub_path, canon.sha256_hex(raw)


class Clock:
    def __init__(self):
        self.epoch_calls = 0
        self.iso_calls = 0

    def epoch(self):
        value = BASE_EPOCH + EPOCH_STEP * self.epoch_calls
        self.epoch_calls += 1
        return value

    def iso(self):
        value = datetime.fromtimestamp(BASE_ISO + self.iso_calls, timezone.utc).isoformat(timespec="seconds")
        self.iso_calls += 1
        return value


# ------------------------------------------------------------------ the corpus: packs, envelopes, cases

class _FixedDatetime(datetime):
    """`created` in a manifest is the wall clock; the corpus pins it so a regeneration is byte stable."""

    @classmethod
    def now(cls, tz=None):
        return datetime(2026, 1, 1, 0, 0, 0, tzinfo=tz)


def _build_packs(td, priv_path, pub_path):
    """name -> {image_b64, manifest, sig_hex, sidecar_b64?, absent?}, every one built by the reference."""
    packs = {}
    real_datetime, pp.datetime = pp.datetime, _FixedDatetime
    try:
        return _build_packs_pinned(td, priv_path, pub_path, packs)
    finally:
        pp.datetime = real_datetime


def _build_packs_pinned(td, priv_path, pub_path, packs):

    def signed(name, hot, version, envelope_id="env1", fields=None, overlay_of=None):
        ppt = td / "build" / f"{name}.ppt"
        ppt.parent.mkdir(parents=True, exist_ok=True)
        ppt.write_bytes(_image(hot))
        manifest = pp.build_pack(str(ppt), fields if fields is not None else FIELDS, version=version,
                                 envelope_id=envelope_id, priv_path=priv_path, pub_path=pub_path,
                                 overlay_of=overlay_of)
        packs[name] = {"image_b64": b64(ppt.read_bytes()), "manifest": manifest,
                       "sig_hex": Path(str(ppt) + ".manifest.sig").read_bytes().hex()}
        return packs[name]

    signed("v1", 100, 1)
    signed("v2", 80, 2)
    signed("v2b", 50, 2)
    signed("v3", 60, 3)
    signed("v4_overlay", 40, 4, overlay_of="baseline-2026-07")
    signed("v5", 30, 5)
    signed("v6", 20, 6)
    signed("bad_field", 70, 7, fields={"z": "int"})
    signed("other_envelope", 71, 8, envelope_id="env-other")
    signed("unicode_v1", 72, 1, envelope_id=UNICODE_ENVELOPE)
    tampered = json.loads(json.dumps(packs["v3"]))
    tampered["manifest"]["version"] = 9
    packs["tampered"] = tampered
    packs["no_manifest"] = {"image_b64": packs["v1"]["image_b64"], "manifest": None, "sig_hex": None}
    corrupt = bytearray(base64.b64decode(packs["v1"]["image_b64"]))
    corrupt[0] ^= 0xFF
    packs["bad_magic_image"] = {"image_b64": b64(bytes(corrupt)), "manifest": None, "sig_hex": None}
    packs["absent"] = {"absent": True}
    return packs


def _swap(pack, **extra):
    return {"op": "swap", "pack": pack, **extra}


def _cases(key_id):
    cases = []

    def case(name, ops, **extra):
        cases.append({"name": name, "ops": ops, **extra})

    snap, verify, active = {"op": "snapshot"}, {"op": "verify"}, {"op": "active"}
    open_ = {"op": "open"}

    case("swap_chain", [open_, _swap("v1"), _swap("v2"), _swap("v3"), {"op": "rollback"}, {"op": "rollback"},
                        {"op": "attest"}, active, verify, snap])
    case("floor_and_rejections", [open_, _swap("v2"), _swap("v1"), _swap("v2"), _swap("v2b"), _swap("tampered"),
                                  _swap("bad_field"), _swap("other_envelope"), _swap("no_manifest"),
                                  _swap("absent"), active, verify, snap])
    case("revoked_key", [open_, _swap("v1"), active, snap], revoked=[key_id])
    case("strict_raises", [open_, _swap("v2"), _swap("v1", strict=True), _swap("tampered", strict=True),
                           _swap("absent", strict=True), _swap("v3", strict=True), verify, snap])
    case("unsigned", [open_, _swap("v1"), _swap("no_manifest", allow_unsigned=True),
                      _swap("bad_magic_image", allow_unsigned=True), _swap("absent", allow_unsigned=True),
                      {"op": "rollback"}, active, verify, snap])
    case("overlay_of", [open_, _swap("v1"), _swap("v4_overlay"), {"op": "attest"}, active, snap, open_, active,
                        {"op": "attest"}, snap])
    case("unicode_envelope", [open_, _swap("unicode_v1"), {"op": "attest"}, active, verify, snap, open_, active],
         envelope="unicode")
    case("restart_restores_active", [open_, _swap("v1"), open_, active, {"op": "attest"}, _swap("v2"), open_,
                                     active, {"op": "rollback"}, snap])
    case("restart_after_rollback", [open_, _swap("v1"), _swap("v2"), {"op": "rollback"}, open_, active,
                                    {"op": "rollback"}, snap])
    case("floor_file_forms", [open_, snap,
                              {"op": "fs", "do": "write", "path": "active_version", "text": "abc"}, _swap("v1"),
                              {"op": "fs", "do": "write", "path": "active_version", "text": ""}, _swap("v1"),
                              {"op": "fs", "do": "write", "path": "active_version", "text": "  2\n"}, _swap("v2"),
                              _swap("v3"), snap])

    # a process that dies before each commit step, then the next one
    for step in STEPS:
        case(f"crash_{step}_then_retry",
             [open_, _swap("v1"), _swap("v2", fault=step), snap, active, open_, active, snap, _swap("v2"), snap,
              active, verify, open_, active])
    case("crash_evidence_other_image_same_version",
         [open_, _swap("v1"), _swap("v2", fault="evidence"), open_, _swap("v2b"), _swap("v3"), _swap("v2"),
          verify, snap])
    case("crash_evidence_then_a_higher_version",
         [open_, _swap("v1"), _swap("v2", fault="evidence"), open_, _swap("v3"), snap, active])
    case("recovery_recorded_once_per_process",
         [open_, _swap("v1"), _swap("v2", fault="evidence"), _swap("v2", fault="evidence"),
          _swap("v2", fault="active_record"), snap, _swap("v2"), snap, verify])
    case("crash_clear_in_process_state",
         [open_, _swap("v1"), _swap("v2", fault="clear"), active, {"op": "rollback"}, snap])
    case("crash_on_the_first_swap", [open_, _swap("v1", fault="active_record"), snap, open_, active, _swap("v1"),
                                     snap])
    case("crash_unsigned_skips_the_floor", [open_, _swap("v1", allow_unsigned=True, fault="floor"),
                                            _swap("v1", allow_unsigned=True, fault="evidence"), snap])

    # the audit file refuses the event
    case("audit_unwritable_on_accept",
         [open_, _swap("v1"),
          {"op": "fs", "do": "rename", "path": "swaps.log", "to": "swaps.log.bak"},
          {"op": "fs", "do": "mkdir", "path": "swaps.log"},
          _swap("v2"), verify, snap,
          {"op": "fs", "do": "rmdir", "path": "swaps.log"},
          {"op": "fs", "do": "rename", "path": "swaps.log.bak", "to": "swaps.log"},
          open_, active, _swap("v2"), verify, snap])
    case("audit_unwritable_on_reject",
         [open_, _swap("v1"),
          {"op": "fs", "do": "rename", "path": "swaps.log", "to": "swaps.log.bak"},
          {"op": "fs", "do": "mkdir", "path": "swaps.log"},
          _swap("tampered"), _swap("v1"), {"op": "attest"}, {"op": "verify"}, snap,
          {"op": "fs", "do": "rmdir", "path": "swaps.log"},
          {"op": "fs", "do": "rename", "path": "swaps.log.bak", "to": "swaps.log"}, open_, verify])
    case("audit_directory_at_open", [open_, _swap("v1"),
                                     {"op": "fs", "do": "rename", "path": "swaps.log", "to": "swaps.log.bak"},
                                     {"op": "fs", "do": "mkdir", "path": "swaps.log"}, open_])

    # the log file as it can be found
    case("skipped_lines",
         [open_, _swap("v1"),
          {"op": "fs", "do": "append", "path": "swaps.log", "text": "this is not json\n"},
          {"op": "fs", "do": "append", "path": "swaps.log", "text": "\n   \n{\"half\": \n"},
          open_, verify, {"op": "attest"}, verify, snap])
    case("log_forms", [open_, _swap("v1"), _swap("v2"), {"op": "attest"},
                       {"op": "fs", "do": "crlf", "path": "swaps.log"}, open_, verify,
                       {"op": "fs", "do": "append", "path": "swaps.log", "text": "\n\n"}, open_, verify,
                       {"op": "fs", "do": "append", "path": "swaps.log", "text": "5\n"}, open_, verify, snap])
    case("verify_persisted_diverges",
         [open_, _swap("v1"), _swap("v2"), {"op": "attest"}, verify,
          {"op": "fs", "do": "replace", "path": "swaps.log", "old": "attestation", "new": "attestatiox"},
          verify,
          {"op": "fs", "do": "write", "path": "swaps.log", "text": ""}, verify,
          {"op": "fs", "do": "remove", "path": "swaps.log"}, verify, snap])
    case("prove_every_size", [open_] + [{"op": "attest"} for _ in range(7)]
         + [{"op": "prove", "index": index} for index in (0, 1, 2, 3, 4, 5, 6, 7, -1)] + [verify]
         + [{"op": "verify_prefix", "count": count} for count in (1, 2, 3, 5)])

    # what a fresh host does with the active record on disk
    case("tampered_active_image", [open_, _swap("v1"),
                                   {"op": "fs", "do": "write", "path": "active-{sha:v1}.ppt", "text": "not the image"},
                                   open_, active, snap])
    case("active_image_missing", [open_, _swap("v1"), {"op": "fs", "do": "remove", "path": "active-{sha:v1}.ppt"}, open_,
                                  active, snap])
    case("active_image_is_a_directory", [open_, _swap("v1"), {"op": "fs", "do": "remove", "path": "active-{sha:v1}.ppt"},
                                         {"op": "fs", "do": "mkdir", "path": "active-{sha:v1}.ppt"}, open_, active, snap])
    case("active_record_not_an_object", [open_, {"op": "fs", "do": "write", "path": "active_policy.json",
                                                 "text": '["not", "an", "object"]'}, open_, active, snap])
    case("active_record_without_image", [open_, _swap("v1"), {"op": "fs", "do": "remove", "path": "active-{sha:v1}.ppt"},
                                         {"op": "fs", "do": "write", "path": "active_policy.json",
                                          "text": '{"sha256": null}'}, open_, active, snap])
    case("intent_record_unreadable", [open_, _swap("v1"),
                                      {"op": "fs", "do": "write", "path": "pending_swap", "text": "{not json"},
                                      open_, snap])
    case("intent_record_unreadable_at_swap", [open_, _swap("v1"),
                                              {"op": "fs", "do": "write", "path": "pending_swap",
                                               "text": "{not json"}, _swap("v2"), snap])
    case("intent_record_with_a_null_version", [open_, _swap("v1"),
                                               {"op": "fs", "do": "write", "path": "pending_swap",
                                                "text": '{"to_hash": null, "version": null}'},
                                               open_, _swap("v2"), snap])

    # a death at each step of a rollback, in the process and then a restart
    log_aside = [{"op": "fs", "do": "rename", "path": "swaps.log", "to": "swaps.log.bak"},
                 {"op": "fs", "do": "mkdir", "path": "swaps.log"}]
    log_back = [{"op": "fs", "do": "rmdir", "path": "swaps.log"},
                {"op": "fs", "do": "rename", "path": "swaps.log.bak", "to": "swaps.log"}]
    for step in ROLLBACK_STEPS:
        case(f"crash_rollback_{step}_then_retry",
             [open_, _swap("v1"), _swap("v2"), {"op": "rollback", "fault": step}, snap, active,
              {"op": "rollback"}, snap, active, verify, open_, active, snap])
        case(f"crash_rollback_{step}_then_restart",
             [open_, _swap("v1"), _swap("v2"), {"op": "rollback", "fault": step}, open_, active, snap, verify,
              {"op": "rollback"}, _swap("v3"), snap, active, verify, open_, active])
    case("audit_unwritable_on_rollback",
         [open_, _swap("v1"), _swap("v2")] + log_aside
         + [{"op": "rollback"}, active, snap] + log_back
         + [verify, {"op": "rollback"}, active, snap, verify, open_, active])
    case("audit_unwritable_on_rollback_then_restart",
         [open_, _swap("v1"), _swap("v2")] + log_aside + [{"op": "rollback"}] + log_back
         + [open_, active, snap, verify, _swap("v3"), snap, verify])
    case("rollback_does_not_lower_the_floor",
         [open_, _swap("v1"), _swap("v2"), {"op": "rollback"}, _swap("v2"), _swap("v1"), _swap("v3"), snap])
    case("rollback_without_a_previous_policy_after_restart",
         [open_, _swap("v1"), _swap("v2"), open_, {"op": "rollback"}, snap])

    # images the record does not name, and a state directory written with the image called active.ppt
    legacy_v1 = [{"op": "fs", "do": "rename", "path": "active-{sha:v1}.ppt", "to": "active.ppt"},
                 {"op": "fs", "do": "replace", "path": "active_policy.json",
                  "old": "\"image_file\": \"active-{sha:v1}.ppt\", ", "new": ""}]
    legacy_v2 = [{"op": "fs", "do": "rename", "path": "active-{sha:v2}.ppt", "to": "active.ppt"},
                 {"op": "fs", "do": "replace", "path": "active_policy.json",
                  "old": "\"image_file\": \"active-{sha:v2}.ppt\", ", "new": ""}]
    case("stray_image_with_wrong_content_is_ignored_then_overwritten",
         [open_, _swap("v1"),
          {"op": "fs", "do": "write", "path": "active-{sha:v2}.ppt", "text": "not the image"},
          open_, active, snap, _swap("v2"), snap, active, open_, active, verify])
    case("stray_image_with_the_right_content_is_not_a_record",
         [open_, _swap("v1"), {"op": "fs", "do": "copy_pack", "path": "active-{sha:v2}.ppt", "pack": "v2"},
          open_, active, snap, _swap("v3"), snap, active])
    case("stray_images_are_collected_by_the_next_commit",
         [open_, _swap("v1"),
          {"op": "fs", "do": "write", "path": "active-{sha:v5}.ppt", "text": "left by a dead commit"},
          {"op": "fs", "do": "write", "path": "active-{sha:v6}.ppt.tmp", "text": "torn"},
          {"op": "fs", "do": "write", "path": "active-notes.ppt", "text": "not ours"},
          _swap("v2"), snap, active])
    case("old_layout_is_read_then_migrated_by_a_swap",
         [open_, _swap("v1")] + legacy_v1
         + [snap, open_, active, {"op": "attest"}, _swap("v2"), snap, active, open_, active, verify])
    case("old_layout_is_migrated_by_a_rollback",
         [open_, _swap("v1"), _swap("v2")] + legacy_v2
         + [open_, active, _swap("v3"), snap, {"op": "rollback"}, snap, active, open_, active, verify])
    case("old_layout_with_an_unfinished_clear_is_finished_at_open",
         [open_, _swap("v1"), _swap("v2", fault="clear")] + legacy_v2 + [snap, open_, active, snap, verify])
    case("old_layout_dead_between_image_and_record_fails_closed_until_the_swap_is_retried",
         [open_, _swap("v1")] + legacy_v1
         + [{"op": "fs", "do": "copy_pack", "path": "active.ppt", "pack": "v2"},
            {"op": "fs", "do": "write", "path": "active_version", "text": "2"},
            {"op": "fs", "do": "write", "path": "pending_swap",
             "text": "{\"to_hash\": \"{sha:v2}\", \"version\": 2}"},
            open_, active, snap, _swap("v2"), snap, active, open_, active, verify])
    case("active_record_names_an_invalid_image_file",
         [open_, _swap("v1"),
          {"op": "fs", "do": "replace", "path": "active_policy.json", "old": "active-{sha:v1}.ppt",
           "new": "../active-{sha:v1}.ppt"}, open_, active, snap])

    # numbers canonical JSON has no form for: refused when written, and read as damage when found on disk
    overflow = {"number_text": "1e400"}
    case("audit_event_with_a_non_finite_number_is_refused",
         [open_, _swap("v1"),
          {"op": "append", "action": "probe", "data": {"n": 1}},
          {"op": "append", "action": "probe", "data": {"n": overflow}},
          {"op": "append", "action": "probe", "data": {"n": {"number_text": "-1e400"}}},
          {"op": "append", "action": "probe", "data": {"n": 2}},
          verify, snap, open_, active, verify])
    case("log_lines_with_no_canonical_form_are_skipped",
         [open_, _swap("v1"),
          {"op": "fs", "do": "append", "path": "swaps.log", "text": "NaN\n[Infinity]\n{\"x\": -Infinity}\n"},
          {"op": "fs", "do": "append", "path": "swaps.log", "text": "{\"x\": 1e400}\n{\"x\": \"\\ud800\"}\n"},
          open_, verify, {"op": "attest"}, verify, snap])
    for index, (label, text) in enumerate([
            ("nan", '{"to_hash": null, "version": NaN}'), ("overflow", '{"to_hash": null, "version": 1e400}'),
            ("infinity_in_op", '{"to_hash": null, "version": 1, "op": Infinity}')]):
        case(f"intent_record_with_{label}_fails_closed",
             [open_, _swap("v1"), {"op": "fs", "do": "write", "path": "pending_swap", "text": text},
              open_, snap, _swap("v2"), snap, active])
    case("rollback_intent_record_with_a_non_finite_version_fails_closed",
         [open_, _swap("v1"), _swap("v2"),
          {"op": "fs", "do": "write", "path": "pending_swap",
           "text": '{"to_hash": "{sha:v1}", "version": 1e400, "op": "rollback"}'},
          open_, active, snap, {"op": "rollback"}, snap])
    return cases


# ------------------------------------------------------------------ running one case under Python

def _normalise(text, root):
    return text.replace(root, ROOT_MARK)


def _snapshot(state, root):
    files = {}
    for name in sorted(os.listdir(state)):
        path = os.path.join(state, name)
        if os.path.isdir(path):
            files[name] = {"dir": True}
        elif name.startswith("active") and name.endswith(".ppt"):
            files[name] = {"sha256": canon.sha256_hex(open(path, "rb").read())}
        else:
            files[name] = _normalise(open(path, "rb").read().decode("utf-8"), root)
    return files


def _kind(error):
    if isinstance(error, al.AuditWriteError):
        return "AuditWriteError"
    if isinstance(error, ph.SwapRejected):
        return "SwapRejected"
    if isinstance(error, InjectedFault):
        return "Injected"
    if isinstance(error, canon.CanonicalError):
        return "CanonicalError"
    if isinstance(error, IndexError):
        return "IndexError"
    if isinstance(error, RuntimeError) and str(error).startswith("unreadable intent record"):
        return "IntentUnreadable"
    if isinstance(error, OSError):
        return "OSError"
    raise AssertionError(f"unclassified error {error!r}")


def _install_fault(host, step, action="swap"):
    """Make the commit raise before `step`; returns the function that undoes it."""
    def boom(*args, **kwargs):
        raise InjectedFault(step)

    saved = []

    def patch(target, name, replacement):
        saved.append((target, name, getattr(target, name)))
        setattr(target, name, replacement)

    if step == "intent":
        patch(host, "_write_pending", boom)
    elif step == "floor":
        patch(host, "_persist_version", boom)
    elif step == "evidence":
        real = host.audit.append
        patch(host.audit, "append", lambda actor, name, data: boom() if name == action else real(actor, name, data))
    elif step == "active_image":
        real = canon.atomic_write_bytes
        patch(canon, "atomic_write_bytes", lambda path, data: boom() if os.path.basename(str(path)).startswith("active-") else real(path, data))
    elif step == "active_record":
        real = canon.atomic_write
        patch(canon, "atomic_write", lambda path, data, *a, **k: boom() if str(path).endswith("active_policy.json") else real(path, data, *a, **k))
    elif step == "clear":
        patch(host, "_clear_pending", boom)
    else:
        raise AssertionError(step)

    def undo():
        for target, name, original in reversed(saved):
            setattr(target, name, original)
    return undo


def _swap_result(host, path, op):
    undo = _install_fault(host, op["fault"]) if op.get("fault") else (lambda: None)
    try:
        result = host.swap(path, allow_unsigned=op.get("allow_unsigned", False), strict=op.get("strict", False))
        return result
    except Exception as error:     # noqa: BLE001 - every kind is classified, an unknown one aborts the generator
        out = {"raised": _kind(error)}
        if isinstance(error, ph.SwapRejected):
            out["reasons"] = error.reasons
        return out
    finally:
        undo()


def _rollback_result(host, op):
    undo = _install_fault(host, op["fault"], "rollback") if op.get("fault") else (lambda: None)
    try:
        return host.rollback()
    except Exception as error:     # noqa: BLE001
        return {"raised": _kind(error)}
    finally:
        undo()


def _path_of(state, rel):
    return os.path.join(state, rel)


def _subst(text, doc):
    """`{sha:NAME}` is the sha256 of pack NAME's image."""
    return re.sub(r"\{sha:(\w+)\}", lambda match: canon.sha256_hex(base64.b64decode(doc["packs"][match.group(1)]["image_b64"])), text)


def _fs(state, op, doc, packs_dir):
    op = {key: (_subst(value, doc) if isinstance(value, str) and key != "do" else value) for key, value in op.items()}
    target = _path_of(state, op["path"])
    kind = op["do"]
    if kind == "copy_pack":
        Path(target).write_bytes(Path(packs_dir, f"{op['pack']}.ppt").read_bytes())
        return {"done": kind}
    if kind == "write":
        with open(target, "wb") as handle:
            handle.write(op["text"].encode("utf-8"))
    elif kind == "append":
        with open(target, "ab") as handle:
            handle.write(op["text"].encode("utf-8"))
    elif kind == "remove":
        os.remove(target)
    elif kind == "mkdir":
        os.mkdir(target)
    elif kind == "rmdir":
        os.rmdir(target)
    elif kind == "rename":
        os.rename(target, _path_of(state, op["to"]))
    elif kind == "replace":
        text = open(target, "rb").read().decode("utf-8")
        assert op["old"] in text
        with open(target, "wb") as handle:
            handle.write(text.replace(op["old"], op["new"], 1).encode("utf-8"))
    elif kind == "crlf":
        text = open(target, "rb").read().decode("utf-8")
        with open(target, "wb") as handle:
            handle.write(text.replace("\n", "\r\n").encode("utf-8"))
    else:
        raise AssertionError(kind)
    return {"done": kind}


def _verify_report(log):
    return {"verify_log": log.verify_log(), "verify_persisted": log.verify_persisted(),
            "root": log.current_root(), "leaf_count": len(log.leaves), "skipped": list(log.skipped)}


def run_case(case, doc, work):
    state = os.path.join(work, "state")
    packs_dir = os.path.join(work, "packs")
    os.makedirs(packs_dir)
    pub_paths = [os.path.join(work, "keys", "authority.pub")]
    for name, pack in doc["packs"].items():
        if pack.get("absent"):
            continue
        base = os.path.join(packs_dir, f"{name}.ppt")
        Path(base).write_bytes(base64.b64decode(pack["image_b64"]))
        if pack["manifest"] is not None:
            Path(base + ".manifest.json").write_text(json.dumps(pack["manifest"], indent=1, sort_keys=True) + "\n")
            Path(base + ".manifest.sig").write_bytes(bytes.fromhex(pack["sig_hex"]))
    envelope = doc["envelopes"][case.get("envelope", "default")]
    clock = Clock()
    saved_time, saved_now = al.time, ph._now
    al.time = types.SimpleNamespace(time=clock.epoch)
    ph._now = clock.iso
    host = None
    results = []
    try:
        for op in case["ops"]:
            kind = op["op"]
            try:
                if kind == "open":
                    host = ph.PolicyHost(state, pub_paths, envelope, revoked=frozenset(case.get("revoked", [])))
                    result = {"opened": True, **host.active()}
                elif kind == "swap":
                    result = _swap_result(host, os.path.join(packs_dir, f"{op['pack']}.ppt"), op)
                elif kind == "rollback":
                    result = _rollback_result(host, op)
                elif kind == "append":
                    # an audit event with `data`; a `{"number_text": T}` value is the number the text T reads as
                    data = {key: (float(value["number_text"]) if isinstance(value, dict) else value)
                            for key, value in op["data"].items()}
                    host.audit.append("policy_host", op["action"], data)
                    result = {"appended": True}
                elif kind == "attest":
                    result = host.attest()
                elif kind == "active":
                    result = host.active()
                elif kind == "verify":
                    result = _verify_report(host.audit)
                elif kind == "verify_prefix":
                    # a proof for each of the first `count` leaves, checked against a root over only those
                    prefix = al.AuditLog("")
                    prefix.leaves = host.audit.leaves[:op["count"]]
                    result = {"root": prefix.current_root(),
                              "proofs": [prefix.prove(index) for index in range(len(prefix.leaves))],
                              "verified": [al.verify(prefix.leaves[i], prefix.prove(i), prefix.current_root())
                                           for i in range(len(prefix.leaves))]}
                elif kind == "prove":
                    proof = host.audit.prove(op["index"])
                    result = {"proof": proof,
                              "verified": al.verify(host.audit.leaves[op["index"]], proof, host.audit.current_root())}
                elif kind == "snapshot":
                    result = _snapshot(state, work)
                elif kind == "fs":
                    result = _fs(state, op, doc, packs_dir)
                else:
                    raise AssertionError(kind)
            except Exception as error:     # noqa: BLE001
                result = {"raised": _kind(error)}
            results.append(result)
        final_log = al.AuditLog(os.path.join(state, "swaps.log")) if os.path.isfile(os.path.join(state, "swaps.log")) else None
        final = None
        if final_log is not None:
            final = {"events": final_log.events, "leaves": final_log.leaves, **_verify_report(final_log)}
        return {"results": results, "final": final, "files": _snapshot(state, work)}
    finally:
        al.time, ph._now = saved_time, saved_now


def build():
    with tempfile.TemporaryDirectory(prefix="cw_host_trace_") as raw_td:
        td = Path(raw_td).resolve()
        priv_path, pub_path, key_id = _write_keys(str(td / "keys"))
        packs = _build_packs(td, priv_path, pub_path)
        envelope = pp.build_envelope("env1", FIELDS, None, priv_path, pub_path, str(td / "env"))
        unicode_envelope = pp.build_envelope(UNICODE_ENVELOPE, FIELDS, None, priv_path, pub_path, str(td / "env"))
        doc = {"version": 1,
               "note": "Policy host traces. Every result, event, leaf, root and file was produced by the Python "
                       "PolicyHost and AuditLog under a counter clock; the Rust host must reproduce each exactly. "
                       "The work directory is written as @ROOT@.",
               "clock": {"base_epoch": BASE_EPOCH, "epoch_step": EPOCH_STEP, "base_iso": BASE_ISO},
               "steps": STEPS, "rollback_steps": ROLLBACK_STEPS,
               "authority_pub_hex": Path(pub_path).read_bytes().hex(), "authority_key_id": key_id,
               "envelopes": {"default": envelope, "unicode": unicode_envelope},
               "packs": packs}
        doc["cases"] = _cases(key_id)
        for case in doc["cases"]:
            work = td / "runs" / case["name"]
            work.mkdir(parents=True)
            (work / "keys").mkdir()
            (work / "keys" / "authority.pub").write_bytes(Path(pub_path).read_bytes())
            case["expect"] = run_case(case, doc, str(work))
    return doc


def main() -> int:
    doc = build()
    OUT.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n")
    print(f"wrote {OUT}  ({len(doc['cases'])} cases, {len(doc['packs'])} packs)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
