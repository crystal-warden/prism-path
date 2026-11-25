#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Verify a run downlinked from the PrismPath cFS app, on the ground.

    python -m integrations.cfs.ground.downlink FROM RUN --keys KEYS

FROM is the app's run directory as it came down (`/cf/pprun` onboard), and RUN is where the ground keeps it. It is
already a signed core run in the layout `prismpath evidence verify` reads: the app wrote every receipt, the cases
file, the image attestations, the manifest and the root statement, and signed the statement itself with the
instance key. Nothing is reconstructed. `fetch` copies it, giving one file its core run name back: OSAL limits a
file name to 19 characters, so onboard the root statement is `roots.jsonl`, and here it is `receipts.roots.jsonl`,
the same bytes. (`cases.stream`, the cases file while it grows, is not part of the run and stays behind.) Then two
checks:

  1. the repository's verifier, `prismpath.ledgers.core_evidence.verify`, with both keys pinned to the ground's
     own copies (`KEYS/authority.pub`, `KEYS/instance.pub`) and every receipt replayed through the reference
     kernel (`--sample all`): the same check `prismpath evidence verify RUN --sample all --pin-authority ...
     --pin-instance ...` makes;
  2. the root history, `roots.log.jsonl`: every root statement the app sealed, in order, each signed with the
     pinned instance key over its own domain and body, each a `prismpath.core-run-root/2` statement whose root is
     the RFC 6962 root of the first `leaves` receipts of the run, the counts never going back, and the last one
     the run's root statement. A statement sealed before a processor reset is then a root of a prefix of the
     receipts after it, which is what "the receipts continue across the reset" means.

Each earlier statement's `policy` member binds the manifest as it stood when it was sealed, which a later seal
replaced, so for those only the signature, the root and the count are checked; the last is checked in full by 1.

An app that holds install statements (docs/design/spec-policy-distribution.md, RC4) also downlinks `install.jsonl`,
every install statement it decided under or applied in the run, in order, and `rates.jsonl`, a line per override its
action floor counted, and its run has a case per basis: `release`, `floor` and `fallback`, and the release's `would`
lines marked not enacted. `run.json` names both files by hash. Such a run is verified with the install key set the app
held when the run began pinned beside the two keys, `KEYS/install.json`, the `install` member of the anchor the
ground provisioned it with (`install_pin`). A run with no install statements has both files empty, run.json names
neither, and it is verified as before with no install key pinned.

An app whose action floor escalates also downlinks `escalations.jsonl`, every escalation document it opened (OP3),
which run.json names by hash. `escalations` reads them by the SHA-256 the ground seals an operator's answer to. The
answers the app applied are in `install.jsonl`, and each answered request is an `operator` case of the run, its
receipt the answer's, a route to allow or the escalation's own refusal, which the verifier holds to the answer and to
the escalation it names.

The app also sends a state record of policy distribution (docs/design/spec-policy-distribution.md H1) in every
housekeeping packet, signed by the same instance key. `read_state_record` checks one and reads it, with the type 3
entry of H10 an app that holds an install record carries.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Dict, List

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from prismpath.kernel import canon2  # noqa: E402
from prismpath.ledgers import core_evidence, root_statement  # noqa: E402


class Bad(Exception):
    """A downlinked run the ground refuses."""


ONBOARD_NAMES = {"roots.jsonl": "receipts.roots.jsonl"}
LEFT_BEHIND = ("cases.stream",)


def fetch(source: Path, run: Path) -> Path:
    """Copy a downlinked run directory to `run`, each file under its core run name."""
    source, run = Path(source), Path(run)
    run.mkdir(parents=True, exist_ok=False)
    for path in sorted(source.iterdir()):
        if path.is_file() and path.name not in LEFT_BEHIND:
            (run / ONBOARD_NAMES.get(path.name, path.name)).write_bytes(path.read_bytes())
    return run


def root_history(run: Path, instance_pub: bytes) -> List[Dict]:
    """Every sealed root statement, checked as the module says, or Bad."""
    _Priv, _Pub, _ser, InvalidSignature = root_statement._ed25519()
    key = core_evidence._public_key(instance_pub, "instance")
    leaves = [core_evidence.sha256_hex(line) for line in core_evidence._lines(run / "receipts.jsonl")]
    lines = core_evidence._lines(run / "roots.log.jsonl")
    if not lines:
        raise Bad("the run has no sealed root statement")
    out, last = [], -1
    for number, line in enumerate(lines):
        statement = canon2.loads(line)
        if canon2.dumps(statement) != line or set(statement) != set(core_evidence.ROOT_MEMBERS) \
                or statement["format"] != core_evidence.ROOT_FORMAT:
            raise Bad(f"root statement {number} is not a canonical {core_evidence.ROOT_FORMAT} statement")
        if statement["public_key"] != instance_pub.hex() or statement["key_id"] != core_evidence.sha256_hex(instance_pub):
            raise Bad(f"root statement {number} is not signed with the pinned instance key")
        try:
            key.verify(bytes.fromhex(statement["sig"]), core_evidence.root_signed_bytes(statement))
        except (InvalidSignature, ValueError):
            raise Bad(f"root statement {number}: the signature does not verify") from None
        count = statement["leaves"]
        if count < last or count > len(leaves):
            raise Bad(f"root statement {number} counts {count} receipts after one that counted {last}, of {len(leaves)}")
        if statement["root"] != root_statement.merkle_root(leaves[:count]):
            raise Bad(f"root statement {number}: its root is not the root of the run's first {count} receipts")
        last = count
        out.append({"leaves": count, "root": statement["root"], "time_us": statement["time_us"]})
    if lines[-1] + b"\n" != (run / "receipts.roots.jsonl").read_bytes():
        raise Bad("the last sealed statement is not the run's root statement")
    return out


def escalations(run: Path) -> Dict[str, Dict]:
    """OP3: {receipt hash: escalation document} of every escalation the app opened, from `escalations.jsonl` (empty for
    a run with none), each a canonical `prismpath.cfs-escalation/1` document, or Bad."""
    path = Path(run) / "escalations.jsonl"
    out = {}
    for number, line in enumerate(core_evidence._lines(path) if path.exists() else []):
        doc = canon2.loads(line)
        if canon2.dumps(doc) != line or not isinstance(doc, dict) or doc.get("format") != core_evidence.ESCALATION_FORMAT:
            raise Bad(f"escalations.jsonl line {number} is not a {core_evidence.ESCALATION_FORMAT} document")
        out[core_evidence.sha256_hex(line)] = doc
    return out


def install_pin(anchor: bytes) -> Dict:
    """RC4: the install key set a run of an app provisioned with `anchor` starts from, the anchor's `install` member,
    which the ground keeps as `KEYS/install.json`."""
    doc = canon2.loads(bytes(anchor))
    if not isinstance(doc, dict) or not isinstance(doc.get("install"), dict):
        raise Bad("the anchor holds no install member")
    return doc["install"]


def verify(run: Path, keys: Path) -> Dict:
    """Both checks, or Bad (the verifier's own refusal is passed on as Bad with its message). The install key set is
    pinned from `KEYS/install.json` when the ground holds one (RC4), and the escalation documents are held to the hash
    run.json names and counted (OP3)."""
    run, keys = Path(run), Path(keys)
    pin_install = keys / "install.json"
    try:
        summary = core_evidence.verify(run, sample=None, pin_authority=keys / "authority.pub",
                                       pin_instance=keys / "instance.pub",
                                       pin_install=pin_install if pin_install.exists() else None)
    except core_evidence.Bad as bad:
        raise Bad(f"prismpath evidence verify refuses the run: {bad}") from None
    summary["roots"] = root_history(run, (keys / "instance.pub").read_bytes())
    named = core_evidence._manifest(run).get("escalations_sha256")
    path = run / "escalations.jsonl"
    if named is not None and (not path.exists() or core_evidence.sha256_hex(path.read_bytes()) != named):
        raise Bad("escalations.jsonl is not the file run.json names")
    summary["escalations"] = len(escalations(run))
    return summary


STATES = ("no-policy", "active", "locked")
EVENTS = ("beat", "staged", "refused", "committed", "aborted", "trust-applied", "lapsed", "rolled-back", "provisioned",
          "held", "fallback", "install-applied", "install-widened", "answered")
_STATE_HEAD = b"DSSEv1 36 application/vnd.prismpath.dist-state "


def read_state_record(raw: bytes, instance_pub: bytes) -> Dict:
    """One state record (H1) from the app, its signature checked under the pinned instance key, or Bad: its event, state,
    the held bit (5) and the fallback bit (4), its cause, time, the active seq and the floor, and the install entry."""
    from prismpath.kernel import causes
    _Priv, _Pub, _ser, InvalidSignature = root_statement._ed25519()
    raw = bytes(raw)
    if len(raw) < 148 + 64 or raw[:5] != b"PPSR\x01":
        raise Bad("not a state record")
    extension = int.from_bytes(raw[146:148], "little")
    body, signature = raw[:148 + extension], raw[148 + extension:]
    if len(signature) != 64:
        raise Bad("a state record whose length is not its body's and a signature's")
    message = _STATE_HEAD + str(len(body)).encode() + b" " + body
    try:
        core_evidence._public_key(instance_pub, "instance").verify(signature, message)
    except (InvalidSignature, ValueError):
        raise Bad("the state record is not signed by the pinned instance key") from None
    if raw[8:24] != hashlib.sha256(instance_pub).digest()[:16]:
        raise Bad("the state record names another PEP")
    status = raw[6]
    out = {"event": EVENTS[raw[5]] if raw[5] < len(EVENTS) else raw[5], "state": STATES[status & 3] if status & 3 < 3
           else status & 3, "staged": bool(status & 0x80), "held": bool(status & 0x20), "fallback": bool(status & 0x10),
           "cause": causes.name(raw[7]) if raw[7] else None, "counter": int.from_bytes(raw[24:32], "little"),
           "time": int.from_bytes(raw[32:40], "little"), "active_policy": raw[64:80].hex(),
           "active_seq": int.from_bytes(raw[96:104], "little"), "floor": int.from_bytes(raw[104:112], "little"),
           "trust_seq": int.from_bytes(raw[136:144], "little")}
    if extension:
        entry = raw[148:148 + extension]
        if entry[0] != 3 or int.from_bytes(entry[1:3], "little") != 27:
            raise Bad("a state record extension other than the install entry of H10")
        out.update(install_id=entry[3:19].hex(), subject=entry[21], answers=int.from_bytes(entry[22:26], "little"),
                   overrides=int.from_bytes(entry[26:30], "little"))
    return out


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("source", type=Path, help="the run directory as downlinked")
    parser.add_argument("run", type=Path, help="where the ground keeps the run (must not exist)")
    parser.add_argument("--keys", type=Path, required=True,
                        help="the ground's keys (authority.pub, instance.pub, and install.json for an app that holds "
                             "install statements)")
    args = parser.parse_args(argv)
    try:
        summary = verify(fetch(args.source, args.run), args.keys)
    except Bad as bad:
        print(f"REFUSED {args.run}: {bad}")
        return 1
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
