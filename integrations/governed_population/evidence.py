# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Every decision of the population as a receipt, in signed core runs the repository's verifier checks.

A run is a directory in exactly the layout of `formal/diff/core_evidence.py` (spec-verified-core.md section
11), the layout `governed_harness.evidence.EpisodeRun` writes: one case, its image and the canon/2 bytes of
every reading in order; `receipts.jsonl`, one `prismpath.core-receipt/1` line per decision, written when the
decision is made and before anything is done about it; and, when the run is sealed, the cases, the image
attestation, the manifest, both public keys and one root statement over the Merkle root of every receipt.

The one difference from `EpisodeRun` is who signs. There the run's own keys directory holds the authority
key, which signs the image attestation at close. Here no instance key's directory ever holds it: the
operator signs the image once (`Operator.attest`) and the run carries that signature, so a member, the
controller and a canary each seal their runs with their own instance key alone. The verifier checks the
attestation under the pinned authority key either way.

The Merkle root and the root statement are the repository's own (`root_statement.merkle_root`,
`core_evidence.make_root_statement`), called exactly as `EpisodeRun.close` calls them; nothing here
computes a tree or renders a flow of its own.
"""
from __future__ import annotations

import sys
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
for extra in (REPO, REPO / "formal" / "diff"):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))

import core_evidence  # noqa: E402  (formal/diff: the verifier with the Lean oracle replay on top)
from prismpath.kernel import canon2  # noqa: E402
from prismpath.ledgers import root_statement  # noqa: E402

from .identity import InstanceIdentity  # noqa: E402


class DecisionRun:
    def __init__(self, run: Path, case_id: str, image: bytes, attestation_sig: str, identity: InstanceIdentity,
                 authority_pub: bytes, decider: str = "python"):
        self.run, self.case_id, self.image = Path(run), case_id, image
        self.attestation_sig, self.identity, self.authority_pub = attestation_sig, identity, authority_pub
        self.decider = decider
        self.run.mkdir(parents=True, exist_ok=False)
        self.readings: List[bytes] = []
        self.receipts = open(self.run / "receipts.jsonl", "wb")
        self.sealed = False
        self._lock = threading.Lock()

    def record(self, reading: bytes, verdict: Dict[str, Any]) -> int:
        """Write the receipt of one decision now, before anything is done about it; its index."""
        with self._lock:
            if self.sealed:
                raise RuntimeError(f"run {self.run} is sealed")
            idx = len(self.readings)
            self.readings.append(reading)
            receipt = {"format": core_evidence.RECEIPT_FORMAT, "idx": idx, "case": self.case_id, "reading": idx,
                       "image_sha256": core_evidence.sha256_hex(self.image),
                       "reading_sha256": core_evidence.sha256_hex(reading), "decider": self.decider,
                       **core_evidence._decision(verdict)}
            self.receipts.write(canon2.dumps(receipt) + b"\n")
            self.receipts.flush()
            return idx

    def close(self, time_us: Optional[int] = None) -> Dict[str, Any]:
        with self._lock:
            if self.sealed:
                return canon2.loads((self.run / "run.json").read_bytes().rstrip(b"\n"))
            self.sealed = True
            self.receipts.close()
            authority_id = core_evidence.sha256_hex(self.authority_pub)
            root_statement.check_separation(self.identity.key, [authority_id])
            cases = [{"id": self.case_id, "image": self.image, "readings": list(self.readings), "render_seed": 0}]
            core_evidence.write_cases(cases, self.run / "cases.jsonl")
            images = canon2.dumps({"format": core_evidence.IMAGE_FORMAT, "case": self.case_id,
                                   "image_sha256": core_evidence.sha256_hex(self.image), "key_id": authority_id,
                                   "sig": self.attestation_sig}) + b"\n"
            (self.run / "images.jsonl").write_bytes(images)
            leaves = [core_evidence.sha256_hex(line) for line in core_evidence._lines(self.run / "receipts.jsonl")]
            manifest = {"format": core_evidence.RUN_FORMAT, "decider": self.decider, "cases": 1, "receipts": len(leaves),
                        "excluded": [], "cases_sha256": core_evidence.sha256_hex((self.run / "cases.jsonl").read_bytes()),
                        "images_sha256": core_evidence.sha256_hex(images), "authority_key_id": authority_id,
                        "instance_key_id": self.identity.key_id}
            manifest_bytes = canon2.dumps(manifest)
            (self.run / "run.json").write_bytes(manifest_bytes + b"\n")
            (self.run / "authority.pub").write_bytes(self.authority_pub)
            (self.run / "instance.pub").write_bytes(self.identity.public_raw)
            statement = core_evidence.make_root_statement(self.identity.key, root_statement.merkle_root(leaves),
                                                          len(leaves), manifest_bytes, time_us=time_us)
            (self.run / "receipts.roots.jsonl").write_bytes(canon2.dumps(statement) + b"\n")
            return manifest

    def refusals(self) -> int:
        """Decisions of this run so far that were not an allow: refusals and routes to an escalation."""
        with self._lock:
            return _refusals(self.run / "receipts.jsonl")


def _refusals(path: Path) -> int:
    count = 0
    if not Path(path).exists():
        return 0
    for line in core_evidence._lines(path):
        receipt = canon2.loads(line)
        if receipt.get("decision") == "refuse" or str(receipt.get("target", "")).startswith(("refuse_", "escalate_")):
            count += 1
    return count


def verify(run: Path, authority_pub: Path, instance_pub: Path, oracle=None) -> Dict[str, Any]:
    """The repository's verifier, both keys pinned, every receipt replayed through the Lean oracle (or the
    reference when no oracle is given)."""
    if oracle:
        return core_evidence.verify(Path(run), sample=None, pin_authority=authority_pub, pin_instance=instance_pub,
                                    oracle=oracle)
    from prismpath.ledgers import core_evidence as package
    return package.verify(Path(run), sample=None, pin_authority=authority_pub, pin_instance=instance_pub)


def replay_identical(run: Path) -> bool:
    """The run's readings decided again by the reference from its written cases, and the receipts rebuilt
    as `core_evidence.produce` builds them: true when they are the run's own bytes. No key is needed, since
    receipts are not signed one by one."""
    run = Path(run)
    cases = core_evidence.read_cases(run / "cases.jsonl")
    decisions = core_evidence.python_decisions(cases)
    manifest = canon2.loads((run / "run.json").read_bytes().rstrip(b"\n"))
    lines, idx = [], 0
    for case in cases:
        for index, (raw, decision) in enumerate(zip(case["readings"], decisions[case["id"]])):
            receipt = {"format": core_evidence.RECEIPT_FORMAT, "idx": idx, "case": case["id"], "reading": index,
                       "image_sha256": core_evidence.sha256_hex(case["image"]), "reading_sha256": core_evidence.sha256_hex(raw),
                       "decider": manifest["decider"], **decision}
            lines.append(canon2.dumps(receipt) + b"\n")
            idx += 1
    return b"".join(lines) == (run / "receipts.jsonl").read_bytes()


def receipts(run: Path) -> List[Dict[str, Any]]:
    return [canon2.loads(line) for line in core_evidence._lines(Path(run) / "receipts.jsonl")]


def readings(run: Path) -> List[bytes]:
    cases = core_evidence.read_cases(Path(run) / "cases.jsonl")
    return [raw for case in cases for raw in case["readings"]]
