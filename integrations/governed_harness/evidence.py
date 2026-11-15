# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Every decision of an episode as a receipt, and the episode as a signed core run.

An episode's evidence is a run directory in exactly the layout of a differential run as evidence
(docs/design/spec-verified-core.md, section 11; `formal/diff/core_evidence.py`), so the repository's own
verifier checks it, and no format is invented here:

  * one case, the episode: the policy image and, as its readings, the canon/2 bytes of every reading the
    classifier made of a proposed call, in order;
  * `receipts.jsonl`: one `prismpath.core-receipt/1` line per decision, written WHEN the call is decided,
    before anything runs, whether the decision is a route to `allow`, to a refusal or to an escalation,
    or a refusal of the core itself;
  * when the episode ends: the cases file, the image attestation signed with the authority key, the
    manifest, and one root statement signed with the instance key over the Merkle root of every receipt.

`verify` is `core_evidence.verify` with every receipt replayed through the Lean oracle and both keys
pinned. `replay` decides the episode's readings again with `core_evidence.produce` (the reference, from the
written cases) into a separate directory and compares the receipts byte for byte: the decision is a
function of the image and the reading, so a second decision must write the same bytes.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
for extra in (REPO, REPO / "formal" / "diff"):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))

import core_evidence  # noqa: E402
from prismpath.kernel import canon2  # noqa: E402

DECIDER = "python"


def ensure_keys(keys: Path):
    """The authority key (which says which policy may run) and the instance key (which attests what was
    recorded): test keys made by the repository's own key generators, never a deployment's."""
    return core_evidence.ensure_keys(Path(keys))


class EpisodeRun:
    def __init__(self, run: Path, case_id: str, image: bytes, keys: Path, decider: str = DECIDER):
        self.run, self.case_id, self.image, self.keys = Path(run), case_id, image, Path(keys)
        self.decider = decider            # who decided: the receipts and the manifest name it
        self.run.mkdir(parents=True, exist_ok=False)
        self.readings: List[bytes] = []
        self.receipts = open(self.run / "receipts.jsonl", "wb")

    def record(self, reading: bytes, verdict: Dict[str, Any]) -> int:
        """Write the receipt of one decision now, before the call runs or is withheld; its index."""
        idx = len(self.readings)
        self.readings.append(reading)
        receipt = {"format": core_evidence.RECEIPT_FORMAT, "idx": idx, "case": self.case_id, "reading": idx,
                   "image_sha256": core_evidence.sha256_hex(self.image),
                   "reading_sha256": core_evidence.sha256_hex(reading), "decider": self.decider,
                   **core_evidence._decision(verdict)}
        self.receipts.write(canon2.dumps(receipt) + b"\n")
        self.receipts.flush()
        return idx

    def close(self, time_us: int = None) -> Dict[str, Any]:
        """Seal the episode: the inputs, the signed image attestation, the manifest and the signed root."""
        from prismpath.hotswap import policy_pack
        from prismpath.ledgers import root_statement
        self.receipts.close()
        authority_key, authority_pub, instance_key, instance_pub = ensure_keys(self.keys)
        instance = root_statement.InstanceKey.load(str(instance_key))
        authority_id = core_evidence.sha256_hex(authority_pub.read_bytes())
        root_statement.check_separation(instance, [authority_id])
        cases = [{"id": self.case_id, "image": self.image, "readings": list(self.readings)}]
        core_evidence.write_cases(cases, self.run / "cases.jsonl")
        signer = policy_pack._load_private(str(authority_key))
        images = canon2.dumps({"format": core_evidence.IMAGE_FORMAT, "case": self.case_id,
                               "image_sha256": core_evidence.sha256_hex(self.image), "key_id": authority_id,
                               "sig": signer.sign(core_evidence.IMAGE_DOMAIN + self.image).hex()}) + b"\n"
        (self.run / "images.jsonl").write_bytes(images)
        leaves = [core_evidence.sha256_hex(line) for line in core_evidence._lines(self.run / "receipts.jsonl")]
        manifest = {"format": core_evidence.RUN_FORMAT, "decider": self.decider, "cases": 1, "receipts": len(leaves),
                    "excluded": [], "cases_sha256": core_evidence.sha256_hex((self.run / "cases.jsonl").read_bytes()),
                    "images_sha256": core_evidence.sha256_hex(images), "authority_key_id": authority_id,
                    "instance_key_id": instance.key_id}
        manifest_bytes = canon2.dumps(manifest)
        (self.run / "run.json").write_bytes(manifest_bytes + b"\n")
        (self.run / "authority.pub").write_bytes(authority_pub.read_bytes())
        (self.run / "instance.pub").write_bytes(instance_pub.read_bytes())
        statement = core_evidence.make_root_statement(instance, root_statement.merkle_root(leaves), len(leaves),
                                                      manifest_bytes, time_us=time_us)
        (self.run / "receipts.roots.jsonl").write_bytes(canon2.dumps(statement) + b"\n")
        return manifest


def verify(run: Path, keys: Path, oracle=None) -> Dict[str, Any]:
    """The repository's verifier on the episode, every receipt replayed through the Lean oracle, keys pinned."""
    return core_evidence.verify(Path(run), sample=None, pin_authority=Path(keys) / "authority.pub",
                                pin_instance=Path(keys) / "instance.pub", oracle=oracle)


def replay(run: Path, keys: Path, decider: str = DECIDER) -> bool:
    """Decide the episode again from its written cases with the reference producer, into `run/replay`, and
    say whether its receipts are the episode's own bytes."""
    again = Path(run) / "replay"
    core_evidence.produce(Path(run) / "cases.jsonl", again, Path(keys), decider=decider)
    return (again / "receipts.jsonl").read_bytes() == (Path(run) / "receipts.jsonl").read_bytes()
