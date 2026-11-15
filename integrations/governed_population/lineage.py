# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Verify a population after the fact: every member's existence traces through receipts to the root the
operator founded, and every change was a decision the verifier accepts.

Given only the population's directory and the reader's own copies of the operator's authority key and the
controller's instance key, `verify_population` checks, and raises Bad naming the first failure:

  1. the controller's admission run verifies with both keys pinned and every receipt replayed (through the
     Lean oracle when one is given), and deciding its readings again writes the same receipt bytes;
  2. the founding certificate and the standing order are the operator's, and the root member's spec is the
     one the certificate names;
  3. every other member was admitted by an allow receipt of that run whose reading is a replication, whose
     `subject` is the digest of exactly the specs of the members admitted with it, and whose integer and
     boolean fields are the member's own facts: its generation (its parent's plus one), its rights (within
     the reading's parent rights, themselves within the parent's recorded rights), the count of its batch,
     a fresh instance key and the operator's harness policy; one receipt admits one batch, once;
  4. no member holds the authority key or the controller's key or another member's key, and no member's
     keys directory holds a private authority key;
  5. every version change is an allow receipt of an evolution whose reading names the new version and a
     passed canary, and the evaluation run it cites verifies and passed that exact version;
  6. every stop record is an allowed stop's receipt (or an operator's order the controller carried out);
  7. every member's own harness run verifies with the operator's key and that member's key pinned, and
     replays to the same bytes;
  8. every member not stopped has every ancestor up to the root not stopped: there is no orphan.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from prismpath.kernel import canon2

from . import canary as canary_mod
from . import evidence
from . import identity as ident
from . import policy as pp
from .agent import Version
from .controller import MEMBER_FORMAT, batch_subject, spec_digest
from .limits import RIGHTS


class Bad(Exception):
    pass


def _jsonl(path: Path) -> List[Dict[str, Any]]:
    if not Path(path).exists():
        return []
    rows = []
    for line in Path(path).read_bytes().split(b"\n"):
        if line:
            doc = canon2.loads(line)
            if canon2.dumps(doc) != line:
                raise Bad(f"{path.name}: a line not in its canonical spelling")
            rows.append(doc)
    return rows


def verify_population(root: Path, authority_pub: Path, controller_pub: Path, oracle=None) -> Dict[str, Any]:
    root = Path(root)
    authority_raw, controller_raw = Path(authority_pub).read_bytes(), Path(controller_pub).read_bytes()
    authority_id, controller_id = ident.sha256_hex(authority_raw), ident.sha256_hex(controller_raw)
    admission_image = pp.admission().image
    evaluation_image = pp.evaluation().image

    # 1. the controller's decisions
    run = root / "controller" / "admission"
    try:
        verified = evidence.verify(run, authority_pub, controller_pub, oracle=oracle)
    except Exception as error:  # noqa: BLE001
        raise Bad(f"the admission run does not verify: {error}") from None
    if not evidence.replay_identical(run):
        raise Bad("the admission run's readings decide to other receipts")
    receipts = evidence.receipts(run)
    readings = [canon2.loads(raw) for raw in evidence.readings(run)]
    if any(r["image_sha256"] != ident.sha256_hex(admission_image) for r in receipts):
        raise Bad("an admission receipt names another image")

    def allowed(idx: Any, request: str) -> Dict[str, Any]:
        if type(idx) is not int or not 0 <= idx < len(receipts):
            raise Bad(f"receipt {idx} is not in the admission run")
        receipt = receipts[idx]
        if receipt.get("decision") != "route" or receipt.get("target") != "allow":
            raise Bad(f"receipt {idx} is not an allow")
        if readings[idx]["request"] != request:
            raise Bad(f"receipt {idx} allows a {readings[idx]['request']}, not a {request}")
        return readings[idx]

    # 2. the operator's documents
    founding = canon2.loads((root / "founding.json").read_bytes().rstrip(b"\n"))
    if not ident.verify_signed(founding, authority_raw, "prismpath.population-founding/1"):
        raise Bad("the founding certificate is not signed by the operator")
    standing = canon2.loads((root / "standing_order.json").read_bytes().rstrip(b"\n"))
    if not ident.verify_signed(standing, authority_raw, "prismpath.population-standing-order/1") \
            or standing["image_sha256"] != ident.sha256_hex(admission_image):
        raise Bad("the standing order is not the operator's for this admission image")

    # 3, 4. the members, in the order they were committed
    members: Dict[str, Dict[str, Any]] = {}
    versions: Dict[str, List[str]] = {}
    keys_seen = {authority_id: "the operator", controller_id: "the controller"}
    batches: Dict[int, List[str]] = {}
    for record in _jsonl(root / "members.jsonl"):
        if record.get("format") != MEMBER_FORMAT or set(record) - {"admission"} != set(spec_keys()):
            raise Bad("a member record is not a prismpath.population-member/1 record")
        member_id = record["id"]
        if member_id in members:
            raise Bad(f"member {member_id} is recorded twice")
        spec = {key: value for key, value in record.items() if key != "admission"}
        raw = bytes.fromhex(record["instance_public_key"])
        if ident.sha256_hex(raw) != record["instance_key_id"]:
            raise Bad(f"member {member_id}: its key id is not its key's")
        if record["instance_key_id"] in keys_seen:
            raise Bad(f"member {member_id} holds the key of {keys_seen[record['instance_key_id']]}")
        keys_seen[record["instance_key_id"]] = member_id
        keydir = root / "agents" / member_id / "keys"
        if (keydir / "authority.key").exists() or any(p.suffix == ".key" and p.name != "instance.key" for p in keydir.iterdir()):
            raise Bad(f"member {member_id}'s keys directory holds a key other than its own")
        if (keydir / "instance.pub").read_bytes() != raw:
            raise Bad(f"member {member_id}'s key on disk is not the key its record names")
        version = Version.from_doc(record["version"])
        if version is None or version.sha256 != record["version_sha256"]:
            raise Bad(f"member {member_id}: its version is not the version its record names")
        if not set(record["rights"]) <= set(RIGHTS) or record["rights"] != sorted(set(record["rights"])):
            raise Bad(f"member {member_id}: rights outside the registry of rights")
        admission = record["admission"]
        if record["parent"] == "":
            if members or record["generation"] != 0 or record["line"] != member_id:
                raise Bad("the root is not the first member at generation 0")
            if admission != {"founding_sha256": ident.digest(founding)} or founding["root_spec_sha256"] != spec_digest(spec):
                raise Bad("the root is not the member the founding certificate names")
        else:
            parent = members.get(record["parent"])
            if parent is None:
                raise Bad(f"member {member_id}: its parent is not an earlier member")
            if record["generation"] != parent["generation"] + 1:
                raise Bad(f"member {member_id}: its generation is not its parent's plus one")
            want_line = member_id if parent["generation"] == 0 else parent["line"]
            if record["line"] != want_line:
                raise Bad(f"member {member_id}: its lineage is not its parent's")
            if record["version_sha256"] not in versions[parent["id"]]:
                raise Bad(f"member {member_id}: its version was never its parent's")
            if set(admission) != {"receipt", "batch"}:
                raise Bad(f"member {member_id}: no admission receipt")
            idx, batch = admission["receipt"], admission["batch"]
            reading = allowed(idx, "replicate")
            if idx in batches and batches[idx] != batch:
                raise Bad(f"receipt {idx} admits two batches")
            batches.setdefault(idx, batch)
            if member_id not in batch or reading["requested"] != len(batch):
                raise Bad(f"member {member_id}: its batch is not the count its receipt admitted")
            if reading["child_generation"] != record["generation"] or reading["child_key"] != "instance" \
                    or reading["policy_ref"] != "current" or reading["lineage"] != "verified":
                raise Bad(f"member {member_id}: its receipt's reading is not its own facts")
            for right in RIGHTS:
                if reading[f"child_{right}"] != (right in record["rights"]):
                    raise Bad(f"member {member_id}: its rights are not the rights its receipt admitted")
                if reading[f"parent_{right}"] and right not in parent["rights"]:
                    raise Bad(f"member {member_id}: its receipt gives its parent a right the parent never held")
            members[member_id] = record
        members[member_id] = record
        versions[member_id] = [record["version_sha256"]]
    # each batch's subject binds exactly its members' specs
    for idx, batch in batches.items():
        if any(member_id not in members for member_id in batch):
            raise Bad(f"receipt {idx}: a member of its batch was never recorded")
        specs = [{k: v for k, v in members[m].items() if k != "admission"} for m in batch]
        if readings[idx]["subject"] != batch_subject(specs):
            raise Bad(f"receipt {idx}: its subject is not its batch's specs")

    # 5. evolution
    changes = 0
    for change in _jsonl(root / "versions.jsonl"):
        member_id = change["member"]
        if member_id not in members:
            raise Bad(f"a version change of an unknown member {member_id}")
        reading = allowed(change["receipt"], "evolve")
        if reading["subject"] != change["to"] or reading["canary"] != "passed":
            raise Bad(f"version change of {member_id}: its receipt is not an evolution to {change['to'][:12]} with a passed canary")
        if versions[member_id][-1] != change["from"]:
            raise Bad(f"version change of {member_id}: it did not run the version it changed from")
        why = canary_mod.check_evaluation(root / change["evaluation_run"], change["to"], authority_pub, controller_pub,
                                          evaluation_image, oracle=oracle)
        if why is not None:
            raise Bad(f"version change of {member_id}: {why}")
        versions[member_id].append(change["to"])
        changes += 1

    # 6. stops
    stopped = set()
    for stop in _jsonl(root / "stops.jsonl"):
        if stop["member"] not in members:
            raise Bad(f"a stop of an unknown member {stop['member']}")
        if stop.get("receipt") is not None:
            allowed(stop["receipt"], "stop")
        elif stop.get("by") != "operator":
            raise Bad(f"a stop of {stop['member']} with no receipt that is not the operator's")
        stopped.add(stop["member"])

    # 7. every member's own harness run
    tool_calls = 0
    for member_id, record in members.items():
        member_run = root / "agents" / member_id / "run"
        pub = root / "agents" / member_id / "keys" / "instance.pub"
        try:
            got = evidence.verify(member_run, authority_pub, pub, oracle=oracle)
        except Exception as error:  # noqa: BLE001
            raise Bad(f"member {member_id}'s harness run does not verify: {error}") from None
        if not evidence.replay_identical(member_run):
            raise Bad(f"member {member_id}'s harness run decides to other receipts")
        tool_calls += got["receipts"]

    # 8. no orphan
    survivors = [m for m in members if m not in stopped]
    for member_id in survivors:
        here = members[member_id]["parent"]
        while here:
            if here in stopped:
                raise Bad(f"member {member_id} survives a stopped ancestor {here}")
            here = members[here]["parent"]

    admitted_unused = [i for i, r in enumerate(receipts) if r.get("target") == "allow"
                       and readings[i]["request"] == "replicate" and i not in batches]
    return {"members": len(members), "survivors": len(survivors), "stopped": len(stopped),
            "admission_receipts": len(receipts), "admission_replayed": verified["replayed"],
            "admission_agree": verified["agree"], "replication_receipts_used": len(batches),
            "replication_allows_not_committed": len(admitted_unused), "version_changes": changes,
            "member_tool_call_receipts": tool_calls,
            "growth_bound": sum(len(b) for b in batches.values()) == len(members) - 1}


def spec_keys():
    return ("format", "id", "parent", "generation", "line", "rights", "version_sha256", "version",
            "instance_key_id", "instance_public_key")
