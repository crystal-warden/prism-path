#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Assess a signed policy delivery against NIST SSDF (SP 800-218) and the Cyber Resilience Act's Annex I.

The evidence is a deployed directory as the Zarf integrations leave it: the signed pack, its manifest and
signature, the authority key, the signed envelope, the host's state and audit log, the pack SBOM, and,
when the kernel leg ran, the activation receipt. Nothing here takes that evidence at its word. Every
check is run again by this assessor: the pack is verified, a copy with one byte changed must be refused,
the host state is reopened from a copy and must attest the verified image, a replay of the same pack
into that copy must be refused, the audit log must verify and record the swap, and the SBOM must
validate and name the verified image by hash. The deployed directory is never written; the host checks
run on a temporary copy, because opening a host can append to its audit log.

The mapping from checks to requirements is curated and narrow, and the boundary is the policy artifact.
A requirement the evidence reaches only in part is partially met, with the part it does not reach
written out. A requirement the evidence does not reach is not assessed, and is reported as such, never
as met and never as failed. A failed check makes every requirement that rests on it not met.

    python -m adapters.compliance.assess_policy_delivery <deployed dir> [--out DIR]
"""
import argparse
import hashlib
import json
import os
import shutil
import tempfile

# ============================================================================
# CONFIGURE: set these to your own deployment layout, then run. Nothing below needs editing.
# ----------------------------------------------------------------------------
PACK_NAME = "policy.ppt"                      # the delivered image; its manifest and signature sit beside it
PUBKEY_NAMES = ["authority.pub"]              # the authority key(s) the host trusts
ENVELOPE_BASE = "env1.envelope"               # the signed envelope, without .json or .sig
STATE_DIR_NAME = "state"                      # the host's state directory (active image, version floor, audit log)
SBOM_NAME = "policy.ppt.cdx.json"             # the pack SBOM written by `python -m adapters.compliance.emit --pack-sbom`
ACTIVATION_NAME = "activation.json"           # written by integrations/zarf-kernel/activate.sh; optional
BOUNDARY = "the signed policy pack delivered to this host"
# ============================================================================

from adapters.compliance import emit
from prismpath.hotswap import policy_pack
from prismpath.hotswap.policy_host import PolicyHost
from prismpath.ledgers import ledger_airgap
from prismpath.ledgers.audit_log import AuditLog

HERE = os.path.dirname(os.path.abspath(__file__))
CATALOGS = {"nist_ssdf": os.path.join(HERE, "catalog", "nist_ssdf.json"),
            "eu_cra_annex_i": os.path.join(HERE, "catalog", "eu_cra_annex_i.json")}
ASSESSOR_ID = "policy_delivery_assessor@v1"


# ---------- the checks, each run here, each returning {"ok": True | False | None, "detail": str} ----------
# None means the evidence is absent and the check is optional; a required check that is absent fails.

def _sha256_file(path):
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def _pass(detail):
    return {"ok": True, "detail": detail}


def _fail(detail):
    return {"ok": False, "detail": detail}


def _paths(deployed):
    pack = os.path.join(deployed, PACK_NAME)
    return {"pack": pack, "manifest": pack + ".manifest.json", "signature": pack + ".manifest.sig",
            "pubkeys": [os.path.join(deployed, name) for name in PUBKEY_NAMES],
            "envelope": os.path.join(deployed, ENVELOPE_BASE), "state": os.path.join(deployed, STATE_DIR_NAME),
            "sbom": os.path.join(deployed, SBOM_NAME), "activation": os.path.join(deployed, ACTIVATION_NAME)}


def check_pack_verifies(paths):
    ok, reasons, manifest = policy_pack.verify_pack(paths["pack"], paths["pubkeys"])
    if not ok or manifest is None:
        return _fail("the delivered pack does not verify: " + ", ".join(reasons)), None
    return _pass("the pack verifies against %s: image %s, version %s, key %s" % (
        ", ".join(PUBKEY_NAMES), manifest["image_sha256"], manifest["version"], manifest["key_id"])), manifest


def check_tampered_copy_refused(paths, workdir):
    """Flip one byte in the middle of a copy of the image, keep the authentic manifest and signature,
    and require verification to refuse it."""
    copy = os.path.join(workdir, "tampered", PACK_NAME)
    os.makedirs(os.path.dirname(copy))
    for source, suffix in ((paths["pack"], ""), (paths["manifest"], ".manifest.json"), (paths["signature"], ".manifest.sig")):
        shutil.copyfile(source, copy + suffix)
    with open(copy, "r+b") as handle:
        image = bytearray(handle.read())
        image[len(image) // 2] ^= 0xFF
        handle.seek(0)
        handle.write(image)
    ok, reasons, _manifest = policy_pack.verify_pack(copy, paths["pubkeys"])
    if ok:
        return _fail("a copy with one byte changed still verifies")
    return _pass("a copy with one byte changed is refused: " + ", ".join(reasons))


def _open_host_copy(paths, workdir):
    envelope, reasons = policy_pack.load_envelope(paths["envelope"], paths["pubkeys"])
    if envelope is None:
        return None, "the envelope does not verify: " + ", ".join(reasons)
    if not os.path.isdir(paths["state"]):
        return None, "no host state directory at " + paths["state"]
    state_copy = os.path.join(workdir, "state")
    shutil.copytree(paths["state"], state_copy)
    return PolicyHost(state_copy, paths["pubkeys"], envelope), None


def check_host_attests_pack(paths, manifest, workdir):
    host, problem = _open_host_copy(paths, os.path.join(workdir, "attest"))
    if host is None:
        return _fail(problem)
    active = host.active().get("active")
    on_disk = os.path.join(paths["state"], "active.ppt")
    disk_hash = _sha256_file(on_disk) if os.path.exists(on_disk) else None
    if active != manifest["image_sha256"] or disk_hash != manifest["image_sha256"]:
        return _fail("the host attests %s and its stored image hashes to %s, but the verified pack is %s" % (
            active or "nothing", disk_hash or "nothing", manifest["image_sha256"]))
    return _pass("the host's state, reopened, attests the verified image as active and its stored copy hashes to it")


def check_replay_refused(paths, manifest, workdir):
    host, problem = _open_host_copy(paths, os.path.join(workdir, "replay"))
    if host is None:
        return _fail(problem)
    outcome = host.swap(paths["pack"])
    reasons = outcome.get("reasons", [])
    if outcome.get("ok") or not any(reason.startswith("version:not-monotonic") for reason in reasons):
        return _fail("replaying version %s into a copy of the host state was not refused by the version floor: %s" % (
            manifest["version"], outcome))
    return _pass("replaying the same pack into a copy of the host state is refused: " + ", ".join(reasons))


def check_audit_trail_intact(paths, manifest):
    log_path = os.path.join(paths["state"], "swaps.log")
    if not os.path.exists(log_path):
        return _fail("no audit log at " + log_path)
    log = AuditLog(log_path)
    if not log.verify_log():
        return _fail("the audit log does not verify (%d unreadable lines)" % len(log.skipped))
    accepted = [event for event in log.events if event.get("action") == "swap"
                and event.get("data", {}).get("to_hash") == manifest["image_sha256"]
                and event.get("data", {}).get("result") == "accepted"]
    if not accepted:
        return _fail("the audit log verifies but records no accepted swap of the verified image")
    return _pass("the audit log verifies (%d events, Merkle root %s) and records the accepted swap of the verified image" % (
        len(log.events), log.current_root()))


def check_sbom_bound(paths, manifest):
    if not os.path.exists(paths["sbom"]):
        return _fail("no pack SBOM at " + paths["sbom"])
    with open(paths["sbom"]) as handle:
        sbom = json.load(handle)
    valid, errors = emit.validate(sbom, "cyclonedx")
    if not valid:
        return _fail("the SBOM is not valid CycloneDX: " + "; ".join(errors[:3]))
    component = sbom.get("metadata", {}).get("component", {})
    hashes = {entry.get("alg"): entry.get("content") for entry in component.get("hashes", [])}
    if hashes.get("SHA-256") != manifest["image_sha256"] or component.get("version") != str(manifest["version"]):
        return _fail("the SBOM describes %s version %s, not the verified image %s version %s" % (
            hashes.get("SHA-256"), component.get("version"), manifest["image_sha256"], manifest["version"]))
    return _pass("the SBOM is valid CycloneDX %s and names the verified image by SHA-256 and version" % sbom.get("specVersion"))


def check_activation_consistent(paths, manifest):
    if not os.path.exists(paths["activation"]):
        return {"ok": None, "detail": "no activation receipt; the kernel leg was not run"}
    with open(paths["activation"]) as handle:
        receipt = json.load(handle)
    image = manifest["image_sha256"]
    if not (receipt.get("activated") is True and receipt.get("attested_active") == image
            and receipt.get("loaded_sha256") == image and receipt.get("in_kernel_path")
            and receipt.get("in_kernel_path") == receipt.get("host_reference_path")):
        return _fail("the activation receipt does not show the verified image deciding in the kernel along the host reference path: %s" % receipt)
    return _pass("the kernel loaded the attested image and decided the probe along the host reference path: " + receipt["in_kernel_path"])


def run_checks(deployed):
    """Run every check against a deployed directory. Returns (checks, manifest, evidence hashes)."""
    paths = _paths(deployed)
    checks = {}
    verified, manifest = check_pack_verifies(paths)
    checks["pack_verifies"] = verified
    with tempfile.TemporaryDirectory() as workdir:
        if manifest is None:
            for name in ("tampered_copy_refused", "host_attests_pack", "replay_refused", "audit_trail_intact",
                         "sbom_bound", "activation_consistent"):
                checks[name] = _fail("not run: the pack itself does not verify")
        else:
            checks["tampered_copy_refused"] = check_tampered_copy_refused(paths, workdir)
            checks["host_attests_pack"] = check_host_attests_pack(paths, manifest, workdir)
            checks["replay_refused"] = check_replay_refused(paths, manifest, workdir)
            checks["audit_trail_intact"] = check_audit_trail_intact(paths, manifest)
            checks["sbom_bound"] = check_sbom_bound(paths, manifest)
            checks["activation_consistent"] = check_activation_consistent(paths, manifest)
    evidence = {}
    for label, path in (("pack", paths["pack"]), ("manifest", paths["manifest"]), ("signature", paths["signature"]),
                        ("envelope", paths["envelope"] + ".json"), ("sbom", paths["sbom"]),
                        ("audit_log", os.path.join(paths["state"], "swaps.log")), ("activation", paths["activation"])):
        if os.path.exists(path):
            evidence[label] = _sha256_file(path)
    return checks, manifest, evidence


# ---------- the curated mapping: which checks evidence which requirement, and how far ----------
# `required` checks must all pass; `supporting` checks count only when their evidence is present.
# `limit` names the part of the requirement the evidence does not reach; an objective with a limit is
# at most partially met. Objectives absent from this table are not assessed.
MAPPING = {
    "nist_ssdf": {
        "PS.2.1": {"required": ["pack_verifies", "tampered_copy_refused"], "supporting": [],
                   "shows": "the pack ships its signed manifest, detached Ed25519 signature and authority key, the pack verifies, and a copy with one byte changed is refused",
                   "limit": None},
        "PS.3.2": {"required": ["pack_verifies", "sbom_bound"], "supporting": [],
                   "shows": "a CycloneDX SBOM generated from the verified manifest is delivered with the pack and names the image by hash and version",
                   "limit": "the SBOM is bound to the image by hash but is not itself signed, and its retention across releases is not evidenced"},
        "PW.4.4": {"required": ["pack_verifies", "host_attests_pack", "replay_refused"], "supporting": ["activation_consistent"],
                   "shows": "the host verifies the acquired pack against the signed envelope and the version floor before it becomes active, and refuses a replay",
                   "limit": "verification is evidenced at each swap, not between swaps, and only for the policy pack"},
    },
    "eu_cra_annex_i": {
        "I.2.f[a]": {"required": ["pack_verifies", "tampered_copy_refused", "host_attests_pack", "audit_trail_intact"],
                     "supporting": ["activation_consistent"],
                     "shows": "a modified policy is refused before activation, the refusal is recorded, and the host attests exactly the verified image",
                     "limit": "evidenced for the policy, which is program and configuration, only; the integrity of other data the product stores, transmits or processes is not evidenced"},
        "I.2.l[a]": {"required": ["audit_trail_intact"], "supporting": [],
                     "shows": "every swap, refusal and attestation is recorded in an audit log whose Merkle root verifies",
                     "limit": "recording is evidenced for policy changes only, and no user opt-out mechanism is evidenced"},
        "II.1[a]": {"required": ["pack_verifies", "sbom_bound"], "supporting": [],
                    "shows": "a machine-readable CycloneDX 1.6 SBOM covers the policy component and is bound to the verified image by hash",
                    "limit": "identifying and documenting vulnerabilities, and the product's other dependencies, are not evidenced"},
        "II.7[a]": {"required": ["pack_verifies", "tampered_copy_refused", "replay_refused", "host_attests_pack"],
                    "supporting": ["activation_consistent"],
                    "shows": "policy updates are signed, verified on arrival, refused when altered or replayed, and recorded",
                    "limit": "timely and automatic distribution of security updates is not evidenced"},
    },
}

NOT_REACHED = "no check this assessor runs produces evidence for it"


def _objective_outcome(row, checks):
    failed = [name for name in row["required"] if checks[name]["ok"] is not True]
    failed += [name for name in row["supporting"] if checks[name]["ok"] is False]
    if failed:
        return "not-met", "check failed: " + "; ".join("%s (%s)" % (name, checks[name]["detail"]) for name in failed)
    used = row["required"] + [name for name in row["supporting"] if checks[name]["ok"] is True]
    reason = row["shows"] + " (checks: " + ", ".join(used) + ")"
    if row["limit"]:
        return "partially-met", reason + "; not reached: " + row["limit"]
    return "met", reason


def assess(standard, checks, manifest, evidence):
    """Turn the checks into emit() records for one standard. Returns (records, not_assessed)."""
    with open(CATALOGS[standard], encoding="utf-8") as handle:
        catalog = json.load(handle)
    catalog_hash = "sha256:" + _sha256_file(CATALOGS[standard])
    mapping = MAPPING[standard]
    records, not_assessed = [], []
    for control_id, control in catalog["controls"].items():
        outcomes = {}
        for objective in control["objectives"]:
            row = mapping.get(objective["id"])
            outcomes[objective["id"]] = _objective_outcome(row, checks) if row else ("not-assessed", NOT_REACHED)
        if all(outcome == "not-assessed" for outcome, _reason in outcomes.values()):
            not_assessed.append({"control_id": control_id, "title": control["title"], "reason": NOT_REACHED})
            continue
        statuses = [outcome for outcome, _reason in outcomes.values()]
        status = "not-met" if "not-met" in statuses else ("met" if all(item == "met" for item in statuses) else "partially-met")
        determination = {"standard": standard, "control_id": control_id, "status": status,
                         "objectives": {objective_id: list(outcome) for objective_id, outcome in outcomes.items()},
                         "checks": {name: checks[name] for name in sorted(checks)}}
        root = hashlib.sha256(json.dumps(determination, sort_keys=True).encode()).hexdigest()
        records.append({
            "control_id": control_id, "title": control["title"], "boundary": BOUNDARY, "status": status,
            "gap_summary": " ".join("%s %s: %s." % (objective_id, outcome, reason) for objective_id, (outcome, reason) in outcomes.items()),
            "unmet_objective_ids": [objective_id for objective_id, (outcome, _reason) in outcomes.items() if outcome != "met"],
            "manifest": ledger_airgap.provenance_manifest(
                root, "assess:policy-delivery:%s:%s" % (standard, control_id),
                policy_hash="sha256:" + manifest["image_sha256"] if manifest else None, gate_id=ASSESSOR_ID,
                ingestion_hashes=["sha256:" + evidence[label] for label in sorted(evidence)],
                knowledge_base_hash=catalog_hash),
        })
    return records, not_assessed


def assess_deployment(deployed, out_dir=None, now=None):
    """Run the checks once, then assess and emit both standards. Returns a summary per standard."""
    checks, manifest, evidence = run_checks(deployed)
    summary = {"deployed": os.path.abspath(deployed), "boundary": BOUNDARY, "checks": checks, "standards": {}}
    for standard in CATALOGS:
        records, not_assessed = assess(standard, checks, manifest, evidence)
        emitted = emit.emit(records, fmt="both", now=now, standard=standard, not_assessed=not_assessed,
                            out_dir=os.path.join(out_dir, standard) if out_dir else None)
        summary["standards"][standard] = {
            "assessed": {record["control_id"]: record["status"] for record in records},
            "not_assessed": [item["control_id"] for item in not_assessed],
            "emitted": {name: {"valid": emission["valid"], "errors": emission["errors"][:3], "path": emission["path"]}
                        for name, emission in emitted.items()},
            "records": records, "not_assessed_detail": not_assessed}
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("deployed", help="the deployed directory a Zarf integration left on the host")
    parser.add_argument("--out", default=None, help="write OSCAL and CycloneDX reports under this directory")
    args = parser.parse_args()
    summary = assess_deployment(args.deployed, out_dir=args.out)
    printable = {"checks": {name: check["ok"] for name, check in summary["checks"].items()},
                 "standards": {standard: {key: value for key, value in result.items()
                                          if key not in ("records", "not_assessed_detail")}
                               for standard, result in summary["standards"].items()}}
    print(json.dumps(printable, indent=1))
    all_valid = all(emission["valid"] for result in summary["standards"].values()
                    for emission in result["emitted"].values())
    return 0 if all_valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
