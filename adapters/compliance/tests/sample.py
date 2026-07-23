"""Deterministic factories for the compliance-adapter test suite (no gemma)."""
import hashlib
from prismpath import ledger_airgap

FIXED_NOW = "2026-07-22T12:00:00+00:00"
CATALOG_CIDS = ["3.1.1", "3.1.2", "3.1.4", "3.1.5", "3.1.7", "3.1.11", "3.1.12", "3.1.22"]
STATUSES = ["met", "partially-met", "not-met"]


def make_manifest(cid, root="deadbeef"):
    return ledger_airgap.provenance_manifest(
        root_hex=hashlib.sha256((cid + root).encode()).hexdigest(),
        label="assess:" + cid, policy_hash="sha256:flow", gate_id="gate@v0",
        ingestion_hashes=["sha256:bundle" + cid.replace(".", "")], knowledge_base_hash="sha256:kb")


def record(cid, title="Control", status="met", unmet=None, boundary="CUI enclave", gap="summary"):
    return {"control_id": cid, "title": title, "boundary": boundary, "status": status,
            "gap_summary": gap, "unmet_objective_ids": unmet or [], "manifest": make_manifest(cid)}
