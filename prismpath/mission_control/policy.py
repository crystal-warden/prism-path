# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Policy router: read-only policy pack verification, the active policy of a deployment, and telemetry facet encoding.

Surfaces policy pack verification, the policy a deployment's state directory names as active with its
swap history, and facet wire encoding and decoding for Mission Control. Every route here reads. The
active policy is read from the state directory's files (`active_policy.json`, the image it names,
`swaps.log`) without constructing a `PolicyHost`, whose constructor creates the directory and may append
recovery events, and nothing is attested: attesting appends to the deployment's own log, which is the
operator's act from the command line (`prismpath swap attest`), not the console's. All file path
references are confined to the active project root through the mission control core sandbox guard to
prevent path traversal.
"""
import json
import os
from typing import Any, Dict, List, Optional, Union

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from . import core

router = APIRouter(prefix="/policy", tags=["auditing", "policy"])


class PackVerifyRequest(BaseModel):
    ppt_path: str = Field(..., description="Path to the signed policy image table artifact.")
    pub: List[str] = Field(..., description="List of authority public key file paths.")


class PackActiveRequest(BaseModel):
    state_dir: str = Field(..., description="Project relative state directory of the deployment's policy host.")
    last: int = Field(50, ge=0, le=1000, description="How many of the most recent swaps.log events to return.")


class FacetDecodeRequest(BaseModel):
    flow_md: str = Field(..., description="Relative path to the flow markdown definition file.")
    payload_hex: str = Field(..., description="Wire telemetry payload encoded as hexadecimal text.")


class FacetEncodeRequest(BaseModel):
    flow_md: str = Field(..., description="Relative path to the flow markdown definition file.")
    reading_json: Union[Dict[str, Any], str] = Field(..., description="Telemetry reading dictionary or JSON string.")


@router.post("/pack-verify")
def verify_pack_endpoint(request: PackVerifyRequest):
    """Verify a signed policy pack against public keys without applying hot-swap changes."""
    project_dir = core.current_project()              # one project for the whole request
    safe_ppt_path = core.safe_path(project_dir, request.ppt_path)
    safe_pubkey_paths = [core.safe_path(project_dir, key_path) for key_path in request.pub]

    if not os.path.exists(safe_ppt_path):
        raise HTTPException(status_code=400, detail="policy pack image file does not exist")
    for key_path in safe_pubkey_paths:
        if not os.path.exists(key_path):
            raise HTTPException(status_code=400, detail=f"public key file does not exist: {key_path}")

    try:
        from prismpath.hotswap import policy_pack
    except Exception as exception:
        raise HTTPException(status_code=500, detail=f"policy pack module unavailable: {exception}")

    is_ok, reasons, manifest = policy_pack.verify_pack(safe_ppt_path, safe_pubkey_paths)
    return {"ok": is_ok, "reasons": reasons, "manifest": manifest}


@router.post("/pack-active")
def pack_active_endpoint(request: PackActiveRequest):
    """The policy a deployment's state directory names as active, whether its image is there with the
    digest the record names, and the swap history from `swaps.log` with whether its Merkle root holds.
    Reads only: no directory is created and nothing is appended to the deployment's log."""
    state_dir = core.safe_path(core.current_project(), request.state_dir)
    return active_report(state_dir, request.state_dir, request.last)


def active_report(state_dir: str, label: str, last: int = 50) -> dict:
    """The report `/policy/pack-active` returns for an already confined state directory `state_dir`,
    named `label` in the report. The operating interface's `/policy/active` reads the same report from a
    state directory under the evidence roots."""
    from prismpath import canon
    from prismpath.hotswap import policy_host
    from prismpath.ledgers.audit_log import AuditLog

    report = {"state_dir": label, "active": None, "image_ok": None, "reason": None,
              "pending": os.path.exists(os.path.join(state_dir, "pending_swap")),
              "history": [], "log": {"present": False, "events": 0, "verifies": None, "root": None}}
    if not os.path.isdir(state_dir):
        report["reason"] = "state:missing"
        return report

    record_path = os.path.join(state_dir, "active_policy.json")
    try:
        if os.path.getsize(record_path) > core.SETTINGS.max_file_bytes:
            raise HTTPException(status_code=413, detail="active record exceeds MC_MAX_FILE_BYTES")
        with open(record_path, encoding="utf-8", newline="") as record_file:
            record = canon.loads_document(record_file.read())
    except FileNotFoundError:
        record, report["reason"] = None, "record:missing"
    except (OSError, ValueError) as error:
        record, report["reason"] = None, f"record:unreadable:{type(error).__name__}"
    if isinstance(record, dict):
        record.pop(canon.ENCODING_KEY, None)
        name = record.get("image_file", policy_host.LEGACY_IMAGE)
        report.update({"active": record.get("sha256"), "version": record.get("version"),
                       "since": record.get("since"), "unsigned": record.get("unsigned"),
                       "envelope_id": record.get("envelope_id"), "overlay_of": record.get("overlay_of"),
                       "image_file": name})
        if name != policy_host.LEGACY_IMAGE and not (isinstance(name, str) and policy_host._IMAGE_FILE.fullmatch(name)):
            report["image_ok"], report["reason"] = False, "record:image-file-invalid"
        else:
            try:
                with open(os.path.join(state_dir, name), "rb") as image_file:
                    digest = canon.sha256_hex(image_file.read())
                report["image_ok"] = digest == record.get("sha256")
                if not report["image_ok"]:
                    report["reason"] = "image:digest-mismatch"
            except OSError:
                report["image_ok"], report["reason"] = False, "image:unreadable"
    elif record is not None:
        report["reason"] = "record:not-an-object"

    log_path = os.path.join(state_dir, "swaps.log")
    if os.path.isfile(log_path):
        if os.path.getsize(log_path) > core.SETTINGS.max_file_bytes:
            raise HTTPException(status_code=413, detail="swaps.log exceeds MC_MAX_FILE_BYTES")
        swaps = AuditLog(log_path)                    # reads; an AuditLog writes only on append
        report["log"] = {"present": True, "events": len(swaps.events), "verifies": swaps.verify_log(),
                         "root": swaps.current_root(), "skipped": list(swaps.skipped)}
        report["signing"] = _statement_status(swaps)
        report["history"] = swaps.events[-last:] if last else []
    return report


def _statement_status(log) -> dict:
    """The root statement chain beside a log, as `prismpath trail` reports it, with no key pinned."""
    from prismpath.extras import MissingExtra
    try:
        status = log.verify_statements(None)
    except MissingExtra as missing:
        return {"status": "unchecked", "reason": str(missing)}
    return {key: status.get(key) for key in ("status", "statements", "keys", "findings") if key in status}


@router.post("/facet-decode")
def facet_decode_endpoint(request: FacetDecodeRequest):
    """Decode a wire telemetry hex string into a structured reading and resolve the start node edge transition."""
    project_dir = core.current_project()              # one project for the whole request
    safe_flow_path = core.safe_path(project_dir, request.flow_md)

    if not os.path.exists(safe_flow_path):
        raise HTTPException(status_code=400, detail="flow markdown file does not exist")

    from prismpath.kernel import parser, predicates
    from prismpath.telemetry import packed, quantizer, wire

    try:
        flow_graph = parser.parse_file(safe_flow_path)
    except Exception as exception:
        raise HTTPException(status_code=400, detail=f"could not parse flow markdown: {exception}")

    try:
        raw_bytes = bytes.fromhex(request.payload_hex)
    except ValueError as exception:
        raise HTTPException(status_code=400, detail=f"invalid hexadecimal payload: {exception}")

    partitions = quantizer.build_partitions(flow_graph)
    unpacked_bits = packed.unpack(raw_bytes)
    reconstructed_reading = wire.decode_reading(partitions, unpacked_bits)

    start_node = flow_graph.start
    next_node = None
    transition_cause = None

    if start_node in flow_graph.nodes:
        for target_node, condition_expression in flow_graph.nodes[start_node].edges:
            if (
                predicates.is_deterministic(condition_expression)
                and predicates.eval_condition(condition_expression, reconstructed_reading)
            ):
                next_node = target_node
                transition_cause = condition_expression
                break

    return {
        "reading": reconstructed_reading,
        "next_node": next_node,
        "cause": transition_cause,
    }


@router.post("/facet-encode")
def facet_encode_endpoint(request: FacetEncodeRequest):
    """Quantize and wire-encode a JSON telemetry reading against flow decision partitions."""
    project_dir = core.current_project()              # one project for the whole request
    safe_flow_path = core.safe_path(project_dir, request.flow_md)

    if not os.path.exists(safe_flow_path):
        raise HTTPException(status_code=400, detail="flow markdown file does not exist")

    from prismpath.kernel import parser
    from prismpath.telemetry import packed, quantizer, wire

    try:
        flow_graph = parser.parse_file(safe_flow_path)
    except Exception as exception:
        raise HTTPException(status_code=400, detail=f"could not parse flow markdown: {exception}")

    if isinstance(request.reading_json, str):
        try:
            reading_dict = json.loads(request.reading_json)
        except Exception as exception:
            raise HTTPException(status_code=400, detail=f"invalid JSON reading payload: {exception}")
    elif isinstance(request.reading_json, dict):
        reading_dict = request.reading_json
    else:
        raise HTTPException(status_code=400, detail="reading payload must be a JSON object or string")

    partitions = quantizer.build_partitions(flow_graph)
    partition_keys = sorted(partitions.keys())
    missing_fields = [field_name for field_name in partition_keys if field_name not in reading_dict]
    if missing_fields:
        raise HTTPException(
            status_code=400,
            detail=f"reading missing decision fields: {missing_fields}",
        )

    quantized_symbols = quantizer.quantize(partitions, reading_dict)
    encoded_bits = wire.encode_reading(partitions, reading_dict)
    packed_bytes = packed.pack(encoded_bits, 8)
    payload_hex = packed_bytes.hex()

    return {
        "payload_hex": payload_hex,
        "quantized": quantized_symbols,
    }

