# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Policy router: read-only policy pack verification, attestation status, and telemetry facet encoding.

Surfaces policy pack verification, active policy host attestation status, and facet wire encoding
and decoding for Mission Control. All file path references are strictly confined to the active project
root through the mission control core sandbox guard to prevent path traversal.
"""
import json
import os
from typing import Any, Dict, List, Optional, Union

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from . import core

router = APIRouter(prefix="/policy", tags=["policy"])


class PackVerifyRequest(BaseModel):
    ppt_path: str = Field(..., description="Path to the signed policy image table artifact.")
    pub: List[str] = Field(..., description="List of authority public key file paths.")


class PackAttestRequest(BaseModel):
    state_dir: str = Field(..., description="State directory for active policy host tracking.")
    envelope: Optional[str] = Field(None, description="Optional envelope base path without file extension.")
    pub: Optional[List[str]] = Field(None, description="Optional list of public key paths for envelope verification.")


class FacetDecodeRequest(BaseModel):
    flow_md: str = Field(..., description="Relative path to the flow markdown definition file.")
    payload_hex: str = Field(..., description="Wire telemetry payload encoded as hexadecimal text.")


class FacetEncodeRequest(BaseModel):
    flow_md: str = Field(..., description="Relative path to the flow markdown definition file.")
    reading_json: Union[Dict[str, Any], str] = Field(..., description="Telemetry reading dictionary or JSON string.")


@router.post("/pack-verify")
def verify_pack_endpoint(request: PackVerifyRequest):
    """Verify a signed policy pack against public keys without applying hot-swap changes."""
    project_dir = core.STATE["proj"]
    safe_ppt_path = core._safe(project_dir, request.ppt_path)
    safe_pubkey_paths = [core._safe(project_dir, key_path) for key_path in request.pub]

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


@router.post("/pack-attest")
def pack_attest_endpoint(request: PackAttestRequest):
    """Return the active policy attestation and status for Mission Control in read-only mode."""
    project_dir = core.STATE["proj"]
    safe_state_dir = core._safe(project_dir, request.state_dir)
    safe_pubkey_paths = [core._safe(project_dir, key_path) for key_path in (request.pub or [])]

    try:
        from prismpath.hotswap import policy_host, policy_pack
    except Exception as exception:
        raise HTTPException(status_code=500, detail=f"policy host module unavailable: {exception}")

    envelope_data = {}
    if request.envelope:
        safe_envelope_path = core._safe(project_dir, request.envelope)
        if safe_pubkey_paths:
            envelope_dict, reasons = policy_pack.load_envelope(safe_envelope_path, safe_pubkey_paths)
            if envelope_dict is None:
                return {"ok": False, "reasons": reasons}
            envelope_data = envelope_dict
        else:
            json_path = safe_envelope_path if safe_envelope_path.endswith(".json") else safe_envelope_path + ".json"
            if not os.path.exists(json_path):
                return {"ok": False, "reasons": ["envelope:missing"]}
            try:
                with open(json_path, encoding="utf-8") as file_handle:
                    envelope_data = json.load(file_handle)
            except Exception as exception:
                return {"ok": False, "reasons": [f"envelope:unreadable:{exception}"]}

    host = policy_host.PolicyHost(
        state_dir=safe_state_dir,
        pubkey_paths=safe_pubkey_paths,
        envelope=envelope_data,
    )
    attestation_status = host.attest()
    return attestation_status


@router.post("/facet-decode")
def facet_decode_endpoint(request: FacetDecodeRequest):
    """Decode a wire telemetry hex string into a structured reading and resolve the start node edge transition."""
    project_dir = core.STATE["proj"]
    safe_flow_path = core._safe(project_dir, request.flow_md)

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
    project_dir = core.STATE["proj"]
    safe_flow_path = core._safe(project_dir, request.flow_md)

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


# app.include_router(policy.router, prefix=API_PREFIX)
