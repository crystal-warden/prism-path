# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Facet encode an OPA input (the A5 combination test of PREREGISTRATION.md section 5).

The sender quantizes a reading against the partitions PrismPath derives from the policy, packs the
symbols as a self framing Zeckendorf stream, and ships those bytes. The receiver decodes them back to
a representative reading in the same cells and posts that representative to OPA as the input JSON. If
OPA's decision on the representative equals its decision on the original reading for every corpus
scenario, Facet is a transport that composes with OPA; the partitions come from the policy text, so
the OPA policy and the PrismPath flow must be the same neutral policy (the corpus guarantees that).
"""
from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path
from typing import Any, Dict, Tuple

REPO = Path(__file__).resolve().parents[3]
from prismpath.telemetry import packed  # noqa: E402
from prismpath.telemetry import quantizer as q  # noqa: E402
from prismpath.telemetry import wire as w  # noqa: E402

from prismpath.kernel.parser import parse  # noqa: E402


def partitions_for(flow_markdown: str) -> Dict[str, Any]:
    return q.build_partitions(parse(flow_markdown))


def encode(parts: Dict[str, Any], reading: Dict[str, Any]) -> bytes:
    """Sender side: reading -> Facet frame bytes."""
    return packed.pack(w.encode_reading(parts, reading), 8)


def decode(parts: Dict[str, Any], frame: bytes) -> Dict[str, Any]:
    """Receiver side: Facet frame bytes -> representative reading for OPA's input document."""
    return w.decode_reading(parts, packed.unpack(frame))


def opa_decide(url: str, reading: Dict[str, Any]) -> Tuple[Dict[str, Any], int, int]:
    """POST the reading as OPA input; returns (result document, request bytes, response bytes)."""
    body = json.dumps({"input": reading}, separators=(",", ":")).encode()
    req = urllib.request.Request(url, data=body, headers={"content-type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=10) as r:
        raw = r.read()
    return json.loads(raw).get("result"), len(body), len(raw)
