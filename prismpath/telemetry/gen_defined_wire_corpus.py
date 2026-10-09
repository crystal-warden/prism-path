#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Freeze the Facet stream of every canonical probe in the field definition vectors.

    python -m prismpath.telemetry.gen_defined_wire_corpus

For each accepted policy in `prismpath/portable/conformance/field_definitions.json`, records every
field's cell count, whether it has an absent cell, and for each probe the symbols and the encoded bits
the reference produces. Facet conformance (PROTOCOL section 4) asks for byte identical streams, and
this is what holds the Rust twin to the reference's cell layout for defined fields, the absent cell
included. Regenerating it is a spec change and must be reviewed as one.
"""
import json
from pathlib import Path

from prismpath.kernel.parser import parse
from prismpath.portable import gen_field_definitions
from prismpath.telemetry import quantizer, wire

SOURCE = Path(gen_field_definitions.__file__).parent / "conformance" / "field_definitions.json"
OUT = Path(__file__).resolve().parent / "conformance" / "defined_wire.json"


def build() -> dict:
    policies = []
    for policy in json.loads(SOURCE.read_text())["policies"]:
        if not policy["accepted"]:
            continue
        parts = quantizer.build_partitions(parse(policy["flow"]))
        fields = {field: {"cells": part.n, "absent_symbol": part.absent_symbol} for field, part in sorted(parts.items())}
        probes = [{"reading": probe["reading"],
                   "symbols": dict(sorted(quantizer.checked_quantize(parts, probe["reading"]).items())),
                   "bits": wire.encode_reading_checked(parts, probe["reading"])}
                  for probe in policy["probes"]]
        policies.append({"name": policy["name"], "fields": fields, "probes": probes})
    return {"comment": "FROZEN. The Facet stream of every canonical probe of the field definition vectors, "
                       "from the Python reference. Both implementation twins replay this file.",
            "policies": policies}


def main() -> int:
    corpus = build()
    OUT.write_text(json.dumps(corpus, indent=1) + "\n")
    print(f"wrote {OUT}: {sum(len(policy['probes']) for policy in corpus['policies'])} probes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
