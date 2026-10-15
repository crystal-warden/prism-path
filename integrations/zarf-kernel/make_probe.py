#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Build-time inputs for the kernel activation demo: the node names, and one probe reading encoded as
the register file the in-kernel evaluator reads.

The compiled image carries register indices and string ids, not field names or the strings themselves,
so a reading can only be encoded with the compiler's binding of the same flow. This script recompiles
the flow, refuses unless the result is byte identical to the committed policy image, and only then
encodes the probe against it. The binding itself is not covered by the pack's signature today; the
demo's README says so, and the pack format change that would carry it is a separate decision.

    python make_probe.py [flow.md] [policy.ppt]
"""
import json
import os
import sys
from pathlib import Path

# ============================================================================
# CONFIGURE: set these to your own flow, image and reading, then run. Nothing below needs editing.
# ----------------------------------------------------------------------------
HERE = Path(__file__).resolve().parent
REPO = Path(os.environ.get("PRISMPATH_REPO", HERE.parent.parent))   # the prism-path checkout (compiler, flows)
FLOW_PATH = Path(sys.argv[1]) if len(sys.argv) > 1 else REPO / "adapters" / "fusion" / "flows" / "fusion_triage.md"
IMAGE_PATH = Path(sys.argv[2]) if len(sys.argv) > 2 else REPO / "integrations" / "zarf" / "policy.ppt"
# SAMPLE: a shaken device during a containment level alert, which the fusion flow escalates.
PROBE_READING = {"rule_level": 12, "soc_action": "contain", "stability": "shaken", "dev_mg": 3000}
# ============================================================================

sys.path.insert(0, str(REPO / "prismpath-hw"))       # the compiler lives beside the hardware targets
import ppt_compile  # noqa: E402

from prismpath.kernel.parser import parse_file  # noqa: E402


def main() -> int:
    image = ppt_compile.compile_flow(parse_file(str(FLOW_PATH)))
    if image.serialize() != IMAGE_PATH.read_bytes():
        print(f"refused: {FLOW_PATH.name} does not compile to the committed {IMAGE_PATH.name}; "
              f"the probe would be encoded against a different binding", file=sys.stderr)
        return 1
    (HERE / "probe.regs.bin").write_bytes(ppt_compile.encode_regs(image, PROBE_READING, node_idx=image.start))
    (HERE / "policy.names").write_text("".join(name + "\n" for name, _edges in image.nodes))
    (HERE / "probe.json").write_text(json.dumps({"flow": FLOW_PATH.name, "reading": PROBE_READING}, indent=1) + "\n")
    print(f"probe encoded against {IMAGE_PATH.name}: {len(image.fields)} registers, {len(image.nodes)} nodes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
