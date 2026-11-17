#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Turn the example core policy into the kernel's image bytes and the cFE table's include file.

    python3 -m integrations.cfs.prismpath_app.policy.gen_image            # rewrite the include file
    python3 -m integrations.cfs.prismpath_app.policy.gen_image --check    # fail when it is out of date

The readable rules source (`example.rules.md`) is compiled with `prismpath policy compile` to the signed core
image (`example.core.json`). The core image is checked by the port of the Lean oracle's loadPolicy
(`prismpath.kernel.core_policy`), rendered to its canonical flow and compiled to a PPT v1 table the way
`integrations/governed_net/policy.py` does it for the XDP program: the policy's one node holds one edge per
rule, in rule order, and each edge leads to its own terminal node, so the kernel's first matching edge IS the
rule that decided. The register order is the policy's field names sorted, the order the reading layout in
`fsw/inc/prismpath_app_layout.h` must list them in.

What the C table carries beside the image (prismpath_app_policy_image.inc):
  the image bytes, the rule actions (allow, refuse or escalate, and the registered cause code), the two
  causes the core itself refuses with (route:contract-violation for a reading outside its field definitions,
  route:no-matching-edge for a reading no rule holds), and a hash of the field layout so an image for another
  reading is refused at validation; and for the receipts (work package S2) the image's version, the signed core
  image's canon/2 bytes and its canonical flow rendering spelled as a canon/2 string, which a core run's
  receipts and cases file carry. The two authority signatures are not in the include: they are made on the
  ground with the authority key, over the built table file (integrations/cfs/ground/table.py).
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Dict, List, Tuple

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[3]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from prismpath.agent.policy import Policy, target_decision  # noqa: E402
from prismpath.kernel import canon2, causes, ppt_compile  # noqa: E402
from prismpath.kernel.parser import Node, parse  # noqa: E402

CORE = HERE / "example.core.json"
INC = HERE.parent / "fsw" / "tables" / "prismpath_app_policy_image.inc"
IMAGE_MAX = 1024          # PRISMPATH_APP_IMAGE_MAX
RULES_MAX = 16            # PRISMPATH_APP_MAX_RULES
CORE_MAX = 2048          # PRISMPATH_APP_CORE_MAX
FLOW_MAX = 1536          # PRISMPATH_APP_FLOW_MAX
KIND = {"allow": 0, "refuse": 1, "escalate": 2}
# The example image's version. The Critical Data Store holds the highest version accepted, and a table below it,
# or equal to it with other bytes, is refused (image:version-replay). A new image ships with a higher version.
VERSION = 3


def field_defs(doc: dict) -> List[Tuple[str, str, int, int]]:
    """(name, 'int'|'bool', min, max) in register order: the field names sorted."""
    out = []
    for name in sorted(doc["fields"]):
        words = doc["fields"][name].split()
        kind = words[0]
        opts = dict(word.split("=", 1) for word in words[1:])
        if kind == "bool":
            out.append((name, "bool", 0, 1))
        elif kind == "int":
            out.append((name, "int", int(opts["min"]), int(opts["max"])))
        else:
            raise ValueError(f"field {name}: the cFS app reads only bool and int fields, not {kind}")
    return out


def layout_signature(defs: List[Tuple[str, str, int, int]]) -> str:
    """The text the C layout hashes: `name:int:min:max;` or `name:bool;` per field, in register order."""
    return "".join(f"{n}:int:{lo}:{hi};" if k == "int" else f"{n}:bool;" for n, k, lo, hi in defs)


def fnv1a32(text: str) -> int:
    h = 0x811C9DC5
    for byte in text.encode("ascii"):
        h = ((h ^ byte) * 0x01000193) & 0xFFFFFFFF
    return h


def build(core: bytes) -> Dict:
    policy = Policy(core)                       # runs the oracle's loadPolicy port; raises on a bad image
    defs = field_defs(policy.doc)
    graph = parse(policy.flow)
    start = graph.nodes[graph.start]
    labels = [target for target, _cond in start.edges]
    start.edges = [(f"rule{i}", cond) for i, (_t, cond) in enumerate(start.edges)]
    kept = {graph.start: start}                  # the target nodes of the source graph are labels here, not nodes
    for i in range(len(labels)):
        kept[f"rule{i}"] = Node(name=f"rule{i}")
    graph.nodes = kept
    image = ppt_compile.TableImage()
    for slot, (name, _k, _lo, _hi) in enumerate(defs):
        image.fields[name] = slot
    names = list(graph.nodes)
    idx = {name: i for i, name in enumerate(names)}
    for name in names:
        edges = [(idx[t], cond, image.compile_condition(cond)) for t, cond in graph.nodes[name].edges]
        image.nodes.append((name, edges))
    image.start = idx[graph.start]
    if list(image.fields) != [d[0] for d in defs]:
        raise ValueError(f"the compiled table reads fields {list(image.fields)}, not the policy's {[d[0] for d in defs]}")
    if len(image.intern) != 1:
        raise ValueError("the policy interns strings; the cFS reading has bool and int fields only")
    blob = image.serialize()
    rules = []
    for label in labels:
        kind, _cause, code = target_decision(label)
        rules.append((KIND[kind], code or 0))
    if len(blob) > IMAGE_MAX or len(rules) > RULES_MAX:
        raise ValueError(f"the image ({len(blob)} bytes, {len(rules)} rules) is over the table's {IMAGE_MAX} and {RULES_MAX}")
    flow_json = canon2.dumps(policy.flow)
    if len(policy.image) > CORE_MAX or len(flow_json) > FLOW_MAX:
        raise ValueError(f"the core image ({len(policy.image)} bytes) or its flow ({len(flow_json)}) is over the table's "
                         f"{CORE_MAX} and {FLOW_MAX}")
    return {
        "image": blob, "rules": rules, "defs": defs, "version": VERSION, "core": policy.image, "flow_json": flow_json,
        "layout_hash": fnv1a32(layout_signature(defs)),
        "contract_cause": causes.code("route:contract-violation"),
        "nomatch_cause": causes.code("route:no-matching-edge"),
    }


def _c_bytes(data: bytes) -> str:
    rows = [", ".join(f"0x{b:02X}" for b in data[i:i + 12]) for i in range(0, len(data), 12)]
    return "{" + ", \\\n     ".join(rows) + "}"


def render_inc(built: Dict) -> str:
    rows = [", ".join(f"0x{b:02X}" for b in built["image"][i:i + 12]) for i in range(0, len(built["image"]), 12)]
    rules = ", ".join(f"{{{kind}, 0, {cause}}}" for kind, cause in built["rules"])
    return (
        "/* SPDX-License-Identifier: Apache-2.0 */\n"
        "/* Generated by policy/gen_image.py from policy/example.core.json. Do not edit; rerun the generator. */\n"
        f"#define PRISMPATH_APP_EXAMPLE_LAYOUT_HASH     0x{built['layout_hash']:08X}u\n"
        f"#define PRISMPATH_APP_EXAMPLE_CONTRACT_CAUSE  {built['contract_cause']}\n"
        f"#define PRISMPATH_APP_EXAMPLE_NOMATCH_CAUSE   {built['nomatch_cause']}\n"
        f"#define PRISMPATH_APP_EXAMPLE_IMAGE_LEN       {len(built['image'])}\n"
        f"#define PRISMPATH_APP_EXAMPLE_RULE_COUNT      {len(built['rules'])}\n"
        f"#define PRISMPATH_APP_EXAMPLE_RULES           {{{rules}}}\n"
        "#define PRISMPATH_APP_EXAMPLE_IMAGE \\\n    {" + ", \\\n     ".join(rows) + "}\n"
        f"#define PRISMPATH_APP_EXAMPLE_VERSION         {built['version']}u\n"
        f"#define PRISMPATH_APP_EXAMPLE_CORE_LEN        {len(built['core'])}\n"
        f"#define PRISMPATH_APP_EXAMPLE_FLOW_JSON_LEN   {len(built['flow_json'])}\n"
        "/* the signed core image, canon/2 */\n"
        "#define PRISMPATH_APP_EXAMPLE_CORE \\\n    " + _c_bytes(built["core"]) + "\n"
        "/* its canonical flow rendering, spelled as a canon/2 string */\n"
        "#define PRISMPATH_APP_EXAMPLE_FLOW_JSON \\\n    " + _c_bytes(built["flow_json"]) + "\n"
    )


def main(argv: List[str]) -> int:
    core = CORE.read_bytes()
    if core.endswith(b"\n"):
        core = core[:-1]
    text = render_inc(build(core))
    if "--check" in argv:
        if not INC.exists() or INC.read_text() != text:
            print(f"{INC} is out of date; run gen_image.py", file=sys.stderr)
            return 1
        return 0
    INC.write_text(text)
    print(f"wrote {INC}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
