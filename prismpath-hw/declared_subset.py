#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The declared hardware subset of the predicate corpus: defined once, frozen, and gated.

A case of `prismpath/portable/conformance/predicates.json` is in the subset when its condition compiles to
a PPT table and every field the condition reads encodes into a table register. The table targets (the C
interpreters here, the eBPF evaluator, the firmware copies) certify exactly that subset, and a published
"N of N" is only as good as N. Until October 2026 the count lived as a constant two runners compared
against with a warning, so a subset that shrank would have certified less and still reported every
vector passing; an eBPF count once fell to 66 that way before anyone looked.

`declared_subset.json` beside this file freezes the selection as content IDs, a hash of each case's
condition and context, so adding cases to the corpus does not move them. Both certification runners
(`run_vectors.py`, `prismpath-ebpf/cert_corpus.py`) refuse to report when their selection differs from
it, and `prismpath/tests/test_conformance_drift.py` checks the same in every CI run. A subset that shrank
is a failure to explain; one that grew is a reviewed change, made by freezing again:

    python declared_subset.py            # check the selection against the manifest, exit 1 on drift
    python declared_subset.py --write    # freeze the current selection (review the diff as a spec change)
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

HERE = Path(__file__).resolve().parent
CORPUS = HERE.parent / "prismpath" / "portable" / "conformance" / "predicates.json"
MANIFEST = HERE / "declared_subset.json"

sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))
import ppt_compile as pc                                   # noqa: E402


def case_id(case: dict) -> str:
    """A case's identity by content: the condition and context, independent of its position."""
    canonical = json.dumps({"cond": case["cond"], "ctx": case["ctx"]}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def exclusion_reason(case: dict) -> Optional[str]:
    """None when the case is in the subset, else the compiler's reason it is not. Any error other than
    a subset refusal propagates, because a selection that hides an exception would undercount."""
    try:
        image = pc.compile_predicate(case["cond"])
        pc.encode_regs(image, case["ctx"], node_idx=0)
    except pc.SubsetError as error:
        return error.reason
    return None


def selected_ids(cases: Iterable[dict]) -> List[str]:
    return sorted(case_id(case) for case in cases if exclusion_reason(case) is None)


def corpus_cases() -> List[dict]:
    return json.loads(CORPUS.read_text())["cases"]


def frozen() -> Dict:
    return json.loads(MANIFEST.read_text())


def drift(kept_ids: Iterable[str]) -> Tuple[List[str], List[str]]:
    """(ids the manifest declares that the selection lost, ids the selection has that it does not)."""
    kept, declared = set(kept_ids), set(frozen()["case_ids"])
    return sorted(declared - kept), sorted(kept - declared)


def require_frozen(kept_ids: Iterable[str], runner: str) -> None:
    """Raise unless a runner's selection is exactly the frozen subset, naming what moved."""
    shrank, grew = drift(kept_ids)
    if shrank:
        raise SystemExit(f"{runner}: the declared hardware subset SHRANK by {len(shrank)} case(s) {shrank[:5]}; "
                         f"a certification over fewer cases would still report every one passing. "
                         f"Find what excluded them before anything else.")
    if grew:
        raise SystemExit(f"{runner}: the declared hardware subset grew by {len(grew)} case(s) {grew[:5]}; "
                         f"freeze it with `python prismpath-hw/declared_subset.py --write`, review the diff, "
                         f"and recertify the targets on the larger subset.")


def write() -> Dict:
    cases = corpus_cases()
    ids = selected_ids(cases)
    manifest = {
        "comment": "FROZEN. The declared hardware subset of the predicate corpus, as content IDs "
                   "(declared_subset.case_id). Certification runners refuse to report on any other "
                   "selection. Regenerate with `declared_subset.py --write` and review as a spec change.",
        "corpus": "prismpath/portable/conformance/predicates.json",
        "corpus_cases": len(cases),
        "count": len(ids),
        "history": [
            {"count": 124, "corpus_cases": 1079, "note": "corpus v2 with signed integer literals, August 2026"},
            {"count": 147, "corpus_cases": 1112, "note": "October 2026: numeric strings and absence under "
                                                          "membership, negation and inequality join the subset"},
        ],
        "case_ids": ids,
    }
    MANIFEST.write_text(json.dumps(manifest, indent=1) + "\n")
    return manifest


def main(argv: List[str]) -> int:
    if argv == ["--write"]:
        manifest = write()
        print(f"froze {manifest['count']} of {manifest['corpus_cases']} cases into {MANIFEST}")
        return 0
    try:
        require_frozen(selected_ids(corpus_cases()), "declared_subset")
    except SystemExit as failure:
        print(failure)
        return 1
    print(f"declared hardware subset: {frozen()['count']} cases, unchanged")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
