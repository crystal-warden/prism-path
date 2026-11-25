# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Write conformance/install_larger.json, the IS12 rule of what makes an install set larger, as one table.

The rule lived three times, in `install.set_larger` and `install.widens_ok`, in the Rust crate's `install.rs` and
inline in the C core's `pp_apply_set`, and only Python's was unit tested. This table is the one statement of it that
all three replay (spec-policy-distribution.md IS10, IS12, AF8, OP4, CL3). Each row is what a PEP holds of one install
kind before (`none`, the set `held`, the set `lost` because no copy of it reads, or `withdrawn` by the empty set),
the set it is then sent (`new`, or `empty`), the signer's `widens` and `replaces`, and what the PEP answers: the event
of its state record and the cause.

A row names its sets abstractly so every implementation can build them for its own kind. `T1` to `T3` are three
release tables a ceiling lists, `F1` and `F2` two narrow action floor tables, each harness giving its own bytes for
them; a floor carries `rate` and `answer_rate` as `[allows, window]` or null. `replaces` is `held` for the policy hash
of the set the row held (the one the install record names, also when that set is lost or was withdrawn), `""` for
none and `other` for the hash of a set the PEP never held. The PEP has install keys at a threshold of 2 and holds no
other install set and no release. A held set was applied at `seq` 1, a withdrawal at 2, and `new` comes at the next.

Python replays every row on `host` and on `mesh` (prismpath/tests/test_distribution_larger.py), Rust on `host`
(prismpath-hotswap-rs/tests/test_distribution_larger.rs) and the C core on `mesh` (prismpath/tests/test_distribution_c.py).
`cfs` takes the signer's word beyond the `replaces` test (H13) and is not in the table.

The rows are written here by hand from the spec, so the table is the authority and not any implementation's output.

    python prismpath/portable/gen_install_larger_fixtures.py
"""
from __future__ import annotations

import json
from pathlib import Path

OUT = Path(__file__).resolve().parent / "conformance" / "install_larger.json"
APPLIED, WIDENED, REFUSED = "install-applied", "install-widened", "refused"
UNSIGNED, STANDS_OUT = "dist:widening-unsigned", "dist:install-widened"
KINDS = ["host", "mesh"]


def _floor(table="F1", rate=(5, 60), answer_rate=(5, 60)) -> dict:
    return {"table": table, "rate": list(rate) if rate else None, "answer_rate": list(answer_rate) if answer_rate else None}


def _list(*tables) -> dict:
    return {"list": list(tables)}


HELD_LIST = _list("T1", "T2")
HELD_FLOOR = _floor()

# (name, set, before, new, widens, replaces, event); the cause follows from the event and `widens`
ROWS = [
    # IS12: a first ceiling does not widen, and the empty one with none held removes nothing
    ("ceiling_first", "ceiling", "none", _list("T1"), False, "", APPLIED),
    ("ceiling_first_replacing_another", "ceiling", "none", _list("T1"), False, "other", REFUSED),
    ("ceiling_first_said_to_widen", "ceiling", "none", _list("T1"), True, "", WIDENED),
    ("ceiling_empty_with_none_held", "ceiling", "none", "empty", False, "", APPLIED),
    # IS12, CL3: a narrower ceiling is never a widening; a hash the list before did not hold is
    ("ceiling_narrower", "ceiling", "held", _list("T1"), False, "held", APPLIED),
    ("ceiling_the_same_list", "ceiling", "held", _list("T1", "T2"), False, "held", APPLIED),
    ("ceiling_wider", "ceiling", "held", _list("T1", "T2", "T3"), False, "held", REFUSED),
    ("ceiling_wider_said_to_widen", "ceiling", "held", _list("T1", "T2", "T3"), True, "held", WIDENED),
    ("ceiling_another_hash", "ceiling", "held", _list("T3"), False, "held", REFUSED),
    ("ceiling_empty_removes_the_bound", "ceiling", "held", "empty", False, "held", REFUSED),
    ("ceiling_empty_said_to_widen", "ceiling", "held", "empty", True, "held", WIDENED),
    ("ceiling_narrower_replacing_none", "ceiling", "held", _list("T1"), False, "", REFUSED),
    ("ceiling_narrower_said_to_widen", "ceiling", "held", _list("T1"), True, "held", WIDENED),
    # IS10, IS12: after a lost ceiling only a byte for byte resend naming the lost set's policy hash is no widening
    ("ceiling_lost_resent", "ceiling", "lost", _list("T1", "T2"), False, "held", APPLIED),
    ("ceiling_lost_resent_replacing_none", "ceiling", "lost", _list("T1", "T2"), False, "", REFUSED),
    ("ceiling_lost_resent_replacing_another", "ceiling", "lost", _list("T1", "T2"), False, "other", REFUSED),
    ("ceiling_lost_then_narrower", "ceiling", "lost", _list("T1"), False, "held", REFUSED),
    ("ceiling_lost_then_narrower_replacing_none", "ceiling", "lost", _list("T1"), False, "", REFUSED),
    ("ceiling_lost_then_wider", "ceiling", "lost", _list("T1", "T2", "T3"), False, "held", REFUSED),
    ("ceiling_lost_then_empty", "ceiling", "lost", "empty", False, "held", REFUSED),
    ("ceiling_lost_then_empty_replacing_none", "ceiling", "lost", "empty", False, "", REFUSED),
    ("ceiling_lost_then_empty_said_to_widen", "ceiling", "lost", "empty", True, "", WIDENED),
    ("ceiling_lost_then_narrower_said_to_widen", "ceiling", "lost", _list("T1"), True, "", WIDENED),
    ("ceiling_lost_resent_said_to_widen", "ceiling", "lost", _list("T1", "T2"), True, "held", WIDENED),
    # IS6: a kind the empty set withdrew holds none, so the set after it names the empty string
    ("ceiling_withdrawn_then_first", "ceiling", "withdrawn", _list("T1"), False, "", APPLIED),
    ("ceiling_withdrawn_then_replacing_the_withdrawn", "ceiling", "withdrawn", _list("T1"), False, "held", REFUSED),
    ("ceiling_withdrawn_then_said_to_widen", "ceiling", "withdrawn", _list("T1"), True, "", WIDENED),
    # IS12: a first action floor widens, the empty one does not; a table not byte for byte the held one is larger
    ("floor_first", "floor", "none", _floor(), False, "", REFUSED),
    ("floor_first_said_to_widen", "floor", "none", _floor(), True, "", WIDENED),
    ("floor_the_same", "floor", "held", _floor(), False, "held", APPLIED),
    ("floor_the_same_replacing_none", "floor", "held", _floor(), False, "", REFUSED),
    ("floor_another_table", "floor", "held", _floor("F2"), False, "held", REFUSED),
    ("floor_another_table_said_to_widen", "floor", "held", _floor("F2"), True, "held", WIDENED),
    ("floor_empty", "floor", "held", "empty", False, "held", APPLIED),
    # AF8, IS12: a looser rate, one with a shorter window, or one removed widens; a tighter one does not
    ("floor_rate_allows_more", "floor", "held", _floor(rate=(9, 60)), False, "held", REFUSED),
    ("floor_rate_shorter_window", "floor", "held", _floor(rate=(5, 30)), False, "held", REFUSED),
    ("floor_rate_removed", "floor", "held", _floor(rate=None), False, "held", REFUSED),
    ("floor_rate_tighter", "floor", "held", _floor(rate=(3, 60)), False, "held", APPLIED),
    # OP4, IS12, the owner's ruling: only changes that allow more count as larger, and a looser answer_rate does
    ("floor_answer_rate_allows_more", "floor", "held", _floor(answer_rate=(9, 60)), False, "held", REFUSED),
    ("floor_answer_rate_shorter_window", "floor", "held", _floor(answer_rate=(5, 30)), False, "held", REFUSED),
    ("floor_answer_rate_removed", "floor", "held", _floor(answer_rate=None), False, "held", REFUSED),
    ("floor_answer_rate_tighter", "floor", "held", _floor(answer_rate=(3, 60)), False, "held", APPLIED),
    ("floor_answer_rate_looser_said_to_widen", "floor", "held", _floor(answer_rate=(9, 60)), True, "held", WIDENED),
    # IS6, IS10: after the empty floor, and after a lost floor, the PEP decides as one that never had it
    ("floor_withdrawn_then_first", "floor", "withdrawn", _floor(), False, "", REFUSED),
    ("floor_withdrawn_then_said_to_widen", "floor", "withdrawn", _floor(), True, "", WIDENED),
    ("floor_lost_then_the_same", "floor", "lost", _floor(), False, "held", REFUSED),
    ("floor_lost_then_said_to_widen", "floor", "lost", _floor(), True, "held", WIDENED),
]


def rows() -> list:
    out = []
    for name, kind, before, new, widens, replaces, event in ROWS:
        cause = UNSIGNED if event == REFUSED else STANDS_OUT if event == WIDENED else None
        out.append({"name": name, "set": kind, "before": before,
                    "held": None if before == "none" else (HELD_LIST if kind == "ceiling" else HELD_FLOOR),
                    "new": new, "widens": widens, "replaces": replaces, "kinds": KINDS,
                    "expect": {"event": event, "cause": cause}})
    return out


def corpus() -> dict:
    return {"format": "prismpath.install-larger-corpus/1", "spec": "docs/design/spec-policy-distribution.md",
            "rules": ["IS6", "IS10", "IS12", "AF8", "OP4", "CL3"],
            "note": "IS12 as a table. Each row is what the PEP holds before, the set it is sent, the signer's widens "
                    "and replaces, and the event and cause of the PEP's answer. Every implementation replays every "
                    "row on each kind of `kinds` it has.",
            "rows": rows()}


def main() -> int:
    OUT.write_text(json.dumps(corpus(), indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {OUT} ({len(ROWS)} rows)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
