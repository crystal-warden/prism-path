# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""State across calls: what this session already did, as two finite reading fields.

Every other field of a reading is read off one call. A policy that defines `session_protected_changes` or
`session_shell_runs` opts in to the session's own history, and the decider adds both fields to the reading before the
core decides it, so the core stays a pure function of (policy, reading) and the Lean model, the oracle and the
differential see a reading like any other.

  session_protected_changes   none | some    `some` once a receipt of this session is a change whose `zone_reach` was
                                             not `none` and was not refused (it was allowed, or asked about)
  session_shell_runs          none | few | many   the receipts of this session that were not refused and read as a
                                             `run_command`, banded: none for 0, few below `SHELL_MANY`, many from it

Where the state comes from. Only the session's journal (prismpath/agent/run.py), the receipts the decider itself
appended, each checked line by line against its reading and the policy image when it is read. Nothing the agent can
write is read: an outcome (which a hook event or the runner reports, so a claim) is never an input, and a call that
was asked about and declined counts like one that ran, which is the safe direction since a count only ever restricts.

Fail safe. A journal that cannot be read in full (a line that does not verify, a journal missing where the run's
other files show there was one, a run directory with no image, a torn tail, which means a call may have run with no
receipt, any error) reads as the most restrictive value of each
field, `RESTRICTIVE`, never as the permissive one. A session with no run directory at all has not begun and reads
`FRESH`. A policy that defines neither field gets neither; a reading that is decided for a policy that defines one
without the field being supplied is given `RESTRICTIVE` (`Policy.reading_bytes`).

The two rules that read these fields are in the `session` starter (`policy/agent_session.rules.md`). Every rule
that reads them only adds a question (an escalation), after every refusal, so a state can only make a decision more
restrictive (formal/Classifier/Session.lean: `session_restricts`, checked per image by the oracle's `--session` mode).
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

CHANGES = "session_protected_changes"
SHELL = "session_shell_runs"
FIELDS = (CHANGES, SHELL)
CHANGES_VALUES = ("none", "some")
SHELL_VALUES = ("none", "few", "many")
VALUES = {CHANGES: CHANGES_VALUES, SHELL: SHELL_VALUES}
SHELL_MANY = 20                       # the shell runs of a session from which `session_shell_runs` reads `many`
FRESH = {CHANGES: "none", SHELL: "none"}
RESTRICTIVE = {CHANGES: "some", SHELL: "many"}
CHANGING_TOOLS = ("write_file", "delete_path")


def defined_by(fields: Iterable[str]) -> bool:
    """True when a policy's field names include either session field: the policy opts in."""
    names = set(fields)
    return any(name in names for name in FIELDS)


def band(shell_runs: int) -> str:
    return "none" if shell_runs <= 0 else ("few" if shell_runs < SHELL_MANY else "many")


def _is_change(reading: Mapping[str, Any]) -> bool:
    return reading.get("tool") in CHANGING_TOOLS or reading.get("command_class") == "mutating"


def derive(entries: List[Dict[str, Any]]) -> Dict[str, str]:
    """The two fields from the journal lines of one session (as `Run.snapshot` returns them), a pure function of them.
    A line is counted unless its receipt is a refusal. A change whose `zone_reach` is missing or anything but `none`
    makes the first field `some`; a `run_command` adds one to the second."""
    from prismpath.agent import run as run_module
    from prismpath.kernel import canon2
    protected, shell = False, 0
    for entry in entries:
        if run_module.receipt_kind(entry["receipt"]) == "refuse":
            continue
        reading = canon2.loads(bytes.fromhex(entry["reading"]))
        if not isinstance(reading, dict):
            raise ValueError("a journal reading is not an object")
        if _is_change(reading) and reading.get("zone_reach") != "none":
            protected = True
        if reading.get("tool") == "run_command":
            shell += 1
    return {CHANGES: "some" if protected else "none", SHELL: band(shell)}


def read(store, session: str) -> Tuple[Dict[str, str], Optional[int]]:
    """(the fields, the number of receipts they were read from) for `session` in `store`. The number is what a caller
    passes to `Run.append(expect=...)`, so a receipt appended between the read and the append (a parallel tool call) is
    noticed; it is None when the state could not be read, and then the fields are `RESTRICTIVE`."""
    from prismpath.agent import run as run_module
    try:
        if not (store.root / run_module.run_dir_name(session)).exists():
            return dict(FRESH), 0
        run = store.get(session)
        count, entries = run.snapshot()
        if (run.dir / run_module.TORN).exists():
            # a writer was killed inside an append: its call may have run with no receipt, so the history is incomplete
            return dict(RESTRICTIVE), None
        return derive(entries), count
    except Exception:       # noqa: BLE001 - whatever cannot be read reads as the most restrictive value
        return dict(RESTRICTIVE), None
