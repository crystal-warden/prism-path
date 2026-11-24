# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The seven checks of the mesh as a policy distribution target (the plan's PR 17), written once over a fleet of
nodes, so the same checks run on the simulated mesh of `host/sim_fleet.py` now and on the boards through `board_run.py`
in the board validation pass.

A fleet is anything with these members, each answering the state records every node signed meanwhile, by node
id, read under that node's own instance key:

    ids                      the node ids, a board's MAC or a simulated node's name
    hold(node_id)            the node's build setting, 1 for HOLD (X6)
    deliver(sealed, body)    one sealed envelope and its body, as offer and chunk frames on the radio (B6)
    control(frame)           one commit, abort or epoch frame on the radio
    wait(seconds)            time passes and every node ticks (X1, B8)
    reset()                  every node's RAM is lost and it boots again from its store
    forget()                 every node forgets its store and its instance key and provisions from its anchor
    rebuild(node_id, variant)  one node is built again with `variant` and forgets its store
    ask(regs)                one decision on every node: {node id: (outcome, cause, basis, held mark)}
    time()                   the latest time a node reported

`run_checks` answers {check: {"passed": bool, "boards": {node id: bool}, "detail": {node id: text}}}."""
from __future__ import annotations

from typing import Callable, Dict, List

from prismpath import canon
from prismpath.distribution import frames

FLIP_DELAY_MS = 120                                # B8: commit at each node's own time plus this
ALLOW, REFUSE = 1, 2                               # pp_decision outcomes
BASIS_RELEASE = 1


def _last(records, *events):
    found = [record for record in records if record.event in events]
    return found[-1] if found else None


def _describe(records) -> str:
    return ", ".join(f"{record.event}{'/' + record.cause if record.cause else ''}" for record in records) or "nothing"


def _result(per_node: Dict[str, bool], detail: Dict[str, str]) -> dict:
    return {"passed": all(per_node.values()) and bool(per_node), "boards": per_node, "detail": detail}


def _join(*answers: Dict[str, list]) -> Dict[str, list]:
    out: Dict[str, list] = {}
    for answer in answers:
        for node_id, records in answer.items():
            out.setdefault(node_id, []).extend(records)
    return out


def deliver_all(fleet, pairs) -> Dict[str, list]:
    """Every (sealed, body) of `pairs` in turn."""
    return _join(*(fleet.deliver(sealed, body) for sealed, body in pairs))


def commit(fleet, stream: str, seq: int, policy: str, transfer: int = 0) -> Dict[str, list]:
    """A commit with the group's delay (B8), and the time it takes to flip."""
    sent = fleet.control(frames.encode(frames.commit_for(transfer, stream, seq, policy, FLIP_DELAY_MS)))
    return _join(sent, fleet.wait(2 * FLIP_DELAY_MS / 1000))


def run_checks(fleet, signer, after_flash: Dict[str, list] = None) -> dict:
    """The checks, in the order the boards run them. `signer` is a gen_mesh_tables.Signer for the fleet's anchor.
    The test input is one policy A allows and policy B refuses. `after_flash` is what each node signed when it
    first started, or None to have every node forget its store and start again."""
    import gen_mesh_tables as tables
    regs = tables.regs(**tables.TEST_INPUT)
    allowed = tables.regs(**{**tables.TEST_INPUT, "level": 150})      # B allows it too
    table_a, table_b = tables.tables()
    h_a, h_b = canon.sha256_hex(table_a), canon.sha256_hex(table_b)
    stream = signer.stream
    out = {}

    def check(name: str, expect: Callable[[str, list], bool], answers: Dict[str, list], extra=None):
        per = {node_id: bool(expect(node_id, records)) for node_id, records in answers.items()}
        detail = {node_id: _describe(records) + (f"; {extra[node_id]}" if extra else "") for node_id, records in answers.items()}
        out[name] = _result(per, detail)

    # 1. every node runs the one build and provisions from its anchor with an instance key of its own
    started = after_flash if after_flash is not None else fleet.forget()
    keys = {node_id: records[0].pep_id if records else None for node_id, records in started.items()}
    check("flashed", lambda node_id, records: _last(records, "provisioned") is not None
          and list(keys.values()).count(keys[node_id]) == 1, started)

    # 2. the signed release for B is staged on every node and committed, and every node flips and reports B's hash
    deliver_all(fleet, signer.release_with_statement(table_a, 1))
    commit(fleet, stream, 1, h_a)
    before = fleet.ask(regs)
    staged = deliver_all(fleet, signer.release_with_statement(table_b, 2, replaces=h_a))
    committed = commit(fleet, stream, 2, h_b)
    after = fleet.ask(regs)
    flipped = {node_id: f"A answered {before[node_id][0]}, B answers {after[node_id][0]}" for node_id in fleet.ids}
    check("release_b_committed", lambda node_id, records: _last(records, "staged") is not None
          and _last(records, "committed") is not None
          and _last(records, "committed").active_policy == bytes.fromhex(h_b)[:16]
          and before[node_id][:3] == (ALLOW, 0, BASIS_RELEASE) and after[node_id][0] == REFUSE
          and after[node_id][2] == BASIS_RELEASE, _join(staged, committed), flipped)

    # 3. a release with a bad signature is refused with sig:invalid
    sealed = bytearray(signer.release(table_a, 3, replaces=h_b))
    sealed[6 + 32] ^= 0xFF                         # the first byte of the one signature
    check("bad_signature_refused", lambda node_id, records: any(
        record.event == "refused" and record.cause == "sig:invalid" for record in records),
        fleet.deliver(bytes(sealed), table_a))

    # 4. a replay of A's release is refused with dist:seq-replay, and again after a reset, the floor held in NVS
    replay = signer.release(table_a, 1, widens=True)
    first = fleet.deliver(replay, table_a)
    restarted = fleet.reset()
    second = fleet.deliver(replay, table_a)
    check("replay_refused_across_a_reset", lambda node_id, records: [
        record.cause for record in records if record.event == "refused"].count("dist:seq-replay") == 2
        and all(record.floor == 2 and record.active_policy == bytes.fromhex(h_b)[:16]
                for record in records if record.event != "provisioned"),
        _join(first, restarted, second))

    # 5. A after B with no widening statement: on mesh every changed table is larger (W2)
    unsigned = fleet.deliver(signer.release(table_a, 3, replaces=h_b), table_a)
    claimed = fleet.deliver(signer.release(table_a, 3, replaces=h_b, widens=True), table_a)
    check("widening_refused", lambda node_id, records: [record.cause for record in records if record.event == "refused"]
          == ["dist:widening-unsigned"] * 2, _join(unsigned, claimed))

    # 7 and 6. expiry refused on every default node and held on one built with HOLD, then a revocation
    hold_id = fleet.ids[-1]
    fleet.rebuild(hold_id, "hold")
    fleet.forget()
    deliver_all(fleet, signer.release_with_statement(table_a, 1))
    commit(fleet, stream, 1, h_a)
    now = fleet.time()
    expiring = signer.release_with_statement(table_b, 2, replaces=h_a, not_before=now, expires=now + 25)
    deliver_all(fleet, expiring)
    commit(fleet, stream, 2, h_b)
    lapses = fleet.wait(32)
    held_answer, held_allow = fleet.ask(regs), fleet.ask(allowed)
    expired = signer.release(table_a, 3, replaces=h_b, widens=True, not_before=now - 100, expires=now - 50)
    refused = fleet.deliver(expired, table_a)
    defaults = {node_id: lapses[node_id] + refused[node_id] for node_id in fleet.ids if node_id != hold_id}
    check("expiry_refused_by_default", lambda node_id, records: fleet.hold(node_id) == 0
          and _last(records, "lapsed") is not None and _last(records, "lapsed").cause == "dist:expired"
          and any(record.cause == "dist:expired" for record in records if record.event == "refused"), defaults)
    held = lapses[hold_id] + refused[hold_id]
    mark = _last(held, "held")
    out["hold_keeps_deciding"] = _result(
        {hold_id: fleet.hold(hold_id) == 1 and mark is not None and mark.cause == "dist:held"
         and all(record.held for record in held[held.index(mark):])
         and held_answer[hold_id][0] == REFUSE and held_answer[hold_id][2] == BASIS_RELEASE and held_answer[hold_id][3] == 1
         and held_allow[hold_id] == (ALLOW, 0, BASIS_RELEASE, 1)},
        {hold_id: _describe(held) + f"; under B it answers {held_answer[hold_id]} and {held_allow[hold_id]}"})

    revocation, body = signer.revocation(1, policies=[h_b])
    applied = fleet.deliver(revocation, body)
    again = fleet.deliver(signer.release(table_b, 3, replaces="", widens=True, not_before=now, expires=now + 30 * 86400),
                          table_b)
    check("revocation_applied_then_refused", lambda node_id, records: _last(records, "trust-applied") is not None
          and _last(records, "trust-applied").trust_seq == 1
          and any(record.cause == "dist:revoked" for record in records if record.event == "refused"),
          _join(applied, again))
    dropped = applied[hold_id]
    out["hold_dropped_on_revocation"] = _result(
        {hold_id: any(record.event == "lapsed" and record.cause == "dist:revoked" for record in dropped)
         and _last(dropped, "trust-applied") is not None and _last(dropped, "trust-applied").state == "no-policy"
         and not _last(dropped, "trust-applied").held},
        {hold_id: _describe(dropped)})
    return out


SEVEN = {1: "flashed", 2: "release_b_committed", 3: "bad_signature_refused", 4: "replay_refused_across_a_reset",
         5: "widening_refused", 6: "revocation_applied_then_refused",
         7: ("expiry_refused_by_default", "hold_keeps_deciding", "hold_dropped_on_revocation")}
CHECKS: List[str] = [name for names in SEVEN.values() for name in ((names,) if isinstance(names, str) else names)]
