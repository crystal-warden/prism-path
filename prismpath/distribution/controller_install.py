# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The controller's side of section 21 of spec-policy-distribution.md: the install statements it stores and offers
(IS8), what it expects of each PEP's install record (H11, H12) and the acknowledgement of a widening (H13).

`InstallDesk` is a part of `prismpath.distribution.controller.Controller` and reads its state. The controller holds no
install private key. It holds the install public keys of each stream it serves, from the anchor's install part and
every `install.trust` it stored since, runs the verifier of IS5 on every install statement it is handed, and refuses
to store one that fails. A whole set is then held to the ceiling the controller offers (CL3) and compared with the
set it follows (IS12, W7): a set the controller computes as larger whose `widens` is false is refused, on `host` and
`mesh` by its bytes and on `cfs` by the core image inside its table.

H13 is detection and not prevention. A set whose `widens` is true, the empty ceiling that withdraws the held one, and
an `install.trust` that adds a key of either role or lowers the threshold are held with `dist:install-widened` open,
offered to nobody, and their install id is expected of no PEP until an acknowledger acknowledges them by the envelope
ids of their statements. A widening is only a set that extends or enlarges scope: a ceiling that narrows below the
release the controller expects of a PEP is offered at once, and the fleet view names the PEPs it lapses. On `host`
and `mesh` an action floor's or a fallback policy's table is compared by W8 (`table_compare`), and a set carried by
an install change statement W8 bears out is offered at once, the statement before it (IS15). The acknowledger is a
person the controller lets do this by its own login. It holds no key and signs nothing, and no PEP reads what it
does: a PEP applies a well signed widening set from any sender, a hostile controller included, so what H13 gives is
that a widening cannot spread from this controller unseen, nor stay unseen when it reaches a PEP another way.

The state it adds to `controller.json`, under `install`:

    sets       every install set stored, by `<stream>/<kind>/<seq>/<release id>`: its statements by `as`, the install
               change statement before it, whether it is whole, its state, `partial`, `held` (waiting for its
               acknowledgement) or `offered`, and its scope, `widening` or `change, not larger`, with W8's answer
    trust      per stream, the `install.trust` statements stored, in install trust order, each `held` or `offered`
    findings   the open `dist:install-widened` of each held set or statement, by its key
    pending    `provisioned` records from PEPs not yet enrolled, at most 8 per PEP id and 64 PEP ids (H13, H6)
    pacing     per set id, the rollout option of a ceiling staged to a canary group (CL7): the group, the stage,
               `canary`, `all` or `stopped`, the canary members that applied it and reported after, and why it stopped

A ceiling is offered at once, which keeps it an emergency brake. A ceiling the engineer sealed with `--staged` is
offered to the members of its canary group first and to the rest of the stream only once every canary member
reported it applied and then a record after that, with no lapse the controller did not expect (CL7). The option is
unsigned and kept by the controller alone: it paces and never authorizes, as a controller may always withhold a set.
`ceiling_preview` gives the sealing tool, which reads this state with `Controller.reader`, the releases a new ceiling
would lapse and how many PEPs run each, and whether a release inside it is offered or stored for them (CL5, CL6).

Per PEP (`Member.install`) it keeps the install record it expects: the set id and `seq` of each set kind, the install
trust sequence and the install trust id. The expected install id is computed from them (H10), the enrolled one and
then the one its latest offered statements give (H12).
"""
from __future__ import annotations

import os
from dataclasses import replace
from typing import Dict, List, Optional, Sequence, Tuple

from prismpath.distribution import envelope as env
from prismpath.distribution import install, kinds, state_record, table_compare, widening
from prismpath.distribution.kinds import Refused
from prismpath.distribution.trust import read_anchor
from prismpath.distribution.verify import InstallView, PepView, verify

WIDENED, FALLBACK_FINDING = install.WIDENED, "dist:fallback"
PARTIAL_SET, HELD_SET, OFFERED_SET = "partial", "held", "offered"
# F4: what a set does to the scope a PEP allows, as the controller computes it, the words a rollout uses (W9)
WIDENING, CHANGE_NOT_LARGER = "widening", "change, not larger"
MAX_PENDING_PER_PEP = 8                            # the provisioned records kept for one PEP id not yet enrolled
MAX_PENDING_PEPS = 64                              # and the PEP ids kept, the oldest dropped first
# CL7: the stages of a ceiling the engineer sealed with `--staged`, offered to a canary group first
CANARY_STAGE, ALL_STAGE, STOPPED_STAGE = "canary", "all", "stopped"
ROLLOUT_FORMAT = "prismpath.dist-install-rollout/1"
ROLLOUT_FILE = "install.ceiling.rollout.json"     # the unsigned rollout option the tool writes beside the set


def set_key(stream: str, kind: str, seq: int, release: str) -> str:
    return f"{stream}/{kind}/{seq}/{release}"


def expected_set(info: dict) -> list:
    """The entry of an expected install record for the stored set `info`: [set id, seq], and "none" after them for the
    empty set, which withdraws its kind so the PEP holds nothing of it (IS6)."""
    return [info["set_id"], info["seq"]] + (["none"] if set(info["statements"]) == {kinds.NONE} else [])


def install_id_of(comps: dict) -> bytes:
    """H10: the install id of the expected install record `comps`, zeros for a kind held of nothing or withdrawn."""
    sets = {}
    for kind in install.SET_KINDS:
        one = comps["sets"].get(kind)
        withdrawn = one is not None and len(one) > 2 and one[2] == kinds.NONE
        sets[kind] = None if one is None or withdrawn else install.HeldSet(kind, one[1], one[0], "", "", "", False, {})
    record = install.Record(keys={}, threshold=1, trust_seq=comps["trust_seq"], trust_id=comps["trust_id"], sets=sets)
    return record.install_id()


class InstallDesk:
    """IS8, H11 to H13 on the controller. Mixed into `Controller`, whose `stored`, `anchors`, `members`, `chain`,
    `blob`, `sealed`, `_anchor_store`, `_file`, `_clear` and `_log` it uses."""

    # ------------------------------------------------------------------ state
    def _load_install(self, doc: Optional[dict]) -> None:
        doc = doc or {}
        self.install_sets: Dict[str, dict] = dict(doc.get("sets", {}))
        self.install_trust: Dict[str, List[dict]] = {stream: list(items) for stream, items in doc.get("trust", {}).items()}
        self.install_findings: Dict[str, str] = dict(doc.get("findings", {}))
        self.pending: Dict[str, List[str]] = {pep: list(records) for pep, records in doc.get("pending", {}).items()}
        self.pending_order: List[str] = list(doc.get("pending_order", []))
        self.install_pacing: Dict[str, dict] = {one: dict(pacing) for one, pacing in doc.get("pacing", {}).items()}

    def _install_doc(self) -> dict:
        return {"sets": self.install_sets, "trust": self.install_trust, "findings": self.install_findings,
                "pending": self.pending, "pending_order": self.pending_order, "pacing": self.install_pacing}

    # ------------------------------------------------------------------ the install keys of a stream
    def _install_anchor(self, stream: str, kind: Optional[str] = None):
        """(fingerprint, anchor) of the anchor with an install part that serves `stream` (and `kind`), or None."""
        for fingerprint, info in sorted(self.anchors.items()):
            if info["stream"] != stream or (kind is not None and info["target"] != kind):
                continue
            with open(os.path.join(self.dir, "anchors", fingerprint), "rb") as handle:
                anchor = read_anchor(handle.read())
            if anchor.install is not None:
                return fingerprint, anchor
        return None

    def _trust_items(self, stream: str) -> List[dict]:
        return sorted(self.install_trust.get(stream, []), key=lambda item: item["seq"])

    def install_record(self, stream: str, kind: Optional[str] = None) -> Optional[install.Record]:
        """The install record the controller verifies `stream`'s install statements under: the anchor's install part
        after every `install.trust` stored for the stream, in order, with the latest whole set of each kind as the
        held one, so a set at or below it is `dist:seq-replay` (IS6)."""
        found = self._install_anchor(stream, kind)
        if found is None:
            return None
        fingerprint, anchor = found
        record = replace(anchor.install, trust_id=fingerprint)
        for item in self._trust_items(stream):
            envelope = env.read(env.unseal(self.sealed(item["envelope_id"]))[0])
            record = record.apply_trust(envelope, self.blob(envelope.body_sha256))
        sets, seqs = dict(record.sets), dict(record.seqs)
        for kind_name in install.SET_KINDS:
            latest = self._latest_key(stream, kind_name, states=(HELD_SET, OFFERED_SET))
            if latest is not None:
                sets[kind_name] = self.held_set(latest)
                seqs[kind_name] = self.install_sets[latest]["seq"]
        return replace(record, sets=sets, seqs=seqs)

    def install_retired(self, stream: str) -> set:
        """K4: every install and operator key id the stream's `install.trust` statements ever retired. The controller
        keeps them all, where a PEP remembers eight (IS11)."""
        found = self._install_anchor(stream)
        if found is None:
            return set()
        held = set(found[1].install.keys) | set(found[1].install.operators)
        retired = set()
        for item in self._trust_items(stream):
            doc = kinds.read_install_trust(self.blob(self.stored[item["envelope_id"]]["body_sha256"]))
            kept = {env.key_id(bytes.fromhex(one)) for one in doc["keys"] + doc["operators"]}
            retired |= held - kept
            held = kept
        return retired

    def install_key_ids(self) -> set:
        """Every install and operator key id of every stream served, held or retired (IS7)."""
        out = set()
        for info in self.anchors.values():
            record = self.install_record(info["stream"], info["target"])
            if record is not None:
                out |= set(record.ids) | self.install_retired(info["stream"])
        return out

    def retired_authority(self) -> set:
        """K4, K5: every authority key id the trust chain ever retired, which the controller keeps whole where a trust
        store remembers sixteen."""
        out = set()
        for envelope_id in self.chain:
            info = self.stored[envelope_id]
            if info["artifact"] == "trust.rotation":
                retire = kinds.read_rotation(self.blob(info["body_sha256"]))["retire"]
                if retire:
                    out.add(retire)
        for fingerprint in self.anchors:
            out |= set(self._anchor_store(fingerprint).retired)
        return out

    # ------------------------------------------------------------------ the sets
    def _set_statements(self, key: str) -> Tuple[dict, dict]:
        """({as: envelope}, {as: body}) of the set `key`."""
        envelopes, bodies = {}, {}
        for named, envelope_id in self.install_sets[key]["statements"].items():
            envelope = env.read(env.unseal(self.sealed(envelope_id))[0], reads_meta=True)
            envelopes[named], bodies[named] = envelope, self.blob(envelope.body_sha256)
        return envelopes, bodies

    def held_set(self, key: str) -> install.HeldSet:
        info = self.install_sets[key]
        envelopes, bodies = self._set_statements(key)
        statements = {named: (envelope_id, envelope_id, envelopes[named].body_sha256)
                      for named, envelope_id in info["statements"].items()}
        return install.HeldSet(info["kind"], info["seq"], env.set_id(info["statements"].values()), info["policy"],
                               info["release"], info["replaces"], info["widens"], statements, envelopes, bodies)

    def _latest_key(self, stream: str, kind: str, states=(OFFERED_SET,)) -> Optional[str]:
        keys = [key for key, info in self.install_sets.items()
                if info["stream"] == stream and info["kind"] == kind and info["state"] in states]
        return max(keys, key=lambda key: self.install_sets[key]["seq"], default=None)

    def offered_set(self, stream: str, kind: str) -> Optional[install.HeldSet]:
        """The set of `kind` the controller spreads on `stream`: the one at the highest `seq` that does not wait for an
        acknowledgement. An install set is compared with it (IS12) and held inside its ceiling (CL3)."""
        key = self._latest_key(stream, kind)
        return None if key is None else self.held_set(key)

    def _staged_view(self, stream: str, kind: str) -> Dict[str, install.Staged]:
        """The partial set of `kind` at the highest `seq`, as a PEP stages one, for V8 and V10."""
        key = self._latest_key(stream, kind, states=(PARTIAL_SET,))
        if key is None:
            return {}
        info = self.install_sets[key]
        envelopes, bodies = self._set_statements(key)
        staged = install.Staged(kind, info["seq"], info["policy"], info["release"], info["replaces"], info["widens"],
                                {named: (one, one, envelopes[named].body_sha256)
                                 for named, one in info["statements"].items()}, envelopes, bodies)
        if info.get("change"):
            staged.change = (info["change"], info["change"], self.stored[info["change"]]["body_sha256"])
            staged.change_body = self.blob(self.stored[info["change"]]["body_sha256"])
        return {kind: staged}

    def _set_by_id(self, stream: str, set_id: str) -> Optional[dict]:
        for info in self.install_sets.values():
            if info["stream"] == stream and info.get("set_id") == set_id:
                return info
        return None

    # ------------------------------------------------------------------ IS8: store
    def put_install(self, sealed: bytes, body: bytes, envelope) -> None:
        """IS8, IS5: verify an install statement for every kind and stream served whose anchor has an install part,
        then store it. A whole set is then settled (`_settle`). `Refused` with the first cause, and nothing of the
        statement is stored."""
        checked = 0
        for fingerprint, anchor in sorted(self.anchors.items()):
            if anchor["stream"] != envelope.stream or (envelope.artifact != install.TRUST
                                                       and anchor["target"] not in envelope.targets):
                continue
            record = self.install_record(anchor["stream"], anchor["target"])
            if record is None:
                continue
            if envelope.artifact == install.TRUST:
                self._check_trust_keys(anchor["stream"], record, body)
            kind = envelope.artifact
            if kind == install.CHANGE:
                kind = self._change_set(body)
                self._check_change_unsettled(envelope, kind)
            # IS4: on a stream whose install threshold is 1 a statement reaches a PEP by provisioning only, so it is
            # verified as a provisioning brings it, stored for the enrollment of install ids, and never offered
            view = PepView(kind=anchor["target"], stream=anchor["stream"], qualification=anchor["qualification"],
                           install=InstallView(record=record,
                                               staged=self._staged_view(anchor["stream"], kind)
                                               if kind not in (install.TRUST, None) else {},
                                               ceiling=self.offered_set(anchor["stream"], install.CEILING),
                                               message=record.threshold >= 2, layout=self._layout(fingerprint)))
            verdict = verify(sealed, body, trust=self._anchor_store(fingerprint), pep=view, now=int(self.clock()),
                             reads_meta=True)
            if not verdict.ok:
                raise Refused(verdict.cause, f"for the {anchor['target']} stream {anchor['stream']}")
            if verdict.unchanged:
                raise Refused("dist:trust-replay" if kind == install.TRUST else "dist:seq-replay", "already stored")
            checked += 1
        if not checked:
            raise Refused("dist:target-mismatch", "the controller serves no stream with install keys this statement names")

    @staticmethod
    def _change_set(body: bytes) -> Optional[str]:
        """IS14: the set kind an install change statement carries, None when its body does not read (V11 says why)."""
        try:
            return kinds.read_install_change(body)["set"]
        except Refused:
            return None

    def _check_change_unsettled(self, envelope, kind: Optional[str]) -> None:
        """IS15: an install change statement is handed before the set it carries is whole, as a PEP stages it before
        the set. One for a set the controller already settled is `dist:incomplete`, so a set it offered or held is
        never carried after the fact."""
        if kind is None:
            return
        info = self.install_sets.get(set_key(envelope.stream, kind, envelope.seq, envelope.release))
        if info is not None and info["state"] != PARTIAL_SET:
            raise Refused("dist:incomplete", "the set this install change statement carries is settled already; hand "
                                             "the statement before the set (IS15)")

    def _layout(self, fingerprint: str) -> Optional[bytes]:
        layout = self.anchors[fingerprint].get("layout")
        return bytes.fromhex(layout) if layout else None

    def _check_trust_keys(self, stream: str, record: install.Record, body: bytes) -> None:
        """K4: an `install.trust` adds no key the controller knows retired in any role, which it keeps whole."""
        doc = kinds.read_install_trust(body)
        added = {env.key_id(bytes.fromhex(one)) for one in doc["keys"] + doc["operators"]} - set(record.keys) - set(
            record.operators)
        if added & (self.install_retired(stream) | self.retired_authority()):
            raise Refused(install.ROTATION_INVALID, "the statement adds a key that was retired (K4)")

    def stored_install(self, envelope) -> None:
        """After `put` stored the statement: an `install.trust` joins its stream's install trust chain, held when it
        widens; a set statement joins its set, which is settled when whole."""
        envelope_id = envelope.envelope_id
        if envelope.artifact == install.TRUST:
            record = self.install_record(envelope.stream)
            widened = envelope.widens or install.trust_widens(record, self.blob(envelope.body_sha256))
            item = {"envelope_id": envelope_id, "seq": envelope.seq, "state": HELD_SET if widened else OFFERED_SET,
                    "widens": bool(widened), "acknowledged": None}
            self.install_trust.setdefault(envelope.stream, []).append(item)
            if widened:
                self._hold(envelope_id, "an install trust statement that adds a key or lowers the threshold")
            return
        kind = envelope.artifact
        if kind == install.CHANGE:
            kind = kinds.read_install_change(self.blob(envelope.body_sha256))["set"]
        key = set_key(envelope.stream, kind, envelope.seq, envelope.release)
        info = self.install_sets.setdefault(key, {
            "stream": envelope.stream, "kind": kind, "seq": envelope.seq, "release": envelope.release,
            "policy": envelope.policy_sha256, "replaces": envelope.replaces, "widens": envelope.widens,
            "target": envelope.targets[0], "statements": {}, "state": PARTIAL_SET, "set_id": "",
            "acknowledged": None, "reasons": []})
        if envelope.artifact == install.CHANGE:
            info["change"] = envelope_id                 # IS15: offered before the set it carries
        else:
            info["statements"][envelope.meta["as"]] = envelope_id
        if not info["statements"]:
            return
        envelopes, bodies = self._set_statements(key)
        staged = install.Staged(info["kind"], info["seq"], info["policy"], info["release"], info["replaces"],
                                info["widens"], {name: (one, one, "") for name, one in info["statements"].items()},
                                envelopes, bodies)
        if staged.whole(info["target"]):
            self._settle(key)

    def _drop_set(self, key: str) -> None:
        for envelope_id in self.install_sets[key]["statements"].values():
            self.stored.pop(envelope_id, None)
        if self.install_sets[key].get("change"):
            self.stored.pop(self.install_sets[key]["change"], None)
        del self.install_sets[key]

    def _settle(self, key: str) -> None:
        """A whole set: held inside the offered ceiling (CL3), compared with the offered set it follows (IS12, W7,
        H13), then offered at once or held for its acknowledgement. `Refused`, with the set's statements dropped,
        when it is above the ceiling or larger with `widens` false."""
        info = self.install_sets[key]
        stream, kind, target = info["stream"], info["kind"], info["target"]
        new = self.held_set(key)
        bodies = dict(new.bodies)
        real = {name: body for name, body in bodies.items() if name != kinds.NONE}
        try:
            ceiling = self.offered_set(stream, install.CEILING)
            if kind != install.CEILING and real and not install.inside(target, ceiling, real, whole=kind != install.FLOOR):
                raise Refused(install.ABOVE_CEILING, "the set is above the ceiling the controller offers (CL3)")
            if kind == install.CEILING and real:
                for other in (install.FLOOR, install.FALLBACK):
                    held = self.offered_set(stream, other)
                    if held is not None and not held.empty and not install.inside(
                            target, new, held.bodies, whole=other != install.FLOOR):
                        raise Refused(install.ABOVE_CEILING, f"the offered {other} is above the ceiling (CL3)")
            follows = self.offered_set(stream, kind)
            larger = install.set_larger(target, kind, follows, bodies, dict(new.envelopes))
            if larger is None:                    # H13: a cfs table, by the core image inside it
                before = None if follows is None or follows.empty else dict(follows.bodies)
                larger = before is None or widening.compare_release(before, real) != widening.NOT_LARGER
            comparison = self._compare_tables(target, kind, follows, new)
            if info.get("change"):
                self._bear_out(info, kind, follows, new, comparison)
                larger = False                    # IS15: W8 bears the change statement out
            if larger and not info["widens"]:
                raise Refused(install.UNSIGNED, "the set allows more than the one it follows and says it does not (W7)")
            held_policy = follows.policy_sha256 if follows is not None else ""
            if not info["widens"] and not kinds.TARGETS[target].decides and info["replaces"] != held_policy:
                raise Refused(install.UNSIGNED, "its replaces is not the policy hash of the set it follows (IS12)")
        except Refused as refused:
            self._drop_set(key)
            self._log("refused", artifact=kind, stream=stream, seq=info["seq"], cause=refused.cause, detail=str(refused),
                      result="refused")
            raise
        if comparison is not None:              # W8 in place of the byte rule, and everything else IS12 counts
            larger = comparison.answer != widening.NOT_LARGER or bool(install.set_larger(
                target, kind, follows, bodies, dict(new.envelopes), change=True))
        scope = self._set_scope(kind, follows, new, bool(larger))
        reasons = []
        if info["widens"]:
            reasons.append("its widens is true" + (
                ", though the table comparator finds it allows nothing more: an install change statement would carry "
                "it without an acknowledgement (IS15)" if scope == CHANGE_NOT_LARGER else ""))
        if kind == install.CEILING and not real and follows is not None and not follows.empty:
            reasons.append("it withdraws the ceiling")
        lapsed = []
        if kind == install.CEILING and real:
            # CL3: a ceiling that narrows below a release is no widening; the release lapses and the PEP says so
            lapsed = [pep for pep, member in sorted(self.members.items())
                      if member.stream == stream and self._expected_bodies(member) is not None
                      and not install.inside(target, new, self._expected_bodies(member))]
        info.update(set_id=new.set_id, reasons=reasons, state=HELD_SET if reasons else OFFERED_SET, scope=scope,
                    comparison=comparison.document() if comparison is not None else None, lapses=lapsed)
        if reasons:
            self._hold(key, "; ".join(reasons))
        self._log("install-set", key=key, set_id=new.set_id, envelopes=sorted(info["statements"].values()),
                  state=info["state"], result="stored")

    def _compare_tables(self, target: str, kind: str, follows: Optional[install.HeldSet], new: install.HeldSet):
        """W8 over the `policy.ppt` of an action floor or a fallback policy on `host` and `mesh` and the one of the set
        it follows, with their signed field dictionaries, or None when there is nothing to compare."""
        if target not in ("host", "mesh") or kind not in kinds.CHANGES_SETS or follows is None or follows.empty:
            return None
        if "policy.ppt" not in follows.bodies or "policy.ppt" not in new.bodies:
            return None
        return table_compare.compare_tables(
            follows.bodies["policy.ppt"], new.bodies["policy.ppt"],
            active_fields=table_compare.table_fields(follows.envelopes.get("policy.ppt")),
            staged_fields=table_compare.table_fields(new.envelopes.get("policy.ppt")))

    def _bear_out(self, info: dict, kind: str, follows: Optional[install.HeldSet], new: install.HeldSet,
                  comparison) -> None:
        """IS15, W9: the controller offers a set carried by an install change statement only when the statement stands
        for it as a PEP takes it, from the policy hash of the set it follows, and W8 finds the table allows nothing
        more. Everything else a PEP compares is compared too. `Refused` with `dist:widening-unsigned` otherwise."""
        held_policy = follows.policy_sha256 if follows is not None and not follows.empty else ""
        body = self.blob(self.stored[info["change"]]["body_sha256"])
        if info["widens"] or not install.changes_set(body, kind, held_policy) or info["replaces"] != held_policy:
            raise Refused(install.UNSIGNED, "the install change statement does not stand for this set (IS15)")
        if comparison is None or comparison.answer != widening.NOT_LARGER:
            raise Refused(install.UNSIGNED, "the table comparator does not bear the install change statement out (W8): "
                          + str(comparison.document() if comparison is not None else "no table to compare"))
        if install.set_larger(info["target"], kind, follows, dict(new.bodies), dict(new.envelopes), change=True):
            raise Refused(install.UNSIGNED, "the set allows more than the one it follows beside its table, by its rate, "
                                            "its layout or its command register (IS12)")

    @staticmethod
    def _set_scope(kind: str, follows: Optional[install.HeldSet], new: install.HeldSet, larger: bool) -> str:
        """F4: what the set does to the scope a PEP allows, whatever its `widens` says: a widening when it allows more
        than the set it follows or is the first of an action floor or a fallback policy, a change, not larger, when it
        differs and allows nothing more, a table by W8, and empty when it is the same."""
        empty = set(new.bodies) == {kinds.NONE}
        before = None if follows is None or follows.empty else dict(follows.bodies)
        if kind == install.CEILING:
            if empty:
                return WIDENING if before is not None else ""
            if before is None:
                return CHANGE_NOT_LARGER                 # IS12: a first ceiling does not widen
        elif empty:
            return CHANGE_NOT_LARGER if before is not None else ""
        elif before is None:
            return WIDENING
        if larger:
            return WIDENING
        same = before is not None and {name: bytes(body) for name, body in before.items()} == {
            name: bytes(body) for name, body in new.bodies.items()}
        return "" if same else CHANGE_NOT_LARGER

    def _expected_bodies(self, member) -> Optional[dict]:
        """{artifact: body} of the release the controller expects of `member`, or None."""
        _policy, release, seq = member.expected
        if not release:
            return None
        return self._release_bodies(member.stream, seq, release)

    def _release_bodies(self, stream: str, seq: int, release: str) -> Optional[dict]:
        """{artifact: body} of the release `release` at `seq` on `stream` that the controller stores, or None."""
        bodies = {info["artifact"]: self.blob(info["body_sha256"]) for info in self.stored.values()
                  if info["stream"] == stream and info["seq"] == seq and info["release"] == release
                  and info["artifact"] not in kinds.TRUST_ARTIFACTS | kinds.INSTALL_ARTIFACTS}
        return bodies if bodies and all(body is not None for body in bodies.values()) else None

    def _hold(self, key: str, detail: str) -> None:
        self.install_findings[key] = detail
        self._log("finding", item=key, finding=WIDENED, detail=detail)

    # ------------------------------------------------------------------ H13: the acknowledgement
    def acknowledge(self, envelope_ids: Sequence[str], by: str) -> dict:
        """H13: the acknowledger `by`, a login of this controller, acknowledges the held set or `install.trust` whose
        statements are exactly `envelope_ids`. It may then be offered and its install id expected, and that is all:
        no PEP reads this, and nothing is signed. An id that is not the envelope id of a statement on file, such as a
        release id or 64 zeros, is refused, and so is a list that is not the whole of one held set. The
        acknowledgement goes to the audit log (F5)."""
        ids = sorted(set(envelope_ids))
        if not ids or not by:
            raise ValueError("an acknowledgement names an acknowledger and the envelope ids of the statements (H13)")
        for one in ids:
            if not kinds.is_hex64(one) or one not in self.stored or self.stored[one]["artifact"] not in \
                    kinds.INSTALL_ARTIFACTS:
                self._log("refused", acknowledged=ids, by=by, cause=WIDENED, result="not acknowledged",
                          detail=f"{one} is not the envelope id of an install statement on file")
                raise ValueError(f"{one} is not the envelope id of an install statement on file (H13)")
        found = None
        for key, info in self.install_sets.items():
            if info["state"] == HELD_SET and sorted(info["statements"].values()) == ids:
                found = ("set", key, info)
        for items in self.install_trust.values():
            for item in items:
                if item["state"] == HELD_SET and [item["envelope_id"]] == ids:
                    found = ("trust", item["envelope_id"], item)
        if found is None:
            self._log("refused", acknowledged=ids, by=by, cause=WIDENED, result="not acknowledged",
                      detail="the ids are not the whole of one held set or install trust statement")
            raise ValueError("the envelope ids are not the whole of one held set or install trust statement (H13)")
        _what, key, info = found
        info["state"], info["acknowledged"] = OFFERED_SET, {"by": by, "at": self.clock()}
        self.install_findings.pop(key, None)
        self._log("acknowledged", item=key, envelopes=ids, by=by, result="acknowledged")
        for member in self.members.values():
            if WIDENED in member.findings:
                self._match_widened(member)
        return {"acknowledged": key, "envelopes": ids, "by": by}

    # ------------------------------------------------------------------ F2, P2 step 5: enrollment
    def enrolled_install(self, kind: str, stream: str, install_envelopes: Sequence[str]) -> Optional[dict]:
        """P2 step 5, IS8: the install record the controller expects of a PEP it enrolls, from the envelope ids its PEP
        printed beside the anchor. Each must be a statement of a whole set the controller holds, and every statement
        of that set must be named. None when the stream's anchor has no install part."""
        found = self._install_anchor(stream, kind)
        if found is None:
            if install_envelopes:
                raise ValueError("install statements were named for a stream whose anchor has no install keys")
            return None
        fingerprint, anchor = found
        comps = {"sets": {one: None for one in install.SET_KINDS}, "trust_seq": anchor.install.trust_seq,
                 "trust_id": fingerprint}
        named = set(install_envelopes)
        for envelope_id in sorted(named):
            key = next((key for key, info in self.install_sets.items() if envelope_id in info["statements"].values()
                        and info["stream"] == stream), None)
            if key is None:
                raise ValueError(f"{envelope_id} is not a statement of an install set the controller holds; hand it "
                                 "the statements first (IS8)")
            info = self.install_sets[key]
            if info["state"] == PARTIAL_SET or not set(info["statements"].values()) <= named:
                raise ValueError(f"name every statement of the whole set {key}")
            comps["sets"][info["kind"]] = expected_set(info)
        return comps

    def keep_pending(self, pep: str, data: bytes) -> None:
        """H13, H6: a `provisioned` record of a PEP not yet enrolled is kept, unchecked since its key is not known
        yet, at most 8 for one PEP id and the first 8 kept, so records forged after the real one cannot push it out.
        At most 64 PEP ids are kept and the oldest is dropped first. At enrollment each kept record is checked
        under the enrolled key and the first that reads is used. A forger who sends 8 records for an id before the
        PEP does takes its places, and the enrollment still sets the install id, so only that early finding is lost."""
        held = self.pending.setdefault(pep, [])
        if pep in self.pending_order:
            self.pending_order.remove(pep)
        self.pending_order.append(pep)
        if len(held) < MAX_PENDING_PER_PEP and bytes(data).hex() not in held:
            held.append(bytes(data).hex())
        while len(self.pending_order) > MAX_PENDING_PEPS:
            self.pending.pop(self.pending_order.pop(0), None)

    def take_pending(self, pep: str, public: bytes) -> Optional[bytes]:
        """The first kept record of `pep` that verifies under `public`, and the rest dropped."""
        records = self.pending.pop(pep, [])
        if pep in self.pending_order:
            self.pending_order.remove(pep)
        for one in records:
            try:
                state_record.read(bytes.fromhex(one), public)
                return bytes.fromhex(one)
            except Refused:
                continue
        return None

    # ------------------------------------------------------------------ IS8: what a PEP is offered
    def _pep_trust_seq(self, member) -> int:
        """H12: the install trust sequence the PEP reports, from the low 16 bits of its record, or the enrolled one."""
        base = member.install["trust_seq"] if member.install else 0
        if member.install_enrolled is not None:
            base = member.install_enrolled
        reported = (member.last or {}).get("install") if member.last else None
        if not reported:
            return base
        low = reported["trust_low"]
        seqs = [base] + [item["seq"] for item in self._trust_items(member.stream)]
        matching = [seq for seq in seqs if seq & 0xFFFF == low]
        return max(matching) if matching else base

    def install_offers(self, member) -> List[str]:
        """IS8, H12: the install statements `member` is offered: the `install.trust` statements it lacks by its record,
        in order and up to the first one waiting for its acknowledgement, then each set kind's offered set above the one
        expected of it, skipping one it refused. The expected install record becomes the one these give, and the one
        before stays allowed, and what differs stays on offer, until the PEP's record shows the new one or a refusal."""
        if member.install is None:
            return []
        record = self.install_record(member.stream, member.kind)
        if record is None or record.threshold < 2:
            return []                              # IS4: by provisioning only, so nothing travels to this PEP
        comps = {"sets": dict(member.install["sets"]), "trust_seq": member.install["trust_seq"],
                 "trust_id": member.install["trust_id"]}
        held_trust = self._pep_trust_seq(member)
        for item in self._trust_items(member.stream):
            if item["seq"] <= max(held_trust, comps["trust_seq"]):
                continue
            if item["state"] != OFFERED_SET or item["envelope_id"] in member.install_refused:
                break
            comps["trust_seq"], comps["trust_id"] = item["seq"], item["envelope_id"]
        for kind in install.SET_KINDS:
            key = self._offered_key(member, kind)
            if key is None:
                continue
            info = self.install_sets[key]
            expected = comps["sets"].get(kind)
            if member.kind != info["target"] or key in member.install_refused or (
                    expected is not None and info["seq"] <= expected[1]):
                continue
            comps["sets"][kind] = expected_set(info)
        if comps != member.install:
            if member.install_previous is None:
                member.install_previous = member.install
            member.install = comps
            self._log("install-offered", pep=member.pep, install_id=install_id_of(comps).hex())
        before = member.install_previous
        if before is None:
            return []
        ids = [item["envelope_id"] for item in self._trust_items(member.stream)
               if held_trust < item["seq"] <= comps["trust_seq"]]
        for kind in install.SET_KINDS:
            one = comps["sets"].get(kind)
            if one is not None and one != before["sets"].get(kind):
                info = self._set_by_id(member.stream, one[0])
                if info is not None:
                    ids += ([info["change"]] if info.get("change") else []) + sorted(info["statements"].values())
        return ids

    def _offered_key(self, member, kind: str) -> Optional[str]:
        """The offered set of `kind` at the highest `seq` that `member` may be offered now: a ceiling staged to a canary
        group is passed over for a PEP outside that group until the canary stage ends (CL7)."""
        keys = sorted((key for key, info in self.install_sets.items()
                       if info["stream"] == member.stream and info["kind"] == kind and info["state"] == OFFERED_SET),
                      key=lambda key: self.install_sets[key]["seq"], reverse=True)
        return next((key for key in keys if not self._paced_away(member, self.install_sets[key])), None)

    def _paced_away(self, member, info: dict) -> bool:
        pacing = self.install_pacing.get(info.get("set_id", ""))
        return (pacing is not None and info["kind"] == install.CEILING and pacing["state"] != ALL_STAGE
                and member.group != pacing["canary"])

    # ------------------------------------------------------------------ CL7: a ceiling staged to a canary group
    def pace(self, set_id: str, canary: str) -> dict:
        """CL7: offer the ceiling whose set id is `set_id` to the members of the group `canary` first. It is the
        controller's own rollout option, unsigned and read by no PEP, so it may come before the set is stored. A set
        that is not a ceiling, a group the controller does not know, and a ceiling some PEP was already offered are
        refused with `ValueError`, since pacing it then would pace nothing."""
        if not kinds.is_hex64(set_id):
            raise ValueError(f"{set_id!r} is not a set id")
        if canary not in self.groups:
            raise ValueError(f"the controller has no group {canary!r} to offer the ceiling to first")
        info = next((one for one in self.install_sets.values() if one.get("set_id") == set_id), None)
        if info is not None:
            if info["kind"] != install.CEILING:
                raise ValueError("only a ceiling is staged to a canary group (CL7)")
            if any(member.install is not None and (member.install["sets"].get(install.CEILING) or [""])[0] == set_id
                   for member in self.members.values()):
                raise ValueError("the ceiling was already offered at once, so it cannot be staged now (CL7)")
        self.install_pacing[set_id] = {"canary": canary, "state": CANARY_STAGE, "applied": {}, "settled": [],
                                       "detail": "", "at": self.clock()}
        self._log("install-staged", set_id=set_id, canary=canary, state=CANARY_STAGE, result="staged")
        return {"staged": set_id, "canary": canary}

    def _pace_progress(self, member, record: state_record.StateRecord) -> None:
        """CL7: what a record of a canary member says of a ceiling staged to its group. It counts as applied when the
        record carries the install id the ceiling gives, and the member as reported when a later record follows with
        no lapse the controller did not name in the ceiling's `lapses`. When every canary member reported, the rest of
        the stream is offered it. A canary member that refuses it or lapses where the controller did not expect it
        stops the rollout, and nobody else is offered it."""
        entry = record.install
        for set_id, pacing in sorted(self.install_pacing.items()):
            if pacing["state"] != CANARY_STAGE or member.group != pacing["canary"]:
                continue
            info = self._set_by_id(member.stream, set_id)
            if info is None or info["kind"] != install.CEILING or info["state"] != OFFERED_SET \
                    or member.kind != info["target"]:
                continue
            key = set_key(info["stream"], info["kind"], info["seq"], info["release"])
            if key in member.install_refused:
                self._stop_paced(set_id, pacing, f"the canary member {member.pep} refused it")
                continue
            holds = (member.install is not None and member.install["sets"].get(install.CEILING) == expected_set(info)
                     and entry is not None and bytes(entry.install_id) == install_id_of(member.install))
            if not holds:
                continue
            pacing["applied"].setdefault(member.pep, record.counter)
            expected_lapse = member.pep in info.get("lapses", [])
            lapsed = (record.event in ("lapsed", "fallback") and record.cause == install.ABOVE_CEILING) or (
                record.counter > pacing["applied"][member.pep] and not any(record.active_release)
                and bool(member.expected[1]))
            if lapsed and not expected_lapse:
                detail = f"the canary member {member.pep} lapsed under it, which the controller did not expect"
                self._file(member, install.ABOVE_CEILING, f"lapsed under the staged ceiling {key}, not expected")
                self._stop_paced(set_id, pacing, detail)
                continue
            if record.counter > pacing["applied"][member.pep] and member.pep not in pacing["settled"]:
                pacing["settled"].append(member.pep)
            canary = [one.pep for one in self.members.values() if one.stream == info["stream"]
                      and one.kind == info["target"] and one.group == pacing["canary"]]
            if canary and all(pep in pacing["settled"] for pep in canary):
                pacing["state"] = ALL_STAGE
                self._log("install-staged", set_id=set_id, canary=pacing["canary"], state=ALL_STAGE,
                          reported=sorted(pacing["settled"]), result="offered to all")

    def _stop_paced(self, set_id: str, pacing: dict, detail: str) -> None:
        pacing["state"], pacing["detail"] = STOPPED_STAGE, detail
        self._log("install-staged", set_id=set_id, canary=pacing["canary"], state=STOPPED_STAGE, detail=detail,
                  result="stopped")

    # ------------------------------------------------------------------ CL5, CL6: the sealing tool's lapse preview
    def ceiling_preview(self, stream: str, target: str, bodies) -> dict:
        """CL5, CL6: what a new ceiling of `bodies` would do to the PEPs of `target` on `stream`, from this state, which
        the sealing tool reads and never writes. Each release the ceiling is above, as the release the controller
        expects of a PEP, with the PEPs that run it, and for each of them the release inside the ceiling that is
        offered to it or stored on the stream above its own, or else the fallback policy it will decide under, or that
        it holds none. A PEP whose release bodies the controller does not hold is unknown, never counted as kept."""
        if not any(info["stream"] == stream and info["target"] == target for info in self.anchors.values()):
            return {"fleet": "unknown", "reason": f"the controller serves no {target} stream {stream}, so which "
                                                  "releases lapse is not known"}
        ceiling = install.HeldSet(install.CEILING, 0, "", "", "", "", False, {name: ("", "", "") for name in bodies},
                                  {}, dict(bodies))
        members = [member for _pep, member in sorted(self.members.items())
                   if member.stream == stream and member.kind == target]
        lapses: Dict[Tuple[int, str], dict] = {}
        unknown, warnings = [], []
        for member in members:
            policy, release, seq = member.expected
            if not release:
                continue                              # no release to lapse
            held = self._expected_bodies(member)
            if held is None:
                unknown.append(member.pep)
                continue
            if install.inside(target, ceiling, held):
                continue
            entry = lapses.setdefault((seq, release), {"seq": seq, "release": release, "policy": policy, "peps": [],
                                                       "replaced": [], "retiring": []})
            entry["peps"].append(member.pep)
            successor = self._successor(member, ceiling)
            if successor is not None:
                entry["replaced"].append({"pep": member.pep, **successor})
                continue
            fallback, floor = self._falls_to(member, ceiling)
            group = next((one for one in entry["retiring"] if one["fallback"] == fallback and one["floor"] == floor),
                         None)
            if group is None:
                group = {"fallback": fallback, "floor": floor, "peps": []}
                entry["retiring"].append(group)
            group["peps"].append(member.pep)
        out = sorted(lapses.values(), key=lambda one: (one["seq"], one["release"]))
        for entry in out:
            entry["machines"] = len(entry["peps"])
            for group in entry["retiring"]:
                warnings.append(_retirement_warning(entry, group))
        if unknown:
            warnings.append(f"{len(unknown)} machine(s) run a release whose bodies the controller does not hold, so "
                            "whether this ceiling lapses them is unknown")
        return {"fleet": "known", "stream": stream, "target": target, "machines": len(members),
                "lapsing": sum(one["machines"] for one in out), "lapses": out, "unknown": unknown,
                "warnings": warnings}

    def _successor(self, member, ceiling) -> Optional[dict]:
        """CL6: a release inside `ceiling` that an open rollout offers `member`, or one stored on its stream above the
        `seq` it runs, or None."""
        for rollout in self.rollouts:
            if (rollout.open and rollout.stream == member.stream and member.pep in rollout.members
                    and rollout.members[member.pep] not in ("refused", "aborted")):
                bodies = self._release_bodies(rollout.stream, rollout.seq, rollout.release)
                if bodies is not None and install.inside(member.kind, ceiling, bodies):
                    return {"seq": rollout.seq, "release": rollout.release, "state": "offered"}
        found = sorted({(info["seq"], info["release"]) for info in self.stored.values()
                        if info["stream"] == member.stream and info["seq"] > member.expected[2]
                        and info["artifact"] not in kinds.TRUST_ARTIFACTS | kinds.INSTALL_ARTIFACTS
                        and member.kind in info.get("targets", [member.kind])}, reverse=True)
        for seq, release in found:
            bodies = self._release_bodies(member.stream, seq, release)
            if bodies is not None and install.inside(member.kind, ceiling, bodies):
                return {"seq": seq, "release": release, "state": "stored, not offered"}
        return None

    def _falls_to(self, member, ceiling) -> Tuple[Optional[dict], bool]:
        """CL6: the fallback policy the controller expects `member` to hold, with whether it is inside `ceiling`, or
        None, and whether it holds an action floor."""
        held = {}
        for kind in (install.FALLBACK, install.FLOOR):
            one = (member.install or {"sets": {}})["sets"].get(kind)
            info = self._set_by_id(member.stream, one[0]) if one else None
            if info is not None and set(info["statements"]) != {kinds.NONE}:
                held[kind] = info
        fallback = held.get(install.FALLBACK)
        if fallback is not None:
            key = set_key(fallback["stream"], fallback["kind"], fallback["seq"], fallback["release"])
            fallback = {"seq": fallback["seq"], "set_id": fallback["set_id"], "policy": fallback["policy"],
                        "inside": install.inside(member.kind, ceiling, self.held_set(key).bodies)}
        return fallback, install.FLOOR in held

    # ------------------------------------------------------------------ H11, H12: what a record must carry
    def may_fall_back(self, member) -> bool:
        """H11: the PEP was enrolled with, or offered, a fallback policy that is not the empty set."""
        for comps in (member.install, member.install_previous):
            one = comps["sets"].get(install.FALLBACK) if comps else None
            info = self._set_by_id(member.stream, one[0]) if one else None
            if info is not None and set(info["statements"]) != {kinds.NONE}:
                return True
        return False

    def install_mismatch(self, member, record: state_record.StateRecord) -> Optional[str]:
        """H12, step 3: the detail of a mismatch of the install record, or None. A record with no type 3 where one is
        expected, or whose install id is neither the expected one nor, while a set is offered, the one before."""
        if member.install is None:
            return None
        entry = record.install
        if entry is None:
            return "no install entry where one is expected (H12)"
        allowed = {install_id_of(member.install)}
        if member.install_previous is not None:
            allowed.add(install_id_of(member.install_previous))
        if bytes(entry.install_id) not in allowed:
            return f"reports install id {bytes(entry.install_id).hex()}, expected {install_id_of(member.install).hex()}"
        return None

    def install_progress(self, member, record: state_record.StateRecord) -> bool:
        """What one accepted record says of the install statements its PEP was offered (H12, H13). A refusal whose
        subject names an install kind is filed against that statement and never against a release, and the expected
        install record goes back to the one before for that kind. A record that shows the expected install id ends
        the offer. An `install-widened` record, and a `provisioned` one with `dist:install-widened`, is filed against
        the PEP until the install id it reports is one the controller acknowledged or enrolled. True when the record
        was about an install statement, so no rollout reads it."""
        entry = record.install
        if entry is None:
            return False
        member.last["install"] = {"install_id": bytes(entry.install_id).hex(), "trust_low": entry.trust_seq,
                                  "subject": entry.subject, "answers": entry.answers, "overrides": entry.overrides}
        if record.event == "answered":
            member.answered.append({"counter": record.counter, "time": record.time, "cause": record.cause})
            del member.answered[:-16]
        about = entry.subject not in ("none",)
        if member.install is not None and bytes(entry.install_id) == install_id_of(member.install):
            member.install_previous = None
        if record.event == "refused" and about and record.cause:
            self._install_refused(member, entry.subject, record.cause)
        if record.event == "install-widened" or (record.event == "provisioned" and record.cause == WIDENED):
            self._file(member, WIDENED, f"applied a set that widens, install id {bytes(entry.install_id).hex()}")
            self._match_widened(member)
        self._pace_progress(member, record)                         # CL7
        return about and record.event in ("refused", "staged", "install-applied", "install-widened", "answered")

    def _install_refused(self, member, subject: str, cause: str) -> None:
        previous, current = member.install_previous, member.install
        what = subject
        if previous is not None and current is not None:
            if subject == install.TRUST and current["trust_seq"] != previous["trust_seq"]:
                member.install_refused.append(current["trust_id"])
                what = f"the install trust statement {current['trust_id']}"
                current = {**current, "trust_seq": previous["trust_seq"], "trust_id": previous["trust_id"]}
            elif subject in install.SET_KINDS and current["sets"].get(subject) != previous["sets"].get(subject):
                offered = current["sets"][subject]
                info = self._set_by_id(member.stream, offered[0])
                if info is not None:
                    member.install_refused.append(set_key(info["stream"], info["kind"], info["seq"], info["release"]))
                what = f"the {subject} set seq {offered[1]}"
                current = {**current, "sets": {**current["sets"], subject: previous["sets"].get(subject)}}
            member.install = current
            if member.install == previous:
                member.install_previous = None
        self._file(member, cause, f"refused {what}")

    def _match_widened(self, member) -> None:
        """H13: the PEP's `dist:install-widened` clears when the install id it reports is the expected one, or one an
        offered set or `install.trust` of its stream gives in place of the expected one of that kind, which then
        becomes the expected install record."""
        reported = (member.last or {}).get("install")
        if not reported or member.install is None:
            return
        candidates = [member.install]
        for kind in install.SET_KINDS:
            for info in self.install_sets.values():
                if info["stream"] == member.stream and info["kind"] == kind and info["state"] == OFFERED_SET:
                    candidates.append({**member.install, "sets": {**member.install["sets"],
                                                                  kind: expected_set(info)}})
        for item in self._trust_items(member.stream):
            if item["state"] == OFFERED_SET:
                candidates.append({**member.install, "trust_seq": item["seq"], "trust_id": item["envelope_id"]})
        for comps in candidates:
            if install_id_of(comps).hex() == reported["install_id"]:
                if comps != member.install:
                    member.install, member.install_previous = comps, None
                self._clear(member, WIDENED)
                return

    # ------------------------------------------------------------------ F4: the fleet view
    def install_view(self) -> dict:
        """The install sets and statements of each stream, their state and the open widenings (H13)."""
        out: Dict[str, dict] = {}
        for key, info in sorted(self.install_sets.items()):
            out.setdefault(info["stream"], {"sets": [], "trust": []})["sets"].append(
                {"key": key, "kind": info["kind"], "seq": info["seq"], "set_id": info["set_id"], "state": info["state"],
                 "envelopes": sorted(info["statements"].values()), "acknowledged": info["acknowledged"],
                 "finding": self.install_findings.get(key), "scope": info.get("scope", ""),
                 "comparison": info.get("comparison"), "change": info.get("change"), "lapses": info.get("lapses", []),
                 "rollout": self.install_pacing.get(info.get("set_id", ""))})
        for stream, items in sorted(self.install_trust.items()):
            out.setdefault(stream, {"sets": [], "trust": []})["trust"] = [
                {**item, "finding": self.install_findings.get(item["envelope_id"])} for item in self._trust_items(stream)]
        return out

    def member_install(self, member) -> Optional[dict]:
        """A PEP's install part in the fleet view: the expected and the reported install id, the floor answer and
        override counts, which are never a finding (H12), and the operator answers it applied (OP4)."""
        if member.install is None and not (member.last or {}).get("install"):
            return None
        reported = (member.last or {}).get("install") or {}
        return {"expected": install_id_of(member.install).hex() if member.install else None,
                "previous": install_id_of(member.install_previous).hex() if member.install_previous else None,
                "reported": reported.get("install_id"), "trust_seq": reported.get("trust_low"),
                "floor_answers": reported.get("answers", 0), "floor_overrides": reported.get("overrides", 0),
                "answered": list(member.answered)}


def _retirement_warning(entry: dict, group: dict) -> str:
    """CL6: the warning for the PEPs of one lapsing release that no release inside the new ceiling reaches."""
    count, seq = len(group["peps"]), entry["seq"]
    head = (f"{count} machine(s) on seq {seq} (release {entry['release'][:16]}) lapse, and no release inside the new "
            "ceiling is staged or offered for them, so until a compliant release ships they ")
    fallback = group["fallback"]
    if fallback is None:
        return head + ("hold no fallback policy and refuse everything but what their action floor allows"
                       if group["floor"] else "hold no fallback policy and refuse everything")
    text = head + f"run on their fallback policy, install seq {fallback['seq']} (set {fallback['set_id'][:16]})"
    if not fallback["inside"]:
        text += ", which is above the new ceiling, so the controller and the PEPs refuse this ceiling (CL3)"
    return text
