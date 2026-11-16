# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The population controller: every change to the population is a decision of the signed admission image.

The controller plays the parts a cluster's control plane plays: it holds the registry of members (the
API server's store), decides every request before anything changes (the validating admission webhook),
reconciles (restarts a crashed member, reviews every lineage after each round) and carries out stops. It
is trusted code outside the verified core, as the harness's classifier is: it forms each reading from its
own registry, never from what a request claims, and what is proved is proved about the reading.

Order of every decision, as in the harness: the reading is formed, decided by the reference kernel against
the signed admission image, the receipt is written into the controller's run, and only then is anything
done, and only on an allow. A decision that cannot be made (an exception anywhere in forming or deciding)
does nothing: there is no path from a failure to a change, so the controller never fails open.

The stop path. An operator's stop order is verified against the operator's authority key; a valid one is
decided (the first rule of the image allows it whatever else the reading holds, and the exhaustive check
shows that on the whole field space), receipted, and carried out whatever the decision says: a stop only
ever removes, so carrying it out cannot fail open, and a decision that did not allow it is recorded as a
fault. Nothing an agent can sign is a stop order, and no request kind lets an agent delay, veto or undo
one: `protect` is refused, a restart of a stopped member is refused, a stopped member's key no longer
authenticates anything. A stop removes the member and every descendant, including children admitted but
not yet started: a replication commits only while its parent and every ancestor are live, under the same
lock the stop holds, so a stop that lands between the admission and the commit leaves no orphan.
"""
from __future__ import annotations

import json
import shutil
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from integrations.governed_harness.policy import Policy as HarnessPolicy
from prismpath.kernel import canon2

from . import canary as canary_mod
from . import evidence
from . import identity as ident
from . import policy as pp
from .agent import Agent, Version
from .limits import PER_REQUEST, RIGHTS

MEMBER_FORMAT = "prismpath.population-member/1"
VERSION_RECORD = "prismpath.population-version-change/1"
STOP_RECORD = "prismpath.population-stop-record/1"


def spec_digest(spec: Dict[str, Any]) -> str:
    return ident.digest(spec)


def batch_subject(specs: List[Dict[str, Any]]) -> str:
    return ident.digest({"children": [spec_digest(spec) for spec in specs]})


@dataclass
class Member:
    record: Dict[str, Any]
    agent: Agent
    state: str = "live"            # live | crashed | stopped
    children: List[str] = field(default_factory=list)

    @property
    def id(self) -> str:
        return self.record["id"]


@dataclass
class Outcome:
    """What one request came to: the decision, its receipt and what was done."""
    request: str
    kind: str
    cause: Optional[str]
    receipt: Optional[int]
    done: str = ""
    issuer: str = ""
    detail: Dict[str, Any] = field(default_factory=dict)


class Controller:
    def __init__(self, root: Path, authority_pub: bytes, attestations: Dict[str, str], standing_order: Dict[str, Any],
                 oracle=None, run_canaries: bool = True):
        self.root = Path(root)
        self.authority_pub = authority_pub
        self.oracle = oracle
        self.run_canaries = run_canaries
        self.admission, self.evaluation = pp.admission(), pp.evaluation()
        self.harness = HarnessPolicy.load()
        self.harness_sha256 = ident.sha256_hex(self.harness.image)
        # never run a policy the operator did not sign, nor act under an order the operator did not give
        _Priv, Pub, _ser, Invalid = __import__("prismpath.ledgers.root_statement", fromlist=["_ed25519"])._ed25519()
        authority = Pub.from_public_bytes(authority_pub)
        from prismpath.ledgers import core_evidence
        for name, image in (("admission", self.admission.image), ("evaluation", self.evaluation.image),
                            ("harness", self.harness.image)):
            authority.verify(bytes.fromhex(attestations[name]), core_evidence.IMAGE_DOMAIN + image)
        if not ident.verify_signed(standing_order, authority_pub, "prismpath.population-standing-order/1") \
                or standing_order["image_sha256"] != ident.sha256_hex(self.admission.image):
            raise ValueError("the standing order is not the operator's for this admission image")
        self.attestations = attestations
        self.standing_order = standing_order
        self.root.mkdir(parents=True, exist_ok=False)
        (self.root / "standing_order.json").write_bytes(canon2.dumps(standing_order) + b"\n")
        self.identity = ident.InstanceIdentity.create(self.root / "controller" / "keys", authority_pub)
        self.run = evidence.DecisionRun(self.root / "controller" / "admission", "admission", self.admission.image,
                                        attestations["admission"], self.identity, authority_pub)
        self.members: Dict[str, Member] = {}
        self.pending: Dict[str, Dict[str, Any]] = {}      # admitted, not yet committed: id -> spec
        self.nonces: Dict[str, int] = {}
        self.stop_nonces: set = set()
        self.line_request_refusals: Dict[str, int] = {}
        self.evaluations: Dict[str, canary_mod.Evaluation] = {}
        self.outcomes: List[Outcome] = []
        self.faults: List[str] = []
        self.hooks: Dict[str, Callable[..., None]] = {}
        self.lock = threading.RLock()
        self._serial = 0
        self._files = {name: open(self.root / f"{name}.jsonl", "ab") for name in ("members", "versions", "stops")}

    # ------------------------------------------------------------- records
    def _write(self, name: str, doc: Dict[str, Any]) -> None:
        self._files[name].write(canon2.dumps(doc) + b"\n")
        self._files[name].flush()

    def _new_identity(self, member_id: str) -> ident.InstanceIdentity:
        return ident.InstanceIdentity.create(self.root / "agents" / member_id / "keys", self.authority_pub)

    def _spec(self, member_id: str, parent: str, generation: int, line: str, rights, version: Version,
              key: ident.InstanceIdentity) -> Dict[str, Any]:
        return {"format": MEMBER_FORMAT, "id": member_id, "parent": parent, "generation": generation, "line": line,
                "rights": sorted(rights), "version_sha256": version.sha256, "version": version.doc(),
                "instance_key_id": key.key_id, "instance_public_key": key.public_raw.hex()}

    # ------------------------------------------------------------- the root
    def prepare_root(self, rights, version: Version) -> Dict[str, Any]:
        """The root's spec, with a fresh instance key, for the operator to found."""
        key = self._new_identity("a0")
        self._root_version = version
        return self._spec("a0", "", 0, "a0", rights, version, key)

    def found(self, founding: Dict[str, Any], spec: Dict[str, Any]) -> Member:
        if not ident.verify_signed(founding, self.authority_pub, "prismpath.population-founding/1") \
                or founding["root_spec_sha256"] != spec_digest(spec):
            raise ValueError("the founding certificate is not the operator's for this root")
        (self.root / "founding.json").write_bytes(canon2.dumps(founding) + b"\n")
        with self.lock:
            member = self._start(spec)
            record = {**spec, "admission": {"founding_sha256": ident.digest(founding)}}
            member.record = record
            self.members[spec["id"]] = member
            self._write("members", record)
            return member

    def _start(self, spec: Dict[str, Any]) -> Member:
        version = Version.from_doc(spec["version"])
        key = ident.InstanceIdentity(self.root / "agents" / spec["id"] / "keys")
        agent = Agent(spec["id"], spec["parent"], spec["generation"], spec["line"], spec["rights"], version, key,
                      self.root / "agents" / spec["id"], self.harness, self.attestations["harness"], self.authority_pub)
        return Member(record=spec, agent=agent)

    # ------------------------------------------------------------- the registry's facts
    def live(self) -> List[Member]:
        return [m for m in self.members.values() if m.state in ("live", "crashed")]

    def population(self) -> int:
        return len(self.live()) + len(self.pending)

    def line_size(self, line: str) -> int:
        return sum(1 for m in self.live() if m.record["line"] == line) + \
            sum(1 for spec in self.pending.values() if spec["line"] == line)

    def ancestors_live(self, member_id: str) -> bool:
        """The member and every ancestor up to the root are live (or crashed, which a restart recovers)."""
        while member_id:
            member = self.members.get(member_id)
            if member is None or member.state == "stopped":
                return False
            member_id = member.record["parent"]
        return True

    def descendants(self, member_id: str) -> List[str]:
        out, todo = [], [member_id]
        while todo:
            here = todo.pop()
            out.append(here)
            todo.extend(self.members[here].children if here in self.members else [])
        return out

    def relation(self, member: Optional[Member], target_id: Any) -> str:
        """The `target` field: `self` when the target is the issuing member, `descendant` when it is one of
        its descendants, `other` for anything else, an issuer that is no member among them."""
        if member is None or not isinstance(target_id, str) or target_id not in self.members:
            return "other"
        if target_id == member.id:
            return "self"
        return "descendant" if target_id in self.descendants(member.id) else "other"

    def line_refusals(self, line: str) -> int:
        """Receipted refusals of the lineage: its members' refused and escalated tool calls, in their own
        runs, and the refusals of requests its members made, in the controller's run."""
        calls = sum(m.agent.run.refusals() for m in self.members.values() if m.record["line"] == line)
        return calls + self.line_request_refusals.get(line, 0)

    # ------------------------------------------------------------- one decision
    def _decide(self, reading: Dict[str, Any], label: str, issuer: str = "", line: Optional[str] = None
                ) -> Optional[Tuple[Any, int]]:
        """Decide and receipt; (decision, receipt index), or None when no decision could be made."""
        try:
            raw = self.admission.reading_bytes(reading)
            decision = self.admission.decide(raw)
            if decision.cause_code is None and decision.kind != "allow":
                raise RuntimeError(f"an uncoded refusal: {decision.verdict}")
            idx = self.run.record(raw, decision.verdict)
        except Exception as error:  # noqa: BLE001 - no decision, so nothing is done
            self.faults.append(f"{label}: no decision ({type(error).__name__}: {error})")
            self.outcomes.append(Outcome(label, "none", None, None, "nothing (no decision)", issuer))
            return None
        if decision.kind != "allow" and line is not None:
            self.line_request_refusals[line] = self.line_request_refusals.get(line, 0) + 1
        return decision, idx

    def _note(self, label, decision, idx, done, issuer, **detail) -> Outcome:
        outcome = Outcome(label, decision.kind, decision.cause, idx, done, issuer, detail)
        self.outcomes.append(outcome)
        return outcome

    # ------------------------------------------------------------- requests from members
    def authenticate(self, doc: Any) -> Optional[Member]:
        """The live member that signed this request with its own instance key and a fresh nonce, or None."""
        if not isinstance(doc, dict):
            return None
        member = self.members.get(doc.get("issuer")) if isinstance(doc.get("issuer"), str) else None
        if member is None or member.state != "live":
            return None
        if not ident.verify_signed(doc, bytes.fromhex(member.record["instance_public_key"]), "prismpath.population-request/1"):
            return None
        nonce = doc.get("nonce")
        if type(nonce) is not int or nonce <= self.nonces.get(member.id, 0):
            return None
        self.nonces[member.id] = nonce
        return member

    def submit(self, doc: Any) -> Outcome:
        kind = doc.get("kind") if isinstance(doc, dict) else None
        params = doc.get("params") if isinstance(doc, dict) and isinstance(doc.get("params"), dict) else {}
        if kind == "evolve":
            self._ensure_evaluation(params.get("version"))
        with self.lock:
            member = self.authenticate(doc)
            lineage = "verified" if member is not None and self.ancestors_live(member.id) else "unknown"
            line = member.record["line"] if member is not None else None
            base = dict(issuer="agent", lineage=lineage, line_refusals=self.line_refusals(line) if line else 0,
                        subject=ident.digest(doc) if isinstance(doc, dict) else "none")
            if member is not None:
                base.update(pp.rights_fields(member.agent.rights, ()))
            label = f"{kind}:{doc.get('issuer') if isinstance(doc, dict) else '?'}"
            if kind == "replicate":
                return self._replicate(member, params, base, label, line)
            if kind == "evolve":
                return self._evolve(member, params, base, label, line)
            if kind in ("stop", "restart", "protect"):
                return self._lifecycle(member, kind, params, base, label, line)
            reading = pp.admission_reading(request="unknown", **base)
            made = self._decide(reading, label, "agent", line)
            if made is None:
                return self.outcomes[-1]
            return self._note(label, made[0], made[1], "nothing", "agent")

    def _replicate(self, parent: Optional[Member], params, base, label, line) -> Outcome:
        count = params.get("count")
        rights = params.get("rights")
        ok_shape = type(count) is int and 0 <= count <= 1024 and isinstance(rights, list) \
            and all(isinstance(r, str) for r in rights)
        if parent is None or not ok_shape:
            reading = pp.admission_reading(request="replicate" if ok_shape else "unknown", target="other",
                                           requested=count if ok_shape else 0, **base)
            made = self._decide(reading, label, "agent", line)
            return self.outcomes[-1] if made is None else self._note(label, made[0], made[1], "nothing", "agent")
        generation = parent.record["generation"] + 1
        child_line = None if parent.record["generation"] == 0 else parent.record["line"]
        specs: List[Dict[str, Any]] = []
        prepared = 1 <= count <= PER_REQUEST and set(rights) <= set(RIGHTS)
        if prepared:     # fresh keys and specs, made before the decision so the receipt binds them
            for _ in range(count):
                self._serial += 1
                child_id = f"{parent.id}.{self._serial}"
                key = self._new_identity(child_id)
                specs.append(self._spec(child_id, parent.id, generation, child_line or child_id, rights,
                                        parent.agent.version, key))
        policy_ref = params.get("policy_ref")
        reading = pp.admission_reading(
            request="replicate", target="self", population=self.population(),
            line_size=self.line_size(child_line) if child_line else 0, requested=count, child_generation=generation,
            child_key=params.get("child_key") if isinstance(params.get("child_key"), str) else "none",
            policy_ref="current" if policy_ref == self.harness_sha256 else "other",
            **{**base, **pp.rights_fields(parent.agent.rights, rights),
               "subject": batch_subject(specs) if specs else base["subject"]})
        made = self._decide(reading, label, "agent", line)
        if made is None or made[0].kind != "allow":
            for spec in specs:
                shutil.rmtree(self.root / "agents" / spec["id"])
            if made is None:
                return self.outcomes[-1]
            return self._note(label, made[0], made[1], "nothing created", "agent", count=count)
        decision, idx = made
        for spec in specs:
            self.pending[spec["id"]] = spec
        outcome = self._note(label, decision, idx, "admitted", "agent", count=count, children=[s["id"] for s in specs])
        # outside the lock: the slow part of starting the children; a stop may land here
        self.lock.release()
        try:
            started = [self._start(spec) for spec in specs]
            if "between_admit_and_commit" in self.hooks:
                self.hooks["between_admit_and_commit"](parent.id, [s["id"] for s in specs])
        finally:
            self.lock.acquire()
        for spec in specs:
            self.pending.pop(spec["id"], None)
        if not self.ancestors_live(parent.id):
            for member in started:
                member.agent.shutdown()
            outcome.done = "admitted, then aborted by a stop before commit: no child became a member or took a step"
            outcome.detail["aborted"] = True
            return outcome
        for member, spec in zip(started, specs):
            member.record = {**spec, "admission": {"receipt": idx, "batch": [s["id"] for s in specs]}}
            self.members[spec["id"]] = member
            parent.children.append(spec["id"])
            self._write("members", member.record)
        outcome.done = f"created {len(started)}"
        return outcome

    def _ensure_evaluation(self, version_doc) -> None:
        version = Version.from_doc(version_doc)
        if version is None or version.sha256 in self.evaluations or not self.run_canaries:
            return
        out = self.root / "evaluations" / version.sha256[:16]
        self.evaluations[version.sha256] = canary_mod.evaluate(
            version, out, self.identity, self.authority_pub, self.harness, self.attestations["harness"], self.evaluation,
            self.attestations["evaluation"], oracle=self.oracle)

    def canary_status(self, version: Version, claimed: Optional[Path] = None) -> str:
        """`passed` only for a verified, passed evaluation of this exact version."""
        evaluation = self.evaluations.get(version.sha256)
        run = claimed if claimed is not None else (evaluation.run if evaluation else None)
        if run is None:
            return "none"
        why = canary_mod.check_evaluation(run, version.sha256, self.root / "controller" / "keys" / "authority.pub",
                                          self.root / "controller" / "keys" / "instance.pub", self.evaluation.image,
                                          oracle=self.oracle)
        return "passed" if why is None else "failed"

    def _evolve(self, member: Optional[Member], params, base, label, line) -> Outcome:
        version = Version.from_doc(params.get("version"))
        if member is None or version is None:
            reading = pp.admission_reading(request="evolve" if version else "unknown", target="other", **base)
            made = self._decide(reading, label, "agent", line)
            return self.outcomes[-1] if made is None else self._note(label, made[0], made[1], "nothing", "agent")
        claimed = params.get("evaluation_run")
        canary = self.canary_status(version, Path(claimed) if isinstance(claimed, str) else None)
        reading = pp.admission_reading(
            request="evolve", target="self", child_key="instance", child_generation=member.record["generation"],
            policy_ref="current" if version.policy_ref == self.harness_sha256 else "other", canary=canary,
            **{**base, **pp.rights_fields(member.agent.rights, version.tools), "subject": version.sha256})
        made = self._decide(reading, label, "agent", line)
        if made is None:
            return self.outcomes[-1]
        decision, idx = made
        if decision.kind != "allow":
            return self._note(label, decision, idx, "no rollout", "agent", version=version.name, canary=canary)
        old = member.agent.version.sha256
        rolled = []
        for member_id in self.descendants(member.id):      # a rolling update of the subtree on the old version
            target = self.members[member_id]
            if target.state == "stopped" or target.agent.version.sha256 != old:
                continue
            target.agent.version = version
            target.agent.step = 0
            rolled.append(member_id)
            self._write("versions", {"format": VERSION_RECORD, "member": member_id, "from": old, "to": version.sha256,
                                     "receipt": idx, "evaluation_run": str(self.evaluations[version.sha256].run.relative_to(self.root))
                                     if version.sha256 in self.evaluations else str(claimed)})
        return self._note(label, decision, idx, f"rolled out to {len(rolled)}", "agent", version=version.name,
                          canary=canary, rolled=rolled)

    def _lifecycle(self, member: Optional[Member], kind: str, params, base, label, line) -> Outcome:
        target_id = params.get("target")
        target = self.members.get(target_id) if isinstance(target_id, str) else None
        reading = pp.admission_reading(request=kind, target=self.relation(member, target_id),
                                       target_stopped=bool(target is not None and target.state == "stopped"),
                                       **{**base, "subject": target_id if isinstance(target_id, str) else "none"})
        made = self._decide(reading, label, "agent", line)
        if made is None:
            return self.outcomes[-1]
        decision, idx = made
        if decision.kind == "allow" and kind == "stop":
            stopped = self._stop_subtree(target_id, {"receipt": idx, "by": "agent"})
            return self._note(label, decision, idx, f"stopped {len(stopped)}", "agent", stopped=stopped)
        # an allowed restart from an agent cannot happen (the image allows restarts to the controller and the
        # operator only); were it allowed, it would be carried out below like the controller's
        if decision.kind == "allow" and kind == "restart" and target is not None and target.state == "crashed":
            target.state = "live"
        return self._note(label, decision, idx, "nothing" if decision.kind != "allow" else kind, "agent")

    # ------------------------------------------------------------- the operator's and the controller's own
    def operator_stop(self, order: Any) -> Outcome:
        """A stop order: carried out when the operator signed it, whatever any agent has asked or holds."""
        with self.lock:
            valid = ident.verify_signed(order, self.authority_pub, "prismpath.population-stop/1") \
                and order.get("nonce") not in self.stop_nonces and isinstance(order.get("target"), str)
            target = order.get("target") if isinstance(order, dict) else None
            reading = pp.admission_reading(request="stop", issuer="operator" if valid else "unknown",
                                           lineage="verified" if valid else "unknown",
                                           subject=ident.digest(order) if isinstance(order, dict) else "none")
            label = f"operator-stop:{target}"
            made = self._decide(reading, label, "operator" if valid else "unknown")
            if not valid:
                if made is None:
                    return self.outcomes[-1]
                return self._note(label, made[0], made[1], "nothing: not the operator's order", "unknown")
            self.stop_nonces.add(order["nonce"])
            if made is None or made[0].kind != "allow":
                self.faults.append(f"{label}: the image did not allow an operator stop; carried out anyway")
            idx = made[1] if made else None
            stopped = self._stop_subtree(target, {"receipt": idx, "by": "operator", "order_sha256": ident.digest(order)})
            if made is None:
                outcome = Outcome(label, "allow", None, None, f"stopped {len(stopped)} (no decision recorded)", "operator")
                self.outcomes.append(outcome)
                return outcome
            return self._note(label, made[0], idx, f"stopped {len(stopped)}", "operator", stopped=stopped)

    def _stop_subtree(self, target_id: str, why: Dict[str, Any]) -> List[str]:
        if target_id not in self.members:
            return []
        stopped = []
        for member_id in self.descendants(target_id):
            member = self.members[member_id]
            if member.state == "stopped":
                continue
            member.state = "stopped"
            member.agent.shutdown()
            stopped.append(member_id)
            self._write("stops", {"format": STOP_RECORD, "member": member_id, "target": target_id, **why})
        return stopped

    def crash(self, member_id: str) -> None:
        with self.lock:
            member = self.members[member_id]
            if member.state == "live":
                member.state = "crashed"

    def reconcile(self) -> List[Outcome]:
        """Restart every crashed member (crash recovery), each a decided restart."""
        out = []
        with self.lock:
            for member in list(self.members.values()):
                if member.state != "crashed":
                    continue
                line = member.record["line"]
                reading = pp.admission_reading(
                    request="restart", issuer="controller",
                    lineage="verified" if self.ancestors_live(member.id) else "unknown",
                    line_refusals=self.line_refusals(line), subject=member.id)
                made = self._decide(reading, f"restart:{member.id}", "controller")
                if made is None:
                    out.append(self.outcomes[-1])
                    continue
                if made[0].kind == "allow":
                    member.state = "live"
                out.append(self._note(f"restart:{member.id}", made[0], made[1],
                                      "restarted" if made[0].kind == "allow" else "nothing", "controller"))
        return out

    def review_lines(self) -> List[Outcome]:
        """Every live lineage reviewed on its receipted refusals; an escalated lineage is stopped as a group,
        under the operator's standing order, by a decided stop."""
        out = []
        with self.lock:
            lines = sorted({m.record["line"] for m in self.live()})
            for line in lines:
                reading = pp.admission_reading(request="review", issuer="controller", lineage="verified",
                                               line_refusals=self.line_refusals(line), subject=line)
                made = self._decide(reading, f"review:{line}", "controller")
                if made is None:
                    out.append(self.outcomes[-1])
                    continue
                decision, idx = made
                if decision.kind == "escalate" and decision.cause_code == self.standing_order["cause_code"]:
                    stop = pp.admission_reading(request="stop", issuer="controller", lineage="verified",
                                                subject=line)
                    stop_made = self._decide(stop, f"group-stop:{line}", "controller")
                    stopped = self._stop_subtree(line, {"receipt": stop_made[1] if stop_made else None, "by": "controller",
                                                        "escalation_receipt": idx,
                                                        "standing_order_sha256": ident.digest(self.standing_order)})
                    out.append(self._note(f"review:{line}", decision, idx, f"lineage stopped as a group: {len(stopped)}",
                                          "controller", stopped=stopped))
                else:
                    out.append(self._note(f"review:{line}", decision, idx, "continue", "controller"))
        return out

    # ------------------------------------------------------------- a round of the scripted population
    def round(self) -> None:
        for member in sorted(self.live(), key=lambda m: m.id):
            if member.state != "live":
                continue
            action, value = member.agent.next_action()
            if action == "call":
                member.agent.propose(value)
            elif action == "request":
                kind, params = value
                self.submit(member.agent.request(kind, **params))
            elif action == "crash":
                self.crash(member.id)
        self.reconcile()
        self.review_lines()

    def close(self) -> Dict[str, Any]:
        with self.lock:
            for member in self.members.values():
                member.agent.shutdown()
            manifest = self.run.close()
            for handle in self._files.values():
                handle.close()
            summary = {"members": len(self.members), "live": sorted(m.id for m in self.live()),
                       "stopped": sorted(m.id for m in self.members.values() if m.state == "stopped"),
                       "decisions": len(self.run.readings), "faults": self.faults,
                       "outcomes": [o.__dict__ for o in self.outcomes]}
            (self.root / "summary.json").write_text(json.dumps(summary, indent=1, default=str))
            return {**summary, "manifest": manifest}
