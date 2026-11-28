# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The action floor of policy distribution (spec-policy-distribution.md, section 21.2), the operator's answer (21.5)
and the receipts (21.6) in the Python machine.

The action floor is an install set (`prismpath.distribution.install`) that a PEP asks first on every request, in every
state (AF1). It only allows or escalates (AF2): any other answer, a refusal or a request it cannot read, leaves the
floor silent and the decision to what would decide with no floor. This module holds what the PEP machine
(`prismpath.distribution.pep`), the verifier and the sealing tool share:

    read_layout     AF10: the layout document a table kind is built with, each field's register, role, bounds and
                    staleness bound
    narrow          AF9, AF10: whether an action floor statement is narrow, `dist:floor-broad` when it is not
    ask             the answer one set gives one request, in the form of its kind, with the rule that gave it
    Book            AF8, OP3, OP4: the durable rate counts of floor overrides and operator answers, and the open
                    escalations an operator may answer
    read_answer     OP2: the body of an `operator.answer`, and `answer_body` the operator's tool
    receipt         RC1 to RC3: the receipt document of one decision and its hash

A request is the reading the kind's policy reads, as a mapping:

    agent     {"reading": {...}} for the hook and the MCP proxy, {"host": name} for the egress proxy
    gateway   {"path": path, "reading": {...}}, the reading without `path_class`, which each set's routes give
    cfs       {"reading": {...}, "independent": {field: [value, age]}}, the monitor's own value and its age
    host,mesh {"regs": register bytes, "ages": {register: age}}, the age of each independent register's value

The floor reads nothing more (AF6). A field the layout marks independent is taken from `independent`, never from the
proposal, and a rule that tests one whose value is absent or older than its staleness bound is silent (AF10).

Files, beside the install record (IS10), each written whole and in both copies:

    install/rates.json    the rate counts of AF8 and OP4 and the open escalations of OP3
"""
from __future__ import annotations

import functools
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from prismpath import canon
from prismpath.distribution import kinds
from prismpath.distribution.kinds import Refused, is_hex64, is_int

BROAD, RATE, ALLOWED, UNBOUND = "dist:floor-broad", "dist:floor-rate", "dist:floor-allowed", "dist:answer-unbound"
LAYOUT_FORMAT = "prismpath.dist-layout/1"
RATES_FORMAT = "prismpath.dist-rates/1"
RECEIPT_FORMAT = "prismpath.dist-receipt/1"
MAX_RULES = 8                                      # AF9: rules that allow or escalate, zones, hosts, routes
ANSWER_LIFE = 600                                  # OP2, OP3: an answer's lifetime and an escalation's
MAX_OPEN = 8                                       # OP3: the open escalations a PEP holds
ESCALATING = frozenset({"agent", "gateway", "cfs"})        # AF2, OP1: the kinds whose policy form escalates
ROLES = ("command", "parameter", "independent", "proposer")    # AF10
# AF9: the action field of each kind and the tools of an `agent` that change files
ACTION = {"agent": "tool", "gateway": "path_class", "xdp": "net_dest"}
CHANGES = frozenset({"write_file", "delete_path", "git"})
ALLOW, ESCALATE, REFUSE = "allow", "escalate", "refuse"


# ------------------------------------------------------------------ AF10: the layout document

def read_layout(body: bytes) -> dict:
    """AF10: a layout document, the canon/2 list of each field of a table kind's reading: its `name`, its `register`,
    its `role` (the `command`, a `parameter` of it, an `independent` reading of the world the PEP takes from a source
    other than the proposer, or a `proposer`'s reading), its bounds `min` and `max`, and `stale`, the staleness bound
    in seconds of an independent field, which is never 0, and 0 for every other. `Refused` with `dist:bad-format`
    otherwise, and exactly one field is the command."""
    doc = kinds.load_canonical(body, "layout document")
    members = {"encoding", "fields", "format"}
    if not (isinstance(doc, dict) and set(doc) == members and doc["format"] == LAYOUT_FORMAT
            and doc["encoding"] == canon.CANON2 and isinstance(doc["fields"], list) and doc["fields"]):
        raise Refused(kinds.BAD_FORMAT, "not a layout document")
    names, registers = set(), set()
    for one in doc["fields"]:
        if not (isinstance(one, dict) and set(one) == {"max", "min", "name", "register", "role", "stale"}
                and isinstance(one["name"], str) and one["name"] and is_int(one["register"], 0, 255)
                and one["role"] in ROLES and isinstance(one["min"], int) and isinstance(one["max"], int)
                and not isinstance(one["min"], bool) and not isinstance(one["max"], bool) and one["min"] <= one["max"]
                and is_int(one["stale"], 0, 86400) and (one["stale"] > 0) == (one["role"] == "independent")):
            raise Refused(kinds.BAD_FORMAT, "a layout field that does not read, or an independent field whose "
                                            "staleness bound is 0 (AF10)")
        if one["name"] in names or one["register"] in registers:
            raise Refused(kinds.BAD_FORMAT, "a layout that names one field or register twice")
        names.add(one["name"])
        registers.add(one["register"])
    if [one["role"] for one in doc["fields"]].count("command") != 1:
        raise Refused(kinds.BAD_FORMAT, "a layout labels exactly one field as its command")
    return doc


def layout_body(fields: Sequence[Mapping[str, Any]]) -> bytes:
    """The sealing tool's layout document: refused as `read_layout` refuses it, a staleness bound of 0 included."""
    body = canon.canon2_bytes({canon.ENCODING_KEY: canon.CANON2, "format": LAYOUT_FORMAT,
                               "fields": sorted((dict(one) for one in fields), key=lambda one: one["register"])})
    read_layout(body)
    return body


def _by(layout: Optional[dict], key: str) -> Dict[Any, dict]:
    return {} if layout is None else {one[key]: one for one in layout["fields"]}


# ------------------------------------------------------------------ the core form's conditions

def _conjuncts(condition: Any) -> List[Any]:
    """The conjuncts of the whole rule: the operands of a top `and`, flattened."""
    if isinstance(condition, list) and condition and condition[0] == "and":
        return [part for operand in condition[1:] for part in _conjuncts(operand)]
    return [condition]


def _const(value: Any) -> Tuple[bool, Any]:
    if isinstance(value, list) and len(value) == 2 and value[0] in ("str", "bool"):
        return True, value[1]
    if isinstance(value, list) and len(value) == 2 and value[0] == "num" and isinstance(value[1], int) \
            and not isinstance(value[1], bool):
        return True, value[1]
    return False, None


def _equality(conjunct: Any) -> Optional[Tuple[str, Any]]:
    """(field, value) of an equality test of one field against one constant, else None. A set, a range and a
    negation are no equality (AF9)."""
    if isinstance(conjunct, list) and len(conjunct) == 4 and conjunct[0] == "cmp" and conjunct[2] == "==":
        known, value = _const(conjunct[3])
        if known and isinstance(conjunct[1], str):
            return conjunct[1], value
    return None


def _fields(condition: Any) -> List[str]:
    """Every field a condition tests."""
    if not isinstance(condition, list) or not condition:
        return []
    tag = condition[0]
    if tag == "truthy" and len(condition) == 2:
        return [condition[1]]
    if tag in ("cmp", "in", "not in") and len(condition) >= 3:
        out = [condition[1]]
        values = condition[3:] if tag == "cmp" else condition[2]
        out += [value[1] for value in values if isinstance(value, list) and value[:1] == ["field"]]
        return out
    if tag in ("not", "and", "or"):
        return [name for operand in condition[1:] for name in _fields(operand)]
    return []


def _bounds(conjuncts: Sequence[Any], name: str) -> Tuple[Optional[int], Optional[int]]:
    """The lower and the upper bound the conjuncts put on the int field `name`, each None when none does. An
    equality bounds it from both sides."""
    low = high = None
    for conjunct in conjuncts:
        if not (isinstance(conjunct, list) and len(conjunct) == 4 and conjunct[0] == "cmp" and conjunct[1] == name):
            continue
        known, value = _const(conjunct[3])
        if not known or not isinstance(value, int) or isinstance(value, bool):
            continue
        op = conjunct[2]
        if op in ("==", ">=", ">"):
            bound = value + (1 if op == ">" else 0)
            low = bound if low is None else max(low, bound)
        if op in ("==", "<=", "<"):
            bound = value - (1 if op == "<" else 0)
            high = bound if high is None else min(high, bound)
    return low, high


def _bounded(conjuncts: Sequence[Any], name: str, field_min: int, field_max: int) -> bool:
    """AF9: the field is bounded from both sides, and the bound is not its whole domain."""
    low, high = _bounds(conjuncts, name)
    return low is not None and high is not None and not (low <= field_min and high >= field_max)


def _target(rule: Any) -> Optional[str]:
    from prismpath.kernel.decision import target_decision
    target = rule.get("target") if isinstance(rule, dict) else None
    decision = target_decision(target) if isinstance(target, str) else None
    return None if decision is None else decision[0]


def _core_doc(image: bytes) -> dict:
    from prismpath.kernel import canon2
    try:
        doc = canon2.loads(bytes(image).rstrip(b"\n"))
    except Exception:  # noqa: BLE001 - an image that does not read is the artifact check's to refuse
        raise Refused(BROAD, "the floor's policy does not read") from None
    if not isinstance(doc, dict) or not isinstance(doc.get("rules"), list):
        raise Refused(BROAD, "the floor's policy holds no rule list")
    return doc


def zone_problem(when: Any) -> bool:
    """AF1: `domain.name_problem`, a test of `zone_name` that is not an equality with one readable name."""
    from prismpath.kernel import domain
    return domain.name_problem(when, domain.AGENT_DOMAIN)


def _core_rule_problem(kind: str, rule: dict, layout: Optional[dict]) -> Optional[str]:
    """AF9 and AF10 for one rule of a core policy that allows or escalates, None when it is narrow."""
    when = rule.get("when")
    conjuncts = _conjuncts(when)
    equal = dict(one for one in (_equality(conjunct) for conjunct in conjuncts) if one is not None)
    tested = set(_fields(when))
    if kind == "cfs":
        by_name = _by(layout, "name")
        command = next(one["name"] for one in layout["fields"] if one["role"] == "command")
        if command not in equal:
            return f"the rule tests the command field `{command}` for equality with one value as no conjunct"
        for name in tested:
            if name not in by_name or by_name[name]["role"] == "proposer":
                return f"the rule tests `{name}`, which the layout does not mark independent (AF10)"
        for one in layout["fields"]:
            if one["role"] == "parameter" and one["max"] - one["min"] > 1 and not _bounded(
                    conjuncts, one["name"], one["min"], one["max"]):
                return f"the rule does not bound the parameter `{one['name']}` from both sides"
        return None
    action = ACTION[kind]
    if action not in equal:
        return f"the rule tests `{action}` for equality with one value as no conjunct of the whole rule"
    value = equal[action]
    if kind == "agent":
        if value == "unknown":
            return "a floor never allows the tool `unknown`"
        command = equal.get("command_class")
        if value == "run_command" and (command is None or command == "unknown"):
            return "`run_command` needs an equality test of `command_class` against a value other than `unknown`"
        if value in CHANGES or (value == "run_command" and command in ("mutating", "git")):
            scope = equal.get("path_scope")
            if scope is None or scope == "unknown":
                return f"`{value}` needs an equality test of `path_scope` against a value other than `unknown`"
            if not any("path_control" in _fields(conjunct) for conjunct in conjuncts):
                return f"`{value}` needs a test of `path_control`"
    if kind == "gateway":
        if value in ("other", "unknown") or equal.get("method_class") in (None, "other", "unknown"):
            return "a gateway floor rule tests `path_class` and `method_class` for equality, never `other` or `unknown`"
    if kind == "xdp" and value in ("other", "unknown"):
        return "an xdp floor rule tests the destination class `net_dest` for equality, never `other` or `unknown`"
    return None


def narrow_core(kind: str, image: bytes, layout: Optional[dict] = None) -> Optional[str]:
    """AF9, AF10 for the `policy.core` of an `agent` or a `gateway` floor or the core image of a `cfs.table` floor.
    None when it is narrow, else `dist:floor-broad` (or `policy:out-of-domain` for a test of `zone_name` that is not
    an equality with one name, AF1)."""
    doc = _core_doc(image)
    if any(zone_problem(rule.get("when")) for rule in doc["rules"] if isinstance(rule, dict)):
        return "policy:out-of-domain"
    deciding = [rule for rule in doc["rules"] if _target(rule) in (ALLOW, ESCALATE)]
    if len(deciding) > MAX_RULES:
        return BROAD
    for rule in deciding:
        problem = _core_rule_problem(kind, rule, layout)
        if problem == "policy:out-of-domain":
            return problem
        if problem is not None:
            return BROAD
    return None


def can_escalate(image: bytes) -> bool:
    """OP4: a core policy with a rule that escalates."""
    try:
        return any(_target(rule) == ESCALATE for rule in _core_doc(image)["rules"])
    except Refused:
        return False


# ------------------------------------------------------------------ the table form (host, mesh)

def _program(image: bytes, offset: int, count: int, words: int) -> Any:
    """The tree of one edge program: ("atom", index), ("not", t), ("and", a, b), ("or", a, b), ("const", bool)."""
    from prismpath.distribution.adapters import mesh
    from prismpath.hotswap import policy_pack
    stack: List[Any] = []
    for position in range(count):
        (word,) = policy_pack.WORD.unpack_from(image, words + policy_pack.WORD.size * (offset + position))
        if word < 0x8000:
            stack.append(("atom", word))
        elif word in (mesh.OPC_TRUE, mesh.OPC_FALSE):
            stack.append(("const", word == mesh.OPC_TRUE))
        elif word == mesh.OPC_NOT and stack:
            stack[-1] = ("not", stack[-1])
        elif word in (mesh.OPC_AND, mesh.OPC_OR) and len(stack) >= 2:
            right = stack.pop()
            stack[-1] = ("and" if word == mesh.OPC_AND else "or", stack[-1], right)
        else:
            raise Refused(BROAD, "a floor edge whose program does not read")
    if len(stack) != 1:
        raise Refused(BROAD, "a floor edge whose program does not leave one value")
    return stack[0]


def _tree_conjuncts(tree: Any) -> List[Any]:
    if tree[0] == "and":
        return _tree_conjuncts(tree[1]) + _tree_conjuncts(tree[2])
    return [tree]


def _tree_atoms(tree: Any) -> List[int]:
    if tree[0] == "atom":
        return [tree[1]]
    if tree[0] == "const":
        return []
    return [index for part in tree[1:] for index in _tree_atoms(part)]


@dataclass(frozen=True)
class Table:
    """A `.ppt` table read for the floor: its start node and, per edge of it, the target, the program tree and the
    atoms (register, op, type, value) the program reads."""
    start: int
    nodes: int
    decision_nodes: Tuple[int, ...]
    edges: Tuple[Tuple[int, Any], ...]
    atoms: Tuple[Tuple[int, int, int, int], ...]


def read_table(image: bytes) -> Table:
    from prismpath.hotswap import policy_pack
    try:
        header = policy_pack.read_ppt_header(image)
    except ValueError:
        raise Refused(BROAD, "the floor's table does not read") from None
    atoms_at = policy_pack.HEADER.size
    nodes_at = atoms_at + policy_pack.ATOM.size * header["atoms"]
    edges_at = nodes_at + policy_pack.NODE.size * header["nodes"]
    words_at = edges_at + policy_pack.EDGE.size * header["edges"]
    atoms = tuple(policy_pack.ATOM.unpack_from(image, atoms_at + policy_pack.ATOM.size * index)
                  for index in range(header["atoms"]))
    deciding, edges = [], []
    for node in range(header["nodes"]):
        offset, count = policy_pack.NODE.unpack_from(image, nodes_at + policy_pack.NODE.size * node)
        if count:
            deciding.append(node)
        if node != header["start"]:
            continue
        for index in range(count):
            target, program_offset, program_count = policy_pack.EDGE.unpack_from(
                image, edges_at + policy_pack.EDGE.size * (offset + index))
            edges.append((target, _program(image, program_offset, program_count, words_at)))
    return Table(header["start"], header["nodes"], tuple(deciding), tuple(edges), atoms)


def narrow_table(image: bytes, command: Any, layout: Optional[dict]) -> Optional[str]:
    """AF9, AF10 for the `policy.ppt` of a `host` or a `mesh` floor. There is one decision node, the start node, and
    each of its edges is a rule: at most 8, each with an equality test of the command register against one value as a
    conjunct of the whole program, each parameter register bounded from both sides by less than its whole domain,
    and no test of a register the layout does not label or marks the proposer's. `command` is the register the
    floor's `meta` names, which is the one the layout labels its command field. None when it is narrow."""
    from prismpath.distribution.adapters import mesh
    if layout is None:
        return BROAD
    by_register = _by(layout, "register")
    labelled = next(one["register"] for one in layout["fields"] if one["role"] == "command")
    if command != labelled:
        return BROAD
    try:
        table = read_table(image)
    except Refused:
        return BROAD
    if table.decision_nodes != (table.start,) or not table.edges or len(table.edges) > MAX_RULES:
        return BROAD
    for _target_node, tree in table.edges:
        conjuncts = _tree_conjuncts(tree)
        tests = []
        for conjunct in conjuncts:
            if conjunct[0] == "atom":
                register, op, kind, value = table.atoms[conjunct[1]]
                tests.append((register, op, kind, value))
        if not any(register == labelled and op == mesh.OP_EQ and kind == mesh.TY_INT for register, op, kind, _v in tests):
            return BROAD
        for index in _tree_atoms(tree):
            register = table.atoms[index][0]
            if register not in by_register or by_register[register]["role"] == "proposer":
                return BROAD
        for one in layout["fields"]:
            if one["role"] != "parameter":
                continue
            low = high = None
            for register, op, kind, value in tests:
                if register != one["register"] or kind != mesh.TY_INT:
                    continue
                if op in (mesh.OP_EQ, mesh.OP_GE, mesh.OP_GT):
                    bound = value + (1 if op == mesh.OP_GT else 0)
                    low = bound if low is None else max(low, bound)
                if op in (mesh.OP_EQ, mesh.OP_LE, mesh.OP_LT):
                    bound = value - (1 if op == mesh.OP_LT else 0)
                    high = bound if high is None else min(high, bound)
            if low is None or high is None or (low <= one["min"] and high >= one["max"]):
                return BROAD
    return None


# ------------------------------------------------------------------ AF9 for one statement

def narrow(kind: str, named: str, body: bytes, meta: Mapping[str, Any], layout: Optional[bytes]) -> Optional[str]:
    """AF9, AF10: the narrowness of one statement of an action floor whose `as` is `named`, as a PEP checks it at IS5
    and the sealing tool and a controller check it before. None when it is narrow. A table floor names the layout the
    PEP was built with (`dist:target-mismatch` otherwise) and a PEP built with none takes no table floor."""
    if named == "egress.hosts":
        listed = kinds.load_canonical(body, "egress.hosts")
        if isinstance(listed, list) and (len(listed) > MAX_RULES or any(
                not isinstance(host, str) or "*" in host or "." not in host.strip(".") for host in listed)):
            return BROAD                               # AF9: at most 8 entries, each one full name
        kinds.read_hosts(body)
        return None
    if named == "net.dests" and kind == "xdp":
        table = kinds.load_canonical(body, "net.dests")
        classes = [hosts for name, hosts in table.items() if name != "format"] if isinstance(table, dict) else [None]
        if not all(isinstance(hosts, dict) for hosts in classes):
            return BROAD
        entries = [(host, addresses) for hosts in classes for host, addresses in hosts.items()]
        if len(entries) > MAX_RULES or any(not isinstance(host, str) or "*" in host or "." not in host.strip(".")
                                           or not isinstance(addresses, list) or len(addresses) != 1
                                           for host, addresses in entries):
            return BROAD                               # AF9: at most 8 entries, each one full name at one address
        return None
    if named == "net.edge" and kind == "xdp":
        return None                                    # AF9: held byte for byte to what the two above compile to (V11)
    if named == "gateway.routes":
        routes = kinds.read_routes(body)
        return BROAD if len(routes.entries) > MAX_RULES or any(prefix for _b, prefix, _n in routes.entries) else None
    if named == "policy.core":
        return narrow_core(kind, body) if kind in ACTION else BROAD
    if named in ("policy.ppt", "cfs.table"):
        if layout is None or meta.get("layout") != canon.sha256_hex(layout):
            return "dist:target-mismatch"
        read = read_layout(layout)
        if named == "cfs.table":
            from integrations.cfs.ground import table
            labelled = next(one["register"] for one in read["fields"] if one["role"] == "command")
            if meta.get("command") != labelled:
                return BROAD                           # AF9: the command the floor names is the layout's
            image = bytes(body[table.OFF["Image"]:table.OFF["Image"] + table.u16(body, "ImageLen")])
            try:
                compiled = read_table(image)
            except Refused:
                return BROAD
            if compiled.decision_nodes != (compiled.start,):
                return BROAD                           # AF9: a table with more than one decision node
            return narrow_core("cfs", table.core_of(body), read)
        return narrow_table(body, meta.get("command"), read)
    if named == "policy.spiral":
        return None
    return BROAD


def needs_answer_rate(kind: str, named: str, body: bytes, meta: Mapping[str, Any]) -> bool:
    """OP4: a floor that can escalate, on a kind with escalation, carries `answer_rate`. It can escalate when its
    policy holds a rule that escalates or when it has a `rate`, past which it escalates an override (AF8)."""
    if kind not in ESCALATING:
        return False
    if "rate" in meta:
        return True
    if named == "policy.core":
        return can_escalate(body)
    if named == "cfs.table":
        from integrations.cfs.ground import table
        return can_escalate(table.core_of(body))
    return False


# ------------------------------------------------------------------ ask: one set, one request

@dataclass(frozen=True)
class Answer:
    """What one set answers one request: `allow`, `escalate` or `refuse`, or None when it cannot read it, with the
    cause, the rule that answered (the count key of AF8), the zone a floor rule overrode (AF1), and whether that rule
    is one the floor may only allow, a host list's entry or a table's edge (AF2)."""
    outcome: Optional[str]
    cause: Optional[str] = None
    rule: Optional[str] = None
    zone: Optional[str] = None
    allow_only: bool = False

    def document(self, policy_sha256: Optional[str]) -> dict:
        if self.outcome is None:
            return {"outcome": "none"}
        return {"cause": self.cause, "outcome": self.outcome, "policy_sha256": policy_sha256}


SILENT = Answer(None)


@functools.lru_cache(maxsize=64)
def _policy(image: bytes):
    from prismpath.kernel.decision import Policy
    from prismpath.kernel.domain import AGENT_DOMAIN
    return Policy(bytes(image), AGENT_DOMAIN)


def _hold(condition: Any, reading: Mapping[str, Any]) -> Optional[bool]:
    """A core condition on `reading`, None where this reader cannot tell. Only the rule that answered is taken from it,
    and the answer itself is the reference decision path's."""
    if not isinstance(condition, list) or not condition:
        return None
    tag = condition[0]
    if tag in ("always",):
        return True
    if tag in ("never",):
        return False
    if tag == "truthy" and len(condition) == 2:
        value = reading.get(condition[1])
        return None if value is None else bool(value)
    if tag == "cmp" and len(condition) == 4:
        known, value = _const(condition[3])
        if not known or condition[1] not in reading:
            return None
        have = reading[condition[1]]
        op = condition[2]
        if op in ("==", "!="):
            return (have == value and type(have) is type(value)) == (op == "==")
        if not all(isinstance(one, int) and not isinstance(one, bool) for one in (have, value)):
            return None
        return {"<": have < value, "<=": have <= value, ">": have > value, ">=": have >= value}.get(op)
    if tag in ("in", "not in") and len(condition) == 3 and isinstance(condition[2], list):
        if condition[1] not in reading:
            return None
        values = [_const(one) for one in condition[2]]
        if not all(known for known, _v in values):
            return None
        inside = any(reading[condition[1]] == value and type(reading[condition[1]]) is type(value) for _k, value in values)
        return inside == (tag == "in")
    if tag == "not" and len(condition) == 2:
        inner = _hold(condition[1], reading)
        return None if inner is None else not inner
    if tag in ("and", "or"):
        parts = [_hold(operand, reading) for operand in condition[1:]]
        if tag == "and":
            return False if False in parts else (None if None in parts else True)
        return True if True in parts else (None if None in parts else False)
    return None


def _ask_core(image: bytes, reading: Mapping[str, Any], name: str) -> Tuple[Answer, Optional[dict]]:
    """The reference decision of a core policy on `reading`, and the rule that made it, the first whose condition
    holds. The answer is the reference path's, and a rule this reader cannot find for it leaves the rule None."""
    try:
        policy = _policy(bytes(image))
        decision = policy.decide(policy.reading_bytes(dict(reading)))
    except Exception:  # noqa: BLE001 - a request the policy cannot read is no answer
        return SILENT, None
    for index, rule in enumerate(policy.doc["rules"]):
        held = _hold(rule.get("when"), reading)
        if held is None:
            break
        if held:
            if _target(rule) == decision.kind and (decision.kind == ALLOW or decision.verdict.get("target") == rule.get("target")):
                return Answer(decision.kind, decision.cause, f"{name}:{index}"), rule
            break
    return Answer(decision.kind, decision.cause), None


def _table_answer(image: bytes, regs: bytes) -> Tuple[Answer, Optional[int]]:
    from prismpath.distribution.adapters import mesh
    from prismpath.hotswap import policy_pack
    try:
        start = policy_pack.read_ppt_header(image)["start"]
        step = mesh.evaluate(image, regs, start)
    except (ValueError, IndexError, KeyError, mesh.EvalError):
        return SILENT, None
    if step is None:
        return Answer(REFUSE, "route:no-matching-edge"), None
    return Answer(ALLOW, None, f"policy.ppt:{step[0]}", allow_only=True), step[0]


def _independent(request: Mapping[str, Any], layout: Optional[dict], reading: Dict[str, Any]) -> Tuple[Dict[str, Any], set]:
    """AF10: the reading with each independent field taken from its own source, and the fields whose value is absent
    or older than its staleness bound."""
    out, stale = dict(reading), set()
    given = request.get("independent") or {}
    for one in (layout or {"fields": []})["fields"]:
        if one["role"] != "independent":
            continue
        name = one["name"]
        out.pop(name, None)
        value = given.get(name)
        if not (isinstance(value, (list, tuple)) and len(value) == 2) or not isinstance(value[1], (int, float)) \
                or value[1] > one["stale"] or value[1] < 0:
            stale.add(name)
            continue
        out[name] = value[0]
    return out, stale


def ask(kind: str, bodies: Mapping[str, bytes], request: Mapping[str, Any], *, floor: bool = False,
        layout: Optional[bytes] = None, ceiling_names: Sequence[str] = ()) -> Answer:
    """The answer of the set `bodies`, in the form of a release of `kind`, to `request`. With `floor` the set is an
    action floor and only its narrow reading counts: an `agent` floor rule that answers a call reaching a protected
    zone tests `zone_reach` for `protected` and `zone_name` for that one name, which no ceiling name is, and is silent
    otherwise and whenever `zone_reach` is `unknown` (AF1); its `connect` reaches only a host of its own
    `egress.hosts` (AF9); and a rule that tests an independent field with no fresh value is silent (AF10)."""
    read = read_layout(layout) if layout is not None and kind in ("cfs", "host", "mesh") else None
    if kind in ("host", "mesh"):
        image = bodies.get("policy.ppt")
        regs = request.get("regs")
        if image is None or not isinstance(regs, (bytes, bytearray)):
            return SILENT
        answer, edge = _table_answer(bytes(image), bytes(regs))
        if floor and edge is not None and read is not None:
            table = read_table(bytes(image))
            ages = request.get("ages") or {}
            by_register = _by(read, "register")
            for index in _tree_atoms(table.edges[edge][1]):
                one = by_register.get(table.atoms[index][0])
                if one is not None and one["role"] == "independent":
                    age = ages.get(one["register"])
                    if not isinstance(age, (int, float)) or age < 0 or age > one["stale"]:
                        return SILENT
        return answer
    if kind == "agent" and "host" in request:
        hosts = bodies.get("egress.hosts")
        host = request.get("host")
        if hosts is None or not isinstance(host, str):
            return SILENT
        listed = host in kinds.read_hosts(bytes(hosts))
        return Answer(ALLOW, None, f"egress.hosts:{host}", allow_only=True) if listed else Answer(REFUSE, None)
    reading = dict(request.get("reading") or {})
    if kind == "gateway":
        routes = bodies.get("gateway.routes")
        path = request.get("path")
        if routes is None or not isinstance(path, str):
            return SILENT
        path_class = kinds.read_routes(bytes(routes)).classify(path)
        if floor and path_class in ("other", "unknown"):
            return SILENT
        reading["path_class"] = path_class
        image = bodies.get("policy.core")
        name = "policy.core"
    elif kind == "cfs":
        from integrations.cfs.ground import table
        data = bodies.get("cfs.table")
        if data is None:
            return SILENT
        image, name = table.core_of(bytes(data)), "cfs.table"
        stale: set = set()
        if floor:
            reading, stale = _independent(request, read, reading)
    else:
        image, name = bodies.get("policy.core"), "policy.core"
    if image is None:
        return SILENT
    answer, rule = _ask_core(bytes(image), reading, name)
    if not floor or answer.outcome not in (ALLOW, ESCALATE):
        return answer
    if rule is None:
        return SILENT                                  # the floor answers only by a rule it can name (AF8)
    tested = set(_fields(rule.get("when")))
    if kind == "cfs" and tested & stale:
        return SILENT                                  # AF10
    if kind == "agent":
        equal = dict(one for one in (_equality(conjunct) for conjunct in _conjuncts(rule.get("when"))) if one is not None)
        reach = reading.get("zone_reach", "none")
        zone = None
        if reach == "unknown":
            return SILENT
        if reach == "protected":
            zone = equal.get("zone_name")
            if equal.get("zone_reach") != "protected" or not isinstance(zone, str) or not zone \
                    or reading.get("zone_name") != zone or zone in set(ceiling_names):
                return SILENT
        if equal.get("tool") == "connect":
            hosts = bodies.get("egress.hosts")
            host = request.get("connect_host")
            if hosts is None or not isinstance(host, str) or host not in kinds.read_hosts(bytes(hosts)):
                return SILENT
        return Answer(answer.outcome, answer.cause, answer.rule, zone)
    return answer


# ------------------------------------------------------------------ OP2: the operator's answer

def read_answer(body: bytes) -> dict:
    """OP2: the body of an `operator.answer` (`kinds.read_answer`)."""
    return kinds.read_answer(body)


def answer_body(answer: str, pep: str, receipt: str) -> bytes:
    """The operator's tool: the canon/2 body of an answer to the escalation whose receipt hash is `receipt`."""
    body = canon.canon2_bytes({"answer": answer, canon.ENCODING_KEY: canon.CANON2, "format": kinds.ANSWER_FORMAT,
                               "pep": pep, "receipt": receipt})
    kinds.read_answer(body)
    return body


# ------------------------------------------------------------------ RC1 to RC3: the receipt

def receipt(doc: Mapping[str, Any]) -> Tuple[bytes, str]:
    """The canon/2 bytes of a receipt and its SHA-256, which an operator's answer names (OP2)."""
    data = canon.canon2_bytes({"format": RECEIPT_FORMAT, **{key: value for key, value in doc.items() if value is not None}})
    return data, canon.sha256_hex(data)


# ------------------------------------------------------------------ AF8, OP3, OP4: the durable counts

@dataclass
class Book:
    """The rate counts and the open escalations of one PEP, kept beside its install record in both copies (IS10,
    AF8). `rules` maps a floor rule to [window start, overrides counted in it], `answers` is [window start, operator
    allows counted in it], and `open` the open escalations oldest first, each {receipt, at, policy_sha256, answered}.
    Every change is written before the PEP acts on it."""
    paths: Tuple[str, str]
    rules: Dict[str, List[int]] = field(default_factory=dict)
    answers: List[int] = field(default_factory=lambda: [0, 0])
    open: List[dict] = field(default_factory=list)

    @classmethod
    def load(cls, paths: Tuple[str, str]) -> "Book":
        for path in paths:
            try:
                with open(path, "rb") as handle:
                    doc = kinds.load_canonical(handle.read(), "rate counts")
                if not (isinstance(doc, dict) and doc.get("format") == RATES_FORMAT):
                    continue
                return cls(paths, {key: list(value) for key, value in doc["rules"].items()}, list(doc["answers"]),
                           [dict(one) for one in doc["open"]])
            except (OSError, Refused, KeyError, TypeError, ValueError):
                continue
        return cls(paths)

    def save(self) -> None:
        data = canon.canon2_bytes({canon.ENCODING_KEY: canon.CANON2, "format": RATES_FORMAT, "answers": self.answers,
                                   "open": self.open, "rules": self.rules})
        for path in self.paths:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            canon.atomic_write_bytes(path, data)
            canon.fsync_dir(os.path.dirname(path))

    @staticmethod
    def _window(slot: List[int], rate: Mapping[str, int], now: int) -> List[int]:
        """A fixed window of the PEP's own time: a new one starts once `window` seconds passed since the start. A time
        before the start, a clock set back, keeps the window and its count, so it never grants a fresh allowance."""
        start, count = slot
        if count == 0 or now >= start + rate["window"]:
            return [now, 0]
        return [start, count]

    def spend(self, rule: str, rate: Mapping[str, int], now: int) -> Optional[Tuple[int, int]]:
        """AF8: count one override of `rule` under `rate`, durably, and answer (window start, count after it), or None
        when the rate is spent and nothing was counted."""
        start, count = self._window(self.rules.get(rule, [0, 0]), rate, now)
        if count >= rate["allows"]:
            return None
        self.rules[rule] = [start, count + 1]
        self.save()
        return start, count + 1

    def spend_answer(self, rate: Mapping[str, int], now: int) -> Optional[Tuple[int, int]]:
        """OP4: count one operator `allow` for the whole PEP, durably, or None past the rate."""
        start, count = self._window(self.answers, rate, now)
        if count >= rate["allows"]:
            return None
        self.answers = [start, count + 1]
        self.save()
        return start, count + 1

    def escalated(self, receipt_sha256: str, policy_sha256: str, now: int) -> None:
        """OP3: an escalation by the action floor opens, the oldest of nine dropped."""
        self.open = [one for one in self.open if not one["answered"]][-(MAX_OPEN - 1):] + [
            {"answered": False, "at": now, "policy_sha256": policy_sha256, "receipt": receipt_sha256}]
        self.save()

    def find(self, receipt_sha256: str, policy_sha256: Optional[str], now: int) -> Optional[dict]:
        """OP2: the open escalation `receipt_sha256` names, made under the floor of `policy_sha256` the PEP still holds,
        not answered and not older than 600 seconds, else None."""
        for one in self.open:
            if (one["receipt"] == receipt_sha256 and not one["answered"] and one["policy_sha256"] == policy_sha256
                    and 0 <= now - one["at"] <= ANSWER_LIFE):
                return one
        return None

    def answered(self, one: dict) -> None:
        """OP3: the escalation is written as answered before the PEP acts on its answer."""
        one["answered"] = True
        self.save()


__all__ = ["read_layout", "layout_body", "narrow", "narrow_core", "narrow_table", "needs_answer_rate", "ask",
           "Answer", "SILENT", "read_answer", "answer_body", "receipt", "Book", "BROAD", "RATE", "ALLOWED", "UNBOUND"]
