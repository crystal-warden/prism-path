# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Worker-contract derivation tests (roadmap item 1) — extract per-node output schemas from `when`
edges, infer types, generate grammars, and type-gate worker outputs."""
import os

from prismpath.kernel import contract
from prismpath.kernel.parser import parse, parse_file

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _c(flow_body, node="n"):
    return contract.derive_contract(parse(flow_body))[node]


TYPES_FLOW = """---
name: t
start: n
---
## n
Do it.
-> a: when tests_pass
-> b: when not blocked
-> c: when visits < 4 and error_count >= 2
-> d: when action == "contain"
-> e: when action in ["watch", "ignore"]
-> f: when amount > 500
-> g: when priority == 3
-> h: the semantic one
## a
## b
## c
## d
## e
## f
## g
## h
"""


def test_type_inference_across_operators():
    field_types = _c(TYPES_FLOW)
    assert field_types["tests_pass"] == {"type": "boolean"}
    assert field_types["blocked"] == {"type": "boolean"}              # `not blocked`
    assert field_types["amount"] == {"type": "number"}               # `> 500` is a range -> no closed value set
    assert field_types["priority"] == {"type": "number", "values": [3]}   # `== 3` is a numeric enum -> keep the value
    assert field_types["action"]["type"] == "enum"
    assert field_types["action"]["values"] == ["contain", "ignore", "watch"]   # accumulated + sorted across edges


def test_numeric_enum_vs_numeric_range():
    # a field compared only by equality keeps its value set (numeric enum); a ranged field does not,
    # and mixing the two makes it ranged (a range subsumes the points).
    assert _c("---\nname:t\nstart:n\n---\n## n\nGo.\n-> a: when p == 1\n-> b: when p == 2\n## a\n## b\n")["p"] \
        == {"type": "number", "values": [1, 2]}
    assert _c("---\nname:t\nstart:n\n---\n## n\nGo.\n-> a: when p == 1\n-> b: when p > 5\n## a\n## b\n")["p"] \
        == {"type": "number"}                              # ranged -> value set suppressed


def test_mixed_and_empty_in_lists_are_unknown_not_string_enum():
    # a mixed-type or empty `in` list has no clean single type; don't fabricate a string enum
    assert _c('---\nname:t\nstart:n\n---\n## n\nGo.\n-> a: when x in [1, "a"]\n## a\n')["x"]["type"] == "unknown"
    assert _c('---\nname:t\nstart:n\n---\n## n\nGo.\n-> a: when x in []\n## a\n')["x"]["type"] == "unknown"


def test_engine_fields_excluded():
    field_types = _c(TYPES_FLOW)
    assert "visits" not in field_types and "error_count" not in field_types     # engine-provided, not the worker's contract


def test_conflict_flagged():
    field_types = _c("""---
name: t
start: n
---
## n
Do it.
-> a: when done
-> b: when done == "yes"
## a
## b
""")
    assert field_types["done"].get("conflict")                        # used as boolean AND enum


def test_nodes_without_deterministic_edges_are_empty():
    field_types = contract.derive_contract(parse("""---
name: t
start: n
---
## n
Do it.
-> a: it looks good
-> b: on error
## a
## b
"""))
    assert field_types["n"] == {}                                     # all semantic/error -> nothing to constrain


def test_to_json_schema_is_a_constrained_grammar():
    sch = contract.to_json_schema(_c(TYPES_FLOW))
    assert sch["type"] == "object"
    assert sch["properties"]["tests_pass"] == {"type": "boolean"}
    assert sch["properties"]["amount"] == {"type": "number"}
    assert sch["properties"]["action"] == {"type": "string", "enum": ["contain", "ignore", "watch"]}
    assert "action" in sch["required"] and "tests_pass" in sch["required"]


def test_validate_output_type_gate():
    node = _c(TYPES_FLOW)
    # a good output: right types, routed enum value
    good = {"tests_pass": True, "blocked": False, "action": "contain", "amount": 600, "priority": 3}
    probs = [problem for problem in contract.validate_output(node, good) if problem.startswith("type:")]
    assert probs == []
    # wrong types -> hard `type:` problems
    bad = contract.validate_output(node, {"tests_pass": "yes", "amount": "600", "action": "contain"})
    assert any("tests_pass" in problem and problem.startswith("type:") for problem in bad)
    assert any("amount" in problem and problem.startswith("type:") for problem in bad)
    # an enum value no edge routes on -> soft note (falls through), not a type error
    note = contract.validate_output(node, {"action": "escalate"})
    assert any("escalate" in problem and problem.startswith("note:") for problem in note)


def test_engine_type_gate_stops_on_wrong_type():
    from prismpath.kernel.engine import run
    graph = parse("---\nname:t\nstart:work\n---\n## work\nGo.\n-> review: when tests_pass\n"
              "-> work: when not tests_pass\n## review\n## done\n")

    def bad(node, instr, state):
        return {"text": "done", "tests_pass": "yes"}          # string where a boolean is read

    result = run(graph, bad, type_gate=True, max_steps=5)
    assert result.stopped == "contract_violation"
    assert any("tests_pass" in violation for violation in result.pending["violations"])
    # OFF: the string "yes" is truthy, so it SILENTLY routes to review — the bug the gate catches
    assert run(graph, bad, type_gate=False, max_steps=5).stopped == "terminal"

    def good(node, instr, state):
        return {"text": "done", "tests_pass": True} if node == "work" else {"text": node}

    assert run(graph, good, type_gate=True, max_steps=5).stopped == "terminal"


def test_run_durable_passes_type_gate(tmp_path):
    from prismpath.ledgers import checkpoint
    flow = tmp_path / "f.md"
    flow.write_text("---\nname:t\nstart:work\n---\n## work\nGo.\n-> done: when ok\n## done\n")
    res = checkpoint.run_durable(str(flow), lambda node, instruction, state: {"text": "x", "ok": 1}, str(tmp_path / "c.json"),
                                 type_gate=True)
    assert res.stopped == "contract_violation"                # ok=1 (int) where a boolean is read


def _codes(flow):
    from prismpath.kernel import analysis
    return sorted({finding.code for finding in analysis.analyze(parse(flow))})


def test_declared_emits_parsing():
    graph = parse("---\nname:t\nstart:n\n---\n## n\nGo.\n@emits(action, level=number)\n-> a: when action == \"go\"\n## a\n")
    assert contract.declared_emits(graph.nodes["n"]) == {"action", "level"}
    # a node with no @emits -> None (declarations are opt-in), not an empty set
    g2 = parse("---\nname:t\nstart:n\n---\n## n\nGo.\n-> a: when x\n## a\n")
    assert contract.declared_emits(g2.nodes["n"]) is None


def test_provenance_lint_flags_read_but_undeclared_fields():
    # `severity` is read by an edge but not in @emits -> undeclared-field warning
    flagged = _codes("---\nname:t\nstart:n\n---\n## n\nGo.\n@emits(action)\n"
                     "-> a: when action == \"go\"\n-> b: when severity == \"high\"\n-> c: else\n## a\n## b\n## c\n")
    assert "undeclared-field" in flagged
    # fully-declared -> no provenance warning
    ok = _codes("---\nname:t\nstart:n\n---\n## n\nGo.\n@emits(action, severity)\n"
                "-> a: when action == \"go\"\n-> b: when severity == \"high\"\n-> c: else\n## a\n## b\n## c\n")
    assert "undeclared-field" not in ok


def test_field_only_security_lint():
    # a @field_only node routing on raw text (a semantic edge) is a violation
    bad = _codes("---\nname:t\nstart:n\n---\n## n\nGo.\n@emits(action)\n@field_only()\n"
                 "-> a: when action == \"go\"\n-> b: it looks risky\n## a\n## b\n")
    assert "field-only-violation" in bad
    # a well-formed field-only node (declared fields only, exhaustive `else`, no semantic edge) is clean
    good = _codes("---\nname:t\nstart:n\n---\n## n\nGo.\n@emits(action)\n@field_only()\n"
                  "-> a: when action == \"go\"\n-> b: else\n## a\n## b\n")
    assert "field-only-violation" not in good and "undeclared-field" not in good
    # @field_only WITHOUT @emits cannot be enforced -> violation
    nodecl = _codes("---\nname:t\nstart:n\n---\n## n\nGo.\n@field_only()\n-> a: when action == \"go\"\n-> b: else\n## a\n## b\n")
    assert "field-only-violation" in nodecl


def test_type_gate_survives_resume(tmp_path):
    # the gate must NOT be dropped when a run suspends and resumes (adversarial-review HIGH bug)
    from prismpath.ledgers import checkpoint
    flow = tmp_path / "f.md"
    flow.write_text("---\nname:t\nstart:n\n---\n## n\nGo.\n-> m: when go\n## m\nDo it.\n"
                    "-> a: when tests_pass\n-> b: when not tests_pass\n## a\n## b\n")
    ckpt = str(tmp_path / "c.json")

    def agent(node, instr, state):
        if node == "n":
            return {"text": "n", "go": True, "needs_human": True}   # suspend for a human
        if node == "m":
            return {"text": "m", "tests_pass": "yes"}               # wrong type on the RESUMED path
        return {"text": node}

    r1 = checkpoint.run_durable(str(flow), agent, ckpt, type_gate=True)
    assert r1.stopped == "needs_human"
    # resume with the human's choice -> node m emits a mistyped field -> the gate (persisted) must fire
    r2 = checkpoint.resume(ckpt, agent, choose="m")
    assert r2.stopped == "contract_violation"


def test_none_value_is_not_a_type_violation():
    node = _c(TYPES_FLOW)
    assert [problem for problem in contract.validate_output(node, {"tests_pass": None}) if problem.startswith("type:")] == []


def test_duplicate_emits_unions_and_empty_key_ignored():
    graph = parse("---\nname:t\nstart:n\n---\n## n\nGo.\n@emits(a)\n@emits(b, =junk)\n-> x: when a\n## x\n")
    assert contract.declared_emits(graph.nodes["n"]) == {"a", "b"}     # merged across lines, empty key dropped


def test_recovers_the_soc_verdict_schema_from_the_real_flow():
    # the payoff: the wazuh flow's classify node re-derives the hand-written verdict enum
    field_types = contract.derive_contract(parse_file(os.path.join(HERE, "flows", "wazuh_triage.md")))
    classify = field_types["classify"]
    assert classify["recommended_action"] == {"type": "enum",
                                              "values": ["contain", "ignore", "watch"]}
