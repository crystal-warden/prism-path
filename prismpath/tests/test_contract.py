"""Worker-contract derivation tests (roadmap item 1) — extract per-node output schemas from `when`
edges, infer types, generate grammars, and type-gate worker outputs."""
import os

from prismpath import contract
from prismpath.parser import parse, parse_file

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
    c = _c(TYPES_FLOW)
    assert c["tests_pass"] == {"type": "boolean"}
    assert c["blocked"] == {"type": "boolean"}              # `not blocked`
    assert c["amount"] == {"type": "number"}               # `> 500` is a range -> no closed value set
    assert c["priority"] == {"type": "number", "values": [3]}   # `== 3` is a numeric enum -> keep the value
    assert c["action"]["type"] == "enum"
    assert c["action"]["values"] == ["contain", "ignore", "watch"]   # accumulated + sorted across edges


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
    c = _c(TYPES_FLOW)
    assert "visits" not in c and "error_count" not in c     # engine-provided, not the worker's contract


def test_conflict_flagged():
    c = _c("""---
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
    assert c["done"].get("conflict")                        # used as boolean AND enum


def test_nodes_without_deterministic_edges_are_empty():
    c = contract.derive_contract(parse("""---
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
    assert c["n"] == {}                                     # all semantic/error -> nothing to constrain


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
    probs = [p for p in contract.validate_output(node, good) if p.startswith("type:")]
    assert probs == []
    # wrong types -> hard `type:` problems
    bad = contract.validate_output(node, {"tests_pass": "yes", "amount": "600", "action": "contain"})
    assert any("tests_pass" in p and p.startswith("type:") for p in bad)
    assert any("amount" in p and p.startswith("type:") for p in bad)
    # an enum value no edge routes on -> soft note (falls through), not a type error
    note = contract.validate_output(node, {"action": "escalate"})
    assert any("escalate" in p and p.startswith("note:") for p in note)


def test_engine_type_gate_stops_on_wrong_type():
    from prismpath.engine import run
    g = parse("---\nname:t\nstart:work\n---\n## work\nGo.\n-> review: when tests_pass\n"
              "-> work: when not tests_pass\n## review\n## done\n")

    def bad(node, instr, state):
        return {"text": "done", "tests_pass": "yes"}          # string where a boolean is read

    r = run(g, bad, type_gate=True, max_steps=5)
    assert r.stopped == "contract_violation"
    assert any("tests_pass" in v for v in r.pending["violations"])
    # OFF: the string "yes" is truthy, so it SILENTLY routes to review — the bug the gate catches
    assert run(g, bad, type_gate=False, max_steps=5).stopped == "terminal"

    def good(node, instr, state):
        return {"text": "done", "tests_pass": True} if node == "work" else {"text": node}

    assert run(g, good, type_gate=True, max_steps=5).stopped == "terminal"


def test_run_durable_passes_type_gate(tmp_path):
    from prismpath import checkpoint
    flow = tmp_path / "f.md"
    flow.write_text("---\nname:t\nstart:work\n---\n## work\nGo.\n-> done: when ok\n## done\n")
    res = checkpoint.run_durable(str(flow), lambda n, i, s: {"text": "x", "ok": 1}, str(tmp_path / "c.json"),
                                 type_gate=True)
    assert res.stopped == "contract_violation"                # ok=1 (int) where a boolean is read


def _codes(flow):
    from prismpath import analysis
    return sorted({f.code for f in analysis.analyze(parse(flow))})


def test_declared_emits_parsing():
    g = parse("---\nname:t\nstart:n\n---\n## n\nGo.\n@emits(action, level=number)\n-> a: when action == \"go\"\n## a\n")
    assert contract.declared_emits(g.nodes["n"]) == {"action", "level"}
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
    from prismpath import checkpoint
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
    assert [p for p in contract.validate_output(node, {"tests_pass": None}) if p.startswith("type:")] == []


def test_duplicate_emits_unions_and_empty_key_ignored():
    g = parse("---\nname:t\nstart:n\n---\n## n\nGo.\n@emits(a)\n@emits(b, =junk)\n-> x: when a\n## x\n")
    assert contract.declared_emits(g.nodes["n"]) == {"a", "b"}     # merged across lines, empty key dropped


def test_recovers_the_soc_verdict_schema_from_the_real_flow():
    # the payoff: the wazuh flow's classify node re-derives the hand-written verdict enum
    c = contract.derive_contract(parse_file(os.path.join(HERE, "flows", "wazuh_triage.md")))
    classify = c["classify"]
    assert classify["recommended_action"] == {"type": "enum",
                                              "values": ["contain", "ignore", "watch"]}
