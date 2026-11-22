# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The readable rules source of a core policy image (prismpath/kernel/policy_source.py).

The shipped agent policies compile from their sources byte for byte; every image in the repository's corpora
renders to a source that compiles back to its exact bytes, and a refused one is refused for the oracle's own
cause on the line it is about (the differential generator's images too, in test_core_diff.py, which
research alone carries); every error names its line; cause names resolve through the registry; the
order of the rules is part of the image; and random valid images render and recompile identically.
"""
import json
import os
import random
import subprocess
import sys
from pathlib import Path

import pytest

from prismpath.kernel import canon2, causes, core_policy, core_render
from prismpath.kernel import policy_source as ps

ROOT = Path(__file__).resolve().parents[2]
POLICY = ROOT / "prismpath" / "agent" / "policy"
CASES = Path(__file__).resolve().parent / "fixtures" / "core_evidence" / "cases.jsonl"


def _images():
    """Every shipped core image in the tree: the agent's, and the integrations' where research carries them."""
    found = sorted(path for path in ROOT.glob("**/*.core.json")
                   if not {"target", "node_modules", ".git"} & set(path.relative_to(ROOT).parts))
    assert {"agent_rules.core.json", "agent_default.core.json"} <= {path.name for path in found}
    return found


def _image_bytes(path):
    raw = path.read_bytes()
    assert raw.endswith(b"\n")
    return raw[:-1]


# ----------------------------------------------------------------- the policy of record
@pytest.mark.parametrize("name", ["agent_rules", "agent_default"])
def test_the_shipped_source_compiles_to_the_shipped_image_byte_for_byte(name):
    source = (POLICY / f"{name}.rules.md").read_text(encoding="utf-8")
    image = ps.compile_source(source, f"{name}.rules.md")
    assert image + b"\n" == (POLICY / f"{name}.core.json").read_bytes()
    # and the image is the one the JSON source has always canonicalized to
    assert image == canon2.canonicalize((POLICY / f"{name}.src.json").read_bytes())


@pytest.mark.parametrize("path", _images(), ids=lambda path: path.name)
def test_every_shipped_image_renders_and_recompiles_identically(path):
    image = _image_bytes(path)
    assert core_policy.load_policy(image) is None
    source = ps.render_source(image)
    assert ps.compile_source(source, path.name) == image
    assert ps.render_source(ps.compile_source(source)) == source


def test_every_corpus_image_round_trips_and_a_refused_one_is_refused_for_the_oracles_cause():
    accepted = refused = 0
    for line in CASES.read_text(encoding="utf-8").splitlines():
        case = json.loads(line)
        image = bytes.fromhex(case["image"])
        try:
            doc = canon2.loads(image)
            source = ps.render_source(doc)
        except (canon2.Canon2Error, core_render.Unrenderable):
            continue                                   # no source, as it has no flow (spec section 11)
        assert ps.compile_source(source, checked=False) == image, case["case"]
        refusal = core_policy.load_policy(image)
        if refusal is None:
            assert ps.compile_source(source) == image
            accepted += 1
            continue
        with pytest.raises(ps.SourceError) as error:
            ps.compile_source(source)
        (where, message), = error.value.problems
        assert where > 0 and f"({refusal[0]}" in message, (case["case"], refusal, message)
        refused += 1
    assert accepted >= 10 and refused >= 25


# ----------------------------------------------------------------- causes and order
def test_every_registered_cause_name_resolves_to_its_code_and_back():
    for code, name, _cls, _about in causes._REGISTRY:
        for decision in ps.DECISIONS:
            source = f"---\n---\n## core_decision\n-> {decision} {name}: always\n"
            doc = canon2.loads(ps.compile_source(source))
            assert doc["rules"] == [{"target": f"{decision}_{code}", "when": ["always"]}]
            assert ps.readable_target(f"{decision}_{code}") == f"{decision} {name}"


def test_an_unregistered_cause_is_an_error_and_names_a_near_one():
    with pytest.raises(ps.SourceError) as error:
        ps.compile_source("---\n---\n## core_decision\n-> refuse agent:netwrk: always\n", "x.rules.md")
    assert error.value.lines() == ["x.rules.md:4: agent:netwrk is not a registered cause name; did you mean agent:network?"]
    with pytest.raises(core_render.Unrenderable):
        ps.readable_target("refuse_250")


def test_the_order_of_the_rules_is_part_of_the_image():
    source = (POLICY / "agent_rules.rules.md").read_text(encoding="utf-8")
    lines = source.split("\n")
    allow = [at for at, text in enumerate(lines) if text.startswith("-> allow: when git_op == \"push\"")][0]
    lines[allow], lines[allow + 1] = lines[allow + 1], lines[allow]
    swapped = ps.compile_source("\n".join(lines))
    assert swapped != ps.compile_source(source)
    rules = canon2.loads(swapped)["rules"]
    assert [rule["target"] for rule in rules[12:14]] == ["escalate_113", "allow"]   # rule 12 is the zone question


# ----------------------------------------------------------------- the source format
HEAD = "---\nfield.n: int min=0 max=10\nfield.t: category\nfield.b: bool\n---\n## core_decision\n"


def _rules(text, checked=True):
    return canon2.loads(ps.compile_source(HEAD + text, checked=checked))["rules"]


def test_conditions_mean_what_the_image_means():
    assert _rules("-> allow: when b\n") == [{"target": "allow", "when": ["truthy", "b"]}]
    assert _rules("-> allow: when 3 < n\n")[0]["when"] == ["cmp", "n", ">", ["num", 3]]
    assert _rules("-> allow: when 1 <= n < 5\n")[0]["when"] == [
        "and", ["cmp", "n", ">=", ["num", 1]], ["cmp", "n", "<", ["num", 5]]]
    assert _rules("-> allow: when t not in ('a',)\n")[0]["when"] == ["not in", "t", [["str", "a"]]]
    assert _rules("-> allow: when not (b or t == 'x') and n != -0\n")[0]["when"] == [
        "and", ["not", ["or", ["truthy", "b"], ["cmp", "t", "==", ["str", "x"]]]], ["cmp", "n", "!=", ["num", 0]]]
    assert _rules("-> allow: when b == True\n-> t-1: else\n-> x: never\n") == [
        {"target": "allow", "when": ["cmp", "b", "==", ["bool", True]]},
        {"target": "t-1", "when": ["always"]}, {"target": "x", "when": ["never"]}]
    fixed = "---\nfield.r: fixed scale=100 rounding=exact\n---\n## core_decision\n-> allow: when r >= +1.50\n"
    assert canon2.loads(ps.compile_source(fixed))["rules"][0]["when"] == ["cmp", "r", ">=", ["num", "+1.50"]]


def test_notes_names_and_line_ends_are_not_part_of_the_image():
    plain = ps.compile_source(HEAD + "-> allow: when b\n")
    noted = ("---\nname: mine\ndescription: a note\nstart: Core Decision\nfield.n: int min=0 max=10  \n"
             "field.t:category\nfield.b: bool\n---\nA note before the rules.\n## Core Decision\nWhy b.\n"
             "- -> allow: when b\n## allow\nThe end.\n")
    assert ps.compile_source(noted) == plain
    assert ps.compile_source(noted.replace("\n", "\r\n")) == plain


def test_the_compiler_warns_about_rules_no_reading_reaches_and_routes():
    compiled = ps.compile_full(HEAD + "-> allow: always\n-> elsewhere: when b\n")
    assert [line for line, _ in compiled.warnings] == [8, 8]
    assert "no reading reaches" in compiled.warnings[0][1] and "is a route" in compiled.warnings[1][1]
    assert ps.compile_full(HEAD).warnings[0][0] == 0


ERRORS = [
    # (source, line, words the message holds)
    ("## core_decision\n-> allow: always\n", 1, "front matter block"),
    ("---\nfield.b: bool\n", 1, "no closing"),
    ("---\nowner: me\n---\n## core_decision\n", 2, "not a front matter key"),
    ("---\njust words\n---\n## core_decision\n", 2, "key: value"),
    ("---\nfield.: bool\n---\n## core_decision\n", 2, "field.<name>"),
    ("---\nfield.b: bool\nfield.b: int\n---\n## core_decision\n", 3, "declared twice (first on line 2)"),
    ("---\nname: a\nname: b\n---\n## core_decision\n", 3, "written twice"),
    ("---\nstart: decide\n---\n## core_decision\n", 2, "no ## decide section"),
    ("---\n---\n## core_decision\n## core_decision\n", 4, "appears twice"),
    ("---\n---\n-> allow: always\n## core_decision\n", 3, "before any section"),
    ("---\n---\n## core_decision\n## other\n-> allow: always\n", 5, "under ## other"),
    ("---\n---\n## core_decision\n@checkpoint(unit=x)\n", 4, "annotations"),
    ("---\n---\n## core_decision\n-> refuse_105: always\n", 4, "write `refuse agent:kill-by-pattern`"),
    ("---\n---\n## core_decision\n-> escalate_250: always\n", 4, "code 250 is not registered"),
    ("---\n---\n## core_decision\n-> refuse: always\n", 4, "needs a cause name"),
    ("---\n---\n## core_decision\n-> Refuse agent:network: always\n", 4, "a rule is written"),
    ("---\n---\n## core_decision\n-> refuse agent:network:when b\n", 4, "space after the colon"),
    ("---\n---\n## core_decision\n-> allow:\n", 4, "no condition"),
    ("---\nfield.b: bool\n---\n## core_decision\n-> allow: if b\n", 5, "always, never, or start with when"),
    ("---\nfield.b: bool\n---\n## core_decision\n-> allow: when b ==\n", 5, "does not read"),
    ("---\nfield.b: bool\n---\n## core_decision\n-> allow: when f(b)\n", 5, "is not a field, a comparison"),
    ("---\nfield.b: bool\n---\n## core_decision\n-> allow: when (True)\n", 5, "reads no field"),
    ("---\nfield.n: int\n---\n## core_decision\n-> allow: when 1 == 2\n", 5, "does not read a field"),
    ("---\nfield.n: int\n---\n## core_decision\n-> allow: when n in 3\n", 5, "list of constants"),
    ("---\nfield.n: int\n---\n## core_decision\n-> allow: when 3 in [n]\n", 5, "field on its left"),
    ("---\nfield.n: int\n---\n## core_decision\n-> allow: when n is None\n", 5, "compare with =="),
    ("---\nfield.n: int\n---\n## core_decision\n-> allow: when n == -(5)\n", 5, "sign directly on the number"),
    ("---\nfield.n: int\n---\n## core_decision\n-> allow: when n == -m\n", 5, "sign directly on the number"),
    ("---\nfield.n: int\n---\n## core_decision\n-> allow: when n == 0x10\n", 5, "plain decimal digits"),
    ("---\nfield.n: int\n---\n## core_decision\n-> allow: when n == 1_000\n", 5, "plain decimal digits"),
    ("---\nfield.n: int\n---\n## core_decision\n-> allow: when n == 2j\n", 5, "is not a number"),
    ("---\nfield.n: int\n---\n## core_decision\n-> allow: when n == b'x'\n", 5, "is not a number, a string"),
    ("---\nfield.n: int\n---\n## core_decision\n-> allow: when n in [[1]]\n", 5, "a list cannot hold a list"),
    ("---\nfield.n: int\n---\n## core_decision\n-> allow: when n == n + 1\n", 5, "is not a constant"),
    ("---\nfield.t: category\n---\n## core_decision\n-> allow: when t == '\\ud800'\n", 5, "no canon/2 form"),
    ("---\nfield.n: int\n---\n## core_decision\n-> allow: when " + "not " * 200 + "n\n", 5, "nested"),
    # what the core refuses, on the line it is about
    ("---\nfield.n: int\n---\n## core_decision\n-> allow: when n == 'x'\n", 5, "(policy:kind-mismatch: field n)"),
    ("---\nfield.n: int\n---\n## core_decision\n-> allow: when ghost\n", 5, "(image:field-index-oob: field ghost)"),
    ("---\nfield.n: int\n---\n## core_decision\n-> allow: when n == y\n", 5, "not another field"),
    ("---\nfield.t: category\n---\n## core_decision\n-> allow: when t < 'a'\n", 5, "only be compared with == or !="),
    ("---\nfield.n: int max=5\n---\n## core_decision\n-> allow: when n > 6\n", 5, "outside the field's min and max"),
    ("---\nfield.n: int\n---\n## core_decision\n-> allow: when n > 1.5\n", 5, "only be compared with a fixed field"),
    ("---\nfield.n: int\n---\n## core_decision\n-> allow: when n == None\n", 5, "does not declare absent=allowed"),
    ("---\nfield.r: fixed scale=10 rounding=floor\n---\n## core_decision\n-> allow: when r > 1.5\n", 5,
     "(policy:rounding: field r)"),
    ("---\nfield.r: fixed scale=10 rounding=exact\n---\n## core_decision\n-> allow: when r > 1.55\n", 5, "decimal places"),
    ("---\nfield.n: int\n---\n## core_decision\n-> allow: when True == visits\n", 5, "engine counter"),
    ("---\nfield.n: int\n---\n## core_decision\n-> allow: when " + "not " * 50 + "n\n", 5, "nested deeper than 50"),
    ("---\nfield.n: int\n---\n## core_decision\n-> allow: when lambda == 1\n", 5, "does not read"),
    ("---\nfield.n: int\nfield.k: whole\n---\n## core_decision\n", 3, "bool, category, int or fixed"),
    ("---\nfield.n: int scale=3\n---\n## core_decision\n", 2, "does not take that option"),
    ("---\nfield.n: int min=4 max=2\n---\n## core_decision\n", 2, "min must not exceed max"),
    ("---\nfield.visits: int\n---\n## core_decision\n", 2, "engine's own counters"),
    ("---\nfield.n: int absent=allowed\n---\n## core_decision\n-> allow: when n > 1\n", 2,
     "(policy:absence-untested: field n)"),
]


@pytest.mark.parametrize("source,line,words", ERRORS, ids=[words for _s, _l, words in ERRORS])
def test_every_error_names_its_line_and_the_problem(source, line, words):
    with pytest.raises(ps.SourceError) as error:
        ps.compile_source(source, "rules.md")
    assert [where for where, _ in error.value.problems][0] == line, error.value.problems
    assert words in str(error.value), str(error.value)
    assert str(error.value).startswith(f"rules.md:{line}: ")


def test_every_line_that_does_not_read_is_named_at_once():
    with pytest.raises(ps.SourceError) as error:
        ps.compile_source("---\nfield.b: bool\n---\n## core_decision\n-> allow: if b\n-> refuse no-such: always\n")
    assert [line for line, _ in error.value.problems] == [5, 6]


def test_an_image_the_source_cannot_carry_is_not_rendered():
    def doc(fields, rules):
        return {"format": "prismpath.core/1", "fields": fields, "rules": rules}
    for bad in (doc({"b": " bool"}, []), doc({"b": "bool"}, [{"target": "refuse", "when": ["always"]}]),
                doc({"b": "bool"}, [{"target": "escalate_250", "when": ["always"]}]),
                doc({}, [{"target": "x", "when": ["cmp", "b", "~", ["num", 1]]}])):
        with pytest.raises(core_render.Unrenderable):
            ps.render_source(bad)


# ----------------------------------------------------------------- random valid images
_STRINGS = ["", "a", "unknown", "read_only", "x y", "quote\"d", "back\\slash", "tab\there", "line\nbreak",
            "caf\u00e9", "\u2028", "\U0001f600", "--", "None"]


def _field(rng, name):
    kind = rng.choice(["bool", "category", "int", "fixed"])
    words, info = [kind], {"name": name, "kind": kind, "scale": 1, "rounding": "exact", "absent": False}
    if kind in ("int", "fixed"):
        lo = rng.choice([None, -1000, 0, 1])
        hi = rng.choice([None, 1000, 10 ** 6])
        if kind == "fixed":
            info["scale"] = rng.choice([1, 10, 100, 1000])
            info["rounding"] = rng.choice(["exact", "exact", "floor", "ceiling"])
            words += [f"scale={info['scale']}", f"rounding={info['rounding']}"]
        if lo is not None:
            words.append(f"min={lo}")
        if hi is not None:
            words.append(f"max={hi}")
        info["lo"] = -1000 if lo is None else lo
        info["hi"] = 1000 if hi is None else min(hi, 10 ** 6)
    if rng.random() < 0.2:
        words.append("absent=allowed")
        info["absent"] = True
    return " ".join(words), info


def _number_text(rng, info, units):
    """A literal that means `units` canonical units of a fixed field: decimal text, maybe with a + sign."""
    scale = info["scale"]
    sign = "-" if units < 0 else rng.choice(["", "", "+"])
    whole, part = divmod(abs(units), scale)
    places = len(str(scale)) - 1
    text = f"{whole}.{part:0{places}d}" if places else f"{whole}." + "0" * rng.choice([0, 1, 2])
    if rng.random() < 0.3:
        text += "0"
    return ["num", sign + text]


def _atom(rng, fields):
    info = rng.choice(fields)
    name, kind = info["name"], info["kind"]
    if info["absent"] and rng.random() < 0.3:
        return ["cmp", name, rng.choice(["==", "!="]), ["none"]]
    if kind == "bool":
        return ["truthy", name] if rng.random() < 0.5 else ["cmp", name, rng.choice(["==", "!="]),
                                                             ["bool", rng.random() < 0.5]]
    if kind == "category":
        if rng.random() < 0.4:
            members = [["str", rng.choice(_STRINGS)] for _ in range(rng.randint(0, 3))]
            return [rng.choice(["in", "not in"]), name, members]
        return ["cmp", name, rng.choice(["==", "!="]), ["str", rng.choice(_STRINGS)]]
    ops = {"exact": ["<", "<=", ">", ">=", "==", "!="], "floor": [">=", "<"], "ceiling": [">", "<="]}[info["rounding"]]
    if kind == "int":
        value = rng.randint(info["lo"], info["hi"])
        if rng.random() < 0.3 and info["rounding"] == "exact":
            return [rng.choice(["in", "not in"]), name, [["num", rng.randint(info["lo"], info["hi"])]
                                                          for _ in range(rng.randint(1, 3))]]
        return ["cmp", name, rng.choice(ops), ["num", value]]
    units = rng.randint(info["lo"], info["hi"])
    const = ["num", units // info["scale"]] if units % info["scale"] == 0 and rng.random() < 0.3 \
        else _number_text(rng, info, units)
    return ["cmp", name, rng.choice(ops), const]


def _cond(rng, fields, depth):
    if depth <= 0 or rng.random() < 0.35:
        return _atom(rng, fields)
    tag = rng.choice(["and", "or", "not"])
    if tag == "not":
        return ["not", _cond(rng, fields, depth - 1)]
    return [tag] + [_cond(rng, fields, depth - 1) for _ in range(rng.randint(2, 3))]


def _valid_image(rng):
    fields, texts = [], {}
    for index in range(rng.randint(1, 5)):
        name = rng.choice(["a", "b", "tool", "x_1", "_", "always", "default", "true", "never", "Score"]) + str(index)
        name = name if rng.random() < 0.5 else rng.choice(["always", "default", "true", "never", "_", "else"])
        if name in texts:
            continue
        text, info = _field(rng, name)
        texts[name] = text
        fields.append(info)
    targets = ["allow", "refuse_105", "escalate_113", "refuse_32", "hit", "t-1", "core_decision"]
    rules = [{"target": rng.choice(targets), "when": _cond(rng, fields, rng.randint(0, 4))}
             for _ in range(rng.randint(0, 6))]
    for info in fields:
        if info["absent"]:
            rules.insert(rng.randint(0, len(rules)), {"target": "refuse_104", "when": ["cmp", info["name"], "==", ["none"]]})
    if rng.random() < 0.5:
        rules.append({"target": rng.choice(targets), "when": [rng.choice(["always", "never"])]})
    return {"format": "prismpath.core/1", "fields": texts, "rules": rules}


def test_random_valid_images_render_and_recompile_identically():
    rng, accepted = random.Random(20261116), 0
    for _ in range(600):
        doc = _valid_image(rng)
        image = canon2.dumps(doc)
        if core_policy.load_policy(image) is not None:
            continue
        source = ps.render_source(image)
        assert ps.compile_source(source) == image, source
        accepted += 1
    assert accepted >= 450


# ----------------------------------------------------------------- the classifier skeleton
def test_the_skeleton_sets_every_field_to_its_conservative_value(tmp_path):
    source = HEAD.replace("field.b: bool\n", "field.b: bool\nfield.gone: category absent=allowed\n"
                                             "field.r: fixed scale=10 rounding=exact min=5\n")
    source += "-> refuse agent:unclassifiable: when gone == None\n-> allow: when t in ['a', 'b']\n"
    module, test = ps.skeleton(source, "mine", "mine.rules.md")
    namespace = {}
    exec(compile(module, "mine.py", "exec"), namespace)
    assert namespace["unknown_reading"]() == {"b": False, "gone": None, "n": 0, "r": 5, "t": "unknown"}
    assert namespace["classify"]({"anything": 1}, None) == namespace["unknown_reading"]()
    assert "TRUSTED CODE OUTSIDE THE VERIFIED CORE" in module and "t     category: a | b" in module
    compile(test, "test_mine.py", "exec")


def _package_env():
    """The environment of a child that must import this package, wherever the child runs."""
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(ROOT)] + [p for p in [env.get("PYTHONPATH")] if p])
    return env


def _cli(*args, cwd=None):
    return subprocess.run([sys.executable, "-m", "prismpath", "policy", *args], capture_output=True, text=True,
                          cwd=cwd, timeout=120, env=_package_env())


def test_the_command_line_compiles_renders_and_starts_a_classifier(tmp_path):
    source = tmp_path / "agent_rules.rules.md"
    source.write_bytes((POLICY / "agent_rules.rules.md").read_bytes())
    out = tmp_path / "agent_rules.core.json"
    done = _cli("compile", str(source), "-o", str(out))
    assert done.returncode == 0, done.stderr
    assert out.read_bytes() == (POLICY / "agent_rules.core.json").read_bytes()
    printed = subprocess.run([sys.executable, "-m", "prismpath", "policy", "compile", str(source)],
                             capture_output=True, timeout=120, env=_package_env())
    assert printed.stdout == out.read_bytes()

    for image in (POLICY / "agent_rules.core.json", POLICY / "agent_rules.src.json"):
        done = _cli("render", str(image))
        assert done.returncode == 0, done.stderr
        assert done.stdout == ps.render_source(_image_bytes(POLICY / "agent_rules.core.json"))

    module = tmp_path / "rules_classifier.py"
    done = _cli("skeleton", str(source), "-o", str(module))
    assert done.returncode == 0, done.stderr
    assert _cli("skeleton", str(source), "-o", str(module)).returncode == 2       # never overwrites unasked
    tests = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
                            str(tmp_path / "test_rules_classifier.py")], capture_output=True, text=True,
                           cwd=tmp_path, timeout=300, env=_package_env())
    assert tests.returncode == 0, tests.stdout + tests.stderr
    assert "4 passed" in tests.stdout


def test_the_command_line_names_the_line_of_an_error(tmp_path):
    bad = tmp_path / "bad.rules.md"
    bad.write_text("---\nfield.b: bool\n---\n## core_decision\n-> refuse agent:nope: when b\n", encoding="utf-8")
    done = _cli("compile", str(bad), "-o", str(tmp_path / "out.json"))
    assert done.returncode == 2 and not (tmp_path / "out.json").exists()
    assert f"{bad}:5: agent:nope is not a registered cause name" in done.stderr
    garbage = tmp_path / "garbage.json"
    garbage.write_text("{not json", encoding="utf-8")
    assert _cli("render", str(garbage)).returncode == 2
    assert _cli("render", str(tmp_path / "missing.json")).returncode == 2
