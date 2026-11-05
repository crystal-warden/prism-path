# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Fixes from the 0.1.1 hand check of every documented capability against the built package.

Each test is one thing a person following the documentation met: a command that crashed on ordinary
input, a certificate printed over nothing, a browser module that could not load, an anchor that never
ran. They run the command line the way a person does (see test_cli_errors).
"""
import json
import os
import shutil
import subprocess
import sys

import pytest

import prismpath
from prismpath import cli

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(prismpath.__file__)))

FLOW = """---
name: t
start: a
---

## a
Do the thing.
-> b: when ok
-> c: else

## b
Done.

## c
Done too.
"""


def _main(capsys, *argv):
    code = cli.main(list(argv))
    out = capsys.readouterr()
    return code, out.out, out.err


def _flow(tmp_path, text=FLOW):
    path = tmp_path / "flow.md"
    path.write_text(text)
    return str(path)


# ------------------------------------------------------------------ verify

@pytest.mark.parametrize("flag", ["--forbid", "--reach"])
def test_verify_refuses_a_node_the_flow_does_not_have(flag, tmp_path, capsys):
    # `--forbid typo` used to print "UNREACHABLE (proven for all bounds)" and exit 0
    code, out, err = _main(capsys, "verify", _flow(tmp_path), flag, "nosuch")
    assert code == 2 and out == ""
    assert err.startswith("prismpath verify: no such node in ") and "nosuch" in err
    assert len(err.strip().splitlines()) == 1


def test_verify_still_proves_a_real_node(tmp_path, capsys):
    code, out, _err = _main(capsys, "verify", _flow(tmp_path), "--reach", "b", "--forbid", "c")
    assert code == 1 and "b: REACHABLE" in out


# ------------------------------------------------------------------ annotate

def _bench(tmp_path, *rows):
    path = tmp_path / "bench.jsonl"
    path.write_text("".join(json.dumps(row) + "\n" for row in rows))
    return str(path)


def test_annotate_names_the_missing_key(tmp_path, capsys):
    # before: `KeyError: 'flow'`
    code, _out, err = _main(capsys, "annotate", "--out", str(tmp_path / "a.jsonl"),
                            _bench(tmp_path, {"node": "a", "outcome": "x", "label": "b"}))
    assert code == 2
    assert err.startswith("prismpath annotate: ") and "no 'flow'" in err
    assert len(err.strip().splitlines()) == 1


def test_annotate_names_a_node_the_flow_does_not_have(tmp_path, capsys):
    _flow(tmp_path)
    code, _out, err = _main(capsys, "annotate", "--out", str(tmp_path / "a.jsonl"), "--flows-dir", str(tmp_path),
                            _bench(tmp_path, {"flow": "flow", "node": "zzz", "outcome": "x", "label": "b"}))
    assert code == 2 and "has no node 'zzz'" in err and "a, b, c" in err


def test_annotate_saves_and_stops_when_input_ends(tmp_path):
    # a closed pipe used to end in an EOFError traceback
    _flow(tmp_path)
    bench = _bench(tmp_path, {"flow": "flow", "node": "a", "outcome": "x", "label": "b"})
    env = {**os.environ, "PYTHONPATH": REPO_ROOT + os.pathsep + os.environ.get("PYTHONPATH", "")}
    result = subprocess.run([sys.executable, "-m", "prismpath.cli", "annotate", "--out", str(tmp_path / "a.jsonl"),
                             "--flows-dir", str(tmp_path), bench],
                            input="", capture_output=True, text=True, env=env)
    assert result.returncode == 0 and "Traceback" not in result.stderr
    assert "labeled 0 case(s)" in result.stdout


# ------------------------------------------------------------------ test --emit-labels and calibrate

class _StubRouter:
    class _Decision:
        def __init__(self, target, margin):
            self.target, self.info = target, {"used": "embed", "margin": margin}

    def route(self, outcome, sem, instruction=""):
        return self._Decision(sem[0][0], 0.12)


SEMANTIC = """---
name: s
start: a
---

## a
Read the report.
-> b: the report describes an outage
-> c: the report is a routine request

## b
Page someone.

## c
Answer it.
"""


def test_emit_labels_records_the_margin_of_an_embedder_row(tmp_path):
    from prismpath.kernel import flow_test
    flow = _flow(tmp_path, SEMANTIC)
    (tmp_path / "flow.tests.md").write_text(
        "| node | outcome | fields | expect |\n|---|---|---|---|\n| a | the site is down | | b |\n")
    report = flow_test.run_tests(flow, router=_StubRouter())
    labels = tmp_path / "labels.jsonl"
    flow_test.emit_labels(report, "s", labels)
    record = json.loads(labels.read_text())
    assert record["mechanism"] == "embed" and record["margin"] == pytest.approx(0.12)


def test_emit_labels_omits_a_margin_for_a_deterministic_row(tmp_path):
    from prismpath.kernel import flow_test
    flow = _flow(tmp_path)
    (tmp_path / "flow.tests.md").write_text(
        "| node | outcome | fields | expect |\n|---|---|---|---|\n| a | fine | ok=true | b |\n")
    labels = tmp_path / "labels.jsonl"
    flow_test.emit_labels(flow_test.run_tests(flow), "t", labels)
    assert "margin" not in json.loads(labels.read_text())


# ------------------------------------------------------------------ calibrate

def test_calibrate_refuses_a_log_with_no_margins(tmp_path, capsys):
    # before: "n=0 ... calibrated tau = 0.0 (escalation threshold with a >=95% correctness guarantee)"
    log = tmp_path / "labels.jsonl"
    log.write_text(json.dumps({"flow": "t", "node": "a", "chosen": "b", "label": "b", "mechanism": "deterministic"}) + "\n")
    code, out, err = _main(capsys, "calibrate", str(log))
    assert code == 2 and out == ""
    assert err.startswith("prismpath calibrate: ") and "no labeled routing decisions with a margin" in err


def test_calibrate_prints_the_warning_it_computes(tmp_path, capsys):
    log = tmp_path / "labels.jsonl"
    log.write_text(json.dumps({"flow": "t", "node": "a", "chosen": "b", "label": "b", "margin": 0.1}) + "\n")
    code, _out, err = _main(capsys, "calibrate", str(log))
    assert code == 0 and "warning:" in err and "n=1" in err


# ------------------------------------------------------------------ centroids

def test_centroids_says_when_no_row_is_a_semantic_decision(tmp_path, capsys):
    # a benchmark over a flow with no semantic edge used to print `{}` and exit 0
    _flow(tmp_path)
    code, out, err = _main(capsys, "centroids", "--flows-dir", str(tmp_path),
                           _bench(tmp_path, {"flow": "flow", "node": "a", "outcome": "x", "label": "b"}))
    assert code == 2 and out == ""
    assert err.startswith("prismpath centroids: no row of ") and "semantic routing decision" in err


# ------------------------------------------------------------------ facet decode

@pytest.mark.parametrize("payload", ["zz", "7", "", "ff", "00"])
def test_facet_decode_of_a_bad_frame_is_one_line(payload, tmp_path, capsys):
    flow = _flow(tmp_path, "---\nname: t\nstart: a\n---\n\n## a\nX.\n@emits(n=int)\n-> b: when n > 5\n-> c: else\n\n## b\nB.\n\n## c\nC.\n")
    code, _out, err = _main(capsys, "facet", "decode", flow, payload)
    assert code == 2 and err.startswith("facet: not a frame")
    assert len(err.strip().splitlines()) == 1


# ------------------------------------------------------------------ the command line itself

def test_version(capsys):
    with pytest.raises(SystemExit) as stop:
        cli.main(["--version"])
    assert stop.value.code == 0
    assert capsys.readouterr().out.startswith("prismpath ")


def test_the_program_name_in_usage_is_prismpath(capsys):
    cli.main([])
    assert capsys.readouterr().out.startswith("usage: prismpath ")


# ------------------------------------------------------------------ swap: the envelope path

def test_swap_accepts_the_envelope_file_name_as_well_as_its_base(tmp_path):
    pytest.importorskip("cryptography")
    from prismpath.hotswap import policy_pack
    keys = policy_pack.keygen(str(tmp_path / "keys"), "authority")
    policy_pack.build_envelope("env1", {"x": "int"}, None, keys["private"], keys["public"], str(tmp_path / "env"))
    base = str(tmp_path / "env" / "env1.envelope")
    for given in (base, base + ".json", base + ".sig"):
        env, reasons = policy_pack.load_envelope(given, [keys["public"]])
        assert reasons == [] and env["envelope_id"] == "env1"


# ------------------------------------------------------------------ the ledger anchor

def test_the_ledger_hashes_anchor_as_bare_hex(tmp_path):
    # the Flow-Ledger writes `sha256:<hex>`; the Merkle tree is over the bytes, and `ledger anchor`
    # used to die with "non-hexadecimal number found in fromhex()"
    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    from prismpath.ledgers import ledger_ots
    from prismpath.ledgers.ledger import Ledger
    ledger = Ledger("demo", "run1", state_dir=str(tmp_path))
    for unit in ("a", "b", "c"):
        ledger.commit_unit(unit, files={unit + ".txt": unit})
    hashes = ledger_ots.from_ledger(str(tmp_path / "demo.git"))
    assert len(hashes) == 3 and all(len(h) == 64 and not h.startswith("sha256:") for h in hashes)
    root, paths = ledger_ots.merkle_root_and_paths(hashes)
    assert all(ledger_ots.verify_leaf(h, paths[i], root) for i, h in enumerate(hashes))


def test_verify_unit_accepts_a_prefixed_leaf(tmp_path, monkeypatch):
    from prismpath.ledgers import ledger_ots
    leaves = ["aa" * 32, "bb" * 32]
    root, paths = ledger_ots.merkle_root_and_paths(leaves)
    (tmp_path / "manifest_v1.json").write_text(json.dumps(
        {"label": "v1", "root": root, "leaf_count": 2, "leaves": {leaves[0]: paths[0], leaves[1]: paths[1]}}))
    monkeypatch.setattr(ledger_ots.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 0, "", ""))
    assert ledger_ots.verify_unit("sha256:" + leaves[0], str(tmp_path), "v1")["merkle_ok"] is True


# ------------------------------------------------------------------ the browser kernel

def test_the_portable_kernel_imports_nothing():
    # `import ... from "node:crypto"` is a module-resolution error in a browser: the playground, the
    # first path in GETTING_STARTED, showed empty panels, and a compiled bundle could not load either
    source = open(os.path.join(REPO_ROOT, "prismpath", "portable", "prismpath.mjs"), encoding="utf-8").read()
    import re
    assert not re.search(r"^\s*import\s", source, re.M)
    assert "await import(" not in source


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_the_kernel_sha256_agrees_with_hashlib(tmp_path):
    import hashlib
    kernel = os.path.join(REPO_ROOT, "prismpath", "portable", "prismpath.mjs")
    samples = ["", "abc", "a" * 55, "a" * 56, "a" * 64, "é€𝄞 unicode", "x" * 1000]
    script = tmp_path / "sha.mjs"
    script.write_text(f"import {{ sha256Hex }} from {json.dumps('file://' + kernel)};\n"
                      f"console.log(JSON.stringify({json.dumps(samples)}.map(sha256Hex)));\n")
    result = subprocess.run(["node", str(script)], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == [hashlib.sha256(text.encode("utf-8")).hexdigest() for text in samples]


# ------------------------------------------------------------------ what the wheel carries

def test_every_example_flow_is_package_data():
    # the wheel shipped examples/*/run_demo.py without the .md flow each one parses
    import fnmatch
    tomllib = pytest.importorskip("tomllib")          # Python 3.11+
    if not os.path.exists(os.path.join(REPO_ROOT, "pyproject.toml")):
        pytest.skip("run from an installed package: there is no pyproject.toml beside it")
    with open(os.path.join(REPO_ROOT, "pyproject.toml"), "rb") as handle:
        patterns = tomllib.load(handle)["tool"]["setuptools"]["package-data"]["prismpath"]
    examples = os.path.join(REPO_ROOT, "prismpath", "examples")
    missing = []
    for folder, _dirs, files in os.walk(examples):
        for name in files:
            if name.endswith((".md", ".sh", ".js", ".rs", ".go")):
                rel = os.path.relpath(os.path.join(folder, name), os.path.join(REPO_ROOT, "prismpath"))
                if not any(fnmatch.fnmatch(rel, pattern) for pattern in patterns):
                    missing.append(rel)
    assert missing == []


# ------------------------------------------------------------------ the optional-extra message for Mission Control

def test_mission_control_without_the_extra_names_the_install_line():
    script = ("import sys\nsys.modules['uvicorn'] = None\nsys.modules['fastapi'] = None\n"
              "import runpy\nrunpy.run_module('prismpath.mission_control', run_name='__main__')\n")
    env = {**os.environ, "PYTHONPATH": REPO_ROOT + os.pathsep + os.environ.get("PYTHONPATH", "")}
    result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, env=env)
    assert result.returncode != 0 and "Traceback" not in result.stderr
    assert result.stderr.strip() == "prismpath mission_control: needs uvicorn (the control-plane extra): pip install 'prismpath[control-plane]'"
