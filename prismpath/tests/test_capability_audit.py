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


