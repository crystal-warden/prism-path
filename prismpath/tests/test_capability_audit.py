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


