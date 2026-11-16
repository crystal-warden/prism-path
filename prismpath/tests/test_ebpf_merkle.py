# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""merkle.h's streaming root (`ppt_merkle_acc`), compiled natively and run against the tree, the RFC 6962
known answers and the frozen Python vectors (portable/conformance/merkle_stream.json): the same checks
`make test-merkle` runs in prismpath-ebpf, on OpenSSL's SHA-256 and through the header's swappable seam."""
import shutil
import subprocess

import pytest

from prismpath.tests._repo import repo_file

_ebpf = repo_file("prismpath-ebpf", "merkle.h").parent
_test = repo_file("prismpath-ebpf", "test_merkle.c")
_vectors = repo_file("prismpath", "portable", "conformance", "merkle_stream.json")


@pytest.mark.parametrize("backend", [[], ["-DTEST_EXTERNAL_SHA256"]], ids=["openssl", "external_seam"])
def test_the_c_accumulator_matches_the_tree_and_the_python_reference(tmp_path, backend):
    cc = shutil.which("cc")
    if not cc:
        pytest.skip("no C compiler")
    out = tmp_path / "test_merkle"
    build = subprocess.run([cc, "-O2", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-I", str(_ebpf), *backend,
                            str(_test), "-lcrypto", "-o", str(out)], capture_output=True, text=True)
    if build.returncode != 0 and "openssl/sha.h" in build.stderr:
        pytest.skip("no OpenSSL headers")
    assert build.returncode == 0, build.stderr
    result = subprocess.run([str(out), str(_vectors)], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "frozen vectors: 3 sets, 378 prefix roots equal to the Python reference" in result.stdout
