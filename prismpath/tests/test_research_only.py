# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Checks that need what only the research repository carries: the JavaScript and Go kernels and
examples, the hardware subset manifest, the Lean development, the routing benchmark and the
pyproject. They are the research side of tests the product repository's export shares in a narrower
form, so this file is held back from the export (tools/export_clean.py) and a product test run never
sees it. When the export gains one of these subjects, move its check out of here."""
import base64
import json
import os
import shutil
import subprocess
import sys

import pytest

from prismpath.tests._repo import repo_file

PACKAGE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFORMANCE = os.path.join(PACKAGE, "portable", "conformance")


# ---- the declared hardware subset (prismpath-hw/declared_subset.json)
def test_the_declared_hardware_subset_neither_shrinks_nor_grows_unreviewed():
    """The selection the table compiler makes today must be exactly the frozen manifest. A subset that
    shrank would let every certification report all of fewer vectors passing; one that grew needs the
    manifest frozen again and the targets recertified. Both runners enforce the same check where they
    certify; this runs it on every CI push, with no interpreter or kernel needed."""
    sys.path.insert(0, str(repo_file("prismpath-hw")))
    repo_file("prismpath-hw", "declared_subset.json")
    import declared_subset
    cases = json.loads(open(os.path.join(CONFORMANCE, "predicates.json"), encoding="utf-8").read())["cases"]
    shrank, grew = declared_subset.drift(declared_subset.selected_ids(cases))
    assert shrank == [], f"the declared subset shrank: {shrank}"
    assert grew == [], f"the declared subset grew; freeze it with declared_subset.py --write: {grew}"
    assert declared_subset.frozen()["count"] == 147 == len(declared_subset.frozen()["case_ids"])


# ---- the JavaScript port against the frozen vectors
@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed, port conformance untested here")
def test_the_port_passes_the_frozen_vectors():
    process = subprocess.run(["node", os.path.join(PACKAGE, "portable", "run_vectors.mjs"), CONFORMANCE],
                             capture_output=True, text=True, timeout=120)
    assert process.returncode == 0, f"port is NON-CONFORMANT:\n{process.stdout[-2000:]}\n{process.stderr[-1000:]}"
    assert "CONFORMANT" in process.stdout


# ---- the Lean development
def test_the_lean_registry_is_what_the_generator_writes_now():
    import importlib.util
    path = os.path.join(PACKAGE, "portable", "gen_causes_rs.py")
    spec = importlib.util.spec_from_file_location("gen_causes_rs", path)
    generator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generator)
    lean = repo_file("formal", "Core", "Causes.lean")
    assert lean.read_text(encoding="utf-8") == generator.build_lean(), (
        "formal/Core/Causes.lean is stale; run prismpath/portable/gen_causes_rs.py and commit the result")


# ---- the bundle compiler
def test_compile_report_size_is_the_decoded_byte_count():
    from prismpath import bundle_compile
    for payload_length in range(1, 40):
        payload = bytes(range(payload_length))
        encoded = base64.b64encode(payload).decode()
        assert bundle_compile._b64_decoded_size(encoded) == payload_length


# ---- the routing benchmark the kappa tooling is built for
def test_the_routing_benchmark_loads_through_the_blind_annotation():
    from prismpath.evals import annotate
    cases = list(annotate.blind_cases(str(repo_file("prismpath", "benchmark", "routing_bench.jsonl"))))
    assert len(cases) >= 300


# ---- the declared extras exist in the pyproject
def test_every_extra_module_maps_to_an_extra_pyproject_declares():
    tomllib = pytest.importorskip("tomllib")
    from prismpath import extras
    with open(repo_file("pyproject.toml"), "rb") as handle:
        declared = tomllib.load(handle)["project"]["optional-dependencies"]
    for module, (extra, package) in extras.EXTRAS.items():
        assert extra in declared, module
        assert any(req.split()[0].split(";")[0].strip() == package for req in declared[extra]), module


# ---- the JavaScript and Go worker examples
EX = os.path.join(PACKAGE, "examples", "cli_worker")


def _route(flow, cmd, pass_state, seed):
    from prismpath.kernel.engine import run
    from prismpath.kernel.parser import parse_file
    from prismpath.workers.cli_worker import cli_worker
    worker = cli_worker(cmd, pass_state=pass_state)
    return run(parse_file(os.path.join(EX, flow)), worker, state=seed, max_steps=5).path[-1]


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_js_log_alert():
    cmd = ["node", os.path.join(EX, "log_alert.js")]
    route = lambda line: _route("log_alert.md", cmd, ["line"], {"line": line})         # noqa: E731
    assert route("ERROR api latency=1900ms db timeout") == "page_oncall"
    assert route("WARN api latency=1500ms") == "slow_warn"
    assert route("INFO request latency=120ms") == "archive"
    assert route("garbage with no level") == "error_hold"


@pytest.mark.skipif(shutil.which("go") is None, reason="go toolchain not installed")
def test_go_release_gate(tmp_path):
    binary = str(tmp_path / "release_gate")
    subprocess.run(["go", "build", "-o", binary, os.path.join(EX, "release_gate.go")], check=True)
    route = lambda frm, to: _route("release_gate.md", [binary], ["from", "to"], {"from": frm, "to": to})  # noqa: E731
    assert route("1.4.2", "2.0.0") == "block"
    assert route("1.4.2", "1.4.3") == "auto_publish"
    assert route("1.4.2", "1.5.0") == "needs_review"
    assert route("1.4.2", "x.y.z") == "error_hold"                # unparseable -> nonzero exit -> error tier
