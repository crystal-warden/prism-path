# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The kernel names no CLI, reads no file in `analysis`, and warns when `engine.run` builds its own router."""
import ast
from pathlib import Path

import pytest

from prismpath import cli, flow_files
from prismpath.kernel import analysis, engine, model_check
from prismpath.kernel.parser import FlowInputError, parse_file

PKG = Path(__file__).resolve().parents[1]
FLOW = PKG / "flows" / "bugfix.md"


def _imports(path):
    names = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            names.add(node.module or "")
    return names


def test_model_check_and_analysis_import_neither_the_cli_nor_the_os():
    assert not any(name == "prismpath.cli" for name in _imports(PKG / "kernel" / "model_check.py"))
    found = _imports(PKG / "kernel" / "analysis.py")
    assert "os" not in found and "prismpath.routing" not in found and "prismpath.flow_files" not in found


def test_an_unknown_node_is_a_kernel_error_the_cli_prints_as_one_line(capsys):
    with pytest.raises(FlowInputError):
        model_check.verify_cmd(type("A", (), dict(flow_md=str(FLOW), reach=["nosuch"], forbid=[]))())
    assert cli.main(["verify", str(FLOW), "--reach", "nosuch"]) == 2
    assert capsys.readouterr().err.startswith("prismpath verify: no such node in ")


def test_the_old_analysis_names_and_flow_files_agree():
    graph = parse_file(str(FLOW))
    assert analysis.portability_tier(graph, str(FLOW)) == flow_files.portability_tier(graph, str(FLOW))
    assert analysis.analyze_composition(graph, str(FLOW)) == flow_files.analyze_composition(graph, str(FLOW))


def test_run_with_no_router_warns_once_for_the_default(monkeypatch):
    # The default router needs the embeddings extra, which this test does not. A stand in keeps it to the warning.
    from prismpath.routing import router as router_module
    class Built(Exception):
        pass

    class Stand:
        def route(self, *args, **kwargs):
            raise Built

    monkeypatch.setattr(router_module, "EmbeddingRouter", Stand)
    graph = parse_file(str(FLOW))
    with pytest.warns(DeprecationWarning, match="no router"):
        try:
            engine.run(graph, lambda node, text, state: "", max_steps=1)
        except Built:
            pass
