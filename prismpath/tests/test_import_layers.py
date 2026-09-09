# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The kernel's import layering, pinned: the parser and predicates import no analyzer, the Level M
classifier imports only the parser and predicates, and the analyzer never imports the model checker.
These were cycles once (parser <-> analysis, analysis <-> model_check); this keeps them broken."""
import re
from pathlib import Path

import prismpath

PKG = Path(prismpath.__file__).parent


def _imports(module_file: Path):
    text = module_file.read_text()
    return set(re.findall(r"^\s*(?:from|import)\s+prismpath\.?([A-Za-z_.]*)", text, flags=re.M))


def _find(name: str) -> Path:
    hits = list(PKG.rglob(f"{name}.py"))
    real = [h for h in hits if "sys.modules[__name__]" not in h.read_text()]
    assert real, name
    return real[0]


def test_parser_and_predicates_import_no_analyzer():
    for mod in ("parser", "predicates"):
        imported = _imports(_find(mod))
        assert not any(x.endswith(("analysis", "model_check", "level_m")) for x in imported), (mod, imported)


def test_level_m_imports_only_parser_and_predicates():
    imported = {x.split(".")[-1] for x in _imports(_find("level_m"))}
    assert imported <= {"predicates", "parser", "kernel", ""}, imported


def test_analysis_never_imports_model_check():
    assert not any(x.endswith("model_check") for x in _imports(_find("analysis")))
    assert not any(x.endswith("model_check") for x in _imports(_find("level_m")))
