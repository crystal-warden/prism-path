"""Tests for the Roblox/Luau gate. Tool-dependent cases self-skip when the vendored toolchain
is absent (CI without tools/bin), so the suite stays green either way."""
import os
import shutil

import pytest

from prismpath.luau_gate import BIN, DEFS, validate_luau

FIX = os.path.join(os.path.dirname(__file__), "fixtures", "roblox_clean")


def _has(binary):
    return os.path.isfile(os.path.join(BIN, binary))


needs_analyze = pytest.mark.skipif(not _has("luau-analyze"), reason="vendored luau-analyze absent")
needs_lsp = pytest.mark.skipif(not _has("luau-lsp"), reason="vendored luau-lsp absent")
needs_rojo = pytest.mark.skipif(not _has("rojo"), reason="vendored rojo absent")
needs_lune = pytest.mark.skipif(not _has("lune"), reason="vendored lune absent")


def _proj(tmp_path):
    dst = os.path.join(tmp_path, "proj")
    shutil.copytree(FIX, dst)
    return dst


def _write(proj, rel, text):
    ap = os.path.join(proj, rel)
    os.makedirs(os.path.dirname(ap), exist_ok=True)
    with open(ap, "w", encoding="utf-8") as fh:
        fh.write(text)


def test_return_shape(tmp_path):
    v = validate_luau(_proj(tmp_path))
    assert set(v) == {"valid", "oversized", "oversized_file", "biggest", "biggest_file", "errs"}
    assert isinstance(v["errs"], list)
    assert isinstance(v["biggest"], int)
    assert isinstance(v["valid"], bool)


def test_missing_project_file(tmp_path):
    proj = _proj(tmp_path)
    os.remove(os.path.join(proj, "default.project.json"))
    v = validate_luau(proj)
    assert not v["valid"]
    assert any("default.project.json" in e for e in v["errs"])


@needs_analyze
@needs_lsp
@needs_rojo
@needs_lune
def test_clean_project_passes(tmp_path):
    v = validate_luau(_proj(tmp_path))
    assert v["valid"], v["errs"]


@needs_analyze
def test_syntax_error_flagged(tmp_path):
    proj = _proj(tmp_path)
    _write(proj, "src/Broken.luau", "local S = {}\nfunction S.x(\nreturn S\n")
    v = validate_luau(proj)
    assert not v["valid"]
    assert any(e.startswith("src/Broken.luau") and "SyntaxError" in e for e in v["errs"])


@needs_lsp
@pytest.mark.skipif(not os.path.isfile(DEFS), reason="Roblox API defs not vendored")
def test_type_typo_flagged(tmp_path):
    proj = _proj(tmp_path)
    # returns a number where the annotation promises a string
    _write(proj, "src/Greeter.luau",
           "--!strict\nlocal G = {}\nfunction G.hello(name: string): string\n\treturn 42\nend\nreturn G\n")
    v = validate_luau(proj)
    assert not v["valid"]
    assert any(e.startswith("src/Greeter.luau") and "TypeError" in e for e in v["errs"])


@needs_lune
@needs_rojo
@needs_lsp
@needs_analyze
def test_logic_bug_flagged_by_lune(tmp_path):
    proj = _proj(tmp_path)
    # syntax + types still pass; only the Lune assertion catches the wrong arithmetic
    _write(proj, "src/Math.luau",
           "--!strict\nlocal Math = {}\nfunction Math.add(a: number, b: number): number\n\treturn a - b\nend\nreturn Math\n")
    v = validate_luau(proj)
    assert not v["valid"]
    assert any("spec.luau" in e and "lune test failed" in e for e in v["errs"])


def test_duplicate_module_flagged(tmp_path):
    """Main.lua AND Main.luau coexisting is structural drift the per-file gate can't see."""
    proj = _proj(tmp_path)
    _write(proj, "src/server/Main.luau", "--!strict\nreturn {}\n")
    _write(proj, "src/server/Main.lua", "--!strict\nreturn {}\n")
    v = validate_luau(proj)
    assert not v["valid"]
    assert any("duplicate module" in e and "Main" in e for e in v["errs"])


def test_oversized_seam(tmp_path):
    proj = _proj(tmp_path)
    _write(proj, "src/Big.luau", "-- pad\n" * 5000)
    v = validate_luau(proj, tokens_max=10)
    assert v["oversized"]
    assert v["oversized_file"]
    assert v["biggest"] > 10


def test_errors_name_offending_file(tmp_path):
    """Every error string must reference a .luau/.lua/.json file so run_sprint's FILE_RE can route it."""
    import re
    proj = _proj(tmp_path)
    os.remove(os.path.join(proj, "default.project.json"))
    _write(proj, "src/Broken.luau", "function bad(\n")
    v = validate_luau(proj)
    assert v["errs"]
    for e in v["errs"]:
        assert re.search(r"[\w./\-]+\.(?:luau|lua|json)", e), e
