"""pysprint gate plugin — the Python gate that runs pytest and reports the verdict.

Function-level, no server, tmp_path — the suite's convention for a component like this.
"""
import pytest

from prismpath.plugins import pysprint


def _write(d, name, body):
    p = d / name
    p.write_text(body, encoding="utf-8")
    return p


def test_no_tests_is_invalid(tmp_path):
    _write(tmp_path, "mod.py", "x = 1\n")
    v = pysprint.validate(str(tmp_path))
    assert v["valid"] is False
    assert any("no test" in e.lower() for e in v["errs"])


def test_passing_suite_is_green(tmp_path):
    _write(tmp_path, "mod.py", "def add(a, b):\n    return a + b\n")
    _write(tmp_path, "test_mod.py",
           "import mod\ndef test_add():\n    assert mod.add(2, 3) == 5\n")
    v = pysprint.validate(str(tmp_path))
    assert v["valid"] is True
    assert v["errs"] == []
    assert v["biggest_file"]                 # reports a size like the browser gate


def test_failing_test_names_the_file(tmp_path):
    _write(tmp_path, "mod.py", "def add(a, b):\n    return a - b\n")   # bug
    _write(tmp_path, "test_mod.py",
           "import mod\ndef test_add():\n    assert mod.add(2, 3) == 5\n")
    v = pysprint.validate(str(tmp_path))
    assert v["valid"] is False
    assert any("test_mod.py" in e for e in v["errs"])


def test_import_error_is_reported_not_raised(tmp_path):
    _write(tmp_path, "mod.py", "def add(a, b):\n    return a +\n")     # syntax error
    _write(tmp_path, "test_mod.py",
           "import mod\ndef test_add():\n    assert mod.add(2, 3) == 5\n")
    v = pysprint.validate(str(tmp_path))
    assert v["valid"] is False
    assert v["errs"]                         # some diagnostic, never an exception


def test_attribute_surface_present():
    # the engine reads these; a missing one breaks run_sprint at import
    for attr in ("validate", "HAS_SPEC_LAYER", "FILE_EXTS", "SOURCE_DIRS", "ENTRY_FILES",
                 "SPEC_SUFFIXES", "ARCH_PATH", "LESSONS_PATH", "BUILD_RULES"):
        assert hasattr(pysprint, attr), attr
    assert ".py" in pysprint.FILE_EXTS
