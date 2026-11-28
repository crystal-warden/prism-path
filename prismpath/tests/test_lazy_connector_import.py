# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Importing the kernel loads no worker. `prismpath/__init__.py` names the connector SDK and loads it on first use,
so the kernel layer imports nothing above it, and every `from prismpath import BaseConnector` still works."""
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def _python(code: str) -> str:
    done = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=120,
                          env=dict(os.environ, PYTHONPATH=str(REPO)), cwd=str(REPO))
    assert done.returncode == 0, done.stderr
    return done.stdout.strip()


def test_importing_the_kernel_does_not_load_the_connector():
    assert _python("import sys, prismpath.kernel; print('prismpath.workers.connector' in sys.modules)") == "False"
    assert _python("import sys, prismpath.kernel.engine; print(any(m.startswith('prismpath.workers') for m in sys.modules))") == "False"


def test_the_connector_names_still_import_from_the_package():
    out = _python("import sys; from prismpath import BaseConnector, node, PayloadFlattener; "
                  "from prismpath.workers import connector; "
                  "print(BaseConnector is connector.BaseConnector, node is connector.node, "
                  "PayloadFlattener is connector.PayloadFlattener, 'prismpath.workers.connector' in sys.modules)")
    assert out == "True True True True"


def test_a_name_the_package_does_not_have_is_an_attribute_error_and_a_submodule_still_imports():
    out = _python("import prismpath\n"
                  "try:\n    prismpath.NoSuchName\nexcept AttributeError as e:\n    print('AttributeError')\n"
                  "from prismpath import canon, extras\nprint(canon.__name__, extras.__name__)")
    assert out.splitlines() == ["AttributeError", "prismpath.canon prismpath.extras"]


def test_all_and_dir_list_the_connector_names():
    import prismpath
    assert set(prismpath.__all__) == {"BaseConnector", "node", "PayloadFlattener"}
    assert set(prismpath.__all__) <= set(dir(prismpath))
