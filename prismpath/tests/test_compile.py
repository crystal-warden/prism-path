# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
import json
import os
import subprocess
import pytest
from prismpath.kernel.parser import parse

P0_FLOW = """---
name: p0_flow
start: first
---

## first
First step.
-> second: when x == 1
-> done: else

## second
Second step.
-> done: always

## done
Done.
"""

P1_FLOW = """---
name: p1_flow
start: first
---

## first
First step.
-> second: the task was completed successfully
-> escalate: the task failed or crashed

## second
Second step.
-> done: always

## escalate
Escalate.
-> done: always

## done
Done.
"""

def test_compile_p0(tmp_path):
    flow_file = tmp_path / "flow.md"
    flow_file.write_text(P0_FLOW, encoding="utf-8")
    
    bundle_file = tmp_path / "flow.bundle.mjs"
    
    from prismpath.cli import main
    rc = main(["compile", str(flow_file), "--tier", "p0", "--out", str(bundle_file)])
    assert rc == 0
    assert os.path.exists(bundle_file)
    
    node_script = f"""
    import {{ runFlow }} from "./flow.bundle.mjs";
    
    const agent = (node, instr, state) => {{
      if (node === "first") return {{ x: 1 }};
      return "always";
    }};
    
    const res = await runFlow(agent);
    console.log(JSON.stringify(res));
    """
    script_file = tmp_path / "run.mjs"
    script_file.write_text(node_script, encoding="utf-8")
    
    res = subprocess.run(["node", str(script_file)], capture_output=True, text=True, cwd=str(tmp_path))
    assert res.returncode == 0, f"Node failed: {res.stderr}"
    
    data = json.loads(res.stdout)
    assert data["path"] == ["first", "second", "done"]
    assert data["stopped"] == "terminal"

def test_compile_p1(tmp_path):
    flow_file = tmp_path / "flow.md"
    flow_file.write_text(P1_FLOW, encoding="utf-8")
    
    from unittest.mock import patch
    import numpy as np
    
    def mock_embed(texts, is_query=False):
        n = len(texts)
        arr = np.random.randn(n, 384).astype("float32")
        norms = np.linalg.norm(arr, axis=1, keepdims=True)
        norms[norms == 0] = 1.0
        return arr / norms
        
    from prismpath.cli import main
    with patch("prismpath.routing.embedder.embed", side_effect=mock_embed):
        rc_lock = main(["lock", str(flow_file)])
        assert rc_lock == 0
        
        bundle_file = tmp_path / "flow.bundle.mjs"
        rc = main(["compile", str(flow_file), "--tier", "p1", "--out", str(bundle_file)])
        assert rc == 0
        assert os.path.exists(bundle_file)
    
    node_script = f"""
    import {{ runFlow, EMBEDDED_LOCK }} from "./flow.bundle.mjs";
    
    function decodeFloat16(b64) {{
      const binary = atob(b64);
      const len = binary.length;
      const bytes = new Uint8Array(len);
      for (let i = 0; i < len; i++) {{
        bytes[i] = binary.charCodeAt(i);
      }}
      const view = new DataView(bytes.buffer);
      const floats = new Float32Array(len / 2);
      for (let i = 0; i < len / 2; i++) {{
        const h = view.getUint16(i * 2, true);
        const s = (h & 0x8000) >> 15;
        const e = (h & 0x7c00) >> 10;
        const f = h & 0x03ff;
        let val;
        if (e === 0) {{
          val = (s ? -1 : 1) * Math.pow(2, -14) * (f / 1024);
        }} else if (e === 31) {{
          val = f ? NaN : (s ? -Infinity : Infinity);
        }} else {{
          val = (s ? -1 : 1) * Math.pow(2, e - 15) * (1 + f / 1024);
        }}
        floats[i] = val;
      }}
      return floats;
    }}
    
    const targetCond = "the task was completed successfully";
    const targetVec = decodeFloat16(EMBEDDED_LOCK.conditions[targetCond]);
    
    const agent = (node, instr, state) => {{
      if (node === "first") return "we finished cleanly";
      return "always";
    }};
    
    const embed = async (text) => {{
      return targetVec;
    }};
    
    const res = await runFlow(agent, {{ embed }});
    console.log(JSON.stringify(res));
    """
    script_file = tmp_path / "run.mjs"
    script_file.write_text(node_script, encoding="utf-8")
    
    res = subprocess.run(["node", str(script_file)], capture_output=True, text=True, cwd=str(tmp_path))
    assert res.returncode == 0, f"Node failed: {res.stderr}"
    
    data = json.loads(res.stdout)
    assert data["path"] == ["first", "second", "done"]
    assert data["stopped"] == "terminal"


def test_compile_helpers(tmp_path):
    # Testing individual helpers ensures each stage of the compile pipeline operates independently.
    from prismpath.cli import _gather_compile_inputs, _build_compile_bundle, _write_compile_output

    flow_file = tmp_path / "flow.md"
    flow_file.write_text(P0_FLOW, encoding="utf-8")

    gathered_inputs = _gather_compile_inputs(str(flow_file), "p0")
    assert gathered_inputs is not None
    js_kernel, parsed_graph_js, embedded_lock_js, lock_info = gathered_inputs
    assert len(js_kernel) > 0
    assert "p0_flow" in parsed_graph_js
    assert embedded_lock_js == "null"

    bundle_code = _build_compile_bundle("p0", js_kernel, parsed_graph_js, embedded_lock_js)
    assert "// Auto-generated by prismpath compile --tier p0" in bundle_code
    assert "export const GRAPH =" in bundle_code
    assert "runFlow" in bundle_code

    output_path = tmp_path / "custom.bundle.mjs"
    status_code = _write_compile_output(str(output_path), bundle_code, str(flow_file), "p0", lock_info)
    assert status_code == 0
    assert output_path.exists()
    assert output_path.read_text(encoding="utf-8") == bundle_code


def test_model_check_context_no_deprecation_warning(tmp_path):
    # Verifying that the context parser subcommand does not trigger deprecated shim warnings.
    import argparse
    import warnings
    from prismpath.kernel import model_check

    flow_file = tmp_path / "flow.md"
    flow_file.write_text(P0_FLOW, encoding="utf-8")

    parent_parser = argparse.ArgumentParser()
    subparsers_action = parent_parser.add_subparsers(dest="command")
    model_check.add_parser(subparsers_action)

    parsed_args = parent_parser.parse_args(["context", str(flow_file), "--json"])

    with warnings.catch_warnings(record=True) as captured_warnings:
        warnings.simplefilter("always")
        exit_code = parsed_args.func(parsed_args)
        assert exit_code == 0
        shim_warnings = [
            warn_item for warn_item in captured_warnings
            if "prismpath.flow_context moved to prismpath.kernel" in str(warn_item.message)
        ]
        assert len(shim_warnings) == 0

