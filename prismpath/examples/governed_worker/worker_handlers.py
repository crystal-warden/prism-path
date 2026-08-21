# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Verify handler for governed_worker.md.

One leaf action: evaluate the task's gates and emit verdict fields. The branching lives on the
flow's edges, never in here. Gates that must WRITE (cargo, pytest with caches) should be run by
the driver outside the read-only sandbox and passed in as ``precomputed_gates``; read-only gate
commands may run here directly via ``gate_cmds``.
"""
import subprocess


def verify(node, instruction, state):
    if "precomputed_gates" in state:
        results = state["precomputed_gates"]
        ok = all(r["rc"] == 0 for r in results)
    else:
        results, ok = [], True
        for cmd in state.get("gate_cmds", []):
            r = subprocess.run(cmd, shell=True, cwd=state.get("workspace", "."),
                               capture_output=True, text=True,
                               timeout=state.get("gate_timeout", 300))
            results.append({"cmd": cmd, "rc": r.returncode,
                            "tail": (r.stdout + r.stderr)[-400:]})
            ok = ok and r.returncode == 0
    return {"gates_pass": ok, "claimed_success": bool(state.get("claimed_success")),
            "gate_results": results,
            "text": f"gates_pass={ok} claimed={state.get('claimed_success')} "
                    f"({len(results)} gates)"}
