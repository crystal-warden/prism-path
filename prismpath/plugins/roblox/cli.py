#!/usr/bin/env python3
"""Thin CLI wrapper around the luau gate, for use as an Aider/cecli --test-cmd.

Usage: python gate_cli.py [PROJECT_DIR]   (default: $SPRINT_PROJ or cwd)

Exit 0 + "GATE GREEN" on stdout when the project passes the full luau gate.
Exit 1 + the deduped error list on stderr otherwise, so the coding tool sees
exactly what to fix. The oversized-file tech-debt signal is surfaced too.
"""
import os
import sys

# cwprojects root (prismpath's parent) on the path so `import prismpath.*` resolves; cli.py is 3 dirs below it
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
from prismpath.plugins.roblox.gate import validate_luau  # noqa: E402


def main() -> int:
    proj = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("SPRINT_PROJ") or os.getcwd()
    proj = os.path.abspath(proj)
    r = validate_luau(proj)
    if r["valid"]:
        # oversized is a SOFT, non-blocking tech-debt signal — NOT a hard fail. Failing cecli's
        # --test-cmd on it made the model try to split the file mid-feature and botch it; surface it
        # as a warning instead so the build stays green and structure work happens deliberately.
        msg = f"GATE GREEN — {proj} passes (biggest file {r['biggest_file']} @ {r['biggest']} tok)"
        if r["oversized"]:
            msg += (f"\n  [tech-debt warning, non-blocking] {r['oversized_file']} exceeds the size "
                    f"budget — consider splitting along a seam later.")
        print(msg)
        return 0
    print("GATE RED — fix these before the project will build:", file=sys.stderr)
    for e in r["errs"]:
        print(f"  - {e}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
