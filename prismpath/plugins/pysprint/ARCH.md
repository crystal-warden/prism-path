# Architecture contract · Python module improvement (pysprint gate)

You are improving a single Python module, test-first. The rules:

- **One file per unit.** Each requirement names exactly one file in its `produces`. Edit only
  that file. Emit it whole: `FILE: <path>` on its own line, then a fenced code block.
- **The tests are the gate, and they are frozen.** `test_*.py` files encode the definition of
  done. Never edit them. Make the current requirement's test pass without breaking any other.
- **Keep it importable.** A syntax error or an import-time exception fails every test at once;
  the module must import cleanly after every edit.
- **Standard library only**, plus whatever the module already imports. Add no new dependencies.
- **Preserve the security posture.** This module (Mission Control) is loopback-only by design,
  fails closed on unknown identity, and audits every state-changing action before it acts. Do
  not weaken any of these. Do not widen `HOST` off `127.0.0.1`. Do not remove an audit call.
- **Small, surgical diffs.** Change the minimum to satisfy the requirement; leave unrelated code
  exactly as it was.
