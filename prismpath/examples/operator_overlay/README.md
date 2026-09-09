# Operator overlay

A short lived policy change that expires by construction. `overlay.md` is a baseline posture with one
node the operator turns on during an incident; the hold ends on the operator's `stand_down` event or
on the worker's timer, and the run returns to the baseline node either way. No pack metadata, no
second policy, one signed flow.

```bash
prismpath validate prismpath/examples/operator_overlay/overlay.md
prismpath test     prismpath/examples/operator_overlay/overlay.md      # 6/6, deterministic
python -m pytest -q prismpath/tests/test_operator_overlay.py            # the real hold, stand down, and timer
```

The pattern and its limits (event edges are an engine feature; compiled table images skip them) are
in [`docs/guides/operator.md`](../../../docs/guides/operator.md).
