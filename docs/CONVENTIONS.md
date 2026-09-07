# Repo conventions

## Sample work vs. generic (adopter-facing) work

Any script an adopter is meant to run should make it obvious, at a glance, which of two things it is.
The distinction mirrors how the policy templates expose their input schema: inputs are surfaced, not
buried.

### Generic (adopter-configurable) scripts: a `CONFIGURE` block at the top

A script an adopter runs against their own environment exposes its inputs in one labelled block at the
very top of the file, before any logic:

```python
# ============================================================================
# CONFIGURE -- set these to your own environment, then run. Nothing below this
# block needs editing.
# ----------------------------------------------------------------------------
LLM_BASE   = os.environ.get("LLM_BASE", "http://127.0.0.1:8888/v1")  # your model endpoint
ORG        = {"org_name": "Example Org", ...}                        # your org profile
INPUT_PATH = None   # your data; None -> the built-in SAMPLE below
# ============================================================================
```

Rules:
- The block is the first thing after the imports the config needs (or before them if pure literals).
- Every adopter-changeable value lives here: endpoints, model ids, org profile, file paths, actor
  selection. An adopter should never have to read the body to find what to change.
- When a variable is left unset (e.g. `None`), the script falls back to a **clearly labelled built-in
  sample** so it still runs out of the box, and switches to the adopter's source when set.
- Environment-variable defaults are a valid form of this (surface them in the block with a comment).

Exemplars: `adapters/compliance/assess_texas.py`, `adapters/compliance/texas_ai_connector.py`.

### Sample work: a one-line `SAMPLE` label

A script that is a fixed illustration or a feature-proof (not something an adopter configures) says so
on its first docstring line:

```python
"""... (SAMPLE) -- fixed illustration, not configurable. See <the generic script> to run against
your own data."""
```

Exemplar: `adapters/compliance/demo_texas_ai.py`.

### Not in scope

Internal developer/build tooling (CLIs, linters, fixture generators, benchmarks, exporters) is not
adopter-facing and does not take a `CONFIGURE` block. Hardware/firmware research demos
(`prismpath-hw`, `prismpath-ebpf`) are a separate category, swept only on request.
