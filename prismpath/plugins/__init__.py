"""prismpath plugins — the harness-side extension ecosystem.

A plugin packages non-core capability behind ONE uniform, auditable boundary so the engine stays
pure and domain-agnostic. Three extension slots (see `registry.py`, the discovery/audit layer):

  * **workers** — named tools a flow binds with `@worker(plugin.name)`; the binding lives in the
    document, `prismpath plugins --check` verifies it resolves, outcomes carry `_worker` provenance.
  * **gates** — build/validation targets (the original seam; `roblox` is the exemplar). Interface:
    NAME, HAS_SPEC_LAYER, ARCH_PATH, LESSONS_PATH, FILE_EXTS, validate(proj) -> {valid, errs, ...}.
  * **cli** — a `cli.py` submodule adds plugin subcommands.

Discovery: bundled packages here + pip-installed entry points (group ``prismpath.plugins``) — the seam
third-party and private plugin packages load through without forking the repo. The engine never
imports a plugin; plugins extend the HARNESS, and routing/predicates/engine purity are not
extensible on purpose.
"""
import importlib

_ALIASES = {"luau": "roblox"}  # back-compat: SPRINT_GATE=luau -> the roblox plugin


def load_gate(name: str):
    """Import and return the gate plugin module for `name` (raises ModuleNotFoundError if absent)."""
    mod = _ALIASES.get(name, name)
    return importlib.import_module(f"prismpath.plugins.{mod}")
