"""The plugin registry — discovery, audit, and worker binding for the prismpath plugin ecosystem.

The engine's purity non-goal stands untouched: plugins NEVER extend routing, predicates, or the
engine. What they extend is the HARNESS — the layer that was always allowed to do I/O:

  * **workers** — named tools a flow binds with the `@worker(plugin.name)` annotation; the binding
    lives in the document (diffable, reviewable) and `prismpath plugins --check flow.md` verifies every
    binding resolves against what is actually installed. Dispatched outcomes carry a `_worker`
    provenance field, so the transcript records which tool produced each hop.
  * **gates** — build/validation targets (the original seam; `gates.py`'s browser gate is built in).
  * **CLI** — a plugin may ship its own subcommands (`plugins/<name>/cli.py`).

Discovery is two-source, both auditable via `prismpath plugins [--json]`:
  1. bundled  — packages under `prismpath.plugins.*` (this directory),
  2. installed — Python entry points in group ``prismpath.plugins`` (a pip-installed
     `prismpath-foo` package registers `foo = its.module`), the seam third-party and
     private plugin packages load through without forking the repo.

A plugin is a MODULE with (all optional, by convention):
    NAME: str            canonical name (defaults to the module tail)
    VERSION: str         plugin version (defaults to "0")
    DESCRIPTION: str     one line for the audit listing
    WORKERS: dict        {worker_name: callable(node, instruction, state) -> outcome}
    validate(proj)       presence marks the plugin as a GATE (the load_gate contract)
    cli.py submodule     presence marks CLI subcommands
"""
from __future__ import annotations

import importlib
import json
import pkgutil
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

ENTRY_POINT_GROUP = "prismpath.plugins"


@dataclass
class PluginInfo:
    name: str
    module: str                       # import path
    source: str                       # "bundled" | "entry-point"
    version: str = "0"
    description: str = ""
    workers: List[str] = field(default_factory=list)
    is_gate: bool = False
    has_cli: bool = False

    def summary(self) -> dict:
        return {"name": self.name, "module": self.module, "source": self.source,
                "version": self.version, "description": self.description,
                "workers": self.workers, "gate": self.is_gate, "cli": self.has_cli}


def _inspect(name: str, module_path: str, source: str) -> Optional[PluginInfo]:
    try:
        mod = importlib.import_module(module_path)
    except Exception:
        return None                    # a broken plugin never takes the registry down
    workers = sorted((getattr(mod, "WORKERS", None) or {}).keys())
    has_cli = False
    if hasattr(mod, "__path__"):
        try:
            has_cli = importlib.util.find_spec(f"{module_path}.cli") is not None
        except (ImportError, ValueError):
            pass
    return PluginInfo(
        name=getattr(mod, "NAME", name), module=module_path, source=source,
        version=str(getattr(mod, "VERSION", "0")),
        description=(getattr(mod, "DESCRIPTION", "") or (mod.__doc__ or "").strip().splitlines()[0]
                     if (getattr(mod, "DESCRIPTION", "") or mod.__doc__) else ""),
        workers=workers, is_gate=callable(getattr(mod, "validate", None)), has_cli=has_cli)


def discover() -> Dict[str, PluginInfo]:
    """Every plugin visible right now, bundled first (an entry point may override a bundled name —
    the audit listing makes that visible rather than silent)."""
    found: Dict[str, PluginInfo] = {}
    import prismpath.plugins as _pkg
    for m in pkgutil.iter_modules(_pkg.__path__):
        if not m.ispkg and m.name in ("registry",):
            continue
        info = _inspect(m.name, f"prismpath.plugins.{m.name}", "bundled")
        if info:
            found[info.name] = info
    try:
        from importlib.metadata import entry_points
        eps = entry_points(group=ENTRY_POINT_GROUP)
    except Exception:
        eps = []
    for ep in eps:
        info = _inspect(ep.name, ep.value, "entry-point")
        if info:
            found[info.name] = info
    return found


def resolve_worker(ref: str) -> Callable:
    """`"plugin.worker"` -> the callable. Strict dotted form — a binding that names its plugin is a
    binding a reviewer can trace without guessing."""
    plugin, _, worker = ref.partition(".")
    if not plugin or not worker:
        raise KeyError(f"worker ref {ref!r} must be 'plugin.worker'")
    infos = discover()
    if plugin not in infos:
        raise KeyError(f"plugin {plugin!r} not installed (have: {sorted(infos)})")
    mod = importlib.import_module(infos[plugin].module)
    workers = getattr(mod, "WORKERS", None) or {}
    if worker not in workers:
        raise KeyError(f"plugin {plugin!r} has no worker {worker!r} (has: {sorted(workers)})")
    return workers[worker]


def _bound_ref(node) -> Optional[str]:
    """The `@worker(...)` binding on a node: bare form `@worker(council.tally)` or `name=` form."""
    args = node.annotations.get("worker")
    if args is None:
        return None
    if args.get("name"):
        return args["name"]
    return next((k for k, v in args.items() if v is None), None)


def worker_agent(graph, default: Optional[Callable] = None) -> Callable:
    """A harness agent for `graph` that dispatches `@worker`-annotated nodes to registry workers and
    everything else to `default`. Bindings resolve at CONSTRUCTION (one registry pass, fail-fast —
    a missing tool is discovered before the run starts, not at hop 40). The dispatched outcome (when
    a dict) gains a `_worker` provenance field, so the transcript and `_outcomes` record which
    installed tool produced each hop — the audit trail the binding annotation promises."""
    bound: Dict[str, tuple] = {}
    for name, n in graph.nodes.items():
        ref = _bound_ref(n)
        if ref is not None:
            bound[name] = (ref, resolve_worker(ref))       # raises KeyError up front if unresolvable

    def agent(node, instruction, state):
        hit = bound.get(node)
        if hit is None:
            if default is None:
                raise KeyError(f"node {node!r} has no @worker binding and no default agent was given")
            return default(node, instruction, state)
        ref, fn = hit
        out = fn(node, instruction, state)
        if isinstance(out, dict):
            out.setdefault("_worker", ref)
        return out
    return agent


def check_flow(graph) -> List[str]:
    """Ahead-of-time audit: every `@worker` binding in the flow resolves against the installed
    registry. Returns problems (empty = clean). This is the ecosystem's `validate` counterpart —
    run it in CI so a flow never reaches a host missing the tools it names."""
    problems = []
    for name, n in graph.nodes.items():
        args = n.annotations.get("worker")
        if args is None:
            continue
        ref = _bound_ref(n)
        if not ref:
            problems.append(f"node {name!r}: @worker has no name")
            continue
        try:
            resolve_worker(ref)
        except KeyError as e:
            problems.append(f"node {name!r}: {e.args[0]}")
    return problems


def audit(as_json: bool = False) -> str:
    """The human/CI-readable listing of everything installed and what each thing provides."""
    infos = discover()
    if as_json:
        return json.dumps({k: v.summary() for k, v in sorted(infos.items())}, indent=2)
    if not infos:
        return "no plugins installed"
    lines = []
    for name, i in sorted(infos.items()):
        provides = ([f"workers: {', '.join(i.workers)}"] if i.workers else []) \
                 + (["gate"] if i.is_gate else []) + (["cli"] if i.has_cli else [])
        lines.append(f"{name} {i.version} [{i.source}] — {i.description or i.module}")
        lines.append(f"    provides: {'; '.join(provides) or '(nothing declared)'}")
    return "\n".join(lines)
