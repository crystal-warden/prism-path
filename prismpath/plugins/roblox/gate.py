"""Roblox/Luau validation gate — the Roblox-track analog of gates.validate_browser.

Same return contract as the browser gate (run_sprint.py consumes both identically):
  {valid, oversized, oversized_file, biggest, biggest_file, errs}

The gated pipeline (each layer a precondition for the next being meaningful, like the browser
gate deferring the behavioral check until the static checks are clean):
  1. syntax — `luau-analyze` parses every .luau/.lua file (keep only SyntaxError-class lines)
  2. type   — `luau-lsp analyze` with a Rojo sourcemap + the vendored Roblox API defs catches wrong
              API usage / undefined globals / type mismatches against the REAL engine surface
  3. build  — `rojo build` proves the tree + default.project.json produce a valid .rbxl place
  4. logic  — `lune run` executes *.spec.luau / *.test.luau headless (self-skips if there are none)
  5. studio — Tier-3 remote-Studio smoke gate (stub; self-skips unless STUDIO_RUNNER is set)

Every error string starts with the offending file's relpath ending in .luau/.lua/.json so the
builder's FILE_RE (run_sprint.py) feeds the right file body back for repair.

The toolchain lives in tools/bin/ and the API defs in tools/defs/ (vendored via tools/fetch.sh).
The gate DEGRADES GRACEFULLY: missing defs -> core-Luau type-checking (--platform=standard);
missing binary / no project file / no specs -> that layer self-skips. Runtime never hits the network.
"""
from __future__ import annotations

import glob
import os
import re
import subprocess
import tempfile
import uuid

from prismpath.gates import TOKENS_MAX, token_est

_HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(_HERE, "tools", "bin")  # toolchain is co-located in the plugin (plugins/roblox/tools/)
DEFS = os.path.join(_HERE, "tools", "defs", "globalTypes.d.luau")
LUAU_ANALYZE = os.path.join(BIN, "luau-analyze")
LUAU_LSP = os.path.join(BIN, "luau-lsp")
ROJO = os.path.join(BIN, "rojo")
LUNE = os.path.join(BIN, "lune")

PROJECT_FILE = "default.project.json"
TIMEOUT = 25            # match the browser gate's per-subprocess cap
BUILD_TIMEOUT = 40      # rojo build over a larger tree can be a touch slower

# Both tools print `<path>[ [DataModel/path]](line,col): Kind: message`. luau-analyze uses a relative
# `./path` (cwd=proj); luau-lsp uses an absolute path plus a ` [game/...]` DataModel annotation.
_DIAG = re.compile(r"^(?P<path>\S+\.luau?)(?:\s+\[[^\]]*\])?\((?P<line>\d+),(?P<col>\d+)\):\s*(?P<rest>.+)$")
_NOISE = ("[INFO]", "[WARN]", "WARNING:", "[ERROR", "[Stack Begin]", "[Stack End]")


def _dedupe(seq):
    seen, out = set(), []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def _run(cmd, cwd, timeout=TIMEOUT):
    """Run a tool; return (rc, combined_output) or (None, reason) if it could not run."""
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except FileNotFoundError:
        return None, "missing"
    except subprocess.TimeoutExpired:
        return None, "timeout"


def _rel(proj: str, path: str) -> str:
    """Normalize a tool-printed path (relative ./x or absolute) to a proj-relative path."""
    ap = path if os.path.isabs(path) else os.path.normpath(os.path.join(proj, path))
    rel = os.path.relpath(ap, proj)
    return rel if not rel.startswith("..") else os.path.basename(path)


def _diags(text: str, proj: str):
    """Parse `path(line,col): Kind: msg` diagnostics out of mixed tool output, dropping log noise."""
    out = []
    for line in text.splitlines():
        if any(n in line for n in _NOISE):
            continue
        m = _DIAG.match(line.strip())
        if m:
            out.append((_rel(proj, m.group("path")), m.group("rest").strip()))
    return out


def _excluded(rel: str) -> bool:
    # skip archive/hidden/vendor dirs (e.g. _archive/, .git/, .vscode/) — gate ONLY the live source tree.
    return any(seg.startswith((".", "_")) for seg in rel.split(os.sep)[:-1])


def _luau_files(proj: str):
    fs = glob.glob(os.path.join(proj, "**", "*.luau"), recursive=True) \
        + glob.glob(os.path.join(proj, "**", "*.lua"), recursive=True)
    return sorted(r for r in (os.path.relpath(f, proj) for f in fs) if not _excluded(r))


def luau_syntax_check(proj: str) -> list:
    """Parse every .luau/.lua file; report only SyntaxError-class diagnostics (no defs needed)."""
    files = _luau_files(proj)
    if not files:
        return []
    rc, out = _run([LUAU_ANALYZE, *files], cwd=proj)
    if rc is None:
        return [] if out == "missing" else [f"{files[0]}: luau-analyze timed out (>{TIMEOUT}s)"]
    if rc == 0:
        return []
    errs = [f"{rel}: {rest}" for rel, rest in _diags(out, proj) if rest.startswith("SyntaxError")]
    return _dedupe(errs)


def luau_type_check(proj: str) -> list:
    """Type-check against the real Roblox API (sourcemap + vendored defs). Degrades to core-Luau.

    Excludes the whole `tests/` tree (specs + their helpers like a Lune game-shim): it uses Lune's
    filesystem-require + custom-environment module system, not Roblox's DataModel requires, so it isn't part
    of the game and luau-lsp can't resolve its requires. It's validated by RUNNING it in lune_test_check.
    """
    def _in_tests(f: str) -> bool:
        return "tests" in f.replace(os.sep, "/").split("/")[:-1]
    files = [f for f in _luau_files(proj)
             if not f.endswith((".spec.luau", ".test.luau")) and not _in_tests(f)]
    if not files:
        return []
    sm = os.path.join(tempfile.gettempdir(), f"prismpath_sm_{uuid.uuid4().hex}.json")
    cmd = [LUAU_LSP, "analyze"]
    try:
        if os.path.isfile(os.path.join(proj, PROJECT_FILE)):
            rc, _ = _run([ROJO, "sourcemap", PROJECT_FILE, "-o", sm], cwd=proj)
            if rc == 0 and os.path.isfile(sm):
                cmd += ["--sourcemap", sm]
        if os.path.isfile(DEFS):
            cmd += ["--platform=roblox", "--definitions", f"@roblox={DEFS}"]
        else:
            cmd += ["--platform=standard"]   # core-Luau only; the behavioral-self-skip analog
        if os.path.isfile(os.path.join(proj, ".luaurc")):
            cmd += ["--base-luaurc", ".luaurc"]
        rc, out = _run([*cmd, *files], cwd=proj)
    finally:
        try:
            os.remove(sm)
        except OSError:
            pass
    if rc is None:
        return [] if out == "missing" else [f"{files[0]}: luau-lsp timed out (>{TIMEOUT}s)"]
    if rc == 0:
        return []
    return _dedupe(f"{rel}: {rest}" for rel, rest in _diags(out, proj))


def duplicate_module_check(proj: str) -> list:
    """Flag a module emitted under two extensions in the same dir (e.g. Main.lua AND Main.luau).

    Rojo turns both into instances with the same name — an ambiguous/duplicate module. The per-file
    layers can't see this (each file is individually valid); it's the structural drift that let a
    'valid' project ship two composition roots. Deterministic, so it routes straight to the fixer.
    """
    stems = {}
    for rel in _luau_files(proj):
        stems.setdefault(os.path.splitext(rel)[0], []).append(rel)
    errs = []
    for _stem, group in sorted(stems.items()):
        if len(group) > 1:
            g = sorted(group)
            errs.append(f"{g[0]}: duplicate module — also defined as {', '.join(g[1:])}; "
                        f"keep ONE (delete the others)")
    return errs


def rojo_build_check(proj: str) -> list:
    """`rojo build` must produce a valid place from the tree + default.project.json."""
    if not os.path.isfile(os.path.join(proj, PROJECT_FILE)):
        return []
    out_rbxl = os.path.join(tempfile.gettempdir(), f"prismpath_build_{uuid.uuid4().hex}.rbxl")
    try:
        rc, out = _run([ROJO, "build", PROJECT_FILE, "-o", out_rbxl], cwd=proj, timeout=BUILD_TIMEOUT)
    finally:
        try:
            os.remove(out_rbxl)
        except OSError:
            pass
    if rc is None:
        return [] if out == "missing" else [f"{PROJECT_FILE}: rojo build timed out (>{BUILD_TIMEOUT}s)"]
    if rc != 0:
        msg = next((l.strip() for l in out.splitlines() if l.strip()), "rojo build failed")
        return [f"{PROJECT_FILE}: rojo build failed: {msg[:200]}"]
    return []


def lune_test_check(proj: str) -> list:
    """Run *.spec.luau / *.test.luau headless under Lune. Self-skips when there are no specs."""
    specs = sorted(s for s in set(glob.glob(os.path.join(proj, "**", "*.spec.luau"), recursive=True)
                       + glob.glob(os.path.join(proj, "**", "*.test.luau"), recursive=True))
                   if not _excluded(os.path.relpath(s, proj)))
    errs = []
    for spec in specs:
        rel = os.path.relpath(spec, proj)
        rc, out = _run([LUNE, "run", rel], cwd=proj)
        if rc is None:
            if out == "timeout":
                errs.append(f"{rel}: lune test timed out (>{TIMEOUT}s)")
            continue   # binary missing -> skip the whole layer's signal gracefully
        if rc != 0:
            msg = next((l.strip() for l in out.splitlines()
                        if l.strip() and not l.strip().startswith("[Stack")), "test failed")
            errs.append(f"{rel}: lune test failed: {msg[:200]}")
    return _dedupe(errs)


def studio_smoke_check(proj: str) -> list:
    """Tier-3 remote Studio gameplay gate (the playwright-behavioral analog). Stub/seam.

    Self-skips unless STUDIO_RUNNER points at a logged-in Windows+GPU runner that drives a real
    Roblox Studio via run-in-roblox. Not implemented this session; left as a clear extension point.
    """
    if not os.environ.get("STUDIO_RUNNER"):
        return []
    return []   # TODO: ship the built .rbxl to STUDIO_RUNNER, assert it loads w/o script errors


def _modname(rel: str) -> str:
    b = os.path.basename(rel)
    for suf in (".server.luau", ".client.luau", ".server.lua", ".client.lua", ".luau", ".lua"):
        if b.endswith(suf):
            return b[: -len(suf)]
    return b


def wiring_check(proj: str) -> list:
    """DEAD-MODULE gate. A core module that compiles but is unreachable via `require()` from a
    composition root (a .server/.client script that auto-runs) is functional-but-DEAD — it drives
    nothing in-game, yet every other check passes. Flag it so the fixer wires it, turning 'it compiles'
    into 'it is actually wired'. Reachability resolves each require by its trailing module name
    (basenames are unique in this layout). Scoped to CORE modules (the game systems that MUST be driven;
    ports/adapters are wired by the composition root by definition)."""
    if not PLAYABILITY_GATE:
        return []                         # spec-driven layer builds: cores are wired at integration, not per-core
    files = [f for f in _luau_files(proj) if not f.endswith((".spec.luau", ".test.luau"))]
    roots = [_modname(f) for f in files
             if f.endswith((".server.luau", ".client.luau", ".server.lua", ".client.lua"))]
    if not roots:
        return []                                  # no composition root yet (early scaffold) — don't gate
    name2rel = {_modname(f): f for f in files}
    deps = {}
    for f in files:
        try:
            txt = open(os.path.join(proj, f), encoding="utf-8", errors="ignore").read()
        except OSError:
            continue
        txt = "\n".join(ln for ln in txt.splitlines() if not ln.lstrip().startswith("--"))
        reqs = set()
        for inner in re.findall(r"require\s*\(([^)]*)\)", txt):
            toks = re.findall(r"[A-Za-z_]\w*", inner)
            if toks:
                reqs.add(toks[-1])
        deps[_modname(f)] = reqs
    reach, stack = set(), list(roots)
    while stack:
        m = stack.pop()
        if m in reach:
            continue
        reach.add(m)
        for d in deps.get(m, ()):
            if d in name2rel and d not in reach:
                stack.append(d)
    errs = []
    for f in files:
        parts = f.replace(os.sep, "/").split("/")
        if "core" in parts[:-1] and _modname(f) not in reach:
            errs.append(f"{f}: built but DEAD — nothing requires it from a composition root. Wire it: "
                        f"`require` it in src/shared/ports/AppService.luau and invoke it in the update "
                        f"flow (add a port/adapter only if it touches the engine). Do NOT delete it.")
    return errs


# --- playability gates: a game can be green (compiles + wired) yet UNPLAYABLE. These confirm the two
# things the type-checker can't: a world the player spawns into, and a surface the player can reach. ----
PLAYABILITY_GATE = os.environ.get("PLAYABILITY_GATE", "1") == "1"
PRES_RATIO = int(os.environ.get("PRES_RATIO", "8"))    # cores may outpace surfaced actions by this factor
PRES_MIN = int(os.environ.get("PRES_MIN", "2"))        # but never fewer than this many surfaced actions


def _read_all(proj: str) -> dict:
    out = {}
    for f in _luau_files(proj):
        try:
            out[f] = open(os.path.join(proj, f), encoding="utf-8", errors="ignore").read()
        except OSError:
            out[f] = ""
    return out


def world_check(proj: str) -> list:
    """The physical world must actually EXIST at runtime: the world-build entry (spawnDropper) must be
    CALLED (not merely defined), and a SpawnLocation/Baseplate must exist so the player has somewhere to
    spawn and stand. A green but empty Workspace is not a playable tycoon."""
    if not PLAYABILITY_GATE:
        return []
    blob = "\n".join(_read_all(proj).values())
    try:
        blob += "\n" + open(os.path.join(proj, PROJECT_FILE), encoding="utf-8", errors="ignore").read()
    except OSError:
        pass
    errs = []
    if not re.search(r"\.spawnDropper\s*\(", blob):     # a CALL `x.spawnDropper(`; the def is `spawnDropper =`
        errs.append("world: WorldAdapter.spawnDropper is never called — the physical tycoon never spawns. "
                    "Call world.spawnDropper(plotId) per player at PlayerAdded and feed onCollectCash back "
                    "into the Economy core so collecting cash actually banks it.")
    if not re.search(r"SpawnLocation|Baseplate", blob):
        errs.append("world: no SpawnLocation/Baseplate anywhere — a built place spawns the player into an "
                    "empty void. Add a baseplate Part + a SpawnLocation (a server script at startup, or the "
                    "Workspace tree in default.project.json).")
    return errs


def presentation_check(proj: str) -> list:
    """The player must be able to REACH the systems. Ratcheting floor of surfaced actions (RemoteNet routes
    or client buttons) proportional to the number of core systems, plus a cash/stat HUD — so the storefront
    grows with the basement instead of staying one button while 19 systems hide on the server."""
    if not PLAYABILITY_GATE:
        return []
    files = _read_all(proj)
    cores = sum(1 for f in files if "core" in f.replace(os.sep, "/").split("/")[:-1])
    client = "".join(v for k, v in files.items() if "/client/" in "/" + k.replace(os.sep, "/"))
    net = "".join(v for k, v in files.items() if "Net" in os.path.basename(k))
    routes = len(re.findall(r"\bon[A-Z]\w*\s*=\s*function", net)) or len(re.findall(r"OnServerEvent", net))
    buttons = len(re.findall(r'Instance\.new\(\s*"(?:Text|Image)Button"', client))
    # Each distinct command the client fires is a surfaced action — this counts data-driven / helper-built
    # buttons that the raw Instance.new tally misses (DRY clients build many buttons from one constructor).
    fires = len(set(re.findall(r'FireServer\(\s*"([^"]+)"', client)))
    cmds = len(set(re.findall(r'\bcmd\s*=\s*"([^"]+)"', client)))
    surfaced = max(routes, buttons, fires, cmds)
    has_hud = bool(re.search(r'Instance\.new\(\s*"TextLabel"', client))
    required = max(PRES_MIN, cores // PRES_RATIO)
    errs = []
    if surfaced < required:
        errs.append(f"presentation: only {surfaced} player action(s) surfaced but the game has {cores} core "
                    f"systems — surface at least {required}. Add RemoteNet routes + client buttons for key "
                    f"systems players still can't reach (prestige, pets, daily reward, exchange, ...).")
    if not has_hud:
        errs.append("presentation: the client has no HUD — add a TextLabel showing the player's cash (and "
                    "ideally net worth / active boosts) so progress is visible beyond the default leaderstat.")
    return errs


def validate_luau(proj: str, tokens_max: int = TOKENS_MAX) -> dict:
    """Full Luau gate. Returns {valid, oversized, oversized_file, biggest, biggest_file, errs}."""
    errs, oversized_file, biggest, biggest_file = [], None, 0, None
    paths = (glob.glob(os.path.join(proj, "**", "*.luau"), recursive=True)
             + glob.glob(os.path.join(proj, "**", "*.lua"), recursive=True)
             + glob.glob(os.path.join(proj, "**", "*.json"), recursive=True))
    if not os.path.isfile(os.path.join(proj, PROJECT_FILE)):
        errs.append(f"missing {PROJECT_FILE}")
    errs += duplicate_module_check(proj)
    for p in paths:
        rel = os.path.relpath(p, proj)
        src = open(p, encoding="utf-8").read()
        tk = token_est(src)
        if tk > biggest:
            biggest, biggest_file = tk, rel
        if tk > tokens_max and (oversized_file is None
                                or tk > token_est(open(os.path.join(proj, oversized_file)).read())):
            oversized_file = rel

    errs += luau_syntax_check(proj)
    if not errs:
        errs += luau_type_check(proj)
    if not errs:
        errs += rojo_build_check(proj)
    if not errs:
        errs += lune_test_check(proj)
        errs += studio_smoke_check(proj)
    if not errs:
        errs += wiring_check(proj)        # a module can compile yet be unreachable (dead) — catch it
    if not errs:
        errs += world_check(proj)         # a green project can still spawn into an empty void —
        errs += presentation_check(proj)  # and hide every system behind one button. Confirm playability.
    return {"valid": not errs, "oversized": oversized_file is not None,
            "oversized_file": oversized_file, "biggest": biggest,
            "biggest_file": biggest_file, "errs": _dedupe(errs)}
