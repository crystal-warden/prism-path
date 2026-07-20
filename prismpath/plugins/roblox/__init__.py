"""Roblox / Luau gate plugin for prismpath — OPTIONAL. Load only when targeting Roblox.

This is the ONLY place in prismpath that knows about Roblox/Luau. It bundles everything platform-specific
behind the plugin interface: the Luau gate (parse / type-check vs the real Roblox API / rojo build /
headless Lune specs), the onion+hexagonal architecture contract, the hard-won Luau lessons, and the
Luau source extensions. The engine stays game- and platform-agnostic and talks only to this interface.
Extractable to a standalone `prismpath-roblox` package / docker image later.
"""
import os
from .gate import validate_luau

_HERE = os.path.dirname(os.path.abspath(__file__))

NAME = "roblox"
HAS_SPEC_LAYER = True  # the luau gate runs Lune *.spec.luau -> the test-author owns the specs
ARCH_PATH = os.path.join(_HERE, "ROBLOX_ARCHITECTURE.md")
LESSONS_PATH = os.path.join(_HERE, "lessons.md")
FILE_EXTS = (".luau", ".lua")
RAG_INDEX = os.path.join(_HERE, "rag", "luau.tvim")  # the Luau-docs vector index (grounding the coder)

# Project LAYOUT this target builds into — used to collect the files the coder edits ("focus"). The engine
# stays layout-agnostic; the Roblox onion/Rojo structure lives here.
SOURCE_DIRS = ("src/shared/core", "src/shared/ports", "src/server/adapters")
KG_SOURCE_DIRS = ("src/shared/ports", "src/server/adapters")  # KG/integration mode skips the bulk cores
CORE_DIR = "src/shared/core"                                  # spec-referenced cores get pulled in (KG mode)
ENTRY_FILES = ("src/server/main.server.luau", "src/client/Main.client.luau")  # composition roots
SPEC_SUFFIXES = (".spec.luau", ".test.luau")                 # the test-author's spec/test files (Lune-run)
TESTABLE_DIRS = ("src/shared/core", "src/shared/ports")      # layers the test-author can exercise headlessly

# A note appended to the planner's system prompt for this target (orchestrator.py).
PLANNER_NOTE = (
    "\n\nThis is a Roblox/Luau project. Be honest: we automatically compile it, type-check it against the real "
    "Roblox API, and run logic tests headless — but YOU press Play in Roblox Studio to confirm it's actually fun. "
    "Plan a Rojo project (default.project.json + small Luau ModuleScripts under src/)."
)

# Target-specific build conventions injected into the coder's prompt by the engine (it states only generic
# build discipline; the Roblox/onion-architecture rules live here).
BUILD_RULES_SPEC = (
    "Keep the core PURE and `--!strict`. Do NOT wire this into AppService and do NOT add ports/adapters — it is "
    "a pure core built in isolation; integration happens in a later phase."
)
BUILD_RULES = (
    "Keep the core pure and `--!strict` (a feature is a plugin/adapter). "
    "WIRE IT OR IT IS DEAD: a NEW core module does nothing until it is reachable from a composition root — you "
    "MUST `require` it in src/shared/ports/AppService.luau AND invoke it in the update flow (add a port + adapter "
    "only if it touches the engine). The gate fails on unwired modules. "
    "SURFACE IT OR THE PLAYER CAN'T REACH IT: a player-facing system also needs a RemoteNet route + a client UI "
    "affordance; the gate also checks the world spawns (spawnDropper is CALLED + a SpawnLocation exists) and a "
    "cash HUD is shown. Prefer surfacing an EXISTING system (a route + a button + HUD) over adding another hidden core."
)


def validate(proj: str) -> dict:
    return validate_luau(proj)
