# Roblox/Luau architecture contract (onion + hexagonal, as a Rojo project)

You are building a Roblox experience as a SMALL, LAYERED Rojo project of many tiny Luau
ModuleScripts — never one big script. Every file you write must conform to this architecture. The
project is built and machine-validated automatically (parse, type-check against the REAL Roblox API,
`rojo build`, and headless logic tests); a human presses **Play in Roblox Studio** for the final
"is it fun" check. Build for the real engine, not a stub.

## The three rings (dependencies point INWARD only)

1. **CORE — the concept (innermost).** Pure domain logic: state, rules, transitions, scoring. Plain
   Luau tables + functions. **No `game`, no `workspace`, no services, no `Instance`, no
   `RemoteEvent`, no `task`/`wait`, no DataStore, no UI.** A core module imports nothing from the
   outer rings and ideally is a self-contained leaf — it could run unchanged under plain Lune. This
   is "the concept" and it must stay stable as features come and go.

2. **PORTS — contracts + application services (the compatibility layer).** Wraps the core. Defines
   **PORTS**: the contracts the core needs from the engine, written as Luau `export type` definitions
   (e.g. `Clock`, `Store`, `Net`, `Renderer`). Holds the **application service(s)** that drive the
   core through those ports. This ring keeps the core and the adapters COMPATIBLE: adapters can change
   freely as long as they honor the ports, and the core never has to change. Depends only on the core.

3. **ADAPTERS — engine plugins (outer ring).** Each adapter implements ONE port with a concrete
   Roblox technology: a DataStore-backed `Store`, a `RemoteEvent`-backed `Net`, a `Players`/`Humanoid`
   adapter, a GUI renderer. Adapters touch the engine (services, Instances, events) and depend on the
   ports (inward), **never on each other or on the core's internals.** Adding a feature = adding or
   extending an adapter, not editing the core.

The **composition root** is the ONLY place that knows the concrete adapters: a top-level `Script` in
`ServerScriptService` (and/or a `LocalScript` in `StarterPlayerScripts`) that requires the core +
adapters, wires them to the ports, and starts the application service. Swapping an adapter (e.g.
DataStore → MemoryStore) must require touching only that adapter and the composition root.

## Rules (non-negotiable)
- **Dependency rule:** requires point inward — `adapters → ports → core`. If the core needs anything
  from the engine, define a PORT (a Luau type) and let an adapter provide it. The core requires
  nothing outward and never touches `game`/services/Instances.
- **Adapters are swappable and isolated:** no adapter requires another adapter.
- **Composition root only** wires concrete implementations and reaches for services.
- Type-safety is enforced: every file starts with `--!strict`. The type-checker runs against the real
  Roblox API (DataModel, services, Instance types), so use the actual API correctly — undefined
  globals, wrong service names, and type mismatches FAIL the gate.

## Rojo project shape
- A root **`default.project.json`** maps your `src/` tree into the DataModel. Split source by service.
  Minimal example:
```json
{
  "name": "MyGame",
  "tree": {
    "$className": "DataModel",
    "ReplicatedStorage": { "$path": "src/shared" },
    "ServerScriptService": { "$path": "src/server" },
    "StarterPlayer": {
      "StarterPlayerScripts": { "$path": "src/client" }
    }
  }
}
```
- **Layout:** `src/shared/` = core + ports (pure ModuleScripts shared by server & client);
  `src/server/` = server adapters + the server composition-root `Script`; `src/client/` = client
  adapters + the client composition-root `LocalScript`.
- **Requires inside the game** use Roblox resolution, e.g.
  `require(script.Parent.Rules)` or `require(game:GetService("ReplicatedStorage").Counter)`.

## Headless logic tests (this is the behavioral gate you can satisfy locally)
- Put assertion specs in `tests/` named `*.spec.luau`. They run headless under **Lune**, so they
  CANNOT use the engine — they test only **pure core modules**.
- A spec `require`s the module it tests by a **path relative to the spec file** (Lune string-require):
  `local Rules = require("../src/shared/Rules")`, then `assert(...)` on its behavior. Errors on
  failure, returns normally on success.
- Because Lune can't load engine code, keep the testable core modules as self-contained leaves (no
  inward requires of other modules), so a spec can load one in isolation. Adapter/engine behavior is
  validated by type-check + `rojo build` (and, when available, a real-Studio smoke run), not by Lune.

## Tech-debt rule (HARD — pause and pay it down)
- Keep every file **focused and small**. **If ANY file exceeds ~4,000 tokens (~16 KB), STOP adding
  features and REFACTOR FIRST**: split it along an architecture seam — extract a cohesive core
  sub-module, a port, or a separate adapter — so each file is small and single-purpose. An oversized
  file is the #1 tech-debt signal; pay the debt before it compounds. Prefer many small,
  single-responsibility ModuleScripts over a few large ones.

## How to emit files
Output each file as a line `FILE: <relative/path>` immediately followed by ONE fenced code block
containing that file's COMPLETE contents (use ```` ```luau ```` for Luau, ```` ```json ```` for the
project file). Emit one or more files per turn. No prose. Always include `default.project.json` and at
least one core module + its spec in the initial project.
