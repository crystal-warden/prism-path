# App architecture contract (onion + hexagonal hybrid)

You are building a single-page interactive browser app as a SMALL, LAYERED project of multiple
ES-module files — never one big file. Every file you write must conform to this architecture.

## The three rings (dependencies point INWARD only)

1. **CORE — the concept (innermost).** Pure domain logic: state, rules, transitions, scoring.
   Plain data + functions/classes. **No DOM, no canvas, no audio, no timers, no `window`, no
   I/O.** It imports nothing from the outer rings; it could run unchanged in plain Node. This is
   "the concept" and it must stay stable as features come and go.

2. **ONION ABSTRACTION — ports + application services (the compatibility layer).** Wraps the
   core. Defines **PORTS**: the contracts the core needs from the outside world (e.g. `Renderer`,
   `Input`, `Clock`, `Audio`, `Storage`) as JSDoc typedefs / documented shapes. Holds the
   **application service(s)** that drive the core through those ports. This ring exists to keep
   the core and the plugins COMPATIBLE: plugins can change freely as long as they honor the
   ports, and the core never has to change. Depends only on the core.

3. **HEXAGONAL PLUGINS — adapters (outer ring).** Each adapter is a **plugin** that implements
   ONE port with a concrete technology: `adapters/render.js` (canvas), `adapters/input.js`
   (keyboard/touch), `adapters/audio.js` (WebAudio), `adapters/storage.js` (localStorage), …
   Adapters depend on the ports (inward) and **never on each other or on the core's internals.**
   Adding a feature = adding or extending a plugin, not editing the core.

The **composition root** (`main.js`, loaded by `index.html`) is the ONLY place that knows the
concrete adapters; it instantiates them, wires them to the ports, and starts the application
service. Swapping a plugin (e.g. canvas → SVG renderer) must require touching only that adapter
and the composition root.

## Rules (non-negotiable)
- **Dependency rule:** imports point inward — `adapters → ports → core`. If the core needs
  anything external, define a PORT and let an adapter provide it. The core imports nothing outward.
- **Plugins are swappable and isolated:** no adapter imports another adapter.
- **Composition root only** wires concrete implementations.
- Use native ES modules (`<script type="module" src="main.js">`, relative imports). NO external
  resources / CDNs, NO backend, NO logins, NO payments — everything is local files.

## Tech-debt rule (HARD — pause and pay it down)
- Keep every file **focused and small**. **If ANY file exceeds ~4,000 tokens (~16 KB), STOP
  adding features and REFACTOR FIRST**: split that file along an architecture seam — extract a
  cohesive core sub-module, a port, or a separate adapter — so each file is small and
  single-purpose. An oversized file is the #1 tech-debt signal; pay the debt before it compounds.
- Prefer many small, single-responsibility files over a few large ones.

## Suggested layout
```
index.html        thin shell: markup + <script type="module" src="main.js"></script>
core/             pure domain (e.g. core/state.js, core/rules.js)
ports/            port contracts (JSDoc typedefs / documented shapes)
adapters/         one plugin per file (render.js, input.js, audio.js, …)
main.js           composition root: import core + adapters, wire ports, start
```

## How to emit files
Output each file as a line `FILE: <relative/path>` immediately followed by ONE fenced code
block containing that file's COMPLETE contents. Emit one or more files per turn. No prose.
