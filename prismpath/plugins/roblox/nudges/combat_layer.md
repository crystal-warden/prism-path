Build the GEMBOUND combat layer — the tower-defense half of the game — ON TOP of the existing tycoon.
Do NOT rebuild, refactor, or touch the existing tycoon systems; only ADD the new combat-layer modules.

Every contract lives in `specs/`:
- `specs/GLOSSARY.md` is the canonical, non-negotiable TYPE contract. Obey its exact type names, field
  names, and function signatures everywhere a value crosses a module boundary.
- Each `specs/<Module>.md` is that module's full spec (purpose, contract, behavior, acceptance).

Build the pure-core modules in DEPENDENCY ORDER. `Elements` is the spine — every other module reads element
ids, named values, the strong/weak matchup, and gem tints from it. Each module is a single pure `--!strict`
core under `src/shared/core/` that composes the others ONLY through the GLOSSARY types — no per-entity element
branches, no duplicated rules. Implement exactly what each spec specifies: no more, no less.
