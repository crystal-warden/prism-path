---
name: roblox
start: design
---

## design
The ARCHITECT turns the goal into the smallest blueprint that delivers it — a file manifest
(core/ports/adapters/composition-root/specs) and the key port contracts, conforming to
ROBLOX_ARCHITECTURE.md. Design ONLY: it writes no code and hands off to the coder.
-> build: when always

## build
The CODER implements the blueprint (initially, then one reviewer-chosen improvement per turn) as small
`--!strict` ModuleScripts. It writes no tests and never validates its own work; it may emit
`DELETE: <path>` to remove a file.
-> test: when always

## test
The TEST-AUTHOR writes/maintains headless `*.spec.luau` specs that exercise the pure core's contract
adversarially — independent of the implementation. It owns specs; it never touches impl.
-> validate: when always

## validate
The Luau gate runs deterministic checks: parse, type-check against the real Roblox API, `rojo build`,
Lune specs, and the ~4k-token size budget.
-> fix: when not valid
-> refactor: when oversized
-> review: when valid

## fix
The FIXER makes the SMALLEST change to satisfy the gate (implementation only — the specs are the
authoritative contract, so it conforms code to them and never edits a spec). A spec that won't LOAD is
routed back to the test-author instead.
-> validate: when always

## refactor
The CODER splits an oversized file along an architecture seam (extract a core sub-module, a port, or an
adapter), preserving behavior and updating requires.
-> validate: when always

## review
The CRITIC reviews product quality, architecture, and blueprint adherence (flagging duplication/drift),
then chooses the single highest-value next improvement — or stops.
-> done: when visits > 8
-> build: when improve

## done
The experience has been iterated to a good, well-architected state. A human presses Play in Studio for
the final check. Stop.
