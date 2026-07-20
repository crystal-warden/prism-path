# Hard-won Luau / Roblox rules for this project

Authoritative, supervisor-verified rules distilled from real failures on this codebase. Treat these
as non-negotiable; they encode the exact mistakes that have broken the gate before.

## Require paths (the #1 recurring break)
This Rojo project maps `ReplicatedStorage` directly to `src/shared`, `ServerScriptService` to
`src/server`, and `StarterPlayer.StarterPlayerScripts` to `src/client`. Bind the service to a local ONCE at
the top, then require THROUGH the local — use EXACTLY:
- `local ReplicatedStorage = game:GetService("ReplicatedStorage")`  (once, at the top)
- shared core:  `require(ReplicatedStorage.core.X)`
- shared ports: `require(ReplicatedStorage.ports.Types)` / `.ports.AppService`
- server sibling adapter (from a server script): `require(script.Parent.adapters.X)`
- client sibling: `require(script.Parent.X)`
**Do NOT write `require(game:GetService("ReplicatedStorage").core.X)` inline.** It resolves at runtime, but the
`wiring_check` reachability parser reads the require's LAST identifier inside the FIRST paren — the inline
`GetService("ReplicatedStorage")` closes that paren early, so it records the dependency as `ReplicatedStorage`
and the real edge (`->CombatService`, `->Combat`, …) goes INVISIBLE → modules get falsely flagged "built but
DEAD." Requiring through the bound local (`require(ReplicatedStorage.core.X)`) parses correctly. NEVER edit a
`require` that already resolves; never reference `ReplicatedStorage`/`workspace` as a bare global in `--!strict`.

## nil-safety (the #2 recurring break)
A value typed `T?` is NOT a `T`. A type cast does NOT strip `nil` at runtime — `value :: T` is a
lie to the checker, not a guard.
- To narrow: `local v = assert(maybeNil, "why")` (returns the non-nil `T`), or `if maybeNil then ... end`.
- A typed local must be assigned a concrete value in EVERY branch before use.
- `instance:FindFirstChild(...)` returns `Instance?` — assert/guard before using it.

## String-literal-union enums (a silent type-widening trap)
A type like `type Rarity = "Common" | "Rare" | ...` is great, but luau WIDENS string literals to plain
`string` in two places that break `--!strict`:
- An array literal annotated with the union — `local rs: { Rarity } = { "Common", "Rare" }` — still
  infers element type `string`, so iterating it (`for _, r in rs`) gives `r: string`, NOT `Rarity`.
  Assigning that `r` back to a `Rarity`-typed variable fails with `Expected this to be '"Common" | ...'
  but got 'string'`. The `: { Rarity }` annotation does NOT fix it; cast at the USE site instead:
  `selectedRarity = r :: Rarity`. (Verified: the cast clears luau-lsp; annotating the literal does not.)
- Returning a bare string literal where the union is expected usually works, but a string built/picked
  at runtime needs the same `:: TheUnion` cast. This is the rare legitimate use of `::` (a literal-union
  narrowing the checker can't infer) — distinct from the nil-safety rule above, where `::` is forbidden.
- THE CAST MUST LAND IN A TYPED POSITION. `local x = expr :: Union` does NOT keep the union — the
  un-annotated local RE-WIDENS it straight back to `string`, and the error then surfaces at a LATER line
  (where `x` is passed into a typed param), not at the cast. Two fixes that actually hold:
  (a) inline the cast into the typed argument — `f(expr :: Union)` with no intermediate local (preferred); or
  (b) annotate the local — `local x: Union = expr` (the annotation, not a trailing `::`, is what pins it).
  A typed lookup table `{ [K]: Union }` does NOT reliably stop the widening either. Likewise inside a typed
  table literal, write `kind = "Tower" :: UpgradeKind` (cast each literal) — the field annotation alone can
  still widen. (Verified twice on the gembound combat layer, 2026-06-18.)
- THE MIRROR TRAP — NARROWING then comparing to an excluded member: `Type "Active" cannot be compared with
  "Victory"`. After you narrow a singleton-union variable (e.g. `local phase = svc.getPhase()` then
  `if phase ~= "Active" then return end`), luau KNOWS `phase` is now `"Active"` in the fall-through — so a
  LATER `phase == "Victory"` is provably disjoint and errors (the two literal sets don't overlap). Fixes:
  (a) compute what you need BEFORE the narrowing guard — `local won = svc.getPhase() == "Victory"` first; or
  (b) call the accessor FRESH at each use (`svc.getPhase() == "Victory"`) instead of reusing a narrowed local; or
  (c) branch with `if/elseif` over the members rather than guard-and-return-then-recompare. This bites phase /
  status / run-state enums (RunPhase = "Active"|"Victory"|"Defeat") in composition roots especially.

## Pure core (reducers must not leak)
Core/economy logic is pure: same input → same output, no `game`/services/Instances/`task`/`wait`.
- `table.clone` is SHALLOW. If you mutate a nested table (e.g. `state.upgrades`), clone THAT table
  too before writing; never assign the same nested table reference back into the new state.
- Reject invalid actions by returning the state UNCHANGED (and the SAME reference, so `newState == state`
  identity checks work).

## DataStore / persistence
- Wrap every `GetAsync`/`SetAsync`/`UpdateAsync`/`RemoveAsync` in `pcall` — a DataStore outage must
  never error the server. On load failure return `nil` and continue.
- Prefer `GlobalDataStore:UpdateAsync(key, transform)` for read-modify-write — it is race-safe;
  separate `GetAsync` then `SetAsync` can lose concurrent writes.
- Respect `DataStoreService:GetRequestBudgetForRequestType(...)`; back off when budget is low.
- Save on `Players.PlayerRemoving`, keyed by `tostring(player.UserId)`; keep a per-player table of
  state and clear it on leave.

## Server-authoritative networking (anti-exploit)
- NEVER trust the client. On `RemoteEvent.OnServerEvent`, validate every argument
  (`typeof(arg) == "string"`, range-check numbers, whitelist ids) before acting.
- Keep authoritative state on the server; the client only requests and renders.
- Use `UnreliableRemoteEvent` for high-frequency non-critical replication (position/cash ticks).

## Scheduling & deprecations
- Use `task.spawn` / `task.defer` / `task.wait` — never the deprecated `spawn`/`wait`/`delay`.

## Tests (Lune specs)
- When testing cost-scaling or level progression, the purchase must SUCCEED first: either fund the
  account (`ADD_CASH`) or buy with `cost = 0`. An unfunded buy is rejected, so the level never
  advances and the assertion fails — this has bitten multiple times.
- A spec requires its module by a path relative to the spec file; test only pure core (no engine).
- When you rename or add any symbol (a port field, function, upgrade id), update ALL call sites
  INCLUDING tests — grep for the old name first so nothing is left stale.

## Architecture (onion + hexagonal)
- Dependencies point inward: `adapters → ports → core`. The core requires nothing outward.
- A new feature is a new adapter/plugin or a small core extension — never core bloat.
- Every file `--!strict` and small; if a file exceeds ~4,000 tokens, split it along a seam first.

## Never use a literal-union type as a TABLE KEY (the recurring widening trap)
`type Kind = "A" | "B"` then `{ [Kind]: V }` is a trap: indexing that table with a variable (a loop key, a
field, a narrowed local) fails type-check with `Expected '"A" | "B"' but got 'string'` — Luau widens the
key to `string` at the access site, and `string` is not assignable back to the literal union.
- This bit StatusEffects (`{ [StatusKind]: Status }`) and Evolution (`{ [Choice]: Node }`) — both thrashed.
- FIX: make the storage table **string-keyed** — `{ [string]: V }` — and keep the literal union ONLY on the
  public function PARAMETERS (e.g. `apply(set, kind: Kind, ...)`), where it validates input at the boundary.
  Storing/looking-up uses plain string keys, which never widen.
- Rule of thumb: literal unions are great for `: Kind` params and field VALUES; never as `[Kind]` table keys.

## Runtime-only Roblox bugs the gate CANNOT catch (Studio test, 2026-06-19)
The luau_gate validates parse + type-check (real Roblox API) + `rojo build` + headless Lune core tests. It does
NOT run the live DataModel, so these classes of bug pass the gate green yet break on Play:

1. **PlayerAdded misses the local player in Studio Play Solo / fast joins.** Per-player setup placed ONLY in
   `Players.PlayerAdded:Connect(...)` never runs for a player who joined before the connect registered (always the
   case in Play Solo). Symptom cascade: no leaderstats (frozen HUD), no plot/dropper, and any RemoteFunction that
   reads per-player state returns nil so every client interaction silently bails. **FIX: always also iterate
   `Players:GetPlayers()` after the connect and run the same setup for them** (extract the handler to a named
   function; `for _,p in Players:GetPlayers() do task.spawn(setup, p) end`).
2. **Startup ordering: create the client-facing RemoteEvents/RemoteFunctions BEFORE any fallible work**, or a throw
   in (e.g.) an engine adapter build leaves the client's `WaitForChild` hanging forever -> no HUD/input. pcall-isolate
   risky startup builds so the critical infra (ground, remotes, per-player setup) always comes up.
3. **ProximityPrompt.ObjectText must EXACTLY equal the client's `if name == "..."` branch** or hold-E fires the
   handler but matches no branch and does nothing. Keep the server label and client switch in sync.
4. **A rojo-built .rbxl has no default Baseplate** unless the project defines one — build a guaranteed ground plane
   from a dependency-free script (or in the project) so players can't fall into the void.
