# Build: a deep, FUN Roblox money-tycoon (Luau, Rojo project)

GOAL: a polished, addictive **Roblox money-tycoon** experience. A player walks onto their own plot,
buys droppers that produce cash, collects it, and reinvests into upgrades — the classic loop — but
the win condition is *retention and delight*, not just "it compiles". The game should keep growing in
PLAYER-FACING DEPTH every round.

The economic + world core already exists (cash, upgrades with cost-scaling, prestige/rebirth, physical
droppers + collectors, leaderstats, save/load). Do NOT keep re-optimizing what already works — the
council's job each EXPANSION round is to add a NET-NEW player-facing system the game still lacks, e.g.:

- **Boosts** — temporary multipliers (2x cash for N minutes) the player activates.
- **Quests / daily goals** — objectives that grant rewards and a reason to log in.
- **Pets / companions** — collectible helpers with passive bonuses (a fun flex).
- **Leaderboard / competition** — global or server ranking by net worth.
- **Codes / rewards** — redeemable codes granting cash or boosts.
- **Tiered plots / map expansion** — unlock new areas as wealth grows.

Each new system must be a pure CORE module (testable rules) wired through PORTS to engine ADAPTERS,
per the architecture contract — never a monolithic script, never touching `game`/`workspace` from core.
Keep the build green (parse + type-check + `rojo build` + Lune logic tests) at every step.

Make it FUN: progression hooks, juicy rewards, surprise, things a player would screenshot and brag
about. A player should always have a clear "one more upgrade / one more run" reason to keep playing.
