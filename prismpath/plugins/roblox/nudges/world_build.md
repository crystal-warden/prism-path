# Build: flesh out the WORLD of the tycoon — the physical place, not more server systems

GOAL: the game already has a DEEP engine — ~30 pure-core systems (cash, droppers, upgrades, prestige,
pets, boosts, quests, tiers, ascension, exchange, investments, and more), a playable storefront, and
save/load. But the WORLD it all lives in is BARE: a grey baseplate, one dropper, a few flat UI buttons.
The systems are invisible — they only exist as numbers.

The priority NOW is to make this a PLACE — the player's home BASE/HUB tycoon plot — and to give the
existing systems a physical, visible body:
- A laid-out plot the player owns and stands in: droppers, collectors, buildings, signs, and paths
  arranged as a coherent, readable space (not parts stacked at the origin).
- The economy made PHYSICAL: droppers that visibly produce, cash that flows through real parts/conveyors,
  and the upgrade you just bought visibly changing something in the world.
- Systems given a BODY: prestige/ascension shown in the world, pets as companions that follow you,
  boosts as visible effects, tiers as the plot physically expanding as you grow.
- Terrain, theme, lighting, skybox — an identity and mood, so it feels like a world, not a void.
- Interactive, JUICY feedback — things to touch, particles, sound, satisfying responses to input.
- A PORTAL structure on the plot (unlocked after the player banks $X) — for now just the physical portal
  in the hub; it will later transport the player to a separate combat map.

Build this as SERVER ADAPTERS (src/server/adapters/*.luau that create real Instances/Parts in workspace,
depending on ports, wired from the composition root so they actually appear in-game) and CLIENT visuals —
NOT new pure-core rulesets. Keep the architecture: adapters → ports → core; the pure core stays untouched;
the composition root wires every new adapter so nothing is dead.

THE BAR: a player should spawn into a home tycoon they want to explore and screenshot, where everything
they have built and upgraded is visible and alive around them.

(This is a deliberate redirect to WORLD-BUILDING the hub. A tower-defense layer — a portal to a separate
combat map with enemies, pets-as-towers, and resource-gathering — is the planned next phase. First, build
the world the current tycoon deserves.)
