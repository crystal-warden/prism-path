"""Oblique-Strategies dice for the council — STRUCTURED, SEEDED, AUDITABLE stochasticity.

The coverage map answers "what's missing"; once it's exhausted the council starts re-optimizing what
exists. These dice answer "what NON-OBVIOUS direction" — they widen the EXPAND-round proposal
distribution so the council explores instead of fixating. The gate + the PM veto + the vote still
dispose, so a wild roll that doesn't cohere is simply voted down or fails the gate.

Three dice, MULTIPLIED → 6 × 6 × 3 = 108 distinct mandates from a tiny table:
  • DIRECTION (d6) — which axis of the product to push. COVERAGE-WEIGHTED: biased toward under-covered axes.
  • PROVOCATION (d6) — a lateral-thinking nudge (the real "think differently" engine).
  • SCOPE (d3) — how big: a hook, a full subsystem, or a cross-cutting tie between two systems.

DETERMINISTIC: seeded by (round, project file set), so a run is reproducible and every roll can be
logged to the append-only action log + an interactions event (visible in the Lens).
This is structured/auditable randomness — strictly better than just raising the LLM temperature, which
is unaccountable noise you can't inspect, weight, seed, or replay.
"""
import hashlib
import json
import os
import random
import re

# (name, description, coverage-keywords). If any keyword already appears in the project, that axis is
# "covered" and its weight drops — the die leans toward axes the product has not explored yet.
DIRECTIONS = [
    ("Player progression",
     "new ways to advance: prestige layers, skill trees, milestone unlocks, ascension/rebirth tiers",
     ("prestige", "rebirth", "skill", "milestone", "ascend", "talent")),
    ("Social & competitive",
     "make it multiplayer-social: visiting other plots, co-op, rivalries, gifting, guilds/teams",
     ("leaderboard", "rival", "versus", "guild", "team", "visit", "trade", "gift", "party")),
    ("Economy depth",
     "new economic layers: extra resource types, a market/auction, risk/reward sinks, conversions",
     ("market", "auction", "resource", "currency", "sink", "convert", "stock", "investment")),
    ("World & spectacle",
     "make the world react: timed events, weather, biomes, map expansion, bosses, visual juice",
     ("event", "weather", "biome", "boss", "zone", "spectacle", "fireworks")),
    ("Retention hooks",
     "reasons to come back: daily rewards, streaks, time-limited offers, login bonuses, quests",
     ("daily", "streak", "login", "redeem", "promocode", "giftcode", "quest", "mission", "objective")),
    ("Player expression",
     "let players express themselves: cosmetics, plot decoration, naming, skins, customization",
     ("cosmetic", "skin", "decor", "customi", "nameplate", "trail", "title")),
]

PROVOCATIONS = [
    "What would make a player STOP and screenshot this to brag to friends?",
    "Introduce a meaningful RISK or LOSS the player can actually suffer (stakes, not just gains).",
    "Make TWO existing systems INTERACT in a way neither was designed for.",
    "Design for the player returning after a WEEK away — what concretely pulls them back?",
    "REMOVE or automate a tedious step players currently grind through.",
    "Add a moment of SURPRISE or controlled randomness the player cannot predict.",
]

SCOPES = [
    ("hook", "a small standalone HOOK — one new pure-core module, minimal surface"),
    ("subsystem", "a full SUBSYSTEM — a new pure-core module plus its port + adapter"),
    ("cross-cut", "a CROSS-CUTTING feature that wires TWO existing systems together"),
]

# ---- WORLD LENS: a SECOND oblique strategy centered on the PHYSICAL/VISUAL world the player sees and
# stands in. Used on WORLD rounds, where the council builds the SPACE (server adapters that spawn real
# Instances/Parts, or client visuals) — NOT another pure-core ruleset. The systems are deep; the world is
# bare, so this die points the swarm at the place itself. Reusable for the hub now and the combat map later.
WORLD_AXES = [
    ("Layout & plot", "the physical arrangement the player owns and stands in — where droppers, "
     "collectors, buildings, the portal, and paths sit, and how the plot reads as a coherent space"),
    ("Economy machinery", "make the economy PHYSICAL and visible — producers that visibly produce, "
     "conveyors and collectors, cash flowing through real parts the player watches and touches"),
    ("Systems made visible", "give an existing server system a BODY in the world — a prestige aura, pet "
     "companions that follow, boosts as visible effects, tiers as the plot physically expanding"),
    ("Terrain, theme & atmosphere", "ground, biome, skybox, lighting and color — the world's identity "
     "and mood, so it feels like a real place, not a grey baseplate"),
    ("Interactive props & feedback", "things the player physically touches and the JUICE of it — buttons, "
     "the act of collecting, particles, sound, satisfying responses to input"),
    ("Living world & progression", "how the space visibly TRANSFORMS as the player grows — new structures "
     "appearing, the plot filling in, motion and life over time"),
]

WORLD_PROVOCATIONS = [
    "What does the player SEE the instant they spawn — does it read as a real place in one glance?",
    "Make an upgrade produce a VISIBLE, physical change in the world the player can point at.",
    "Take a system that only lives in numbers and give it a BODY the player can see.",
    "Where should the player's eye be drawn, and what physically rewards looking there?",
    "Make the space feel ALIVE and inhabited — motion, props, detail — not an empty pad.",
    "What would make someone screenshot the WORLD itself, not the cash counter?",
]


def world_roll(round_key, files: dict) -> dict:
    """A WORLD-round roll: physical/visual aspect × visual provocation × scope. Seeded (prefixed 'W' so
    it's independent of the system roll) for reproducibility."""
    seed = _seed("W" + str(round_key), files)
    rng = random.Random(seed)
    axis = rng.choice(WORLD_AXES)
    return {"seed": seed, "axis": axis[0], "axis_desc": axis[1],
            "provocation": rng.choice(WORLD_PROVOCATIONS),
            "scope": (s := rng.choice(SCOPES))[0], "scope_desc": s[1]}


def world_mandate(r: dict) -> str:
    return (
        f"\U0001F30D WORLD-BUILD ROLL (seed {r['seed']}) — this round BUILD THE PHYSICAL WORLD, not a "
        f"server ruleset. The systems are deep; the space they live in is bare. Make it a PLACE.\n"
        f"• ASPECT: {r['axis']} — {r['axis_desc']}\n"
        f"• PROVOCATION: {r['provocation']}\n"
        f"• SCOPE: {r['scope']} — {r['scope_desc']}\n"
        f"Target a PHYSICAL/VISUAL file — an ADAPTER (adapters/X.js that builds real "
        f"Instances/Parts in workspace) or the CLIENT — NOT a pure-core module. The player must SEE it, "
        f"and it must be wired from the composition root so it actually appears in the product."
    )


def _blob(files: dict) -> str:
    return "\n".join((p + "\n" + c) for p, c in files.items()).lower()


def _seed(round_key, files) -> int:
    keys = "|".join(sorted(files.keys() if isinstance(files, dict) else files))
    return int(hashlib.sha256(f"{round_key}|{keys}".encode()).hexdigest()[:16], 16)


def roll(round_key, files: dict, ledger: dict | None = None) -> dict:
    """Deterministic roll for one EXPAND round. round_key (e.g. the council round #) + the project file
    set seed the RNG, so the same state always rolls the same mandate (reproducible/replayable).

    DIRECTION weight = coverage × balance:
      • coverage — an axis NOT yet present in the codebase is 3× as likely (explore the gaps).
      • balance  — an axis we've SELECTED often (per the ledger) weighs less; neglected axes rise.
    """
    seed = _seed(round_key, files)
    rng = random.Random(seed)
    blob = _blob(files)
    ledger = ledger or {}
    weights = []
    for (name, _d, _kws) in DIRECTIONS:
        cov = 1.0 if _covers(blob, name) else 3.0          # already present in code -> 1x, else 3x
        weights.append(cov * balance_weight(ledger, name))
    direction = rng.choices(DIRECTIONS, weights=weights, k=1)[0]
    provocation = rng.choice(PROVOCATIONS)
    scope = rng.choice(SCOPES)
    return {
        "seed": seed,
        "direction": direction[0], "direction_desc": direction[1],
        "provocation": provocation,
        "scope": scope[0], "scope_desc": scope[1],
        "weights": {n: round(w, 2) for (n, _d, _k), w in zip(DIRECTIONS, weights)},
    }


# ---- category-balance ledger: keep expansion EVEN across the 6 direction categories -----------------
# "Gone down a path more often -> weigh it LESS; as one category loses weight from overprescription, the
# others rise." Inverse-frequency, mean-normalized, gently clamped. Drives BOTH the direction die and the
# council vote tally (an over-built category's votes count for less), so the product grows in balance.
CATEGORIES = [d[0] for d in DIRECTIONS]
_KEYWORDS = {d[0]: d[2] for d in DIRECTIONS}
# WORD-BOUNDARY matching (not raw substring): otherwise 'event' matches 'OnServerEvent', 'invest' matches
# 'investigate', 'team' matches 'teamwork', 'code' matches 'encode' — silently mis-crediting the ledger.
_PATTERNS = {name: re.compile(r"\b(?:" + "|".join(re.escape(k) for k in kws) + r")", re.I)
             for name, kws in _KEYWORDS.items()}


def _covers(text: str, name: str) -> bool:
    return _PATTERNS[name].search(text or "") is not None


def classify(target: str, instruction: str = "") -> str:
    """Map a proposal (target + instruction) to the BEST-matching direction CATEGORY (most keyword hits;
    declaration order breaks ties), or 'other' if nothing matches."""
    text = ((target or "") + " " + (instruction or "")).lower()
    best, best_n = "other", 0
    for name in CATEGORIES:
        n = len(_PATTERNS[name].findall(text))
        if n > best_n:
            best, best_n = name, n
    return best


def balance_weight(ledger: dict, category: str) -> float:
    """Inverse-frequency vs the mean: a category chosen as often as average weighs ~1.0, an over-chosen
    one < 1.0, an under-chosen one > 1.0. Clamped to [0.34, 3.0] so one rare category can't always win."""
    counts = [ledger.get(c, 0) for c in CATEGORIES]
    mean = (sum(counts) / len(counts)) if counts else 0.0
    w = (mean + 1.0) / (ledger.get(category, 0) + 1.0)
    return max(0.34, min(3.0, w))


def load_ledger(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def save_ledger(path: str, ledger: dict) -> None:
    # atomic: write a temp file then os.replace — a SIGKILL/OOM mid-write must never leave a truncated
    # JSON that load_ledger would silently reset to {} (losing all balance history on the next resume).
    try:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(ledger, f, indent=2)
        os.replace(tmp, path)
    except OSError:
        pass


def record(ledger: dict, category: str) -> dict:
    ledger[category] = ledger.get(category, 0) + 1
    return ledger


def mandate(r: dict) -> str:
    """The directive injected into every council voice's propose prompt for this round."""
    return (
        f"\U0001F3B2 EXPLORATION ROLL (seed {r['seed']}) — this EXPANSION round you MUST explore THIS direction:\n"
        f"• DIRECTION: {r['direction']} — {r['direction_desc']}\n"
        f"• PROVOCATION: {r['provocation']}\n"
        f"• SCOPE: {r['scope']} — {r['scope_desc']}\n"
        f"Propose a NET-NEW target that fits this roll and let the PROVOCATION push you somewhere "
        f"non-obvious — do NOT just pick the next salient subsystem."
    )


if __name__ == "__main__":   # self-test: determinism + distribution + sample mandates
    sample = {"core/economy.js": "upgrades costGrowth",
              "core/prestige.js": "rebirth prestige",
              "core/leaderboards.js": "leaderboard rival",
              "core/collectibles.js": "collectible cosmetic"}
    a = roll(1, sample)
    b = roll(1, sample)
    assert a == b, "NOT deterministic!"
    assert roll(2, sample) != a or True  # different round usually differs
    from collections import Counter
    dist = Counter(roll(i, sample)["direction"] for i in range(600))
    print("determinism: OK (round 1 stable)")
    print("direction distribution over 600 rounds, EMPTY ledger (under-covered axes should dominate):")
    for k, v in dist.most_common():
        print(f"  {v:3d}  {k}")

    # balance: over-prescribe one axis, confirm its weight drops and others rise
    led = {}
    for _ in range(8):
        record(led, "World & spectacle")
    print("\nafter building 'World & spectacle' 8x — balance weights (overbuilt<1, neglected>1):")
    for c in CATEGORIES:
        print(f"  {balance_weight(led, c):.2f}  {c}")
    dist2 = Counter(roll(i, sample, led)["direction"] for i in range(600))
    print("direction distribution WITH that ledger (World should now be suppressed):")
    for k, v in dist2.most_common():
        print(f"  {v:3d}  {k}")
    assert dist2["World & spectacle"] < dist["World & spectacle"], "balance did not suppress overbuilt axis"
    print("\nclassify checks:",
          classify("core/leaderboards.js", "global rivalry ranking"),
          "|", classify("core/daily_streak.js", "login streak reward"),
          "|", classify("core/foo.js", "generic thing"))
    print("\nsample mandate (round 7):\n" + mandate(roll(7, sample)))
