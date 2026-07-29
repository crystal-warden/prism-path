"""The security half of the onion — a deterministic, non-weakenable safety boundary.

PrismPath's onion is security + observability wrapped around the engine. The observability half
already exists (`audit_log.py`, `ledger*.py`, attestation). This is the security half.

WHY IT IS A LAYER AND NOT AN ADAPTER
------------------------------------
A safety boundary that any one domain can define is not a boundary. This is cross-cutting: every
adapter inherits it and none can bypass it, so it lives in the core and carries **no domain nouns**
(`tools/arch_guard.py` Signal-1 is a hard fail on those). It speaks of policies, principals, text and
verdicts — never of any particular application.

THE TWO-AUTHOR MODEL
--------------------
Two different people with two different jobs write policy:

* A **safety owner** writes the *floor* — the statutory controls that must hold everywhere, authored
  once, centrally, by whoever actually tracks the regulatory landscape.
* A **flow author** writes *augmentations* — the runtime guardrails they can think of while authoring
  their own content, and any extra strictness their domain demands.

MONOTONICITY IS ENFORCED BY THE GRAMMAR, NOT BY A CHECK
-------------------------------------------------------
The obvious risk in letting flow authors touch safety is that one of them weakens it. So the policy
language **has no verb for permitting**. There is `deny` and nothing else. An augmentation can only
ever add denials; composing policies is a union. Weakening the floor is not "disallowed and checked
for" — it is *unsayable*. That is a much stronger guarantee than a validation pass, because there is
no expression for a reviewer to miss and no code path to get wrong.

DETERMINISTIC BY CONSTRUCTION (P0)
----------------------------------
Evaluation is literal and regex matching only — no model, no embeddings. The weakest device runs the
weakest model, so the guarantee has to be strongest exactly where the model is least trustworthy. A
guard that asked a small local model whether something was safe would be weakest precisely when it
matters most.

FAIL CLOSED
-----------
A malformed policy raises rather than being skipped, and a guard cannot be built without a floor. A
safety layer that silently degrades to permissive is worse than none, because it is trusted.

Policy documents are Markdown, so the people who write them can read them:

    ---
    name: statutory-floor
    authority: safety-owner
    precedence: floor
    ---

    ## self-harm
    Prose explaining why this rule exists, for the human reviewing it.

    direction: both
    citation: EU AI Act Art. 50
    message: Redirecting to support resources.
    deny: /\\bkill myself\\b/i
    deny: "literal phrase"
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Iterable, Sequence

__all__ = [
    "PolicyError",
    "Rule",
    "Policy",
    "Verdict",
    "Guard",
    "Blocked",
    "parse_policy",
    "parse_policy_file",
    "compose",
    "guarded_exchange",
    "INBOUND",
    "OUTBOUND",
]

#: Text heading toward a model or tool — what a principal supplies.
INBOUND = "inbound"
#: Text heading back toward a principal — what a model or tool produced.
OUTBOUND = "outbound"

_DIRECTIONS = (INBOUND, OUTBOUND)
_PRECEDENCES = ("floor", "augmentation")

_FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n(.*)$", re.DOTALL)
_HEADING_RE = re.compile(r"^##\s+(.+?)\s*$")
_ATTR_RE = re.compile(r"^([a-zA-Z_][\w-]*)\s*:\s*(.*)$")
_REGEX_LITERAL_RE = re.compile(r"^/(.*)/([a-zA-Z]*)$", re.DOTALL)


class PolicyError(ValueError):
    """A policy document is malformed. Raised rather than skipped — the layer fails closed."""


@dataclass(frozen=True)
class Rule:
    """One denial. There is no permitting counterpart, by design."""

    name: str
    #: Which crossings this applies to; a subset of (INBOUND, OUTBOUND).
    directions: tuple[str, ...]
    #: Compiled matchers. A rule with no patterns is rejected at parse time.
    patterns: tuple[re.Pattern[str], ...]
    #: Shown to the principal when this fires.
    message: str = ""
    #: The obligation or statute this implements, for the audit trail.
    citation: str = ""
    #: Prose from the document, kept so a human can review intent alongside effect.
    rationale: str = ""
    #: Name of the policy that contributed this rule.
    policy: str = ""
    #: "floor" | "augmentation" — floor rules come from the safety owner.
    precedence: str = "augmentation"

    def applies_to(self, direction: str) -> bool:
        return direction in self.directions

    def matches(self, text: str) -> bool:
        return any(p.search(text) for p in self.patterns)


@dataclass(frozen=True)
class Policy:
    name: str
    authority: str
    precedence: str
    rules: tuple[Rule, ...]
    #: sha256 of the source document — bind this into attestation so "which policy ran" is provable.
    source_hash: str = ""

    @property
    def is_floor(self) -> bool:
        return self.precedence == "floor"


@dataclass(frozen=True)
class Verdict:
    """The outcome of a crossing. `allowed=False` names exactly what stopped it and why."""

    allowed: bool
    direction: str = ""
    rule: str = ""
    policy: str = ""
    message: str = ""
    citation: str = ""
    precedence: str = ""

    def __bool__(self) -> bool:  # `if verdict:` reads as "was it allowed"
        return self.allowed


# ------------------------------------------------------------------------------------- parsing


def _parse_pattern(raw: str, rule_name: str) -> re.Pattern[str]:
    """Accept either `/regex/flags` or a quoted literal.

    A bare literal is matched case-insensitively and verbatim — policy authors are not expected to
    know regex, and a phrase written in a document should mean that phrase.
    """
    value = raw.strip()
    if not value:
        raise PolicyError(f"rule '{rule_name}': empty deny pattern")

    m = _REGEX_LITERAL_RE.match(value)
    if m:
        body, flags = m.group(1), m.group(2)
        f = 0
        for ch in flags:
            if ch == "i":
                f |= re.IGNORECASE
            elif ch == "s":
                f |= re.DOTALL
            elif ch == "m":
                f |= re.MULTILINE
            else:
                raise PolicyError(f"rule '{rule_name}': unknown regex flag '{ch}'")
        try:
            return re.compile(body, f)
        except re.error as e:
            raise PolicyError(f"rule '{rule_name}': invalid regex /{body}/: {e}") from e

    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1]
    if not value:
        raise PolicyError(f"rule '{rule_name}': empty deny pattern")
    return re.compile(re.escape(value), re.IGNORECASE)


def _parse_directions(raw: str, rule_name: str) -> tuple[str, ...]:
    value = raw.strip().lower()
    if value in ("both", "", "*"):
        return _DIRECTIONS
    parts = tuple(p.strip() for p in value.replace(",", " ").split() if p.strip())
    for p in parts:
        if p not in _DIRECTIONS:
            raise PolicyError(
                f"rule '{rule_name}': unknown direction '{p}' "
                f"(expected {INBOUND}, {OUTBOUND}, or both)"
            )
    return parts or _DIRECTIONS


def parse_policy(text: str) -> Policy:
    """Parse a policy document. Raises `PolicyError` on anything malformed."""
    m = _FRONTMATTER_RE.match(text)
    if not m:
        raise PolicyError("policy document must open with a --- frontmatter block")

    meta: dict[str, str] = {}
    for line in m.group(1).splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        am = _ATTR_RE.match(line)
        if not am:
            raise PolicyError(f"malformed frontmatter line: {line!r}")
        meta[am.group(1).lower()] = am.group(2).strip()

    name = meta.get("name", "").strip()
    if not name:
        raise PolicyError("policy frontmatter must set 'name'")
    authority = meta.get("authority", "").strip()
    if not authority:
        raise PolicyError(f"policy '{name}': frontmatter must set 'authority' (who owns this policy)")
    precedence = meta.get("precedence", "augmentation").strip().lower()
    if precedence not in _PRECEDENCES:
        raise PolicyError(
            f"policy '{name}': precedence must be one of {_PRECEDENCES}, got {precedence!r}"
        )

    rules: list[Rule] = []
    current: dict | None = None
    prose: list[str] = []

    def flush() -> None:
        if current is None:
            return
        if not current["patterns"]:
            raise PolicyError(
                f"policy '{name}': rule '{current['name']}' declares no 'deny:' pattern. "
                "A rule that denies nothing is almost certainly a mistake."
            )
        rules.append(
            Rule(
                name=current["name"],
                directions=current["directions"],
                patterns=tuple(current["patterns"]),
                message=current["message"],
                citation=current["citation"],
                rationale="\n".join(prose).strip(),
                policy=name,
                precedence=precedence,
            )
        )

    for line in m.group(2).splitlines():
        heading = _HEADING_RE.match(line)
        if heading:
            flush()
            prose = []
            current = {
                "name": heading.group(1).strip(),
                "directions": _DIRECTIONS,
                "patterns": [],
                "message": "",
                "citation": "",
            }
            continue

        if current is None:
            continue  # preamble prose before the first rule

        attr = _ATTR_RE.match(line.strip())
        if attr:
            key, value = attr.group(1).lower(), attr.group(2).strip()
            if key == "deny":
                current["patterns"].append(_parse_pattern(value, current["name"]))
                continue
            if key == "allow":
                # The whole point. Making this an error (rather than ignoring it) means an author who
                # tries to carve an exception is told plainly that the language cannot express one.
                raise PolicyError(
                    f"policy '{name}': rule '{current['name']}' uses 'allow:'. The policy language "
                    "has no permitting verb — composition is union-of-denials so that an "
                    "augmentation can never weaken the floor. Remove the rule instead."
                )
            if key == "direction":
                current["directions"] = _parse_directions(value, current["name"])
                continue
            if key in ("message", "citation"):
                current[key] = value
                continue
        if line.strip():
            prose.append(line.strip())

    flush()

    if not rules:
        raise PolicyError(f"policy '{name}': declares no rules")

    return Policy(
        name=name,
        authority=authority,
        precedence=precedence,
        rules=tuple(rules),
        source_hash=hashlib.sha256(text.encode("utf-8")).hexdigest(),
    )


def parse_policy_file(path: str) -> Policy:
    with open(path, "r", encoding="utf-8") as fh:
        return parse_policy(fh.read())


# --------------------------------------------------------------------------------- composition


@dataclass(frozen=True)
class Guard:
    """A composed, non-weakenable boundary.

    Built from one or more policies. At least one must be a floor policy: a guard with no floor is a
    configuration mistake, and this layer refuses rather than running permissively.
    """

    policies: tuple[Policy, ...]
    rules: tuple[Rule, ...] = field(default=())

    @property
    def policy_hash(self) -> str:
        """Stable hash of every contributing policy — bind into attestation to prove what ran."""
        h = hashlib.sha256()
        for p in sorted(self.policies, key=lambda p: p.name):
            h.update(p.name.encode("utf-8"))
            h.update(p.source_hash.encode("utf-8"))
        return h.hexdigest()

    def check(self, text: str, direction: str) -> Verdict:
        """Evaluate one crossing. Floor rules are checked first so they win attribution."""
        if direction not in _DIRECTIONS:
            raise ValueError(f"direction must be one of {_DIRECTIONS}, got {direction!r}")
        if text is None:
            text = ""

        for rule in self.rules:
            if rule.applies_to(direction) and rule.matches(text):
                return Verdict(
                    allowed=False,
                    direction=direction,
                    rule=rule.name,
                    policy=rule.policy,
                    message=rule.message,
                    citation=rule.citation,
                    precedence=rule.precedence,
                )
        return Verdict(allowed=True, direction=direction)

    def check_inbound(self, text: str) -> Verdict:
        return self.check(text, INBOUND)

    def check_outbound(self, text: str) -> Verdict:
        return self.check(text, OUTBOUND)

    def rule_names(self) -> tuple[str, ...]:
        return tuple(f"{r.policy}/{r.name}" for r in self.rules)


def compose(policies: Iterable[Policy] | Sequence[Policy]) -> Guard:
    """Compose policies into a guard. The result denies whatever ANY layer denies.

    Ordering only affects which rule is *named* when several would fire — floor rules sort first so a
    statutory citation is what surfaces. It can never affect *whether* text is denied, because there
    is no permitting verb for a later policy to override with.
    """
    pols = tuple(policies)
    if not pols:
        raise PolicyError("a guard needs at least one policy")
    if not any(p.is_floor for p in pols):
        raise PolicyError(
            "a guard needs at least one 'precedence: floor' policy. Running with only "
            "augmentations would mean the statutory baseline is absent — refusing rather than "
            "silently applying a weaker boundary."
        )

    seen: set[str] = set()
    for p in pols:
        if p.name in seen:
            raise PolicyError(f"duplicate policy name '{p.name}'")
        seen.add(p.name)

    floor = [r for p in pols if p.is_floor for r in p.rules]
    extra = [r for p in pols if not p.is_floor for r in p.rules]
    return Guard(policies=pols, rules=tuple(floor + extra))


# ------------------------------------------------------------------------------ the shim itself


@dataclass(frozen=True)
class Blocked(Exception):
    """Raised by `guarded_exchange` when a crossing is denied.

    Carries the verdict so a caller can render the policy's message and record the citation, rather
    than inventing its own explanation for a refusal.
    """

    verdict: Verdict

    def __str__(self) -> str:  # pragma: no cover - trivial
        v = self.verdict
        return f"blocked {v.direction} by {v.policy}/{v.rule}"


def guarded_exchange(guard: Guard, text: str, call, *, on_verdict=None) -> str:
    """Run one model/tool exchange with the boundary on both sides.

    This is the shim in the literal sense: it sits *between* the principal and whatever answers them.
    Inbound text is checked **before** `call` happens, so denied input never reaches the model at all;
    the response is checked before it is returned, so denied output never reaches the principal.

    The safe path is the only path worth taking here, so the signature makes it the easy one: a guard
    is a required positional argument, not an option with a permissive default. There is no
    `guarded_exchange(text, call)` overload that quietly skips the boundary, and an adapter that wants
    a model response has nothing simpler to reach for.

    `on_verdict` receives every verdict, allowed or not — wire it to `audit_log` / attestation so the
    observability half of the onion records what the security half decided. Bind `guard.policy_hash`
    into the attestation manifest and *which policy ran* becomes provable after the fact.

    Raises `Blocked` rather than returning a sentinel, so a caller that forgets to check cannot
    accidentally treat a refusal as a normal answer.
    """
    inbound = guard.check(text, INBOUND)
    if on_verdict is not None:
        on_verdict(inbound)
    if not inbound.allowed:
        raise Blocked(inbound)

    response = call(text)

    outbound = guard.check(response, OUTBOUND)
    if on_verdict is not None:
        on_verdict(outbound)
    if not outbound.allowed:
        raise Blocked(outbound)

    return response
