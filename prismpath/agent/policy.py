# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The owner's agent rules as a signed core policy, and the one decision per proposed tool call.

The policy is `policy/agent_rules.core.json`, a `prismpath.core/1` image in its canonical canon/2 bytes,
compiled from the readable rules `agent_rules.rules.md` by `prismpath policy compile`
(`prismpath.kernel.policy_source`); `agent_rules.src.json` is the same image as written JSON, and both
compile to these bytes exactly (tests/test_policy_source.py). It is decided by the repository's
own code, nothing reimplemented here:

  * the image is checked by the port of the Lean oracle's `loadPolicy` (`prismpath.kernel.core_policy`),
    which must accept it;
  * it is rendered to its canonical flow text (`prismpath.kernel.core_render.render`, the rendering a core
    run stores and the evidence verifier holds every stored flow to) and
    parsed by the reference kernel (`prismpath.kernel.parser.parse`), which applies the field definitions
    and the six policy rules of SPEC.md section 4.5;
  * a reading is decided by the reference's decision path (`prismpath.kernel.core_reference.python_reading`: the strict canon/2
    reader, the system boundary, the first deterministic rule that holds), and every receipted decision
    is replayed through the Lean oracle when the run is verified (evidence.py).

A rule's target says what the harness does with the call, and names the cause by its registered code, so
the cause is part of the signed image rather than a table beside it:

  allow            the call runs, in the sandbox
  refuse_<code>    the call never runs; the decision is a refusal with that registered cause
  escalate_<code>  the call never runs; it is held for the owner, with that registered cause

A refusal of the core itself (a reading the boundary refuses, `route:contract-violation`; no rule holds,
`route:no-matching-edge`; a reading that does not read) is a refusal too. There is no catch all allow:
what no rule allows is refused by the core, so the policy fails closed by the core's own semantics.
"""
from __future__ import annotations

import hashlib
import itertools
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

HERE = Path(__file__).resolve().parent

from prismpath.kernel import canon2, causes, core_policy, core_reference, core_render  # noqa: E402
from prismpath.kernel.parser import parse  # noqa: E402

POLICY_PATH = HERE / "policy" / "agent_rules.core.json"
SOURCE_PATH = HERE / "policy" / "agent_rules.src.json"
DEFAULT_POLICY_PATH = HERE / "policy" / "agent_default.core.json"   # agent_rules, but an unreadable call asks

# The starter policies `prismpath agent init --policy` offers, each a readable source `<image>.rules.md` beside
# the canonical image `<image>.core.json` it compiles to byte for byte. They ship unsigned in the wheel; `init`
# attests the chosen image with the user's own authority key, as it always has for agent_default.
#   strict   agent_rules: a call it cannot read and a shell command that changes files are refused
#   default  agent_default: those two ask the person instead
#   review   agent_review: agent_default, but every change inside the workspace asks (cause 127)
STARTERS = {"strict": "agent_rules", "default": "agent_default", "review": "agent_review"}
DEFAULT_STARTER = "default"


def starter_path(name: str) -> Path:
    """The canonical image of the starter `name`; KeyError for a name that is not a starter."""
    return HERE / "policy" / f"{STARTERS[name]}.core.json"


def starter_of(image: bytes) -> Optional[str]:
    """The starter whose shipped image is exactly `image` as `init` records it (the canonical bytes, without the
    file's closing line feed), or None. Exact bytes, so the name always goes with the hash that was attested."""
    for name in STARTERS:
        shipped = starter_path(name).read_bytes()
        if (shipped[:-1] if shipped.endswith(b"\n") else shipped) == image:
            return name
    return None

# Shipped starter images that are older than the current ones, by the first 16 hex digits of the sha256 of the image
# as `init` records it: hash -> (the starter it was, what it was). The first three ones were recorded by `init`
# before 2026-11-19 and have no `path_control` field, so they allow a change to the agent's own control files. The
# bytes of each are kept as test fixtures (tests/fixtures/agent_old_starters/).
OLDER_STARTERS = {
    "ca48f48ddc5e5eb0": ("default", "the first agent_default (before cause 125, which asks about a file-changing "
                                    "shell command inside the project)"),
    "bd856d4dc167d5f4": ("default", "the agent_default from before the control-file rule (cause 128)"),
    "c827acc6c86c47b1": ("strict", "the agent_rules from before the control-file rule (cause 128)"),
    "f3eb1c190c0588ec": ("review", "the agent_review from before the control-file rule (cause 128)"),
    # The three that followed it, recorded by `init` from 2026-11-19 until the connect rule shipped. They have the
    # path_control field and refuse its changes, but they bound `classifier_version` to 1, so every reading from the
    # current classifier (version 2) is refused at their boundary until they are recorded again.
    "e184122df6538d99": ("default", "the agent_default from before the connect rule (cause 130, classifier version 2), "
                                    "which refuses every reading of the current classifier"),
    "6e6f4f8604997b41": ("review", "the agent_review from before the connect rule (cause 130, classifier version 2), "
                                   "which refuses every reading of the current classifier"),
    "9d50ffe71afff5ef": ("strict", "the agent_rules from before the connect rule (cause 130, classifier version 2), "
                                   "which refuses every reading of the current classifier"),
    # The three recorded from 2026-11-20 until the read-only fix (classifier version 3). They bound `classifier_version`
    # to 2, and they allow `sed`, `sort`, `uniq`, `xxd`, `tree` and the git options that write files or run programs.
    "b64f0e29805388f5": ("default", "the agent_default from before the read-only fix (classifier version 3), which "
                                    "refuses every reading of the current classifier"),
    "4cb122afd5c105de": ("review", "the agent_review from before the read-only fix (classifier version 3), which "
                                   "refuses every reading of the current classifier"),
    "0a079f267aab636c": ("strict", "the agent_rules from before the read-only fix (classifier version 3), which "
                                   "refuses every reading of the current classifier"),
}
RULE_DATE = "2026-11-19"          # the day the control-file rule shipped: the first four older images are "from before" it
NET_RULE_DATE = "2026-11-20"      # the day the connect rule and classifier version 2 shipped: the next three are "from before" it
_NET_OLDER = ("e184122df6538d99", "6e6f4f8604997b41", "9d50ffe71afff5ef")
READONLY_RULE_DATE = "2026-11-21"   # the day classifier version 3 shipped: the last three are "from before" it
_READONLY_OLDER = ("b64f0e29805388f5", "4cb122afd5c105de", "0a079f267aab636c")


def older_starter_of(image: bytes) -> Optional[Tuple[str, str]]:
    """(starter, description) when `image` is exactly an older shipped image of one, or None."""
    return OLDER_STARTERS.get(hashlib.sha256(image).hexdigest()[:16])


def older_date(image: bytes) -> Optional[str]:
    """The day the shipped rule an older starter image lacks was added (`RULE_DATE` or `NET_RULE_DATE`), or None."""
    key = hashlib.sha256(image).hexdigest()[:16]
    if key not in OLDER_STARTERS:
        return None
    if key in _READONLY_OLDER:
        return READONLY_RULE_DATE
    return NET_RULE_DATE if key in _NET_OLDER else RULE_DATE


# The values each category of a reading takes, as the Lean model of the classifier lists them
# (formal/Classifier/Control.lean: allTools, allScopes, allCmds, allGitOps, allRemotes, allNetDests, allProcClasses).
_TOOLS = ("list_dir", "read_file", "write_file", "delete_path", "run_command", "git", "connect", "unknown")
_NET_DESTS = ("none", "model_api", "allowed_host", "other", "unknown")
_PROC_CLASSES = ("none", "single", "tree", "unknown")
_SCOPES = ("none", "workspace", "outside", "unknown")
_COMMANDS = ("none", "read_only", "mutating", "network", "git", "unknown")
_GIT_OPS = ("none", "local_read", "local_write", "mutating", "push", "network", "unknown")
_REMOTES = ("none", "allowed", "other")
_FLAGS = ("kill_by_pattern", "path_in_toolchain", "path_glob", "path_traversal", "path_symlink")


def _is_change(tool: str, command: str, git_op: str) -> bool:
    """Lean `isChange`: a file written or deleted, a command that changes files, a local git write or mutation."""
    return tool in ("write_file", "delete_path") or command == "mutating" or git_op in ("local_write", "mutating")


def control_gap(policy: "Policy") -> Optional[str]:
    """None when the policy refuses every change that reads `path_control`, otherwise why not.

    This is the oracle's `control_refused` property (`controlSafe` in formal/Classifier/Control.lean): every reading
    with `path_control` true that is a change, over every value of every other field, decided by the reference
    decision path (`core_reference.python_decision`, the one `Policy.decide` uses), must be a refusal. A policy that
    defines no `path_control` field fails outright, since its rules cannot see a control path at all. It stops at the
    first reading that is not refused, which it names."""
    from prismpath.kernel import core_reference
    fields = policy.doc["fields"]
    if "path_control" not in fields:
        return "it has no path_control field, so its rules cannot see a control file"
    base = _base_reading(policy)
    # The classifier gives a proc_class other than none only to a run_command and a net_dest other than none only to a
    # connect, which is not a change; the Lean model holds the whole product, here the readings it can make.
    for tool, scope, command, git_op, remote in itertools.product(_TOOLS, _SCOPES, _COMMANDS, _GIT_OPS, _REMOTES):
        if not _is_change(tool, command, git_op):
            continue
        for proc in (_PROC_CLASSES if tool == "run_command" and "proc_class" in fields else ("none",)):
            for flags in itertools.product((False, True), repeat=len(_FLAGS)):
                reading = {**base, "tool": tool, "path_scope": scope, "command_class": command, "git_op": git_op,
                           "remote_class": remote, "path_control": True, **dict(zip(_FLAGS, flags))}
                if "proc_class" in fields:
                    reading["proc_class"] = proc
                if _not_refused(policy, reading):
                    return (f"it does not refuse a change to a control file (tool {tool}, path_scope {scope}, "
                            f"command_class {command}, git_op {git_op})")
    return None


def classifier_mismatch(policy: "Policy") -> Optional[str]:
    """Why this policy cannot decide any reading the installed classifier makes, or None. An image recorded for an
    older classifier bounds `classifier_version` below the current one, so the core would refuse every call as a
    contract violation; this says so in words, with the fix, instead."""
    from prismpath.agent import classifier
    bound = policy.doc["fields"].get("classifier_version", "")
    low, high = re.search(r"min=(-?\d+)", bound), re.search(r"max=(-?\d+)", bound)
    version = classifier.CLASSIFIER_VERSION
    if (low and version < int(low.group(1))) or (high and version > int(high.group(1))):
        made_for = high.group(1) if high else low.group(1)
        return (f"the recorded policy was made for classifier version {made_for} and this PrismPath reads calls as "
                f"version {version}, so it can decide none of them; run `prismpath agent init` to record a current "
                f"starter")
    return None


def _base_reading(policy: "Policy") -> Dict[str, Any]:
    """The fields of a reading the policy defines, at their values for a call that reads nothing: the classifier
    version at the top of the policy's own bound (so an older image is asked about the readings it was made for)."""
    from prismpath.agent import classifier
    fields = policy.doc["fields"]
    version = classifier.CLASSIFIER_VERSION
    match = re.search(r"max=(-?\d+)", fields.get("classifier_version", ""))
    if match:
        version = int(match.group(1))
    base: Dict[str, Any] = {"classifier_version": version}
    if "net_dest" in fields:
        base["net_dest"] = "none"
    if "proc_class" in fields:
        base["proc_class"] = "none"
    return base


def _not_refused(policy: "Policy", reading: Dict[str, Any]) -> bool:
    """True when the reference does not refuse the reading (it allows or escalates it). A quick screen reads the first
    rule that holds as the reference does (`profile._holds`): a boundary refusal, a rule whose target refuses and a
    reading no rule holds for are refusals, and everything else is decided by the reference's own decision path before
    it is called not refused."""
    from prismpath.agent import profile
    from prismpath.kernel import core_reference, field_definitions, predicates
    try:
        if field_definitions.system_boundary(policy.graph, reading) is not None:
            return False
        for target, condition in policy.graph.nodes[policy.graph.start].edges:
            if not predicates.is_deterministic(condition):
                continue
            try:
                if profile._holds(condition, reading):
                    if target.startswith("refuse_"):
                        return False
                    break
            except predicates.PredicateError:
                continue
        else:
            return False
    except Exception:  # noqa: BLE001 - decided by the full path
        pass
    verdict, _ = core_reference.python_decision(policy.graph, policy.reading_bytes(reading))
    return not (verdict["verdict"] == "refuse" or (verdict["verdict"] == "route"
                                                   and verdict["target"].startswith("refuse_")))


def net_gap(policy: "Policy") -> Optional[str]:
    """None when the policy refuses every connection that is not the model's API, otherwise why not.

    This is the oracle's `net_refused` property (`netSafe` in formal/Classifier/Net.lean) over the readings the
    classifier can make: a `connect` whose `net_dest` is none, allowed_host, other or unknown, and any other tool
    whose `net_dest` is other or unknown, decided by the reference decision path, must be a refusal. A policy that
    defines no `net_dest` field fails outright. A reading holding `model_api` is not asked about: whether it runs is
    the owner's rule."""
    fields = policy.doc["fields"]
    if "net_dest" not in fields:
        return "it has no net_dest field, so its rules cannot see where a connection goes"
    base = {**_base_reading(policy), "tool": "connect"}
    for tool, dest in itertools.product(_TOOLS, _NET_DESTS):
        if dest == "model_api" or (dest in ("none", "allowed_host") and tool != "connect"):
            continue
        reading = {**base, "tool": tool, "net_dest": dest, "path_scope": "none", "command_class": "none",
                   "git_op": "none", "remote_class": "none", "path_control": False,
                   **{flag: False for flag in _FLAGS}}
        if _not_refused(policy, reading):
            return f"it does not refuse a connection (tool {tool}, net_dest {dest})"
    return None


def control_check(image: bytes) -> Dict[str, Any]:
    """What `status` and `doctor` report about a recorded image: whether it refuses every change to a control file,
    decided by the image alone. A current starter's image is the one the tests hold to `control_gap`, and an older
    shipped image has no `path_control` field; anything else is evaluated (a few seconds)."""
    older = older_starter_of(image)
    if starter_of(image) is not None:
        gap = None
    elif older is not None and older_date(image) == RULE_DATE:
        gap = "it has no path_control field, so its rules cannot see a control file"
    else:
        gap = control_gap(Policy(image))
    fix_name = older[0] if older else (starter_of(image) or DEFAULT_STARTER)
    result: Dict[str, Any] = {"refuses_control_changes": gap is None}
    if gap is not None:
        name = (f"the {older[0]} starter from before {older_date(image)}" if older else "a custom policy")
        replaces = "" if older else ", which replaces its rules"
        result.update(
            reason=gap, policy=name, fix=f"prismpath agent init --policy {fix_name}",
            message=(f"This policy ({name}) does not refuse a change to the agent's own control files, so the agent "
                     f"can still rewrite .claude/settings.json and remove its hook; run `prismpath agent init --policy "
                     f"{fix_name}` to record a current starter{replaces} (runs already sealed keep verifying; a session still "
                     f"open is denied its next call until it ends, and keeps the old policy in its own run)."))
    return result

_TARGET = re.compile(r"^(allow|refuse_(\d+)|escalate_(\d+))$")


@dataclass(frozen=True)
class Decision:
    """What the harness does with one call: `allow`, `refuse` or `escalate`, with the registered cause of a
    refusal or an escalation, and the core's own verdict it came from."""
    kind: str
    cause: Optional[str]
    cause_code: Optional[int]
    verdict: Dict[str, Any]

    @property
    def runs(self) -> bool:
        return self.kind == "allow"


def target_decision(target: str):
    """(kind, cause, code) a rule's target names, or None when it names nothing the harness knows."""
    match = _TARGET.match(target)
    if not match:
        return None
    if match.group(1) == "allow":
        return "allow", None, None
    code = int(match.group(2) or match.group(3))
    name = causes.name(code)
    if name is None:
        return None
    return ("refuse" if match.group(2) else "escalate"), name, code


class Policy:
    def __init__(self, image: bytes):
        if image.endswith(b"\n"):
            image = image[:-1]                 # the one line feed a file may end with
        self.image = image
        refusal = core_policy.load_policy(image)
        if refusal is not None:
            raise ValueError(f"the core refuses the agent policy: {refusal}")
        self.doc = canon2.loads(image)
        self.flow = core_render.render(self.doc)
        self.graph = parse(self.flow)
        self.fields = sorted(self.doc["fields"])
        for rule in self.doc["rules"]:
            if target_decision(rule["target"]) is None:
                raise ValueError(f"the policy names a target the harness does not know: {rule['target']}")

    @classmethod
    def load(cls, path: Path = POLICY_PATH) -> "Policy":
        return cls(Path(path).read_bytes())

    def reading_bytes(self, reading: Dict[str, Any]) -> bytes:
        """A reading's canonical canon/2 bytes: the only spelling the core reads."""
        return canon2.dumps(reading)

    def verdict(self, raw: bytes) -> Dict[str, Any]:
        """The core's verdict on one reading's bytes, from the reference decision path."""
        verdict = core_reference.python_reading(self.graph, raw)
        verdict.pop("policy_check", None)
        return verdict

    def decide(self, raw: bytes) -> Decision:
        verdict = self.verdict(raw)
        if verdict.get("verdict") == "route":
            kind, cause, code = target_decision(verdict["target"])
            return Decision(kind, cause, code, verdict)
        cause = verdict.get("cause")
        code = causes.code(cause) if isinstance(cause, str) else None
        # an uncoded refusal (the reference crashed) is still a refusal, never a run; it carries no code, so
        # its receipt fails verification and the run reports it, rather than borrowing another cause
        return Decision("refuse", cause if isinstance(cause, str) else "crash", code, verdict)
