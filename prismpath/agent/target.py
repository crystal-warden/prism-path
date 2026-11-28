# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The checks `prismpath policy compile --target agent` runs on a compiled image, before anything records it.

The core accepts any image that is well formed. The governed agent needs more, and until now it found out late:
a value outside a field's reading domain when the image loads (`Policy`, cause 160), a field the classifier does
not read when every call is refused as a contract violation (cause 37), no sandbox for want of a field when an
allowed shell call is refused (cause 129), and a policy that cannot see a control file or a connection in `agent
status` and `agent doctor`. Each check here is the agent's own (prismpath/agent/policy.py and profile.py), run
on the image the compiler just made, so the author learns it with the line it is about.

  outside the domain   every rule is asked `profile.outside_domain` on its own, so each value is named on its rule's line
  unknown fields       a declared field the classifier never reads (prismpath/agent/fields.py), or one declared with
                       another kind than the classifier gives it
  required fields      `fields.REQUIRED`
  control files        `policy.control_gap`, every change to a control file refused
  connections          `policy.net_gap`, every connection but the model's API refused
  the sandbox          `profile.compile_profile` for both roles
  listed values        `check_listed`, on the source, a category whose `a|b|c` list is not the classifier's values

A finding is (field or rule index, message), and the compiler turns a field into its declaration line and a rule into
its rule line. The agent kind registers these checks with the kind registry (prismpath/agent/dist_kind.py), and the
compiler runs what the registry holds for `--target`.
"""
from __future__ import annotations

from typing import List, Tuple, Union

from prismpath.agent import fields as agent_fields

Where = Union[None, str, int]       # a field name, a rule index, or the whole policy


def check(image: bytes) -> List[Tuple[Where, str]]:
    """What stops the governed agent from running this image as its policy, in source order. Empty when nothing does."""
    from prismpath.agent import policy as agent_policy
    from prismpath.agent import profile
    from prismpath.kernel import canon2

    doc = canon2.loads(image)
    declared = doc["fields"]
    found: List[Tuple[Where, str]] = []
    known = agent_fields.by_name()
    for name, text in declared.items():
        if name not in known:
            found.append((name, f"the agent's classifier reads no field {name}, so every call would be refused as a "
                                f"contract violation (route:contract-violation)"))
        elif text.split()[:1] != [known[name][0]]:
            found.append((name, f"the agent's classifier gives {name} as a {known[name][0]}, not a "
                                f"{(text.split() or ['nothing'])[0]}"))
    for index, rule in enumerate(doc["rules"]):
        outside = profile.outside_domain({"fields": declared, "rules": [rule]})
        if outside is not None:
            found.append((index, f"{outside} (policy:out-of-domain)"))
        if agent_policy.target_decision(rule["target"]) is None:
            found.append((index, f"the agent acts on allow, refuse and escalate only, not the route {rule['target']}"))
    for name, why in agent_fields.REQUIRED:
        if name not in declared:
            found.append((None, f"the policy declares no {name} field, {why}"))
    if found:
        return found                   # the checks below load the image as the agent does, which these stop
    try:
        loaded = agent_policy.Policy(image)
    except ValueError as error:
        return [(None, str(error))]
    mismatch = agent_policy.classifier_mismatch(loaded)
    if mismatch is not None:
        found.append(("classifier_version", mismatch))
    gap = agent_policy.control_gap(loaded)
    if gap is not None:
        found.append(("path_control", f"{gap} (agent:control-write is never decided)"))
    gap = agent_policy.net_gap(loaded)
    if gap is not None:
        found.append(("net_dest", f"{gap} (agent:net-refused is never decided)"))
    for role in ("bash", "agent"):
        try:
            profile.compile_profile(loaded, role)
        except profile.ProfileError as error:
            found.append((None, f"no sandbox profile can be built for the {role} role, because {error} "
                                f"(agent:sandbox-unavailable)"))
    return found


def check_listed(values) -> List[Tuple[Where, str]]:
    """A category whose source lists values other than the ones the agent's classifier produces, named on its
    declaration. The list never reaches the image, so this runs on the source (`Compiled.values`)."""
    found: List[Tuple[Where, str]] = []
    for name, listed in values.items():
        known = agent_fields.values(name)
        if known and tuple(listed) != known:
            found.append((name, f"{name} lists {'|'.join(listed)}, but the agent's classifier gives "
                                f"{'|'.join(known)}"))
    return found


TARGETS = {"agent": check}
LISTED = {"agent": check_listed}


from prismpath.kernel.policy_source import line_of  # noqa: E402,F401 - the source line a finding is about
