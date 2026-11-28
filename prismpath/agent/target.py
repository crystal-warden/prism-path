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

from typing import List, Sequence, Tuple, Union

from prismpath.agent import fields as agent_fields
from prismpath.information import catalog

Where = Union[None, str, int]       # a field name, a rule index, or the whole policy


def _evidence_finding(name, text, have, bound) -> List[Tuple[Where, str]]:
    if have.point not in bound:
        return [(name, f"{name} is a field of the information point {have.point}, and no point of that name is "
                       f"bound, so nothing would supply it; build the policy with `--point {have.point}` or write "
                       f"`policy.points: {have.point}` in its manifest")]
    if text.split()[:1] != [have.kind]:
        return [(name, f"the information point {have.point} gives {name} as a {have.kind}, not a "
                       f"{(text.split() or ['nothing'])[0]}")]
    if have.kind == "int" and sorted(text.split()) != sorted(catalog.declaration(have).split()):
        return [(name, f"the information point {have.point} gives {name} as `{catalog.declaration(have)}`, not "
                       f"`{text}`")]
    return []


def evidence_findings(image: bytes, points: Sequence[str] = ()) -> List[Tuple[Where, str]]:
    """Only the findings about evidence fields: one for each field the image declares that an information point
    supplies and `points` does not name, or declares as another kind than the point gives it, and one for a point
    name that is no point. The manifest check runs this on the image its rules compile to."""
    from prismpath.agent import profile
    from prismpath.kernel import canon2

    declared = canon2.loads(image)["fields"]
    try:
        profile.agent_domain(tuple(points))
    except ValueError as error:
        return [(None, str(error))]
    known = agent_fields.by_name()
    evidence = catalog.evidence_fields()
    found: List[Tuple[Where, str]] = []
    for name, text in declared.items():
        if name not in known and name in evidence:
            found.extend(_evidence_finding(name, text, evidence[name], tuple(points)))
    return found


def monotone(loaded, bound) -> List[Tuple[Where, str]]:
    """A value that says a point gave no evidence (`tests_pass` `not_run`) must never get past a rule that the
    restrictive value does not: every reading the policy allows with the field at such a value it must allow with the
    field at its restrictive value too, else a rule that refuses only on `false` lets an unrun test through. Walks the
    policy's finite domain by classes of values, as `profile.needs_all` does. One finding for each field and value,
    on the field's declaration."""
    import itertools

    from prismpath.kernel import domain as kdomain
    found: List[Tuple[Where, str]] = []
    doc, domain = loaded.doc, loaded.domain
    for name in sorted(bound):
        have = bound[name]
        if not have.no_evidence:
            continue
        try:
            names, constant, groups = kdomain.domain_classes([doc], domain, (name,))
        except kdomain.DomainError:
            continue
        others = [(n, g) for n, g in zip(names, groups) if n != name]
        bad = set()
        for combo in itertools.product(*(g for _n, g in others)):
            reading = {n: members[0] for (n, _g), members in zip(others, combo)}
            reading.update(constant)
            for value in have.no_evidence:
                if value in bad:
                    continue
                chosen = {n: members for (n, _g), members in zip(others, combo)}
                full = tuple(chosen[n] if n != name else [value] for n in names)
                if profile_unproduced(names, full):
                    continue
                if loaded.decide(loaded.reading_bytes({**reading, name: value})).runs \
                        and not loaded.decide(loaded.reading_bytes({**reading, name: have.restrictive})).runs:
                    bad.add(value)
        for value in sorted(bad, key=str):
            found.append((name, f"{name} read as {value!r} allows a reading that {name} read as {have.restrictive!r} "
                                f"refuses, so a point that gave no evidence would get past a rule written for failing "
                                f"evidence; make the rule allow only on a value that is evidence"))
    return found


ORDER = {"refuse": 0, "escalate": 1, "allow": 2}


def dominance(loaded, bound) -> List[Tuple[Where, str]]:
    """The restrictive value of an evidence field must be treated no more permissively than any other value of it:
    every reading the policy decides at the field's restrictive value it must decide at every other value of the field
    no stricter, in the order refuse < escalate < allow. Else a point that cannot answer (it reads the restrictive
    value) would get past a rule written for its answers, as `refuse when cc_certainty == "certain"` lets `unknown`
    through. Rules over an evidence field must therefore be written as allows (`allow when cc_certainty == "none"`).
    Walks the policy's finite domain by classes of values, as `monotone` does. One finding for each field, on the
    field's declaration, naming the first value that is treated more strictly."""
    import itertools

    from prismpath.kernel import domain as kdomain
    found: List[Tuple[Where, str]] = []
    doc, domain = loaded.doc, loaded.domain
    for name in sorted(bound):
        have = bound[name]
        try:
            names, constant, groups = kdomain.domain_classes([doc], domain, (name,))
        except kdomain.DomainError:
            continue
        if name not in names:
            continue
        others = [(n, g) for n, g in zip(names, groups) if n != name]
        values = [members[0] for members in groups[list(names).index(name)]]
        bad = None
        for combo in itertools.product(*(g for _n, g in others)):
            reading = {n: members[0] for (n, _g), members in zip(others, combo)}
            reading.update(constant)
            chosen = {n: members for (n, _g), members in zip(others, combo)}
            at_restrictive = ORDER[loaded.decide(loaded.reading_bytes({**reading, name: have.restrictive})).kind]
            for value in values:
                if value == have.restrictive:
                    continue
                full = tuple(chosen[n] if n != name else [value] for n in names)
                if profile_unproduced(names, full):
                    continue
                if ORDER[loaded.decide(loaded.reading_bytes({**reading, name: value})).kind] < at_restrictive:
                    bad = value
                    break
            if bad is not None:
                break
        if bad is not None:
            found.append((name, f"{name} read as {have.restrictive!r} is decided more permissively than {name} read as "
                                f"{bad!r}, so a point that cannot answer would get past a rule written for its answers; "
                                f"write the rules over {name} as allows (refuse < escalate < allow)"))
    return found


def profile_unproduced(names, combo) -> bool:
    from prismpath.agent import profile
    return profile.unproduced(list(names), combo)


def check(image: bytes, points: Sequence[str] = ()) -> List[Tuple[Where, str]]:
    """What stops the governed agent from running this image as its policy, in source order. Empty when nothing does.
    `points` are the information points the policy is built with (`--point`, or `policy.points` of a manifest): a field
    that only a point supplies is read when its point is named and refused when it is not."""
    from prismpath.agent import policy as agent_policy
    from prismpath.agent import profile
    from prismpath.kernel import canon2

    doc = canon2.loads(image)
    declared = doc["fields"]
    found: List[Tuple[Where, str]] = []
    known = agent_fields.by_name()
    try:
        domain_points = tuple(points)
        profile.agent_domain(domain_points)
    except ValueError as error:
        return [(None, str(error))]
    evidence = catalog.evidence_fields()
    for name, text in declared.items():
        if name not in known and name in evidence:
            found.extend(_evidence_finding(name, text, evidence[name], domain_points))
        elif name not in known:
            found.append((name, f"the agent's classifier reads no field {name}, so every call would be refused as a "
                                f"contract violation (route:contract-violation)"))
        elif text.split()[:1] != [known[name][0]]:
            found.append((name, f"the agent's classifier gives {name} as a {known[name][0]}, not a "
                                f"{(text.split() or ['nothing'])[0]}"))
    for index, rule in enumerate(doc["rules"]):
        outside = profile.outside_domain({"fields": declared, "rules": [rule]}, domain_points)
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
        loaded = agent_policy.Policy(image, domain_points)
    except ValueError as error:
        return [(None, str(error))]
    bound = {n: e for n, e in evidence.items() if n in declared and n not in known and e.point in domain_points}
    if bound:
        found.extend(monotone(loaded, bound))
        found.extend(dominance(loaded, bound))
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
    evidence = catalog.evidence_fields()
    for name, listed in values.items():
        known = agent_fields.values(name)
        if not known and name in evidence and evidence[name].kind == "category":
            known = tuple(evidence[name].values)
        if known and tuple(listed) != known:
            found.append((name, f"{name} lists {'|'.join(listed)}, but the agent's classifier gives "
                                f"{'|'.join(known)}"))
    return found


TARGETS = {"agent": check}
LISTED = {"agent": check_listed}


from prismpath.kernel.policy_source import line_of  # noqa: E402,F401 - the source line a finding is about
