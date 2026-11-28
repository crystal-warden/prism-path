"""The sealing tool, as a function from inputs to sealed envelopes.

`seal_release` takes the body, the stream, the sequence, the targets and the signers, compares the release with the
one it replaces, and returns the sealed envelope with what the command prints about it. It reads no argument
namespace, prints nothing and asks no one. The terminal's yes for a change statement is a `confirm` callback, so
`dist seal` and any later caller (a manifest) use the one function. The same inputs, keys and `not_before` give the
same bytes. The commands in `cli.py` keep only the argument reading, the files and the printing.

`seal_manifest` seals a whole release from a signed policy manifest that `policy_manifest.verify` found holds: one
release per target, each made by the target kind's registered `derive`, with the stream, seq, times, `replaces` and
`widens` the manifest and the tool's own comparison give (SPEC.md section 10). It seals each artifact with
`build_sealed` rather than `seal_release`, because `seal_release` compares one artifact with the one it replaces and
a release from a manifest is several artifacts with one `widens` and one `replaces` (E7), so the tool compares the
whole release, as the PEP that decides does (W1).
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

from prismpath import canon
from prismpath.distribution import envelope as env
from prismpath.distribution import kinds
from prismpath.distribution.kinds import Refused
from prismpath.ports.keys import Signer


def _read(path: str) -> bytes:
    with open(path, "rb") as handle:
        return handle.read()


def policy_meta(body: bytes, qualification: dict) -> dict:
    """The `meta` of a `policy.ppt` envelope, from the image and the qualification envelope a host holds."""
    from prismpath.hotswap import policy_pack
    header = policy_pack.read_ppt_header(body)
    return {"counts": {key: header[key] for key in sorted(kinds.COUNT_MEMBERS)},
            "fields": dict(qualification["fields"]), "qualification": qualification["envelope_id"],
            "wcet_cycles": policy_pack.wcet_cycles(body)}


def build_sealed(artifact: str, body: bytes, *, stream: str, seq: int, targets: List[str], signers: List[Signer],
                 not_before: int, expires: int, meta: Optional[dict] = None, release: Optional[str] = None,
                 policy: Optional[str] = None, replaces: str = "", widens: bool = False,
                 held: Optional[str] = None) -> bytes:
    """The sealing tool. A revocation list is checked against the controller directory `held` first (R8)."""
    trust_kind = artifact in kinds.ON_TRUST_STREAM
    if artifact == "trust.revocation":
        if held is None:
            raise Refused("dist:trust-replay", "a revocation list is sealed against the controller's directory (R8)")
        _check_drops(body, held)
    envelope_bytes = env.build(
        artifact, body, stream=env.TRUST_STREAM if trust_kind else stream, seq=seq, targets=targets,
        not_before=not_before, expires=0 if trust_kind else expires, meta=meta or {}, replaces=replaces, widens=widens,
        policy_sha256=env.ZERO_HASH if trust_kind else (policy or canon.sha256_hex(body)),
        release=env.ZERO_HASH if trust_kind else (release or env.release_id([(artifact, canon.sha256_hex(body))])))
    return env.seal(envelope_bytes, signers)


def held_controller(directory: str):
    """The controller state in `directory`, read and never written, for the sealing tool."""
    from prismpath.distribution.controller import Controller
    return Controller.reader(directory)


def _check_drops(body: bytes, directory: str) -> None:
    from prismpath.distribution.trust import check_drops
    controller = held_controller(directory)
    earlier = [controller.blob(controller.stored[one]["body_sha256"]) for one in controller.chain
               if controller.stored[one]["artifact"] == "trust.revocation"]
    check_drops(body, earlier, controller.held_envelopes())


def replaced(directory: Optional[str], artifact: str, stream: str, seq: int, policy: Optional[str] = None):
    """The (policy hash, body) of the release a new one at `seq` replaces: the latest one the controller in
    `directory` stores on `stream` below `seq`, with its `artifact` body, or the latest whose policy hash is
    `policy` when one is named. ("", None) when there is none, and (`policy`, None) when none is held for it."""
    if directory is None or artifact in kinds.TRUST_ARTIFACTS:
        return policy or "", None
    return replaced_in(held_controller(directory), artifact, stream, seq, policy)


def replaced_in(controller, artifact: str, stream: str, seq: int, policy: Optional[str] = None):
    below = _below(controller, artifact, stream, seq, policy)
    if not below and policy is not None:
        return policy, None
    if not below:
        return "", None
    latest = max(below, key=lambda info: info["seq"])
    return latest["policy"], controller.blob(latest["body_sha256"])


def _below(controller, artifact: str, stream: str, seq: int, policy: Optional[str]) -> list:
    return [dict(info, envelope_id=one) for one, info in controller.stored.items()
            if info["stream"] == stream and info["artifact"] == artifact and info["seq"] < seq
            and (policy is None or info["policy"] == policy)]


def _replaced_fields(controller, stream: str, seq: int, policy: Optional[str]) -> Optional[dict]:
    """The signed field dictionary of the `policy.ppt` envelope `replaced_in` holds the new one to (W8)."""
    from prismpath.distribution import table_compare
    below = _below(controller, "policy.ppt", stream, seq, policy)
    if not below:
        return None
    latest = max(below, key=lambda info: info["seq"])
    return table_compare.table_fields(env.read(env.unseal(controller.sealed(latest["envelope_id"]))[0]))


def table_comparison(controller, body: bytes, meta: Optional[dict], stream: str, seq: int, policy: Optional[str],
                     previous: Optional[bytes]):
    """W8 at the sealing tool: the table comparator's answer for a `policy.ppt` body against the table it
    replaces, which `controller` holds, or None when it holds none."""
    from prismpath.distribution import table_compare
    if previous is None:
        return None
    fields = (meta or {}).get("fields")
    return table_compare.compare_tables(previous, body, active_fields=_replaced_fields(controller, stream, seq, policy),
                                        staged_fields=dict(fields) if isinstance(fields, dict) else None)


def scope_mark(artifact: str, previous: Optional[bytes], body: bytes, comparison) -> str:
    """F4 at the sealing tool, as the controller marks a rollout: a widening for a release that replaces nothing
    held, that a comparator with an order finds larger, or a table W8 finds larger or cannot decide, a change, not
    larger, for one that differs and allows nothing more, and empty for a renewal."""
    from prismpath.distribution import widening
    from prismpath.distribution.controller import CHANGE_NOT_LARGER, WIDENING
    if previous is None:
        return WIDENING
    if bytes(previous) == bytes(body):
        return ""
    if widening.compare_artifact(artifact, previous, body) == widening.NOT_LARGER:
        return CHANGE_NOT_LARGER
    if artifact == "policy.ppt" and comparison is not None and comparison.answer == widening.NOT_LARGER:
        return CHANGE_NOT_LARGER
    return WIDENING


def change_sealed(release_sealed: bytes, signers: List[Signer]) -> tuple:
    """The sealed change statement for the release in `release_sealed` and its body (W10): the same stream, seq,
    policy hash, release id, targets, `replaces` and `widens` (E7), `from` the policy hash it replaces and `basis`
    the table comparator its claim rests on."""
    release = env.read(env.unseal(release_sealed)[0])
    if release.artifact in kinds.TRUST_ARTIFACTS or release.widens or not release.replaces:
        raise Refused(kinds.BAD_FORMAT, "a change statement is for a release that replaces one and does not widen")
    body = canon.canon2_bytes({"basis": kinds.CHANGE_BASIS, canon.ENCODING_KEY: canon.CANON2,
                               "format": kinds.CHANGE_FORMAT, "from": release.replaces})
    kinds.read_change(body)
    envelope_bytes = env.build("trust.change", body, stream=release.stream, seq=release.seq,
                               targets=list(release.targets), not_before=release.not_before, expires=0,
                               policy_sha256=release.policy_sha256, release=release.release,
                               replaces=release.replaces, widens=False)
    return env.seal(envelope_bytes, signers), body


NOT_CONFIRMED = ("the table allows nothing more than the one it replaces, and a change statement is signed only when "
                 "the owner says yes; run again at a terminal or with --yes, or with --widens to release it as a "
                 "widening")


def widening_sealed(release_sealed: bytes, froms: List[str], signers: List[Signer]) -> tuple:
    """The sealed widening statement for the release in `release_sealed` and its body: the same stream, seq,
    policy hash, release id, targets, `replaces` and `widens` (W4, E7), and `from` sorted. Only `widen` and a
    `rekey` the owner passes `--widens` sign one, never the tool on its own (W9)."""
    release = env.read(env.unseal(release_sealed)[0])
    if release.artifact in kinds.TRUST_ARTIFACTS:
        raise Refused(kinds.BAD_FORMAT, "a widening statement is for a release, not a trust statement")
    body = canon.canon2_bytes({canon.ENCODING_KEY: canon.CANON2, "format": kinds.WIDENING_FORMAT,
                               "from": sorted(set(froms))})
    kinds.read_widening(body)
    envelope_bytes = env.build("trust.widening", body, stream=release.stream, seq=release.seq,
                               targets=list(release.targets), not_before=release.not_before, expires=0,
                               policy_sha256=release.policy_sha256, release=release.release,
                               replaces=release.replaces, widens=release.widens)
    return env.seal(envelope_bytes, signers), body


def read_set_dir(directory: str):
    """The install set `dist install` wrote to `directory`, as a held set, each statement checked against its body."""
    from prismpath.distribution import install
    statements, envelopes, bodies = {}, {}, {}
    for name in sorted(os.listdir(directory)):
        if not name.endswith(".sealed"):
            continue
        sealed = _read(os.path.join(directory, name))
        body = _read(os.path.join(directory, name[:-len(".sealed")] + ".body"))
        envelope = env.read(env.unseal(sealed)[0])
        if envelope.artifact == install.CHANGE and envelope.body_sha256 == canon.sha256_hex(body):
            continue                                 # IS14: the change statement written beside the set
        if envelope.body_sha256 != canon.sha256_hex(body) or envelope.artifact not in install.SET_KINDS:
            raise Refused("dist:body-mismatch", f"{name} is not an install statement with its body")
        named = envelope.meta["as"]
        statements[named] = (envelope.envelope_id, canon.sha256_hex(sealed), envelope.body_sha256)
        envelopes[named], bodies[named] = envelope, body
    if not envelopes:
        raise Refused(kinds.BAD_FORMAT, f"{directory} holds no install set")
    first = next(iter(envelopes.values()))
    return install.HeldSet(first.artifact, first.seq, env.set_id(one[0] for one in statements.values()),
                           first.policy_sha256, first.release, first.replaces, first.widens, statements, envelopes,
                           bodies)


@dataclass(frozen=True)
class SealedRelease:
    """What `seal_release` returns. `change` is the (sealed, body) change statement, or None."""
    sealed: bytes
    replaces: str
    widens: bool
    scope: str
    comparison: object = None
    change: Optional[tuple] = None


def seal_release(artifact: str, body: bytes, *, stream: str, seq: int, targets: List[str], signers: List[Signer],
                 not_before: Optional[int] = None, expires: int = 0, meta: Optional[dict] = None,
                 qualification: Optional[dict] = None, release: Optional[str] = None, policy: Optional[str] = None,
                 replaces: Optional[str] = None, widens: bool = False, held: Optional[str] = None,
                 ceiling: Optional[str] = None,
                 confirm: Optional[Callable[[object, str], bool]] = None) -> SealedRelease:
    """The sealed envelope for `body`, and the change statement when the release allows nothing more than the one it
    replaces. `meta` is the meta object; for a `policy.ppt` with none, `qualification` (the qualification envelope's
    fields) gives it. `ceiling` is an install set directory the release must stay inside (CL2). `held` is a controller
    directory, for the release this one replaces, and for R8. `replaces` names the policy hash to replace (default the
    latest one held below `seq`). `confirm(comparison, replaces)` is asked before a change statement is signed, and
    None is a no. `not_before` defaults to now. A refusal raises `Refused`."""
    from prismpath.distribution import widening
    from prismpath.distribution.controller import WIDENING
    if meta is None and artifact == "policy.ppt" and qualification:
        meta = policy_meta(body, qualification)
    if ceiling:
        from prismpath.distribution import install
        inside = install.inside(targets[0], read_set_dir(ceiling), {artifact: body}, whole=False)
        if not inside:
            raise Refused(install.ABOVE_CEILING, "the release is above the ceiling (CL2)")
    previous_hash, previous = replaced(held, artifact, stream, seq, replaces)
    # W7: `widens` is false only when the release is compared with the one it replaces and is not larger, so
    # a release that replaces nothing, or one the directory holds nothing for, widens
    asked = widens
    widens = asked or artifact not in kinds.TRUST_ARTIFACTS and (
        previous is None or widening.compare_artifact(artifact, previous, body) != widening.NOT_LARGER)
    comparison = None
    if artifact == "policy.ppt" and held is not None and previous is not None:
        comparison = table_comparison(held_controller(held), body, meta, stream, seq, replaces, previous)
    mark = scope_mark(artifact, previous, body, comparison) if artifact not in kinds.TRUST_ARTIFACTS else ""
    change = (widens and not asked and comparison is not None and comparison.answer == widening.NOT_LARGER
              and previous_hash != "")
    if change:
        if confirm is None or not confirm(comparison, previous_hash):
            raise Refused(widening.UNSIGNED, NOT_CONFIRMED)
        widens = False                                   # W11: it allows nothing more, so it does not widen
    sealed = build_sealed(artifact, body, stream=stream, seq=seq, targets=targets, signers=signers,
                          not_before=not_before or int(time.time()), expires=expires, meta=meta, release=release,
                          policy=policy, replaces=previous_hash, widens=widens, held=held)
    statement = change_sealed(sealed, signers) if change else None
    return SealedRelease(sealed, previous_hash, widens, mark, comparison, statement)



# ------------------------------------------------------------------ sealing from a signed policy manifest

@dataclass(frozen=True)
class SealedArtifact:
    """One envelope `seal_manifest` sealed: the target kind its release is for, the artifact, the sealed envelope and
    the body beside it."""
    target: str
    artifact: str
    sealed: bytes
    body: bytes


@dataclass(frozen=True)
class ManifestSealed:
    """What `seal_manifest` returns: every envelope in the order target, then artifact, the one `replaces` and `widens`
    of every release it sealed (E7), whether the tool found the release larger than the one it replaces (W1), the
    release id of each target's release, and per target what it compared (`_compared`): the artifacts it found larger,
    the optional artifacts absent, and whether the held release was whole."""
    envelopes: Tuple[SealedArtifact, ...]
    replaces: str
    widens: bool
    larger: bool
    releases: Dict[str, str]
    compared: Dict[str, dict]


def _same_value(written, carried) -> bool:
    """A manifest value equals the one a kind carries. A list compares as a set: the order of toolchain directories or
    of remotes changes nothing a PEP reads."""
    if isinstance(written, tuple) and isinstance(carried, tuple):
        return sorted(written) == sorted(carried)
    return written == carried


def _registered(manifest) -> Dict[str, object]:
    """The registration of each target of `manifest` that can be sealed from a manifest, or `Refused`."""
    found = {}
    for target in manifest.targets:
        kind = kinds.KINDS.get(target)
        if kind is None or getattr(kind, "derive", None) is None:
            raise Refused(kinds.BAD_FORMAT, f"a {target} release is not sealed from a manifest: no kind of that name "
                                            f"registered a derive in this process (the grammar names none of its "
                                            f"artifacts)")
        if not kinds.TARGETS[target].decides:
            raise Refused(kinds.BAD_FORMAT, f"a {target} PEP cannot decide larger (W1), and the manifest form has no "
                                            f"table comparison (W8) or change statement (W10), so the tool's own "
                                            f"comparison would be the only one; it is not sealed from a manifest")
        found[target] = kind
    return found


def _carried(manifest, registered: Dict[str, object]) -> None:
    """Every side file and value key the manifest writes reaches a release, or `Refused`: a signed key no PEP holds would
    read as enforced and be dropped. A side file is read by a target that lists it in `manifest_inputs`. A value key is
    carried by a target that lists it in `manifest_values`, at that value only, by every target that lists it."""
    from prismpath.kernel import policy_manifest
    inputs = {key for kind in registered.values() for key in kind.manifest_inputs}
    for key in sorted(manifest.files):
        if key not in inputs:
            raise Refused(kinds.BAD_FORMAT, f"policy.{key} is read by no target of this release "
                                            f"({', '.join(manifest.targets)}), so no PEP would hold it")
    for key in policy_manifest.VALUE_KEYS:
        if key not in manifest.values:
            continue
        carriers = [(name, kind.manifest_values[key]) for name, kind in registered.items() if key in kind.manifest_values]
        if not carriers:
            raise Refused(kinds.BAD_FORMAT, f"policy.{key}: no PEP holds this yet, no artifact of a "
                                            f"{', '.join(manifest.targets)} release carries it, so it is not sealed")
        for name, value in carriers:
            if not _same_value(manifest.values[key], value):
                raise Refused(kinds.BAD_FORMAT, f"policy.{key} is not the value a {name} release carries; no artifact "
                                                f"of a release holds another value yet, so it is not sealed")


def _previous(controller, target: str, stream: str, seq: int, policy: Optional[str]):
    """(policy hash, {artifact: body} or None, what is held) of the release a `target` release at `seq` replaces in the
    controller state: the latest one stored on `stream` below `seq` for that target, or the latest whose policy hash is
    `policy` when one is named, with every artifact of its release that names the target. The bodies are given only when
    the held release is whole: every body is stored and hashes to its envelope's, and the release id computed over them
    is the signed `release` (E10). A partial copy would make the tool compare with less than the release, and a zone
    file missing from it would read as protecting nothing. What is held is `whole`, `partial` or `none`."""
    def release_member(info) -> bool:
        return (info["stream"] == stream and target in info["targets"] and info["artifact"] not in kinds.TRUST_ARTIFACTS
                and info["artifact"] not in kinds.INSTALL_ARTIFACTS)
    held = [info for info in controller.stored.values()
            if release_member(info) and info["seq"] < seq and (policy is None or info["policy"] == policy)]
    if not held:
        return (policy or ""), None, "none"
    latest = max(held, key=lambda info: info["seq"])
    members = [info for info in controller.stored.values()
               if release_member(info) and info["release"] == latest["release"] and info["seq"] == latest["seq"]]
    bodies = {info["artifact"]: controller.blob(info["body_sha256"]) for info in members}
    whole = (len(bodies) == len(members)
             and all(body is not None and canon.sha256_hex(body) == info["body_sha256"]
                     for info, body in ((info, bodies[info["artifact"]]) for info in members))
             and env.release_id([(name, canon.sha256_hex(body)) for name, body in bodies.items()]) == latest["release"])
    return latest["policy"], (bodies if whole else None), ("whole" if whole else "partial")


def _compared(target: str, old: Optional[Dict[str, bytes]], new: Dict[str, bytes], held: str) -> dict:
    """What the tool found for one target's release against the one it replaces, for the owner to read before a widening
    statement: the artifacts it found larger (W1, each as `widening.compare_artifact` answers), the optional artifacts
    the release does not carry, and whether the held release was whole."""
    from prismpath.distribution import widening
    absent = sorted(name for name in kinds.TARGETS[target].when_declared if name not in new and name != "sandbox.profile")
    if old is None:
        return {"held": held, "larger": sorted(new), "absent": absent}
    larger = sorted(name for name in sorted(set(old) | set(new)) if (name in new or name in widening.OPTIONAL)
                    and widening.compare_artifact(name, old.get(name), new.get(name)) != widening.NOT_LARGER)
    return {"held": held, "larger": larger, "absent": absent}


def _view(target: str):
    """What an artifact's own check (V11) reads of a PEP of `target` that holds no install part, for the check the
    sealing tool runs before it signs."""
    from types import SimpleNamespace
    return SimpleNamespace(kind=target, install=None, qualification=None)


def seal_manifest(release, signers: List[Signer], *, held: Optional[str] = None) -> ManifestSealed:
    """The envelopes of a verified policy manifest (`policy_manifest.verify`, a `Release`), one release per target and
    one envelope per artifact of it, made by the target kind's `derive` from the bytes the check verified and nothing
    read again (SPEC.md section 10). Each release carries the manifest's stream, seq, not_before and end, and every
    envelope's meta names the manifest (`manifest_sha256`, its signed `flow_sha256`) and the rules (`source_sha256` on
    the `policy.core`, `rules_sha256` on a side artifact).

    The tool decides `widens` itself (W7): it compares each target's release, whole, with the one it replaces in the
    controller state `held` (W1, `widening.compare_release`, as a PEP that decides compares it). `widens: no` is
    refused with `dist:widening-unsigned` when it finds the release larger or holds no release to compare with, and
    `widens: yes` seals a widening, which needs its own widening statement (`dist widen`): the tool never signs one.
    `replaces` is the manifest's, else the policy hash of the release `held` holds below this seq, else none, and it
    must be one hash for every target. A release is sealed per target because a PEP computes the release id over the
    artifacts staged for it (E10, C2). `Refused` with the first cause, and nothing is returned."""
    from prismpath.distribution import widening
    manifest = release.manifest
    registered = _registered(manifest)
    _carried(manifest, registered)
    bodies = {}
    for target, kind in registered.items():
        derived = dict(kind.derive(release))
        if "policy.core" not in derived or canon.sha256_hex(derived["policy.core"]) != manifest.image_sha256:
            raise Refused(kinds.BAD_FORMAT, f"the {target} release's policy is not the manifest's image; a manifest "
                                            f"states one policy hash, its image's, for every target")
        unused = set(derived) - kinds.TARGETS[target].uses
        if unused:
            raise Refused(kinds.BAD_FORMAT, f"a {target} release does not carry {', '.join(sorted(unused))}")
        bodies[target] = derived
    policy = manifest.image_sha256
    controller = held_controller(held) if held is not None else None
    previous = {target: _previous(controller, target, manifest.stream, manifest.seq, manifest.replaces or None)
                if controller is not None else (manifest.replaces, None, "none") for target in registered}
    replaces = {hash_ for hash_, _bodies, _held in previous.values()}
    if len(replaces) != 1:
        raise Refused(kinds.BAD_FORMAT, "the targets' releases replace different policies, and a manifest states one "
                                        "replaces; name it with policy.replaces or seal each target from a manifest "
                                        "on its own stream")
    replaces_hash = replaces.pop()
    compared = {target: _compared(target, old, bodies[target], held_as) for target, (_h, old, held_as) in previous.items()}
    larger = any(widening.compare_release(old, bodies[target]) != widening.NOT_LARGER
                 for target, (_hash, old, _held) in previous.items())
    if not manifest.widens and larger:
        if all(old is not None for _hash, old, _held in previous.values()):
            found = "found the release larger"
        elif any(held_as == "partial" for _hash, _old, held_as in previous.values()):
            found = "holds only part of the release it replaces, so it holds no whole release to compare with"
        else:
            found = "holds no release it replaces to compare with"
        found += " (" + "; ".join(f"{target}: larger {', '.join(seen['larger']) or 'nothing'}, absent "
                                  f"{', '.join(seen['absent']) or 'nothing'}" for target, seen in sorted(compared.items())) + ")"
        raise Refused(widening.UNSIGNED, f"the manifest says widens: no and the sealing tool {found} (W7); write "
                                         f"widens: yes and sign its widening statement with dist widen")
    widens = bool(manifest.widens)
    sealed = []
    ids = {}
    for target in sorted(bodies):
        derived = bodies[target]
        release_id = env.release_id([(artifact, canon.sha256_hex(body)) for artifact, body in derived.items()])
        ids[target] = release_id
        for artifact in sorted(derived):
            body = derived[artifact]
            meta = ({"manifest_sha256": release.manifest_sha256, "source_sha256": manifest.rules_sha256}
                    if artifact == "policy.core" else
                    {"manifest_sha256": release.manifest_sha256, "rules_sha256": manifest.rules_sha256})
            one = build_sealed(artifact, body, stream=manifest.stream, seq=manifest.seq, targets=[target],
                               signers=signers, not_before=release.not_before, expires=release.expires, meta=meta,
                               release=release_id, policy=policy, replaces=replaces_hash, widens=widens)
            envelope = env.read(env.unseal(one)[0])
            cause = kinds.TARGETS[target].check_for(artifact)(envelope, body, _view(target))
            if cause is not None:
                raise Refused(cause, f"the {target} release's {artifact} does not pass its own check (V11)")
            sealed.append(SealedArtifact(target, artifact, one, body))
    return ManifestSealed(tuple(sealed), replaces_hash, widens, larger, ids, compared)
