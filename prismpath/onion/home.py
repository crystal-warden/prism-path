# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""A home: the directory an agent or a gateway keeps its keys, its recorded policy and its PEP store in, and the
checks every reader of it runs before it decides anything.

Where things live (`prismpath.agent.commands` says more):

  authority.key, authority.pub   the authority key, which says which policy may run (mode 0600)
  instance.key, instance.pub     the instance key, which signs the root statement over a run (mode 0600)
  policy.core.json               the policy image every decision is made under
  policy.attestation.json        its sealed `policy.core` distribution envelope on the stream `local`, signed
                                 with the authority key (L1 of spec-policy-distribution.md), or the older
                                 `prismpath.core-image/1` attestation, read with a `legacy_form` event
  dist/                          the PEP store of a home that follows a stream, which holds no authority key

`load_checked` is the policy of a home that holds its own authority key, its keys and its attestation checked on
every load, and `load_distributed` and `Committed` the committed release of a home that follows a stream, every
envelope of it checked again (`pep.read_committed_release`). The policy is the one the home's kind decides with
(`policy_of`, from the kind registry), so an agent home gives `prismpath.agent.policy.Policy` and a gateway home the
kernel's policy under the reading domain the registry gives it. A home whose kind the registry cannot describe is
not read.

The agent and the gateway read their homes through this module, so neither imports the other.
"""
from __future__ import annotations

import os
import sys
import time
import time as _time
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Tuple

from prismpath import canon

AGENT_DIR = ("prismpath", "agent")
POLICY_FILE = "policy.core.json"
ATTESTATION_FILE = "policy.attestation.json"
RUNS_DIR = "runs"
POLICY_CASE = "agent_default"
KEY_ROLES = ("authority", "instance")


class AgentError(Exception):
    """Something the person can fix; the message says what."""


def policy_of(kind: str, image: bytes):
    """The policy a home of `kind` decides with, built from `image`: the kind's own policy object when it registered
    one (`TargetKind.policy`), else the kernel's policy under the reading domain the kind registry gives the kind
    (`kinds.reading_domain`). AgentError when the registry knows no domain for it, so nothing is decided under a guess."""
    from prismpath.distribution import kinds as dist_kinds
    registered = dist_kinds.KINDS.get(kind)
    if registered is not None and registered.policy is not None:
        return registered.policy(image)
    from prismpath.kernel.decision import Policy
    try:
        domain = dist_kinds.reading_domain(kind)
    except dist_kinds.Refused as refused:
        raise AgentError(f"a {kind} home cannot be read here ({refused})") from None
    return Policy(image, domain)


# ----------------------------------------------------------------------------------------------- places
def config_dir(env: Optional[Mapping[str, str]] = None, platform: Optional[str] = None) -> Path:
    """`<config>/prismpath/agent` for this platform."""
    env = os.environ if env is None else env
    platform = sys.platform if platform is None else platform
    home = Path(env.get("HOME") or env.get("USERPROFILE") or Path.home())
    if platform.startswith("win"):
        base = Path(env["APPDATA"]) if env.get("APPDATA") else home / "AppData" / "Roaming"
    elif platform == "darwin":
        base = home / "Library" / "Application Support"
    else:
        xdg = env.get("XDG_CONFIG_HOME", "")
        base = Path(xdg) if xdg and os.path.isabs(xdg) else home / ".config"
    return base.joinpath(*AGENT_DIR)



def sha256_hex(data: bytes) -> str:
    import hashlib
    return hashlib.sha256(data).hexdigest()


# ------------------------------------------------------------------------------------------------- keys
def key_paths(home: Path, role: str):
    return home / f"{role}.key", home / f"{role}.pub"


def key_id(home: Path, role: str) -> Optional[str]:
    pub = key_paths(home, role)[1]
    return sha256_hex(pub.read_bytes()) if pub.is_file() else None


def make_dir(path: Path) -> None:
    for directory in (path.parent, path):
        if not directory.exists():
            directory.mkdir(parents=True, exist_ok=True)
            os.chmod(directory, 0o700)
    os.chmod(path, 0o700)


def ensure_key(home: Path, role: str) -> str:
    """Make the key pair of `role` when neither file exists; keep a whole pair; refuse half of one."""
    key, pub = key_paths(home, role)
    if key.exists() and pub.exists():
        os.chmod(key, 0o600)
        os.chmod(pub, 0o600)
        return "kept"
    if key.exists() or pub.exists():
        raise AgentError(f"{home} holds only half of the {role} key pair ({(key if key.exists() else pub).name}); "
                         f"it is never replaced, so move it aside or restore the other half")
    if role == "authority":
        from prismpath.hotswap import policy_pack
        policy_pack.keygen(str(home), "authority")
    else:
        from prismpath.ledgers import root_statement
        root_statement.keygen(str(home), "instance")
    os.chmod(key, 0o600)
    os.chmod(pub, 0o600)
    return "created"


LOCAL_KINDS = ("agent", "gateway")     # the target kinds a home that holds its own authority key seals its policy for


def attestation(home: Path, image: bytes, case: str = POLICY_CASE) -> bytes:
    """The record of the home's policy (L1): a sealed `policy.core` envelope over `image`, on the stream `local`,
    for the `gateway` kind when `case` is `gateway` and for `agent` otherwise, signed with the authority key. The
    starter's name is not sealed; `starter_of` reads it from the image."""
    from prismpath.distribution import legacy
    from prismpath.onion import keys as onion_keys
    signer = onion_keys.load_signer(str(key_paths(home, "authority")[0]))
    kind = "gateway" if case == "gateway" else "agent"
    return legacy.local_seal("policy.core", image, [signer], seq=1, targets=(kind,))


def is_sealed(record: bytes) -> bool:
    from prismpath.distribution import envelope as env
    return record[:len(env.MAGIC)] == env.MAGIC


def check_sealed(sealed: bytes, image: bytes, authority) -> None:
    """The home's sealed `policy.core` envelope checked as the verifier's V2 to V9 check it, for a home that holds
    its own authority key: the container and the envelope read, a `policy.core` for one agent or gateway kind, a
    signature by the authority key, in force now (V6), and the image its body and its policy hash. V11, the image
    read as the core reads it, is the `Policy` the caller builds from it. AgentError with the cause otherwise.
    Nothing here reads a floor or a trust store, since a home that holds its key has neither."""
    from prismpath.distribution import envelope as env
    from prismpath.distribution.kinds import Refused
    try:
        envelope_bytes, entries = env.unseal(sealed)
        envelope = env.read(envelope_bytes)
    except Refused as refused:
        raise AgentError(f"the recorded policy's attestation envelope does not read ({refused.cause})") from None
    kinds = [kind for kind in envelope.targets if kind in LOCAL_KINDS]
    if envelope.artifact != "policy.core" or len(kinds) != 1:
        raise AgentError("the recorded policy's attestation envelope is not a policy.core for an agent or gateway home")
    message, signed = env.signed_message(envelope_bytes), False
    for _key_id, signature in entries:
        try:
            authority.verify(signature, message)
            signed = True
            break
        except Exception:  # noqa: BLE001 - another key's entry, or a signature that does not verify
            continue
    now, digest = int(time.time()), sha256_hex(image)      # V6 with the SKEW of section 7, 300 seconds
    cause = ("sig:invalid" if not signed else "dist:not-yet-valid" if envelope.not_before - now > 300
             else "dist:expired" if now >= envelope.expires
             else "image:sha256-mismatch" if (len(image), digest, digest)
             != (envelope.body_size, envelope.body_sha256, envelope.policy_sha256) else None)
    if cause is not None:
        raise AgentError(f"the recorded policy's attestation envelope does not verify under the authority key ({cause})")


def load_distributed(home: Path, *, until: Optional[list] = None, kind: str = "agent"):
    """The policy of a home that follows a stream (spec-policy-distribution.md, section 3): the committed
    `policy.core`, every envelope of the release checked again on this load (`committed_until`). Such a home
    holds its instance key and no authority key. Returns the policy and the committed bodies, and appends to
    `until`, when given, the earliest `expires` of the release (0 when none expires). A gateway home has the same
    layout and passes `kind` `gateway`. The policy is the one the kind decides with (`policy_of`)."""
    from prismpath.distribution.kinds import Refused
    from prismpath.ledgers import root_statement
    if any(path.exists() for path in key_paths(home, "authority")):
        raise AgentError(f"{home} follows a stream and must hold no authority key; remove authority.key")
    for path in key_paths(home, "instance"):
        if not path.is_file():
            raise AgentError(f"no instance key at {path}; run `prismpath agent init --follow`")
    instance = root_statement.InstanceKey.load(str(key_paths(home, "instance")[0]))
    if instance.key_id != key_id(home, "instance"):
        raise AgentError("instance.key and instance.pub are not one key pair")
    try:
        bodies, expires = committed_until(home, kind=kind)
    except Refused as refused:
        raise AgentError(f"the home's release does not stand: {refused}") from None
    if until is not None:
        until.append(expires)
    return policy_of(kind, bodies["policy.core"]), bodies


class Committed:
    """The committed release of a home that follows a stream, for a decider that runs long (the egress proxy's
    gate, the MCP proxy). `current()` answers (policy, bodies) as `load_distributed` does, or raises its
    AgentError, and loads again only when a file of the PEP's store changed (a commit, a rollback, a lapse, a
    revocation, a lock) or the release's earliest expiry has come, so a decision costs a few `stat` calls and a
    release that no longer stands stops deciding at the next one (section 9, X3, R5)."""
    # the install record too, so a fallback set applied while no release decides reaches it (FB1, FB8)
    WATCHED = ("anchor.json", "setting.json", "counter.json", "floor.json", "trust.json", "active.json",
               "install/record.json")

    def __init__(self, home: Path, kind: str = "agent"):
        self.home, self.kind = Path(home), kind
        self._stamp: Any = None
        self._until = 0
        self._loaded: Any = None
        self._error: Optional[AgentError] = None

    def _files(self) -> tuple:
        out = []
        for name in self.WATCHED:
            try:
                stat = os.stat(self.home / "dist" / name)
                out.append((stat.st_ino, stat.st_mtime_ns, stat.st_size))
            except OSError:
                out.append(None)
        return tuple(out)

    def current(self):
        stamp = self._files()
        if stamp != self._stamp or (self._until and clock() >= self._until):
            self._stamp, until = stamp, []
            try:
                self._loaded, self._error = load_distributed(self.home, until=until, kind=self.kind), None
                self._until = until[0]
            except AgentError as exc:
                self._loaded, self._error, self._until = None, exc, 0
        if self._error is not None:
            raise self._error
        return self._loaded


def load_checked(home: Path, kind: str = "agent"):
    """The policy the hook decides under, after checking that both key pairs are present and read, the instance key
    is not the authority key, and the policy's attestation verifies under the authority key, built as a home of
    `kind` decides with it (`policy_of`). Raises with the reason otherwise; the hook answers that reason with a deny.
    A home that follows a stream reads its committed release instead (`load_distributed`). The store of runs is the
    caller's, as `prismpath.agent.commands.load_checked` gives both."""
    from prismpath.hotswap import policy_pack
    from prismpath.onion import keys as onion_keys
    from prismpath.kernel import canon2
    from prismpath.ledgers import core_evidence, root_statement
    if is_distributed(home):
        return load_distributed(home)[0]
    for role in KEY_ROLES:
        for path in key_paths(home, role):
            if not path.is_file():
                raise AgentError(f"no {role} key at {path}; run `prismpath agent init`")
    authority, authority_id = policy_pack.load_public(str(key_paths(home, "authority")[1]))
    onion_keys.load_signer(str(key_paths(home, "authority")[0]))   # the private half must read too
    instance = root_statement.InstanceKey.load(str(key_paths(home, "instance")[0]))
    if instance.key_id != key_id(home, "instance"):
        raise AgentError("instance.key and instance.pub are not one key pair")
    root_statement.check_separation(instance, [authority_id])
    policy_path, attestation_path = home / POLICY_FILE, home / ATTESTATION_FILE
    if not policy_path.is_file() or not attestation_path.is_file():
        raise AgentError(f"no recorded policy in {home}; run `prismpath agent init`")
    image = policy_path.read_bytes()
    record = attestation_path.read_bytes()
    if is_sealed(record):
        check_sealed(record, image, authority)
        return policy_of(kind, image)
    # the older form (L3): a `prismpath.core-image/1` attestation, read with a `legacy_form` event each time
    statement = canon2.loads(record.rstrip(b"\n"))
    if (not isinstance(statement, dict) or statement.get("format") != core_evidence.IMAGE_FORMAT
            or statement.get("key_id") != authority_id or statement.get("image_sha256") != sha256_hex(image)):
        raise AgentError("the recorded policy's attestation does not name this policy and authority key")
    try:
        authority.verify(bytes.fromhex(statement["sig"]), core_evidence.IMAGE_DOMAIN + image)
    except Exception as exc:
        raise AgentError("the recorded policy's attestation signature does not verify") from exc
    from prismpath.distribution import legacy
    legacy.record_at(str(home / legacy.AUDIT_FILE), legacy.CORE_IMAGE, reader="agent.load_checked",
                     sha256=sha256_hex(image), key_id=authority_id, instance_key=instance)
    return policy_of(kind, image)



def detail(exc: BaseException) -> str:
    text = " ".join(str(exc).split()) or type(exc).__name__
    return text if len(text) <= 240 else text[:237] + "..."



def require_keys(home: Path) -> None:
    for role in KEY_ROLES:
        for path in key_paths(home, role):
            if not path.is_file():
                raise AgentError(f"no {role} key at {path}; run `prismpath agent init`")



# ------------------------------------------------------------------ the home's PEP store (spec-policy-distribution.md, section 3)

clock = _time.time                                 # the home's clock, Unix seconds


SPOOL = "recent.jsonl"
SPOOL_KEEP = 64                                    # H5: a record carries at most the last 64 decisions


def note(home, reading: Mapping[str, Any]) -> None:
    """A decider of a distributed home (the egress proxy, the MCP proxy) hands the reading it decided to the PEP's
    ring for the next state record (H5). The spool keeps the last 64, and a reading that cannot be written is
    dropped: the decision stands and only the heartbeat misses it."""
    if not is_distributed(home):
        return
    from prismpath.kernel import canon2
    path = Path(home) / "dist" / SPOOL
    try:
        with open(path, "ab") as handle:
            handle.write(canon2.dumps(dict(reading)) + b"\n")
        if path.stat().st_size > 64 * 1024:
            lines = path.read_bytes().splitlines()[-SPOOL_KEEP:]
            canon.atomic_write_bytes(str(path), b"".join(line + b"\n" for line in lines))
    except (OSError, ValueError, TypeError):
        return


def take_readings(home) -> list:
    """The spooled readings, the last 64, and the spool emptied. The spool is moved aside before it is read, so a
    reading noted meanwhile starts a new spool rather than being removed unread."""
    from prismpath.kernel import canon2
    path = Path(home) / "dist" / SPOOL
    taking = path.with_name(SPOOL + ".taking")
    try:
        os.replace(path, taking)
        lines = taking.read_bytes().splitlines()
        taking.unlink()
    except OSError:
        return []
    out = []
    for line in lines[-SPOOL_KEEP:]:
        try:
            out.append(canon2.loads(line))
        except Exception:  # noqa: BLE001 - a torn line is a reading lost to the heartbeat, not to the decision
            continue
    return out


def is_distributed(home) -> bool:
    """A home that follows a stream: its PEP store holds a trust store."""
    return (Path(home) / "dist" / "trust.json").is_file()


def committed_until(home, now: Optional[int] = None, kind: str = "agent") -> Tuple[Dict[str, bytes], int]:
    """`committed`, and the earliest `expires` of the release's envelopes, 0 when none expires. `kind` is the
    target the home is, `agent` or `gateway`, whose homes have one layout."""
    from prismpath.distribution.pep import read_committed_release
    release = read_committed_release(str(home), kind, int(clock() if now is None else now))
    expiries = [envelope.expires for envelope in release.envelopes.values() if envelope.expires]
    return dict(release.bodies), min(expiries, default=0)
