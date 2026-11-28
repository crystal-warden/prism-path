# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The egress proxy's decision, read from the signed policy.

`PolicyGate` is the `gate` of `egress.EgressProxy`. It runs in the launcher, outside the sandbox, with the keys and
the runs directory that stay there. For each CONNECT it

  1. splits the target as written into a host and a port (a port that is not plain digits is 0), and reads it into
     a `connect` reading with the classifier, `Config.allowed_hosts` being the hosts the owner passed to the
     launcher. The classifier does not normalise: a host with upper case, a trailing dot, userinfo or an IP
     literal is `net_dest` `unknown`, and a port other than 443 is `other` (or `unknown` outside 1 to 65535);
  2. decides the reading with the reference kernel under the active attested image (`Policy.decide`, which is
     `prismpath.kernel.core_reference`);
  3. appends the reading and the verdict as the next receipt of the run, the same `Run.append` and receipt format
     the hook uses, with the SHA-256 of the agent profile on the journal line, so `prismpath agent verify` and
     `prismpath agent rules` see it. A refusal carries the cause the policy names (130 for a refused connection);
  4. answers (allowed, reason). Only a decision of `allow` that the compiled profile's `net` also covers passes.
     An escalation is a refusal here, since nobody is at the proxy to answer it.

The reading holds classes, never the host, so a receipt does not carry a name by accident. Fail closed: if the
receipt cannot be written, or anything else raises, the connection is refused and no tunnel opens.
"""
from __future__ import annotations

import threading
from pathlib import Path
from typing import Iterable, Optional, Tuple

from prismpath.agent import classifier
from prismpath.agent.profile import Profile
from prismpath.agent.run import Extras

PROXY_CLASSES = {"none": (), "proxy_model": ("model_api",), "proxy_allow": ("model_api", "allowed_host")}


def split_authority(authority: str) -> Tuple[str, int]:
    """(host, port) of a CONNECT target as written. No colon, or a port that is not 1 to 9 ASCII digits, is port 0."""
    host, sep, port = authority.rpartition(":")
    if not sep or not port.isascii() or not port.isdigit() or len(port) > 9:
        return authority, 0
    return host, int(port)


def hosts_digest(allowed_hosts: Iterable[str]) -> str:
    """The digest of the allowed host list `--allow-host` named: lower case, sorted, without repeats, as canon/2 bytes.
    The list is a launcher argument and not part of the signed policy, so each egress receipt records it."""
    import hashlib
    from prismpath.kernel import canon2
    return hashlib.sha256(canon2.dumps(sorted({str(h).lower() for h in allowed_hosts}))).hexdigest()


class PolicyGate:
    """`follow`, a `home.Committed`, is given for a home that follows a stream: each CONNECT then reads the
    committed state first, refuses with `policy-lapsed` when the release no longer decides and with
    `policy-changed` when another policy was committed since the run began, and takes its hosts from the committed
    `egress.hosts`, so a commit that removes a host closes it at the next connection."""

    def __init__(self, policy, store, session: str, workspace, profile: Profile, allowed_hosts: Iterable[str] = (),
                 home=None, follow=None):
        self.policy, self.store, self.session, self.profile = policy, store, session, profile
        self.home = home        # a home that follows a stream is told each reading, for its heartbeat
        self.follow = follow
        self.run = None         # opened by the first receipt, so a run with no connection leaves no run behind
        self.workspace = Path(workspace)
        self._hosts = tuple(allowed_hosts)
        self.config = classifier.Config.for_workspace(self.workspace, allowed_hosts=self._hosts)
        self.profile_sha256 = profile.hash()
        self.hosts_sha256 = hosts_digest(allowed_hosts)
        self._lock = threading.Lock()

    def reading(self, authority: str) -> dict:
        host, port = split_authority(authority)
        return classifier.classify({"tool": "connect", "args": {"host": host, "port": port}}, self.config)

    def _follow(self) -> Optional[str]:
        """The committed state for this connection: None to decide, else the refusal's reason."""
        from prismpath.agent import dist_kind as agent_home
        from prismpath.onion.home import AgentError
        try:
            policy, bodies = self.follow.current()
        except AgentError:
            return "policy-lapsed"
        if policy.image != self.policy.image:
            return "policy-changed"
        hosts = tuple(host.lower() for host in agent_home.hosts(bodies))
        if hosts != self._hosts:
            with self._lock:
                self._hosts = hosts
                self.config = classifier.Config.for_workspace(self.workspace, allowed_hosts=hosts)
                self.hosts_sha256 = hosts_digest(hosts)
        return None

    def _floor(self, authority: str) -> bool:
        """AF1: the action floor's `egress.hosts` of a home that follows a stream is asked first, in every state, and a
        host it lists is reached whatever the release says. Its receipt is the floor's (`agent_home.ask_floor`)."""
        if self.home is None:
            return False
        from prismpath.agent import dist_kind as agent_home
        host, _port = split_authority(authority)
        answered = agent_home.ask_floor(self.home, {"host": host.lower()})
        return answered is not None and answered["decision"] == "allow"

    def __call__(self, authority: str) -> Tuple[bool, str]:
        try:
            if self._floor(authority):
                return True, "floor-allow"
        except Exception:  # noqa: BLE001 - a floor that cannot be asked is silent; the release decides
            pass
        try:
            if self.follow is not None:
                refused = self._follow()
                if refused is not None:
                    return False, refused
            reading = self.reading(authority)
            raw = self.policy.reading_bytes(reading)
            decision = self.policy.decide(raw)
            if self.home is not None:
                from prismpath.agent import dist_kind as agent_home
                agent_home.note(self.home, reading)
            with self._lock:
                if self.run is None:
                    self.run = self.store.open(self.session, self.policy.image)
                self.run.append(raw, decision.verdict, extras=Extras(sandbox_profile=self.profile_sha256, hosts_sha256=self.hosts_sha256))
        except Exception:  # noqa: BLE001 - no receipt, no tunnel
            return False, "receipt-error"
        if decision.kind == "allow":
            if reading["net_dest"] in PROXY_CLASSES[self.profile.net]:
                return True, "policy-allow"
            return False, "profile-net"
        code = decision.cause_code
        return False, f"{'refused' if decision.kind == 'refuse' else 'escalated'}-{code if code is not None else 'uncoded'}"
