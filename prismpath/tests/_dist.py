# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""What the policy distribution tests share: the corpus generator's fixed keys and image, a host enforcement
point over a temporary state directory, and a signer that seals releases for it."""
from __future__ import annotations

import importlib.util
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from prismpath import canon
from prismpath.distribution import envelope as env
from prismpath.distribution import trust as trust_module
from prismpath.distribution.adapters.host import HostAdapter
from prismpath.distribution.pep import Pep
from prismpath.hotswap.policy_host import PolicyHost
from prismpath.ledgers.root_statement import InstanceKey

REPO = Path(__file__).resolve().parent.parent


def generator():
    spec = importlib.util.spec_from_file_location("gen_distribution_corpus",
                                                  REPO / "portable" / "gen_distribution_corpus.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GEN = generator()
STREAM = GEN.STREAM
NOT_BEFORE, EXPIRES, NOW = GEN.NOT_BEFORE, GEN.EXPIRES, GEN.NOW


def instance_key(name: str = "I") -> InstanceKey:
    private = GEN.test_key(name)
    return InstanceKey(private, GEN.public_raw(private))


@dataclass
class Clock:
    now: int = NOW

    def __call__(self) -> int:
        return self.now


def seal(artifact: str, body: bytes, *, seq: int = 1, signer: str = "A", release: Optional[str] = None,
         policy_sha256: Optional[str] = None, not_before: int = NOT_BEFORE, expires: int = EXPIRES,
         meta: Optional[dict] = None, stream: str = STREAM, targets=("host",)) -> bytes:
    """A sealed envelope for `body`, by default a `policy.ppt` release of one artifact."""
    if meta is None:
        meta = GEN.image_meta(body) if artifact == "policy.ppt" else {}
    trust_kind = artifact in ("trust.revocation", "trust.rotation")
    envelope_bytes = env.build(
        artifact, body, stream=stream, seq=seq, targets=targets, not_before=not_before,
        expires=0 if artifact.startswith("trust.") else expires, meta=meta,
        policy_sha256=env.ZERO_HASH if trust_kind else (policy_sha256 or canon.sha256_hex(body)),
        release=env.ZERO_HASH if trust_kind else (release or env.release_id([(artifact, canon.sha256_hex(body))])))
    return env.seal(envelope_bytes, [GEN.test_key(signer)])


def image(threshold: int = 5) -> bytes:
    from prismpath.kernel import ppt_compile
    return ppt_compile.compile_predicate(f"when x >= {threshold}").serialize()


@dataclass
class HostPep:
    """A provisioned host PEP over `state_dir`, with its PolicyHost, its clock and its instance key."""
    state_dir: Path
    clock: Clock = field(default_factory=Clock)
    key: InstanceKey = field(default_factory=instance_key)
    authorities: List[str] = field(default_factory=lambda: ["A"])
    expiry_response: str = "refuse"

    def __post_init__(self):
        self.pep = self.open()

    def anchor(self) -> bytes:
        return trust_module.anchor_bytes([GEN.public_raw(GEN.test_key(name)) for name in self.authorities],
                                         target="host", stream=STREAM)

    def host(self) -> PolicyHost:
        return PolicyHost(str(self.state_dir), [], dict(GEN.QUALIFICATION), instance_key=self.key)

    def open(self, provision: bool = True) -> Pep:
        """A fresh PEP over the state directory, as after a restart, provisioned on first open."""
        pep = Pep(str(self.state_dir), HostAdapter(self.host()), self.key, self.clock,
                  expiry_response=self.expiry_response)
        if provision and not pep.provisioned:
            pep.confirm(pep.provision(self.anchor()))
        return pep

    def commit(self, body: bytes, seq: int = 1, **seal_args) -> bytes:
        self.pep.stage(seal("policy.ppt", body, seq=seq, **seal_args), body)
        return self.pep.commit(STREAM, seq, seal_args.get("policy_sha256") or canon.sha256_hex(body))
