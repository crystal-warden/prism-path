#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""An operator's answer to an escalation the cFS app's action floor made (docs/design/spec-policy-distribution.md,
section 21.5), sealed on the ground.

    python -m integrations.cfs.ground.answer seal --key OPERATOR_KEY --pep PEP_ID --receipt HASH --policy HASH
                                               [--refuse] [--stream S] [--lifetime SECONDS] -o OUT

The app downlinks each escalation it opens: its event PRISMPATH_APP ESCALATION names the receipt hash, and the PEP id
is bytes 8 to 24 of every state record in its housekeeping (`downlink.read_state_record`). The answer is an
`operator.answer` envelope (OP2) on the app's stream for the `cfs` kind, whose body names that PEP and that receipt
and whose policy hash is the one of the action floor that escalated. It is signed by one operator key, lives at most
600 seconds and is offered on the app's command topic in the offer and chunk frames of any sealed envelope
(`table.frames`). `OUT` is a statement file (`table.statement_file`) holding the sealed envelope and its body.

The app applies an answer once and keeps its request unsent: an operator receipt has no case in a core run yet, so the
answer shows in the app's `answered` state record and its event, and the request it answers is not republished.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from integrations.cfs.ground import table  # noqa: E402

ANSWER_FORMAT = "prismpath.dist-answer/1"
ANSWER_LIFE = 600                                   # OP2: an answer's lifetime is at most 600 seconds


def answer_body(answer: str, pep: str, receipt: str) -> bytes:
    """OP2: the canon/2 body of an answer `allow` or `refuse` to the escalation whose receipt hash is `receipt`, for
    the PEP whose id is `pep`, 32 lower case hex digits."""
    from prismpath import canon
    if answer not in ("allow", "refuse") or len(pep) != 32 or len(receipt) != 64 or \
            any(c not in "0123456789abcdef" for c in pep + receipt):
        raise ValueError("an answer is allow or refuse, for a PEP id of 32 and a receipt hash of 64 hex digits")
    return canon.canon2_bytes({"answer": answer, canon.ENCODING_KEY: canon.CANON2, "format": ANSWER_FORMAT,
                               "pep": pep, "receipt": receipt})


def seal_answer(signer, *, pep: str, receipt: str, policy: str, answer: str = "allow", now: int,
                lifetime: int = 300, stream: str = table.STREAM):
    """The sealed operator.answer and its body: signed by the one operator key `signer` (an Ed25519 private key), on
    `stream` for the `cfs` kind, under the floor's policy hash `policy`, from `now` for `lifetime` seconds."""
    from prismpath import canon
    from prismpath.distribution import envelope as env
    if not 0 < lifetime <= ANSWER_LIFE:
        raise ValueError("an answer lives at most 600 seconds (OP2)")
    body = answer_body(answer, pep, receipt)
    doc = {"artifact": "operator.answer", "body_sha256": canon.sha256_hex(body), "body_size": len(body),
           "encoding": "canon/2", "expires": now + lifetime, "format": env.FORMAT, "meta": {}, "not_before": now,
           "policy_sha256": policy, "release": env.ZERO_HASH, "replaces": "", "seq": 1, "stream": stream,
           "targets": ["cfs"], "widens": False}
    return env.seal(canon.canon2_bytes(doc), [signer]), body


def main(argv=None) -> int:
    import time
    parser = argparse.ArgumentParser(description="seal an operator's answer to an escalation of a cFS app's floor")
    parser.add_argument("action", choices=["seal"])
    parser.add_argument("--key", type=Path, required=True, help="the operator's private key")
    parser.add_argument("--pep", required=True, help="the app's PEP id, from its state record")
    parser.add_argument("--receipt", required=True, help="the receipt hash of the escalation, from its event")
    parser.add_argument("--policy", required=True, help="the policy hash of the action floor that escalated")
    parser.add_argument("--refuse", action="store_true", help="answer refuse (allow otherwise)")
    parser.add_argument("--stream", default=table.STREAM)
    parser.add_argument("--lifetime", type=int, default=300)
    parser.add_argument("-o", "--out", type=Path, required=True)
    args = parser.parse_args(argv)
    from prismpath.hotswap import policy_pack
    sealed, body = seal_answer(policy_pack._load_private(str(args.key)), pep=args.pep, receipt=args.receipt,
                               policy=args.policy, answer="refuse" if args.refuse else "allow", now=int(time.time()),
                               lifetime=args.lifetime, stream=args.stream)
    args.out.write_bytes(table.statement_file(sealed, body))
    print(f"sealed an answer {'refuse' if args.refuse else 'allow'} to {args.receipt} for {args.pep}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
