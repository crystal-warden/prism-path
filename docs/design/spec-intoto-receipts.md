# in-toto and DSSE export of a sealed core run

*Specification of the in-toto Statement v1 and DSSE v1.0 envelope produced and verified by
`prismpath/ledgers/intoto.py` for a sealed core run (`prismpath/ledgers/core_evidence.py`,
`prismpath/agent/evidence.py`, `prismpath/agent/run.py`).*

## 1. Envelope and Pre-Authentication Encoding (PAE)

`prismpath.ledgers.intoto.export(run_dir)` reads a sealed core run directory (or a run store
directory containing sealed runs) and returns a list of DSSE v1.0 envelopes, one per sealed run:

```json
{
  "payloadType": "application/vnd.in-toto+json",
  "payload": "<base64 of canon/2 in-toto Statement v1 bytes>",
  "signatures": [
    {
      "keyid": "<64-char lowercase hex SHA-256 of instance.pub>",
      "sig": "<base64 of 64-byte Ed25519 signature over PAE>"
    }
  ]
}
```

- `payloadType` is `application/vnd.in-toto+json`.
- `payload` is standard RFC 4648 base64 over the `canon/2` bytes (`prismpath.kernel.canon2.dumps`)
  of the in-toto Statement v1 object.
- `signatures` holds one entry signed with the run's Ed25519 instance private key (`instance.key`,
  whose raw 32-byte public half is `instance.pub` and whose identifier `keyid` is
  `SHA-256(instance.pub)` in lowercase hex).
- The signature is computed over the DSSE v1.0 Pre-Authentication Encoding (`pae(payloadType,
  payload_bytes)`):

```text
PAE(type, body) = "DSSEv1" || SP || LEN(type) || SP || type || SP || LEN(body) || SP || body
```

where `SP` is ASCII `0x20`, `type` is the UTF-8 bytes of `payloadType`, `body` is the raw
unencoded payload bytes, and `LEN(x)` is the byte length of `x` in ASCII decimal.

## 2. Statement and predicate schema

The decoded payload is an in-toto Statement v1 (`https://in-toto.io/Statement/v1`) with
`predicateType` `https://prismpath.dev/attestations/core-run/v1`:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {"name": "receipts.jsonl", "digest": {"sha256": "<64-char hex>"}},
    {"name": "receipts.roots.jsonl", "digest": {"sha256": "<64-char hex>"}}
  ],
  "predicateType": "https://prismpath.dev/attestations/core-run/v1",
  "predicate": {
    "authority_key_id": "<64-char hex SHA-256 of authority.pub>",
    "format": "prismpath.core-run-root/2",
    "image_sha256": "<64-char hex SHA-256 of the policy image, or images_sha256 when multiple>",
    "images_sha256": "<64-char hex SHA-256 of images.jsonl>",
    "instance_key_id": "<64-char hex SHA-256 of instance.pub>",
    "key_id": "<64-char hex SHA-256 of instance.pub>",
    "leaves": 200,
    "log": "core-run",
    "policy": {"core_run_sha256": "<64-char hex SHA-256 of run.json>"},
    "public_key": "<64-char hex of raw 32-byte instance.pub>",
    "root": "<64-char hex RFC 6962 Merkle root of receipts.jsonl>",
    "sig": "<128-char hex Ed25519 signature over prismpath.core-run-root/2\\0 + canon/2 body>",
    "time_us": 1762257600123000,
    "trigger": "core-run"
  }
}
```

### Predicate fields

The predicate holds every member of the run's sealed root statement (`receipts.roots.jsonl`)
alongside the manifest's bound key and image digests (`run.json`, `images.jsonl`), with the exact
field names and values stored in the run:

| field | type | source in run | meaning |
|---|---|---|---|
| `format` | string | `receipts.roots.jsonl` | `"prismpath.core-run-root/2"` (RFC 6962 Merkle scheme) |
| `log` | string | `receipts.roots.jsonl` | `"core-run"` |
| `leaves` | integer | `receipts.roots.jsonl` | tree size: number of decision receipt leaves in `receipts.jsonl` |
| `root` | string | `receipts.roots.jsonl` | 64-char hex RFC 6962 Merkle root over the SHA-256 leaf hashes of `receipts.jsonl` (`""` when `leaves` is `0`) |
| `time_us` | integer | `receipts.roots.jsonl` | signer clock in microseconds since the Unix epoch |
| `trigger` | string | `receipts.roots.jsonl` | `"core-run"` |
| `key_id` | string | `receipts.roots.jsonl` | 64-char hex SHA-256 of the raw 32-byte instance public key |
| `public_key` | string | `receipts.roots.jsonl` | 64-char hex encoding of the raw 32-byte Ed25519 instance public key |
| `policy` | object | `receipts.roots.jsonl` | `{"core_run_sha256": "<sha256 of run.json>"}` |
| `sig` | string | `receipts.roots.jsonl` | 128-char hex Ed25519 signature over `b"prismpath.core-run-root/2\x00"` followed by the `canon/2` root statement body |
| `authority_key_id` | string | `run.json` | 64-char hex SHA-256 of the raw 32-byte authority public key (`authority.pub`) |
| `instance_key_id` | string | `run.json` | 64-char hex SHA-256 of the raw 32-byte instance public key (`instance.pub`), equal to `key_id` |
| `images_sha256` | string | `run.json` | 64-char hex SHA-256 of `images.jsonl` |
| `image_sha256` | string | `images.jsonl` / `run.json` | 64-char hex SHA-256 of the policy image when all cases share one image (as in an episode or session run), else `images_sha256` |

### Verification (`prismpath.ledgers.intoto.verify`)

`verify(envelopes, run_dir, pinned_keys)` checks, in order, and raises `Bad` on the first failure:

1. The envelope structure (`payloadType` equal to `application/vnd.in-toto+json`, canonical base64
   `payload` and `signatures`, 64-byte signature, 32-byte hex `keyid`).
2. The run's `authority.pub` and `instance.pub` against `pinned_keys` when supplied. Pinning is optional. Without pins the signature is checked against the run's own
   `instance.pub`, which says nothing about who made the run, so the returned report carries
   `pinned: false` and `root_statement: "signed-unpinned"`, and `pinned: true` only when both the authority
   and instance keys were pinned.
3. The Ed25519 signature in the DSSE envelope over `pae(payloadType, payload_bytes)` under the
   pinned (or run-carried) instance public key.
4. That `payload_bytes` is a canonical `canon/2` document with `_type`
   `https://in-toto.io/Statement/v1` and `predicateType`
   `https://prismpath.dev/attestations/core-run/v1`.
5. That every entry in `subject` (including `receipts.jsonl`) matches the SHA-256 of the
   corresponding file in `run_dir`.
6. That `predicate` equals the run's own sealed root statement and manifest fields.
7. Full core run verification via `prismpath.ledgers.core_evidence.verify` (authority and instance
   key separation, root statement signature and RFC 6962 Merkle root over `receipts.jsonl`, image
   attestations under `authority.pub`, canonical flow rendering of each signed image, and replay of
   the receipts through the Python reference kernel).

## 3. Mapping a root statement to a Rekor or SCITT entry

This section describes how a sealed run's DSSE envelope or root statement maps to a public or
federated transparency log entry. No network client is part of `prismpath/ledgers/intoto.py`.

### 3.1 Rekor (`dsse` and `intoto` entry types)

Rekor (the Sigstore transparency log) accepts DSSE envelopes directly under the `dsse` (v0.0.1) or
`intoto` (v0.0.2) entry types:

| PrismPath artifact | Rekor entry field | value |
|---|---|---|
| DSSE envelope (`intoto.export`) | `spec.proposedContent.envelope` (or `spec.content.envelope`) | the JSON object `{payloadType, payload, signatures}` |
| `SHA-256(payload_bytes)` | `spec.payloadHash` | lowercase hex SHA-256 of the `canon/2` in-toto Statement v1 bytes |
| `instance.pub` (32 raw bytes) | `spec.verifier` / `publicKey` | the Ed25519 public key encoded as RFC 8410 SubjectPublicKeyInfo PEM |
| `predicate.root`, `predicate.leaves` | indexed inside `payload` | the inner RFC 6962 Merkle root and count over `receipts.jsonl` |

Upon submission, Rekor reconstructs `PAE("application/vnd.in-toto+json", payload_bytes)`, verifies
the Ed25519 signature against the supplied `publicKey`, and appends the canonicalized entry to its
own RFC 6962 Merkle tree. Rekor returns a log entry containing `logIndex`, `integratedTime`, a
Signed Entry Timestamp (`verification.signedEntryTimestamp`), and an RFC 6962 `inclusionProof`
(`treeSize`, `rootHash`, `hashes`).

Two RFC 6962 trees compose without exposing individual decisions to the log:

1. **Inner tree (local to the run):** each decision in `receipts.jsonl` is a leaf under
   `predicate.root` (`predicate.leaves` leaves). Individual readings and decisions remain in
   `run_dir`.
2. **Outer tree (Rekor):** the single DSSE envelope attesting `predicate.root` is one leaf in
   Rekor's log. A verifier with a single receipt checks its local RFC 6962 inclusion path to
   `predicate.root`, checks `predicate.root` inside the DSSE statement, and checks Rekor's
   inclusion proof and checkpoint signature for the DSSE entry.

### 3.2 SCITT (IETF COSE Signed Statements and Receipts)

In the IETF SCITT (Supply Chain Integrity, Transparency, and Trust) architecture, an attestation is
submitted as a COSE Signed Statement (`COSE_Sign1`, RFC 9052) and receives a COSE Receipt containing
an inclusion proof in the transparency service's tree:

| PrismPath field | SCITT `COSE_Sign1` field | value |
|---|---|---|
| Ed25519 signing algorithm | protected header `1` (`alg`) | `-8` (`EdDSA`) |
| `PAYLOAD_TYPE` | protected header `3` (`content_type`) | `"application/vnd.in-toto+json"` |
| `predicate.key_id` (`instance_key_id`) | protected header `4` (`kid`) | 32-byte raw SHA-256 digest of `instance.pub` (or UTF-8 hex) |
| `predicate.key_id` / deployment URI | protected header `15` (`CWT_Claims`, RFC 9597) `1` (`iss`) | issuer identifier bound to the pinned instance key |
| `predicate.policy.core_run_sha256` | protected header `15` (`CWT_Claims`) `2` (`sub`) | `run.json` digest identifying the sealed run |
| `predicate.time_us // 1_000_000` | protected header `15` (`CWT_Claims`) `6` (`iat`) | integer seconds since the Unix epoch |
| `canon2.dumps(statement)` | `COSE_Sign1` `payload` | the `canon/2` bytes of the in-toto Statement v1 (or of the `prismpath.core-run-root/2` statement) |
| Ed25519 signature over `Sig_structure` | `COSE_Sign1` `signature` | 64-byte Ed25519 signature over the CBOR `Sig_structure` (`["Signature1", body_protected, b"", payload]`) |

When registered with a SCITT transparency service, the service verifies the `COSE_Sign1` signature
under the issuer's Ed25519 key, appends the statement hash to its append-only Merkle tree, and
returns a SCITT Receipt (a `COSE_Sign1` signed by the service's key whose unprotected/protected
headers carry the RFC 9162 / COSE Merkle inclusion proof). Storing that receipt beside
`receipts.roots.jsonl` allows offline verification of both the run's internal decision tree and the
external transparency log inclusion proof.
