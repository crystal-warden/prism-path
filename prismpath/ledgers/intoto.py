# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Export a sealed PrismPath core run as in-toto Statement v1 attestations in DSSE v1.0 envelopes,
and verify them back against the run directory and pinned public keys (docs/design/spec-intoto-receipts.md).

An exported envelope has `payloadType` `application/vnd.in-toto+json`, a base64-encoded canon/2
`https://in-toto.io/Statement/v1` payload whose `subject` names the run's receipts files by SHA-256
digest and whose `predicate` (`https://prismpath.dev/attestations/core-run/v1`) carries the sealed root
statement fields alongside the manifest's image and key digests, and an Ed25519 signature made by the
run's instance key over the DSSE Pre-Authentication Encoding (PAE).
"""
from __future__ import annotations

import base64
import binascii
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple, Union

from prismpath.kernel import canon2
from prismpath.ledgers import core_evidence, root_statement

PAYLOAD_TYPE = "application/vnd.in-toto+json"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://prismpath.dev/attestations/core-run/v1"
SUBJECT_FILES = ("receipts.jsonl", "receipts.roots.jsonl")


class Bad(core_evidence.Bad, ValueError):
    """An envelope or run that fails in-toto / DSSE or core run verification."""


def pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE v1.0 Pre-Authentication Encoding:
    PAE(type, body) = "DSSEv1" + SP + LEN(type) + SP + type + SP + LEN(body) + SP + body
    where LEN(s) is the byte length of s in ASCII decimal."""
    if not isinstance(payload_type, str):
        raise TypeError("payload_type must be a string")
    if not isinstance(payload, (bytes, bytearray, memoryview)):
        raise TypeError("payload must be bytes")
    type_bytes = payload_type.encode("utf-8")
    body_bytes = bytes(payload)
    return (b"DSSEv1 " + str(len(type_bytes)).encode("ascii") + b" " + type_bytes
            + b" " + str(len(body_bytes)).encode("ascii") + b" " + body_bytes)


PAE = pae


def _b64_encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64_decode(text: Any, what: str) -> bytes:
    if not isinstance(text, str) or not text:
        raise Bad(f"the DSSE {what} is not a non-empty base64 string")
    try:
        raw = base64.b64decode(text.encode("ascii"), validate=True)
    except (binascii.Error, ValueError, UnicodeEncodeError):
        raise Bad(f"the DSSE {what} is not valid base64") from None
    if _b64_encode(raw) != text:
        raise Bad(f"the DSSE {what} is not in canonical base64 spelling")
    return raw


def _sealed_runs(run_dir: Path) -> List[Path]:
    run_dir = Path(run_dir)
    if not run_dir.is_dir():
        raise Bad(f"{run_dir} is not a directory")
    if (run_dir / "run.json").exists() or (run_dir / "receipts.roots.jsonl").exists():
        return [run_dir]
    subs = sorted(p for p in run_dir.iterdir()
                  if p.is_dir() and ((p / "run.json").exists() or (p / "receipts.roots.jsonl").exists()))
    if not subs:
        raise Bad(f"{run_dir} holds no sealed core run")
    return subs


def _candidate_key_files(run: Path) -> Iterable[Path]:
    seen = set()
    direct = [
        run / "instance.key",
        run / "keys" / "instance.key",
        run.parent / "instance.key",
        run.parent / "keys" / "instance.key",
    ]
    if run.parent.parent != run.parent:
        direct.append(run.parent.parent / "keys" / "instance.key")
        direct.append(run.parent.parent / "instance.key")
    for path in direct:
        if path not in seen and path.is_file():
            seen.add(path)
            yield path
    for base in (run.parent, run.parent.parent):
        if not base.is_dir():
            continue
        for pattern in ("*/instance.key", "*/*.key", "*/*/instance.key"):
            for path in sorted(base.glob(pattern)):
                if path not in seen and path.is_file():
                    seen.add(path)
                    yield path


def _load_key_arg(arg: Any) -> root_statement.InstanceKey:
    if isinstance(arg, root_statement.InstanceKey):
        return arg
    path = Path(arg)
    if path.is_dir():
        path = path / "instance.key"
    if not path.is_file():
        raise Bad(f"instance key {path} does not exist")
    try:
        return root_statement.InstanceKey.load(str(path))
    except Exception as exc:
        raise Bad(f"instance key {path} could not be loaded: {exc}") from None


def _find_instance_key(run: Path, keys: Any = None, instance_key: Any = None) -> root_statement.InstanceKey:
    pub_path = run / "instance.pub"
    if not pub_path.is_file():
        raise Bad("the run has no instance.pub")
    want_pub = pub_path.read_bytes()
    want_id = core_evidence.sha256_hex(want_pub)

    explicit = instance_key if instance_key is not None else keys
    if explicit is not None:
        loaded = _load_key_arg(explicit)
        if loaded.public_raw != want_pub or loaded.key_id != want_id:
            raise Bad("the given instance key does not match the run's instance.pub")
        return loaded

    env_key = root_statement.key_from_env()
    if env_key is not None and env_key.public_raw == want_pub:
        return env_key

    for candidate in _candidate_key_files(run):
        try:
            loaded = root_statement.InstanceKey.load(str(candidate))
        except Exception:
            continue
        if loaded.public_raw == want_pub:
            return loaded

    raise Bad(f"cannot find the instance private key for {run}; pass keys=... or set {root_statement.INSTANCE_KEY_ENV}")


def _build_predicate(run: Path) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    try:
        core_evidence._check(run, None, None)
    except core_evidence.Bad as exc:
        raise Bad(str(exc)) from None
    except (KeyError, TypeError, ValueError, AttributeError, IndexError) as exc:
        raise Bad(f"the run does not read as a core run ({type(exc).__name__}: {exc})") from None

    manifest = canon2.loads((run / "run.json").read_bytes().rstrip(b"\n"))
    statement = canon2.loads((run / "receipts.roots.jsonl").read_bytes().rstrip(b"\n"))
    image_rows = [canon2.loads(line) for line in core_evidence._lines(run / "images.jsonl")]
    unique_images = {row["image_sha256"] for row in image_rows}
    image_sha256 = next(iter(unique_images)) if len(unique_images) == 1 else manifest["images_sha256"]

    predicate: Dict[str, Any] = {
        **statement,
        "authority_key_id": manifest["authority_key_id"],
        "instance_key_id": manifest["instance_key_id"],
        "images_sha256": manifest["images_sha256"],
        "image_sha256": image_sha256,
    }
    return predicate, statement


def _export_one(run: Path, keys: Any = None, instance_key: Any = None) -> Dict[str, Any]:
    predicate, _root_stmt = _build_predicate(run)
    signer = _find_instance_key(run, keys=keys, instance_key=instance_key)
    subject = [
        {"name": name, "digest": {"sha256": core_evidence.sha256_hex((run / name).read_bytes())}}
        for name in SUBJECT_FILES
    ]
    statement = {
        "_type": STATEMENT_TYPE,
        "subject": subject,
        "predicateType": PREDICATE_TYPE,
        "predicate": predicate,
    }
    return sign_statement(statement, signer)


def sign_statement(statement: Dict[str, Any], signer: root_statement.InstanceKey) -> Dict[str, Any]:
    """A DSSE envelope of the in-toto Statement v1 `statement`: its canon/2 bytes as the payload, signed by the
    instance key `signer` over the PAE, with the key id as the hint."""
    if not isinstance(statement, dict) or statement.get("_type") != STATEMENT_TYPE:
        raise Bad(f"a statement to sign has _type {STATEMENT_TYPE}")
    payload_bytes = canon2.dumps(statement)
    sig_bytes = signer.sign(pae(PAYLOAD_TYPE, payload_bytes))
    return {
        "payloadType": PAYLOAD_TYPE,
        "payload": _b64_encode(payload_bytes),
        "signatures": [
            {
                "keyid": signer.key_id,
                "sig": _b64_encode(sig_bytes),
            }
        ],
    }


def open_statement(envelope: Any, public_raw: bytes, predicate_type: str) -> Dict[str, Any]:
    """The Statement v1 a DSSE envelope carries, once the envelope has its three members, a payload in canonical
    base64 and canonical canon/2, the Statement v1 fields with `predicate_type`, and a signature that verifies
    under the 32 raw public bytes `public_raw` over the PAE. `Bad` otherwise. Key ids are a hint only: every
    entry whose signature verifies counts, and one that does not is skipped."""
    if not isinstance(envelope, dict) or set(envelope) != {"payloadType", "payload", "signatures"}:
        raise Bad("the DSSE envelope must be an object with payloadType, payload and signatures")
    if envelope["payloadType"] != PAYLOAD_TYPE:
        raise Bad(f"the DSSE payloadType is not {PAYLOAD_TYPE}")
    payload_bytes = _b64_decode(envelope["payload"], "payload")
    sigs = envelope["signatures"]
    if not isinstance(sigs, list) or not sigs:
        raise Bad("the DSSE envelope carries no signatures")
    public = core_evidence._public_key(bytes(public_raw), "signer")
    _Priv, _Pub, _ser, InvalidSignature = root_statement._ed25519()
    message = pae(PAYLOAD_TYPE, payload_bytes)
    verified = False
    for entry in sigs:
        if not isinstance(entry, dict) or not isinstance(entry.get("sig"), str):
            continue
        try:
            public.verify(_b64_decode(entry["sig"], "signature"), message)
            verified = True
        except (Bad, InvalidSignature, ValueError):
            continue
    if not verified:
        raise Bad("no DSSE signature verifies under the key given")
    try:
        statement = canon2.loads(payload_bytes)
    except canon2.Canon2Error as exc:
        raise Bad(f"the in-toto statement payload is not a canon/2 document ({exc.rule})") from None
    if not isinstance(statement, dict) or canon2.dumps(statement) != payload_bytes:
        raise Bad("the in-toto statement payload is not in its canonical canon/2 spelling")
    if set(statement) != {"_type", "subject", "predicateType", "predicate"} or statement["_type"] != STATEMENT_TYPE:
        raise Bad("the in-toto statement does not have the Statement v1 fields")
    if statement["predicateType"] != predicate_type:
        raise Bad(f"the in-toto statement predicateType is not {predicate_type}")
    return statement


def export(run_dir: Union[Path, str], keys: Any = None, *, instance_key: Any = None) -> List[Dict[str, Any]]:
    """Export each sealed core run in `run_dir` as a DSSE envelope carrying an in-toto Statement v1."""
    runs = _sealed_runs(Path(run_dir))
    return [_export_one(run, keys=keys, instance_key=instance_key) for run in runs]


def _read_pub_bytes(value: Any, what: str) -> bytes:
    if hasattr(value, "public_raw"):
        raw = value.public_raw
    elif isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
    elif isinstance(value, (Path, str)):
        if isinstance(value, str) and core_evidence._hex_of(value, 32) and not Path(value).exists():
            raw = bytes.fromhex(value)
        else:
            path = Path(value)
            if not path.is_file():
                raise Bad(f"pinned {what} key {path} does not exist")
            raw = path.read_bytes()
    else:
        raise Bad(f"pinned {what} key is not a path or 32-byte Ed25519 public key")
    core_evidence._public_key(raw, what)
    return raw


def _resolve_pins(
    pinned_keys: Any,
    pin_authority: Any,
    pin_instance: Any,
) -> Tuple[Optional[bytes], Optional[bytes]]:
    auth_bytes = _read_pub_bytes(pin_authority, "authority") if pin_authority is not None else None
    inst_bytes = _read_pub_bytes(pin_instance, "instance") if pin_instance is not None else None
    if pinned_keys is None:
        return auth_bytes, inst_bytes

    if isinstance(pinned_keys, (Path, str)) and Path(pinned_keys).is_dir():
        base = Path(pinned_keys)
        return (
            _read_pub_bytes(base / "authority.pub", "authority"),
            _read_pub_bytes(base / "instance.pub", "instance"),
        )

    if isinstance(pinned_keys, dict):
        auth_val = next((pinned_keys[k] for k in ("authority", "pin_authority", "authority.pub", "authority_pub")
                         if k in pinned_keys), None)
        inst_val = next((pinned_keys[k] for k in ("instance", "pin_instance", "instance.pub", "instance_pub")
                         if k in pinned_keys), None)
        if auth_val is not None:
            auth_bytes = _read_pub_bytes(auth_val, "authority")
        if inst_val is not None:
            inst_bytes = _read_pub_bytes(inst_val, "instance")
        if auth_val is None and inst_val is None:
            if not pinned_keys:
                raise Bad("pinned_keys dictionary is empty")
            values = [_read_pub_bytes(v, "pinned") for v in pinned_keys.values()]
            if len(values) == 2:
                auth_bytes, inst_bytes = values[0], values[1]
            elif len(values) == 1:
                inst_bytes = values[0]
            else:
                raise Bad("pinned_keys dictionary must name authority and instance keys")
        return auth_bytes, inst_bytes

    if isinstance(pinned_keys, (list, tuple, set, frozenset)):
        items = list(pinned_keys)
        if not items:
            raise Bad("pinned_keys collection is empty")
        if len(items) == 2 and isinstance(pinned_keys, (list, tuple)):
            return (
                _read_pub_bytes(items[0], "authority"),
                _read_pub_bytes(items[1], "instance"),
            )
        if len(items) == 1:
            return auth_bytes, _read_pub_bytes(items[0], "instance")
        raise Bad("pinned_keys must provide (authority, instance) or a keys directory")

    return auth_bytes, _read_pub_bytes(pinned_keys, "instance")


def _verify_one(
    envelope: Any,
    run: Path,
    auth_pin: Optional[bytes],
    inst_pin: Optional[bytes],
    sample: Optional[int],
    seed: int,
    replay: Optional[Callable],
) -> Dict[str, Any]:
    if not isinstance(envelope, dict) or set(envelope) != {"payloadType", "payload", "signatures"}:
        raise Bad("the DSSE envelope must be an object with payloadType, payload and signatures")
    if envelope["payloadType"] != PAYLOAD_TYPE:
        raise Bad(f"the DSSE payloadType is not {PAYLOAD_TYPE}")
    payload_bytes = _b64_decode(envelope["payload"], "payload")

    sigs = envelope["signatures"]
    if not isinstance(sigs, list) or not sigs:
        raise Bad("the DSSE envelope carries no signatures")
    parsed_sigs = []
    for entry in sigs:
        if not isinstance(entry, dict) or set(entry) != {"keyid", "sig"}:
            raise Bad("each DSSE signature must have keyid and sig")
        if not core_evidence._hex_of(entry["keyid"], 32):
            raise Bad("the DSSE signature keyid is not a 32-byte lowercase hex SHA-256 digest")
        sig_raw = _b64_decode(entry["sig"], "signature")
        if len(sig_raw) != 64:
            raise Bad("the DSSE signature is not a 64-byte Ed25519 signature")
        parsed_sigs.append((entry["keyid"], sig_raw))

    for name in core_evidence.FILES:
        if not (run / name).exists():
            raise Bad(f"the run has no {name}")

    authority_raw = (run / "authority.pub").read_bytes()
    instance_raw = (run / "instance.pub").read_bytes()
    core_evidence._public_key(authority_raw, "authority")
    core_evidence._public_key(instance_raw, "instance")

    if auth_pin is not None and auth_pin != authority_raw:
        raise Bad("the run's authority key is not the pinned authority key")
    if inst_pin is not None and inst_pin != instance_raw:
        raise Bad("the run's instance key is not the pinned instance key")

    verify_raw = inst_pin if inst_pin is not None else instance_raw
    verify_key_id = core_evidence.sha256_hex(verify_raw)
    verify_pub = core_evidence._public_key(verify_raw, "instance")
    _Priv, _Pub, _ser, InvalidSignature = root_statement._ed25519()

    pae_bytes = pae(envelope["payloadType"], payload_bytes)
    matching = [sig_raw for keyid, sig_raw in parsed_sigs if keyid == verify_key_id]
    if not matching:
        raise Bad("the DSSE envelope is not signed by the run's instance key")
    for sig_raw in matching:
        try:
            verify_pub.verify(sig_raw, pae_bytes)
        except (InvalidSignature, ValueError):
            raise Bad("the DSSE PAE signature does not verify") from None

    try:
        statement = canon2.loads(payload_bytes)
    except canon2.Canon2Error as exc:
        raise Bad(f"the in-toto statement payload is not a canon/2 document ({exc.rule})") from None
    if not isinstance(statement, dict) or canon2.dumps(statement) != payload_bytes:
        raise Bad("the in-toto statement payload is not in its canonical canon/2 spelling")
    if set(statement) != {"_type", "subject", "predicateType", "predicate"}:
        raise Bad("the in-toto statement does not have the Statement v1 fields")
    if statement["_type"] != STATEMENT_TYPE:
        raise Bad(f"the in-toto statement _type is not {STATEMENT_TYPE}")
    if statement["predicateType"] != PREDICATE_TYPE:
        raise Bad(f"the in-toto statement predicateType is not {PREDICATE_TYPE}")

    subjects = statement["subject"]
    if not isinstance(subjects, list) or not subjects:
        raise Bad("the in-toto statement subject must be a non-empty list")
    seen_names = []
    for item in subjects:
        if not isinstance(item, dict) or set(item) != {"name", "digest"}:
            raise Bad("each in-toto subject must have name and digest")
        name = item["name"]
        digest = item["digest"]
        if not isinstance(name, str) or name not in core_evidence.FILES:
            raise Bad(f"the in-toto subject names an unexpected file: {name!r}")
        if not isinstance(digest, dict) or set(digest) != {"sha256"} or not core_evidence._hex_of(digest["sha256"], 32):
            raise Bad(f"the in-toto subject for {name} does not carry a valid sha256 digest")
        actual_sha256 = core_evidence.sha256_hex((run / name).read_bytes())
        if actual_sha256 != digest["sha256"]:
            raise Bad(f"the in-toto subject digest for {name} does not match the file")
        seen_names.append(name)
    if "receipts.jsonl" not in seen_names:
        raise Bad("the in-toto statement subject does not include receipts.jsonl")

    expected_predicate, expected_root = _build_predicate(run)
    if statement["predicate"] not in (expected_predicate, expected_root):
        raise Bad("the in-toto predicate does not equal the run's sealed root statement")

    try:
        summary = core_evidence.verify(
            run,
            sample=sample,
            seed=seed,
            pin_authority=(run / "authority.pub") if auth_pin is not None else None,
            pin_instance=(run / "instance.pub") if inst_pin is not None else None,
            replay=replay,
        )
    except core_evidence.Bad as exc:
        raise Bad(str(exc)) from None
    summary = dict(summary)
    summary["pinned"] = auth_pin is not None and inst_pin is not None
    summary["pinned_authority"] = auth_pin is not None
    summary["pinned_instance"] = inst_pin is not None
    return summary


def verify(
    envelopes: Union[List[Dict[str, Any]], Dict[str, Any]],
    run_dir: Union[Path, str],
    pinned_keys: Any = None,
    *,
    pin_authority: Any = None,
    pin_instance: Any = None,
    sample: Optional[int] = None,
    seed: int = 0,
    replay: Optional[Callable] = None,
) -> Dict[str, Any]:
    """Verify DSSE envelopes against `run_dir` and pinned public keys, then run `core_evidence.verify`."""
    if isinstance(envelopes, dict):
        env_list = [envelopes]
    elif isinstance(envelopes, (list, tuple)):
        env_list = list(envelopes)
    else:
        raise Bad("envelopes must be a list of DSSE envelopes")
    if not env_list:
        raise Bad("no DSSE envelopes given")

    runs = _sealed_runs(Path(run_dir))
    if len(env_list) != len(runs):
        raise Bad(f"{len(env_list)} envelope(s) for {len(runs)} sealed run(s)")

    auth_pin, inst_pin = _resolve_pins(pinned_keys, pin_authority, pin_instance)
    summaries = [
        _verify_one(env, run, auth_pin, inst_pin, sample=sample, seed=seed, replay=replay)
        for env, run in zip(env_list, runs)
    ]
    if len(summaries) == 1:
        return summaries[0]
    return {
        "runs": summaries,
        "receipts": sum(s["receipts"] for s in summaries),
        "replayed": sum(s["replayed"] for s in summaries),
        "agree": sum(s["agree"] for s in summaries),
        "disagree": sum(s["disagree"] for s in summaries),
        "pinned": all(s["pinned"] for s in summaries),
        "root_statement": "signed" if all(s["root_statement"] == "signed" for s in summaries) else "signed-unpinned",
    }


def import_envelopes(
    envelopes: Union[List[Dict[str, Any]], Dict[str, Any]],
    run_dir: Union[Path, str],
    pinned_keys: Any = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    """Restore `receipts.roots.jsonl` from the envelope predicate when absent in `run_dir`, then verify."""
    env_list = [envelopes] if isinstance(envelopes, dict) else list(envelopes)
    run_path = Path(run_dir)
    if len(env_list) == 1 and (run_path / "run.json").exists() and not (run_path / "receipts.roots.jsonl").exists():
        env = env_list[0]
        if not isinstance(env, dict):
            raise Bad("the DSSE envelope must be an object with payloadType, payload and signatures")
        payload_bytes = _b64_decode(env.get("payload"), "payload")
        try:
            stmt = canon2.loads(payload_bytes)
        except canon2.Canon2Error as exc:
            raise Bad(f"the in-toto statement payload is not a canon/2 document ({exc.rule})") from None
        pred = stmt.get("predicate", {}) if isinstance(stmt, dict) else {}
        if isinstance(pred, dict) and all(k in pred for k in core_evidence.ROOT_MEMBERS):
            root_doc = {k: pred[k] for k in core_evidence.ROOT_MEMBERS}
            target = run_path / "receipts.roots.jsonl"
            target.write_bytes(canon2.dumps(root_doc) + b"\n")
            try:
                return verify(env_list, run_dir, pinned_keys, **kwargs)
            except BaseException:
                target.unlink(missing_ok=True)
                raise
    return verify(env_list, run_dir, pinned_keys, **kwargs)
