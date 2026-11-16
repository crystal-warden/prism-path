# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The population's validating admission webhook: every write of a `GovernedAgent` decided by the signed
admission image, receipted before the API server hears the answer.

    python -m integrations.governed_population.k8s.webhook --data DIR --identity DIR --authority FILE \
        --attestations FILE --config FILE [--evaluations DIR --evaluators DIR] \
        [--tls-cert FILE --tls-key FILE] [--port 8443] [--registry api|file:PATH]

For each AdmissionReview the webhook lists the population's members from the API server (read only),
classifies the request into an admission reading (`classify.py`), decides it with the reference kernel over
the shipped image exactly as the simulation's controller does (`governed_harness.policy.Policy`), writes the
`prismpath.core-receipt/1` line into its current core run, and only then answers: allowed on an allow, and
otherwise denied with the registered cause in the message. Receipts go into runs in the core run layout
(`governed_population.evidence.DecisionRun`): the operator signs the admission image once, and the webhook
seals each run with its own instance key and a root statement over the RFC 6962 root of every receipt, so
`prismpath evidence verify RUN --pin-authority --pin-instance` checks it unchanged.

It fails closed. A body that is no AdmissionReview gets an HTTP error, which the API server turns into a
refusal under `failurePolicy: Fail`. A request the classifier cannot read is decided as `request=unknown`,
which the image refuses. A registry that cannot be listed, a kernel that raises, an uncoded refusal, a
request that waited past the deadline: each is a deny with no allow receipt. The one exception is a stop
by the operator, which reaches this webhook only through the second, `failurePolicy: Ignore` entry: it is
decided and receipted when it can be, and answered allowed whatever happens, since a stop only removes and
nothing may delay it (DESIGN.md, H1); a decision that did not allow it is recorded as a fault.

Run layout under --data: `runs/NNNNNN/core/` (the core run the verifier reads), and beside it
`readings.hex` (each reading's bytes, written before its receipt, so a run cut off by a crash is sealed on
the next start) and `decisions.jsonl` (the AdmissionReview each receipt answered: uid, operation, name,
user, request, cause; unsigned claims the subject of each reading binds). SIGUSR1 seals the current run and
opens the next; SIGTERM seals and exits.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import ssl
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from integrations.governed_harness.policy import Policy as HarnessPolicy
from prismpath.kernel import canon2
from prismpath.ledgers import core_evidence, root_statement

from .. import canary as canary_mod
from .. import evidence
from .. import identity as ident
from .. import policy as pp
from .classify import API_VERSION, GROUP, NAME, PLURAL, Config, Snapshot, State, classify, resolve_issuer, subject_of

ADMISSION = "admission.k8s.io/v1"
MAX_BODY = 1 << 20
PENDING_TTL = 30.0
CASE = "admission"


# ----------------------------------------------------------------------------- the registry
class ApiRegistry:
    """The population's GovernedAgent objects, listed from the API server with the pod's ServiceAccount.
    Any failure raises, and a request whose registry cannot be read is denied."""

    SA = Path("/var/run/secrets/kubernetes.io/serviceaccount")

    def __init__(self, namespace: str, timeout: float = 2.0):
        host, port = os.environ["KUBERNETES_SERVICE_HOST"], os.environ.get("KUBERNETES_SERVICE_PORT", "443")
        host = f"[{host}]" if ":" in host else host
        self.url = f"https://{host}:{port}/apis/{GROUP}/{API_VERSION}/namespaces/{namespace}/{PLURAL}"
        self.timeout = timeout
        self.context = ssl.create_default_context(cafile=str(self.SA / "ca.crt"))
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                                  urllib.request.HTTPSHandler(context=self.context))

    def items(self) -> List[Dict[str, Any]]:
        token = (self.SA / "token").read_text().strip()
        request = urllib.request.Request(self.url, headers={"Authorization": f"Bearer {token}",
                                                            "Accept": "application/json"})
        with self.opener.open(request, timeout=self.timeout) as response:
            doc = json.loads(response.read(16 << 20))
        if not isinstance(doc, dict) or doc.get("kind") != "GovernedAgentList" or not isinstance(doc.get("items"), list):
            raise ValueError("the API server's answer is not a GovernedAgentList")
        return doc["items"]


class FileRegistry:
    """The registry from a JSON file (a list of GovernedAgent objects): for running outside a cluster."""

    def __init__(self, path: Path):
        self.path = Path(path)

    def items(self) -> List[Dict[str, Any]]:
        doc = json.loads(self.path.read_text())
        items = doc.get("items") if isinstance(doc, dict) else doc
        if not isinstance(items, list):
            raise ValueError("the registry file is not a list of GovernedAgent objects")
        return items


# ----------------------------------------------------------------------------- evaluations
class EvaluationStore:
    """Evaluation runs by name: `passed` only for a run that verifies with the authority key and a pinned
    evaluator key, holds one allow of the evaluation image, and binds this exact version
    (`canary.check_evaluation`, the simulation's own check)."""

    def __init__(self, root: Optional[Path], authority_pub: Path, evaluator_pubs: List[Path], image: bytes):
        self.root, self.authority_pub, self.image = (Path(root) if root else None), Path(authority_pub), image
        self.evaluators = {ident.sha256_hex(Path(p).read_bytes()): Path(p) for p in evaluator_pubs}

    def status(self, version, ref: Any) -> str:
        if self.root is None or not isinstance(ref, str) or not NAME.match(ref):
            return "none"
        run = self.root / ref
        if not (run / "run.json").is_file():
            return "none"
        try:
            manifest = canon2.loads((run / "run.json").read_bytes().rstrip(b"\n"))
            pub = self.evaluators.get(manifest.get("instance_key_id")) if isinstance(manifest, dict) else None
        except Exception:  # noqa: BLE001 - a run that does not read is no passed evaluation
            return "failed"
        if pub is None:
            return "failed"
        why = canary_mod.check_evaluation(run, version.sha256, self.authority_pub, pub, self.image)
        return "passed" if why is None else "failed"


# ----------------------------------------------------------------------------- runs
class DurableRun(evidence.DecisionRun):
    """A decision run whose readings are on disk before their receipts, so a run cut off by a crash can be
    sealed later (`reseal`) with exactly the receipts the API server was answered from."""

    def __init__(self, base: Path, image: bytes, attestation: str, identity: ident.InstanceIdentity,
                 authority_pub: bytes):
        base = Path(base)
        base.mkdir(parents=True, exist_ok=False)
        super().__init__(base / "core", CASE, image, attestation, identity, authority_pub)
        self.base = base
        self._hex = open(base / "readings.hex", "ab")
        self._log = open(base / "decisions.jsonl", "ab")

    def record(self, reading: bytes, verdict: Dict[str, Any]) -> int:
        self._hex.write(reading.hex().encode() + b"\n")
        self._hex.flush()
        os.fsync(self._hex.fileno())
        idx = super().record(reading, verdict)
        os.fsync(self.receipts.fileno())
        return idx

    def log(self, doc: Dict[str, Any]) -> None:
        self._log.write(json.dumps(doc, sort_keys=True).encode() + b"\n")
        self._log.flush()

    def close(self, time_us: Optional[int] = None):
        self._hex.close()
        self._log.close()
        if not self.readings:
            self.receipts.close()
            self.sealed = True
            return None
        return super().close(time_us)


def _complete_lines(path: Path) -> List[bytes]:
    """The file's complete lines; a partial last line (a crash mid write) is cut off the file."""
    if not path.exists():
        return []
    data = path.read_bytes()
    keep = data[:data.rfind(b"\n") + 1] if b"\n" in data else b""
    if keep != data:
        path.write_bytes(keep)
    return [line for line in keep.split(b"\n") if line]


def reseal(base: Path, image: bytes, attestation: str, identity: ident.InstanceIdentity, authority_pub: bytes) -> str:
    """Seal a run a crash left open; 'sealed', 'resealed' or 'empty' (removed)."""
    core = Path(base) / "core"
    if (core / "receipts.roots.jsonl").exists():
        return "sealed"
    receipts = _complete_lines(core / "receipts.jsonl")
    readings = [bytes.fromhex(line.decode()) for line in _complete_lines(Path(base) / "readings.hex")]
    if not receipts:
        shutil.rmtree(base)
        return "empty"
    if len(readings) < len(receipts):
        raise RuntimeError(f"{base}: fewer readings than receipts; the run cannot be sealed")
    run = evidence.DecisionRun.__new__(evidence.DecisionRun)
    run.run, run.case_id, run.image, run.attestation_sig = core, CASE, image, attestation
    run.identity, run.authority_pub, run.decider = identity, authority_pub, "python"
    run.readings = readings[:len(receipts)]
    run.receipts = open(core / "receipts.jsonl", "ab")
    run.sealed = False
    run._lock = threading.Lock()
    run.close()
    return "resealed"


# ----------------------------------------------------------------------------- the decider
class Decider:
    def __init__(self, data: Path, identity: Path, authority: Path, attestations: Dict[str, str], config: Config,
                 registry, evaluations: Optional[EvaluationStore] = None, rotate_at: int = 10000,
                 deadline: float = 4.0, clock: Callable[[], float] = time.monotonic, out=None):
        self.data, self.config, self.registry, self.evaluations = Path(data), config, registry, evaluations
        self.rotate_at, self.deadline, self.clock = rotate_at, deadline, clock
        self.out = out if out is not None else sys.stdout
        self.policy = pp.admission()
        self.authority_pub = Path(authority).read_bytes()
        _Priv, Pub, _ser, _Invalid = root_statement._ed25519()
        authority_key = Pub.from_public_bytes(self.authority_pub)
        harness_image = HarnessPolicy.load().image
        for name, image in (("admission", self.policy.image), ("evaluation", pp.evaluation().image),
                            ("harness", harness_image)):
            # never decide under an image the operator did not sign
            authority_key.verify(bytes.fromhex(attestations[name]), core_evidence.IMAGE_DOMAIN + image)
        if ident.sha256_hex(harness_image) != config.harness_sha256:
            raise ValueError("the configured harness image is not the shipped one")
        self.attestation = attestations["admission"]
        self.identity = ident.InstanceIdentity(Path(identity))
        root_statement.check_separation(self.identity.key, [ident.sha256_hex(self.authority_pub)])
        self.state = State()
        self.pending_until: Dict[str, float] = {}
        self.faults: List[str] = []
        self.lock = threading.RLock()
        runs = self.data / "runs"
        runs.mkdir(parents=True, exist_ok=True)
        for base in sorted(p for p in runs.iterdir() if p.is_dir()):
            reseal(base, self.policy.image, self.attestation, self.identity, self.authority_pub)
        self._rebuild(runs)
        self.run = self._open()
        self.ready = True

    # -- runs
    def _open(self) -> DurableRun:
        runs = self.data / "runs"
        numbers = [int(p.name) for p in runs.iterdir() if p.is_dir() and p.name.isdigit()]
        return DurableRun(runs / f"{max(numbers, default=0) + 1:06d}", self.policy.image, self.attestation,
                          self.identity, self.authority_pub)

    def _rebuild(self, runs: Path) -> None:
        """Stops and lineage refusals from every earlier decision this webhook made."""
        for base in sorted(p for p in runs.iterdir() if p.is_dir()):
            for line in _complete_lines(base / "decisions.jsonl"):
                doc = json.loads(line)
                if doc.get("allowed") and doc.get("tombstones"):
                    self.state.tombstones.update(doc["tombstones"])
                if not doc.get("allowed_by_image") and doc.get("line"):
                    self.state.line_refusals[doc["line"]] = self.state.line_refusals.get(doc["line"], 0) + 1

    def rotate(self) -> Optional[Dict[str, Any]]:
        """Seal the current run and open the next; the sealed run's manifest (None when it was empty)."""
        with self.lock:
            sealed = self.run.base
            manifest = self.run.close()
            if manifest is None:
                shutil.rmtree(sealed)
            self.run = self._open()
            return manifest

    def close(self) -> Optional[Dict[str, Any]]:
        with self.lock:
            self.ready = False
            manifest = self.run.close()
            if manifest is None:
                shutil.rmtree(self.run.base)
            return manifest

    # -- one review
    def _answer(self, uid: str, allowed: bool, message: str, annotations: Dict[str, str]) -> Dict[str, Any]:
        response: Dict[str, Any] = {"uid": uid, "allowed": allowed}
        if not allowed:
            response["status"] = {"code": 403, "reason": "Forbidden", "message": message}
        if annotations:
            response["auditAnnotations"] = annotations
        return {"apiVersion": ADMISSION, "kind": "AdmissionReview", "response": response}

    def _fault(self, text: str) -> None:
        self.faults.append(text)
        print(json.dumps({"fault": text}), file=self.out, flush=True)

    def review(self, body: Any) -> Tuple[int, Dict[str, Any]]:
        """(HTTP status, body) for one AdmissionReview."""
        started = self.clock()
        if not isinstance(body, dict) or body.get("apiVersion") != ADMISSION or body.get("kind") != "AdmissionReview" \
                or not isinstance(body.get("request"), dict) or not isinstance(body["request"].get("uid"), str):
            self._fault("a body that is no admission.k8s.io/v1 AdmissionReview")
            return 400, {"error": "not an admission.k8s.io/v1 AdmissionReview"}
        req = body["request"]
        uid = req["uid"]
        try:
            operator_stop = req.get("operation") == "DELETE" and \
                resolve_issuer(req.get("userInfo"), self.config)[0] == "operator"
        except Exception:  # noqa: BLE001
            operator_stop = False

        def no_decision(why: str) -> Tuple[int, Dict[str, Any]]:
            self._fault(f"{uid}: no decision ({why})" + ("; an operator stop, allowed" if operator_stop else ""))
            return 200, self._answer(uid, operator_stop, f"population: no decision ({why}); denied", {})

        if not self.lock.acquire(timeout=self.deadline):
            return no_decision("timed out waiting for the decider")
        try:
            try:
                snap = Snapshot(self.registry.items())
            except Exception as error:  # noqa: BLE001 - no registry, no facts, no allow
                return no_decision(f"the registry could not be read: {type(error).__name__}")
            now = self.clock()
            for name in list(self.state.pending):
                if name in snap.members or self.pending_until.get(name, 0) < now:
                    self.state.pending.pop(name, None)
                    self.pending_until.pop(name, None)
            try:
                got = classify(req, snap, self.state, self.config,
                               self.evaluations.status if self.evaluations else None)
            except Exception as error:  # noqa: BLE001 - a request that cannot be classified is no request
                got = classify({"uid": uid, "userInfo": {}}, Snapshot([]), State(), self.config)
                got.note = f"classification failed: {type(error).__name__}"
                got.reading["subject"] = subject_of(req)
            if self.clock() - started > self.deadline:
                return no_decision("past the deadline")
            try:
                raw = self.policy.reading_bytes(got.reading)
                decision = self.policy.decide(raw)
                if decision.cause_code is None and decision.kind != "allow":
                    raise RuntimeError(f"an uncoded refusal: {decision.verdict}")
            except Exception as error:  # noqa: BLE001 - no decision, nothing allowed
                return no_decision(f"{type(error).__name__}: {error}")
            by_image = decision.kind == "allow"
            allowed = by_image or got.operator_stop or operator_stop
            if req.get("dryRun"):
                return 200, self._answer(uid, allowed, self._message(got, decision, None), {})
            try:
                idx = self.run.record(raw, decision.verdict)
            except Exception as error:  # noqa: BLE001 - no receipt, no allow
                return no_decision(f"the receipt could not be written: {type(error).__name__}")
            run_name = self.run.base.name
            if (got.operator_stop or operator_stop) and not by_image:
                self._fault(f"{uid}: the image did not allow an operator stop ({decision.cause}); allowed anyway")
            effects: Dict[str, Any] = {}
            if allowed:
                if "pending" in got.on_allow:
                    name, line = got.on_allow["pending"]
                    self.state.pending[name] = line
                    self.pending_until[name] = now + PENDING_TTL
                if "tombstones" in got.on_allow:
                    self.state.tombstones.update(got.on_allow["tombstones"])
                    for name in got.on_allow.get("unpend", []):
                        self.state.pending.pop(name, None)
                    effects["tombstones"] = got.on_allow["tombstones"]
            if not by_image and got.line:
                self.state.line_refusals[got.line] = self.state.line_refusals.get(got.line, 0) + 1
            doc = {"run": run_name, "receipt": idx, "uid": uid, "operation": req.get("operation"),
                   "name": got.name, "user": got.user, "issuer": got.issuer, "request": got.request,
                   "decision": decision.kind, "cause": decision.cause, "cause_code": decision.cause_code,
                   "allowed": allowed, "allowed_by_image": by_image, "line": got.line,
                   "subject": got.reading["subject"], "note": got.note, **effects}
            self.run.log(doc)
            print(json.dumps({k: doc[k] for k in ("run", "receipt", "operation", "name", "issuer", "request",
                                                    "decision", "cause", "allowed")}), file=self.out, flush=True)
            answer = self._answer(uid, allowed, self._message(got, decision, (run_name, idx)),
                                  {"receipt": f"{run_name}/{idx}", "request": got.request,
                                   "decision": decision.kind if decision.cause is None
                                   else f"{decision.kind} {decision.cause_code} {decision.cause}"})
            if len(self.run.readings) >= self.rotate_at:
                self.rotate()
            return 200, answer
        finally:
            self.lock.release()

    @staticmethod
    def _message(got, decision, receipt) -> str:
        where = f"receipt {receipt[0]}/{receipt[1]}" if receipt else "dry run, not receipted"
        if decision.kind == "allow":
            return f"population: allow ({got.request}; {where})"
        note = f"; {got.note}" if got.note else ""
        return f"population: {decision.kind} {decision.cause_code} {decision.cause} ({got.request}{note}; {where})"


# ----------------------------------------------------------------------------- the server
class Handler(BaseHTTPRequestHandler):
    server_version = "prismpath-population"
    sys_version = ""

    def _send(self, status: int, doc: Dict[str, Any]) -> None:
        data = json.dumps(doc).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):  # noqa: N802
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            length = -1
        if length < 0 or length > MAX_BODY:     # not read: the connection is closed after the answer
            self.close_connection = True
            return self._send(413 if length > MAX_BODY else 411, {"error": "a body of a known, bounded length"})
        data = self.rfile.read(length)
        if self.path.split("?", 1)[0] != "/validate":
            return self._send(404, {"error": "not found"})
        try:
            body = json.loads(data)
        except (ValueError, UnicodeDecodeError):
            body = None
        try:
            status, doc = self.server.decider.review(body)
        except Exception as error:  # noqa: BLE001 - an error is a refusal: the API server fails closed on a 500
            status, doc = 500, {"error": type(error).__name__}
        self._send(status, doc)

    def do_GET(self):  # noqa: N802
        if self.path == "/healthz" and getattr(self.server.decider, "ready", False):
            return self._send(200, {"ok": True})
        self._send(503 if self.path == "/healthz" else 404, {"ok": False})

    def log_message(self, fmt, *args):  # the decisions are logged by the decider
        pass


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, decider: Decider, context: Optional[ssl.SSLContext]):
        self.decider, self.context = decider, context
        super().__init__(address, Handler)

    def finish_request(self, request, client_address):
        request.settimeout(5.0)
        if self.context is not None:
            request = self.context.wrap_socket(request, server_side=True)
        try:
            self.RequestHandlerClass(request, client_address, self)
        finally:
            if self.context is not None:
                request.close()

    def handle_error(self, request, client_address):
        print(json.dumps({"connection_error": str(sys.exc_info()[1])[:200]}), file=sys.stderr, flush=True)


def tls_context(cert: Path, key: Path) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(cert), str(key))
    return context


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--data", required=True, type=Path)
    parser.add_argument("--identity", required=True, type=Path, help="directory holding instance.key")
    parser.add_argument("--authority", required=True, type=Path, help="the operator's authority.pub")
    parser.add_argument("--attestations", required=True, type=Path, help="attestations.json from operator_tool init")
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--evaluations", type=Path)
    parser.add_argument("--evaluators", type=Path, help="directory of pinned evaluator *.pub keys")
    parser.add_argument("--tls-cert", type=Path)
    parser.add_argument("--tls-key", type=Path)
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--registry", default="api", help="api, or file:PATH")
    parser.add_argument("--rotate-at", type=int, default=10000)
    args = parser.parse_args(argv)

    config = Config.from_doc(json.loads(args.config.read_text()), ident.sha256_hex(HarnessPolicy.load().image))
    registry = ApiRegistry(config.namespace) if args.registry == "api" else FileRegistry(Path(args.registry[5:]))
    evaluators = sorted(args.evaluators.glob("*.pub")) if args.evaluators else []
    store = EvaluationStore(args.evaluations, args.authority, evaluators, pp.evaluation().image)
    signals = {signal.SIGTERM, signal.SIGINT, signal.SIGUSR1}
    for sig in signals:     # as a container's PID 1, a signal with no handler installed is never delivered
        signal.signal(sig, lambda *_: None)
    signal.pthread_sigmask(signal.SIG_BLOCK, signals)          # every thread started below inherits the mask
    decider = Decider(args.data, args.identity, args.authority, json.loads(args.attestations.read_text()), config,
                      registry, store, rotate_at=args.rotate_at)
    context = tls_context(args.tls_cert, args.tls_key) if args.tls_cert else None
    server = Server((args.bind, args.port), decider, context)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(json.dumps({"listening": args.port, "tls": context is not None, "run": decider.run.base.name,
                      "instance_key_id": decider.identity.key_id}), flush=True)
    while True:
        got = signal.sigwait(signals)
        if got == signal.SIGUSR1:
            manifest = decider.rotate()
            print(json.dumps({"sealed": manifest is not None, "next_run": decider.run.base.name}), flush=True)
            continue
        server.shutdown()
        manifest = decider.close()
        print(json.dumps({"sealed": manifest is not None, "exit": True}), flush=True)
        return 0


if __name__ == "__main__":
    sys.exit(main())
