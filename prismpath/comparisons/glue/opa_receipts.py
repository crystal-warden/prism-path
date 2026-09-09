# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""OPA decision log receipt sink and verification."""
from __future__ import annotations

import base64
import gzip
import hashlib
import http.server
import json
import sys
import threading
from typing import Any, Dict, List, Optional, Union

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


class LogHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        if self.headers.get("Content-Encoding") == "gzip":
            body = gzip.decompress(body)
        records = json.loads(body.decode("utf-8"))
        if isinstance(records, list):
            self.server.sink.records.extend(records)
        elif isinstance(records, dict):
            self.server.sink.records.append(records)
        self.send_response(200)
        self.end_headers()

    def log_message(self, format: str, *args: Any) -> None:
        pass


class Sink:
    def __init__(self, private_key_pem: Optional[Union[bytes, str]] = None, host: str = "127.0.0.1", port: int = 0) -> None:
        self.records: List[Dict[str, Any]] = []
        self.private_key_pem = private_key_pem
        self.server = http.server.ThreadingHTTPServer((host, port), LogHandler)
        self.server.sink = self
        self.thread: Optional[threading.Thread] = None

    def start(self) -> int:
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self.server.server_address[1]

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        if self.thread:
            self.thread.join()

    def receipt_for(self, decision_id: str, private_key_pem: Optional[Union[bytes, str]] = None) -> Dict[str, Any]:
        pk = private_key_pem or self.private_key_pem
        if not pk:
            raise ValueError("private key required")
        return receipt_for(self.records, decision_id, pk)


def sign_root(root_bytes: bytes, private_key_pem: Union[bytes, str]) -> bytes:
    if isinstance(private_key_pem, str):
        private_key_pem = private_key_pem.encode("utf-8")
    key = serialization.load_pem_private_key(private_key_pem, password=None)
    return key.sign(root_bytes, padding.PKCS1v15(), hashes.SHA256())


def verify_root(root_bytes: bytes, signature: bytes, public_key_pem: Union[bytes, str]) -> bool:
    if isinstance(public_key_pem, str):
        public_key_pem = public_key_pem.encode("utf-8")
    try:
        key = serialization.load_pem_public_key(public_key_pem)
        key.verify(signature, root_bytes, padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False


def _merkle_tree(records: List[Dict[str, Any]], idx: int):
    leaves = [hashlib.sha256(json.dumps(r, sort_keys=True, separators=(",", ":")).encode("utf-8")).digest() for r in records]
    current = list(leaves)
    cur_idx = idx
    path = []
    while len(current) > 1:
        if len(current) % 2 == 1:
            current.append(current[-1])
        next_lvl = []
        for i in range(0, len(current), 2):
            next_lvl.append(hashlib.sha256(current[i] + current[i + 1]).digest())
        if cur_idx % 2 == 0:
            sibling = current[cur_idx + 1]
            side = "R"
        else:
            sibling = current[cur_idx - 1]
            side = "L"
        path.append({"hash": sibling.hex(), "side": side})
        cur_idx //= 2
        current = next_lvl
    return leaves[idx], path, current[0]


def receipt_for(records: List[Dict[str, Any]], decision_id: str, private_key_pem: Union[bytes, str]) -> Dict[str, Any]:
    pk = private_key_pem
    idx = next((i for i, r in enumerate(records) if r.get("decision_id") == decision_id), -1)
    if idx < 0:
        raise KeyError(f"decision_id {decision_id} not found")
    leaf, path, root_bytes = _merkle_tree(records, idx)
    sig_bytes = sign_root(root_bytes, pk)
    return {
        "record": records[idx],
        "leaf": leaf.hex(),
        "path": path,
        "root": root_bytes.hex(),
        "signature": base64.b64encode(sig_bytes).decode("ascii"),
        "signing_alg": "RS256",
    }


def verify_receipt(receipt: Dict[str, Any], public_key_pem: Union[bytes, str]) -> bool:
    try:
        if receipt.get("signing_alg") != "RS256":
            return False
        rec = receipt["record"]
        leaf_bytes = hashlib.sha256(json.dumps(rec, sort_keys=True, separators=(",", ":")).encode("utf-8")).digest()
        if leaf_bytes.hex() != receipt.get("leaf"):
            return False
        curr = leaf_bytes
        for step in receipt.get("path", []):
            h = bytes.fromhex(step["hash"])
            side = step["side"]
            if side == "R":
                curr = hashlib.sha256(curr + h).digest()
            elif side == "L":
                curr = hashlib.sha256(h + curr).digest()
            else:
                return False
        if curr.hex() != receipt.get("root"):
            return False
        sig_bytes = base64.b64decode(receipt["signature"])
        return verify_root(curr, sig_bytes, public_key_pem)
    except Exception:
        return False


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    sink = Sink(port=port)
    print(f"Sink listening on port {sink.start()}", flush=True)
    try:
        while True:
            threading.Event().wait(1)
    except KeyboardInterrupt:
        sink.stop()
