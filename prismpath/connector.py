"""prismpath.connector — The Connector SDK for PrismPath.

A subclassable developer API for building domain connectors against all **six hexagonal
ports** (adapters/ADAPTER_GUIDE.md): **Ingestion**, **Retrieval**, **Adjudicator**,
**Action/Sink**, **Attestation**, and **Deferral** — plus the node-handler dispatch that turns
a connector instance into a flow agent, and `PayloadFlattener`, the schema-flattening
middleware (nested API responses -> the FLAT key/value surface `when` predicates and guided
decoding actually work over; see the compliance adapter's "keep it FLAT" lesson).

Registry glue: `get_workers()` returns the exact `{name: callable(node, instruction, state)}`
shape the plugin registry consumes, so a pip-installable plugin module is one line —
``WORKERS = MyConnector().get_workers()`` — and every node bound with `@worker(plugin.name)`
carries `_worker` provenance in the transcript.
"""
from __future__ import annotations

import hashlib
import json
import inspect
import os
import re
from abc import ABC
from typing import Any, Dict, List, Callable, Optional, Union, Tuple

# Decorator to register node handlers
def node(name: str):
    """Decorator to mark a connector method as a node handler."""
    def decorator(func):
        func._prismpath_node = name
        return func
    return decorator

class BaseConnector(ABC):
    """
    Base class for all PrismPath Connectors.
    Abstracts the six ports (Ingestion, Retrieval, Adjudicator, Action/Sink, Attestation,
    Deferral) and simplifies node handler registration and agent dispatching.
    """
    def __init__(self, name: str, version: str = "1.0.0", deferral_store=None):
        self.name = name
        self.version = version
        self._handlers: Dict[str, Callable] = {}
        self._deferrals = deferral_store         # lazy default — see the `deferrals` property

        # Automatically discover methods decorated with @node
        for attr_name in dir(self):
            attr = getattr(self, attr_name)
            if hasattr(attr, "_prismpath_node"):
                node_name = getattr(attr, "_prismpath_node")
                self._handlers[node_name] = attr

    def register_handler(self, node_name: str, handler: Callable):
        """Programmatic registration of a handler function for a node."""
        self._handlers[node_name] = handler

    def handler(self, node_name: str):
        """Decorator to register a handler function for a node."""
        def decorator(func: Callable):
            self.register_handler(node_name, func)
            return func
        return decorator

    def __call__(self, node: str, instruction: str, state: dict) -> Any:
        """Allows the connector instance to act directly as an agent callable."""
        return self.agent(node, instruction, state)

    def agent(self, node: str, instruction: str, state: dict) -> Any:
        """
        Dispatches node execution to the registered handlers.
        Wraps executions to inject worker metadata and ensure standard compliance.
        """
        handler = self._handlers.get(node)
        if handler is None:
            return self.fallback(node, instruction, state)
        
        sig = inspect.signature(handler)
        params = list(sig.parameters.keys())
        num_args = len(params)
        
        if num_args == 1:
            res = handler(state)
        elif num_args == 2:
            res = handler(instruction, state)
        else:
            res = handler(node, instruction, state)
            
        if isinstance(res, dict):
            res.setdefault("_worker", f"{self.name}.{node}")
        return res

    def fallback(self, node: str, instruction: str, state: dict) -> Any:
        """Fallback behavior when no handler is registered for the node."""
        raise NotImplementedError(
            f"Node '{node}' is not implemented in connector '{self.name}'"
        )

    def get_workers(self) -> Dict[str, Callable[[str, str, dict], Any]]:
        """
        Returns a dictionary of workers compatible with the prismpath plugins registry.
        """
        return {
            node_name: lambda n, inst, s, name=node_name: self.agent(name, inst, s)
            for node_name in self._handlers
        }

    # --- INGESTION PORT ---
    def ingest_payload(self, raw_data: Any) -> Dict[str, Any]:
        """Override to process, sanitize, or parse raw incoming data."""
        if isinstance(raw_data, dict):
            return raw_data
        return {"raw": raw_data}

    def compute_ingestion_hash(self, data: Dict[str, Any]) -> str:
        """Computes a content-addressable hash for ingestion payloads."""
        body = json.dumps(data, sort_keys=True).encode()
        return "sha256:" + hashlib.sha256(body).hexdigest()[:16]

    # --- RETRIEVAL PORT ---
    def retrieve_criteria(self, query: str) -> Any:
        """Override to fetch domain knowledge or catalog criteria."""
        return None

    def compute_knowledge_hash(self, kb_data: Any) -> str:
        """Computes a content-addressable hash for knowledge base / catalog data."""
        body = json.dumps(kb_data, sort_keys=True).encode()
        return "sha256:" + hashlib.sha256(body).hexdigest()[:16]

    # --- ADJUDICATOR PORT ---
    def adjudication_prompt(self, payload: Dict[str, Any], criteria: Any = None,
                            schema: Optional[Dict[str, Any]] = None) -> str:
        """The default prompt surface: the payload FLATTENED to key/value lines (the
        schema-flattening middleware in action — nested objects destabilize guided decoding),
        optional retrieved criteria, and a flat-JSON reply instruction when a schema is given.
        Override to shape domain prompts; the flat discipline is the part worth keeping."""
        flat = PayloadFlattener().flatten(payload) if isinstance(payload, (dict, list)) \
            else {"input": payload}
        lines = [f"{k}: {v}" for k, v in sorted(flat.items())]
        parts = ["\n".join(lines)]
        if criteria is not None:
            parts.append(f"CRITERIA:\n{criteria}")
        if schema:
            keys = ", ".join(sorted((schema.get("properties") or schema).keys()))
            parts.append(f"Reply with ONE flat JSON object (no nesting) with keys: {keys}.")
        return "\n\n".join(parts)

    def adjudicate(self, payload: Dict[str, Any], generate: Optional[Callable[[str], str]] = None,
                   schema: Optional[Dict[str, Any]] = None, guard=None,
                   criteria: Any = None) -> Dict[str, Any]:
        """Run one adjudication through the port. `generate` is ANY text->text callable — a
        served model, a local pipeline, a comparator bank, a human console; the port never
        assumes an LLM (the compliance contract's rule — an FPGA drives this port with
        comparators). When a `guard` (prismpath.guard.Guard) is given, the exchange crosses
        `guarded_exchange`, so denied input never reaches the model and denied output never
        returns. The reply's first JSON object becomes the outcome dict (fields for `when`
        predicates); a non-JSON reply degrades to {"text": reply}."""
        if generate is None:
            raise TypeError(
                "adjudicate() needs a `generate` callable (text -> text): the Adjudicator port "
                "does not assume an LLM — pass your model client, comparator, or reviewer bridge")
        prompt = self.adjudication_prompt(payload, criteria=criteria, schema=schema)
        if guard is not None:
            from prismpath.guard import guarded_exchange
            reply = guarded_exchange(guard, prompt, generate)
        else:
            reply = generate(prompt)
        m = re.search(r"\{.*\}", reply or "", re.S)
        if m:
            try:
                out = json.loads(m.group(0))
                if isinstance(out, dict):
                    out.setdefault("text", (reply or "").strip())
                    return out
            except ValueError:
                pass
        return {"text": (reply or "").strip()}

    # --- ACTION / SINK PORT ---
    def emit_record(self, result: Dict[str, Any], destination: str, key: str = "id") -> Any:
        """Default sink: idempotent JSONL append (`ledger_runner.upsert_jsonl`) keyed on `key`,
        so a replayed item never double-writes — the property `run_ledgered_loop` relies on.
        Records missing the key field append unconditionally. Override for OSCAL/CycloneDX/
        webhook emitters."""
        from prismpath.ledger_runner import upsert_jsonl
        os.makedirs(os.path.dirname(destination) or ".", exist_ok=True)
        if result.get(key) is None:
            with open(destination, "a") as f:
                f.write(json.dumps(result, sort_keys=True) + "\n")
            return True
        return upsert_jsonl(destination, result, key=key)

    # --- ATTESTATION PORT ---
    @staticmethod
    def policy_hash_for(flow_path: str) -> str:
        """The policy hash `attest_decision` should bind: the content hash of the governing
        flow document (`checkpoint.flow_hash`) — a decision provably tied to the exact flow
        version that made it."""
        from prismpath.checkpoint import flow_hash
        return flow_hash(flow_path)

    def attest_decision(
        self,
        outcome: Dict[str, Any],
        policy_hash: str,
        gate_id: str,
        ingestion_hashes: List[str],
        kb_hash: str,
        label: Optional[str] = None
    ) -> Dict[str, Any]:
        """Default core attestation binding using ledger_airgap. Pass
        `policy_hash_for(flow_path)` as `policy_hash` to bind the governing document."""
        from prismpath import ledger_airgap
        root_hex = hashlib.sha256(json.dumps(outcome, sort_keys=True).encode()).hexdigest()
        return ledger_airgap.provenance_manifest(
            root_hex=root_hex,
            label=label or f"{self.name}:decision",
            policy_hash=policy_hash,
            gate_id=gate_id,
            ingestion_hashes=ingestion_hashes,
            knowledge_base_hash=kb_hash
        )

    # --- DEFERRAL PORT ---
    @property
    def deferrals(self):
        """The connector's DeferralStore (the port base in `prismpath.deferral`). Defaults to a
        `FileDeferralStore` under `./<name>.deferrals` on first use; inject any backend via
        `__init__(deferral_store=...)`."""
        if self._deferrals is None:
            from prismpath.deferral import FileDeferralStore
            self._deferrals = FileDeferralStore(f"{self.name}.deferrals")
        return self._deferrals

    def defer_decision(self, unit_id: str, reason: str, state: Dict[str, Any],
                       prior_output: Any = None):
        """Suspend a unit for human review / evidence discovery. One primitive serves both the
        HITL-override and evidence-request loops; `resume_decision` closes it with the actor
        recorded."""
        return self.deferrals.defer(unit_id, reason, state, prior_output=prior_output)

    def resume_decision(self, unit_id: str, resolution: Dict[str, Any], actor: str):
        return self.deferrals.resume(unit_id, resolution, actor)

    def pending_deferrals(self):
        return self.deferrals.pending()


class PayloadFlattener:
    """
    Utility class to flatten nested dictionary payloads and apply custom mapping rules.
    Helps connectors format nested API responses into flat key-value pairs for the LLM.
    """
    def __init__(self, delimiter: str = "."):
        self.delimiter = delimiter

    def flatten(self, data: Any, prefix: str = "") -> Dict[str, Any]:
        """
        Recursively flattens a nested dict/list structure into a flat dict.
        Lists are represented as index-based keys (e.g., 'roles.0') and also
        joined as comma-separated strings at their parent prefix.
        """
        flat = {}
        if isinstance(data, dict):
            for k, v in data.items():
                new_key = f"{prefix}{k}" if not prefix else f"{prefix}{self.delimiter}{k}"
                flat.update(self.flatten(v, new_key))
        elif isinstance(data, list):
            if prefix:
                flat[prefix] = ", ".join(str(item) for item in data if not isinstance(item, (dict, list)))
            for idx, item in enumerate(data):
                new_key = f"{prefix}{self.delimiter}{idx}" if prefix else str(idx)
                flat.update(self.flatten(item, new_key))
        else:
            if prefix:
                flat[prefix] = data
        return flat

    def map_fields(self, data: Any, rules: Dict[str, Union[str, Tuple[str, Callable]]]) -> Dict[str, Any]:
        """
        Maps fields from a nested structure using rules.
        Rules definition:
        {target_key: source_path}
        or
        {target_key: (source_path, transform_fn)}
        """
        mapped = {}
        # Pre-flatten only if fallback is needed, but we can do it lazily
        flat_data = None
        for target, rule in rules.items():
            if isinstance(rule, tuple):
                source_path, transform = rule
            else:
                source_path, transform = rule, None
            
            # Resolve from raw nested structure first to preserve original types for transformers
            val = self._resolve_path(data, source_path)
            if val is None:
                if flat_data is None:
                    flat_data = self.flatten(data)
                val = flat_data.get(source_path)
                
            if val is not None and transform is not None:
                try:
                    val = transform(val)
                except Exception:
                    pass
            mapped[target] = val
        return mapped


    def _resolve_path(self, data: Any, path: str) -> Any:
        """Resolves a nested path manually in the original raw data structure."""
        parts = path.split(self.delimiter)
        current = data
        for part in parts:
            if isinstance(current, dict):
                current = current.get(part)
            elif isinstance(current, list):
                try:
                    current = current[int(part)]
                except (ValueError, IndexError):
                    return None
            else:
                return None
        return current

    @staticmethod
    def to_delimited_string(key: str, delimiter: str = ", ") -> Callable[[List[Dict[str, Any]]], str]:
        """Extracts a specific key from a list of dicts and joins them into a string."""
        def transformer(items: List[Dict[str, Any]]) -> str:
            if not isinstance(items, list):
                return str(items)
            extracted = []
            for item in items:
                if isinstance(item, dict):
                    val = item.get(key)
                    if val is not None:
                        extracted.append(str(val))
                else:
                    extracted.append(str(item))
            return delimiter.join(extracted)
        return transformer

    @staticmethod
    def format_datetime(output_format: str = "%Y-%m-%d") -> Callable[[str], str]:
        """Parses a datetime string and formats it to output_format."""
        from datetime import datetime
        def transformer(val: str) -> str:
            formats = [
                "%Y-%m-%dT%H:%M:%S.%fZ",
                "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%d"
            ]
            for fmt in formats:
                try:
                    dt = datetime.strptime(val, fmt)
                    return dt.strftime(output_format)
                except ValueError:
                    continue
            return val
        return transformer


class SystemTelemetry(BaseConnector):
    """
    Ingestion Connector to dynamically probe system hardware telemetry (RAM, VRAM, CPU cores)
    on launch.
    """
    def __init__(self):
        super().__init__("SystemTelemetry", "1.0.0")

    def ingest_payload(self, raw_data: Any = None) -> Dict[str, Any]:
        """Probes system hardware: RAM, VRAM, CPU cores."""
        import os

        # Query CPU cores
        try:
            cpu_cores = os.cpu_count() or 1
        except Exception:
            cpu_cores = 1

        # Query System RAM (MB to GB)
        ram_gb = 8.0
        try:
            if os.path.exists("/proc/meminfo"):
                with open("/proc/meminfo", "r") as f:
                    for line in f:
                        if line.startswith("MemTotal:"):
                            parts = line.split()
                            if len(parts) >= 2:
                                ram_gb = round(float(parts[1]) / (1024 * 1024), 2)
                                break
            else:
                import psutil
                ram_gb = round(psutil.virtual_memory().total / (1024 ** 3), 2)
        except Exception:
            ram_gb = 8.0

        # Query VRAM (MB to GB via nvidia-smi if available)
        vram_gb = 0.0
        try:
            import subprocess
            res = subprocess.run(
                ["nvidia-smi", "--query-gpu=memory.total", "--format=csv,noheader,nounits"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True
            )
            val = float(res.stdout.strip())
            vram_gb = round(val / 1024.0, 2)
        except Exception:
            vram_gb = 0.0

        return {
            "ram_gb": ram_gb,
            "vram_gb": vram_gb,
            "cpu_cores": cpu_cores,
            "ram_source": "host",
            "unified": False
        }

