"""prismpath.connector — The Connector SDK for PrismPath.

Provides a clean, subclassable developer API for creating domain connectors.
Abstracts Ingestion, Action/Sink, Retrieval, and Attestation ports.
"""
from __future__ import annotations

import hashlib
import json
import inspect
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
    Abstracts ports (Ingestion, Action/Sink, Retrieval, Attestation)
    and simplifies node handler registration and agent dispatching.
    """
    def __init__(self, name: str, version: str = "1.0.0"):
        self.name = name
        self.version = version
        self._handlers: Dict[str, Callable] = {}
        
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

    # --- ACTION / SINK PORT ---
    def emit_record(self, result: Dict[str, Any], destination: str) -> Any:
        """Override to persist or publish execution records to standard formats."""
        pass

    # --- ATTESTATION PORT ---
    def attest_decision(
        self,
        outcome: Dict[str, Any],
        policy_hash: str,
        gate_id: str,
        ingestion_hashes: List[str],
        kb_hash: str,
        label: Optional[str] = None
    ) -> Dict[str, Any]:
        """Default core attestation binding using ledger_airgap."""
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

