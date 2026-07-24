"""prismpath.connector — The Connector SDK for PrismPath.

Provides a clean, subclassable developer API for creating domain connectors.
Abstracts Ingestion, Action/Sink, Retrieval, and Attestation ports.
"""
from __future__ import annotations

import hashlib
import json
import inspect
from abc import ABC
from typing import Any, Dict, List, Callable, Optional

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
