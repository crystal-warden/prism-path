import pytest
from prismpath import BaseConnector, node
from prismpath.plugins.registry import worker_agent
from prismpath.parser import parse_file

class MockConnector(BaseConnector):
    def __init__(self):
        super().__init__(name="mock_connector", version="1.2.3")
        self.ingest_called = False

    @node("observe")
    def do_observe(self, state):
        self.ingest_called = True
        return {"text": "observed alert"}

    @node("classify")
    def do_classify(self, instruction, state):
        return {"text": "classified as malware", "threat": "malware"}

def test_connector_registration():
    conn = MockConnector()
    assert "observe" in conn._handlers
    assert "classify" in conn._handlers
    assert conn.name == "mock_connector"
    assert conn.version == "1.2.3"

def test_connector_agent_dispatch():
    conn = MockConnector()
    state = {}
    
    # Observe handler takes only 1 argument (state)
    res = conn("observe", "instruction info", state)
    assert res == {"text": "observed alert", "_worker": "mock_connector.observe"}
    assert conn.ingest_called is True
    
    # Classify handler takes 2 arguments (instruction, state)
    res = conn("classify", "classify this alert", state)
    assert res == {"text": "classified as malware", "threat": "malware", "_worker": "mock_connector.classify"}

def test_connector_fallback():
    conn = MockConnector()
    with pytest.raises(NotImplementedError):
        conn("unknown_node", "", {})

def test_connector_workers_dict():
    conn = MockConnector()
    workers = conn.get_workers()
    assert "observe" in workers
    assert "classify" in workers
    
    # Test worker function execution
    res = workers["observe"]("observe", "instruction", {})
    assert res == {"text": "observed alert", "_worker": "mock_connector.observe"}

def test_connector_ports():
    conn = MockConnector()
    
    # Ingestion
    payload = {"alert_id": 123}
    ingest_res = conn.ingest_payload(payload)
    assert ingest_res == payload
    h1 = conn.compute_ingestion_hash(payload)
    assert isinstance(h1, str)
    assert h1.startswith("sha256:")
    
    # Knowledge / Retrieval
    kb = {"controls": [1, 2, 3]}
    h2 = conn.compute_knowledge_hash(kb)
    assert isinstance(h2, str)
    assert h2.startswith("sha256:")
    
    # Attestation (Mock/Default)
    outcome = {"status": "met"}
    manifest = conn.attest_decision(
        outcome=outcome,
        policy_hash="sha256:123",
        gate_id="mock_gate",
        ingestion_hashes=[h1],
        kb_hash=h2
    )
    assert len(manifest["manifest_hash"]) == 64

    assert manifest["policy_hash"] == "sha256:123"
    assert manifest["gate_id"] == "mock_gate"
    assert manifest["ingestion_hashes"] == [h1]
    assert manifest["knowledge_base_hash"] == h2
