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

def test_payload_flattener():
    from prismpath import PayloadFlattener

    nested_data = {
        "event": "alert",
        "timestamp": "2026-07-23T19:33:22Z",
        "data": {
            "source_ip": "10.0.0.5",
            "threats": [
                {"name": "malware_a", "severity": "high"},
                {"name": "adware_b", "severity": "low"}
            ],
            "tags": ["prod", "db"]
        }
    }

    flattener = PayloadFlattener()
    
    # 1. Test Flattening
    flat = flattener.flatten(nested_data)
    assert flat["event"] == "alert"
    assert flat["data.source_ip"] == "10.0.0.5"
    assert flat["data.threats.0.name"] == "malware_a"
    assert flat["data.threats.1.severity"] == "low"
    assert flat["data.tags"] == "prod, db"
    assert flat["data.tags.0"] == "prod"
    assert flat["data.tags.1"] == "db"

    # 2. Test Mapping Rules with Type Transformations
    rules = {
        "event_type": "event",
        "src_ip": "data.source_ip",
        "threat_names": ("data.threats", PayloadFlattener.to_delimited_string("name")),
        "t_date": ("timestamp", PayloadFlattener.format_datetime("%Y/%m/%d")),
        "tag_str": "data.tags"
    }

    mapped = flattener.map_fields(nested_data, rules)
    assert mapped["event_type"] == "alert"
    assert mapped["src_ip"] == "10.0.0.5"
    assert mapped["threat_names"] == "malware_a, adware_b"
    assert mapped["t_date"] == "2026/07/23"
    assert mapped["tag_str"] == ["prod", "db"]


    # 3. Test Manual Resolve Path fallback
    assert flattener._resolve_path(nested_data, "data.threats.0.name") == "malware_a"
    assert flattener._resolve_path(nested_data, "data.threats.99.name") is None
    assert flattener._resolve_path(nested_data, "data.nonexistent") is None


def test_system_telemetry():
    from prismpath.connector import SystemTelemetry
    conn = SystemTelemetry()
    data = conn.ingest_payload()
    
    assert "ram_gb" in data
    assert "vram_gb" in data
    assert "cpu_cores" in data
    assert "ram_source" in data
    assert isinstance(data["ram_gb"], float)
    assert isinstance(data["vram_gb"], float)
    assert isinstance(data["cpu_cores"], int)
    assert data["cpu_cores"] >= 1


