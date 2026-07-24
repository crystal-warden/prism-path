import json
import os
import socket
import threading
import time
import urllib.request
import pytest
from http.server import ThreadingHTTPServer

from prismpath.mission_control import H, PROJ

def get_free_port():
    s = socket.socket()
    s.bind(('', 0))
    port = s.getsockname()[1]
    s.close()
    return port

@pytest.fixture(scope="module")
def mc_server():
    port = get_free_port()
    os.environ["MC_PORT"] = str(port)
    os.environ["MC_HOST"] = "127.0.0.1"
    
    server = ThreadingHTTPServer(("127.0.0.1", port), H)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    time.sleep(0.5)
    yield f"http://127.0.0.1:{port}"
    server.shutdown()
    server.server_close()

def test_api_flow_graph(mc_server, tmp_path):
    flow_content = """---
name: test_flow
start: init
---

## init
Instruction 1
@emits(ok=bool)
-> step2: when ok
-> done: else

## step2
Instruction 2
-> done: always

## done
Done.
"""
    flow_file = tmp_path / "flow.md"
    flow_file.write_text(flow_content, encoding="utf-8")
    
    status_content = {
        "flow_path": str(flow_file),
        "iteration": 1,
        "valid": True
    }
    status_file = tmp_path / "status.json"
    status_file.write_text(json.dumps(status_content), encoding="utf-8")
    
    # Set MC_PROJ env variable
    os.environ["MC_PROJ"] = str(tmp_path)
    
    # Select the project directory via POST /api/sprint/select
    req_body = json.dumps({"proj": str(tmp_path)}).encode()
    req = urllib.request.Request(
        f"{mc_server}/api/sprint/select",
        data=req_body,
        headers={"Content-Type": "application/json"}
    )
    urllib.request.urlopen(req)
    
    # Query /api/flow/graph
    resp = urllib.request.urlopen(f"{mc_server}/api/flow/graph?path={flow_file}")
    data = json.loads(resp.read().decode())
    
    assert data["name"] == "test_flow"
    assert data["start"] == "init"
    assert "init" in data["nodes"]
    assert "step2" in data["nodes"]
    assert "done" in data["nodes"]
    
    init_node = data["nodes"]["init"]
    assert init_node["instruction"] == "Instruction 1"
    assert init_node["terminal"] is False
    assert init_node["annotations"] == {"emits": {"ok": "bool"}}
    
    assert len(init_node["edges"]) == 2
    assert init_node["edges"][0]["target"] == "step2"
    assert init_node["edges"][0]["tier"] == "deterministic"
    assert init_node["edges"][1]["target"] == "done"
    assert init_node["edges"][1]["tier"] == "deterministic"
