# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
import json
import os
from prismpath.cli import main
from prismpath.kernel.parser import parse_file
from prismpath.kernel import predicates

_INCIDENT = os.path.join(
    os.path.dirname(__file__), "..", "gallery", "incident_severity", "incident_severity.md"
)


def _route_node(graph, node: str, reading: dict) -> str | None:
    for target, cond in graph.nodes[node].edges:
        if predicates.is_deterministic(cond) and predicates.eval_condition(cond, reading):
            return target
    return None


def test_facet_encode_decode_roundtrip_route_parity(capsys):
    flow_path = _INCIDENT
    reading = {"data_at_risk": False, "user_facing": True, "error_rate": 10}
    reading_json = json.dumps(reading)

    rc_quant = main(["facet", "quantize", flow_path, reading_json])
    assert rc_quant == 0
    quant_out = capsys.readouterr().out.strip()
    assert quant_out == "(0, 2, 1)"

    rc_enc = main(["facet", "encode", flow_path, reading_json])
    assert rc_enc == 0
    hex_stream = capsys.readouterr().out.strip()
    assert len(hex_stream) > 0

    rc_dec = main(["facet", "decode", flow_path, hex_stream])
    assert rc_dec == 0
    decode_out = capsys.readouterr().out.strip()
    assert "Next node:" in decode_out
    assert "Cause:" in decode_out

    decoded_route = None
    for line in decode_out.splitlines():
        if line.startswith("Next node:"):
            decoded_route = line.split(":", 1)[1].strip()

    graph = parse_file(flow_path)
    direct_route = _route_node(graph, graph.start, reading)

    assert decoded_route == direct_route, (
        f"decoded route {decoded_route!r} != direct evaluation {direct_route!r}"
    )


def test_facet_cli_with_reading_file(tmp_path, capsys):
    flow_path = _INCIDENT
    reading_file = tmp_path / "reading.json"
    reading_data = {"data_at_risk": True, "user_facing": False, "error_rate": 0}
    reading_file.write_text(json.dumps(reading_data))

    rc = main(["facet", "quantize", flow_path, str(reading_file)])
    assert rc == 0
    quant_out = capsys.readouterr().out.strip()
    assert quant_out == "(1, 0, 0)"


def test_a_refused_payload_is_reported_not_raised(tmp_path, capsys):
    # One acceptance rule since October 2026: a number sent as a string and a missing field are
    # refusals with the field and the reason, exit 2, never a traceback or a parsed value.
    from prismpath.cli import main
    flow = tmp_path / "flow.md"
    flow.write_text("---\nname: t\nstart: s\n---\n## s\n-> hot: when temp >= 50\n-> cold: else\n## hot\n## cold\n")
    assert main(["facet", "encode", str(flow), '{"temp": "60"}']) == 2
    assert "refused temp: wrong_type" in capsys.readouterr().err
    assert main(["facet", "quantize", str(flow), "{}"]) == 2
    assert "refused temp: missing" in capsys.readouterr().err
    assert main(["facet", "encode", str(flow), '{"temp": 60}']) == 0
