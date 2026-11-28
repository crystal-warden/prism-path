"""The information point port: the fixed points and the Context Cloud point meet it, and a point that cannot answer
reads every field at its restrictive value."""
from pathlib import Path

import pytest

from prismpath.agent import classifier, zones
from prismpath.information import contextcloud
from prismpath.ports.information import Change, Evidence, InformationPoint


class RaisingPoint:
    name = "raising"
    fields = {"zone_reach": ("none", "protected", "unknown")}
    restrictive = {"zone_reach": "unknown"}
    control_paths = ()

    def reach(self, raw, config=None):
        raise RuntimeError("the point failed")

    def reach_names(self, raw, config=None):
        raise RuntimeError("the point failed")

    def facts(self, change, budget_s):
        raise RuntimeError("the point failed")


class FactsOnlyPoint:
    name = "facts-only"
    fields = {"zone_reach": ("none", "protected", "unknown")}
    restrictive = {"zone_reach": "unknown"}
    control_paths = ()

    def facts(self, change, budget_s):
        return Evidence({"zone_reach": "none"}, frozenset(), "", {})


def _read(point, tmp_path):
    call = {"tool": "write_file", "args": {"path": "src/a.py", "content": ""}}
    return classifier.classify(call, classifier.Config.for_workspace(tmp_path, zones=point))


@pytest.mark.parametrize("point", [zones.NO_ZONES, zones.UNKNOWN_ZONES, zones.fixed("protected"), RaisingPoint()])
def test_every_point_has_the_port_shape(point):
    assert isinstance(point, InformationPoint)
    assert set(point.restrictive) <= set(point.fields)
    assert all(point.restrictive[field] in point.fields[field] for field in point.restrictive)


@pytest.mark.parametrize("answer", ["none", "protected", "unknown"])
def test_a_fixed_point_answers_through_facts_and_through_reach(answer):
    point = zones.fixed(answer)
    evidence = point.facts(Change("src/a.py"), 0.1)
    assert evidence.readings == {"zone_reach": answer} and point.reach("src/a.py") == answer
    assert evidence.names == frozenset() and evidence.why == ""


def test_a_point_that_raises_reads_every_field_at_its_restrictive_value(tmp_path):
    point = RaisingPoint()
    reading = _read(point, tmp_path)
    for field, value in point.restrictive.items():
        assert reading[field] == value


def test_a_point_that_has_no_reach_reads_its_restrictive_value(tmp_path):
    point = FactsOnlyPoint()
    assert _read(point, tmp_path)["zone_reach"] == point.restrictive["zone_reach"]


def test_no_point_at_all_reads_unknown(tmp_path):
    assert _read(None, tmp_path)["zone_reach"] == "unknown"


def test_a_context_cloud_point_without_what_the_agent_kind_hands_it_reads_unknown(tmp_path):
    doc = zones.zone_document(["pkg.x"], tmp_path, tmp_path / "index.sqlite", b"image",
                              {"package": str(tmp_path), "path": str(tmp_path / "contextcloud")})
    point = contextcloud.ContextCloudZones(doc, tmp_path, str(tmp_path / "contextcloud"))
    assert not point._confined()
    evidence = point.facts(Change(str(tmp_path / "a.py")), 0.1)
    assert evidence.readings == {"zone_reach": point.restrictive["zone_reach"]}
    assert point.reach("a.py", classifier.Config.for_workspace(tmp_path)) == "unknown"
    assert point.name == "contextcloud" and isinstance(point, InformationPoint)


def test_the_information_package_imports_no_other_prismpath_package_but_the_port():
    import re
    for path in (Path(contextcloud.__file__), Path(contextcloud.__file__).with_name("__init__.py")):
        text = path.read_text(encoding="utf-8")
        found = set(re.findall(r"^\s*(?:from|import)\s+(prismpath[\w.]*)", text, re.M))
        assert found <= {"prismpath.ports.information"}, found
