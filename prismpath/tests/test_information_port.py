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
    evidence = point.facts(Change("src/a.py", None), 0.1)
    assert evidence.readings == {"zone_reach": answer, "cc_certainty": "none" if answer == "none" else "unknown",
                                 "cc_engine_agreement": 0}
    assert point.reach("src/a.py") == answer
    assert evidence.names == frozenset() and evidence.why == point.why


def test_cc_certainty_is_none_exactly_when_zone_reach_is_none_for_every_fixed_point():
    for point in (zones.NO_ZONES, zones.UNKNOWN_ZONES, zones.fixed("none"), zones.fixed("protected"),
                  zones.fixed("unknown")):
        readings = point.facts(Change("src/a.py", None), 0.1).readings
        assert (readings["zone_reach"] == "none") == (readings["cc_certainty"] == "none")
        assert set(readings) == set(point.fields) and set(point.restrictive) == set(point.fields)


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
    evidence = point.facts(Change(str(tmp_path / "a.py"), classifier.Config.for_workspace(tmp_path)), 0.1)
    assert evidence.readings == dict(point.restrictive)
    assert point.reach("a.py", classifier.Config.for_workspace(tmp_path)) == "unknown"
    assert point.name == "contextcloud" and isinstance(point, InformationPoint)


def test_the_information_package_imports_no_other_prismpath_package_but_the_port():
    import re
    for path in (Path(contextcloud.__file__), Path(contextcloud.__file__).with_name("__init__.py")):
        text = path.read_text(encoding="utf-8")
        found = set(re.findall(r"^\s*(?:from|import)\s+(prismpath[\w.]*)", text, re.M))
        assert found <= {"prismpath.ports.information"}, found


def _built(tmp_path, **kwargs):
    doc = zones.zone_document(["pkg.x"], tmp_path, tmp_path / "index.sqlite", b"image",
                              {"package": str(tmp_path), "path": str(tmp_path / "contextcloud")})
    return contextcloud.ContextCloudZones(doc, tmp_path, str(tmp_path / "contextcloud"), **kwargs)


def _raises():
    raise RuntimeError("the probe failed")


@pytest.mark.parametrize("probe,confined", [(None, False), (lambda: None, False), (lambda: 0, False), (_raises, False),
                                            (lambda: True, False), (lambda: False, True)])
def test_only_a_probe_that_answers_false_says_the_sandbox_holds(tmp_path, probe, confined):
    point = _built(tmp_path, unconfined=probe)         # a raising probe does not escape the constructor
    assert point._confined() is confined
    assert not _built(tmp_path, unconfined=probe, host_write=True)._confined()


def test_a_missing_probe_leaves_the_index_to_the_permission_rule(tmp_path, monkeypatch):
    monkeypatch.setattr(contextcloud, "agent_uid", lambda: 0)          # the agent counts as able to write
    for probe in (None, lambda: None, _raises, lambda: True):
        assert "owns or can write" in _built(tmp_path, unconfined=probe).why


def test_facts_never_raises(tmp_path):
    def broken(raw, config):
        raise RuntimeError("no")
    config = classifier.Config.for_workspace(tmp_path)
    for point in (_built(tmp_path, host_path=broken), _built(tmp_path)):
        evidence = point.facts(Change("a.py", config), 0.1)
        assert evidence.readings == point.restrictive and evidence.why
    assert _built(tmp_path).facts(Change("a.py", None), 0.1).readings == dict(_built(tmp_path).restrictive)
    assert _built(tmp_path, host_path=broken).facts(Change("a.py", None), 0.1).readings == dict(_built(tmp_path).restrictive)
