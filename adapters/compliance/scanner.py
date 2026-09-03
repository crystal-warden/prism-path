#!/usr/bin/env python3
"""Scanner adapters — normalize heterogeneous scanner output into a posture (facts + provenance).

Do not build scanners; ingest them. Each adapter has one job: turn one scanner's output into the fact
keys the deterministic checks read (deterministic_checks.FACT_KEYS). The registry and build_posture
assemble the posture the posture_connector consumes, and merge_postures combines several scanners of the
same host into one posture.

Honesty: an adapter maps only the facts its scanner genuinely reports and leaves the rest absent, so the
posture_connector defers the controls it cannot decide rather than assuming them.
"""
import os
import json

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLE_DIR = os.path.join(HERE, "scanner_samples")

_ADAPTERS = {}   # source name -> parse(raw) -> facts dict


def register(source, parse):
    _ADAPTERS[source] = parse
    return parse


def available():
    return sorted(_ADAPTERS)


def get(source):
    if source not in _ADAPTERS:
        raise KeyError("no scanner adapter %r; have %s" % (source, available()))
    return _ADAPTERS[source]


def build_posture(facts, boundary, source, host=None, extra_provenance=None):
    prov = {"source": source}
    if extra_provenance:
        prov.update(extra_provenance)
    posture = {"boundary": boundary, "facts": dict(facts), "provenance": prov}
    if host:
        posture["host"] = host
    return posture


def to_posture(source, raw, boundary, host=None, extra_provenance=None):
    """Run one scanner's raw output through its adapter into a posture."""
    facts = get(source)(raw)
    return build_posture(facts, boundary, source, host=host, extra_provenance=extra_provenance)


def merge_postures(postures, boundary=None):
    """Combine several scanner postures for one host into a single posture. Facts union; when two
    scanners disagree on a fact the later value wins and the disagreement is recorded in
    provenance.conflicts (never silently dropped). Source names union."""
    facts = {}
    conflicts = []
    sources = []
    host = None
    for p in postures:
        host = host or p.get("host")
        src = p.get("provenance", {}).get("source")
        if src:
            sources.append(src)
        for k, v in (p.get("facts") or {}).items():
            if k in facts and facts[k] != v:
                conflicts.append({"fact": k, "was": facts[k], "now": v, "source": src})
            facts[k] = v
    prov = {"source": "+".join(sources) if sources else "merged", "merged_from": sources}
    if conflicts:
        prov["conflicts"] = conflicts
    out = {"boundary": boundary or (postures[0].get("boundary") if postures else "(unspecified)"),
           "facts": facts, "provenance": prov}
    if host:
        out["host"] = host
    return out


def load_sample(name):
    return json.load(open(os.path.join(SAMPLE_DIR, name + ".json")))


# Register the bundled adapters. Each concrete adapter is a standalone module exposing parse(raw).
from scan_osquery import parse as _osquery_parse  # noqa: E402
register("osquery", _osquery_parse)

from scan_lynis import parse as _lynis_parse  # noqa: E402
register("lynis", _lynis_parse)

from scan_prowler import parse as _prowler_parse  # noqa: E402
register("prowler", _prowler_parse)


