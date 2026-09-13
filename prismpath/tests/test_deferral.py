# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The Deferral / Resumption port: the round trip that used to live in deferral.py's `__main__`
self test, plus the port's abstractness. Suspend a unit, see it pending, resume it with an actor,
and read back the state and the prior output the suspension had to preserve."""
import pytest

from prismpath.workers.deferral import DeferralStore
from prismpath.workers.deferral import FileDeferralStore


@pytest.fixture()
def store(tmp_path):
    return FileDeferralStore(str(tmp_path / "deferrals"))


def test_defer_then_resume_round_trip(store):
    store.defer(
        "wu:001",
        reason="human_review: compensating control claimed",
        state={"flow": "x", "node": "adjudicate"},
        prior_output={"status": "not-met"},
    )
    assert [rec["unit_id"] for rec in store.pending()] == ["wu:001"]

    rec = store.resume(
        "wu:001",
        resolution={"status": "met", "note": "compensating control accepted"},
        actor="reviewer:jsmith",
    )
    assert rec["actor"] == "reviewer:jsmith"
    assert rec["status"] == "resolved"
    assert rec["resolution"]["status"] == "met"
    # the suspension must not lose what the flow already had
    assert rec["prior_output"]["status"] == "not-met"
    assert rec["state"] == {"flow": "x", "node": "adjudicate"}
    assert store.pending() == []


def test_a_resumed_unit_survives_a_fresh_store(tmp_path):
    directory = str(tmp_path / "deferrals")
    FileDeferralStore(directory).defer("wu:002", reason="evidence", state={"n": 1})
    reopened = FileDeferralStore(directory)
    assert reopened.get("wu:002")["reason"] == "evidence"
    assert reopened.get("wu:404") is None


def test_resume_twice_is_refused(store):
    store.defer("wu:003", reason="human_review", state={})
    store.resume("wu:003", resolution={"status": "met"}, actor="auditor")
    with pytest.raises(ValueError):
        store.resume("wu:003", resolution={"status": "met"}, actor="auditor")
    with pytest.raises(KeyError):
        store.resume("wu:never", resolution={"status": "met"}, actor="auditor")


def test_the_port_is_abstract():
    """A backend must supply all four methods; the port itself is not instantiable."""
    with pytest.raises(TypeError):
        DeferralStore()

    class HalfStore(DeferralStore):
        def defer(self, unit_id, reason, state, prior_output=None):
            return {}

    with pytest.raises(TypeError):
        HalfStore()
