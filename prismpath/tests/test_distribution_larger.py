# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Python's replay of portable/conformance/install_larger.json, the IS12 table of what makes an install set larger
(spec-policy-distribution.md IS10, IS12, AF8, OP4). Every row runs on a `host` and a `mesh` PEP: the set the row
holds is applied, withdrawn or lost first, then the row's set is sent and the PEP's state record must carry the row's
event and cause. The committed file must also be what portable/gen_install_larger_fixtures.py writes. Rust and the
C core replay the same file."""
import importlib.util
import json
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from prismpath import canon  # noqa: E402
from prismpath.distribution import install, kinds  # noqa: E402
from prismpath.tests._dist import GEN, image  # noqa: E402
from prismpath.tests.test_distribution_floor import LAYOUT, HostFloor, MeshFloor, table  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
CORPUS_PATH = REPO / "portable" / "conformance" / "install_larger.json"
CORPUS = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
KEYS = ["N1", "N2", "N3"]
TABLES = {"T1": image(5), "T2": image(7), "T3": image(9)}
FLOORS = {"F1": table("cmd == 3 and p >= 2 and p <= 5"), "F2": table("cmd == 4 and p >= 2 and p <= 5")}
SETS = {"ceiling": install.CEILING, "floor": install.FLOOR}
POINTS = {"host": HostFloor, "mesh": MeshFloor}


def _generator():
    spec = importlib.util.spec_from_file_location("gen_install_larger_fixtures",
                                                  REPO / "portable" / "gen_install_larger_fixtures.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _rate(pair):
    return None if pair is None else {"allows": pair[0], "window": pair[1]}


def _statements(point, kind: str, spec, seq: int, *, widens: bool, replaces: str):
    if spec == "empty":
        return point.install_set(kind, {kinds.NONE: b""}, seq, widens=widens, replaces=replaces)
    if kind == install.CEILING:
        body = install.ceiling_body([TABLES[name] for name in spec["list"]])
        return point.install_set(kind, {kinds.POLICY_LIST: body}, seq, widens=widens, replaces=replaces)
    body = FLOORS[spec["table"]]
    return point.install_set(kind, {"policy.ppt": body}, seq, widens=widens, replaces=replaces,
                             metas={"policy.ppt": {**GEN.image_meta(body), "command": 0}}, layout=LAYOUT,
                             rate=_rate(spec["rate"]), answer_rate=_rate(spec["answer_rate"]), check=False)


def replay(row: dict, target: str, directory: Path) -> dict:
    """The event and the cause a fresh PEP of kind `target` answers the row with."""
    point = POINTS[target](directory, install_keys=KEYS, install_threshold=2)
    kind = SETS[row["set"]]
    held, seq = "", 1
    if row["before"] != "none":
        first = point.send(_statements(point, kind, row["held"], 1, widens=kind == install.FLOOR, replaces=""))[-1]
        assert first.event in ("install-applied", "install-widened"), (row["name"], first.cause)
        held, seq = point.pep.installed.record.sets[kind].policy_sha256, 2
    if row["before"] == "withdrawn":
        withdrawn = point.send(_statements(point, kind, "empty", 2, widens=kind == install.CEILING, replaces=held))[-1]
        assert withdrawn.event in ("install-applied", "install-widened"), (row["name"], withdrawn.cause)
        seq = 3
    if row["before"] == "lost":
        for copy in (directory / "dist" / "install" / "blobs", directory / "dist" / "install-copy" / "blobs"):
            for blob in copy.iterdir():
                blob.write_bytes(b"unreadable")
        point.pep = point.open()
        point.pep.drain()
        assert point.pep.installed.held(kind) is None, row["name"]
    replaces = {"held": held, "": "", "other": canon.sha256_hex(b"a set this PEP never held")}[row["replaces"]]
    record = point.send(_statements(point, kind, row["new"], seq, widens=row["widens"], replaces=replaces))[-1]
    return {"event": record.event, "cause": record.cause}


def test_the_corpus_is_what_its_generator_writes():
    assert json.dumps(_generator().corpus(), indent=1, sort_keys=True) + "\n" == CORPUS_PATH.read_text(encoding="utf-8")


def test_the_corpus_holds_ceiling_and_floor_rows_held_lost_and_withdrawn():
    rows = CORPUS["rows"]
    assert len(rows) == 47 and len({row["name"] for row in rows}) == len(rows)
    assert {(row["set"], row["before"]) for row in rows} == {(kind, before) for kind in SETS
                                                             for before in ("none", "held", "lost", "withdrawn")}


@pytest.mark.parametrize("target", ["host", "mesh"])
@pytest.mark.parametrize("row", CORPUS["rows"], ids=[row["name"] for row in CORPUS["rows"]])
def test_case_307_every_row_of_the_is12_table_answers_as_it_says(row, target, tmp_path):
    """case_307 and IS12 as a table: each row answers with its event and cause on `host` and on `mesh`."""
    assert target in row["kinds"]
    assert replay(row, target, tmp_path / "pep") == row["expect"]
