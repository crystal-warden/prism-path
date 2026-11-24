# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The board agnostic harness (prismpath-hw/fleet/) with fake probers, a fake build runner and fake checks, so
its logic is held with no board attached: a device no prober knows is skipped and reported, a board is keyed by
its id and flashed by its path, each family present is built once per variant, a build whose sdkconfig lacks the
family's settings fails, and the report names the families covered and those with an entry not attached."""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
HW = ROOT / "prismpath-hw"
if not (HW / "fleet" / "run.py").exists():
    pytest.skip("the fleet harness is in prismpath-hw, which this tree does not carry", allow_module_level=True)
sys.path.insert(0, str(HW))

from fleet import families, probe, run  # noqa: E402


def _esptool(answers):
    def run_tool(path, command):
        return answers.get(path, {}).get(command)
    return run_tool


CHIP = "Chip is ESP32-D0WD-V3 (revision v3.1)\nCrystal is 26MHz\nMAC: 68:09:47:e0:38:00\n"


def test_the_espressif_prober_reads_the_family_the_mac_and_the_crystal():
    tool = _esptool({"/p/a": {"chip_id": CHIP, "read_mac": "MAC: 68:09:47:e0:38:00\n"},
                     "/p/b": {"chip_id": "Chip is ESP32-C6 (QFN40)\nMAC: 40:4c:ca:00:00:01\n", "read_mac": ""}})
    a = probe.espressif("/p/a", tool)
    assert (a.family, a.board_id, a.chip, a.crystal) == ("esp32", "68:09:47:e0:38:00", "ESP32-D0WD-V3", "26MHz")
    assert probe.espressif("/p/b", tool).family == "esp32-c6"
    assert probe.espressif("/p/none", tool) is None


def test_a_device_no_prober_knows_is_unknown_and_one_device_is_offered_once(tmp_path):
    (tmp_path / "tty").write_text("")
    for name in ("usb-0:1", "usbv2-0:1"):
        (tmp_path / name).symlink_to(tmp_path / "tty")
    assert len(probe.devices(str(tmp_path))) == 1
    boards = probe.probe(["/p/x"], probers=[lambda path: None])
    assert boards == [probe.Board(family="unknown", board_id="", path="/p/x")]


class FakeChecks:
    def __init__(self):
        self.calls = []

    def run_checks(self, boards, family, reflash):
        self.calls.append([board.board_id for board in boards])
        reflash(boards[-1], "hold")
        return {"one": {"passed": True, "boards": {board.board_id: True for board in boards}, "detail": {}}}


def _runner(commands, built=None):
    def run_command(command, cwd):
        commands.append(command)
        if "build" in command:
            sdkconfig = Path(next(arg for arg in command if arg.startswith("SDKCONFIG=")).split("=", 1)[1])
            defaults = next(arg for arg in command if arg.startswith("SDKCONFIG_DEFAULTS=")).split("=", 1)[1]
            sdkconfig.write_text(built if built is not None else Path(defaults.split(";")[1]).read_text())
        return 0
    return run_command


@pytest.fixture
def family(tmp_path, monkeypatch):
    entry = families.Family(name="esp32", target="esp32", project=tmp_path, settings={"CONFIG_XTAL_FREQ_AUTO": "y"},
                            capability=families.FULL, variants={"hold": {"CONFIG_PPT_MESH_EXPIRY_HOLD": "y"}})
    (tmp_path / "sdkconfig.defaults").write_text("")
    (tmp_path / "sdkconfig").write_text("CONFIG_XTAL_FREQ_40=y\n")            # a stale generated sdkconfig
    monkeypatch.setitem(families.FAMILIES, "esp32", entry)
    monkeypatch.setattr(run, "FAMILIES", families.FAMILIES)
    return entry


def test_one_build_per_family_and_variant_each_board_flashed_by_its_path_and_one_report(family, tmp_path, monkeypatch):
    boards = [probe.Board("esp32", "68:09:47:e0:38:00", "/p/a", "ESP32-D0WD-V3", "26MHz"),
              probe.Board("esp32", "58:2a:bd:76:6a:bc", "/p/b", "ESP32-D0WD-V3", "40MHz"),
              probe.Board("unknown", "", "/p/c")]
    paths = {board.path: board for board in boards}
    monkeypatch.setattr(probe, "devices", lambda directory=probe.BY_PATH: list(paths))
    commands, checks = [], FakeChecks()
    report_path = tmp_path / "report.json"
    code = run.main(["--report", str(report_path)], probers=[lambda path: paths[path]], run=_runner(commands),
                    checks_module=checks)
    assert code == 0 and not (tmp_path / "sdkconfig").exists()
    builds = [command for command in commands if "build" in command]
    assert len(builds) == 2 and all("set-target" in command for command in builds)   # a first build sets the target
    flashes = [command for command in commands if "flash" in command]
    assert [command[command.index("-p") + 1] for command in flashes] == ["/p/a", "/p/b", "/p/b"]
    assert all("erase-flash" in command for command in flashes)
    assert checks.calls == [["68:09:47:e0:38:00", "58:2a:bd:76:6a:bc"]]
    doc = json.loads(report_path.read_text())
    assert doc["families_covered"] == ["esp32"] and doc["skipped_unknown"] == ["/p/c"]
    assert [board["id"] for board in doc["boards"]] == ["68:09:47:e0:38:00", "58:2a:bd:76:6a:bc"]
    assert doc["results"]["esp32"]["one"]["passed"] is True


def test_a_build_whose_sdkconfig_lacks_the_family_settings_fails(family):
    with pytest.raises(RuntimeError, match="does not hold the family's settings"):
        run.build(family, "", _runner([], built="CONFIG_XTAL_FREQ_40=y\n"))


def test_the_esp32_classic_entry_builds_for_every_crystal():
    entry = families.FAMILIES["esp32"]
    assert entry.settings == {"CONFIG_XTAL_FREQ_AUTO": "y"} and entry.capability == families.FULL
    defaults = (entry.project / "sdkconfig.defaults").read_text()
    assert "CONFIG_XTAL_FREQ_AUTO=y" in defaults.splitlines()
