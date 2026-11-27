# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Build once per family present, flash every board by its id, run every on board check its capability allows on
the set attached, and write one report.

The report lists the families and board ids it covered, each check's result on each board by id, the families
the harness has an entry for that were not attached, and the devices it skipped as unknown. A check that needs a
group (two boards of one radio or more) is reported as not run when fewer are attached.

    . ~/cwprojects/esp-idf/export.sh && cd prismpath-hw && python -m fleet.run [--skip-flash] [--report PATH] [--relay ID]
"""
from __future__ import annotations

import argparse
import importlib
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional

HW = Path(__file__).resolve().parent.parent
if str(HW) not in sys.path:
    sys.path.insert(0, str(HW))

from fleet import probe as probe_module  # noqa: E402
from fleet.families import CANNOT, FAMILIES, Family  # noqa: E402

Runner = Callable[[List[str], Path], int]


def _run(command: List[str], cwd: Path) -> int:
    return subprocess.run(command, cwd=str(cwd)).returncode


def built_settings(sdkconfig: Path) -> Dict[str, str]:
    """The NAME=value lines of a built sdkconfig."""
    out = {}
    for line in sdkconfig.read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#") and "=" in line:
            name, _, value = line.partition("=")
            out[name] = value
    return out


def build(family: Family, variant: str = "", run: Runner = _run) -> Path:
    """Build `family` (and `variant`) in its own build directory from sdkconfig.defaults and the family's
    settings, then hold the built sdkconfig to those settings: a board of the family must never run a build
    that lacks one (the ESP32 classic's crystal is the reason)."""
    if family.tool == "make":   # the AVR image and the EEPROM anchor its flash command writes
        if run(["make", "-C", str(family.project), "dist", "anchor"], family.project) != 0:
            raise RuntimeError(f"the {family.name} build failed")
        return family.project
    build_dir = family.build_dir(variant)
    stale = family.project / "sdkconfig"
    if stale.exists():
        stale.unlink()                                    # a generated sdkconfig would override the defaults
    settings = {**family.settings, **family.variants.get(variant, {})}
    extra = Path(tempfile.mkdtemp(prefix="fleet_")) / "sdkconfig.family"
    extra.write_text("".join(f"{name}={value}\n" for name, value in settings.items()), encoding="utf-8")
    sdkconfig = family.project / f"sdkconfig.{variant or 'default'}"   # beside the project, gitignored
    defaults = f"{family.project / 'sdkconfig.defaults'};{extra}"
    fresh = not (build_dir / "CMakeCache.txt").exists() or not sdkconfig.exists()
    command = ["idf.py", "-B", str(build_dir), "-D", f"SDKCONFIG={sdkconfig}", "-D", f"SDKCONFIG_DEFAULTS={defaults}",
               *(["set-target", family.target] if fresh else []), "build"]
    if run(command, family.project) != 0:
        raise RuntimeError(f"the {family.name} build{' ' + variant if variant else ''} failed")
    check_settings(sdkconfig, settings)
    return build_dir


def check_settings(sdkconfig: Path, settings: Dict[str, str]) -> None:
    built = built_settings(sdkconfig)
    wrong = {name: built.get(name) for name, value in settings.items() if built.get(name) != value}
    if wrong:
        raise RuntimeError(f"{sdkconfig} does not hold the family's settings: {wrong}")


def flash(family: Family, board: probe_module.Board, variant: str = "", run: Runner = _run, erase: bool = False) -> None:
    """Flash one board, once more at 115200 baud when a bridge drops the link at the default rate."""
    if run(family.flash_command(board.path, variant, erase), family.project) == 0:
        return
    if run(family.flash_command(board.path, variant, erase, baud=115200), family.project) != 0:
        raise RuntimeError(f"flashing {board.board_id} at {board.path} failed")


def report(boards: List[probe_module.Board], results: Dict[str, Dict[str, dict]]) -> dict:
    present = sorted({board.family for board in boards if board.family in FAMILIES})
    return {"time": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "families_covered": present,
            "boards": [{"family": board.family, "id": board.board_id, "chip": board.chip, "path": board.path}
                       for board in boards if board.family in FAMILIES],
            "families_not_attached": sorted(set(FAMILIES) - set(present)),
            "skipped_unknown": [board.path for board in boards if board.family not in FAMILIES],
            "results": results}


def assign(boards: List[probe_module.Board], relays: List[str]) -> List[probe_module.Board]:
    """Each board under the entry it runs as: a board whose id is in `relays` runs its chip's relay entry, which a
    chip with no relay entry cannot do."""
    out = []
    for board in boards:
        if board.board_id in relays:
            entry = next((family for family in FAMILIES.values()
                          if family.probed == board.family and family.capability == CANNOT), None)
            if entry is None:
                raise RuntimeError(f"{board.board_id} is named as a relay, and {board.family} has no relay entry")
            board = probe_module.Board(entry.name, board.board_id, board.path, board.chip, board.crystal)
        out.append(board)
    return out


def checks_for(family: Family, module):
    """The checks module of `family`. Owner decision 13: a board that cannot check a signature is never run as a PEP,
    so a family of capability `cannot` takes only a module that says it does not (RUNS_AS_PEP False)."""
    if family.capability == CANNOT and getattr(module, "RUNS_AS_PEP", True):
        raise RuntimeError(f"{family.name} cannot check a signature and is never run as a PEP")
    return module


def main(argv: Optional[List[str]] = None, *, probers=None, run: Runner = _run, checks_module=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--skip-flash", action="store_true", help="run the checks on the firmware already flashed")
    parser.add_argument("--report", default=str(HW / "evidence" / "fleet-report.json"))
    parser.add_argument("--relay", action="append", default=[], metavar="ID",
                        help="run the board with this id as its chip's relay (B10), never as a PEP")
    args = parser.parse_args(argv)
    boards = assign(probe_module.probe(probers=probers), args.relay)
    for board in boards:
        if board.family not in FAMILIES:
            print(f"skipped {board.path}: no prober or family knows it")
    results: Dict[str, Dict[str, dict]] = {}
    for name in sorted({board.family for board in boards if board.family in FAMILIES}):
        family = FAMILIES[name]
        members = [board for board in boards if board.family == name]
        module = checks_for(family, checks_module or importlib.import_module(family.checks))
        builds = {variant: (None if args.skip_flash else build(family, variant, run)) for variant in ("", *family.variants)}
        if not args.skip_flash:
            for board in members:
                flash(family, board, "", run, erase=True)
        print(f"{name}: {len(members)} boards flashed from one build, running the checks")

        def reflash(board, variant, family=family):
            if not args.skip_flash:
                flash(family, board, variant, run, erase=True)
        results[name] = module.run_checks(members, family, reflash)
        results[name]["builds"] = {variant or "default": os.path.relpath(path, HW) if path else "skipped"
                                   for variant, path in builds.items()}
    doc = report(boards, results)
    Path(args.report).parent.mkdir(parents=True, exist_ok=True)
    Path(args.report).write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8")
    print(f"report: {args.report}")
    failed = [(family, check) for family, checks in results.items() for check, result in checks.items()
              if isinstance(result, dict) and result.get("passed") is False]
    for family, check in failed:
        print(f"FAILED {family} {check}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
