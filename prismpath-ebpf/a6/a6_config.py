# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Configuration constants loaded dynamically from shared eBPF header."""

from pathlib import Path

HEADER_PATH = Path(__file__).resolve().parent.parent / "ppt_common.h"


def load_constant_from_header(symbol_name):
    """Why: keeps Python listener sentinels in sync with C eBPF definitions."""
    with open(HEADER_PATH, "r", encoding="utf-8") as header_file:
        for line_text in header_file:
            trimmed_line = line_text.strip()
            if trimmed_line.startswith("#define"):
                parts = trimmed_line.split()
                if len(parts) >= 3 and parts[1] == symbol_name:
                    raw_val = parts[2].rstrip("uU")
                    return int(raw_val, 0)
    raise ValueError(f"Constant {symbol_name} not found in {HEADER_PATH}")


PPT_A6_REFUSED_SHORT = load_constant_from_header("PPT_A6_REFUSED_SHORT")
PPT_A6_NO_MATCH = load_constant_from_header("PPT_A6_NO_MATCH")

REFUSED_SHORT = PPT_A6_REFUSED_SHORT
NO_MATCH = PPT_A6_NO_MATCH
