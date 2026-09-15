# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Unit tests for A6 listener formatting, constant parsing, and verdict classification."""

import struct
import unittest

from a6_config import PPT_A6_NO_MATCH, PPT_A6_REFUSED_SHORT
from a6_listen import classify, verdict_name


class TestA6Listen(unittest.TestCase):
    """Why: verifies sentinels and verdict parsing work identically after refactoring."""

    def test_constants_loaded_from_header(self):
        """Why: ensures shared header constant values match the eBPF protocol specification."""
        self.assertEqual(PPT_A6_REFUSED_SHORT, 0xFFFFFFFE)
        self.assertEqual(PPT_A6_NO_MATCH, 0xFFFFFFFF)

    def test_verdict_name_resolution(self):
        """Why: ensures sentinel node indices resolve to expected string labels."""
        names = ["node_zero", "node_one"]
        self.assertEqual(verdict_name(0, names), "node_zero")
        self.assertEqual(verdict_name(1, names), "node_one")
        self.assertEqual(verdict_name(PPT_A6_NO_MATCH, names), "no-match")
        self.assertEqual(verdict_name(PPT_A6_REFUSED_SHORT, names), "refused-short")
        self.assertEqual(verdict_name(99, names), "?99")

    def test_classify_valid_packet(self):
        """Why: verifies packet parsing extracts magic, node index, fields count, and trailer fields."""
        magic_val = 0x4D545050
        node_idx = 1
        n_fields = 2
        header_bytes = struct.pack("<III", magic_val, node_idx, n_fields)
        fields_bytes = b"\x00" * (8 * n_fields)
        trailer_bytes = struct.pack("<IIB", 42, 0, 0)
        packet = header_bytes + fields_bytes + trailer_bytes

        parsed = classify(packet)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["magic"], magic_val)
        self.assertEqual(parsed["node_idx"], node_idx)
        self.assertEqual(parsed["n_fields"], n_fields)
        self.assertEqual(parsed["seq"], 42)
        self.assertEqual(parsed["relay_ix"], 0)
        self.assertEqual(parsed["tag"], 0)


if __name__ == "__main__":
    unittest.main()
