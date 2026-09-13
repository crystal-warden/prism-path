# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The category-balance view: how evenly a run expanded across directions."""
import json
import os


def balance_state(state):
    """The category-balance ledger + current weights - visualizes EVEN expansion across directions."""
    led = {}
    try:
        with open(os.path.join(state["proj"], "category_balance.json"), encoding="utf-8") as balance_file:
            led = json.load(balance_file)
    except Exception:
        led = {}
    cats = sorted(led)
    rows = [{"name": category, "count": int(led.get(category, 0)),
             "weight": 1.0}
            for category in cats]
    return {"total": sum(row["count"] for row in rows), "categories": rows}
