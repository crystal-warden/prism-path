# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
import json, random, sys, time
random.seed()
n = 0
while True:
    ev = {"dev_mg": random.choice([120, 480, 900, 1600, 2600]) + random.random()*50,
          "rule_level": random.choice([3, 5, 7, 10, 12, 13]),
          "soc_action": random.choice(["ignore", "watch", "contain"]),
          "stability": random.choice(["stable", "unstable", "unknown"])}
    print(json.dumps(ev), flush=True)
    n += 1
    time.sleep(0.2)
