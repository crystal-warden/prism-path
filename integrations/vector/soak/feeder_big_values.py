# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
import json, random, time
while True:
    # log-uniform across 9 orders of magnitude, occasionally spiking into the >2^50 zone
    def logu(lo, hi): return int(10 ** random.uniform(lo, hi))
    ev = {"bytes_out": logu(2, 15) if random.random() < 0.05 else logu(2, 13),
          "latency_us": logu(1, 9),
          "sessions": logu(0, 6)}
    print(json.dumps(ev), flush=True)
    time.sleep(0.2)
