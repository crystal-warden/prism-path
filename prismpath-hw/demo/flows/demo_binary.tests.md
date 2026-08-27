# demo_binary fixtures

One cut at the calibrated line (1024); >= so exactly at the line reads high. Probe t-1/t/t+1 plus the rails.

| node   | outcome                  | fields   | expect |
|--------|--------------------------|----------|--------|
| decide | bottom rail              | pot=0    | low  |
| decide | just under the line      | pot=1023 | low  |
| decide | exactly at the line      | pot=1024 | high |
| decide | just over the line       | pot=1025 | high |
| decide | top rail                 | pot=4095 | high |
