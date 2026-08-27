# demo_input fixtures

Boundary discipline: probe both thresholds at t - 1, t, and t + 1, plus the rails. The XADC
count is 0 to 4095; 665 and 1631 are the calibrated cuts (>= on both, so t lands in the upper band).

| node   | outcome                       | fields   | expect |
|--------|-------------------------------|----------|--------|
| decide | knob at the bottom rail       | pot=0    | low  |
| decide | just under the mid threshold  | pot=664  | low  |
| decide | exactly at the mid threshold  | pot=665  | mid  |
| decide | just over the mid threshold   | pot=666  | mid  |
| decide | just under the high threshold | pot=1630 | mid  |
| decide | exactly at the high threshold | pot=1631 | high |
| decide | just over the high threshold  | pot=1632 | high |
| decide | knob at the top rail          | pot=4095 | high |
