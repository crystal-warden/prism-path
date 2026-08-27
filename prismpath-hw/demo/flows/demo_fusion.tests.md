# demo_fusion v1 fixtures

The forbidden region invariant, pinned: CRITICAL needs all three, WARN needs any two, a single
input alone never leaves OK. Boundaries probed at the pot cut (2999/3000), the range cut
(200/201), and the armed bit. The `pot=2000` row is the swap beat: v2 makes this CRITICAL.

| node      | outcome                                    | fields                       | expect   |
|-----------|--------------------------------------------|------------------------------|----------|
| correlate | all three agree, at both thresholds        | armed=1; pot=3000; range=200 | critical |
| correlate | all three agree, rails                     | armed=1; pot=4095; range=30  | critical |
| correlate | knob one count under the cut, two remain   | armed=1; pot=2999; range=200 | warn     |
| correlate | not armed, knob hot and object near        | armed=0; pot=3000; range=200 | warn     |
| correlate | armed and hot, object one mm past near     | armed=1; pot=3000; range=201 | warn     |
| correlate | armed and near, knob mid travel (swap row) | armed=1; pot=2000; range=150 | warn     |
| correlate | armed alone                                | armed=1; pot=0; range=2000   | ok       |
| correlate | knob pegged alone                          | armed=0; pot=4095; range=2000| ok       |
| correlate | object near alone                          | armed=0; pot=0; range=30     | ok       |
| correlate | everything quiet                           | armed=0; pot=0; range=2000   | ok       |
