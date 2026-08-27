# demo_fusion v2 fixtures

Version 2 tightens one number (3000 to 1500). The swap row asserts the show beat: the exact
inputs that read WARN under v1 read CRITICAL here. Boundaries probed at the new cut (1499/1500),
the range cut (200/201), and the armed bit; the single-input invariant is re-pinned unchanged.

| node      | outcome                                     | fields                       | expect   |
|-----------|---------------------------------------------|------------------------------|----------|
| correlate | the swap row: v1 said WARN on these inputs  | armed=1; pot=2000; range=150 | critical |
| correlate | all three agree, at both thresholds         | armed=1; pot=1500; range=200 | critical |
| correlate | all three agree, rails                      | armed=1; pot=4095; range=30  | critical |
| correlate | knob one count under the new cut            | armed=1; pot=1499; range=200 | warn     |
| correlate | not armed, knob hot and object near         | armed=0; pot=1500; range=200 | warn     |
| correlate | armed and hot, object one mm past near      | armed=1; pot=1500; range=201 | warn     |
| correlate | armed alone                                 | armed=1; pot=0; range=2000   | ok       |
| correlate | knob pegged alone                           | armed=0; pot=4095; range=2000| ok       |
| correlate | object near alone                           | armed=0; pot=0; range=30     | ok       |
| correlate | everything quiet                            | armed=0; pot=0; range=2000   | ok       |
