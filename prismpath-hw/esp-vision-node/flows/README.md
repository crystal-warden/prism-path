# The flows this bench ran

These are the policies, as authored, that the camera and relay firmware in this folder and in
`../esp-vision-c6` compiled to their table images. They are the invariant the arc claims: the sensor
does not know how it is governed, and these documents are how it was.

| flow | runs on | what it decides |
|---|---|---|
| `occupancy_6x8.md` | camera one | a 6 by 8 grid of motion and departure cells against a shared normal: tamper, relight, evidence, scene_changed, door, occupied, map, idle; door cells 22 to 37 |
| `occupancy_6x8_cam2.md` | camera two | the same with two door zones, 00 to 25 and 40 to 55 |
| `occupancy_6x8_v2.md` | either, as a signed swap | version 2: the evidence threshold at 20 moving cells instead of 28, and therefore a different wire |
| `receiver_admission.md` | the receiver | whether a transported reading is authorized, refused with a cause, or abstained |
| `normal_policy.md` | the receiver or a relay | when the shared normal may be replaced: fixed, living, operator, escalate |
| `../../esp-vision-c6/flows/hop_power.md` | the air relay | its own 802.15.4 transmit power from its retry and give up counters |
| `../../esp-vision-c6/flows/room_fusion.md` | the host relay | two cameras into one room verdict, with a quiet camera as STALE and a presence hold |

`gen_vision_flow.py R C [door cells]` writes the occupancy flow for a grid and a door zone;
`../gen_vision_policy.py flow.md [door cells]` compiles it to `main/vision_policy.h`. Every flow validates
as Level M and compiles to the table image the interpreter walks on every substrate.
