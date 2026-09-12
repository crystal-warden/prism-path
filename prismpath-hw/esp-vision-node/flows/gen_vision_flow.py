#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Generate the decision sufficient vision policy for an R x C cell grid.

Every cell carries two integer fields the camera node computes from pixels:
  m_rc  motion energy in the cell, mean absolute difference against the previous frame (0..255)
  b_rc  departure from the shared background in the cell, mean absolute difference (0..255)
plus four aggregates the node computes from the grid:
  motion_cells  how many cells have m >= MOTION_ON
  dark          mean intensity of the frame (0..255)
  step          1 when the departed cell count rose by 32 or more within 5 frames: a light switch or a camera move,
                which a person cannot do (one person never exceeded 28, T2)
  door_hit      1 when any door zone cell has both motion and background departure
  scene_changed 1 when, after a step, three quarters of the cells stay departed with no motion for 20 frames: the camera
                moved or the room was rearranged; the route escalates and a person adopts the new normal
The same constants appear on every cell so Figueroa quantization gives every cell the same partition;
that partition is the codebook the wire carries. Bands are the policy's, not the pixels': the codebook
is derived from the constants in the policy text and nothing else, so every threshold a cell should
carry must be written on that cell. The codebook anchor is the penultimate edge of the frame node: it names every threshold on every cell
and can only fire when the whole grid is strong, which the evidence edge already caught, so it never routes.

Usage: gen_vision_flow.py [rows] [cols] [door cells, e.g. 22-37 or 31,32,41,42] > occupancy_RxC.md
"""
import sys
R = int(sys.argv[1]) if len(sys.argv) > 1 else 6
C = int(sys.argv[2]) if len(sys.argv) > 2 else 8
MOTION = (4, 16, 48)      # m bands: still, faint, moving, strong
BACK = (6, 24, 64)        # b bands: at rest, drift, departed, replaced
# The door zone, read off the aiming tool's grid by the process owner for this room (camera on its
# side, final position 2026-09-10): cells 22 to 37, rows 2 and 3, columns 2 to 7. The second door frame is in shot
# but not zoned; the dresser is mostly out of frame and is background either way.
def _parse_cells(spec):
    cells = []
    for part in spec.split(","):
        if "-" in part:
            a, b = part.split("-"); r0, c0, r1, c1 = int(a[0]), int(a[1]), int(b[0]), int(b[1])
            cells += [(r, c) for r in range(r0, r1 + 1) for c in range(c0, c1 + 1)]
        else: cells.append((int(part[0]), int(part[1])))
    return cells
DOOR = _parse_cells(sys.argv[3]) if len(sys.argv) > 3 else [(r, c) for r in (2, 3) if r < R for c in range(2, min(8, C))]
cells = [(r, c) for r in range(R) for c in range(C)]
def m(r, c): return f"m_{r}{c}"
def b(r, c): return f"b_{r}{c}"
motion_any = " or ".join(f"{m(r,c)} >= {MOTION[1]}" for r, c in cells)
strong_any = " or ".join(f"{m(r,c)} >= {MOTION[2]}" for r, c in cells)
faint_any = " or ".join(f"{m(r,c)} >= {MOTION[0]}" for r, c in cells)
back_any = " or ".join(f"{b(r,c)} >= {BACK[1]}" for r, c in cells)
back_far = " or ".join(f"{b(r,c)} >= {BACK[2]}" for r, c in cells)
back_near = " or ".join(f"{b(r,c)} >= {BACK[0]}" for r, c in cells)
door = " or ".join(f"({m(r,c)} >= {MOTION[1]} and {b(r,c)} >= {BACK[1]})" for r, c in DOOR)
fields = ["motion_cells", "dark", "step", "door_hit", "scene_changed"] + [m(r, c) for r, c in cells] + [b(r, c) for r, c in cells]
print(f"""---
name: occupancy_{R}x{C}
start: frame
---

## frame
One camera frame, reduced on the node to a {R} by {C} grid: per cell motion `m_rc` and departure from
the shared background `b_rc`, plus `motion_cells`, `dark`, `step`, `door_hit`, `scene_changed`.
@emits({", ".join(fields)})
-> tamper: when dark < 70
-> relight: when step
-> evidence: when motion_cells >= {max(6, (R * C) * 7 // 12)}
-> scene_changed: when scene_changed
-> door: when door_hit
-> occupied: when motion_cells >= 1
-> map: when {back_any}
-> idle: when ({strong_any}) and ({motion_any}) and ({faint_any}) and ({back_far}) and ({back_any}) and ({back_near})
-> idle: else

## tamper
The lens is covered or the room is dark. A person decides; the last good frame is the evidence. Lights
off reads under 50 with exposure locked; a person against the lens reads under 70 and is a tamper too.

## relight
The scene changed all at once: a light switch or a camera move. The map is not trusted until it settles.

## evidence
Too much of the scene is moving to trust the map. Ship one frame of evidence and let a person look. One
person never lit more than 27 cells in any take (T2); 28 means more than one person or chaos.

## scene_changed
After a step the room stayed departed and still: the camera moved or the room was rearranged. This
escalates with a frame of evidence; a person adopts the new normal, shipped as a keyframe with this cause.

## door
Someone came through the door. Ship the door region as evidence and continue.

## occupied
Something is moving. The map carries where; the wire carries only the cells.

## map
Nothing moves but the scene departs from its background somewhere: a person sitting still, a moved
chair. The map shows where. Terminal, so a still occupant is reported as map, not idle.

## idle
The room is at rest. Nothing but the refresh crosses the wire.
""")
