---
name: occupancy_6x8
start: frame
---

## frame
One camera frame, reduced on the node to a 6 by 8 grid: per cell motion `m_rc` and departure from
the shared background `b_rc`, plus `motion_cells`, `dark`, `step`, `door_hit`, `scene_changed`.
@emits(motion_cells, dark, step, door_hit, scene_changed, m_00, m_01, m_02, m_03, m_04, m_05, m_06, m_07, m_10, m_11, m_12, m_13, m_14, m_15, m_16, m_17, m_20, m_21, m_22, m_23, m_24, m_25, m_26, m_27, m_30, m_31, m_32, m_33, m_34, m_35, m_36, m_37, m_40, m_41, m_42, m_43, m_44, m_45, m_46, m_47, m_50, m_51, m_52, m_53, m_54, m_55, m_56, m_57, b_00, b_01, b_02, b_03, b_04, b_05, b_06, b_07, b_10, b_11, b_12, b_13, b_14, b_15, b_16, b_17, b_20, b_21, b_22, b_23, b_24, b_25, b_26, b_27, b_30, b_31, b_32, b_33, b_34, b_35, b_36, b_37, b_40, b_41, b_42, b_43, b_44, b_45, b_46, b_47, b_50, b_51, b_52, b_53, b_54, b_55, b_56, b_57)
-> tamper: when dark < 70
-> relight: when step
-> evidence: when motion_cells >= 28
-> scene_changed: when scene_changed
-> door: when door_hit
-> occupied: when motion_cells >= 1
-> map: when b_00 >= 24 or b_01 >= 24 or b_02 >= 24 or b_03 >= 24 or b_04 >= 24 or b_05 >= 24 or b_06 >= 24 or b_07 >= 24 or b_10 >= 24 or b_11 >= 24 or b_12 >= 24 or b_13 >= 24 or b_14 >= 24 or b_15 >= 24 or b_16 >= 24 or b_17 >= 24 or b_20 >= 24 or b_21 >= 24 or b_22 >= 24 or b_23 >= 24 or b_24 >= 24 or b_25 >= 24 or b_26 >= 24 or b_27 >= 24 or b_30 >= 24 or b_31 >= 24 or b_32 >= 24 or b_33 >= 24 or b_34 >= 24 or b_35 >= 24 or b_36 >= 24 or b_37 >= 24 or b_40 >= 24 or b_41 >= 24 or b_42 >= 24 or b_43 >= 24 or b_44 >= 24 or b_45 >= 24 or b_46 >= 24 or b_47 >= 24 or b_50 >= 24 or b_51 >= 24 or b_52 >= 24 or b_53 >= 24 or b_54 >= 24 or b_55 >= 24 or b_56 >= 24 or b_57 >= 24
-> idle: when (m_00 >= 48 or m_01 >= 48 or m_02 >= 48 or m_03 >= 48 or m_04 >= 48 or m_05 >= 48 or m_06 >= 48 or m_07 >= 48 or m_10 >= 48 or m_11 >= 48 or m_12 >= 48 or m_13 >= 48 or m_14 >= 48 or m_15 >= 48 or m_16 >= 48 or m_17 >= 48 or m_20 >= 48 or m_21 >= 48 or m_22 >= 48 or m_23 >= 48 or m_24 >= 48 or m_25 >= 48 or m_26 >= 48 or m_27 >= 48 or m_30 >= 48 or m_31 >= 48 or m_32 >= 48 or m_33 >= 48 or m_34 >= 48 or m_35 >= 48 or m_36 >= 48 or m_37 >= 48 or m_40 >= 48 or m_41 >= 48 or m_42 >= 48 or m_43 >= 48 or m_44 >= 48 or m_45 >= 48 or m_46 >= 48 or m_47 >= 48 or m_50 >= 48 or m_51 >= 48 or m_52 >= 48 or m_53 >= 48 or m_54 >= 48 or m_55 >= 48 or m_56 >= 48 or m_57 >= 48) and (m_00 >= 16 or m_01 >= 16 or m_02 >= 16 or m_03 >= 16 or m_04 >= 16 or m_05 >= 16 or m_06 >= 16 or m_07 >= 16 or m_10 >= 16 or m_11 >= 16 or m_12 >= 16 or m_13 >= 16 or m_14 >= 16 or m_15 >= 16 or m_16 >= 16 or m_17 >= 16 or m_20 >= 16 or m_21 >= 16 or m_22 >= 16 or m_23 >= 16 or m_24 >= 16 or m_25 >= 16 or m_26 >= 16 or m_27 >= 16 or m_30 >= 16 or m_31 >= 16 or m_32 >= 16 or m_33 >= 16 or m_34 >= 16 or m_35 >= 16 or m_36 >= 16 or m_37 >= 16 or m_40 >= 16 or m_41 >= 16 or m_42 >= 16 or m_43 >= 16 or m_44 >= 16 or m_45 >= 16 or m_46 >= 16 or m_47 >= 16 or m_50 >= 16 or m_51 >= 16 or m_52 >= 16 or m_53 >= 16 or m_54 >= 16 or m_55 >= 16 or m_56 >= 16 or m_57 >= 16) and (m_00 >= 4 or m_01 >= 4 or m_02 >= 4 or m_03 >= 4 or m_04 >= 4 or m_05 >= 4 or m_06 >= 4 or m_07 >= 4 or m_10 >= 4 or m_11 >= 4 or m_12 >= 4 or m_13 >= 4 or m_14 >= 4 or m_15 >= 4 or m_16 >= 4 or m_17 >= 4 or m_20 >= 4 or m_21 >= 4 or m_22 >= 4 or m_23 >= 4 or m_24 >= 4 or m_25 >= 4 or m_26 >= 4 or m_27 >= 4 or m_30 >= 4 or m_31 >= 4 or m_32 >= 4 or m_33 >= 4 or m_34 >= 4 or m_35 >= 4 or m_36 >= 4 or m_37 >= 4 or m_40 >= 4 or m_41 >= 4 or m_42 >= 4 or m_43 >= 4 or m_44 >= 4 or m_45 >= 4 or m_46 >= 4 or m_47 >= 4 or m_50 >= 4 or m_51 >= 4 or m_52 >= 4 or m_53 >= 4 or m_54 >= 4 or m_55 >= 4 or m_56 >= 4 or m_57 >= 4) and (b_00 >= 64 or b_01 >= 64 or b_02 >= 64 or b_03 >= 64 or b_04 >= 64 or b_05 >= 64 or b_06 >= 64 or b_07 >= 64 or b_10 >= 64 or b_11 >= 64 or b_12 >= 64 or b_13 >= 64 or b_14 >= 64 or b_15 >= 64 or b_16 >= 64 or b_17 >= 64 or b_20 >= 64 or b_21 >= 64 or b_22 >= 64 or b_23 >= 64 or b_24 >= 64 or b_25 >= 64 or b_26 >= 64 or b_27 >= 64 or b_30 >= 64 or b_31 >= 64 or b_32 >= 64 or b_33 >= 64 or b_34 >= 64 or b_35 >= 64 or b_36 >= 64 or b_37 >= 64 or b_40 >= 64 or b_41 >= 64 or b_42 >= 64 or b_43 >= 64 or b_44 >= 64 or b_45 >= 64 or b_46 >= 64 or b_47 >= 64 or b_50 >= 64 or b_51 >= 64 or b_52 >= 64 or b_53 >= 64 or b_54 >= 64 or b_55 >= 64 or b_56 >= 64 or b_57 >= 64) and (b_00 >= 24 or b_01 >= 24 or b_02 >= 24 or b_03 >= 24 or b_04 >= 24 or b_05 >= 24 or b_06 >= 24 or b_07 >= 24 or b_10 >= 24 or b_11 >= 24 or b_12 >= 24 or b_13 >= 24 or b_14 >= 24 or b_15 >= 24 or b_16 >= 24 or b_17 >= 24 or b_20 >= 24 or b_21 >= 24 or b_22 >= 24 or b_23 >= 24 or b_24 >= 24 or b_25 >= 24 or b_26 >= 24 or b_27 >= 24 or b_30 >= 24 or b_31 >= 24 or b_32 >= 24 or b_33 >= 24 or b_34 >= 24 or b_35 >= 24 or b_36 >= 24 or b_37 >= 24 or b_40 >= 24 or b_41 >= 24 or b_42 >= 24 or b_43 >= 24 or b_44 >= 24 or b_45 >= 24 or b_46 >= 24 or b_47 >= 24 or b_50 >= 24 or b_51 >= 24 or b_52 >= 24 or b_53 >= 24 or b_54 >= 24 or b_55 >= 24 or b_56 >= 24 or b_57 >= 24) and (b_00 >= 6 or b_01 >= 6 or b_02 >= 6 or b_03 >= 6 or b_04 >= 6 or b_05 >= 6 or b_06 >= 6 or b_07 >= 6 or b_10 >= 6 or b_11 >= 6 or b_12 >= 6 or b_13 >= 6 or b_14 >= 6 or b_15 >= 6 or b_16 >= 6 or b_17 >= 6 or b_20 >= 6 or b_21 >= 6 or b_22 >= 6 or b_23 >= 6 or b_24 >= 6 or b_25 >= 6 or b_26 >= 6 or b_27 >= 6 or b_30 >= 6 or b_31 >= 6 or b_32 >= 6 or b_33 >= 6 or b_34 >= 6 or b_35 >= 6 or b_36 >= 6 or b_37 >= 6 or b_40 >= 6 or b_41 >= 6 or b_42 >= 6 or b_43 >= 6 or b_44 >= 6 or b_45 >= 6 or b_46 >= 6 or b_47 >= 6 or b_50 >= 6 or b_51 >= 6 or b_52 >= 6 or b_53 >= 6 or b_54 >= 6 or b_55 >= 6 or b_56 >= 6 or b_57 >= 6)
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

