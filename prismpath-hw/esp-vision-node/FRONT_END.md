# Walking the camera front end

*A companion to [main/vision_core.h](main/vision_core.h), for a reader who knows what a background
subtraction pipeline is but has never opened this file. Read it beside the code. The vocabulary is
[docs/DICTIONARY.md](../../docs/DICTIONARY.md), the records on the links are
[WIRE.md](WIRE.md), and the evaluator the front end feeds is
[EVALUATOR_WALKTHROUGH.md](../EVALUATOR_WALKTHROUGH.md).*

## Why this document exists

`vision_core.h` has two halves. The second half is the shared embedded evaluator and the wire encoder,
and both of those are certified elsewhere and documented elsewhere. The first half is the front end: the
code that turns a frame of pixels into the hundred and one integers a policy decides on. That half is
where all of the domain knowledge in the vision node lives, and none of it was written down. A reader
can see that `MOTION_ON` is 16 and cannot see what 16 is 16 of; can see `departed_still` counting and
cannot see what it is counting toward; can see a background being copied in three different places and
cannot tell which of them is the one that matters.

This document says what the numbers mean, names every state the front end can be in and every
transition between them, and takes each function of the front end in reading order. Nothing here asks
you to change the code.

## What the front end is for

One call to `front_end` reduces one grayscale frame to five scalars, and leaves a further ninety six
per cell values in two grids where `decide` can find them. Those hundred and one numbers are the
**fields** of the flow in [flows/occupancy_6x8.md](flows/occupancy_6x8.md). Everything downstream, the
evaluator, the wire encoder, the room fusion on the host relay, sees only those numbers. The pixels
never leave the node except as a keyframe or as evidence, and both of those are pictures for a person,
never inputs to a decision.

The front end is deliberately integer only and deliberately small. It has to run inside a frame period
on an ESP32S3 with the frame buffers in external memory, and it has to produce exactly the same numbers
as the host reference so that a recorded clip decided on a laptop and the same clip decided on the board
agree byte for byte.

## The geometry

The grid is always six rows by eight columns, forty eight cells, whatever the frame size. The build
switch `VISION_VGA` chooses the frame size, and the cell size follows from it by integer division:

| build | `FRAME_W` x `FRAME_H` | cell `CELL_W` x `CELL_H` | pixels per cell | bytes per frame |
|---|---|---|---|---|
| default (QVGA) | 320 x 240 | 40 x 40 | 1600 | 76,800 |
| `-DVISION_VGA` (VGA) | 640 x 480 | 80 x 80 | 6400 | 307,200 |

Both divide exactly, so the grid tiles the frame with nothing left over and cells are square in both
builds. The row and column indices are what the field names carry: cell `(row, col)` is `m_<row><col>`
for motion and `b_<row><col>` for departure from the background, so `m_23` is row 2, column 3, which is
in the middle of the frame. `DOOR_CELLS` in the generated
[main/vision_policy.h](main/vision_policy.h) names twelve of those cells as the door region, rows 2 and
3 across columns 2 to 7.

The frame is a single plane of 8 bit gray. `cur` points at the camera's buffer for this frame; `prev`
and `background` are two frames of the same size that the node allocates in external memory at start
up. Switching to the VGA build therefore costs four times the memory and roughly four times the front
end time, which is why the node logs its mean and maximum front end time every ten seconds.

## What a cell value is

**A cell value is the mean absolute difference in gray levels between two frames, over the pixels of
that one cell, truncated to an integer.** It ranges from 0 to 255 and it carries no sign and no
direction: a cell that got brighter and a cell that got darker by the same amount give the same number.

Two grids of them are computed every frame, from the same function against two different references:

- `motion_mad[row][col]` compares this frame to the **previous frame**. It answers "did this part of the
  picture change since the last frame", which is movement now.
- `background_mad[row][col]` compares this frame to the **anchored normal**, the frame the node decided
  was what the room looks like with nobody in it. It answers "does this part of the picture differ from
  how the room is supposed to look", which is departure, and it persists for as long as whatever caused
  it stays where it is.

That distinction is the whole design. A person who walks in and then sits still stops registering in
`motion_mad` within a frame or two and goes on registering in `background_mad` indefinitely, which is
why the flow's `map` node, reached on departure with no motion, is where a still occupant is reported.

The thresholds are in those same units, so they can be stated physically:

| constant | value | what it means |
|---|---|---|
| `MOTION_ON` | 16 | a cell counts as moving when its average pixel moved by 16 gray levels out of 255, about six percent of the range, between consecutive frames |
| `BACK_ON` | 24 | a cell counts as departed when its average pixel sits 24 gray levels away from the anchored normal, about nine percent of the range |
| `JUMP_CELLS` | 32 | a step is 32 more cells departed than five frames ago, two thirds of the grid arriving at once |
| `JUMP_FRAMES` | 5 | the width of the window the step is measured over |
| `SCENE_CELLS` | 36 | three quarters of the forty eight cells; the departure level a scene change has to hold |
| `SCENE_FRAMES` | 20 | how many consecutive frames it has to hold it for |
| `CLEAN_FRAMES` | 20 | consecutive frames with no moving cell at all before the node will adopt a normal |

Because the value is a mean over the whole cell, a small bright object crossing a cell raises that cell
much less than a body filling it. At QVGA a cell is 1600 pixels: an object that covers a tenth of the
cell and differs from what it covers by the full range still only moves the mean by about 25. The
thresholds are set for people at room distance, not for fingers at arm's length.

## The exposure lock, and why the thresholds depend on it

Every one of those thresholds is a claim about gray levels, and gray levels are only stable if the
camera stops adjusting itself. At start up the radio node waits three seconds for the sensor to settle
and then turns automatic exposure and automatic gain off
([main/vision_radio_node.c](main/vision_radio_node.c), in `app_main`, right after
`esp_camera_init`), logging the exposure and gain values it froze at.

With automatic exposure left on, a person entering the frame makes the sensor re brighten the whole
scene, every cell in the grid moves at once, and the front end sees a step and eventually a scene
change where there was only an occupant. The lock is what makes `BACK_ON` mean "this part of the room
looks different" rather than "the camera changed its mind". It is also why the flow treats a `dark`
below 70 as tamper: with the exposure frozen, the picture only goes dark if the light went out or
something is over the lens.

The cost of the lock is that a genuine lighting change is now a real departure across the whole grid,
which is exactly what the step detector below is for.

## The anchored normal, state by state

The **anchored normal** is the frame held in `background`, plus `normal_id`, the 16 bit hash that names
it. Every reading, keyframe and evidence record carries `normal_id`, so a receiver can always say which
picture of the room a decision was made against.

Four variables carry the state: `normal_set` (has a normal been anchored yet), `clean_run` (how many
consecutive frames with no motion), `unstable` (has a step armed the scene change detector), and
`departed_still` (how many consecutive frames the room has been departed and still). `scene_changed` is
a latch, not a state.

```
state SEARCHING            (normal_set == false)
    the background is replaced by the current frame every frame, and normal_id is
    recomputed, so background_mad equals motion_mad and the two detectors below
    cannot fire. The node is looking for a quiet stretch to anchor on.

    transition COUNT      motion_cells == 0            clean_run = clean_run + 1
    transition RESTART    motion_cells > 0             clean_run = 0
    transition ADOPT      clean_run >= CLEAN_FRAMES    -> ANCHORED, via adopt_normal()

state ANCHORED             (normal_set == true)
    the background is frozen. background_mad now measures departure from it.

    transition ARM        a step this frame            unstable = true
                          (departed rose by >= JUMP_CELLS over the last JUMP_FRAMES
                           frames; the step is also published as the `step` field)
    transition DISARM     unstable and departed < SCENE_CELLS / 2
                                                       unstable = false
                                                       departed_still = 0
    transition HOLD       unstable and motion_cells == 0 and departed >= SCENE_CELLS
                                                       departed_still = departed_still + 1
    transition BREAK      any of those three false     departed_still = 0
    transition SETTLE     departed_still >= SCENE_FRAMES
                                                       scene_changed = true   (latched)
    transition READOPT    adopt_normal() called        -> ANCHORED with a new normal,
                          (operator command 'n', or   clearing scene_changed, unstable,
                           the flow's scene_changed    departed_still, clean_run and the
                           handled by a person)        step history
```

Read in words: the node refuses to anchor on a room it has never seen still. Once it has anchored, it
does not re anchor on its own. Something must move a lot at once (ARM), and then the room must settle
into a state that is both very different from the normal and not moving (HOLD), and stay there for
twenty frames (SETTLE), before the node will say `scene_changed`. If the room comes back toward the
normal before that, the arming is cancelled outright (DISARM). If it stays different but keeps moving,
the count keeps resetting (BREAK), because a room with a person walking around in it is occupied, not
rearranged.

`scene_changed` being a latch is the point of the design: the node does not decide that the world has
moved on. It reports that it has, ships evidence, and waits for a person to adopt the new normal. That
is the only path that clears the latch.

Two details a reader will otherwise reconstruct wrongly. First, the two detectors are evaluated on
every frame, including while SEARCHING; they are simply inert there because the background is being
replaced each frame, so `departed` stays near zero. Second, ARM and SETTLE are evaluated in the same
call and in that order, so a step and the beginning of the still departed run can be the same frame.

## One paragraph per function

**`normal_hash`.** Folds every pixel of `background` through FNV-1a 32 and returns the 32 bit result
exclusive ored with its own top half, giving a 16 bit identifier. It is a name for the picture, not a
signature: it is short enough to ride in every record and it has no secret in it. It is recomputed
whenever the background changes, which during SEARCHING is every frame, so a node that has not yet
anchored publishes a `norm` that changes constantly, and that is the visible signal that it is still
searching.

**`cell_mad`.** The only place a pixel is read for a decision. It walks the six by eight grid, and for
each cell sums the absolute difference of the two frames over that cell's rectangle and divides by the
cell's pixel count. The sum is a `uint32_t`, which cannot overflow: the worst case is 6400 pixels at
255 for the VGA build, well inside the range. The division is integer truncation, and that truncation
is part of the certified arithmetic, so it must not become a rounding division. The function takes its
two frames and its output grid as arguments precisely so the same code serves motion, departure, and
the `background_moved` check.

**`adopt_normal`.** The single writer of the anchored normal in the ANCHORED state. It copies the
current frame over the background, recomputes `normal_id`, sets `normal_set`, and clears everything
that the old normal made meaningful: `scene_changed`, `departed_still`, `unstable`, the step history and
`clean_run`. It also sets `refreshed`. Note that `front_end` clears `refreshed` again before it
returns, so the one reader of that flag, the keyframe branch in
[main/vision_live.c](main/vision_live.c), never observes it set; on both live paths the keyframe is in
practice driven by `normal_id` changing, not by `refreshed`. Adoption is called from three places: the
first frame path inside `front_end`, the clean stretch path inside `front_end`, and the operator's `'n'`
command in the radio node.

**`front_end`.** The whole reduction, in one pass, in this order. On frame zero it seeds `prev` and
`background` from the current frame and resets every state variable, which is what makes a replayed
clip starting at sequence zero behave like a freshly booted node. It then computes both grids, counts
`motion_cells` (cells at or above `MOTION_ON`) and `departed` (cells at or above `BACK_ON`), and sums
the whole frame for `dark`, the mean gray level. It slides the step history window and sets the `step`
output, then runs the ARM, DISARM, HOLD and SETTLE transitions above. It scans `DOOR_CELLS` and sets
`door_hit` when any door cell is both moving and departed, which is stricter than either test alone and
is what distinguishes someone coming through the door from a shadow falling across it. Finally it
increments the frame counter, runs the SEARCHING half of the state machine if no normal is anchored,
clears `refreshed`, and copies the current frame into `prev` for the next call. The five outputs are
returned through pointers; the two grids are left in file scope statics for `decide` to read.

**`decide`.** The bridge from the front end to the evaluator. It zeroes the register file, writes all
ninety six cell values through the generated `REG_m_rc` and `REG_b_rc` register indices, writes the five
scalars, and then walks the compiled table from `start_node`, calling `evaluate` for one node at a time
and following the first satisfied edge, until it reaches a node with no edges, exhausts `max_steps`, or
the evaluator reports that nothing matched. It returns the node it stopped on and the number of steps it
took. The long macro expansion in the middle of it is only the ninety six register writes spelled out;
the compiler flattens it, and the shape on the page is the formatter's doing, not a structure.

**`codebook_from_header`.** Copies the generated wire codebook into RAM at start up so that a signed
policy pack can later replace it in place. Each entry is a register index, a cut count, and up to
`CB_MAX_CUTS` cut points; entries shorter than that are filled with `CUT_UNSET_FILL`, which is the
largest 32 bit integer, so an unused cut can never be reached by a comparison. The same function builds
`esc_mask` by matching node names against the four that escalate, so the node's escalation set is
derived from the policy rather than hard coded, and a pack can carry its own.

**`encode_reading`.** The wire encoder. For each codebook field in order it reads the register, walks
that field's cut points, and takes the symbol to be the number of cuts the value is at or above, so a
field with three cuts yields a symbol in 0 to 3. That symbol plus one is Zeckendorf coded into a bit
accumulator, the plus one because the code has no zero. The return is the byte length, the bit position
rounded up to a byte boundary. The reading on the wire is therefore a list of **cells** in the
dictionary's sense, one bucket per field, and never a measurement: two frames whose values fall in the
same buckets produce identical bytes, which is the whole reason a reading fits in an ESP-NOW payload.

**`background_moved`.** A one question helper for the live path: it runs `cell_mad` between the current
background and a frame the node sent earlier, and returns true if any cell has moved by `BACK_ON` or
more. It answers "is the keyframe the receiver holds still a fair picture of my normal". It allocates
nothing; its working grid is a static.

## Escalating to evidence

Four of the flow's nine nodes escalate: `tamper`, `evidence`, `scene_changed` and `door`. Those names
are matched in `codebook_from_header` and become bits in `esc_mask`, and `escalates(node)` in the radio
node is a test of that bit. A signed policy pack carries its own mask in its header
(`PACK_ESC_MASK_OFF`), so the escalation set travels with the policy and is covered by the same
signature as the image.

When a frame's decision lands on an escalating node, and at least ten seconds have passed since the last
one (`EVIDENCE_GAP_US`), the node JPEG encodes the frame it just decided on and ships it as an `EVD1`
record carrying the node id, the normal id, the sequence number, the capture time and the route, split
into `FRG2` fragments. The rate limit is on the record, not on the decision: the decision itself is
published in every reading, and escalating on every frame of a busy minute would cost hundreds of
kilobytes on a link sized for ninety byte readings.

That is the split the whole node is built around. **A decision crosses the link on every frame and costs
tens of bytes. A picture crosses the link only when a decision says a person needs to look, and it is
addressed to that person, not to the policy.**

## What holds this code to its reference

The C front end has a host twin, `frontend.py`, and the claim is that they are arithmetic identical: the
same thresholds, the same integer truncation, the same state machine, the same numbers out. The twin is
not in this repository. It lives in the private strategy folder for the decision sufficient vision work,
and its hash is published in
[../evidence/vision_2026-09-11.SHA256SUMS](../evidence/vision_2026-09-11.SHA256SUMS) alongside the
replay tools, so the record can be checked against it later without publishing it.

The instrument that proves the claim is the replay app, [main/vision_replay.c](main/vision_replay.c).
The host feeds recorded frames over USB as `RPL1` records; the node runs this front end, fills the
registers, evaluates the compiled table with the shared evaluator, encodes the reading, and returns
every field value, the route, the step count, the wire bytes and three timings as a `RES1` record. Both
records are specified in [WIRE.md](WIRE.md). Because the app returns the fields and not only the route,
a disagreement is localized to a cell rather than to a frame, and because it resets the front end's
state when it sees sequence zero, a clip replayed on the board starts from the same place as a fresh
run on the host.
