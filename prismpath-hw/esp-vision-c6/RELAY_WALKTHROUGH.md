# Walking the two relays

*A companion to [main/relay_air.c](main/relay_air.c) and [main/relay_host.c](main/relay_host.c), for a
reader who knows what a store and forward radio bridge is but has never opened these two files. Read it
beside the code. The records are specified in
[../esp-vision-node/WIRE.md](../esp-vision-node/WIRE.md), the vocabulary is
[docs/DICTIONARY.md](../../docs/DICTIONARY.md), and the evaluator both relays run is
[EVALUATOR_WALKTHROUGH.md](../EVALUATOR_WALKTHROUGH.md).*

## Why these two files are one document

Neither relay makes sense alone. The air relay is the half that faces the cameras and has no way to
reach a person; the host relay is the half that faces a person and has no way to reach a camera. Every
interesting property of the bench, the queue priority, the retry budget, the downlink window, the room
verdict, is a property of the pair. Reading either file on its own leaves you with half of a protocol
and a set of constants whose partner is in the other file.

They also carry the two facts a reader most needs and cannot derive. One is a timing contract: the air
relay opens a receive window for a few milliseconds after an acknowledged uplink, and the host relay
waits four hundred microseconds before transmitting into it. Neither number is meaningful without the
other. The other is that both relays **decide** rather than merely forward: the air relay's transmit
power is the route of an authored flow evaluated on the relay, and the host relay's room verdict is the
route of a second authored flow. Both are ordinary PrismPath policies running on the same evaluator the
cameras and the fabric run.

## One reading's journey

```
camera (ESP32S3)
  |  decides on its own frame, encodes the reading (RDG6, about 90 bytes)
  |  ESP-NOW broadcast  ......................  anyone in earshot, no relay needed
  |  UDP to the bench access point, port HOP_PORT (5050)
  v
air relay (XIAO ESP32C6, short address 0x0001)
  |  udp_task: recvfrom, remember where this node id speaks from,
  |            queue on q (readings) or qbulk (anything whose magic starts FRG)
  |  forwarder: qpwr, then q, then qbulk only when q is empty
  |  split into sub frames of at most SUB_DATA (111) bytes:  'S' | id | idx | total | data
  |  each sub frame as an acknowledged 802.15.4 unicast, up to 4 attempts
  |  after an acked sub frame of a reading: open the receive window for WINDOW_US
  v
host relay (XIAO ESP32C6, short address 0x0002)
  |  receive ISR: timestamp, accumulate signal strength, queue
  |  main loop: drop an exact duplicate, reassemble by id into asm_buf
  |  on the last sub frame: wrap as ENF1 | t_rx | len | payload, write to USB
  |  fusion_note: if this was a reading from camera A or B, record its route and arrival
  v
host (USB serial)
```

The command path runs the other way and is described under "the downlink" below.

## The air relay

### Its queues, and the one priority rule

Four queues, three of them on the forwarding path:

| queue | depth | holds | put there by |
|---|---|---|---|
| `qpwr` | 16 | the relay's own signed power decisions (`PWR2`) and its public key (`PUB1`) | the power tick, `publish_key` |
| `q` | 64 | readings and the ten second counter record (`STA1`) | `udp_task`, the stats tick |
| `qbulk` | 160 | keyframe and evidence fragments, everything whose magic starts `FRG` | `udp_task` |
| `qcmd` | 8 | downlink command frames heard on the hop | the 802.15.4 receive ISR |

**The rule, in one sentence: power decisions first, then readings, then bulk, and bulk only when no
reading is waiting.** In the code it is the three lines at the top of the forwarding loop, each a non
blocking receive except the last, which is allowed to block for twenty milliseconds so that an idle
relay is not a spin loop.

The reason for the rule is the size ratio. A reading is about ninety bytes and arrives every frame; a
keyframe is a JPEG of the whole room and arrives as dozens of fragments. Without the rule, one keyframe
would stall every camera's decisions for the length of a burst, and the decisions are the thing the
bench exists to carry. `qbulk` is deep for the same reason: a fragment burst has to survive being made
to wait.

`qpwr` sits above readings because a decision record that is dropped is evidence that is gone. It gets
one further protection: if any sub frame of a `PWR2` record failed all its attempts, the record is put
back at the **front** of `qpwr` and the relay waits two hundred milliseconds before trying again, so a
decision outlives the outage it was made during instead of being lost to it.

### Sub frames, retries, and give ups

An ESP-NOW payload can be 250 bytes; an 802.15.4 frame carries 111 bytes of payload after its header
and the five byte sub frame header. So each queued message is split into `total` sub frames of at most
`SUB_DATA` bytes, each stamped `'S' | id u16 | idx u8 | total u8`, where `id` is a counter the air relay
increments per message. The host relay reassembles by that id.

Each sub frame goes out as an acknowledged unicast, up to four attempts, with a two to four millisecond
pause between attempts and a twelve millisecond wait for the hardware acknowledgement. The comment in
the code states the arithmetic the budget is chosen for: at three percent air loss, four attempts take
the per sub frame loss to near zero. Two counters come out of this and both feed the power policy:
`n_retry` counts attempts beyond the first, and `give_up_run` counts sub frames given up **in a row**,
reset to zero by any acknowledgement.

### The downlink window

After a sub frame **of a reading** is acknowledged, the air relay calls `esp_ieee802154_receive`, busy
waits `WINDOW_US` (6000 microseconds by default), and puts the radio back to sleep. That window is the
only time the air relay can hear anything. It is tied to readings rather than to every sub frame so
that a keyframe burst does not spend the relay's airtime listening, and the radio is asleep the rest of
the time because with continuous receive the access point could not even complete an association.

The host relay's side of that contract is in `send_cmd`: it waits four hundred microseconds before
transmitting, so that the hardware acknowledgement it just sent has left the air and the air relay has
had time to open its window. Both numbers are hardware timing facts about this pair of radios. Neither
can be derived from the other file, and changing either without the other closes the downlink.

### The power policy

Once a second the relay turns its own counters into three fields and walks
[flows/hop_power.md](flows/hop_power.md):

- `give_up_run`, sub frames given up in a row;
- `retry_pct`, retries per hundred sub frames over the last ten one second buckets;
- `backoff`, how far the transmitter sits below full power in dB, zero at `LEVEL_FULL` (20 dBm) and
  forty four at `LEVEL_FLOOR` (minus 24 dBm).

The route names what to do and the code holds only the mechanism: `full_power` sets the level to
maximum, `step_up` and `step_down` move it by `LEVEL_STEP` (6 dB), `hold` does nothing. The floor is in
`set_level`, which clamps to the range and only touches the radio when the level actually changes. If
the table fails to parse at start up, `policy_ok` stays false, the policy never runs, and the radio
stays at full power for good; the start up log says which of the two happened.

### The signed decision record

Whenever the route changes, or the level changes, or ten seconds pass, the relay emits a `PWR2` record:
the timestamp, the route, the step count, the resulting level, and the two inputs `give_up_run` and
`retry_pct`, followed by an Ed25519 signature over all of that. The key is the relay's own, generated
once and kept in non volatile storage by `relay_key_init`, and published as `PUB1` at boot, on the `'K'`
command, and once a minute alongside the counters.

The point of the signature is stated in the code and is worth repeating in the dictionary's terms: a
decision made where the control plane cannot reach is still **evidence**, and the evidence has to carry
the authority of the thing that decided, not of the thing that eventually received it. A receiver that
joins the bench late asks for the key with `'K'` and can then check every record it has kept.

### One paragraph per function

**`relay_key_init`.** Opens the `hop` namespace in non volatile storage, reads a 64 byte secret and a 32
byte public key, and if either is missing or the wrong size generates a fresh pair from the hardware
random source and writes both back. It fails soft: if the namespace will not open it returns with
`relay_key` false, and the relay runs unsigned rather than not at all.

**`set_level`.** The only writer of the transmit power. Clamps to `LEVEL_FLOOR` and `LEVEL_FULL` and
calls the radio only on an actual change, so a `hold` route and a repeated `step_down` at the floor both
cost nothing.

**`policy_decide`.** The evaluator walk, identical in shape to the one in every other substrate: zero
the register file, write the three fields, then follow the first satisfied edge from `start_node` until
a node has no edges, `max_steps` is reached, or the evaluator reports no match. It returns the node
index and writes the step count out.

**`publish_key`.** Puts a 36 byte `PUB1` record on `qpwr`. It is on the priority queue rather than the
reading queue because a receiver that cannot get the key cannot check any of the decisions it has.

**`esp_ieee802154_transmit_done` and `esp_ieee802154_transmit_failed`.** The two radio completion
callbacks. Both record whether an acknowledgement arrived in `last_acked` and release the semaphore the
forwarding loop is waiting on; the success path also hands the acknowledgement frame back to the driver.
The failure path counts a raw transmit failure, which is distinct from a give up: a failure is the radio
refusing to send, a give up is four sends with no acknowledgement.

**`esp_ieee802154_receive_done`.** Runs in interrupt context. It computes the payload length from the
frame's length byte, and if the payload is a `'C'` command that fits, copies it onto `qcmd` and returns.
Everything else on the channel is handed back to the driver and ignored: the air relay is a transmitter
that listens for commands, not a receiver.

**`cmd_task`.** Drains `qcmd`. Node id zero means the command is for the relay itself, and three are
understood: `'K'` publishes the key, `'p'` sets the transmit power by hand and logs that the policy
continues from the new level, and `'R'` re sends the last n kept readings as fresh sub frames. Any other
node id is looked up in the table of cameras `udp_task` has learned, and the command is sent to that
camera's address over the access point; node id 0xffff goes to all of them. The task runs at a higher
priority than the forwarder so a command is acted on the moment it lands.

**`udp_task`.** Binds the bench port and receives datagrams forever. For any datagram of at least six
bytes it reads the node id that sits right after the magic (`RDG6`, `KEY3`, `EVD1` and `FRG2` all put it
there) and remembers the address that node speaks from, in a table of at most six, so the downlink knows
where to send. It then queues the datagram on `qbulk` if the magic starts `FRG` and on `q` otherwise.
That one `memcmp` is the entire classification: bulk is defined as "is a fragment", not by record type.

**`app_main`.** Creates the queues, brings up an open access point and the 802.15.4 radio, loads and
parses the power table, then runs the forwarding loop described above. Folded into the same loop are the
one second power tick and the ten second stats tick, which emits an `STA1` counter record onto the
reading queue and republishes the public key every sixth time, so both the counters and the key reach
the host without a second task. The access point is deliberately open, with the reasoning in the file
header: it is a bench link carrying decision symbols, and the integrity story lives above the transport
in the signatures, not in the link.

### The replay ring

The last thirty two readings are kept in a circular buffer as they are forwarded, and the `'R' | n`
command re sends n of them as fresh sub frames with new ids. This is not a repair mechanism. It is a
bench attacker in the most privileged position on the link: a compromised relay replaying genuine,
correctly formed readings. It exists so the receiver's defences against replay, the camera's sequence
numbers, the `epoch` boot nonce and the `prev` hash chain in every `RDG6`, can be demonstrated failing
an attack rather than asserted. The relay logs a loud warning when the command is used. Only readings
enter the ring; power decisions and fragments do not.

## The host relay

### Reassembly

The receive interrupt timestamps each frame, folds its signal strength into the running minimum,
maximum, count and sum, and queues the raw frame. The main loop does the rest, and it is strict on
purpose.

An exact duplicate, the same message id and the same sub frame index arriving twice, is dropped. This is
the expected case, not a fault: the air relay retries a sub frame whose acknowledgement it did not hear,
and an acknowledgement can be lost after the host has already accepted the data.

Reassembly is in order only. A sub frame whose index is not the next one expected, or which would
overrun the 256 byte assembly buffer, abandons the whole message. A new message id abandons whatever was
in progress. There is no repair at this layer and no hole filling; the acknowledged unicast below it is
what makes loss rare, and the camera's own `FRG2` repair path (the `'r'` command) is what handles the
bulk transfers where loss still matters.

When the last sub frame lands, the payload is wrapped as `ENF1 | t_rx u64 | len u16 | payload` and
written to USB, where `t_rx` is the arrival time of the message's **first** sub frame, and then handed
to `fusion_note`. Every reassembled payload crosses USB unchanged, whatever it is; the host relay never
filters, and its own records ride the same USB stream with their own magics.

### The fusion tick, and FUS2

Two cameras watch one room. The host relay is the only place that sees both, so it is where they are
fused, and the fusion is an authored flow, [flows/room_fusion.md](flows/room_fusion.md), not a rule in
the firmware.

`fusion_note` keeps three things per camera: the last sequence number, the last route, the arrival time
of that reading, and the arrival time of the last reading whose route meant somebody is there. Every 250
milliseconds `fusion_tick` turns those into six fields and walks the table:

```
for each camera A, B:
    a_fresh   = seen at all, and the last reading is younger than FRESH_US (1.5 s)
    a_occ_age = milliseconds since the last route in CAM_OCC_MASK
                (evidence, door or occupied), saturating at 65535, 65535 if never
    a_tamper  = the camera is fresh AND its last route was tamper

room:
    blind             both stale          no verdict, and it says so
    tamper            a fresh camera says tamper
    degraded_present  one stale, the other saw somebody inside the hold
    degraded_clear    one stale, the other sees nobody
    conflict          both fresh and they disagree
    present           both fresh, both saw somebody inside the hold
    clear             else
```

Two things about that table are the point of it. First, **STALE is a state the policy decides on, not a
transport error.** A camera that has gone quiet does not remove itself from the room's verdict and does
not make the verdict unavailable; it produces `blind`, `degraded_present` or `degraded_clear`, each of
which is a verdict a person can act on, with the degradation named. Second, `conflict` is a route of its
own: two fresh cameras that disagree produce the disagreement as the answer, never an average of the
two.

The two second presence hold is the flow's constant, not the relay's: the relay reports the age in
milliseconds and the flow compares it. The relay does keep one copy of the number, in the `a_occ` and
`b_occ` summary bytes of the record it builds, and that copy is a hand kept mirror of the flow's
threshold.

The result is emitted as a forty byte `FUS2` record when the route changes or every
`FUSION_RESEND_US` (two seconds), whichever comes first, and it carries its own inputs: both freshness
flags, both presence and tamper flags, both sequence numbers, both reading ages and both presence ages,
and the step count of the walk. A room verdict is therefore traceable to the two readings it was made
from, by sequence number, without keeping a log.

### The command path

A command arrives from the host over USB as `CMD1 | nid u16 | len u8 | data[len]`. `poll_usb` accumulates
bytes into a small buffer, resynchronizing on anything that is not the magic, and one command is pending
at a time; the next is not read until the pending one has been acknowledged or given up on.

`send_cmd` is called from exactly one place: immediately after a valid uplink sub frame has been
received. That is the only moment the air relay is known to be listening. It waits the four hundred
microseconds described above, builds `'C' | nid | data` as a unicast to the air relay, and waits up to
twelve milliseconds for the hardware acknowledgement. On success it emits `ACK1` with the node id, the
command byte and the number of tries; after `CMD_MAX_TRIES` (200) failures it emits `NAK1` with the same
shape and drops the command. Either way the host learns the fate of what it asked for, which is why
there is no timeout to guess at on the host side.

One command is handled locally rather than forwarded: node id 0x0002 with `'m' | seconds` puts this
relay's radio to sleep for that many seconds. It is a bench hook whose only purpose is to starve the air
relay of acknowledgements so that its power policy meets a real run of give ups.

### One paragraph per function

**`fusion_note`.** Called on every reassembled payload. It refuses anything shorter than thirty bytes or
whose magic is not a reading of version three or later, then reads the node id, sequence number and
route out of the reading by byte offset, matches the node id against the two the generated
`fusion_policy.h` names, and updates that camera's record. Two known debts live in these few lines and
both are recorded in [WIRE.md](../esp-vision-node/WIRE.md): the version test compares the last character
of the magic as a digit, which stops working at version ten, and the header is read by offsets rather
than through the shared struct that does not yet exist.

**`fusion_tick`.** Rate limits itself to one walk per `FUSION_TICK_US`, computes the six fields, walks
the table, and emits `FUS2` on a change or on the resend timer. The ages it reports are saturated at
65535 milliseconds rather than wrapped, so a camera that has been gone for a day reports the same
maximum as one gone for a minute, and `blind` covers both.

**`esp_ieee802154_receive_done`.** The receive interrupt. Timestamps the frame, copies it whole, folds
the signal strength into the four accumulators that `RSS1` reports every two seconds, returns the frame
to the driver and queues the copy. It does no parsing at all; the main loop decides what the frame was.

**`esp_ieee802154_transmit_done` and `esp_ieee802154_transmit_failed`.** The mirror image of the air
relay's pair, and used only by the command path.

**`usb_write_all`.** Writes a buffer to native USB in pieces of at most 2048 bytes, yielding a tick on a
write that makes no progress, so a host that is not draining the port stalls this relay rather than
losing records.

**`emit`.** The one place a locally generated record is put on USB. It writes an `ENF1` header with the
current time and the record's length, then the record, so that everything the host reads has the same
shape whether it came off the air or out of this relay. The reassembly path writes its own copy of the
same header inline rather than calling `emit`, because it has the arrival time of the first sub frame to
report instead of the current time.

**`poll_usb`.** The command reader described above. It is called from three places in the main loop,
including inside the mute branch and on the path where no frame arrived, so the host is never left
unheard while the radio is idle.

**`send_cmd`.** The downlink transmit described above, including the four hundred microsecond wait, the
retry accounting and the `ACK1` and `NAK1` answers. It re arms the receiver on the way out, because
transmitting takes the radio out of receive.

**`app_main`.** Brings up USB, joins the hop as short address 0x0002 with the hardware acknowledging
frames addressed to it, loads and parses the fusion table, and then runs one loop that does everything:
honor the mute, emit `RSS1` on its timer, run the fusion tick, poll USB, and reassemble whatever the
radio queue holds. There is no second task; the ordering in that loop is the whole scheduler.

## What certifies the relays

The air relay's evaluator has its own replay app, [main/relay_replay.c](main/relay_replay.c). The host
sends field triples as an `RPL2` record; the relay walks the same table image the air relay carries with
the same shared evaluator and returns a route and a step count for each as `RES2`, to be compared
against the host engine. That is what makes the relay's power decisions a conformant PrismPath
evaluation on RISC-V rather than firmware that resembles one.
