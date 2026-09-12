# The vision bench wire, record by record

Every record the camera, the air relay, the host relay and the sniffer put on a link, in one place.
The firmware defines most of these as packed structs or comments beside the code that writes them;
the receiver mirrors them by hand. Until a shared header replaces the hand copies (the firmware
conversion waits for a bench recertification, see `../eval_copies_check.py` for how that is
tracked), this file is the contract. All integers are little endian. `nid` is the camera's 16 bit
node id (the low two bytes of its MAC), `seq` its reading counter, `epoch` its boot nonce, `norm`
the 16 bit FNV id of the anchored normal, `pver` the policy version the reading was decided under.
Timestamps `t*` are the sender's microsecond clock.

The version is the last character of the four byte magic. A reader that compares it as a digit
(`pl[3] < '3'`) stops working at version 10; a reader should compare the whole magic.

## Links

| link | carrier | who |
|---|---|---|
| camera to air relay | ESP-NOW broadcast, one 250 byte payload per record, longer records as fragments | camera |
| air relay to host relay | IEEE 802.15.4 raw data frames, PAN 0x5050, channel 25, short addresses 0x0001 (air) and 0x0002 (host), acknowledged unicast | both relays |
| host relay to host | native USB serial, every hop payload wrapped in `ENF1` | host relay |
| host to camera | `CMD1` over USB to the host relay, `'C'` on the hop in the air relay's receive window, ESP-NOW to the camera | host |

## Fragments (camera to air relay, longer than one ESP-NOW payload)

| record | layout | note |
|---|---|---|
| `FRG2` | `"FRG2"` \| nid u16 \| id u16 \| idx u16 \| total u16 \| data[] | kept on the camera for repair; keyframes and evidence |
| `FRG3` | same layout | fire and forget; a refinement layer the next frame supersedes, never repaired |

`FRAG_DATA` is 238 bytes (250 minus the 12 byte header). The host relay reassembles per node and id.

## Hop sub frames (air relay to host relay)

| direction | layout | note |
|---|---|---|
| uplink `'S'` | `'S'` \| id u16 \| idx u8 \| total u8 \| data[] | one ESP-NOW payload becomes sub frames of at most the hop's data size; the host reassembles by id |
| downlink `'C'` | `'C'` \| nid u16 \| data[] | a command for the camera with that node id (nid 0x0000 addresses the air relay itself, 0x0002 the host relay); sent only in the air relay's receive window right after an ack |

The 802.15.4 header is a 2003 data frame with acknowledgement requested and PAN ID compression: `61 88` \| seq u8 \| PAN u16 \| dst u16 \| src u16, then the payload above.

## Camera records

| record | layout | when |
|---|---|---|
| `RDG6` | `"RDG6"` \| nid u16 \| norm u16 \| seq u32 \| t_cap u64 \| t_dec u64 \| node u16 \| steps u16 \| wire_len u16 \| prev u64 \| pver u16 \| epoch u32 \| wire[wire_len] | every frame; `prev` is the first eight bytes of the SHA-256 of the previous reading record, header and wire, the hash chain |
| `KEY3` | `"KEY3"` \| nid u16 \| norm u16 \| seq u32 \| t_cap u64 \| len u32 \| jpeg[len] | the anchored normal as a JPEG, on adoption, on request (`'k'`) and on the minute's resend; fragmented `FRG2` |
| `EVD1` | `"EVD1"` \| nid u16 \| norm u16 \| seq u32 \| t_cap u64 \| route u16 \| len u32 \| jpeg[len] | the frame behind an escalating decision, at most one per ten seconds; fragmented `FRG2` |
| `LAY3` | `"LAY3"` \| nid u16 \| seq u32 \| flags u8 (1 = full refresh) \| n u8 \| (cell u8 = r<<4 \| c, 32 bytes of nibbles) x n | refinement layer 3 for the named cells, only the cells whose 32 bytes changed, every named cell resent every five frames; fragmented `FRG3` |
| `CHN1` | `"CHN1"` \| nid u16 \| epoch u32 \| seq u32 \| head u64 \| pver u16 \| sig[64] | the chain head signed by the camera's own Ed25519 key once a minute and on `'K'`; the signature covers everything before it |
| `PUB2` | `"PUB2"` \| nid u16 \| pk[32] | the camera's public key, on `'K'` |
| `SWP1` | `"SWP1"` \| nid u16 \| version u32 \| cause u16 \| verify_us u32 \| image_hash u64 \| t u64 | the outcome of a policy swap; cause is a registry code, 0 on commit |
| `ACT2` | `"ACT2"` \| nid u16 \| counter u32 \| outcome u16 \| led u8 \| t u64 | the actuator's answer to an action, whatever it decided |

## Camera commands (the `data` of a downlink `'C'`)

| command | layout | effect |
|---|---|---|
| `'n'` | `'n'` | adopt the current frame as the normal |
| `'k'` | `'k'` | send the keyframe of the normal |
| `'K'` | `'K'` | publish the camera key (`PUB2`) and sign the chain head (`CHN1`) |
| `'L'` | `'L'` \| level u8 | set the refinement layer (0 off, 3 the sub cell layer) |
| `'S'` | `'S'` \| idx u16 \| total u16 \| chunk[] | stage a 24 byte chunk of a pack (policy or action) |
| `'X'` | `'X'` | verify the staged policy pack and commit it (answer `SWP1`) |
| `'Y'` | `'Y'` | verify the staged action and act on it (answer `ACT2`) |
| `'r'` | `'r'` \| id u16 \| n u8 \| idx[n] | resend those fragments of a kept message |

`'S'` chunks stage into one buffer for both packs and actions; only the length and the magic of the
staged bytes tell `'X'` and `'Y'` apart. A pack: `"PPKV1"` \| key_id[4] \| version u32 \| image_len u16 \|
cb_len u16 \| esc_mask u32 \| sig[64] \| image \| codebook, the signature by the fleet authority over
the 21 byte header, the image and the codebook. An action: `"ACT1"` \| to u16 \| from u16 \| seq u32 \|
normal u16 \| pver u16 \| admission u8 \| action u8 \| counter u32 \| sig[64], the signature by the fleet
authority over the 22 byte body; the actuator checks the signature, that it is the addressee, that
admission is 1, and that the counter is above the floor it keeps in flash.

## Air relay records (nid 0x0000)

| record | layout | when |
|---|---|---|
| `PWR2` | `"PWR2"` \| t u64 \| route u16 \| steps u16 \| level i8 \| give_up_run u16 \| retry_pct u16 \| sig[64] | every transmit power decision of `hop_power.md`, signed by the relay's own key |
| `PUB1` | `"PUB1"` \| pk[32] | the relay's public key, at boot and on `'K'` |
| `STA1` | `"STA1"` \| t u64 \| n_in u32 \| n_sub u32 \| n_retry u32 \| n_given_up u32 \| n_fail u32 \| q_wait u16 \| qbulk_wait u16 | counters every ten seconds |

Air relay commands: `'K'` publish the key; `'p'` \| level i8 set the transmit power (the policy
continues from there); `'R'` \| n u8 re-send the last n readings as fresh sub frames (the bench replay
attacker).

## Host relay records (USB)

| record | layout | when |
|---|---|---|
| `ENF1` | `"ENF1"` \| t_rx u64 \| len u16 \| payload[len] | every reassembled hop payload, the record the receiver reads |
| `FUS2` | `"FUS2"` \| t u64 \| route u16 \| a_fresh u8 \| b_fresh u8 \| a_occ u8 \| b_occ u8 \| a_tamper u8 \| b_tamper u8 \| a_seq u32 \| b_seq u32 \| a_age_ms u16 \| b_age_ms u16 \| steps u16 \| 0 u16 \| a_occ_age_ms u16 \| b_occ_age_ms u16 | the room verdict of `room_fusion.md`, on change and every resend period; 40 bytes |
| `RSS1` | `"RSS1"` \| t u64 \| n u16 \| sum i32 \| min i8 \| max i8 | received signal strength on the hop every two seconds |
| `ACK1` / `NAK1` | magic \| nid u16 \| cmd u8 \| tries u16 | the fate of a downlink command: acknowledged by the air relay, or given up after 200 tries |

Host relay input: `"CMD1"` \| nid u16 \| len u8 \| data[len]. One command is pending at a time; the
next is read once the pending one is acked or given up. nid 0x0002 with `'m'` \| seconds u8 mutes
this relay (a bench hook).

## Sniffer (relay C, no address, no policy)

`"SNF1"` \| t u64 \| rssi i8 \| lqi u8 \| len u8 \| frame[len], every frame heard on the channel; `len`
counts the FCS as the radio reports it and the FCS is not delivered.

## Bench replay apps (USB, certification only)

| app | in | out |
|---|---|---|
| camera replay | `"RPL1"` \| seq u32 \| len u32 \| frame[len] (grayscale, the build's resolution) | `"RES1"` \| seq u32 \| t_fe u32 \| t_pol u32 \| t_enc u32 \| node u16 \| steps u16 \| n_fields u16 \| field[n_fields] i32 \| wire_len u16 \| wire[wire_len] |
| relay replay | `"RPL2"` \| n u32 \| (give_up_run i32, retry_pct i32, backoff i32) x n | `"RES2"` \| n u32 \| (route u16, steps u16) x n |

## Known debts in these formats

- Fixed node ids for fusion: `fusion_policy.h` names camera A and B by the ids of two specific boards; swapping a board silently removes it from the room verdict until the header is regenerated.
- The staged buffer serves packs and actions alike; a stray `'Y'` after a partial pack is refused by the magic and length checks and by the signature, not by a separate channel.
- The host relay reads the reading header by byte offsets rather than the struct; the shared header that removes that is the firmware side of this document.
