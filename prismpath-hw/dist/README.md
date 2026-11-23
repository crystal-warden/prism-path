# The C core of policy distribution

These files are the C side of `docs/design/spec-policy-distribution.md` for the `mesh` and `cfs` targets.
The same sources are compiled on the host for the tests and unchanged for the boards and the cFS app.
Nothing allocates, every bound is a constant in `pp_dist.h`, and the one dependency is Monocypher's
Ed25519, vendored in `prismpath-hw/mesh/main`.

| File | What it holds |
|---|---|
| `pp_canon2.h` | The canon/2 reader. It tells canonical bytes from canon/2 in another spelling and from bytes that are not canon/2, and then reads canonical bytes member by member |
| `pp_dist.h`, `pp_dist.c` | The sealed container, the envelope scanner, the trust store, the verifier (V2 to V11), the frame reassembly, the enforcement point machine and the signed state record |
| `host_check.c` | A stdio harness the Python tests drive |

The scanner reads the envelope's members in canonical order and checks of `meta` only that it is an
object nesting at most three levels that ends inside the envelope, as E9 allows a constrained target. The
signatures are checked before the scanner reads a byte (V3 before V4). The machine keeps what it must hold
durably in one `pp_durable` struct that the caller's `persist` writes whole, and it reports every
transition in a state record signed by the instance key.

`prismpath/tests/test_distribution_c.py` builds `host_check.c` with the host `cc` and
`-Wall -Wextra -Werror -fsanitize=address,undefined`. It replays every corpus case on the `mesh` kind,
runs the machine step for step beside the Python one (`prismpath/distribution/pep.py` on a modelled mesh
node) and requires the same signed state records byte for byte, and runs the frame reassembly frame for
frame beside `prismpath/distribution/frames.py` on streams from fixed seeds. A fixed seed fuzz holds the
scanner to the Python reader. The test skips, naming the reason, when there is no C compiler.

To build the harness by hand:

```
cc -std=c11 -Wall -Wextra -Werror -I prismpath-hw/dist -I prismpath-hw/mesh/main -o host_check \
   prismpath-hw/dist/host_check.c prismpath-hw/dist/pp_dist.c \
   prismpath-hw/mesh/main/monocypher.c prismpath-hw/mesh/main/monocypher-ed25519.c
```

`PPT_DEV_BUILD` sets bit 6 of every state record's status (D3). The `mesh` and `cfs` targets have no
escape hatch in any build.
