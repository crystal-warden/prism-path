# sim_motion.py - overnight stand-in for shaking the walker: emit a band sweep (0..4 and back) so
# the full board pipe (led_from_band.py) exercises every decision + LED color end to end. Replaces
# the bridge in the pipe; the bridge itself is separately proven to emit the walker's real band.
import time, sys
seq = [0, 1, 2, 3, 4, 4, 3, 2, 1, 0, 0, 2, 4, 2, 0]
sys.stderr.write("[sim] emitting band sweep (simulated motion)\n"); sys.stderr.flush()
for b in seq:
    print(b, flush=True)
    time.sleep(1.2)
sys.stderr.write("[sim] done\n"); sys.stderr.flush()
