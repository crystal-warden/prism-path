#!/usr/bin/env python3
"""load_new_overlay.py — load the (new) finale bitstream and assert the PPT MAGIC.
Runs on the board with the PYNQ env sourced. Part of the stateful-finale deploy kit."""
import sys
sys.path.insert(0, "/home/xilinx")
from ppt_pynq import PptOverlay

ol = PptOverlay("/home/xilinx/ppt_finale.bit")     # asserts MAGIC == PPT1 on load
print("NEW overlay loaded, MAGIC ok")
