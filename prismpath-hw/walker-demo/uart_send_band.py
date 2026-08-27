#!/usr/bin/env python3
# uart_send_band.py - standalone byte source for the PL-native UART demo. Sends band bytes over a
# serial port at 115200 8N1 - the SAME bytes the ESP-NOW bridge sends - so the fabric's UART decode
# can be proven WITHOUT the mesh: wire any USB-serial TX to Arty Z7-20 Pmod JA1 (Y18) + a JA GND pin.
# The fabric turns each byte into a field (byte<<4) and lights the RGB LED from ITS decision.
#
#   python3 uart_send_band.py /dev/ttyUSB0            # cycle bands 0..4, 1.5s each
#   python3 uart_send_band.py /dev/ttyUSB0 3          # hold band 3 (high -> red)
#   python3 uart_send_band.py /dev/ttyUSB0 sweep      # slow ramp 0..255 to find the color cuts
import sys, time
import serial

BAND_BYTE = [13, 31, 63, 113, 163]     # = round(BAND_POT/16); the fabric computes field = byte*16
LABEL     = ["low/GREEN", "low/GREEN", "mid/BLUE", "high/RED", "high/RED"]


def main():
    port = sys.argv[1] if len(sys.argv) > 1 else "/dev/ttyUSB0"
    arg  = sys.argv[2] if len(sys.argv) > 2 else "cycle"
    s = serial.Serial(port, 115200, timeout=0.2)
    time.sleep(0.2)

    if arg == "sweep":
        for b in range(0, 256, 4):
            s.write(bytes([b])); s.flush()
            print(f"byte=0x{b:02x} field={b * 16:5d}")
            time.sleep(0.15)
        return

    if arg.isdigit():
        band = max(0, min(4, int(arg)))
        b = BAND_BYTE[band]
        print(f"holding band {band} -> byte=0x{b:02x} field={b * 16} -> {LABEL[band]} (Ctrl-C to stop)")
        while True:
            s.write(bytes([b])); s.flush(); time.sleep(0.5)

    print("cycling bands 0..4 (1.5s each), Ctrl-C to stop")
    while True:
        for band in range(5):
            b = BAND_BYTE[band]
            s.write(bytes([b])); s.flush()
            print(f"band {band} -> byte=0x{b:02x} field={b * 16:5d} -> {LABEL[band]}")
            time.sleep(1.5)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nstopped")
