"""Module-level probes for the sandbox behavioral test — they must be importable by dotted path so
they can cross into the bwrap subprocess (a lambda/closure cannot)."""


def ok(node, instruction, state):
    return {"v": 1, "text": "ok"}


def hog_memory(node, instruction, state):
    x = bytearray(900 * 1024 * 1024)   # 900 MB — exceeds a modest mem_mb envelope
    return {"len": len(x)}


def sleep_long(node, instruction, state):
    import time
    time.sleep(30)
    return {"text": "slept"}


def open_socket(node, instruction, state):
    import socket
    s = socket.socket()
    s.settimeout(3)
    s.connect(("1.1.1.1", 80))         # unreachable inside an unshared net namespace
    s.close()
    return {"text": "connected"}
