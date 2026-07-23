import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
ADAPTER = os.path.dirname(HERE)
for p in ("/home/cwadmin/cwprojects/prismpath", ADAPTER, HERE):
    if p not in sys.path:
        sys.path.insert(0, p)
