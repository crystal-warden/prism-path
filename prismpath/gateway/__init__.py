# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The first enforcement point in front of a resource: an HTTP reverse proxy that reads each request into a
finite reading, has the core decide it under an attested policy, and appends the decision as a receipt before
anything reaches the service. It never asks who the client is (reading.py, proxy.py, cli.py)."""
