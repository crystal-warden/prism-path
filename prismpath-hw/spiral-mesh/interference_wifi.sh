#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# The `hotspot` interference phase: saturate 2.4 GHz channel 1 from this box's Wi-Fi radio so the
# ESP-NOW mesh (also on channel 1) sees co-channel contention. Run AT TEST TIME, with the operator's
# phone hotspot up on 2.4 GHz / channel 1. Brings up wlP9s9, joins the hotspot, and floods airtime.
#
#   sudo ./interference_wifi.sh "<HOTSPOT_SSID>" "<HOTSPOT_PASSWORD>"
#
# Bringing up the radio + joining an AP is a network change; that is why it lives in a script run
# deliberately at test time, not something to enable ahead of the session. Ctrl-C to stop the flood;
# the trap tears the connection down.
set -euo pipefail
IFACE="${IFACE:-wlP9s9}"
SSID="${1:?usage: interference_wifi.sh <SSID> <PASSWORD>}"
PASS="${2:?usage: interference_wifi.sh <SSID> <PASSWORD>}"

cleanup() { echo; echo "[wifi] tearing down"; nmcli con down "$SSID" 2>/dev/null || true; }
trap cleanup EXIT INT TERM

echo "[wifi] bringing up $IFACE and joining '$SSID' (expect it on 2.4 GHz / channel 1)"
nmcli radio wifi on
nmcli dev set "$IFACE" managed yes 2>/dev/null || true
nmcli dev wifi connect "$SSID" password "$PASS" ifname "$IFACE"

GW="$(ip route | awk -v i="$IFACE" '$0 ~ i && /default/ {print $3; exit}')"
echo "[wifi] joined; gateway=$GW  channel: $(iw dev "$IFACE" link | awk '/freq/ {print $2" MHz"}')"
echo "[wifi] saturating channel 1 airtime (flood ping to the AP). Ctrl-C to stop."
# a flood ping with a full-size payload keeps the channel busy; if iperf3 to a server is available,
# prefer:  iperf3 -c <server> -t 600 -P 8   (heavier, cleaner saturation)
ping -f -s 1400 "${GW:-192.168.1.1}"
