#!/bin/bash

set -e

IFACE="$1"

if [ -z "$IFACE" ]; then
    IFACE=$(ip route | awk '/default/ {print $5; exit}')
fi

if [ -z "$IFACE" ]; then
    echo "Network interface not found."
    echo "Usage: bash run.sh <interface>"
    echo "Example: bash run.sh enp0s3"
    exit 1
fi

echo "[*] Interface: $IFACE"
echo "[*] Build"
make

echo "[*] Run"
sudo ./sniff_improved "$IFACE"
