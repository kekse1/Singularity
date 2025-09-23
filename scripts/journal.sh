#!/bin/bash

if [[ $EUID -ne 0 ]]; then
    echo "Please run this script as root."
    exit 1
fi

echo "[*] Cleaning journal logs..."

journalctl --vacuum-time=1s 2>/dev/null || true
journalctl -k --vacuum-time=1s 2>/dev/null || true
journalctl --rotate --vacuum-time=1s --quiet 2>/dev/null || true

echo "Journal logs cleaned."
