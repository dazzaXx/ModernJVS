#!/bin/bash

BOOTCONFIG="/boot/firmware/config.txt"
PACKAGE1="bluetooth"
PACKAGE2="bluez"
PACKAGE3="bluez-tools"

if ! grep -q "dtoverlay=disable-bt" "$BOOTCONFIG"; then
	echo -e "\ndtoverlay=disable-bt" >> "$BOOTCONFIG"
	echo "Disabled Internal Bluetooth module, rebooting to take effect!"
	reboot
else
	echo "Internal bluetooth module should already be disabled, skipping!"
fi

if ! dpkg -s "$PACKAGE1" >/dev/null 2>&1; then
	echo "bluetooth NOT installed, installing now!"
	sudo apt install -y "$PACKAGE1"
else
	echo "bluetooth already installed, skipping!"
fi

if ! dpkg -s "$PACKAGE2" >/dev/null 2>&1; then
	echo "bluez NOT installed, installing now!"
	sudo apt install -y "$PACKAGE2"
else
	echo "bluez already installed, skipping!"
fi

if ! dpkg -s "$PACKAGE3" >/dev/null 2>&1; then
	echo "bluez-tools NOT installed, installing now!"
	sudo apt install -y "$PACKAGE3"
else
	echo "bluez-tools already installed, skipping!"
fi