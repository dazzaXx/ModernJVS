#!/bin/bash

PACKAGE1="build-essential"
PACKAGE2="cmake"
PACKAGE3="git"
PACKAGE4="file"
PACKAGE5="libgpiod-dev"
PACKAGE6="pkg-config"

if ! dpkg -s "$PACKAGE1" >/dev/null 2>&1; then
	echo "build-essential NOT installed, installing now!"
	sudo apt install -y "$PACKAGE1"
else
	echo "build-essential already installed, skipping!"
fi

if ! dpkg -s "$PACKAGE2" >/dev/null 2>&1; then
	echo "cmake NOT installed, installing now!"
	sudo apt install -y "$PACKAGE2"
else
	echo "cmake already installed, skipping!"
fi

if ! dpkg -s "$PACKAGE3" >/dev/null 2>&1; then
	echo "git NOT installed, installing now!"
	sudo apt install -y "$PACKAGE3"
else
	echo "git already installed, skipping!"
fi

if ! dpkg -s "$PACKAGE4" >/dev/null 2>&1; then
	echo "file NOT installed, installing now!"
	sudo apt install -y "$PACKAGE4"
else
	echo "file already installed, skipping!"
fi

if ! dpkg -s "$PACKAGE5" >/dev/null 2>&1; then
	echo "libgpiod-dev NOT installed, installing now!"
	sudo apt install -y "$PACKAGE5"
else
	echo "libgpiod-dev already installed, skipping!"
fi

if ! dpkg -s "$PACKAGE6" >/dev/null 2>&1; then
	echo "pkg-config NOT installed, installing now!"
	sudo apt install -y "$PACKAGE6"
else
	echo "pkg-config already installed, skipping!"
fi

git clone https://github.com/dazzaXx/ModernJVS.git
cd ModernJVS
make
sudo make install