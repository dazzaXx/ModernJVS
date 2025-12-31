# ModernJVS

ModernJVS is fork of OpenJVS, an emulator for I/O boards in arcade machines that use the JVS protocol. It requires a USB RS485 converter, or an official OpenJVS HAT.

Updated to use libgpiod, with backwards-compatible support for the now deprecated sysfs. Optimized code and new features, as well as support to the Raspberry Pi 5.

Updated using Github Copilot.

The following arcade boards are supported:

- Naomi 1/2
- Triforce
- Chihiro
- Hikaru
- Lindbergh
- Ringedge 1/2
- Namco System 22/23
- Namco System 2x6
- Taito Type X+
- Taito Type X2
- exA-Arcadia

## Installation

Installation is done from the git repository as follows, using RaspiOS Lite:

```
sudo apt install build-essential cmake git file libgpiod-dev
git clone https://github.com/dazzaXx/ModernJVS
make
sudo make install
```

If using DietPi:

```
sudo apt install build-essential cmake git file libgpiod-dev pkg-config
git clone https://github.com/dazzaXx/ModernJVS
make
sudo make install
```

## Supported Hardware

ModernJVS supports all Raspberry Pi models including:
- Raspberry Pi 1, 2, 3, 4
- Raspberry Pi 5 (with automatic GPIO chip detection)

The software automatically detects the correct GPIO chip for your Raspberry Pi model.

On games that require a sense line, the following has to be wired up:

```

|          GND   (BLACK) |-------------| GND           |                 |                        |
| ARCADE   A+    (GREEN) |-------------| A+  RS485 USB |-----------------| USB  RASPBERRY PI > 1  |
|          B-    (WHITE) |-------------| B-            |                 |                        |
|                        |                                               |                        |
|          SENSE (RED)   |----------+------------------------------------| GPIO 12                |
                                    |
                                    +---- (1kOhm Resistor or 4 Signal Diodes) ---- GND
```

A 1KOhm resistor or 4 signal diodes are known to work properly, the purpose of these is to create a 2.5 volt drop.

> Warning: A 1KOhm resistor will not work with the Triforce system, please use the 4 signal diodes for this purpose.

When buying a USB to RS485 dongle be sure to buy one with an FTDI chip inside. The CP2102 and other chips have been found to not work well.

I have tested CH340E USB RS485 converters personally and they work. ~dazzaXx

## Using Bluetooth with Sense Line on Pi 4/5

Raspberry Pi 4 and 5 models have internal Bluetooth enabled by default, and you can use it simultaneously with the GPIO sense line functionality. This allows you to:
- Use Bluetooth controllers or peripherals while running ModernJVS
- Keep the sense line working on GPIO 12 (or your chosen GPIO pin)

### Default Configuration Works

**Good news**: By default on Pi 4/5, internal Bluetooth and the GPIO sense line work together without conflicts:
- Bluetooth uses the primary UART (`/dev/ttyAMA0`) for communication with the Bluetooth chip
- ModernJVS uses a USB RS485 converter (`/dev/ttyUSB0`) for arcade communication
- The sense line uses GPIO 12, which is completely independent of both Bluetooth and UART

**No configuration changes are needed** if you're using the standard USB RS485 setup with Bluetooth.

### Enabling UART for Sense Line

If you want to ensure full UART functionality is enabled (some systems disable it by default), add this to `/boot/firmware/config.txt` (or `/boot/config.txt` on older Raspberry Pi OS versions):

```ini
# Enable UART
enable_uart=1
```

Then reboot:
```bash
sudo reboot
```

This ensures the UART subsystem is active, which can help with overall system stability when using GPIO functionality.

### Using Hardware UART for RS485 (Advanced)

If you want to use a hardware UART for RS485 communication instead of a USB adapter, you have multiple options that keep Bluetooth working:

#### Option 1: Enable an Additional UART (Recommended)

Pi 4 and 5 support multiple UARTs (UART2-5). Enable an additional one while keeping Bluetooth on the primary UART:

Edit `/boot/firmware/config.txt` (or `/boot/config.txt`) and add:

```ini
# Enable UART
enable_uart=1

# Enable UART2 on GPIO pins 0 and 1
dtoverlay=uart2
```

After rebooting:
- Bluetooth continues to work on `/dev/ttyAMA0`
- UART2 is available on `/dev/ttyAMA1` (GPIO 0 = TX, GPIO 1 = RX)
- Sense line on GPIO 12 continues to work

Update your ModernJVS config:
```
DEVICE_PATH /dev/ttyAMA1
```

**Available UART overlays** (choose based on which GPIO pins you want to use):
```ini
dtoverlay=uart2  # Creates /dev/ttyAMA1 on GPIO 0,1
dtoverlay=uart3  # Creates /dev/ttyAMA2 on GPIO 4,5
dtoverlay=uart4  # Creates /dev/ttyAMA3 on GPIO 8,9
dtoverlay=uart5  # Creates /dev/ttyAMA4 on GPIO 12,13
```

> **Warning**: Do not use `uart5` if you're using GPIO 12 for the sense line, as they conflict. Choose `uart2`, `uart3`, or `uart4` instead.

#### Option 2: Move Bluetooth to Mini UART

This frees up the primary UART for RS485 while keeping Bluetooth functional:

Edit `/boot/firmware/config.txt` (or `/boot/config.txt`) and add:

```ini
# Enable UART
enable_uart=1

# Move Bluetooth to mini UART
dtoverlay=miniuart-bt
```

After rebooting:
- Bluetooth uses `/dev/ttyS0` (mini UART)
- Primary UART `/dev/ttyAMA0` is available for RS485
- Sense line on GPIO 12 continues to work

Update your ModernJVS config:
```
DEVICE_PATH /dev/ttyAMA0
```

> **Note**: The mini UART has reduced performance compared to the primary UART. Bluetooth will work, but may have slightly higher latency. This is fine for most Bluetooth controllers and peripherals.

### Verifying Bluetooth and Sense Line Work Together

After any configuration changes, verify that both Bluetooth and the sense line are working:

**Check Bluetooth status:**
```bash
systemctl status bluetooth
hcitool dev
```

**Check available serial devices:**
```bash
ls -l /dev/ttyAMA* /dev/ttyS* /dev/ttyUSB*
```

**Test GPIO access for sense line:**
```bash
# Check that GPIO chip is accessible
ls -l /dev/gpiochip*

# Start ModernJVS and check debug output for sense line initialization
sudo systemctl status modernjvs
```

### Troubleshooting

**If Bluetooth stops working:**
- Make sure you didn't add `dtoverlay=disable-bt` to config.txt
- Check that `systemctl status bluetooth` shows the service is running
- If using `miniuart-bt`, Bluetooth performance may be reduced but should still work

**If sense line stops working:**
- Verify GPIO 12 isn't being used by another overlay (especially `uart5`)
- Check that ModernJVS has permission to access `/dev/gpiochip*`
- Look at ModernJVS debug logs: `sudo journalctl -u modernjvs -f`

**Config file location:**
- Newer Raspberry Pi OS: `/boot/firmware/config.txt`
- Older Raspberry Pi OS: `/boot/config.txt`
- Always reboot after making changes

## Configuration

ModernJVS can be configured using the following command:
```
sudo nano /etc/modernjvs/config
```
Check the /etc/modernjvs/ios folder to see which I/O boards can be emulated and input the name of it on the EMULATE line.

By default it will emulate the Namco FCA1, as well as the debug level set to 1.


## Controller Deadzone Support

With version 4.6.2, configurable deadzone can now be changed in the config for each players controller. Only affects controllers with analog sticks as it's main use is to eliminate stick drift.

