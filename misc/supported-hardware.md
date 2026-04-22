# Supported Hardware

## Raspberry Pi Models

ModernJVS supports all Raspberry Pi models including:
- Raspberry Pi 1, 2, 3, 4 & 5
- Raspberry Pi Zero / Zero (2) W *(Not tested but should work fine.)*

## Controllers & Input Devices

ModernJVS automatically detects and supports a wide range of USB and Bluetooth controllers:
- **Game Controllers**: Xbox 360/One/Series, PlayStation 3/4/5, generic USB gamepads
- **Racing Wheels**: Logitech G25/G29/Momo, Thrustmaster wheels, Sidewinder wheels
- **Light Guns**: Aimtrak, Gun4IR, Wii Remote IR-based setups
- **Arcade Sticks**: Generic USB arcade sticks, Brook converters, Daija arcade stick
- **Wii Remote & Nunchuk**: Bluetooth Wii Remotes with optional Nunchuk (standalone or combined)
- **Keyboards & Mice**: For configuration and some game types

Check the `/etc/modernjvs/devices` folder after installation to see device-specific mappings.

## Hot-plug Controller Support

ModernJVS supports hot-plugging controllers while the service is running. A background watchdog thread monitors for changes to `/dev/input/` and automatically reinitializes the controller threads when devices are connected or disconnected — without resetting the JVS connection to the arcade board. This means you can plug in or unplug controllers without interrupting the arcade machine.

## USB to RS485 Converter Requirements

**Important:** When buying a USB to RS485 dongle, be sure to buy one with an **FTDI chip** inside. The CP2102 and other chips have been found to not work well.

**Confirmed Working Chips:**
- FTDI-based converters (recommended)
- CH340E converters (tested by @dazzaXx)

## Wiring Setup

For games that require a sense line, use the following wiring configuration:

```

|          GND   (BLACK) |-------------| GND           |                 |                        |
| ARCADE   A+    (GREEN) |-------------| A+  RS485 USB |-----------------| USB  RASPBERRY PI > 1  |
|          B-    (WHITE) |-------------| B-            |                 |                        |
|                        |                                               |                        |
|          SENSE (RED)   |----------+------------------------------------| GPIO 26                |
                                    |
                                    +---- (1kOhm Resistor or 4 Signal Diodes) ---- GND
```

A 1KOhm resistor or 4 signal diodes are known to work properly, the purpose of these is to create a 2.5 volt drop.

> **Warning:** A 1KOhm resistor will not work with the Triforce system, please use the 4 signal diodes for this purpose.

**What is the sense line?** The sense line is used by some arcade systems to detect when the cabinet is powered on. It helps synchronize communication between the arcade board and the I/O system.
