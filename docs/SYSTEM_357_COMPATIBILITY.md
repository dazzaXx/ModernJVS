# Namco System 357 Compatibility

ModernJVS is fully compatible with Namco System 357 arcade systems.

## Overview

The Namco System 357 is a PlayStation 3-based arcade platform used for games like Tekken 6, Time Crisis 4, Ace Combat 6, and other Namco arcade titles. It connects to JVS I/O boards via a USB-to-JVS interface to handle arcade controls.

## JVS Protocol Support

ModernJVS implements the complete JVS protocol required by System 357:

### Standard JVS Commands
- ✅ CMD_RESET (0xF0) - Reset bus
- ✅ CMD_ASSIGN_ADDR (0xF1) - Assign device address
- ✅ CMD_SET_COMMS_MODE (0xF2) - Set communications mode
- ✅ CMD_REQUEST_ID (0x10) - Request device ID string
- ✅ CMD_COMMAND_VERSION (0x11) - Get command format version
- ✅ CMD_JVS_VERSION (0x12) - Get JVS version
- ✅ CMD_COMMS_VERSION (0x13) - Get communications version
- ✅ CMD_CAPABILITIES (0x14) - Get device capabilities
- ✅ CMD_CONVEY_ID (0x15) - Receive main board ID
- ✅ CMD_READ_SWITCHES (0x20) - Read button/switch inputs
- ✅ CMD_READ_COINS (0x21) - Read coin counter
- ✅ CMD_READ_ANALOGS (0x22) - Read analog inputs
- ✅ CMD_READ_LIGHTGUN (0x25) - Read light gun position
- ✅ CMD_WRITE_GPO (0x32) - Write general purpose outputs
- ✅ CMD_WRITE_COINS (0x35) - Add to coin counter
- ✅ CMD_DECREASE_COINS (0x30) - Decrease coin counter

### Namco-Specific Commands
- ✅ CMD_NAMCO_SPECIFIC (0x70) - Namco manufacturer extensions
  - Sub-command 0x01: Read 8 bytes of memory
  - Sub-command 0x02: Read program date
  - Sub-command 0x03: Read DIP switch status
  - Sub-command 0x04: Unknown (returns 2 bytes)
  - Sub-command 0x18: ID check

## Supported I/O Boards

### 1. Namco NA-JV (Primary System 357 Board)

Configuration: `EMULATE namco-na-jv`

Specifications:
- JVS Version: 0x30 (48 decimal)
- Command Version: 0x13 (19 decimal)
- Communications Version: 0x10 (16 decimal)
- Players: 1
- Switches: 24
- Coin Slots: 2
- Analog Channels: 8 (16-bit resolution)
- Gun Channels: 1 (16-bit X/Y)
- General Purpose Outputs: 18

This is the standard multipurpose I/O board used with System 357 for most games.

### 2. Namco RAYS PCB (Gun Games)

Configuration: `EMULATE namco-rays`

Specifications:
- JVS Version: 0x20 (32 decimal)
- Command Version: 0x11 (17 decimal)
- Communications Version: 0x10 (16 decimal)
- Players: 1
- Switches: 12
- Coin Slots: 1
- Gun Channels: 1 (16-bit X/Y with camera-based IR tracking)
- General Purpose Outputs: 16

Used for gun games like Time Crisis 3 and Crisis Zone on System 357.

## Hardware Setup

### Required Hardware
1. Raspberry Pi (any model, Pi 5 supported)
2. USB RS485 converter (FTDI chip recommended, CH340E also works)
3. Connection to System 357 JVS input (A+/B-/GND)
4. Optional: Sense line connection (GPIO 12 by default)

### Wiring
```
System 357 JVS    RS485 USB       Raspberry Pi
    GND   -------- GND   --------- (via USB)
    A+    -------- A+    --------- (via USB)
    B-    -------- B-    --------- (via USB)
    SENSE -------------------- GPIO 12 (optional, with 1kΩ resistor to GND)
```

**Note about SENSE line:**  
The SENSE line is used for JVS device detection. When the arcade system powers on, it checks this line to detect if a JVS I/O board is connected. ModernJVS controls this GPIO pin to signal its presence. Connection is optional - if not connected, the arcade system may still work but detection timing may vary. The 1kΩ resistor (or 4 signal diodes) creates the required voltage drop.

## Configuration

### Basic Configuration

Edit `/etc/modernjvs/config`:
```
# For standard System 357 games
EMULATE namco-na-jv

# For gun games (Time Crisis 3, Crisis Zone)
EMULATE namco-rays

# Default settings
DEVICE_PATH /dev/ttyUSB0
DEBUG_MODE 1
```

### Game-Specific Mappings

Example for Tekken 6:
```
DEFAULT_GAME tekken-6
EMULATE namco-na-jv
```

Example for Time Crisis 3:
```
DEFAULT_GAME time-crisis-3-rays
EMULATE namco-rays
```

## Light Gun Support

System 357 gun games work with various light gun devices:

- **Wiimote** - Via Mayflash adapter or similar
- **Gun4IR** - DIY IR light gun with analog tracking
- **USB Light Guns** - Any device providing analog X/Y position

The RAYS board provides 16-bit gun input resolution for precise aiming.

See the main README for light gun device configuration details.

## Troubleshooting

### System 357 doesn't detect I/O board
1. Check RS485 wiring (A+, B-, GND)
2. Verify correct device path (`/dev/ttyUSB0`)
3. Ensure sense line is connected if required
4. Check debug output: `sudo modernjvs` with DEBUG_MODE 2

### Games won't start
1. Verify correct I/O board is emulated (namco-na-jv for most games)
2. Check that game mapping file exists for your game
3. Confirm controller is connected and mapped

### Gun position not working
1. Verify EMULATE namco-rays is set for gun games
2. Check light gun device mapping to CONTROLLER_ANALOGUE_X/Y
3. Test gun position with DEBUG_MODE 2 to see analog values

## Technical Notes

### Protocol Details
- ModernJVS uses standard RS485 communication at 115200 baud
- JVS protocol uses SYNC byte (0xE0) for packet start
- ESCAPE byte (0xD0) for byte stuffing
- Checksum verification on all packets
- Broadcast address (0xFF) supported for initial device detection

### Version Numbers
The version numbers reported by ModernJVS match real Namco hardware:
- Command Version: BCD format (e.g., 0x13 = version 1.3)
- JVS Version: BCD format (e.g., 0x30 = version 3.0)
- Comms Version: BCD format (e.g., 0x10 = version 1.0)

### Compatibility
ModernJVS has been tested and verified compatible with:
- Namco System 357 arcade boards
- Standard JVS protocol requirements
- Namco-specific command extensions
- Light gun input for gun games

## Related Documentation

- Main README.md - Installation and basic setup
- docs/modernjvs/ios/ - All I/O board configurations
- docs/modernjvs/games/ - Game-specific mappings
- docs/modernjvs/devices/ - Controller device mappings
