# Configuration

## Basic Setup

ModernJVS can be configured using the following command, or via the WebUI:
```
sudo nano /etc/modernjvs/config
```

## Key Configuration Options

**Emulate a specific I/O board:**
Check the `/etc/modernjvs/ios` folder to see which I/O boards can be emulated and input the name on the `EMULATE` line. By default it will emulate the Namco FCA1.

**Supported I/O boards:**

| Name | Display Name |
|---|---|
| `namco-FCA1` | Namco FCA-1 *(default)* |
| `namco-na-jv` | Namco NA-JV |
| `namco-na-jv2` | Namco NA-JV2 |
| `namco-v185` | Namco V185 IO (Time Crisis 2) |
| `namco-v221` | Namco V221 MIU (Crisis Zone) |
| `namco-v222` | Namco V222 JYU (Ninja Assault) |
| `namco-v329` | Namco V329 NA-JV (Time Crisis 4) |
| `namco-jyu` | Namco JYU IO |
| `namco-rays-v100` | Namco RAYS Gun IO |
| `namco-rays-v106` | Namco RAYS PCB |
| `namco-taiko` | Namco Taiko (System 256) |
| `sega-type-1` | Sega Type 1 IO |
| `sega-type-2` | Sega Type 2 IO |
| `sega-type-3` | Sega Type 3 IO |
| `sega-838-13683B` | Sega 838-13683B IO |
| `sega-trackball` | Sega Trackball IO |
| `capcom-naomi` | Capcom NAOMI IO |
| `taito-type-x` | Taito Type X IO |
| `nrc-lion` | NRC LION-Board |

**Chaining two I/O boards:**
Some arcade systems enumerate two I/O boards on a single JVS bus. Use `EMULATE_SECOND` to specify a second I/O board to chain after the first:
```
EMULATE namco-FCA1
EMULATE_SECOND sega-type-1
```

**Select a game profile:**
Set the `DEFAULT_GAME` line to match your game. Available profiles are in `/etc/modernjvs/games`. Examples:
- `generic` - Basic arcade controls
- `generic-driving` - Racing games with steering wheel support
- `generic-shooting` - Light gun games
- Game-specific profiles like `initial-d`, `time-crisis-2`, `outrun`, etc.

**Debug Mode:**
- `DEBUG_MODE 1` - Shows JVS outputs (useful for troubleshooting)
- `DEBUG_MODE 2` - Shows raw packet outputs (advanced debugging)

**Sense Line Configuration:**
- `SENSE_LINE_TYPE 0` - USB to RS485 with no sense line
- `SENSE_LINE_TYPE 1` - USB to RS485 with sense line (most common)

**Device Path:**
- Usually `/dev/ttyUSB0` for USB RS485 converters
- May be `/dev/ttyUSB1` if you have multiple USB serial devices

**Wii Remote IR Scale:**
Controls how far the IR cursor travels across the screen per physical movement. Values above 1.0 extend the reachable area so that corners and edges are reachable; values below 1.0 reduce sensitivity.

```
WII_IR_SCALE 1.3  # cursor travels ~30% further per movement
```

Valid range: `0.1` to `5.0` (default `1.0` = no scaling).

## Controller Deadzone Support

Configurable deadzone can be set in the config for each player's controller. Only affects controllers with analog sticks as it's primarily used to eliminate stick drift (unwanted movement from worn analog sticks).

By default it is set to 0.2 to eliminate the analog sticks from being too sensitive to input.

**Configuration:**
```
ANALOG_DEADZONE_PLAYER_1 0.2  # 20% deadzone for player 1
ANALOG_DEADZONE_PLAYER_2 0.15 # 15% deadzone for player 2
```

Valid range: 0.0 to 0.5 (0.0 = no deadzone, 0.1 = 10% deadzone, etc.)

## Additional Resources

- **Configuration Files:** `/etc/modernjvs/config` - Main configuration
- **Game Profiles:** `/etc/modernjvs/games/` - Controller mappings per game
- **I/O Board Definitions:** `/etc/modernjvs/ios/` - Emulated I/O board specifications
- **Device Mappings:** `/etc/modernjvs/devices/` - Controller-specific mappings
