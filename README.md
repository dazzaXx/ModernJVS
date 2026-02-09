![ModernJVS](docs/modernjvs2.png)

# ModernJVS

ModernJVS is fork of OpenJVS, an emulator for I/O boards in arcade machines that use the JVS protocol. It requires a USB RS485 converter, or an official OpenJVS HAT.

Updated to use libgpiod, with backwards-compatible support for the now deprecated sysfs. Optimized code and new features, as well as support for the Raspberry Pi 5.

All code is tested vigorously by me personally to make sure it actually works and is secure.
I'm not some master coder nor would I claim to be, Copilot does the majority of the heavy lifting when updating and fixing bugs, adding in new features.

Thank you to the team responsible for making OpenJVS in the first place. ❤️

## What is JVS?

JVS (JAMMA Video Standard) is a standard for connecting I/O boards to arcade systems. Modern arcade machines use JVS to communicate between the game motherboard and the control panel hardware (buttons, joysticks, steering wheels, light guns, etc.). ModernJVS allows you to use a Raspberry Pi and modern USB controllers (like Xbox, PlayStation, or PC controllers) in place of traditional arcade hardware.

## Use Cases

- **Home Arcade Builds**: Connect modern controllers to arcade PCBs without expensive original control panels
- **Arcade Cabinet Restoration**: Replace faulty or missing I/O boards with a Raspberry Pi solution
- **Game Testing & Development**: Test arcade games with various controller configurations
- **Multi-Game Setups**: Switch between different arcade systems using a single control setup

## Supported Arcade Systems

ModernJVS supports a wide range of arcade hardware platforms:

**Sega Systems:**
- Naomi 1/2
- Triforce
- Chihiro
- Hikaru
- Lindbergh
- Ringedge 1/2

**Namco Systems:**
- System 22/23
- System 256/246 and related platforms
- System 357 (Should also theoretically work with 369's too.)

**Other Platforms:**
- Taito Type X+
- Taito Type X2
- exA-Arcadia

## Popular Games Supported

Some examples of games that work with ModernJVS:
- **Racing**: Initial D, Wangan Midnight Maximum Tune, Mario Kart Arcade GP, Daytona USA, OutRun
- **Shooting**: Time Crisis series, House of the Dead series, Virtua Cop 3, Ghost Squad
- **Fighting**: Tekken series, Virtua Fighter
- **Rhythm**: Taiko no Tatsujin (Taiko Drum Master) on Namco System 256
- **Other**: Crazy Taxi, F-Zero AX, and many more

Check the `/etc/modernjvs/games` folder after installation for game-specific controller mappings.

## Installation

Installation is done from the git repository as follows, using RaspiOS Lite:

```
sudo apt install -y build-essential cmake git file libgpiod-dev
git clone https://github.com/dazzaXx/ModernJVS
make
sudo make install
```

If using DietPi:

```
sudo apt install -y build-essential cmake git file libgpiod-dev pkg-config
git clone https://github.com/dazzaXx/ModernJVS
make
sudo make install
```

## Supported Hardware

### Raspberry Pi Models
ModernJVS supports all Raspberry Pi models including:
- Raspberry Pi 1, 2, 3, 4
- Raspberry Pi 5 (with automatic GPIO chip detection)
- Raspberry Pi Zero/Zero W (may have performance limitations on demanding games)

The software automatically detects the correct GPIO chip for your Raspberry Pi model.

### Controllers & Input Devices
ModernJVS automatically detects and supports a wide range of USB controllers:
- **Game Controllers**: Xbox 360/One, PlayStation 3/4/5, generic USB gamepads
- **Racing Wheels**: Logitech G25/G29, Thrustmaster wheels, generic racing wheels
- **Light Guns**: Aimtrak, Gun4IR, Wiimote-based setups
- **Arcade Sticks**: Generic USB arcade sticks, Brook converters
- **Keyboards & Mice**: For configuration and some game types

Check the `/etc/modernjvs/devices` folder after installation to see device-specific mappings.

### USB to RS485 Converter Requirements

**Important:** When buying a USB to RS485 dongle, be sure to buy one with an **FTDI chip** inside. The CP2102 and other chips have been found to not work well.

**Confirmed Working Chips:**
- FTDI-based converters (recommended)
- CH340E converters (tested by @dazzaXx)

### Wiring Setup

For games that require a sense line, use the following wiring configuration:

**Raspberry Pi 1-4:**
```

|          GND   (BLACK) |-------------| GND           |                 |                        |
| ARCADE   A+    (GREEN) |-------------| A+  RS485 USB |-----------------| USB  RASPBERRY PI 1-4  |
|          B-    (WHITE) |-------------| B-            |                 |                        |
|                        |                                               |                        |
|          SENSE (RED)   |----------+------------------------------------| GPIO 12                |
                                    |
                                    +---- (1kOhm Resistor or 4 Signal Diodes) ---- GND
```

**Raspberry Pi 5:**
```

|          GND   (BLACK) |-------------| GND           |                 |                        |
| ARCADE   A+    (GREEN) |-------------| A+  RS485 USB |-----------------| USB  RASPBERRY PI 5    |
|          B-    (WHITE) |-------------| B-            |                 |                        |
|                        |                                               |                        |
|          SENSE (RED)   |----------+------------------------------------| GPIO 26                |
                                    |
                                    +---- (1kOhm Resistor or 4 Signal Diodes) ---- GND
```

A 1KOhm resistor or 4 signal diodes are known to work properly, the purpose of these is to create a 2.5 volt drop.

> **Warning:** A 1KOhm resistor will not work with the Triforce system, please use the 4 signal diodes for this purpose.

> **Note for Raspberry Pi 5 users:** GPIO 26 is used by default instead of GPIO 12 to avoid PWM hardware conflicts. GPIO 12, 13, 18, and 19 share PWM resources on the Pi 5's RP1 chip, which can cause unreliable sense line behavior. If you need to use GPIO 12, you can override this by setting `SENSE_LINE_PIN 12` in your config file, though GPIO 26 is strongly recommended.

**What is the sense line?** The sense line is used by some arcade systems to detect when the cabinet is powered on. It helps synchronize communication between the arcade board and the I/O system.

## Configuration

### Basic Setup

ModernJVS can be configured using the following command:
```
sudo nano /etc/modernjvs/config
```

### Key Configuration Options

**Emulate a specific I/O board:**
Check the `/etc/modernjvs/ios` folder to see which I/O boards can be emulated and input the name on the `EMULATE` line. By default it will emulate the Namco FCA1.

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
- `SENSE_LINE_TYPE 2` - Raspberry Pi OpenJVS HAT

**Device Path:**
- Usually `/dev/ttyUSB0` for USB RS485 converters
- May be `/dev/ttyUSB1` if you have multiple USB serial devices

## Controller Deadzone Support

Configurable deadzone can be set in the config for each player's controller. Only affects controllers with analog sticks as it's primarily used to eliminate stick drift (unwanted movement from worn analog sticks).

**Configuration:**
```
ANALOG_DEADZONE_PLAYER_1 0.2  # 20% deadzone for player 1
ANALOG_DEADZONE_PLAYER_2 0.15 # 15% deadzone for player 2
```

Valid range: 0.0 to 0.5 (0.0 = no deadzone, 0.1 = 10% deadzone, etc.)

## Quick Start Guide

1. **Install ModernJVS** (see Installation section above)
2. **Connect hardware:**
   - Plug USB RS485 converter into Raspberry Pi
   - Connect RS485 converter to arcade board (GND, A+, B-)
   - Connect sense line if required (GPIO 12 for Pi 1-4, GPIO 26 for Pi 5 + resistor/diodes to GND)
   - Connect USB/Bluetooth controllers to Raspberry Pi
3. **Configure:**
   ```
   sudo nano /etc/modernjvs/config
   ```
   - Set `EMULATE` to match your arcade board's I/O
   - Set `DEFAULT_GAME` for your specific game or use a generic profile
   - Set `SENSE_LINE_TYPE` based on your wiring
4. **Start ModernJVS:**
   ```
   sudo systemctl start modernjvs
   ```
5. **Enable auto-start on boot:**
   ```
   sudo systemctl enable modernjvs
   ```
6. **Check status:**
   ```
   sudo systemctl status modernjvs
   ```
7. **View logs for troubleshooting:**
   ```
   sudo journalctl -u modernjvs -f
   ```

## Troubleshooting

### ModernJVS not detecting controllers
- Ensure `AUTO_CONTROLLER_DETECTION` is set to `1` in config
- Check if the controller appears in `/dev/input/` with `ls /dev/input/`
- Try unplugging and replugging the controller
- Check logs: `sudo journalctl -u modernjvs -f`

### Arcade board not communicating
- Verify wiring connections (GND, A+, B-)
- Check that RS485 converter is recognized: `ls /dev/ttyUSB*`
- If multiple USB serial devices exist, try `/dev/ttyUSB1` instead of `/dev/ttyUSB0`
- Ensure correct `SENSE_LINE_TYPE` is configured
- For Triforce systems, ensure you're using diodes, not a resistor

### Buttons not responding correctly
- Verify you're using the correct game profile for your game
- Check the mapping file in `/etc/modernjvs/games/your-game`
- Try the `generic` profile first to test basic functionality
- Some games require specific I/O board emulation

### Analog stick drift or incorrect calibration
- Adjust `ANALOG_DEADZONE_PLAYER_X` values in config (try 0.15-0.25 for drift issues)
- Test with different controllers to rule out hardware issues

### Service won't start
- Check logs for detailed error messages: `sudo journalctl -u modernjvs -xe`
- Verify config file exists: `ls -la /etc/modernjvs/config`
- Verify permissions: `sudo chmod 644 /etc/modernjvs/config`
- Try running in debug mode: `sudo modernjvs --debug`

## FAQ

**Q: Do I need the OpenJVS HAT or can I use a USB RS485 converter?**
A: Both work! USB RS485 converters are cheaper and easier to find. The HAT provides integrated sense line support.

**Q: Which I/O board should I emulate?**
A: Start with the default (namco-FCA1) or check online documentation for your specific arcade game. Most games work with multiple I/O board types.

**Q: Can I use wireless controllers?**
A: Yes! Bluetooth controllers work as long as they appear as standard USB HID devices to Linux.

**Q: Does this work with MAME?**
A: No, ModernJVS is for real arcade hardware that uses JVS protocol. For MAME, map controllers directly in MAME's settings.

**Q: My game requires a specific I/O board not listed. What do I do?**
A: Try similar I/O boards (e.g., sega-type-1, sega-type-2, namco-FCA1) or open an issue on GitHub with your game details.

**Q: How do I add custom button mappings?**
A: Copy an existing profile from `/etc/modernjvs/games/` and modify it. See existing files for syntax examples.

## Taiko no Tatsujin (Taiko Drum Master) Support

ModernJVS **is capable** of emulating the I/O requirements for Taiko no Tatsujin games on Namco System 256. Here's what you need to know:

### Hardware Requirements

Taiko drums require **8 analog input channels** (4 per player):
- Each player's drum has 4 zones: Left Don (center), Right Don (center), Left Ka (rim), Right Ka (rim)
- Player 1 uses analog channels 0-3
- Player 2 uses analog channels 4-7

### Compatible I/O Boards

Use one of these I/O board configurations:
- **namco-taiko** - Dedicated Taiko configuration (recommended)
- **namco-na-jv** - Alternative, supports 8 analog channels at 16-bit resolution

### Setup Instructions

1. Set your I/O board emulation in `/etc/modernjvs/config`:
   ```
   EMULATE namco-taiko
   ```

2. Set the game profile:
   ```
   DEFAULT_GAME taiko-no-tatsujin
   ```

3. **Choose your input method:**

   **Option A: Authentic arcade drum hardware**
   - Connect drum sensor outputs to analog channels 0-7 via appropriate ADC interface
   - Each drum zone's piezo sensor should output to its corresponding analog channel
   - Provides analog hit strength detection for the most accurate arcade experience

   **Option B: Standard controllers (gamepads, arcade sticks, keyboard)**
   - Works with any USB controller out of the box
   - Don (center): Face buttons (A/B) or D-pad Left/Right
   - Ka (rim): Shoulder buttons or D-pad Up/Down
   - Perfect for home play and accessible to everyone

### Technical Details

- **Analog resolution**: 16-bit (0-65535 range) for accurate hit strength detection
- **Input type**: Analog voltage from piezo/vibration sensors
- **Players supported**: 2 players (8 total analog channels)
- **Additional buttons**: Start, Service, Coin per player

### Notes

- **Arcade drum hardware**: Original arcade drums use piezo sensors that output analog voltage, allowing the game to detect hit strength and distinguish between Don (center) and Ka (rim) hits. For DIY builds, consider using projects like Taiko-256 or DonCon2040 that provide proper analog signal conditioning.
- **Standard controller support**: The game is fully playable with standard gamepads, arcade sticks, or keyboards using the digital button mappings. This provides an accessible way to play without specialized drum hardware.

## Additional Resources

- **Configuration Files:** `/etc/modernjvs/config` - Main configuration
- **Game Profiles:** `/etc/modernjvs/games/` - Controller mappings per game
- **I/O Board Definitions:** `/etc/modernjvs/ios/` - Emulated I/O board specifications
- **Device Mappings:** `/etc/modernjvs/devices/` - Controller-specific mappings

## Contributing

Issues and pull requests welcome! If you have a game-specific configuration that works well, please consider contributing it back to the project.

## License

See LICENSE.md for license information.

