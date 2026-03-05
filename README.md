# ![ModernJVS](docs/modernjvs2.png)

ModernJVS is fork of OpenJVS, an emulator for I/O boards in arcade machines that use the JVS protocol. It requires a USB RS485 converter.

Updated to use libgpiod for GPIO access, with support for the Raspberry Pi 5. Optimized code and new features.

As of v5.6.0, Sysfs support is no longer supported as no one should be running on old and outdated linux kernels.

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

Games with dedicated controller mapping profiles included out of the box:

- **Racing**: Initial D, Wangan Midnight Maximum Tune, Mario Kart Arcade GP, OutRun (+ Chihiro/Lindbergh variants), F355 Challenge, R-Tuned, Sega Race TV, Wild Riders, Harley Davidson King of the Road, Hummer, 18 Wheeler, Final Furlong 2
- **Shooting**: Time Crisis 2/3, House of the Dead 2/3/4, Virtua Cop 3, Ghost Squad, Rambo, Crisis Zone, Dream Raiders, Let's Go Island, Let's Go Jungle (+ Special), Transformers, Ninja Assault, Operation Ghost, Airline Pilots
- **Fighting**: Tekken, Virtua Fighter
- **Rhythm**: Taiko no Tatsujin (Taiko Drum Master) on Namco System 256
- **Other**: Crazy Taxi (+ High Roller), F-Zero AX, After Burner Climax, Alien Front, Jambo Safari, King of Route 66, Monkey Ball, Virtua Golf, and more

There are also four **generic profiles** that work for many unlisted games:
- `generic` – Basic arcade buttons (2 players, up to 6 buttons each)
- `generic-driving` – Steering wheel + pedals
- `generic-shooting` – Light gun (X/Y analogue axes)
- `generic-analogue` – Analogue joystick

Check the `/etc/modernjvs/games` folder after installation for game-specific controller mappings.

## Installation

Installation is done from the git repository as follows, using RaspiOS Lite:

```
sudo apt install -y build-essential cmake git file libgpiod-dev
git clone https://github.com/dazzaXx/ModernJVS
sudo make install
```

> **Note:** The WebUI is included by default and requires Python 3. Raspberry Pi OS Lite includes Python 3 out of the box, so no extra step is needed. Both the `modernjvs` and `modernjvs-webui` services are **automatically enabled and started** after installation.

If using DietPi:

```
sudo apt install -y build-essential cmake git file libgpiod-dev pkg-config python3
git clone https://github.com/dazzaXx/ModernJVS
sudo make install
```

### Installing without the WebUI

If you don't want the WebUI installed (e.g. on a minimal headless system), the recommended method is:

```
sudo make install-no-webui
```

This target always reconfigures cmake with `-DENABLE_WEBUI=OFF` before building, so it works correctly regardless of whether a build directory already exists. The `modernjvs` service is still automatically enabled and started (only `modernjvs-webui` is skipped).

Alternatively, you can pass the flag to the standard `install` target:

```
sudo make install WEBUI=OFF
```

This also always reconfigures cmake with the correct flag, so it works correctly even with an existing build directory.

### Installing without auto-enabling services

To install without automatically enabling and starting the systemd services:

```
sudo make install ENABLE_SERVICES=OFF
```

This applies to both `install` and `install-no-webui`. You can then enable the services manually later:

```
sudo make enable-services
```

`make enable-services` automatically detects whether the WebUI service was installed and only enables it if present. Alternatively, enable services directly with systemctl:

```
sudo systemctl enable --now modernjvs
# Only if the WebUI was installed:
sudo systemctl enable --now modernjvs-webui
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

Controllers support **hot-plugging** — they can be connected or disconnected at any time while ModernJVS is running and will be automatically detected without interrupting the JVS connection to the arcade board.

### Wii Remote Setup

Wii Remotes (Wiimotes) require Bluetooth support and the `hid-wiimote` kernel module (installed automatically by ModernJVS). On **Raspberry Pi 1–4** the internal Bluetooth adapter can conflict with USB Bluetooth dongles; run the included helper script once to disable the internal adapter:

```
sudo ./SetupUSBBluetooth.sh
```

> **Note:** This step is **not** needed on Raspberry Pi 5, which uses a different Bluetooth architecture.

Once Bluetooth is set up, pair Wii Remotes using the **Devices → Bluetooth Controllers** section of the WebUI: click **Scan for Devices**, then press the red **SYNC** button inside the battery compartment (or hold **1+2**) so the Wiimote is discoverable during the 8-second scan.

**Wiimote as a light gun:** The Wiimote uses its IR camera to report absolute X/Y screen coordinates, which are mapped to the game's analogue gun axes automatically using the `nintendo-wii-remote` device profile.

**Wii Remote + Nunchuk (combined):** When a Nunchuk is attached, ModernJVS automatically detects both devices and merges them into a single player slot using the `nintendo-wii-remote-plus-nunchuk` profile. No extra configuration is needed — the merge happens transparently at startup and on every hot-plug event.

### USB to RS485 Converter Requirements

**Important:** When buying a USB to RS485 dongle, be sure to buy one with an **FTDI chip** inside. The CP2102 and other chips have been found to not work well.

**Confirmed Working Chips:**
- FTDI-based converters (recommended)
- CH340E converters (tested by @dazzaXx)

### Wiring Setup

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

## WebUI

ModernJVS ships with a built-in web interface that you can access from any device on your local network. It works on both **Raspberry Pi OS** and **DietPi**.

### Features

- **Dashboard** – live service status with animated indicator (running/stopped), PID, uptime, current I/O board / game / device path, Start / Stop / Restart buttons. Includes a **JVS Overview** panel showing JVS connection status and a toggleable Test Mode button. A **Player Assignments** panel shows which controller is assigned to each player slot (up to 4 players). A **Pi System Usage** panel shows real-time CPU %, memory, CPU temperature, disk usage (with colour-coded progress bars) and load average. Local IP addresses are shown so you always know the URL to use from another device. The installed ModernJVS version is displayed in the header.
- **Configuration** – all key settings in a clean form: primary and secondary I/O board dropdowns (`EMULATE` / `EMULATE_SECOND`), game dropdown (all auto-populated from installed files), device path, sense line type and GPIO pin, debug mode, auto controller detection, and per-player analog deadzone (players 1–4). Saved directly to `/etc/modernjvs/config` with comments preserved. Includes **Save & Restart Service** and **Reset to Defaults** buttons.
- **Monitor & Logs** – live log tail (journalctl on Raspberry Pi OS / DietPi, with automatic fallback to syslog files if journald is not available). Features a **category filter dropdown** (All Messages / Errors & Critical / Warnings / JVS Activity / Controllers), a **live text search box**, auto-refresh every 5 s, configurable line count (50/100/200/500), a **Download Logs** button, and a dedicated **JVS Activity** pane. An **Audit Log** section records WebUI actions such as config changes, service restarts, logins, Bluetooth pairings, and profile edits.
- **Profiles** – a full in-browser editor for all profile file categories: **Games**, **Devices**, and **I/O Boards**. Browse, view, edit, create (+ New File), upload, rename, and delete files in `/etc/modernjvs/games`, `/etc/modernjvs/devices`, and `/etc/modernjvs/ios` without needing SSH access.
- **Devices** – shows all connected `/dev/input/event*` nodes and their human-readable device names (read from sysfs). Includes a **Bluetooth Controllers** section for pairing and removing Bluetooth controllers (including Wii Remotes) with an 8-second scan. Also includes a **Live Input Tester** that streams button presses and axis values from any connected controller in real time.
- **⚠ Diagnostics** – a suite of hardware troubleshooting tools:
  - *Serial Port Test* – open the JVS serial port at 115200 8N1 and confirm it is accessible.
  - *JVS Bus* – **Probe Bus** sends a `RESET` + `ASSIGN_ADDR` broadcast and listens for 2 s to confirm a live board; **Monitor Bus** passively listens for 5 s to show existing traffic. Both tools work whether or not the service is currently running.
  - *GPIO Sense Line Test* – read the current logic level of the configured GPIO pin, or manually drive it HIGH/LOW for a set duration to verify wiring with a multimeter.
  - *Available Serial Devices* – lists all `/dev/ttyUSB*`, `/dev/ttyAMA*`, and `/dev/ttyS*` nodes currently present.
  - *USB Device Inspector* – lists all connected USB devices from `/sys/bus/usb/devices/`, highlights known RS-485/serial adapters, and shows the bound kernel driver.
- **⚙ WebUI Settings** – personalise and secure the interface:
  - *Theme* – 14 colour themes: Pure Dark (default), Dark, Light, Midnight Blue, Dracula, Green Terminal, Ocean Deep, Sunset, Forest, Purple Night, Neon Cyan, Rose, Amber, Solarized Dark.
  - *Layout & Behaviour* – compact mode (reduced padding) and option to disable all CSS animations.
  - *Password Protection* – set a password to restrict access to the WebUI. Reset by removing `/etc/modernjvs/webui-password` via SSH.
  - *WebUI Process* – restart the WebUI service from the browser.
  - *System Power* – restart or shut down the Raspberry Pi directly from the browser.
  - *Active Sessions* – view all logged-in browsers (token shown as first 8 characters) and log out all other devices.

### Accessing the WebUI

Both the `modernjvs` and `modernjvs-webui` services are enabled and started automatically during `make install`. Open `http://<raspberry-pi-ip>:8080` in a browser on any device on your local network.

To check that the WebUI service is running:
```
sudo systemctl status modernjvs-webui
```

### Security

The WebUI **actively blocks connections from public (non-private) IP addresses**. Every request is checked against the private network ranges (RFC 1918, link-local, and loopback) before being served. Requests from public internet IPs receive a `403 Forbidden` response with an explanatory page — so even if the Raspberry Pi has a public-facing IP (e.g. directly connected to a modem), the WebUI remains inaccessible from the internet.

**Allowed networks:**

| Range | Covers |
|---|---|
| `127.0.0.0/8` | Loopback (`127.x.x.x`) |
| `10.0.0.0/8` | All `10.x.x.x` addresses |
| `172.16.0.0/12` | `172.16.x.x` – `172.31.x.x` |
| `192.168.0.0/16` | **All** `192.168.x.x` addresses — `192.168.0.x`, `192.168.1.x`, `192.168.50.x`, `192.168.100.x`, etc. |
| `169.254.0.0/16` | Link-local (APIPA) |
| `::1/128`, `fc00::/7`, `fe80::/10` | IPv6 loopback, ULA, link-local |

> **Common home/office routers** typically use `192.168.0.x`, `192.168.1.x`, or `192.168.50.x` — all of these are inside `192.168.0.0/16` and will be able to connect without any extra configuration.

The WebUI runs as root (required to control the `modernjvs` service and write `/etc/modernjvs/config`). It binds to all interfaces on port **8080** — only LAN devices can connect.

---

## Configuration

### Basic Setup

ModernJVS can be configured using the following command, or via the WebUI:
```
sudo nano /etc/modernjvs/config
```

### Key Configuration Options

**Emulate a specific I/O board:**
Check the `/etc/modernjvs/ios` folder to see which I/O boards can be emulated and input the name on the `EMULATE` line. By default it will emulate the Namco FCA1.

**Chain a second I/O board:**
Some arcade systems use two I/O boards. Set `EMULATE_SECOND` to the name of the second I/O board to chain it:
```
EMULATE namco-FCA1
EMULATE_SECOND sega-type-1
```

**Select a game profile:**
Set the `DEFAULT_GAME` line to match your game. Available profiles are in `/etc/modernjvs/games`. Examples:
- `generic` - Basic arcade controls
- `generic-driving` - Racing games with steering wheel support
- `generic-shooting` - Light gun games
- `generic-analogue` - Analogue joystick games
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

## Controller Deadzone Support

Configurable deadzone can be set in the config for each player's controller. Only affects controllers with analog sticks as it's primarily used to eliminate stick drift (unwanted movement from worn analog sticks).

By default it is set to 0.2 to eliminate the analog sticks from being too sensitive to input.

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
   - Connect sense line if required (GPIO 26 + resistor/diodes to GND)
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

## Command Line Reference

The `modernjvs` binary can be used as a daemon (via systemd) or directly from the command line.

```
modernjvs [options] [game]
```

| Option | Description |
|---|---|
| `modernjvs [game]` | Run with a specific game profile instead of the configured default |
| `modernjvs --list` | List all detected controllers (enabled, disabled, and unmapped) |
| `modernjvs --enable [device]` | Enable a specific controller mapping (or all if no name is given) |
| `modernjvs --disable [device]` | Disable a specific controller mapping (or all if no name is given) |
| `modernjvs --edit [file]` | Open a game or device mapping file in the system editor |
| `modernjvs --debug` | Start in debug mode (equivalent to `DEBUG_MODE 1`) |
| `modernjvs --version` | Print the installed version number |
| `modernjvs --help` | Print usage information |

**Disabling a controller:** Renaming a device file to `filename.disabled` tells ModernJVS to skip that controller even if it is plugged in. `--enable` and `--disable` automate this rename. This is useful when you have multiple controllers connected but only want some of them to be used.

## Troubleshooting

### Wii Remote not connecting
- Run `sudo ./SetupUSBBluetooth.sh` on Pi 1–4 to disable the **internal** Bluetooth adapter (which can conflict with USB dongles) and install the required packages — only needed once; Bluetooth functionality is not removed, only the built-in adapter
- Make sure the `hid-wiimote` and `hidp` kernel modules are loaded (`lsmod | grep wiimote`)
- Use the WebUI **Devices → Bluetooth Controllers → Scan** to pair; press the SYNC button (inside battery cover) or hold **1+2** during the scan
- Ensure `AUTO_CONTROLLER_DETECTION` is `1` so ModernJVS picks up the Wiimote once it's paired

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

**Q: Which I/O board should I emulate?**
A: Start with the default (namco-FCA1) or check online documentation for your specific arcade game. Most games work with multiple I/O board types.

**Q: Can I use wireless controllers?**
A: Yes! Standard Bluetooth gamepads (PlayStation, Xbox, 8BitDo, etc.) work once paired via the OS or the WebUI's Bluetooth section and appear as standard HID input devices. Wii Remotes require additional steps — see the **Wii Remote Setup** section above.

**Q: Does this work with MAME?**
A: No, ModernJVS is for real arcade hardware that uses JVS protocol. For MAME, map controllers directly in MAME's settings.

**Q: My game requires a specific I/O board not listed. What do I do?**
A: Try similar I/O boards (e.g., sega-type-1, sega-type-2, namco-FCA1) or open an issue on GitHub with your game details.

**Q: How do I add custom button mappings?**
A: Copy an existing profile from `/etc/modernjvs/games/` and modify it. Game profiles support:
- `INCLUDE other-profile` – inherit all mappings from another profile (e.g. `INCLUDE generic-driving`)
- `REVERSE` modifier on analogue axis lines – inverts the axis direction (e.g. `CONTROLLER_ANALOGUE_Y CONTROLLER_1 ANALOGUE_2 REVERSE`)
- Multiple output buttons on one line – press one input button and trigger two JVS buttons simultaneously (see `wangan-midnight-maximum-tune` for an example)

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

