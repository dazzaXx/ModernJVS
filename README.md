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

Some examples of games that work with ModernJVS:
- **Racing**: Initial D, Wangan Midnight Maximum Tune, Mario Kart Arcade GP, Daytona USA, OutRun, R-Tuned, F-355 Challenge, F-Zero AX, Sega Race TV, 18 Wheeler
- **Shooting**: Time Crisis 2/3, Crisis Zone, House of the Dead 2/3/4, Virtua Cop 3, Ghost Squad, Operation Ghost, Rambo, Ninja Assault, Let's Go Jungle, Alien Front, Transformers Human Alliance
- **Fighting**: Tekken series
- **Rhythm**: Taiko no Tatsujin (Taiko Drum Master) on Namco System 256
- **Other**: Crazy Taxi, After Burner Climax, Virtua Golf, Monkey Ball, Dream Raiders, Jambo Safari, and many more

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
ModernJVS automatically detects and supports a wide range of USB and Bluetooth controllers:
- **Game Controllers**: Xbox 360/One/Series, PlayStation 3/4/5, generic USB gamepads
- **Racing Wheels**: Logitech G25/G29/Momo, Thrustmaster wheels, Sidewinder wheels
- **Light Guns**: Aimtrak, Gun4IR, Wii Remote IR-based setups
- **Arcade Sticks**: Generic USB arcade sticks, Brook converters, Daija arcade stick
- **Wii Remote & Nunchuk**: Bluetooth Wii Remotes with optional Nunchuk (standalone or combined)
- **Keyboards & Mice**: For configuration and some game types

Check the `/etc/modernjvs/devices` folder after installation to see device-specific mappings.

### Hot-plug Controller Support

ModernJVS supports hot-plugging controllers while the service is running. A background watchdog thread monitors for changes to `/dev/input/` and automatically reinitializes the controller threads when devices are connected or disconnected — without resetting the JVS connection to the arcade board. This means you can plug in or unplug controllers without interrupting the arcade machine.

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

- **Dashboard** – live service status with animated indicator (running/stopped), PID, uptime, current I/O board / game / device path, Start / Stop / Restart buttons. Includes a **Pi System Usage** panel showing real-time CPU %, memory, CPU temperature, disk usage (with colour-coded progress bars) and load average. Local IP addresses are shown so you always know the URL to use from another device. The installed ModernJVS version is displayed in the header.
- **Configuration** – all key settings in a clean form: I/O board and game dropdowns (auto-populated from installed files), device path, sense line type and GPIO pin, debug mode, auto controller detection, and per-player analog deadzone. Saved directly to `/etc/modernjvs/config` with comments preserved.
- **Monitor & Logs** – live log tail (journalctl on Raspberry Pi OS / DietPi, with automatic fallback to syslog files if journald is not available). Features a **category filter dropdown** (All / Errors & Critical / Warnings / JVS Activity / Controllers), a **live text search box**, auto-refresh every 5 s, configurable line count, a **Download Logs** button, and a dedicated **JVS Activity** pane.
- **Devices** – shows all connected `/dev/input/event*` nodes and their human-readable device names (read from sysfs). Includes a live **Input Tester** that streams raw button/axis events from any input device in real time — useful for confirming controller mappings before starting the service.
- **Bluetooth** – scan for nearby Bluetooth devices, pair/unpair controllers (including Wii Remotes, Xbox wireless controllers, and other HID devices), and view currently paired devices with connection status. Wii Remotes are automatically identified and handled with appropriate pairing logic.
- **Profiles** – view, edit, upload, download, delete, and rename game profiles, device mappings, and I/O board definitions. Supports uploading custom profile files directly from the browser.
- **Diagnostics** – serial port tester (lists available `/dev/ttyUSB*` and `/dev/ttyAMA*` ports and runs a connection test), JVS probe and packet monitor, GPIO pin control tester, and a USB device viewer.
- **System** – reboot, shutdown, and WebUI service restart buttons accessible from the dashboard.

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

**Optional password protection:** The WebUI supports an optional password to restrict access on your local network. When set, all pages (except the login form itself) require authentication before they can be accessed. Session tokens are stored as cookies and expire after inactivity. An audit log records login attempts and key actions. Password management and session control are available from the WebUI settings page.

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

## Using ModernJVS

This section covers day-to-day operation once ModernJVS is installed.

### Service Management

After installation the `modernjvs` service starts automatically on every boot. The most common service commands:

```bash
# Check whether the service is running
sudo systemctl status modernjvs

# Start / stop / restart the service
sudo systemctl start   modernjvs
sudo systemctl stop    modernjvs
sudo systemctl restart modernjvs

# Follow the live log output (Ctrl+C to quit)
sudo journalctl -u modernjvs -f

# Show the last 50 log lines
sudo journalctl -u modernjvs -n 50
```

### Switching Games

**Option 1 – edit the config file (persistent):**
```bash
sudo nano /etc/modernjvs/config
# Change: DEFAULT_GAME initial-d
sudo systemctl restart modernjvs
```

**Option 2 – pass the game name as an argument (one-off):**
```bash
sudo modernjvs initial-d
```
This overrides `DEFAULT_GAME` for that single run without touching the config file.

**Option 3 – use the template service (systemd, persistent per-game instances):**

The installed `modernjvs@.service` template lets you start a named instance for a specific game. The instance name is passed as the game argument automatically:

```bash
# Start ModernJVS using the "initial-d" game profile
sudo systemctl start  modernjvs@initial-d

# Auto-start on boot
sudo systemctl enable modernjvs@initial-d

# Stop the named instance
sudo systemctl stop   modernjvs@initial-d
```

> **Note:** Make sure the default `modernjvs` service is stopped first if it is running, to avoid conflicts on the RS485 port.

### Command-Line Reference

Running `modernjvs` without arguments starts the daemon using the settings in `/etc/modernjvs/config`.

| Command | Description |
|---------|-------------|
| `modernjvs` | Start the daemon (uses config defaults) |
| `modernjvs <game>` | Start the daemon with a specific game profile |
| `modernjvs --debug` | Start in debug mode (shows JVS outputs, equivalent to `DEBUG_MODE 1`) |
| `modernjvs --list` | List all detected controllers (enabled / disabled / no mapping) |
| `modernjvs --enable <controller>` | Enable a previously disabled controller mapping |
| `modernjvs --disable <controller>` | Disable a specific controller mapping (adds `.disabled` suffix) |
| `modernjvs --enable` | Re-enable **all** controller mappings |
| `modernjvs --disable` | Disable **all** controller mappings |
| `modernjvs --edit <profile>` | Open a game or device profile in your default editor |
| `modernjvs --version` | Print the installed version |
| `modernjvs --help` | Print usage information |

**Examples:**

```bash
# See which controllers are detected and whether they have a mapping
sudo modernjvs --list

# Run in debug mode to see real-time JVS packet activity
sudo modernjvs --debug

# Disable a specific controller temporarily (e.g. a keyboard that interferes)
sudo modernjvs --disable at-translated-set-2-keyboard

# Re-enable it
sudo modernjvs --enable at-translated-set-2-keyboard

# Open the generic-driving game profile in your editor
sudo modernjvs --edit generic-driving

# Run a one-off session for a specific game (daemon stays in the foreground)
sudo modernjvs crazy-taxi
```

### Enabling the Software Test Button

The arcade test menu is normally accessed by pressing a hardware button wired to the test input. ModernJVS also supports a **software test button** activated by sending `SIGUSR1` to the daemon:

```bash
# Toggle the software test button on/off
sudo kill -USR1 $(systemctl show -p MainPID --value modernjvs)
```

Each `SIGUSR1` toggles the test button state. Send it once to open the test menu, send it again to release it. The WebUI can also do this from the **Dashboard** tab without needing a command line.

### Running Multiple Instances (Multi-Board Setups)

Some setups need two RS485 ports — for example a main board and a satellite cabinet. Use the template service with different configuration files:

1. Create a second config file:
   ```bash
   sudo cp /etc/modernjvs/config /etc/modernjvs/config-satellite
   sudo nano /etc/modernjvs/config-satellite
   # Change DEVICE_PATH to /dev/ttyUSB1 and adjust EMULATE / DEFAULT_GAME
   ```

2. Start both instances (the template service passes the instance name as the game argument, so use the argument form for simple overrides, or edit the service file for full config-file overrides):
   ```bash
   sudo systemctl start modernjvs           # primary board on ttyUSB0
   sudo systemctl start modernjvs@satellite # runs: modernjvs satellite
   ```

### Verifying Controller Input

Before starting a game session, use the WebUI's **Devices → Input Tester** to confirm that button presses and axis movements are being picked up correctly. Alternatively, from the command line:

```bash
# List /dev/input nodes and their names
ls /dev/input/by-id/

# Show raw events from a specific input device
sudo evtest /dev/input/event0
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

**Q: Which I/O board should I emulate?**
A: Start with the default (namco-FCA1) or check online documentation for your specific arcade game. Most games work with multiple I/O board types.

**Q: Can I use wireless controllers?**
A: Yes! Bluetooth controllers work as long as they appear as standard USB HID devices to Linux. Wii Remotes have dedicated support — see the [Wii Remote & Nunchuk Support](#wii-remote--nunchuk-support) section.

**Q: Can I use a Wii Remote as a light gun?**
A: Yes. Pair the Wii Remote via the WebUI Bluetooth tab (or manually with `bluetoothctl`), then use the `generic-shooting` game profile or a game-specific shooting profile. The IR camera's screen coordinates are automatically mapped to analogue axes.

**Q: Does this work with MAME?**
A: No, ModernJVS is for real arcade hardware that uses JVS protocol. For MAME, map controllers directly in MAME's settings.

**Q: My game requires a specific I/O board not listed. What do I do?**
A: Try similar I/O boards (e.g., sega-type-1, sega-type-2, namco-FCA1) or open an issue on GitHub with your game details.

**Q: How do I add custom button mappings?**
A: Copy an existing profile from `/etc/modernjvs/games/` and modify it. See existing files for syntax examples. You can also use the WebUI **Profiles** tab to view, edit, and upload profiles directly from your browser.

**Q: Can I chain two I/O boards?**
A: Yes. Add `EMULATE_SECOND <io-name>` to `/etc/modernjvs/config` to chain a second I/O board after the primary one. See the [Key Configuration Options](#key-configuration-options) section.

## Wii Remote & Nunchuk Support

ModernJVS has built-in support for Nintendo Wii Remotes (with or without a Nunchuk attachment) over Bluetooth. Wii Remotes can be used as light guns (via IR pointing) or as general game controllers.

### Kernel Module

The `hid-wiimote` kernel module is required and is automatically configured during installation — a module loader file is written to `/etc/modules-load.d/wiimote.conf` so the module loads on every boot. No manual setup is needed.

### Bluetooth Pairing

The easiest way to pair a Wii Remote is through the **WebUI** (Bluetooth tab):

1. Open `http://<raspberry-pi-ip>:8080` in a browser
2. Go to the **Bluetooth** tab and click **Scan**
3. While the scan is running, press the `1` and `2` buttons simultaneously on the Wii Remote (or open the battery cover and press the red SYNC button for a permanent pairing)
4. Select the Wii Remote from the device list and click **Pair**

Alternatively, pair manually using `bluetoothctl`:

```
sudo bluetoothctl
[bluetoothctl] scan on
# Press 1+2 (or SYNC) on the Wii Remote
[bluetoothctl] pair AA:BB:CC:DD:EE:FF
[bluetoothctl] connect AA:BB:CC:DD:EE:FF
```

### Standalone Wii Remote vs. Wii Remote + Nunchuk

ModernJVS automatically detects whether a Nunchuk is attached:

- **Standalone Wii Remote** – uses the `nintendo-wii-remote` device profile. IR pointing maps to the analogue X/Y axes for light gun games.
- **Wii Remote + Nunchuk** – when both devices are detected together they are automatically merged into a single player using the `nintendo-wii-remote-plus-nunchuk` combined profile. The Nunchuk's Z button provides an alternate trigger (mapped to Start/pedal).

No extra configuration is required — device detection and merging happen automatically at startup and on hot-plug events.

### IR Light Gun Usage

The Wii Remote's IR camera reports screen coordinates which ModernJVS maps to `CONTROLLER_ANALOGUE_X` / `CONTROLLER_ANALOGUE_Y`. This provides accurate light-gun style aiming for games like House of the Dead, Time Crisis, and Ghost Squad when using the appropriate game profile (e.g. `generic-shooting`).

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

## Third-Party Fonts

The ModernJVS WebUI uses the following fonts, both licensed under the [SIL Open Font License 1.1](https://openfontlicense.org):

| Font | Usage | Source | License file |
|------|-------|--------|--------------|
| [Chakra Petch](https://fonts.google.com/specimen/Chakra+Petch) | UI display font | Google Fonts | `src/webui/static/fonts/OFL-ChakraPetch.txt` |
| [Roboto Mono](https://fonts.google.com/specimen/Roboto+Mono) | Monospace / code font | Google Fonts | `src/webui/static/fonts/OFL-RobotoMono.txt` |

## License

See LICENSE.md for license information.

