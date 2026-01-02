# Copilot Instructions for ModernJVS

## Project Overview

ModernJVS is a fork of OpenJVS - an emulator for I/O boards in arcade machines that use the JVS (JAMMA Video Standard) protocol. The software runs on Raspberry Pi devices (including Pi 5) and requires a USB RS485 converter or an official OpenJVS HAT to communicate with arcade hardware.

**Key Capabilities:**
- Emulates various arcade I/O boards (Namco, Sega Naomi, Triforce, Chihiro, etc.)
- Supports controller input mapping for arcade games
- Handles GPIO communication using libgpiod (modern) or sysfs (legacy)
- Provides force feedback (FFB) support
- Configurable deadzone for analog controllers

## Build System

### Tools Required
- CMake (minimum 3.10)
- GCC (C99 standard)
- Make
- libgpiod-dev (optional but recommended for modern GPIO support)
- pkg-config

### Build Process
```bash
# Standard build
make                # Creates build/ directory and runs cmake + make
sudo make install   # Builds DEB package and installs via dpkg

# Clean build
make clean          # Removes build/ directory
```

The build system uses:
- **Makefile**: Top-level wrapper that creates build directory and invokes CMake
- **CMakeLists.txt**: Main build configuration with dependency detection
- **CPack**: Generates DEB packages for installation

### CMake Details
- Automatically detects libgpiod presence and version (v1 vs v2 API)
- Compiles with `-Wall -Wextra -Wpedantic` warnings enabled
- Links against pthreads and math library
- Generates version.h from version.h.in template
- Project version is defined in CMakeLists.txt (currently 5.0.5)

## Code Structure

### Directory Layout
```
src/
├── modernjvs.c           # Main entry point
├── console/              # Configuration, debug logging, CLI, watchdog
│   ├── cli.c/.h
│   ├── config.c/.h
│   ├── debug.c/.h
│   └── watchdog.c/.h
├── controller/           # Input handling and threading
│   ├── input.c/.h
│   └── threading.c/.h
├── hardware/             # GPIO device control and rotary encoder
│   ├── device.c/.h
│   └── rotary.c/.h
├── jvs/                  # JVS protocol implementation
│   ├── io.c/.h
│   └── jvs.c/.h
└── ffb/                  # Force feedback support
    └── ffb.c/.h

docs/
├── modernjvs/            # Configuration files (config, devices, games, ios, rotary)
├── modernjvs.service     # systemd service files
└── modernjvs@.service
```

### Module Responsibilities

**console/**: Command-line interface, configuration parsing from `/etc/modernjvs/config`, debug output levels, and watchdog monitoring

**controller/**: Input device discovery and mapping, multi-threaded input processing, support for various controllers (Wiimote, Aimtrak, generic gamepads)

**hardware/**: GPIO line control (using libgpiod v1/v2 API or legacy sysfs), sense line management (GPIO 12), rotary encoder input

**jvs/**: JVS packet construction/parsing, serial communication via RS485, device state management, retry logic

**ffb/**: Force feedback effects for supported controllers

## Coding Conventions

### Style Guidelines
- **Standard**: C99
- **Indentation**: 4 spaces (no tabs)
- **Naming**:
  - CamelCase for types and enums: `JVSConfig`, `JVSPacketStatus`
  - camelCase for functions: `initDebug()`, `parseConfig()`
  - UPPER_CASE for constants and macros: `DEFAULT_CONFIG_PATH`, `JVS_MAX_PACKET_SIZE`
  - snake_case for variables: `running`, `packet_size`
- **Headers**: Include guards use `#ifndef FILENAME_H_` pattern
- **Comments**: Inline comments for complex logic, avoid obvious comments
- **Error Handling**: Return status enums (e.g., `JVSRotaryStatus`, `WatchdogStatus`)

### Best Practices
- Always check return values from system calls and library functions
- Use appropriate debug levels (0-4) for logging: `debug(level, format, ...)`
- Initialize all variables before use
- Use const for read-only parameters
- Free allocated memory and close file descriptors
- Handle both libgpiod API versions (v1 and v2) via conditional compilation

### Common Patterns
```c
// Status enum pattern
typedef enum {
    JVS_STATUS_SUCCESS,
    JVS_STATUS_ERROR,
    JVS_STATUS_RETRY
} JVSStatus;

// Config structure access
JVSConfig config;
getDefaultConfig(&config);
parseConfig(DEFAULT_CONFIG_PATH, &config);

// Debug output
debug(1, "Initializing device at %s\n", devicePath);
debugPacket(2, &packet);
```

## Configuration

### Runtime Configuration
The main config is at `/etc/modernjvs/config` with these key settings:
- `EMULATE`: I/O board to emulate (default: namco-FCA1)
- `DEBUG`: Debug level 0-4 (default: 1)
- `DEVICE`: Serial device path (default: /dev/ttyUSB0)
- `SENSE_LINE_PIN`: GPIO pin for sense line (default: 12)
- `ANALOG_DEADZONE`: Controller deadzone (default: 0.0)
- `AUTO_CONTROLLER_DETECTION`: Auto-detect controllers (default: 1)

Additional config directories:
- `/etc/modernjvs/devices/`: Controller device mappings
- `/etc/modernjvs/games/`: Game-specific button mappings
- `/etc/modernjvs/ios/`: I/O board definitions
- `/etc/modernjvs/rotary`: Rotary encoder configuration

## Hardware Requirements

### Supported Platforms
- Raspberry Pi 1, 2, 3, 4, 5
- Automatic GPIO chip detection for different Pi models
- Requires USB RS485 converter (FTDI or CH340E chips recommended)

### GPIO Usage
- GPIO 12: Sense line (requires 1kΩ resistor or 4 signal diodes for voltage drop)
- Uses libgpiod character device API on modern systems
- Falls back to sysfs on older systems

### Arcade Boards Supported
Namco (FCA1, System 22/23, System 2x6), Sega (Naomi 1/2, Triforce, Chihiro, Hikaru, Lindbergh, Ringedge 1/2), Taito (Type X+, Type X2), exA-Arcadia

## Testing

Currently no automated test suite exists. Manual testing involves:
1. Building the project: `make`
2. Installing on Raspberry Pi: `sudo make install`
3. Testing with actual arcade hardware or sense line simulation
4. Monitoring via systemd: `systemctl status modernjvs`

## Deployment

- Software installs as DEB package
- Systemd services: `modernjvs.service` and `modernjvs@.service`
- Enable at boot: `sudo systemctl enable modernjvs`
- Start service: `sudo systemctl start modernjvs`

## CI/CD

GitHub Actions workflow (`.github/workflows/build.yml`):
- Triggers on push and pull requests
- Builds on Ubuntu latest
- Uploads build artifacts
- Does NOT run automated tests (manual testing only)

## Dependencies

### Required
- Standard C library
- pthreads (POSIX threads)
- Linux kernel headers (for input subsystem)
- math library (libm)

### Optional
- libgpiod (v1 or v2) - for modern GPIO access
- Falls back to sysfs if libgpiod not available

## Common Development Tasks

### Adding New I/O Board Support
1. Create new board definition in `docs/modernjvs/ios/`
2. Update JVS capabilities in `src/jvs/io.c`
3. Update documentation in README.md

### Adding New Controller Support
1. Add device identification in `src/controller/input.h`
2. Implement mapping in `src/controller/input.c`
3. Create mapping file in `docs/modernjvs/devices/`
4. Test with actual hardware

### Debugging
- Set `DEBUG=4` in config for verbose output
- Use `debug()` function with appropriate levels
- Check systemd journal: `journalctl -u modernjvs -f`
- Monitor serial communication for JVS protocol issues

## Important Notes

- **GPIO Safety**: Always use appropriate voltage divider (resistor/diodes) on sense line
- **USB Adapters**: FTDI and CH340E chips work; CP2102 chips have known issues
- **Triforce Compatibility**: Must use 4 signal diodes (not 1kΩ resistor) for sense line
- **License**: GPL-3.0 (see LICENSE.md)
- **Fork Status**: This is a fork of OpenJVS with modernization improvements

## When Making Changes

1. **Preserve Backward Compatibility**: Support both libgpiod v1/v2 and sysfs fallback
2. **Test on Multiple Pi Models**: Especially if touching GPIO code
3. **Update Version**: Increment version in CMakeLists.txt for releases
4. **Document Config Changes**: Update README.md if adding new config options
5. **Follow C99 Standard**: No C11/C17 features for wider compatibility
6. **Maintain DEB Package**: Ensure CPack configuration remains functional
