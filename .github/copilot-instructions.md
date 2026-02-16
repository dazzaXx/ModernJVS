# Copilot Instructions for ModernJVS

## Project Overview

ModernJVS is a JVS (JAMMA Video Standard) I/O emulator for arcade systems, forked from OpenJVS. It enables Raspberry Pi devices to act as I/O boards for arcade machines, allowing modern USB controllers to interface with arcade hardware that uses the JVS protocol.

**Key Purpose:** Bridge modern USB input devices (game controllers, racing wheels, light guns) with vintage arcade systems (Sega Naomi, Namco System 256, Taito Type X, etc.) via RS485 serial communication.

**Target Hardware:**
- Raspberry Pi 1-5 (all models supported)
- USB to RS485 converters (FTDI or CH340E chips)
- Wide range of USB HID input devices
- GPIO-based sense line for arcade system synchronization

## Technology Stack

- **Language:** C (C99 standard)
- **Build System:** CMake (minimum version 3.10) with Make wrapper
- **Dependencies:**
  - `libgpiod` (required) - GPIO character-device API for Raspberry Pi 5+ support
  - `pthread` (required) - Multi-threaded controller input handling
  - Standard C math library (`m`)
- **System Integration:** systemd service with templated unit files
- **Package Format:** Debian (.deb) packages via CPack

## Project Structure

```
ModernJVS/
├── src/
│   ├── modernjvs.c          # Main entry point and program loop
│   ├── console/
│   │   ├── cli.c/h          # Command-line argument parsing
│   │   ├── config.c/h       # Configuration file parsing
│   │   ├── debug.c/h        # Debug output management
│   │   └── watchdog.c/h     # Device hot-plug monitoring thread
│   ├── controller/
│   │   ├── input.c/h        # Input device detection and mapping
│   │   └── threading.c/h    # Per-controller thread management
│   ├── hardware/
│   │   ├── device.c/h       # RS485 serial communication
│   │   └── rotary.c/h       # Rotary encoder (steering wheel) support
│   ├── jvs/
│   │   ├── jvs.c/h          # JVS protocol implementation
│   │   └── io.c/h           # I/O board emulation profiles
│   └── ffb/
│       └── ffb.c/h          # Force feedback support
├── docs/
│   └── modernjvs/           # Configuration files (installed to /etc/modernjvs/)
│       ├── config           # Main configuration file
│       ├── devices/         # Device-specific mappings
│       ├── games/           # Game-specific controller profiles
│       ├── ios/             # I/O board emulation definitions
│       └── rotary/          # Rotary encoder configurations
├── CMakeLists.txt           # CMake build configuration
└── Makefile                 # Convenience wrapper for CMake

```

## Build System

### Building from Source

```bash
# Method 1: Using convenience Makefile (recommended)
make

# Method 2: Manual CMake build
mkdir build && cd build
cmake ..
make
```

### Installing

```bash
# Install as .deb package (includes systemd service)
sudo make install

# This runs: cmake build, cpack, and dpkg --install
```

### Package Creation

```bash
# Create .deb package without installing
cd build
cpack
```

**Important Build Notes:**
- The project auto-detects libgpiod major version and sets `GPIOD_API_V2` flag for v2+ API
- Version is defined in `CMakeLists.txt` project() VERSION parameter (currently 5.6.0)
- No test suite exists - all testing is manual/integration testing on real hardware

## Code Standards and Conventions

### Language and Style

- **C Standard:** C99 (`-std=c99`)
- **Compiler Flags:** `-Wall -Wextra -Wpedantic` (all warnings enabled)
- **Memory Management:** Manual allocation/deallocation required - no GC
- **Threading:** POSIX threads (`pthread`) used for concurrent controller processing
- **Error Handling:** Return status codes (enums) from functions; check all return values

### Naming Conventions

- **Files:** lowercase with hyphens (e.g., `device.c`, `rotary-encoder.c`)
- **Functions:** camelCase (e.g., `initJVS`, `parseConfig`, `getInputs`)
- **Structs/Types:** PascalCase with `JVS` prefix (e.g., `JVSConfig`, `JVSDevice`)
- **Enums:** UPPER_SNAKE_CASE with `JVS_` prefix (e.g., `JVS_STATUS_SUCCESS`)
- **Constants:** UPPER_SNAKE_CASE (e.g., `DEFAULT_CONFIG_PATH`, `TIME_REINIT`)

### Code Organization Patterns

1. **Header Guards:** Use `#pragma once` or traditional include guards
2. **Status Enums:** All subsystems return status codes (e.g., `JVSInputStatus`, `JVSConfigStatus`)
3. **Initialization Functions:** Named `init<Subsystem>()` (e.g., `initJVS`, `initInputs`)
4. **Cleanup Functions:** Named `close<Subsystem>()` or `cleanup()` for cleanup
5. **Thread Safety:** Controller input uses per-device thread isolation
6. **Configuration:** Centralized in `/etc/modernjvs/config` with parsing in `console/config.c`

### Memory and Resource Management

- **File Descriptors:** Always close in cleanup paths
- **GPIO Resources:** Properly release GPIO chip handles (libgpiod)
- **Serial Buffers:** Flush with `tcflush()` followed by 100ms delay on reset
- **Threads:** Join all spawned threads on shutdown

### Critical Implementation Details

1. **JVS Sense Line Timing:**
   - Pulse LOW for 200ms, then FLOAT for 100ms stabilization
   - Required for arcade system re-enumeration after restart
   - Implemented in `src/jvs/jvs.c` via libgpiod

2. **Device Hot-Plug Support:**
   - Watchdog thread monitors device count every second
   - Triggers reinitialization while maintaining JVS connection
   - Critical for Wiimote/Nunchuk hot-plug behavior

3. **Wiimote + Nunchuk Merging:**
   - Devices at same `physicalLocation` are merged into combined config
   - Uses "nintendo-wii-remote-plus-nunchuk" profile when both present
   - Standalone Wiimote uses "nintendo-wii-remote" profile

4. **Namco Arcade Compatibility:**
   - Reactive sense line pulsing for 246/256 systems
   - Detects wrong-address packets and re-pulses every second

## Configuration Management

### Configuration File Locations

- **Main Config:** `/etc/modernjvs/config`
- **Game Profiles:** `/etc/modernjvs/games/<game-name>`
- **I/O Definitions:** `/etc/modernjvs/ios/<io-board-name>`
- **Device Mappings:** `/etc/modernjvs/devices/<device-name>`
- **Rotary Configs:** `/etc/modernjvs/rotary/<rotary-name>`

### Key Configuration Parameters

```
EMULATE <io-board>           # I/O board to emulate (default: namco-FCA1)
DEFAULT_GAME <game-profile>  # Game-specific button mapping
DEBUG_MODE <0|1|2>          # 0=off, 1=JVS packets, 2=raw packets
SENSE_LINE_TYPE <0|1|2>     # 0=none, 1=USB RS485, 2=OpenJVS HAT
DEVICE_PATH /dev/ttyUSB0    # RS485 serial device path
ANALOG_DEADZONE_PLAYER_X <float>  # Deadzone 0.0-0.5 (default: 0.2)
```

### When Making Configuration Changes

- Validate config parsing with existing `parseConfig()` function
- Test with `DEBUG_MODE 1` to see JVS protocol output
- Ensure backward compatibility with existing config files
- Document new options in README.md

## Development Practices

### Adding New Features

1. **Input Device Support:**
   - Add device mapping to `docs/modernjvs/devices/`
   - Follow existing device file format (see `docs/modernjvs/devices/xbox-360`)
   - Test with `AUTO_CONTROLLER_DETECTION 1` enabled

2. **Game Profiles:**
   - Add profile to `docs/modernjvs/games/`
   - Reference existing profiles (generic, generic-driving, generic-shooting)
   - Document supported I/O boards for the game

3. **I/O Board Emulation:**
   - Add definition to `docs/modernjvs/ios/`
   - Implement in `src/jvs/io.c`
   - Follow JVS specification for capabilities reporting

### Debugging Techniques

```bash
# Run with debug output
sudo modernjvs --debug

# Watch live logs
sudo journalctl -u modernjvs -f

# Check service status
sudo systemctl status modernjvs

# Manual testing without service
sudo systemctl stop modernjvs
sudo modernjvs --debug
```

### Testing Checklist

Since there's no automated test suite, verify changes by:

1. **Build Test:** `make clean && make` must complete without warnings
2. **Installation Test:** `sudo make install` must succeed
3. **Service Test:** `sudo systemctl start modernjvs && systemctl status modernjvs`
4. **Functional Test:** Test with actual arcade hardware or serial monitor
5. **Hot-Plug Test:** For input changes, test device connect/disconnect
6. **Config Test:** Verify config parsing with various config combinations

### Common Issues and Solutions

**"Checksum errors during hot-plug":**
- Expected during reinitialization when `running == 0`
- Show contextual warning explaining they're normal during hot-plug

**"Controller not detected":**
- Check `validDeviceIndex` after filtering in `getInputs()`
- Return `JVS_INPUT_STATUS_DEVICE_OPEN_ERROR` if no valid devices

**"Sense line not working":**
- Verify 200ms LOW + 100ms float timing
- Check GPIO chip detection (auto-detects based on Pi model)
- Triforce systems require diodes, not resistor

## Security Considerations

### Input Validation

- **Config Files:** Validate all user-provided paths and values
- **Device Paths:** Sanitize `/dev/` paths before opening
- **Serial Input:** Validate JVS packet checksums and lengths
- **Buffer Overflows:** Use safe string functions (`strncpy`, `snprintf`)

### Privilege Management

- **GPIO Access:** Requires root or `gpio` group membership
- **Serial Devices:** Requires read/write on `/dev/ttyUSB*`
- **Systemd Service:** Runs as root by default (required for GPIO)

### Dependency Security

- **libgpiod:** Required dependency - keep updated for security patches
- **No Network Code:** ModernJVS has no network exposure
- **Local-Only:** All communication is local (serial, GPIO, USB)

## Installation and Deployment

### systemd Service Files

- **Single Instance:** `modernjvs.service` - Uses default config
- **Multi Instance:** `modernjvs@.service` - Template for multiple configs

```bash
# Single instance
sudo systemctl enable modernjvs
sudo systemctl start modernjvs

# Multi instance (custom config)
sudo systemctl enable modernjvs@custom
sudo systemctl start modernjvs@custom
```

### Package Installation Process

1. Builds binary to `build/modernjvs`
2. Creates `.deb` package with CPack
3. Installs to `/usr/bin/modernjvs`
4. Copies systemd units to `/etc/systemd/system/`
5. Installs configs to `/etc/modernjvs/`
6. Sets up module loading for Wiimote (`/etc/modules-load.d/wiimote.conf`)

## Contributing Guidelines

### Before Submitting Changes

1. Ensure code compiles without warnings (`-Wall -Wextra -Wpedantic`)
2. Test on actual hardware if possible, or document limitations
3. Update README.md if adding user-facing features
4. Follow existing code style and naming conventions
5. Add appropriate error handling and return status codes
6. Consider backward compatibility with existing configs

### Pull Request Checklist

- [ ] Code builds successfully with `make`
- [ ] No compiler warnings introduced
- [ ] Changes tested on Raspberry Pi (state which model)
- [ ] Documentation updated if needed
- [ ] Config file format remains backward compatible
- [ ] No secrets or sensitive data committed

## AI-Assisted Development Notes

**Context for AI Tools:**
- The project maintainer explicitly uses GitHub Copilot for development
- AI assistance is welcomed for bug fixes, feature additions, and optimizations
- Code is tested manually by maintainer on real arcade hardware
- Prioritize code clarity and maintainability over micro-optimizations
- Always consider cross-platform compatibility (Pi 1-5, different GPIO APIs)

## Additional Resources

- **JVS Protocol:** Industry standard for arcade I/O communication
- **libgpiod Documentation:** https://git.kernel.org/pub/scm/libs/libgpiod/libgpiod.git/about/
- **Repository Memories:** Check stored facts in repository memory system for context
- **Issue Tracker:** https://github.com/dazzaXx/ModernJVS/issues
