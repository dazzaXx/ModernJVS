# ModernJVS – Copilot Coding Agent Instructions

## Project Summary

ModernJVS is a JVS (JAMMA Video Standard) I/O board emulator written in **C99** that runs on a **Raspberry Pi**. It allows modern USB/Bluetooth controllers (Xbox, PlayStation, Wii Remote, steering wheels, light guns, etc.) to be used with arcade hardware that speaks the JVS protocol over RS485. It is a fork of OpenJVS, updated to use `libgpiod` for GPIO access and supporting Raspberry Pi 5.

A **Python 3 WebUI** (`src/webui/modernjvs-webui.py`) is included as an optional companion service (`modernjvs-webui`) that provides a browser-based dashboard, configuration editor, live log tail, input tester, and Bluetooth pairing helper on port 8080.

## Repository Layout

```
/
├── CMakeLists.txt              – CMake build (version, sources, install rules, CPack DEB)
├── Makefile                    – Top-level convenience wrapper (build / install / clean)
├── src/
│   ├── modernjvs.c             – main() entry point, main loop, signal handling, hot-plug reinit
│   ├── version.h.in            – CMake-generated version header
│   ├── console/
│   │   ├── cli.c/h             – command-line argument parsing
│   │   ├── config.c/h          – config file parsing (/etc/modernjvs/config), IO/game/device mappings
│   │   ├── debug.c/h           – debug(level, fmt, ...) logging helper
│   │   └── watchdog.c/h        – background thread that monitors /dev/input for hot-plug events
│   ├── controller/
│   │   ├── input.c/h           – device enumeration, Wiimote/Nunchuk merging, per-controller threads
│   │   └── threading.c/h       – POSIX thread lifecycle helpers (createThread, etc.)
│   ├── ffb/ffb.c/h             – force-feedback output support
│   ├── hardware/device.c/h     – RS485 serial port open/close/flush (tcflush + 100 ms delay)
│   ├── jvs/
│   │   ├── jvs.c/h             – JVS packet read/write/process, sense line init, reactive re-enum
│   │   └── io.c/h              – JVS capability / IO-board data structures
│   └── webui/                  – Python 3 WebUI (modernjvs-webui.py, static/, templates/)
├── docs/
│   ├── modernjvs/
│   │   ├── config              – default runtime config (copied to /etc/modernjvs/config)
│   │   ├── devices/            – per-device input mapping files (one file per device name)
│   │   ├── games/              – per-game button mapping files
│   │   └── ios/                – per-IO-board capability definition files
│   ├── modernjvs.service       – systemd service unit for the main daemon
│   ├── modernjvs-webui.service – systemd service unit for the WebUI
│   └── modernjvs@.service      – template unit for running multiple instances
├── debian/postrm               – dpkg post-remove script (cleans up runtime files)
└── .github/workflows/release.yml – CI: auto-creates a GitHub release on CMakeLists.txt version bump
```

## Building

**Dependencies (install once):**
```bash
sudo apt install -y build-essential cmake git file libgpiod-dev pkg-config
```

**Development build (no install):**
```bash
mkdir -p build && cd build && cmake .. && make
# Binary: build/modernjvs
```

**Full install (builds DEB, installs, enables services):**
```bash
sudo make install
# Equivalent: mkdir build && cd build && cmake .. -DENABLE_WEBUI=ON && make && cpack && sudo dpkg -i *.deb
# Then: sudo systemctl enable --now modernjvs modernjvs-webui
```

**Install without WebUI:**
```bash
sudo make install-no-webui
# or: sudo make install WEBUI=OFF
```

**Clean:**
```bash
make clean   # removes the build/ directory
```

There is **no unit test suite**. Validate changes by building successfully and verifying the binary starts without errors. The CI workflow creates a release whenever the version string in `CMakeLists.txt` changes on the `master` branch.

## Code Standards

- **C99** standard (`set_target_properties … C_STANDARD 99`).
- Compile flags: `-Wall -Wextra -Wpedantic` – all warnings must be clean.
- Use `debug(level, fmt, ...)` from `console/debug.h` for all output (not `printf` directly).
- Function-level Doxygen-style comments (`/** … */`) are used on public functions.
- Header guards use `#ifndef FOO_H_` / `#define FOO_H_` / `#endif // FOO_H_`.

## Key Architecture Notes

### JVS Protocol
- Communication is over an RS485 serial port (default `/dev/ttyUSB0`).
- Packets have a SYNC byte (`0xE0`), destination, length, data, and checksum.
- Escape byte `0xD0` is used when data contains `0xE0` or `0xD0`.
- `processPacket()` in `jvs/jvs.c` is the main dispatch loop.

### Sense Line
- The sense line (GPIO pin 26 by default, via `libgpiod`) signals the arcade board that a device is present.
- On program restart, pulse LOW (200 ms) then FLOAT (100 ms stabilization) to trigger arcade re-enumeration.

### GPIO / libgpiod
- `libgpiod` is **required** (`pkg_check_modules(LIBGPIOD REQUIRED libgpiod)`).
- The build auto-detects libgpiod major version and defines `GPIOD_API_V2` if v2 is found.
- Never use the deprecated sysfs GPIO interface.

### Controller / Input Subsystem
- Input devices are enumerated from `/dev/input/event*` and sorted by `physicalLocation`.
- Devices are filtered against `FILTERED_DEVICE_PATTERNS` (audio/HDMI/touchpad etc.) before use.
- Each accepted controller runs in its own POSIX thread.
- `initInputs()` returns `JVS_INPUT_STATUS_DEVICE_OPEN_ERROR` if no controller threads start.
- `getInputs()` returns `JVS_INPUT_STATUS_DEVICE_OPEN_ERROR` when `validDeviceIndex == 0` after filtering.

### Wiimote / Nunchuk Merging
- **Wiimotes are Bluetooth-only**; there are no retail USB Wiimotes. Never check USB physical locations for Wiimotes or Nunchuks.
- When a Wiimote is found, the code looks ahead up to `DEVICE_LOOKAHEAD_DISTANCE` (6) positions in the sorted device list for a matching Nunchuk.
- If a Nunchuk is found, both devices are merged into a single `nintendo-wii-remote-plus-nunchuk` config; the Nunchuk entry is skipped.
- If no Nunchuk is found, the Wiimote uses the standalone `nintendo-wii-remote` config.
- Merge tracking uses `mergedNunchukDevices[MAX_DEVICES]` with a two-phase search (prefer unclaimed Nunchuks; fall back to claimed ones for IR devices sharing a pair).
- Only the first device in a merged pair prints the player assignment message.

### Hot-plug Support
- `watchdog.c` runs a background thread that polls `getNumberOfDevices()` every second.
- If the device count changes (or `/dev/input` becomes inaccessible), it sets `running = 0`.
- `modernjvs.c` main loop detects this and reinitializes controllers without resetting the JVS connection.
- Checksum errors logged during hot-plug reinitialization are **expected** – a contextual warning explains this when `running == 0`.

### Serial / Device Layer
- `hardware/device.c` handles RS485 serial open/close/read/write.
- Serial buffers **must** be flushed with `tcflush()` followed by a 100 ms delay during reset operations to prevent data corruption.

### Configuration Files
- Runtime config: `/etc/modernjvs/config` – parsed by `console/config.c`.
- Device mappings: `/etc/modernjvs/devices/<device-name>` (one file per recognized device).
- Game mappings: `/etc/modernjvs/games/<game-name>`.
- IO board definitions: `/etc/modernjvs/ios/<io-name>`.
- Installed by CMake from `docs/modernjvs/` to `/etc/modernjvs/`.

### Version
- Version is defined in `CMakeLists.txt` (`project(modernjvs VERSION "X.Y.Z")`).
- `src/version.h.in` is processed by CMake into `build/version.h`.
- Bumping the version in `CMakeLists.txt` and pushing to `master` triggers the release CI workflow.

## CI / Release Workflow

`.github/workflows/release.yml` triggers on pushes to `master` that touch `CMakeLists.txt`. It extracts the version string, checks whether that tag already exists, and creates a GitHub release with auto-generated release notes via `softprops/action-gh-release@v2`.

Trust these instructions. Only search the codebase if the information above is incomplete or appears to be incorrect.
