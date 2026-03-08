---
applyTo: "src/**/*.c,src/**/*.h"
---

# C Code Instructions for ModernJVS

## Language & Standard
- All source files use the **C99** standard.
- Compile flags include `-Wall -Wextra -Wpedantic`. Every warning must be resolved.

## Coding Style
- Indent with **tabs** (as used throughout the existing codebase).
- Opening braces go on a **new line** for functions; same line for `if`/`for`/`while`/`switch`.
- Keep lines reasonably short (under ~120 characters where practical).
- Prefer descriptive variable and function names (camelCase for variables and functions, UPPER_SNAKE_CASE for macros and `#define` constants).

## Comments & Documentation
- Public functions must have a Doxygen-style block comment (`/** … */`) describing purpose, parameters (`@param`), and return value (`@returns`).
- Header guards use the pattern `#ifndef FOO_H_` / `#define FOO_H_` / `#endif // FOO_H_`.
- Inline comments explain *why*, not *what*.

## Logging
- Use `debug(level, fmt, ...)` from `console/debug.h` for all diagnostic output.
- **Never** use bare `printf` or `fprintf(stderr, ...)` for runtime messages.
- Debug level 0 = always shown; 1 = shown at DEBUG_MODE 1; 2 = raw packet debug.

## Error Handling
- Return status/enum values (e.g., `JVSStatus`, `JVSInputStatus`, `JVSConfigStatus`) rather than raw integers from public functions wherever an enum already exists.
- Check every pointer returned by `malloc`/`calloc` for NULL before use.
- Free allocated memory and set pointers to NULL after freeing.

## Threading
- Use helpers in `controller/threading.h` (`createThread`, `getThreadsRunning`, etc.) instead of calling `pthread_create` directly.
- Protect shared state with mutexes; use `volatile` for flags polled across threads (e.g., `running`).

## Hardware / Peripheral Patterns
- Serial buffer flushes must use `tcflush()` **followed by a 100 ms `usleep` delay** to prevent data corruption.
- GPIO access must go through `libgpiod`; never use the deprecated sysfs interface.
- The JVS sense line pulse sequence is: set LOW → wait 200 ms → set FLOAT → wait 100 ms.

## Input Device Rules
- **Wiimotes are Bluetooth-only.** Never use USB physical-location matching for Wiimote or Nunchuk devices.
- Wiimote/Nunchuk merge logic uses proximity-based look-ahead (up to `DEVICE_LOOKAHEAD_DISTANCE` positions in the sorted device list).
- Device lists are sorted by `physicalLocation` before processing so related devices are adjacent.
