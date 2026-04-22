# Developer Test Suite

ModernJVS includes a test suite (`src/testsuite/test_modernjvs.c`) that exercises the JVS packet framing, IO state management, config parsing, and debug-level filtering — all without requiring real hardware (it uses a `socketpair` to emulate the RS485 wire).

> **Note:** The test suite is intended for development and is **not built by default**. There is no need to run it for normal use.

## Building and running the tests

```bash
mkdir -p build && cd build
cmake .. -DBUILD_TESTS=ON
make test_modernjvs
./test_modernjvs
```

Or, if you want CMake's `ctest` runner:

```bash
ctest --output-on-failure
```

## What is tested

| Module | Coverage |
|--------|----------|
| `jvs/io.c` | IO state management (pure logic, no hardware) |
| `jvs/jvs.c` | JVS packet framing and `processPacket()` dispatch |
| `console/config.c` | Config file and IO-board definition parsing |
| `console/debug.c` | Debug-level filtering |
