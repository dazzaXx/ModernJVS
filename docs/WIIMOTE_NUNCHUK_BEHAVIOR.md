# Wii Remote and Nunchuk Device Handling

This document explains how ModernJVS handles Wii Remote controllers with and without Nunchuk attachments.

## Overview

ModernJVS automatically detects whether a Nunchuk is attached to a Wii Remote and selects the appropriate configuration:

- **Wiimote Only**: Uses standalone Wiimote configuration
- **Wiimote + Nunchuk**: Uses combined configuration with all buttons from both devices

## Device Detection Logic

When ModernJVS detects a Wii Remote device, it performs a look-ahead scan to check if a Nunchuk is present at the same physical location (same Bluetooth connection).

### Scenario 1: Wiimote Only (No Nunchuk Attached)

**Detected Devices:**
- `nintendo-wii-remote` (or `nintendo-wii-remote-ir`)

**Configuration Used:**
- `docs/modernjvs/devices/nintendo-wii-remote`

**Available Buttons:**
- BTN_EAST → Button A
- BTN_SOUTH → Start
- D-pad (KEY_UP, KEY_DOWN, KEY_LEFT, KEY_RIGHT)
- BTN_MODE → Test
- BTN_1 → Coin
- BTN_2 → Service
- KEY_NEXT → Button D
- KEY_PREVIOUS → Button C
- ABS_X, ABS_Y → IR analog positioning
- KEY_O → Button B (screen out)

**Debug Output:**
```
Player 1:                  nintendo-wii-remote
```

### Scenario 2: Wiimote + Nunchuk

**Detected Devices:**
- `nintendo-wii-remote` (or `nintendo-wii-remote-ir`)
- `nintendo-wii-remote-nunchuk` (at same physical location)

**Configuration Used:**
- `docs/modernjvs/devices/nintendo-wii-remote-plus-nunchuk` (combined)

**Available Buttons:**
- All Wiimote buttons (as listed above)
- BTN_Z → Button E (Nunchuk)
- BTN_C → Button F (Nunchuk)

**Debug Output:**
```
Player 1:                  nintendo-wii-remote-plus-nunchuk (Wiimote+Nunchuk)
Skipping nintendo-wii-remote-nunchuk (merged with Wiimote)
```

**Important Notes:**
- Only ONE device thread is started for the combined device
- The Nunchuk device is completely skipped (not processed separately)
- All button inputs are handled by the single combined configuration

## Hot-Plugging Support

**The Nunchuk supports hot-plugging during active use!**

The system automatically detects when devices are connected or disconnected:

### How It Works

ModernJVS includes a watchdog thread that monitors `/dev/input` for device changes every second. When a change is detected:

1. **Detection**: Watchdog notices device count changed
2. **Reinitialization**: System stops all input threads and re-scans devices
3. **Configuration**: New configuration is loaded based on current device state
4. **JVS Maintained**: The JVS connection to the arcade board remains intact throughout

### Hot-Plug Scenarios

**Connecting Nunchuk During Use:**
1. Start ModernJVS with Wiimote only
2. System uses `nintendo-wii-remote` configuration
3. Plug in Nunchuk to the Wiimote
4. Within ~1 second, system detects the new device
5. System automatically switches to `nintendo-wii-remote-plus-nunchuk` configuration
6. All Wiimote and Nunchuk buttons now available

**Disconnecting Nunchuk During Use:**
1. Start ModernJVS with Wiimote + Nunchuk
2. System uses `nintendo-wii-remote-plus-nunchuk` configuration  
3. Unplug Nunchuk from the Wiimote
4. Within ~1 second, system detects the device removal
5. System automatically switches back to `nintendo-wii-remote` configuration
6. Wiimote continues to work normally

### Technical Details

- **Detection Time**: ~1 second (watchdog polling interval)
- **Thread Interruption**: Brief interruption (< 200ms) during reinitialization
- **JVS Connection**: Maintained throughout (no arcade system reset needed)
- **Input Buffer**: Minimal input loss during transition
- **Game State**: Preserved (no crash or disconnect)

### Important Notes

- The brief reinitialization pause is typically unnoticeable during gameplay
- Any inputs during the transition (< 200ms window) may be lost
- The JVS connection state is preserved, so the arcade game continues normally
- This is significantly better than requiring a full system restart
- No manual intervention needed - hot-plugging "just works"

## Configuration Files

Three configuration files are available:

1. **`nintendo-wii-remote`** - Standalone Wiimote (used when no Nunchuk detected)
2. **`nintendo-wii-remote-nunchuk`** - Standalone Nunchuk (not used in combined mode)
3. **`nintendo-wii-remote-plus-nunchuk`** - Combined device (used when both detected)

## Implementation Details

The detection logic in `src/controller/input.c`:

```c
// When processing a Wiimote device:
if (isWiimote && device->physicalLocation[0] != '\0')
{
    // Look for a Nunchuk at the same physical location
    for (int j = i + 1; j < deviceList->length; j++)
    {
        if (nunchuk found at same location)
        {
            // Use combined configuration
            deviceName = "nintendo-wii-remote-plus-nunchuk";
            // Mark nunchuk to skip
        }
    }
    // If no Nunchuk found, deviceName remains "nintendo-wii-remote"
}
```

The key advantage of this approach:
- Simple and maintainable
- No complex state tracking needed
- Clear separation between standalone and combined modes
- User has full control over which configuration is used by connecting/disconnecting the Nunchuk
