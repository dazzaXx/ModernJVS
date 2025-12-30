# Bluetooth Multi-Controller Support

## Overview

OpenJVS now supports using multiple Bluetooth controllers connected via a single USB Bluetooth adapter. This is particularly important for Raspberry Pi 3 and other systems where the internal Bluetooth cannot be used because the UART is needed for the JVS sense line.

## How It Works

### The Problem

Previously, when multiple Bluetooth controllers were connected via the same USB Bluetooth adapter, they could receive inconsistent player slot assignments. This happened because:

1. All devices are sorted by their "physical location" (USB bus location)
2. Multiple Bluetooth controllers connected to the same USB adapter report the same physical location
3. The order of device enumeration could vary between system reboots
4. This resulted in controllers being assigned to different player slots each time

### The Solution

OpenJVS now uses a **composite sorting key** that includes both:

1. **Physical Location**: The USB bus location of the device or adapter
2. **Unique Device ID**: A unique identifier specific to each device

For Bluetooth controllers, the unique ID is typically the device's MAC address, which remains constant across reconnections. For devices that don't provide a unique ID, a fallback identifier is generated from the device's vendor ID, product ID, and event device name.

### Device Sorting Order

Devices are now sorted using this two-level hierarchy:

```
Primary Sort:   Physical Location (USB port)
Secondary Sort: Unique Device ID (MAC address or generated ID)
```

This ensures:
- Controllers connected to different USB ports are grouped separately
- Multiple Bluetooth controllers on the same adapter are sorted consistently by their MAC address
- The same controller always receives the same player slot across reboots and reconnections

## Example Scenarios

### Scenario 1: Two Bluetooth Controllers on One USB Adapter

**Hardware:**
- USB Bluetooth adapter in port `usb-0000:00:14.0-1`
- DualShock 4 controller #1 (MAC: `aa:bb:cc:dd:ee:01`)
- DualShock 4 controller #2 (MAC: `aa:bb:cc:dd:ee:02`)

**Result:**
- Controller #1 → Player 1 (lower MAC address sorts first)
- Controller #2 → Player 2

Both controllers will consistently maintain these player slots across reconnections and reboots.

### Scenario 2: Mixed USB and Bluetooth Controllers

**Hardware:**
- USB controller in port `usb-0000:00:14.0-1` (direct USB connection)
- USB Bluetooth adapter in port `usb-0000:00:14.0-2`
- Bluetooth controller (MAC: `aa:bb:cc:dd:ee:01`)

**Result:**
- USB controller → Player 1 (lower USB port number)
- Bluetooth controller → Player 2

### Scenario 3: Multiple USB Bluetooth Adapters

**Hardware:**
- USB Bluetooth adapter #1 in port `usb-0000:00:14.0-1`
  - Bluetooth controller A (MAC: `aa:bb:cc:dd:ee:01`)
  - Bluetooth controller B (MAC: `aa:bb:cc:dd:ee:02`)
- USB Bluetooth adapter #2 in port `usb-0000:00:14.0-2`
  - Bluetooth controller C (MAC: `aa:bb:cc:dd:ee:03`)

**Result:**
- Controller A → Player 1 (adapter #1, lower MAC)
- Controller B → Player 2 (adapter #1, higher MAC)
- Controller C → Player 3 (adapter #2)

## Viewing Device Information

To see the unique IDs assigned to your controllers, use:

```bash
sudo openjvs --list
```

For Bluetooth devices with valid unique IDs, you'll see output like:

```
- sony-interactive-entertainment-wireless-controller (usb-0000:00:14.0-2, ID: aa:bb:cc:dd:ee:01)
```

## Raspberry Pi 3 Configuration

On Raspberry Pi 3, the internal Bluetooth uses the same UART needed for the JVS sense line. To use Bluetooth controllers:

1. **Disable internal Bluetooth** (if not already done for JVS sense line)
2. **Use an external USB Bluetooth adapter**
3. **Connect your Bluetooth controllers** to the external adapter
4. Controllers will be automatically detected and assigned player slots consistently

## Technical Details

### Implementation

The changes are implemented in:
- `src/controller/input.h`: Added `uniqueID` field to `Device` struct
- `src/controller/input.c`: 
  - Modified `getInputs()` to retrieve unique ID via `EVIOCGUNIQ` ioctl
  - Updated device sorting to use composite key (physicalLocation, uniqueID)
- `src/console/cli.c`: Updated device listing to show unique IDs

### Unique ID Sources

1. **Bluetooth devices**: Linux kernel provides MAC address via `EVIOCGUNIQ`
2. **USB devices**: Some USB devices provide serial numbers via `EVIOCGUNIQ`
3. **Fallback**: For devices without unique IDs, generates ID from `vendorID:productID:eventName`

### Backward Compatibility

This change is fully backward compatible:
- Devices without unique IDs use the generated fallback
- Single-controller setups work exactly as before
- The sorting algorithm gracefully handles empty unique IDs

## Troubleshooting

### Controllers Keep Swapping Player Slots

If your controllers still swap player slots:

1. Check that unique IDs are being captured: `sudo openjvs --list`
2. Verify you're using an external USB Bluetooth adapter (not internal Bluetooth)
3. Ensure Bluetooth devices are properly paired
4. Try unplugging and re-plugging the USB Bluetooth adapter

### Can't See Bluetooth Controllers

If Bluetooth controllers aren't detected:

1. Verify the USB Bluetooth adapter is recognized: `lsusb`
2. Check that controllers are paired: `bluetoothctl devices`
3. Ensure controllers are in input mode (press PS button or similar)
4. Check system logs: `dmesg | grep -i bluetooth`

## Support

For issues related to Bluetooth controller support, please:

1. Include output from `sudo openjvs --list`
2. Describe your hardware setup (USB Bluetooth adapter model, controller types)
3. Note which Raspberry Pi model you're using
4. Include any relevant system logs

## Credits

Bluetooth multi-controller support improvements by dazzaXx with assistance from GitHub Copilot.
