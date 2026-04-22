# Wii Remote & Nunchuk Support

ModernJVS has built-in support for Nintendo Wii Remotes (with or without a Nunchuk attachment) over Bluetooth. Wii Remotes can be used as light guns (via IR pointing) or as general game controllers.

## Kernel Module

The `hid-wiimote` kernel module is required and is automatically configured during installation — a module loader file is written to `/etc/modules-load.d/wiimote.conf` so the module loads on every boot. No manual setup is needed.

## Bluetooth Pairing

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

## Standalone Wii Remote vs. Wii Remote + Nunchuk

ModernJVS automatically detects whether a Nunchuk is attached:

- **Standalone Wii Remote** – uses the `nintendo-wii-remote` device profile. IR pointing maps to the analogue X/Y axes for light gun games.
- **Wii Remote + Nunchuk** – when both devices are detected together they are automatically merged into a single player using the `nintendo-wii-remote-plus-nunchuk` combined profile. The Nunchuk's Z button provides an alternate trigger (mapped to Start/pedal).

No extra configuration is required — device detection and merging happen automatically at startup and on hot-plug events.

## IR Light Gun Usage

The Wii Remote's IR camera reports screen coordinates which ModernJVS maps to `CONTROLLER_ANALOGUE_X` / `CONTROLLER_ANALOGUE_Y`. This provides accurate light-gun style aiming for games like House of the Dead, Time Crisis, and Ghost Squad when using the appropriate game profile (e.g. `generic-shooting`).

You can tune how far the cursor travels per physical movement with the `WII_IR_SCALE` config option (see [Configuration](configuration.md)).
