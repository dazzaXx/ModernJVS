# Troubleshooting

## ModernJVS not detecting controllers
- Ensure `AUTO_CONTROLLER_DETECTION` is set to `1` in config
- Check if the controller appears in `/dev/input/` with `ls /dev/input/`
- Try unplugging and replugging the controller
- Check logs: `sudo journalctl -u modernjvs -f`

## Arcade board not communicating
- Verify wiring connections (GND, A+, B-)
- Check that RS485 converter is recognized: `ls /dev/ttyUSB*`
- If multiple USB serial devices exist, try `/dev/ttyUSB1` instead of `/dev/ttyUSB0`
- Ensure correct `SENSE_LINE_TYPE` is configured
- For Triforce systems, ensure you're using diodes, not a resistor

## Buttons not responding correctly
- Verify you're using the correct game profile for your game
- Check the mapping file in `/etc/modernjvs/games/your-game`
- Try the `generic` profile first to test basic functionality
- Some games require specific I/O board emulation

## Analog stick drift or incorrect calibration
- Adjust `ANALOG_DEADZONE_PLAYER_X` values in config (try 0.15-0.25 for drift issues)
- Test with different controllers to rule out hardware issues

## Service won't start
- Check logs for detailed error messages: `sudo journalctl -u modernjvs -xe`
- Verify config file exists: `ls -la /etc/modernjvs/config`
- Verify permissions: `sudo chmod 644 /etc/modernjvs/config`
- Try running in debug mode: `sudo modernjvs --debug`

---

# FAQ

**Q: Which I/O board should I emulate?**
A: Start with the default (namco-FCA1) or check online documentation for your specific arcade game. Most games work with multiple I/O board types.

**Q: Can I use wireless controllers?**
A: Yes! Bluetooth controllers work as long as they appear as standard USB HID devices to Linux. Wii Remotes have dedicated support — see the [Wii Remote & Nunchuk Support](wii-remote-support.md) document.

**Q: Can I use a Wii Remote as a light gun?**
A: Yes. Pair the Wii Remote via the WebUI Bluetooth tab (or manually with `bluetoothctl`), then use the `generic-shooting` game profile or a game-specific shooting profile. The IR camera's screen coordinates are automatically mapped to analogue axes.

**Q: Does this work with MAME?**
A: No, ModernJVS is for real arcade hardware that uses JVS protocol. For MAME, map controllers directly in MAME's settings.

**Q: My game requires a specific I/O board not listed. What do I do?**
A: Try similar I/O boards (e.g., sega-type-1, sega-type-2, namco-FCA1) or open an issue on GitHub with your game details.

**Q: How do I add custom button mappings?**
A: Copy an existing profile from `/etc/modernjvs/games/` and modify it. See existing files for syntax examples. You can also use the WebUI **Profiles** tab to view, edit, and upload profiles directly from your browser.

**Q: Can I chain two I/O boards?**
A: Yes. Add `EMULATE_SECOND <io-name>` to `/etc/modernjvs/config` to chain a second I/O board after the primary one. See the [Configuration](configuration.md) document.
