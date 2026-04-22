# Quick Start Guide

1. **Install ModernJVS** (see [Installation](installation.md))
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
