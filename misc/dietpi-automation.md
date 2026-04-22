# DietPi Automation

The `scripts/` directory contains two DietPi automation files that install ModernJVS hands-free during the first boot of a fresh DietPi image:

- **`dietpi.txt`** – pre-configured DietPi first-run settings (WiFi, locale, password, etc.)
- **`Automation_Custom_Script.sh`** – DietPi's automation hook; enables Bluetooth, clones the repository, and runs `make install` automatically.

To use them, write DietPi to your SD card, open the visible boot partition, and copy both files into it (replace the existing `dietpi.txt` when prompted). See `scripts/README.md` for full details including how to configure WiFi and the default password.
