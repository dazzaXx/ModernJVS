# Taiko no Tatsujin (Taiko Drum Master) Support

ModernJVS **is capable** of emulating the I/O requirements for Taiko no Tatsujin games on Namco System 256. Here's what you need to know:

## Hardware Requirements

Taiko drums require **8 analog input channels** (4 per player):
- Each player's drum has 4 zones: Left Don (center), Right Don (center), Left Ka (rim), Right Ka (rim)
- Player 1 uses analog channels 0-3
- Player 2 uses analog channels 4-7

## Compatible I/O Boards

Use one of these I/O board configurations:
- **namco-taiko** - Dedicated Taiko configuration (recommended)
- **namco-na-jv** - Alternative, supports 8 analog channels at 16-bit resolution

## Setup Instructions

1. Set your I/O board emulation in `/etc/modernjvs/config`:
   ```
   EMULATE namco-taiko
   ```

2. Set the game profile:
   ```
   DEFAULT_GAME taiko-no-tatsujin
   ```

3. **Choose your input method:**

   **Option A: Authentic arcade drum hardware**
   - Connect drum sensor outputs to analog channels 0-7 via appropriate ADC interface
   - Each drum zone's piezo sensor should output to its corresponding analog channel
   - Provides analog hit strength detection for the most accurate arcade experience

   **Option B: Standard controllers (gamepads, arcade sticks, keyboard)**
   - Works with any USB controller out of the box
   - Don (center): Face buttons (A/B) or D-pad Left/Right
   - Ka (rim): Shoulder buttons or D-pad Up/Down
   - Perfect for home play and accessible to everyone

## Technical Details

- **Analog resolution**: 16-bit (0-65535 range) for accurate hit strength detection
- **Input type**: Analog voltage from piezo/vibration sensors
- **Players supported**: 2 players (8 total analog channels)
- **Additional buttons**: Start, Service, Coin per player

## Notes

- **Arcade drum hardware**: Original arcade drums use piezo sensors that output analog voltage, allowing the game to detect hit strength and distinguish between Don (center) and Ka (rim) hits. For DIY builds, consider using projects like Taiko-256 or DonCon2040 that provide proper analog signal conditioning.
- **Standard controller support**: The game is fully playable with standard gamepads, arcade sticks, or keyboards using the digital button mappings. This provides an accessible way to play without specialized drum hardware.
