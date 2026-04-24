# Version 6.0.0-dev - IN DEVELOPMENT & TESTING - Code Refactoring, More Bugfixes and Optimizations

# ![ModernJVS](docs/modernjvs3.png)

ModernJVS is fork of OpenJVS, an emulator for I/O boards in arcade machines that use the JVS protocol. It requires a USB RS485 converter.

Updated to use libgpiod for GPIO access, with support for the Raspberry Pi 5. Optimized code and new features.

Thank you to the team responsible for making OpenJVS in the first place. ❤️

## Documentation

- [What is JVS? & Use Cases](misc/what-is-jvs.md)
- [Supported Arcade Systems & Popular Games](misc/supported-systems.md)
- [Installation](misc/installation.md)
- [Supported Hardware & Wiring](misc/supported-hardware.md)
- [WebUI](misc/webui.md)
- [Configuration](misc/configuration.md)
- [Quick Start Guide](misc/quick-start.md)
- [Troubleshooting & FAQ](misc/troubleshooting.md)
- [Wii Remote & Nunchuk Support](misc/wii-remote-support.md)
- [Taiko no Tatsujin Support](misc/taiko-support.md)
- [CLI Reference](misc/cli-reference.md)
- [DietPi Automation](misc/dietpi-automation.md)
- [Developer Test Suite](misc/developer-test-suite.md)

## Quick Install

```
sudo apt install -y build-essential cmake git file libgpiod-dev pkg-config python3
git clone https://github.com/dazzaXx/ModernJVS
sudo make install
```

See [Installation](misc/installation.md) for full details including DietPi, WebUI-less installs, updating, and uninstalling.

## Contributing

Issues and pull requests welcome! If you have a game-specific configuration that works well, please consider contributing it back to the project.

## Third-Party Fonts

The ModernJVS WebUI uses the following fonts, both licensed under the [SIL Open Font License 1.1](https://openfontlicense.org):

| Font | Usage | Source | License file |
|------|-------|--------|--------------|
| [Chakra Petch](https://fonts.google.com/specimen/Chakra+Petch) | UI display font | Google Fonts | `src/webui/static/fonts/OFL-ChakraPetch.txt` |
| [Roboto Mono](https://fonts.google.com/specimen/Roboto+Mono) | Monospace / code font | Google Fonts | `src/webui/static/fonts/OFL-RobotoMono.txt` |

## License

See LICENSE.md for license information.

