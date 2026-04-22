# CLI Reference

The `modernjvs` binary accepts the following command-line options when run directly (the systemd service starts it with no arguments):

| Option | Description |
|--------|-------------|
| `modernjvs [game]` | Override the default game profile. E.g. `sudo modernjvs initial-d` |
| `--list` | List all detected input devices, grouped by Enabled / Disabled / No Mapping Present |
| `--enable [controller]` | Enable a specific controller mapping or, if no name is given, all disabled controllers |
| `--disable [controller]` | Disable a specific controller mapping or, if no name is given, all active controllers |
| `--edit <name>` | Open a game or device mapping file in `sudo editor` |
| `--debug` | Start in debug mode (equivalent to `DEBUG_MODE 1` in config) |
| `--version` | Print the installed ModernJVS version and exit |
| `--help` | Display usage information and exit |

**Examples:**

```bash
# See which controllers are recognised
sudo modernjvs --list

# Disable a specific controller mapping so ModernJVS ignores that device
sudo modernjvs --disable microsoft-x-box-360-pad

# Re-enable it later
sudo modernjvs --enable microsoft-x-box-360-pad

# Edit a game profile
sudo modernjvs --edit initial-d

# Run manually with a specific game (overrides DEFAULT_GAME in config)
sudo modernjvs initial-d
```
