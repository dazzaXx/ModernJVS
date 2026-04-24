# Installation

Installation is done from the git repository as follows, using RaspiOS Lite:

```
sudo apt install -y build-essential cmake git file libgpiod-dev
git clone https://github.com/dazzaXx/ModernJVS
sudo make install
```

> **Note:** The WebUI is included by default and requires Python 3. Raspberry Pi OS Lite includes Python 3 out of the box, so no extra step is needed. Both the `modernjvs` and `modernjvs-webui` services are **automatically enabled and started** after installation.

If using DietPi:

```
sudo apt install -y build-essential cmake git file libgpiod-dev pkg-config python3
git clone https://github.com/dazzaXx/ModernJVS
sudo make install
```

**Personally, I prefer DietPi just because you can use it as a minimal image and it works great for the old Pi models, although with the old models, the install and setup times are extremely slow. Other than that however, I have noticed no lag whatsoever with a RPi 1 B+ during testing with the WebUI also installed.**

## Installing without the WebUI

If you don't want the WebUI installed (e.g. on a minimal headless system), the recommended method is:

```
sudo make install-no-webui
```

This target always reconfigures cmake with `-DENABLE_WEBUI=OFF` before building, so it works correctly regardless of whether a build directory already exists. The `modernjvs` service is still automatically enabled and started (only `modernjvs-webui` is skipped).

Alternatively, you can pass the flag to the standard `install` target:

```
sudo make install WEBUI=OFF
```

This also always reconfigures cmake with the correct flag, so it works correctly even with an existing build directory.

## Updating ModernJVS

To update to the latest version, pull the repository and reinstall:

```
cd ModernJVS
git pull
sudo make install
```

This rebuilds the binary, repacks the DEB, reinstalls it, and restarts the services.

## Uninstalling ModernJVS

```
sudo systemctl stop modernjvs modernjvs-webui
sudo systemctl disable modernjvs modernjvs-webui
sudo apt remove -y modernjvs
```

The package's post-remove script automatically cleans up runtime files created after installation (WebUI settings, password file, audit log) and removes the `/etc/modernjvs` directory once it is empty.

## Installing without auto-enabling services

To install without automatically enabling and starting the systemd services:

```
sudo make install ENABLE_SERVICES=OFF
```

This applies to both `install` and `install-no-webui`. You can then enable the services manually later:

```
sudo make enable-services
```

`make enable-services` automatically detects whether the WebUI service was installed and only enables it if present. Alternatively, enable services directly with systemctl:

```
sudo systemctl enable --now modernjvs
# Only if the WebUI was installed:
sudo systemctl enable --now modernjvs-webui
```
