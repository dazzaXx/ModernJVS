# WebUI

ModernJVS ships with a built-in web interface that you can access from any device on your local network. It works on both **Raspberry Pi OS** and **DietPi**.

## Features

- **Dashboard** – live service status with animated indicator (running/stopped), PID, uptime, current I/O board / game / device path, Start / Stop / Restart buttons. Includes a **Pi System Usage** panel showing real-time CPU %, memory, CPU temperature, disk usage (with colour-coded progress bars) and load average. Local IP addresses are shown so you always know the URL to use from another device. The installed ModernJVS version is displayed in the header.
- **Configuration** – all key settings in a clean form: I/O board and game dropdowns (auto-populated from installed files), device path, sense line type and GPIO pin, debug mode, auto controller detection, and per-player analog deadzone. Saved directly to `/etc/modernjvs/config` with comments preserved.
- **Monitor & Logs** – live log tail (journalctl on Raspberry Pi OS / DietPi, with automatic fallback to syslog files if journald is not available). Features a **category filter dropdown** (All / Errors & Critical / Warnings / JVS Activity / Controllers), a **live text search box**, auto-refresh every 5 s, configurable line count, a **Download Logs** button, and a dedicated **JVS Activity** pane.
- **Devices** – shows all connected `/dev/input/event*` nodes and their human-readable device names (read from sysfs). Includes a live **Input Tester** that streams raw button/axis events from any input device in real time — useful for confirming controller mappings before starting the service.
- **Bluetooth** – scan for nearby Bluetooth devices, pair/unpair controllers (including Wii Remotes, Xbox wireless controllers, and other HID devices), and view currently paired devices with connection status. Wii Remotes are automatically identified and handled with appropriate pairing logic.
- **Profiles** – view, edit, upload, download, delete, and rename game profiles, device mappings, and I/O board definitions. Supports uploading custom profile files directly from the browser.
- **Diagnostics** – serial port tester (lists available `/dev/ttyUSB*` and `/dev/ttyAMA*` ports and runs a connection test), JVS probe and packet monitor, GPIO pin control tester, and a USB device viewer.
- **System** – reboot, shutdown, and WebUI service restart buttons accessible from the dashboard.

## Accessing the WebUI

Both the `modernjvs` and `modernjvs-webui` services are enabled and started automatically during `make install`. Open `http://<raspberry-pi-ip>:8080` in a browser on any device on your local network.

To check that the WebUI service is running:
```
sudo systemctl status modernjvs-webui
```

## Security

The WebUI **actively blocks connections from public (non-private) IP addresses**. Every request is checked against the private network ranges (RFC 1918, link-local, and loopback) before being served. Requests from public internet IPs receive a `403 Forbidden` response with an explanatory page — so even if the Raspberry Pi has a public-facing IP (e.g. directly connected to a modem), the WebUI remains inaccessible from the internet.

**Allowed networks:**

| Range | Covers |
|---|---|
| `127.0.0.0/8` | Loopback (`127.x.x.x`) |
| `10.0.0.0/8` | All `10.x.x.x` addresses |
| `172.16.0.0/12` | `172.16.x.x` – `172.31.x.x` |
| `192.168.0.0/16` | **All** `192.168.x.x` addresses — `192.168.0.x`, `192.168.1.x`, `192.168.50.x`, `192.168.100.x`, etc. |
| `169.254.0.0/16` | Link-local (APIPA) |
| `::1/128`, `fc00::/7`, `fe80::/10` | IPv6 loopback, ULA, link-local |

> **Common home/office routers** typically use `192.168.0.x`, `192.168.1.x`, or `192.168.50.x` — all of these are inside `192.168.0.0/16` and will be able to connect without any extra configuration.

**Optional password protection:** The WebUI supports an optional password to restrict access on your local network. When set, all pages (except the login form itself) require authentication before they can be accessed. Session tokens are stored as cookies and expire after inactivity. An audit log records login attempts and key actions. Password management and session control are available from the WebUI settings page.

The WebUI runs as root (required to control the `modernjvs` service and write `/etc/modernjvs/config`). It binds to all interfaces on port **8080** — only LAN devices can connect.
