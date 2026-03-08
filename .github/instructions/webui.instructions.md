---
applyTo: "src/webui/**"
---

# WebUI Instructions for ModernJVS

## Language & Runtime
- The WebUI is a single **Python 3** script (`src/webui/modernjvs-webui.py`).
- It uses only Python standard-library modules plus modules available on Raspberry Pi OS / DietPi out of the box.
- Do **not** add third-party `pip` dependencies unless absolutely necessary and approved.

## Security
- All incoming requests must be validated against the private-network allowlist (RFC 1918, link-local, loopback, and IPv6 equivalents) **before** serving any content.
- Requests from public IP addresses must receive a `403 Forbidden` response.
- Write paths (config save, service control, etc.) must verify the request originates from a local address.
- Sensitive operations (reboot, shutdown, service restart) require that the user is authenticated when password protection is enabled.

## Style
- Follow **PEP 8** formatting.
- Use descriptive function and variable names.
- Keep request handlers focused; extract complex logic into helper functions.

## Static Assets & Templates
- Static files (CSS, JS, fonts) live in `src/webui/static/`.
- HTML templates live in `src/webui/templates/`.
- Installation destinations are configured in `CMakeLists.txt` (`/usr/share/modernjvs/webui/`).
- Do not change the install paths without updating `CMakeLists.txt` accordingly.

## Service Integration
- The WebUI controls the `modernjvs` service via `systemctl` commands.
- The WebUI reads the runtime config at `/etc/modernjvs/config` and rewrites it preserving comments.
- Test mode state is read from `/run/modernjvs/testmode`.
