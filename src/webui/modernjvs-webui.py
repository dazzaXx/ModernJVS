#!/usr/bin/env python3
# ModernJVS WebUI
# A local-network web interface for configuring and monitoring ModernJVS.
# Requires Python 3.6+ (stdlib only, no pip dependencies).

import http.server
import glob as _glob
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import shutil
import signal
import subprocess
import threading
import time
import struct
import urllib.parse
import base64
from http import HTTPStatus

WEBUI_PORT = 8080
CONFIG_PATH = "/etc/modernjvs/config"
IOS_PATH = "/etc/modernjvs/ios"
GAMES_PATH = "/etc/modernjvs/games"
DEVICES_PATH = "/etc/modernjvs/devices"
LOGO_PATH = "/usr/share/modernjvs/modernjvs2.png"
STICKS_PATH = "/usr/share/modernjvs/Sticks4.png"
WEBUI_STATIC_PATH    = "/usr/share/modernjvs/webui/static"
WEBUI_TEMPLATES_PATH = "/usr/share/modernjvs/webui/templates"
SERVICE_NAME = "modernjvs"
WEBUI_SERVICE_NAME = "modernjvs-webui"

MAX_SETTING_STRING_LENGTH = 64  # cap per string field in webui-settings.json
MAX_PROFILE_UPLOAD_BYTES = 256 * 1024      # 256 KB hard cap for profile files
MAX_PROFILE_NAME_LENGTH = 64               # max filename length for profile files
MAX_PROFILE_CONTENT_CHARS = 65536         # max content length for profile writes
MAX_POST_BODY_BYTES = 128 * 1024           # 128 KB hard cap for JSON POST request bodies
INPUT_TEST_TIMEOUT_SECONDS = 60           # max duration for SSE input test stream

# Log message strings emitted by jvs.c to track JVS connection state.
# These must match the debug(0, ...) calls in src/jvs/jvs.c exactly.
JVS_LOG_CONNECTED    = "JVS: Connection established"
JVS_LOG_DISCONNECTED = "JVS: Connection reset"
JVS_LOG_LOST         = "JVS: Connection lost"

# Server-side WebUI settings persistence
WEBUI_SETTINGS_PATH  = "/etc/modernjvs/webui-settings.json"
WEBUI_PASSWORD_PATH  = "/etc/modernjvs/webui-password"
AUDIT_LOG_PATH       = "/etc/modernjvs/webui-audit.log"
MAX_AUDIT_LOG_LINES  = 1000

# Runtime state file written by the daemon to expose testButtonActive
TESTMODE_STATE_PATH  = "/run/modernjvs/testmode"
# How long to wait after signalling the daemon before reading back the state
# file.  One daemon processing cycle is well under 1 ms, but a small buffer
# accounts for scheduler latency between the signal delivery and the file write.
DAEMON_STATE_UPDATE_DELAY = 0.05  # seconds

# Session cookie settings
SESSION_COOKIE_NAME = "mjvs_session"
SESSION_MAX_AGE     = 7 * 24 * 3600   # 7 days

_SETTINGS_DEFAULTS = {
    "theme":          "black",
    "compact":        False,
    "noAnim":         False,
}

_settings_lock = threading.Lock()

_test_button_lock = threading.Lock()
_test_button_active = False


def get_test_button_active():
    """Return True if the software test button is currently active (test mode on).

    Reads the daemon's runtime state file (/run/modernjvs/testmode) when
    available so the WebUI reflects changes made by either the dashboard or a
    bound controller button.  Falls back to the in-memory mirror when the
    daemon is not running or hasn't written the file yet.
    """
    global _test_button_active
    try:
        with open(TESTMODE_STATE_PATH, "r") as f:
            val = f.read().strip() == "1"
        with _test_button_lock:
            _test_button_active = val
        return val
    except OSError:
        with _test_button_lock:
            return _test_button_active


def toggle_test_button():
    """Toggle the JVS test button state.

    Signals the running daemon (via SIGUSR1) to toggle its testButtonActive
    latch, waits briefly for the daemon to update its runtime state file, then
    reads back the new state.  If the daemon is not running the local mirror is
    toggled so the UI stays responsive; when the daemon next starts it will
    write the state file and refreshDashboard() will sync the button.
    Returns (ok, new_active_state, error_message).
    """
    global _test_button_active
    pid_signalled = False
    ok, props_out = systemctl("show", SERVICE_NAME, "--property=MainPID")
    if ok:
        for line in props_out.splitlines():
            if line.startswith("MainPID="):
                try:
                    pid = int(line.split("=", 1)[1].strip())
                    if pid > 0:
                        os.kill(pid, signal.SIGUSR1)
                        pid_signalled = True
                except (ValueError, ProcessLookupError, PermissionError) as exc:
                    return False, get_test_button_active(), str(exc)
                break

    if pid_signalled:
        # Give the daemon one processing cycle to update the state file.
        time.sleep(DAEMON_STATE_UPDATE_DELAY)
        new_state = get_test_button_active()
    else:
        # Daemon not running — toggle the local mirror as a fallback.
        with _test_button_lock:
            _test_button_active = not _test_button_active
            new_state = _test_button_active
    return True, new_state, ""


def read_webui_settings():
    """Return the saved WebUI appearance settings dict (merged with defaults)."""
    try:
        with open(WEBUI_SETTINGS_PATH, "r") as f:
            data = json.load(f)
        # Only keep known keys to avoid polluting the response
        return {k: data.get(k, v) for k, v in _SETTINGS_DEFAULTS.items()}
    except (OSError, json.JSONDecodeError):
        return dict(_SETTINGS_DEFAULTS)


def write_webui_settings(settings):
    """Persist WebUI appearance settings to disk. Returns (ok, msg)."""
    # Only persist known keys; validate types to prevent corruption
    cleaned = {}
    for key, default in _SETTINGS_DEFAULTS.items():
        val = settings.get(key, default)
        # Coerce to the same type as the default
        try:
            if isinstance(default, bool):
                cleaned[key] = bool(val)
            elif isinstance(default, float):
                # Clamp float settings to [0.0, 1.0]
                cleaned[key] = max(0.0, min(1.0, float(val)))
            elif isinstance(default, str):
                cleaned[key] = str(val)[:MAX_SETTING_STRING_LENGTH]
            else:
                cleaned[key] = val
        except (TypeError, ValueError):
            cleaned[key] = default
    try:
        with _settings_lock:
            os.makedirs(os.path.dirname(WEBUI_SETTINGS_PATH), exist_ok=True)
            with open(WEBUI_SETTINGS_PATH, "w") as f:
                json.dump(cleaned, f, indent=2)
        return True, "ok"
    except OSError as e:
        return False, str(e)

# ---------------------------------------------------------------------------
# Password protection
# ---------------------------------------------------------------------------

_PBKDF2_ITERATIONS = 260_000


def hash_password(password):
    """Return a PBKDF2-HMAC-SHA256 hash string for *password*."""
    salt = secrets.token_bytes(32)
    key  = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${_PBKDF2_ITERATIONS}${salt.hex()}${key.hex()}"


def verify_password(password, stored_hash):
    """Return True if *password* matches *stored_hash*."""
    try:
        alg, iters_s, salt_hex, key_hex = stored_hash.split("$")
        if alg != "pbkdf2_sha256":
            return False
        key_actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"),
            bytes.fromhex(salt_hex), int(iters_s),
        )
        return hmac.compare_digest(key_actual, bytes.fromhex(key_hex))
    except Exception:
        return False


def read_password_hash():
    """Return the stored password hash string, or None if no password is set."""
    try:
        with open(WEBUI_PASSWORD_PATH, "r") as f:
            return f.read().strip() or None
    except OSError:
        return None


def _write_password_hash(hash_str):
    """Persist *hash_str* to disk readable only by root."""
    os.makedirs(os.path.dirname(WEBUI_PASSWORD_PATH), exist_ok=True)
    with open(WEBUI_PASSWORD_PATH, "w") as f:
        f.write(hash_str + "\n")
    os.chmod(WEBUI_PASSWORD_PATH, 0o600)


def clear_password_file():
    """Remove the stored password hash file.  Returns True on success."""
    try:
        os.remove(WEBUI_PASSWORD_PATH)
        return True
    except FileNotFoundError:
        return True
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Session management (in-memory; cleared on server restart)
# ---------------------------------------------------------------------------

_sessions: dict = {}
_sessions_lock = threading.Lock()


def create_session(ip=""):
    """Create a new random session token and return it."""
    token   = secrets.token_hex(32)
    now     = time.time()
    expiry  = now + SESSION_MAX_AGE
    meta    = {"expiry": expiry, "created": now, "ip": ip}
    with _sessions_lock:
        _sessions[token] = meta
        # Prune expired tokens opportunistically
        expired = [t for t, m in list(_sessions.items()) if m["expiry"] < now]
        for t in expired:
            del _sessions[t]
    return token


def is_valid_session(token):
    """Return True if *token* is a known, unexpired session."""
    if not token:
        return False
    with _sessions_lock:
        meta = _sessions.get(token)
        if meta is None:
            return False
        if time.time() > meta["expiry"]:
            del _sessions[token]
            return False
        return True


def list_sessions():
    """Return a list of dicts describing each active session (token masked)."""
    now = time.time()
    result = []
    with _sessions_lock:
        for token, meta in list(_sessions.items()):
            if meta["expiry"] < now:
                continue
            result.append({
                "token_hint": token[:8] + "…",
                "created":    time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(meta["created"])),
                "expires":    time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(meta["expiry"])),
                "ip":         meta.get("ip", ""),
            })
    return result


def invalidate_all_sessions():
    """Clear every active session (call after password change / removal)."""
    with _sessions_lock:
        _sessions.clear()


def invalidate_other_sessions(current_token):
    """Clear every session except *current_token*."""
    with _sessions_lock:
        tokens_to_del = [t for t in list(_sessions.keys()) if t != current_token]
        for t in tokens_to_del:
            del _sessions[t]


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

_audit_lock = threading.Lock()


def audit_log(action, detail="", ip=""):
    """Append one line to the WebUI audit log (best-effort, never raises).

    The log is trimmed to the most recent MAX_AUDIT_LOG_LINES lines whenever
    it exceeds that limit, keeping the file from growing without bound.
    """
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    parts = [f"[{timestamp}]", action]
    if detail:
        parts.append(f"- {detail}")
    if ip:
        parts.append(f"(from {ip})")
    line = " ".join(parts) + "\n"
    try:
        with _audit_lock:
            os.makedirs(os.path.dirname(AUDIT_LOG_PATH), exist_ok=True)
            try:
                with open(AUDIT_LOG_PATH, "r") as f:
                    lines = f.readlines()
            except OSError:
                lines = []
            lines.append(line)
            if len(lines) > MAX_AUDIT_LOG_LINES:
                lines = lines[-MAX_AUDIT_LOG_LINES:]
            with open(AUDIT_LOG_PATH, "w") as f:
                f.writelines(lines)
    except OSError:
        pass


_PRIVATE_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),    # loopback
    ipaddress.ip_network("10.0.0.0/8"),     # RFC 1918
    ipaddress.ip_network("172.16.0.0/12"),  # RFC 1918
    ipaddress.ip_network("192.168.0.0/16"), # RFC 1918
    ipaddress.ip_network("169.254.0.0/16"), # link-local (RFC 3927)
    ipaddress.ip_network("::1/128"),        # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),       # IPv6 unique local (ULA)
    ipaddress.ip_network("fe80::/10"),      # IPv6 link-local
]


def is_private_ip(addr):
    """Return True if addr is a private/local address that should be allowed.

    Also handles IPv4-mapped IPv6 addresses (::ffff:x.x.x.x) transparently.
    """
    try:
        ip = ipaddress.ip_address(addr)
        # Unwrap IPv4-mapped IPv6 so the RFC-1918 nets match correctly
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        return any(ip in net for net in _PRIVATE_NETS)
    except ValueError:
        return False


# Simple one-page HTML shown to callers from public IPs
_ACCESS_DENIED_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Access Denied \u2013 ModernJVS WebUI</title>
<style>
body{background:#000000;color:#e2e2f0;font-family:system-ui,sans-serif;
     display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.box{background:#1e1e2e;border:1px solid #2e2e42;border-radius:8px;
     padding:2.5rem;max-width:500px;text-align:center}
h1{color:#ff5555;margin-bottom:.75rem;font-size:1.4rem}
p{color:#7878a0;line-height:1.6;margin:.5rem 0}
code{color:#ff7e7e;font-family:monospace}
</style></head>
<body><div class="box">
<h1>\U0001f512 Access Denied</h1>
<p>The ModernJVS WebUI is only accessible from your <strong>local network</strong>.</p>
<p>Your IP address <code>{client_ip}</code> is not a private network address.</p>
<p>Connect from a device on the same LAN as the Raspberry Pi.</p>
</div></body></html>
"""


# ---------------------------------------------------------------------------
# Logo → HTML page builder
# ---------------------------------------------------------------------------

def _logo_data_uri():
    """Return the logo as a base64 data URI, or '/logo' as a fallback URL.

    Trying the base64 approach first ensures the logo always appears in the
    browser without a separate HTTP round-trip, and works whether the WebUI
    script is run directly from the repository or via the installed package.
    """
    data = get_logo_bytes()
    if data:
        return "data:image/png;base64," + base64.b64encode(data).decode()
    return "/logo"


def _sticks_data_uri():
    """Return the Sticks image as a base64 data URI, or '/sticks' as fallback."""
    data = get_sticks_bytes()
    if data:
        return "data:image/png;base64," + base64.b64encode(data).decode()
    return "/sticks"


def _build_html_page():
    """Build the final HTML page, loading the template from disk and embedding the logo."""
    template = _read_webui_file("templates", "index.html")
    if template is None:
        return "<html><body><p>Error: index.html template not found.</p></body></html>"
    return (
        template
        .replace("__LOGO__",   _logo_data_uri())
        .replace("__STICKS__", _sticks_data_uri())
    )


# HTML_PAGE is built after get_logo_bytes() is defined (see below).

# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Profile file helpers
# ---------------------------------------------------------------------------

def _validate_profile_name(name):
    """Return True only if name is a safe, plain filename."""
    if not name or len(name) > MAX_PROFILE_NAME_LENGTH:
        return False
    if "/" in name or "\\" in name or ".." in name:
        return False
    if name.startswith("."):
        return False
    # Reject characters that could enable HTTP header injection or shell issues
    if any(c in name for c in ('\r', '\n', '"', '\x00')):
        return False
    return True


_PROFILE_TYPE_MAP = {
    "games":   GAMES_PATH,
    "devices": DEVICES_PATH,
    "ios":     IOS_PATH,
}


def _resolve_profile_path(type_, name):
    """Map type_ to the correct base path and return the resolved absolute path.

    Returns None if type_ or name is invalid.  The resolved path is verified
    to remain within the expected base directory for defense-in-depth.
    """
    base = _PROFILE_TYPE_MAP.get(type_)
    if base is None:
        return None
    # os.path.basename is the CodeQL-recognised sanitizer for path injection:
    # it strips all directory components, making traversal impossible.
    clean = os.path.basename(name)
    if not _validate_profile_name(clean):
        return None
    resolved = os.path.realpath(os.path.join(base, clean))
    base_real = os.path.realpath(base)
    if not resolved.startswith(base_real + os.sep) and resolved != base_real:
        return None
    return resolved


def read_config():
    """Parse the modernjvs config file into a dict."""
    cfg = {}
    try:
        with open(CONFIG_PATH, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # split on any whitespace, producing at most [directive, value]
                parts = line.split(None, 1)
                if len(parts) == 2:
                    cfg[parts[0]] = parts[1].strip()
    except OSError:
        pass
    return cfg


def write_config(new_values):
    """
    Write updated key=value pairs back into the config file.
    Preserves comments and unknown lines; updates existing keys in-place.
    Appends new keys at the end if not already present.
    """
    # Map from API key names to config file directive names
    key_map = {
        "emulate":                    "EMULATE",
        "game":                       "DEFAULT_GAME",
        "device":                     "DEVICE_PATH",
        "sense_line_type":            "SENSE_LINE_TYPE",
        "sense_line_pin":             "SENSE_LINE_PIN",
        "debug_mode":                 "DEBUG_MODE",
        "auto_controller_detection":  "AUTO_CONTROLLER_DETECTION",
        "deadzone_p1":                "ANALOG_DEADZONE_PLAYER_1",
        "deadzone_p2":                "ANALOG_DEADZONE_PLAYER_2",
        "deadzone_p3":                "ANALOG_DEADZONE_PLAYER_3",
        "deadzone_p4":                "ANALOG_DEADZONE_PLAYER_4",
        "emulate_second":             "EMULATE_SECOND",
    }

    # Build a dict of directive → new value
    # For EMULATE_SECOND: if empty/blank, mark for removal (not append)
    # so unknown directives are never added to the config file.
    _optional_directives = {"EMULATE_SECOND"}
    _remove_directives = set()
    updates = {}
    for api_key, directive in key_map.items():
        if api_key in new_values:
            val = new_values[api_key]
            # Reject values containing newlines or carriage returns to prevent
            # config line injection — none of the supported directives accept
            # multi-line values.
            val_str = str(val)
            if '\n' in val_str or '\r' in val_str:
                return False, f"Value for '{api_key}' must not contain newline characters."
            if directive in _optional_directives and not val_str.strip():
                _remove_directives.add(directive)
            else:
                updates[directive] = val_str

    try:
        with open(CONFIG_PATH, "r") as f:
            lines = f.readlines()
    except OSError as e:
        return False, str(e)

    written = set()
    new_lines = []
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            # split on any whitespace, producing at most [directive, value]
            parts = stripped.split(None, 1)
            if parts and parts[0] in _remove_directives:
                # Drop this line entirely (remove the directive)
                written.add(parts[0])
                continue
            if parts and parts[0] in updates:
                new_lines.append(f"{parts[0]} {updates[parts[0]]}\n")
                written.add(parts[0])
                continue
        new_lines.append(line)

    # Append any directives that weren't already in the file
    for directive, value in updates.items():
        if directive not in written:
            new_lines.append(f"{directive} {value}\n")

    try:
        tmp_path = CONFIG_PATH + ".tmp"
        with open(tmp_path, "w") as f:
            f.writelines(new_lines)
        os.replace(tmp_path, CONFIG_PATH)
    except OSError as e:
        return False, str(e)

    return True, "ok"


def config_to_api(cfg):
    """Convert raw directive dict to the API response shape."""
    return {
        "emulate":                    cfg.get("EMULATE",                    ""),
        "game":                       cfg.get("DEFAULT_GAME",               ""),
        "device":                     cfg.get("DEVICE_PATH",                ""),
        "sense_line_type":            cfg.get("SENSE_LINE_TYPE",            "1"),
        "sense_line_pin":             cfg.get("SENSE_LINE_PIN",             "26"),
        "debug_mode":                 cfg.get("DEBUG_MODE",                 "0"),
        "auto_controller_detection":  cfg.get("AUTO_CONTROLLER_DETECTION",  "1"),
        "deadzone_p1":                cfg.get("ANALOG_DEADZONE_PLAYER_1",   "0.2"),
        "deadzone_p2":                cfg.get("ANALOG_DEADZONE_PLAYER_2",   "0.2"),
        "deadzone_p3":                cfg.get("ANALOG_DEADZONE_PLAYER_3",   "0.2"),
        "deadzone_p4":                cfg.get("ANALOG_DEADZONE_PLAYER_4",   "0.2"),
        "emulate_second":             cfg.get("EMULATE_SECOND",             ""),
    }


# ---------------------------------------------------------------------------
# Service helpers
# ---------------------------------------------------------------------------

def systemctl(*args):
    """Run a systemctl command; return (success, output)."""
    try:
        result = subprocess.run(
            ["systemctl"] + list(args),
            capture_output=True, text=True, timeout=15
        )
        return result.returncode == 0, (result.stdout + result.stderr).strip()
    except Exception as e:
        return False, str(e)


def get_player_slots(logs=None):
    """Parse player slot assignments from the most recent service run's logs.

    Scans the service log for ``Player N:`` lines emitted by initInputs()
    and returns them as a list sorted by player number.  Only the most recent
    service start (identified by the last 'ModernJVS Version' banner) is used
    so that stale entries from a previous run are not shown.

    Hot-plug cycle boundary detection
    ----------------------------------
    After each call to initInputs() the service always prints (at debug level 0):

        ``  Output:          <game-path>``

    This line is the reliable boundary between reinit cycles.  Player
    assignments are accumulated into a *pending* dict as they are seen; when
    ``  Output:`` is encountered the pending dict is committed as the result
    of that cycle, replacing whatever the previous cycle had recorded.  This
    ensures that stale slots from a previous cycle (e.g. the P2 slot for a
    controller that has since disconnected and whose replacement now occupies
    P1) are cleared rather than left behind.

    If controllers are subsequently disconnected (indicated by a
    ``Controllers:     None`` or ``No controllers detected`` log line appearing
    after the last player assignment), an empty list is returned so the UI
    reflects the current disconnected state rather than stale assignments.

    ``logs`` may be passed in to avoid a redundant journalctl call when the
    caller has already fetched the log lines.

    Returns a list of dicts: [{"player": int, "profile": str}, ...]
    """
    if logs is None:
        since = _get_service_active_since()
        logs = get_logs(since=since) if since else get_logs(200)
    # Find index of the last service startup banner
    start_idx = 0
    for i in range(len(logs) - 1, -1, -1):
        if "ModernJVS Version" in logs[i]:
            start_idx = i
            break

    # Pattern matches both variants:
    #   Player 1:                  nintendo-wii-remote (Wiimote+Nunchuk)
    #   Player 1 (Fixed via config):  sony-dualshock4
    _player_re = re.compile(r'Player\s+(\d+)(?:\s+\([^)]*\))?\s*:\s+(\S[^\n]*)')

    # ``committed_players`` holds the last fully-completed reinit cycle's
    # assignments.  ``pending_players`` accumulates assignments for the cycle
    # that is currently being parsed.  When ``  Output:`` is seen the pending
    # dict is committed (replacing the previous cycle entirely) so that stale
    # slots from earlier cycles cannot leak through.
    committed_players = {}
    pending_players = {}
    last_player_idx = -1
    last_no_controllers_idx = -1
    for idx, line in enumerate(logs[start_idx:], start=start_idx):
        m = _player_re.search(line)
        if m:
            num = int(m.group(1))
            pending_players[num] = m.group(2).strip()
            last_player_idx = idx
        elif "  Output:" in line and pending_players:
            # End of a reinit cycle: commit pending assignments and reset.
            # Only commit when pending is non-empty to avoid clobbering a
            # previous good cycle when a reinit finds no controllers and
            # emits no Player lines before its own Output: line.
            committed_players = pending_players
            pending_players = {}
        if "Controllers:     None" in line or "No controllers detected" in line:
            last_no_controllers_idx = idx

    # Use the most recent complete cycle's assignments.  If pending_players is
    # non-empty the Output: line has not yet appeared (e.g. a mid-reinit log
    # read race); those assignments are more current so prefer them.
    players = pending_players if pending_players else committed_players

    # If the most recent reinit cycle reported no controllers (after the last
    # player assignment), return an empty list to reflect the disconnected state.
    if last_no_controllers_idx > last_player_idx:
        return []

    return [{"player": k, "profile": v} for k, v in sorted(players.items())]


def get_jvs_connection_status(logs=None):
    """Determine JVS connection status from the most recent service run's logs.

    Scans the service log for ``JVS: Connection established``,
    ``JVS: Connection reset``, and ``JVS: Connection lost`` lines emitted by
    jvs.c and returns the state based on which event appeared last.  Only the
    most recent service start (identified by the last 'ModernJVS Version'
    banner) is used so that stale entries from a previous run are not shown.

    ``JVS: Connection reset`` is logged when the arcade machine sends CMD_RESET.
    ``JVS: Connection lost`` is logged after 5 s of inactivity on an established
    connection (e.g. arcade machine powered off without sending a reset).

    Uses the service's active start timestamp (``--since``) rather than a fixed
    line count so that debug-mode log flooding does not hide the connection
    events from the query window.

    ``logs`` may be passed in to avoid a redundant journalctl call when the
    caller has already fetched the log lines.

    Returns True if the JVS connection is currently established, False otherwise.
    """
    if logs is None:
        since = _get_service_active_since()
        logs = get_logs(since=since) if since else get_logs(200)
    # Find index of the last service startup banner
    start_idx = 0
    for i in range(len(logs) - 1, -1, -1):
        if "ModernJVS Version" in logs[i]:
            start_idx = i
            break

    connected = False
    for line in logs[start_idx:]:
        if JVS_LOG_CONNECTED in line:
            connected = True
        elif JVS_LOG_DISCONNECTED in line or JVS_LOG_LOST in line:
            connected = False
    return connected


def get_service_status():
    """Return a dict with service state information."""
    ok, out = systemctl("show", SERVICE_NAME,
                        "--property=ActiveState,MainPID,ActiveEnterTimestamp")
    props = {}
    for line in out.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            props[k.strip()] = v.strip()

    # Fetch logs once and share between player-slot and JVS-status parsing so
    # that journalctl is only invoked once per /api/status request.
    since = props.get("ActiveEnterTimestamp") or None
    logs = get_logs(since=since) if since else get_logs(200)

    cfg = config_to_api(read_config())
    active_state = props.get("ActiveState", "unknown")
    # If the daemon is not running, test mode cannot be active.  Reset the
    # in-memory mirror and skip the state file (which may be stale if the
    # daemon crashed before it could delete it).
    if active_state not in ("active", "activating"):
        global _test_button_active
        with _test_button_lock:
            _test_button_active = False
        test_active = False
    else:
        test_active = get_test_button_active()
    jvs_connected = get_jvs_connection_status(logs=logs)
    # Test mode is only meaningful with an active JVS connection.  A controller
    # button mapped to BUTTON_TEST can toggle the daemon's latch even before a
    # JVS connection is established; suppress the active state here so the
    # dashboard never shows "Active" without a live connection.
    if not jvs_connected:
        test_active = False
    return {
        "active_state":       active_state,
        "main_pid":           props.get("MainPID", ""),
        "active_since":       props.get("ActiveEnterTimestamp", ""),
        "config":             cfg,
        "players":            get_player_slots(logs=logs),
        "jvs_connected":      jvs_connected,
        "test_button_active": test_active,
    }


def get_logs(lines=100, since=None):
    """Return recent log lines for the modernjvs service.

    Tries journalctl first (works on Raspberry Pi OS and DietPi with journald).
    Falls back to grepping syslog files on systems without a persistent journal
    (e.g. DietPi configured with volatile-only journald or syslog-only logging).

    If ``since`` is provided it is passed to journalctl as ``--since`` so that
    all entries from that timestamp onward are returned regardless of volume
    (useful when debug mode floods the journal and a fixed line-count window
    would miss the service startup messages).  When ``since`` is used the
    ``lines`` parameter is ignored for the journalctl path.
    """
    lines_count = int(lines)
    lines_str = str(lines_count)

    # Primary: journalctl (systemd journal – works on RPiOS and most DietPi setups)
    try:
        cmd = ["journalctl", "-u", SERVICE_NAME, "--no-pager", "--output=short-iso"]
        if since:
            cmd += ["--since", since]
        else:
            cmd += ["-n", lines_str]
        result = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=15
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.splitlines()
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        pass

    # Fallback: grep system syslog files (DietPi with syslog / no journald persistence)
    syslog_paths = [
        "/var/log/syslog",
        "/var/log/daemon.log",
        "/var/log/messages",
    ]
    for path in syslog_paths:
        try:
            result = subprocess.run(
                ["grep", "-i", SERVICE_NAME, path],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0 and result.stdout.strip():
                log_lines = result.stdout.splitlines()
                return log_lines[-lines_count:]
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            continue

    return [f"No log source found. Run:  journalctl -u {SERVICE_NAME}  to check manually."]


def _get_service_active_since():
    """Return the ActiveEnterTimestamp for the modernjvs service, or None.

    Returns the timestamp string that can be passed directly to journalctl
    ``--since`` to retrieve all log entries from the current service run.
    Returns None if the timestamp cannot be determined (e.g. service inactive).
    """
    ok, out = systemctl("show", SERVICE_NAME, "--property=ActiveEnterTimestamp")
    if not ok:
        return None
    for line in out.splitlines():
        if line.startswith("ActiveEnterTimestamp="):
            ts = line.split("=", 1)[1].strip()
            return ts if ts else None
    return None


# Module-level CPU sampling state for delta calculation between API calls
_cpu_prev = None   # (total_jiffies, idle_jiffies)


def get_sysinfo():
    """Return system resource stats using /proc and /sys (no external deps).

    Works on Raspberry Pi OS, DietPi, and any Linux with standard /proc/sys.
    """
    global _cpu_prev

    # --- CPU usage (delta between consecutive calls) ---
    cpu_pct = 0.0
    try:
        with open("/proc/stat") as f:
            line = f.readline()
        fields = [int(x) for x in line.split()[1:]]
        # fields: user nice system idle iowait irq softirq steal guest guest_nice
        idle  = fields[3] + (fields[4] if len(fields) > 4 else 0)  # idle + iowait
        total = sum(fields)
        if _cpu_prev is not None:
            prev_total, prev_idle = _cpu_prev
            dt = total - prev_total
            di = idle - prev_idle
            if dt > 0:
                cpu_pct = round(max(0.0, min(100.0, 100.0 * (1.0 - di / dt))), 1)
        _cpu_prev = (total, idle)
    except Exception:
        pass

    # --- Memory ---
    mem_used_mb = mem_total_mb = 0
    mem_pct = 0.0
    try:
        meminfo = {}
        with open("/proc/meminfo") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    meminfo[parts[0].rstrip(":")] = int(parts[1])
        mem_total_kb     = meminfo.get("MemTotal", 0)
        mem_available_kb = meminfo.get("MemAvailable", meminfo.get("MemFree", 0))
        mem_used_mb  = (mem_total_kb - mem_available_kb) // 1024
        mem_total_mb = mem_total_kb // 1024
        if mem_total_kb > 0:
            mem_pct = round(100.0 * (mem_total_kb - mem_available_kb) / mem_total_kb, 1)
    except Exception:
        pass

    # --- CPU temperature (Raspberry Pi & DietPi use thermal_zone0) ---
    temp_c = None
    for tz_path in (
        "/sys/class/thermal/thermal_zone0/temp",
        "/sys/class/thermal/thermal_zone1/temp",
    ):
        try:
            with open(tz_path) as f:
                temp_c = round(int(f.read().strip()) / 1000.0, 1)
            break
        except Exception:
            continue

    # --- Disk usage (root filesystem) ---
    disk_used_gb = disk_total_gb = 0.0
    disk_pct = 0.0
    try:
        st = os.statvfs("/")
        disk_total = st.f_blocks * st.f_frsize
        disk_free  = st.f_bavail * st.f_frsize
        disk_used  = disk_total - disk_free
        disk_total_gb = round(disk_total / 1e9, 1)
        disk_used_gb  = round(disk_used  / 1e9, 1)
        if disk_total > 0:
            disk_pct = round(100.0 * disk_used / disk_total, 1)
    except Exception:
        pass

    # --- Load average ---
    load_avg = ""
    try:
        with open("/proc/loadavg") as f:
            parts = f.read().split()
            load_avg = " ".join(parts[:3])
    except Exception:
        pass

    # --- Local IP addresses (LAN IPs only, no loopback) ---
    ip_addresses = []
    try:
        result = subprocess.run(
            ["hostname", "-I"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            ip_addresses = [
                ip for ip in result.stdout.split()
                if not ip.startswith("127.") and not ip.startswith("::1")
                and ":" not in ip               # skip IPv6
            ]
    except Exception:
        pass

    # --- Kernel version ---
    kernel_version = ""
    try:
        with open("/proc/version") as f:
            line = f.read().split()
            # format: "Linux version X.Y.Z-... ..."
            if len(line) >= 3:
                kernel_version = line[2]
    except Exception:
        pass

    # --- libgpiod version ---
    libgpiod_version = ""
    try:
        r = subprocess.run(
            ["gpiodetect", "--version"],
            capture_output=True, text=True, timeout=5,
        )
        # gpiodetect prints "gpiodetect (libgpiod) vX.Y.Z" to stdout or stderr
        out = (r.stdout or r.stderr or "").strip()
        m = re.search(r'v?(\d+\.\d+[\.\d]*)', out)
        if m:
            libgpiod_version = m.group(1)
    except Exception:
        pass
    # Fallback: ask dpkg (works on Pi OS Bullseye where gpiodetect lacks --version)
    if not libgpiod_version:
        for pkg in ("libgpiod2", "libgpiod-dev", "libgpiod3"):
            try:
                r = subprocess.run(
                    ["dpkg-query", "-W", "-f=${Version}", pkg],
                    capture_output=True, text=True, timeout=5,
                )
                v = (r.stdout or "").strip()
                if v and not v.startswith("dpkg"):
                    # Strip Debian revision suffix (e.g. "1.6.3-1+rpt1" -> "1.6.3")
                    libgpiod_version = v.split("-")[0]
                    break
            except Exception:
                pass

    # --- Raspberry Pi model ---
    pi_model_sysinfo = ""
    try:
        with open("/proc/device-tree/model", "r", encoding="utf-8", errors="replace") as f:
            pi_model_sysinfo = f.read().strip().rstrip("\x00")
    except OSError:
        pass

    return {
        "cpu_pct":        cpu_pct,
        "mem_used_mb":    mem_used_mb,
        "mem_total_mb":   mem_total_mb,
        "mem_pct":        mem_pct,
        "temp_c":         temp_c,
        "disk_used_gb":   disk_used_gb,
        "disk_total_gb":  disk_total_gb,
        "disk_pct":       disk_pct,
        "load_avg":       load_avg,
        "ip_addresses":   ip_addresses,
        "kernel_version": kernel_version,
        "libgpiod_version": libgpiod_version,
        "pi_model":       pi_model_sysinfo,
    }


def list_dir(path):
    """Return sorted list of plain files in a directory (no dotfiles)."""
    try:
        return sorted(
            e for e in os.listdir(path)
            if not e.startswith(".") and os.path.isfile(os.path.join(path, e))
        )
    except OSError:
        return []


# ---------------------------------------------------------------------------
# Diagnostics helpers
# ---------------------------------------------------------------------------

def diag_serial_test(device_path):
    """Try to open device_path as a 115200 8N1 serial port.

    Returns a dict with keys: ok (bool), message (str).
    Uses only stdlib (termios + fcntl) so no external dependencies are needed.
    """
    import termios
    import fcntl
    import errno as _errno

    device_path = device_path.strip()
    if not device_path:
        return {"ok": False, "message": "No device path configured."}

    # Only allow /dev/ paths to prevent path traversal
    if not device_path.startswith("/dev/"):
        return {"ok": False, "message": f"Refusing to test non-/dev/ path: {device_path}"}

    try:
        fd = os.open(device_path, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    except OSError as e:
        return {"ok": False, "message": f"Cannot open {device_path}: {e.strerror} (errno {e.errno})"}

    try:
        # Check it is a tty
        if not os.isatty(fd):
            return {"ok": False, "message": f"{device_path} is not a TTY device."}

        # Get and set terminal attributes to 115200 8N1
        try:
            attrs = termios.tcgetattr(fd)
        except termios.error as e:
            return {"ok": False, "message": f"tcgetattr failed on {device_path}: {e}"}

        # cfsetispeed / cfsetospeed via termios constants
        attrs[4] = termios.B115200  # ispeed
        attrs[5] = termios.B115200  # ospeed
        # c_cflag: 8 data bits, no parity, 1 stop bit, enable receiver, no modem control
        attrs[2] = (
            termios.CS8 | termios.CREAD | termios.CLOCAL
        )
        # c_iflag: disable input processing (raw mode)
        attrs[0] = 0
        # c_oflag: disable output processing
        attrs[1] = 0
        # c_lflag: disable echo, canonical, signals
        attrs[3] = 0

        try:
            termios.tcsetattr(fd, termios.TCSANOW, attrs)
        except termios.error as e:
            return {"ok": False, "message": f"tcsetattr failed on {device_path}: {e}"}

        return {
            "ok": True,
            "message": f"Opened {device_path} successfully at 115200 8N1.",
        }
    finally:
        os.close(fd)


# JVS protocol constants used by the bus probe
_JVS_SYNC   = 0xE0
_JVS_ESCAPE = 0xD0

# Event set by POST /api/diag/gpio/cancel to interrupt a running _gpio_write_line sleep.
_gpio_set_cancel = threading.Event()

# Human-readable names for JVS command bytes (master → slave direction)
_JVS_CMD_NAMES = {
    0xF0: "RESET",
    0xF1: "ASSIGN_ADDR",
    0xF2: "SET_COMMS_MODE",
    0x10: "REQUEST_ID",
    0x11: "COMMAND_VERSION",
    0x12: "JVS_VERSION",
    0x13: "COMMS_VERSION",
    0x14: "CAPABILITIES",
    0x15: "CONVEY_ID",
    0x20: "READ_SWITCHES",
    0x21: "READ_COINS",
    0x22: "READ_ANALOGS",
    0x23: "READ_ROTARY",
    0x24: "READ_KEYPAD",
    0x25: "READ_LIGHTGUN",
    0x26: "READ_GPI",
    0x2E: "REMAINING_PAYOUT",
    0x2F: "RETRANSMIT",
    0x30: "DECREASE_COINS",
    0x31: "SET_PAYOUT",
    0x32: "WRITE_GPO",
    0x33: "WRITE_ANALOG",
    0x34: "WRITE_DISPLAY",
    0x35: "WRITE_COINS",
    0x36: "SUBTRACT_PAYOUT",
    0x37: "WRITE_GPO_BYTE",
    0x38: "WRITE_GPO_BIT",
    0x70: "NAMCO_SPECIFIC",
}

# JVS status/report bytes that appear in slave → master responses
_JVS_STATUS_NAMES = {
    0x01: "STATUS_SUCCESS",
    0x02: "STATUS_UNSUPPORTED",
    0x03: "STATUS_CHECKSUM_FAILURE",
    0x04: "STATUS_OVERFLOW",
}


def _parse_jvs_packets(data):
    """Parse a raw byte sequence and return a list of identified JVS packets.

    Each entry is a dict:
        name   – command/status name string
        dest   – human-readable destination ("BROADCAST", "MASTER", or "0xNN")
        length – declared packet length field value

    This is best-effort: malformed bytes are silently skipped.
    """
    packets = []
    raw = bytes(data)
    i = 0

    while i < len(raw) and len(packets) < 16:
        # Scan for SYNC byte
        if raw[i] != _JVS_SYNC:
            i += 1
            continue

        i += 1  # consume SYNC

        # Read destination (with un-escaping)
        if i >= len(raw):
            break
        if raw[i] == _JVS_ESCAPE:
            i += 1
            if i >= len(raw):
                break
            dest = raw[i] + 1
        else:
            dest = raw[i]
        i += 1

        # Read length (with un-escaping)
        if i >= len(raw):
            break
        if raw[i] == _JVS_ESCAPE:
            i += 1
            if i >= len(raw):
                break
            length = raw[i] + 1
        else:
            length = raw[i]
        i += 1

        if length < 2:
            continue  # length must cover at least 1 data byte + 1 checksum

        # Read payload bytes (length − 1 data bytes; last byte is checksum)
        payload_len = length - 1
        payload = []
        for _ in range(payload_len):
            if i >= len(raw):
                break
            if raw[i] == _JVS_ESCAPE:
                i += 1
                if i >= len(raw):
                    break
                payload.append(raw[i] + 1)
            else:
                payload.append(raw[i])
            i += 1

        if not payload:
            continue

        first_byte = payload[0]
        # Destination 0x00 = BUS_MASTER (slave → master response)
        # Destination 0xFF = BROADCAST (master → all slaves)
        # Destination 0x01–0xFE = specific slave address
        if dest == 0xFF:
            dest_str = "BROADCAST"
        elif dest == 0x00:
            dest_str = "MASTER"
        else:
            dest_str = f"0x{dest:02X}"

        # For slave→master packets the first payload byte is the status code;
        # for master→slave the first payload byte is the first command.
        if dest == 0x00:
            name = _JVS_STATUS_NAMES.get(first_byte, f"0x{first_byte:02X}")
        else:
            name = _JVS_CMD_NAMES.get(first_byte, f"0x{first_byte:02X}")

        packets.append({"name": name, "dest": dest_str, "length": length})

    return packets


def _service_owns_port(pid_str, device_path):
    """Return True if the process pid_str currently has device_path open.

    Walks /proc/<pid>/fd/ and checks each symlink target against device_path.
    Returns False (never raises) on any permission error or missing entry.
    """
    try:
        pid = int(pid_str)
    except (TypeError, ValueError):
        return False
    if pid <= 0:
        return False
    fd_dir = f"/proc/{pid}/fd"
    try:
        for entry in os.listdir(fd_dir):
            try:
                target = os.readlink(os.path.join(fd_dir, entry))
                if target == device_path:
                    return True
            except OSError:
                continue
    except OSError:
        pass
    return False


def diag_jvs_probe(device_path):
    """Probe the JVS bus on device_path.

    Behaviour depends on whether the ModernJVS service is already running:

    Service RUNNING:
        The daemon owns the port and is actively exchanging JVS packets with
        the arcade board.  We confirm the daemon has the port open via
        /proc/<PID>/fd/ and return an informational result without touching
        the port.

    Service STOPPED:
        Opens device_path at 115200 8N1, floats the sense line GPIO (if
        SENSE_LINE_TYPE == "1"), flushes stale input, sends:
          1. JVS RESET broadcast (SYNC | 0xFF | 0x03 | CMD_RESET(0xF0) | 0xD9 | checksum)
          2. JVS ASSIGN_ADDR broadcast (SYNC | 0xFF | 0x03 | CMD_ASSIGN_ADDR(0xF1) | 0x01 | checksum)
        then collects any bytes received within 2 s.

    Returns a dict:
        ok             – False on OS/TTY errors, True otherwise
        mode           – "service_running" | "active_probe"
        activity       – True if bus activity confirmed or bytes received
        bytes_received – count of received bytes (0 in service_running mode)
        raw_hex        – space-separated hex of up to 64 bytes
        truncated      – True when more than 64 bytes were received
        packets        – list of parsed JVS packet dicts (see _parse_jvs_packets)
        message        – human-readable summary
    """
    import termios
    import select as _select

    device_path = device_path.strip()
    if not device_path:
        return {"ok": False, "message": "No device path configured."}

    # Only allow /dev/ paths to prevent path traversal
    if not device_path.startswith("/dev/"):
        return {"ok": False, "message": f"Refusing to probe non-/dev/ path: {device_path}"}

    # ------------------------------------------------------------------
    # Service-running check: when the daemon already has the port open, any
    # attempt to open it ourselves + send a RESET broadcast would disrupt
    # the live session and cause the probe to read silence (the daemon's
    # tight select() loop consumes all incoming bytes first).
    # Instead, confirm via /proc/<PID>/fd/ that the daemon owns the port,
    # then return an informational result without touching the serial port.
    # ------------------------------------------------------------------
    _, svc_out = systemctl("show", SERVICE_NAME,
                           "--property=ActiveState,MainPID")
    svc_props = {}
    for line in svc_out.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            svc_props[k.strip()] = v.strip()

    if svc_props.get("ActiveState") == "active":
        pid_str = svc_props.get("MainPID", "")
        port_open = _service_owns_port(pid_str, device_path) if pid_str and pid_str != "0" else False
        if port_open:
            msg = (f"ModernJVS service is running and has {device_path} open — "
                   "the bus is actively in use by the daemon.")
        else:
            msg = ("ModernJVS service is running — the bus is in use by the daemon.")
        return {
            "ok":             True,
            "mode":           "service_running",
            "activity":       True,
            "bytes_received": 0,
            "raw_hex":        "",
            "truncated":      False,
            "packets":        [],
            "message":        msg,
        }

    try:
        fd = os.open(device_path, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    except OSError as e:
        return {"ok": False, "message": f"Cannot open {device_path}: {e.strerror} (errno {e.errno})"}

    try:
        if not os.isatty(fd):
            return {"ok": False, "message": f"{device_path} is not a TTY device."}

        # Configure 115200 8N1 raw mode (mirrors what the C daemon does)
        try:
            attrs = termios.tcgetattr(fd)
        except termios.error as e:
            return {"ok": False, "message": f"tcgetattr failed on {device_path}: {e}"}

        attrs[4] = termios.B115200   # c_ispeed
        attrs[5] = termios.B115200   # c_ospeed
        attrs[2] = termios.CS8 | termios.CREAD | termios.CLOCAL  # c_cflag
        attrs[0] = 0                 # c_iflag – disable all input processing
        attrs[1] = 0                 # c_oflag – disable all output processing
        attrs[3] = 0                 # c_lflag – disable echo / canonical mode
        attrs[6][termios.VMIN]  = 0
        attrs[6][termios.VTIME] = 0

        try:
            termios.tcsetattr(fd, termios.TCSAFLUSH, attrs)
        except termios.error as e:
            return {"ok": False, "message": f"tcsetattr failed on {device_path}: {e}"}

        # Flush any stale input/output
        try:
            termios.tcflush(fd, termios.TCIOFLUSH)
        except termios.error:
            pass

        # ------------------------------------------------------------------
        # Sense line: if configured, float it (set GPIO to INPUT / high-Z)
        # before sending probe packets.  When the daemon is not running the
        # GPIO pin may still be driven LOW (from the last ASSIGN_ADDR), which
        # prevents the arcade board from detecting an I/O device and responding.
        # We keep the handle open for the entire probe so the line stays INPUT.
        # ------------------------------------------------------------------
        cfg = read_config()
        sense_type = cfg.get("SENSE_LINE_TYPE", "0").strip()
        sense_pin_raw = cfg.get("SENSE_LINE_PIN", "26").strip()
        sense_note = ""
        gpio_chip_fd = None
        gpio_line_fd = None
        if sense_type == "1":
            try:
                sense_pin = int(sense_pin_raw)
            except ValueError:
                sense_pin = -1
            if sense_pin >= 0:
                chips = sorted(_glob.glob("/dev/gpiochip*"))
                if chips:
                    gpio_chip_fd, gpio_line_fd = _gpio_open_input(chips[0], sense_pin)
                    if gpio_line_fd is not None:
                        time.sleep(0.01)  # 10 ms for the line to stabilise
                        sense_note = f" (sense line GPIO{sense_pin} floated)"
                    else:
                        # Open failed; close chip_fd if it was returned
                        if gpio_chip_fd is not None:
                            try:
                                os.close(gpio_chip_fd)
                            except OSError:
                                pass
                            gpio_chip_fd = None
                        sense_note = f" (warning: could not float sense line GPIO{sense_pin})"

        try:
            # ----------------------------------------------------------------
            # Build probe packets (master → all slaves, broadcast addr 0xFF)
            #
            # RESET broadcast:
            #   SYNC(0xE0) | dest(0xFF) | len(0x03) | CMD_RESET(0xF0) | 0xD9 | chk
            #   checksum = (0xFF + 0x03 + 0xF0 + 0xD9) & 0xFF = 0x2CB & 0xFF = 0xCB
            #
            # ASSIGN_ADDR broadcast (assign address 0x01):
            #   SYNC(0xE0) | dest(0xFF) | len(0x03) | CMD_ASSIGN_ADDR(0xF1) | 0x01 | chk
            #   checksum = (0xFF + 0x03 + 0xF1 + 0x01) & 0xFF = 0x1F4 & 0xFF = 0xF4
            #
            # None of these bytes equal SYNC(0xE0) or ESCAPE(0xD0) so no escaping
            # is needed in the data portion.
            # ----------------------------------------------------------------
            reset_packet       = bytes([0xE0, 0xFF, 0x03, 0xF0, 0xD9, 0xCB])
            assign_addr_packet = bytes([0xE0, 0xFF, 0x03, 0xF1, 0x01, 0xF4])

            try:
                os.write(fd, reset_packet)
            except OSError:
                pass  # write failure is non-fatal; we still listen for traffic

            time.sleep(0.005)  # 5 ms gap between packets

            try:
                os.write(fd, assign_addr_packet)
            except OSError:
                pass

            # Collect bytes for up to 2 s
            deadline  = time.monotonic() + 2.0
            received  = bytearray()

            while time.monotonic() < deadline:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                r, _, _ = _select.select([fd], [], [], min(remaining, 0.05))
                if fd in r:
                    try:
                        chunk = os.read(fd, 256)
                        if chunk:
                            received.extend(chunk)
                    except OSError:
                        break
        finally:
            # Release the sense line GPIO handle now that the probe is complete
            if gpio_line_fd is not None:
                try:
                    os.close(gpio_line_fd)
                except OSError:
                    pass
            if gpio_chip_fd is not None:
                try:
                    os.close(gpio_chip_fd)
                except OSError:
                    pass

        # Parse any JVS packets found in the received bytes
        packets   = _parse_jvs_packets(received)
        hex_str   = received[:64].hex(' ') if received else ''
        truncated = len(received) > 64

        if received:
            msg = f"Bus activity detected — {len(received)} byte(s) received"
            if packets:
                names = ', '.join(p['name'] for p in packets[:3])
                msg += f" ({names})"
            if truncated:
                msg += " (showing first 64 bytes)"
            msg += sense_note
        else:
            msg = ("No response after 2 s — silence on bus "
                   "(nothing connected, wrong port, or wiring fault)"
                   + sense_note)

        return {
            "ok":             True,
            "mode":           "active_probe",
            "activity":       bool(received),
            "bytes_received": len(received),
            "raw_hex":        hex_str,
            "truncated":      truncated,
            "packets":        packets,
            "message":        msg,
        }
    finally:
        os.close(fd)


def diag_jvs_monitor(device_path):
    """Passively listen on device_path for 5 seconds without sending any bytes.

    Behaviour depends on whether the ModernJVS service is already running:

    Service RUNNING:
        The daemon owns the port.  We confirm via /proc/<PID>/fd/ and return an
        informational result without touching the port.

    Service STOPPED:
        Opens device_path at 115200 8N1, floats the sense line GPIO (if
        SENSE_LINE_TYPE == "1"), flushes stale input, then listens for 5 s.
        No bytes are written to the bus.

    Returns a dict:
        ok             – False on OS/TTY errors, True otherwise
        mode           – "service_running" | "monitor"
        activity       – True if bus activity detected or bytes received
        bytes_received – count of received bytes (0 in service_running mode)
        raw_hex        – space-separated hex of up to 64 bytes
        truncated      – True when more than 64 bytes were received
        packets        – list of parsed JVS packet dicts (see _parse_jvs_packets)
        message        – human-readable summary
    """
    import termios
    import select as _select

    device_path = device_path.strip()
    if not device_path:
        return {"ok": False, "message": "No device path configured."}

    if not device_path.startswith("/dev/"):
        return {"ok": False, "message": f"Refusing to monitor non-/dev/ path: {device_path}"}

    # Service-running check (same as diag_jvs_probe)
    _, svc_out = systemctl("show", SERVICE_NAME,
                           "--property=ActiveState,MainPID")
    svc_props = {}
    for line in svc_out.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            svc_props[k.strip()] = v.strip()

    if svc_props.get("ActiveState") == "active":
        pid_str  = svc_props.get("MainPID", "")
        port_open = _service_owns_port(pid_str, device_path) if pid_str and pid_str != "0" else False
        msg = (f"ModernJVS service is running and has {device_path} open — "
               "the bus is actively in use by the daemon."
               if port_open else
               "ModernJVS service is running — the bus is in use by the daemon.")
        return {
            "ok":             True,
            "mode":           "service_running",
            "activity":       True,
            "bytes_received": 0,
            "raw_hex":        "",
            "truncated":      False,
            "packets":        [],
            "message":        msg,
        }

    try:
        fd = os.open(device_path, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    except OSError as e:
        return {"ok": False, "message": f"Cannot open {device_path}: {e.strerror} (errno {e.errno})"}

    try:
        if not os.isatty(fd):
            return {"ok": False, "message": f"{device_path} is not a TTY device."}

        try:
            attrs = termios.tcgetattr(fd)
        except termios.error as e:
            return {"ok": False, "message": f"tcgetattr failed on {device_path}: {e}"}

        attrs[4] = termios.B115200
        attrs[5] = termios.B115200
        attrs[2] = termios.CS8 | termios.CREAD | termios.CLOCAL
        attrs[0] = 0
        attrs[1] = 0
        attrs[3] = 0
        attrs[6][termios.VMIN]  = 0
        attrs[6][termios.VTIME] = 0

        try:
            termios.tcsetattr(fd, termios.TCSAFLUSH, attrs)
        except termios.error as e:
            return {"ok": False, "message": f"tcsetattr failed on {device_path}: {e}"}

        try:
            termios.tcflush(fd, termios.TCIOFLUSH)
        except termios.error:
            pass

        # Float the sense line (same logic as diag_jvs_probe)
        cfg = read_config()
        sense_type    = cfg.get("SENSE_LINE_TYPE", "0").strip()
        sense_pin_raw = cfg.get("SENSE_LINE_PIN", "26").strip()
        sense_note    = ""
        gpio_chip_fd  = None
        gpio_line_fd  = None
        if sense_type == "1":
            try:
                sense_pin = int(sense_pin_raw)
            except ValueError:
                sense_pin = -1
            if sense_pin >= 0:
                chips = sorted(_glob.glob("/dev/gpiochip*"))
                if chips:
                    gpio_chip_fd, gpio_line_fd = _gpio_open_input(chips[0], sense_pin)
                    if gpio_line_fd is not None:
                        time.sleep(0.01)
                        sense_note = f" (sense line GPIO{sense_pin} floated)"
                    else:
                        if gpio_chip_fd is not None:
                            try:
                                os.close(gpio_chip_fd)
                            except OSError:
                                pass
                            gpio_chip_fd = None
                        sense_note = f" (warning: could not float sense line GPIO{sense_pin})"

        try:
            # Passive listen — no bytes sent to bus
            deadline = time.monotonic() + 5.0
            received = bytearray()

            while time.monotonic() < deadline:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                r, _, _ = _select.select([fd], [], [], min(remaining, 0.05))
                if fd in r:
                    try:
                        chunk = os.read(fd, 256)
                        if chunk:
                            received.extend(chunk)
                    except OSError:
                        break
        finally:
            if gpio_line_fd is not None:
                try:
                    os.close(gpio_line_fd)
                except OSError:
                    pass
            if gpio_chip_fd is not None:
                try:
                    os.close(gpio_chip_fd)
                except OSError:
                    pass

        packets   = _parse_jvs_packets(received)
        hex_str   = received[:64].hex(' ') if received else ''
        truncated = len(received) > 64

        if received:
            msg = f"Bus activity detected — {len(received)} byte(s) received"
            if packets:
                msg += f" ({', '.join(p['name'] for p in packets[:3])})"
            if truncated:
                msg += " (showing first 64 bytes)"
            msg += sense_note
        else:
            msg = ("No traffic after 5 s — silence on bus "
                   "(nothing connected, wrong port, or wiring fault)"
                   + sense_note)

        return {
            "ok":             True,
            "mode":           "monitor",
            "activity":       bool(received),
            "bytes_received": len(received),
            "raw_hex":        hex_str,
            "truncated":      truncated,
            "packets":        packets,
            "message":        msg,
        }
    finally:
        os.close(fd)


def diag_usb_devices():
    """List connected USB devices by reading /sys/bus/usb/devices/.

    For each device that exposes idVendor/idProduct (i.e. actual devices,
    not USB interfaces or root hubs), returns:
      path        – sysfs entry name (e.g. "1-1.2")
      vid / pid   – vendor/product ID (4-char hex strings, lower-case)
      manufacturer / product – human-readable strings (may be empty)
      driver      – kernel driver currently bound to the first interface,
                    or "" if unbound
      is_rs485    – True when the VID:PID matches a known RS-485/serial adapter
      rs485_chip  – friendly chip name when is_rs485 is True, else ""
      is_serial_driver – True when the bound driver is a serial/CDC driver
    """
    usb_base = "/sys/bus/usb/devices"
    devices = []

    try:
        entries = os.listdir(usb_base)
    except OSError as e:
        return {"error": f"Cannot read {usb_base}: {e.strerror}"}

    for entry in sorted(entries):
        dev_path = os.path.join(usb_base, entry)

        def _read_attr(fname, base_path=dev_path):
            try:
                with open(os.path.join(base_path, fname), errors="replace") as f:
                    return f.read().strip()
            except OSError:
                return None

        vid = _read_attr("idVendor")
        pid = _read_attr("idProduct")
        # Skip USB interfaces (e.g. "1-1.2:1.0") and entries without VID/PID
        if not vid or not pid:
            continue

        manufacturer = _read_attr("manufacturer") or ""
        product      = _read_attr("product")      or ""

        # Find the first interface sub-directory that has a bound driver
        driver = ""
        try:
            for iface in sorted(os.listdir(dev_path)):
                iface_path = os.path.join(dev_path, iface)
                if not os.path.isdir(iface_path):
                    continue
                drv_link = os.path.join(iface_path, "driver")
                if os.path.islink(drv_link):
                    driver = os.path.basename(os.readlink(drv_link))
                    break
        except OSError:
            pass

        vid_lower = vid.lower()
        pid_lower = pid.lower()
        key = (vid_lower, pid_lower)
        is_rs485   = key in _USB_RS485_KNOWN
        rs485_chip = _USB_RS485_KNOWN.get(key, "")
        is_serial_driver = driver in _USB_SERIAL_DRIVERS

        devices.append({
            "path":             entry,
            "vid":              vid_lower,
            "pid":              pid_lower,
            "manufacturer":     manufacturer,
            "product":          product,
            "driver":           driver,
            "is_rs485":         is_rs485,
            "rs485_chip":       rs485_chip,
            "is_serial_driver": is_serial_driver,
        })

    return {"devices": devices}


def _gpio_open_input(chip_path, line_offset):
    """Request a GPIO line as INPUT (float/high-Z) using the kernel GPIO ioctl.

    Returns (chip_fd, line_fd) on success, or (None, None) on any error.
    Both fds must be closed by the caller when the line is no longer needed.
    Releasing the line_fd returns the GPIO line to its default kernel-managed state.

    Tries the v1 GPIO ABI first (kernel >= 4.8), then v2 (kernel >= 5.10).
    No external CLI tools or Python C extensions are required.
    """
    import ctypes
    import errno as _errno
    import fcntl

    # ---- v1 ABI constants ----
    GPIOHANDLES_MAX          = 64
    GPIOHANDLE_REQUEST_INPUT = 1
    # _IOWR(0xB4, 0x03, struct gpiohandle_request)  sizeof = 364 bytes
    GPIO_GET_LINEHANDLE_IOCTL = 0xC16CB403

    class GpiohandleRequest(ctypes.Structure):
        _fields_ = [
            ("lineoffsets",    ctypes.c_uint32 * GPIOHANDLES_MAX),
            ("flags",          ctypes.c_uint32),
            ("default_values", ctypes.c_uint8  * GPIOHANDLES_MAX),
            ("consumer_label", ctypes.c_char   * 32),
            ("lines",          ctypes.c_uint32),
            ("fd",             ctypes.c_int),
        ]

    # ---- v2 ABI constants ----
    GPIO_V2_LINES_MAX          = 64
    GPIO_MAX_NAME_SIZE         = 32
    GPIO_V2_LINE_NUM_ATTRS_MAX = 10
    GPIO_V2_LINE_FLAG_INPUT    = (1 << 3)
    # _IOWR(0xB4, 0x0F, struct gpio_v2_line_request)  sizeof = 592 bytes
    GPIO_V2_GET_LINE_IOCTL = 0xC250B40F

    class _GpioV2LineAttrUnion(ctypes.Union):
        _fields_ = [
            ("flags",              ctypes.c_uint64),
            ("values",             ctypes.c_uint64),
            ("debounce_period_us", ctypes.c_uint32),
        ]

    class GpioV2LineAttribute(ctypes.Structure):
        _fields_ = [
            ("id",      ctypes.c_uint32),
            ("padding", ctypes.c_uint32),
            ("u",       _GpioV2LineAttrUnion),
        ]

    class GpioV2LineConfigAttribute(ctypes.Structure):
        _fields_ = [
            ("attr", GpioV2LineAttribute),
            ("mask", ctypes.c_uint64),
        ]

    class GpioV2LineConfig(ctypes.Structure):
        _fields_ = [
            ("flags",     ctypes.c_uint64),
            ("num_attrs", ctypes.c_uint32),
            ("padding",   ctypes.c_uint32 * 5),
            ("attrs",     GpioV2LineConfigAttribute * GPIO_V2_LINE_NUM_ATTRS_MAX),
        ]

    class GpioV2LineRequest(ctypes.Structure):
        _fields_ = [
            ("offsets",           ctypes.c_uint32 * GPIO_V2_LINES_MAX),
            ("consumer",          ctypes.c_char   * GPIO_MAX_NAME_SIZE),
            ("config",            GpioV2LineConfig),
            ("num_lines",         ctypes.c_uint32),
            ("event_buffer_size", ctypes.c_uint32),
            ("padding",           ctypes.c_uint32 * 5),
            ("fd",                ctypes.c_int32),
        ]

    try:
        chip_fd = os.open(chip_path, os.O_RDONLY)
    except OSError:
        return None, None

    # Try v1 ABI
    req = GpiohandleRequest()
    req.lineoffsets[0] = line_offset
    req.flags          = GPIOHANDLE_REQUEST_INPUT
    req.consumer_label = b"modernjvs-webui"
    req.lines          = 1
    try:
        fcntl.ioctl(chip_fd, GPIO_GET_LINEHANDLE_IOCTL, req)
        return chip_fd, req.fd   # caller owns both fds
    except OSError as e:
        if e.errno != _errno.ENOTTY:
            os.close(chip_fd)
            return None, None
        # ENOTTY → v1 not supported by this kernel; chip_fd stays open for v2 attempt below

    # Try v2 ABI (chip_fd is still open from above)
    req2 = GpioV2LineRequest()
    req2.offsets[0]      = line_offset
    req2.consumer        = b"modernjvs-webui"
    req2.config.flags    = GPIO_V2_LINE_FLAG_INPUT
    req2.num_lines       = 1
    try:
        fcntl.ioctl(chip_fd, GPIO_V2_GET_LINE_IOCTL, req2)
        return chip_fd, req2.fd   # caller owns both fds
    except OSError:
        os.close(chip_fd)
        return None, None


def _gpio_read_line(chip_path, line_offset):
    """Read a GPIO line value using ctypes and the Linux GPIO character device ioctl.

    Tries the v1 GPIO ABI (GPIO_GET_LINEHANDLE_IOCTL, kernel >= 4.8) first, then
    falls back to the v2 GPIO ABI (GPIO_V2_GET_LINE_IOCTL, kernel >= 5.10, used
    by libgpiod v2) if the kernel does not recognise the v1 ioctl (ENOTTY).
    No external CLI tools or Python C extensions are required.

    Returns 0 or 1 on success.
    Raises PermissionError if the caller lacks access to chip_path or the line.
    Raises OSError if chip_path does not exist, is not a GPIO chip, or
    line_offset is out of range (EINVAL).
    """
    import ctypes
    import errno
    import fcntl

    # ---- v1 ABI (used by libgpiod v1, kernel >= 4.8) ----
    GPIOHANDLES_MAX = 64
    GPIOHANDLE_REQUEST_INPUT = 1
    # _IOWR(0xB4, 0x03, struct gpiohandle_request)  sizeof = 364 bytes
    GPIO_GET_LINEHANDLE_IOCTL = 0xC16CB403
    # _IOWR(0xB4, 0x08, struct gpiohandle_data)     sizeof = 64 bytes
    GPIOHANDLE_GET_LINE_VALUES_IOCTL = 0xC040B408

    class GpiohandleRequest(ctypes.Structure):
        _fields_ = [
            ("lineoffsets",    ctypes.c_uint32 * GPIOHANDLES_MAX),
            ("flags",          ctypes.c_uint32),
            ("default_values", ctypes.c_uint8  * GPIOHANDLES_MAX),
            ("consumer_label", ctypes.c_char   * 32),
            ("lines",          ctypes.c_uint32),
            ("fd",             ctypes.c_int),
        ]

    class GpiohandleData(ctypes.Structure):
        _fields_ = [
            ("values", ctypes.c_uint8 * GPIOHANDLES_MAX),
        ]

    # ---- v2 ABI (used by libgpiod v2, kernel >= 5.10) ----
    GPIO_V2_LINES_MAX        = 64
    GPIO_MAX_NAME_SIZE       = 32
    GPIO_V2_LINE_NUM_ATTRS_MAX = 10
    GPIO_V2_LINE_FLAG_INPUT  = (1 << 3)
    # _IOWR(0xB4, 0x0F, struct gpio_v2_line_request)  sizeof = 592 bytes
    GPIO_V2_GET_LINE_IOCTL          = 0xC250B40F
    # _IOWR(0xB4, 0x12, struct gpio_v2_line_values)   sizeof = 16 bytes
    GPIO_V2_LINE_GET_VALUES_IOCTL   = 0xC010B412

    class _GpioV2LineAttrUnion(ctypes.Union):
        _fields_ = [
            ("flags",              ctypes.c_uint64),
            ("values",             ctypes.c_uint64),
            ("debounce_period_us", ctypes.c_uint32),
        ]

    class GpioV2LineAttribute(ctypes.Structure):
        _fields_ = [
            ("id",      ctypes.c_uint32),
            ("padding", ctypes.c_uint32),
            ("u",       _GpioV2LineAttrUnion),
        ]

    class GpioV2LineConfigAttribute(ctypes.Structure):
        _fields_ = [
            ("attr", GpioV2LineAttribute),
            ("mask", ctypes.c_uint64),
        ]

    class GpioV2LineConfig(ctypes.Structure):
        _fields_ = [
            ("flags",     ctypes.c_uint64),
            ("num_attrs", ctypes.c_uint32),
            ("padding",   ctypes.c_uint32 * 5),
            ("attrs",     GpioV2LineConfigAttribute * GPIO_V2_LINE_NUM_ATTRS_MAX),
        ]

    class GpioV2LineRequest(ctypes.Structure):
        _fields_ = [
            ("offsets",           ctypes.c_uint32 * GPIO_V2_LINES_MAX),
            ("consumer",          ctypes.c_char   * GPIO_MAX_NAME_SIZE),
            ("config",            GpioV2LineConfig),
            ("num_lines",         ctypes.c_uint32),
            ("event_buffer_size", ctypes.c_uint32),
            ("padding",           ctypes.c_uint32 * 5),
            ("fd",                ctypes.c_int32),
        ]

    class GpioV2LineValues(ctypes.Structure):
        _fields_ = [
            ("bits", ctypes.c_uint64),
            ("mask", ctypes.c_uint64),
        ]

    chip_fd = os.open(chip_path, os.O_RDONLY)
    try:
        # Try v1 ABI first (kernel >= 4.8, used by libgpiod v1).
        # ENOTTY from the chip ioctl means the kernel doesn't support v1; any
        # other error (e.g. EINVAL for a bad offset, EPERM) propagates normally.
        req = GpiohandleRequest()
        req.lineoffsets[0] = line_offset
        req.flags = GPIOHANDLE_REQUEST_INPUT
        req.consumer_label = b"modernjvs-webui"
        req.lines = 1
        _v1_line_fd = None
        try:
            fcntl.ioctl(chip_fd, GPIO_GET_LINEHANDLE_IOCTL, req)  # OSError(EINVAL) if line_offset is out of range
            _v1_line_fd = req.fd
        except OSError as e:
            if e.errno != errno.ENOTTY:
                raise
            # v1 ioctl not supported by this kernel — fall through to v2

        if _v1_line_fd is not None:
            try:
                data = GpiohandleData()
                fcntl.ioctl(_v1_line_fd, GPIOHANDLE_GET_LINE_VALUES_IOCTL, data)
                return data.values[0]
            finally:
                os.close(_v1_line_fd)

        # v1 ioctl not supported — fall back to v2 ABI (kernel >= 5.10, used by libgpiod v2)
        req2 = GpioV2LineRequest()
        req2.offsets[0] = line_offset
        req2.consumer = b"modernjvs-webui"
        req2.config.flags = GPIO_V2_LINE_FLAG_INPUT
        req2.num_lines = 1
        fcntl.ioctl(chip_fd, GPIO_V2_GET_LINE_IOCTL, req2)  # OSError(EINVAL) if line_offset is out of range
        _v2_line_fd = req2.fd
        try:
            vals = GpioV2LineValues()
            vals.mask = 1  # bit 0 = first line in the request
            fcntl.ioctl(_v2_line_fd, GPIO_V2_LINE_GET_VALUES_IOCTL, vals)
            return int(vals.bits & 1)
        finally:
            os.close(_v2_line_fd)
    finally:
        os.close(chip_fd)


def _gpio_write_line(chip_path, line_offset, value, duration_s=3.0):
    """Drive a GPIO line as OUTPUT at `value` (0 or 1) for `duration_s` seconds.

    Uses the same v1/v2 kernel GPIO ioctl approach as _gpio_open_input.
    Blocks for duration_s then closes the handle, returning the line to its
    default kernel-managed state.

    Raises OSError on failure (e.g. EBUSY if another process holds the line).
    """
    import ctypes
    import errno as _errno
    import fcntl

    # ---- v1 ABI ----
    GPIOHANDLES_MAX           = 64
    GPIOHANDLE_REQUEST_OUTPUT = 2
    GPIO_GET_LINEHANDLE_IOCTL = 0xC16CB403

    class GpiohandleRequest(ctypes.Structure):
        _fields_ = [
            ("lineoffsets",    ctypes.c_uint32 * GPIOHANDLES_MAX),
            ("flags",          ctypes.c_uint32),
            ("default_values", ctypes.c_uint8  * GPIOHANDLES_MAX),
            ("consumer_label", ctypes.c_char   * 32),
            ("lines",          ctypes.c_uint32),
            ("fd",             ctypes.c_int),
        ]

    # ---- v2 ABI ----
    GPIO_V2_LINES_MAX          = 64
    GPIO_MAX_NAME_SIZE         = 32
    GPIO_V2_LINE_NUM_ATTRS_MAX = 10
    GPIO_V2_LINE_FLAG_OUTPUT   = (1 << 4)
    GPIO_V2_LINE_ATTR_ID_OUTPUT_VALUES = 3
    GPIO_V2_GET_LINE_IOCTL             = 0xC250B40F
    # _IOWR(0xB4, 0x13, struct gpio_v2_line_values)  sizeof = 16 bytes
    GPIO_V2_LINE_SET_VALUES_IOCTL      = 0xC010B413

    class _GpioV2LineAttrUnion(ctypes.Union):
        _fields_ = [
            ("flags",              ctypes.c_uint64),
            ("values",             ctypes.c_uint64),
            ("debounce_period_us", ctypes.c_uint32),
        ]

    class GpioV2LineAttribute(ctypes.Structure):
        _fields_ = [
            ("id",      ctypes.c_uint32),
            ("padding", ctypes.c_uint32),
            ("u",       _GpioV2LineAttrUnion),
        ]

    class GpioV2LineConfigAttribute(ctypes.Structure):
        _fields_ = [
            ("attr", GpioV2LineAttribute),
            ("mask", ctypes.c_uint64),
        ]

    class GpioV2LineConfig(ctypes.Structure):
        _fields_ = [
            ("flags",     ctypes.c_uint64),
            ("num_attrs", ctypes.c_uint32),
            ("padding",   ctypes.c_uint32 * 5),
            ("attrs",     GpioV2LineConfigAttribute * GPIO_V2_LINE_NUM_ATTRS_MAX),
        ]

    class GpioV2LineRequest(ctypes.Structure):
        _fields_ = [
            ("offsets",           ctypes.c_uint32 * GPIO_V2_LINES_MAX),
            ("consumer",          ctypes.c_char   * GPIO_MAX_NAME_SIZE),
            ("config",            GpioV2LineConfig),
            ("num_lines",         ctypes.c_uint32),
            ("event_buffer_size", ctypes.c_uint32),
            ("padding",           ctypes.c_uint32 * 5),
            ("fd",                ctypes.c_int32),
        ]

    chip_fd = os.open(chip_path, os.O_RDONLY)
    try:
        # Try v1 ABI
        req = GpiohandleRequest()
        req.lineoffsets[0]    = line_offset
        req.flags             = GPIOHANDLE_REQUEST_OUTPUT
        req.default_values[0] = 1 if value else 0
        req.consumer_label    = b"modernjvs-webui"
        req.lines             = 1
        line_fd = None
        try:
            fcntl.ioctl(chip_fd, GPIO_GET_LINEHANDLE_IOCTL, req)
            line_fd = req.fd
        except OSError as e:
            if e.errno != _errno.ENOTTY:
                raise
            # v1 not supported — fall through to v2

        if line_fd is None:
            # v2 ABI — set initial output value via config attribute
            req2 = GpioV2LineRequest()
            req2.offsets[0]   = line_offset
            req2.consumer     = b"modernjvs-webui"
            req2.num_lines    = 1
            req2.config.flags = GPIO_V2_LINE_FLAG_OUTPUT
            # Set initial value via attribute
            req2.config.num_attrs        = 1
            req2.config.attrs[0].attr.id = GPIO_V2_LINE_ATTR_ID_OUTPUT_VALUES
            req2.config.attrs[0].attr.u.values = (1 if value else 0)
            req2.config.attrs[0].mask    = 1   # bit 0 = first line
            fcntl.ioctl(chip_fd, GPIO_V2_GET_LINE_IOCTL, req2)
            line_fd = req2.fd

        try:
            # Poll in 50 ms ticks so the hold can be cancelled early via _gpio_set_cancel.
            _gpio_set_cancel.clear()
            deadline = time.monotonic() + duration_s
            while time.monotonic() < deadline:
                if _gpio_set_cancel.wait(timeout=0.05):
                    break  # cancelled early — line is released in the finally below
        finally:
            os.close(line_fd)
    finally:
        os.close(chip_fd)


def diag_gpio_set(pin, level, duration=3):
    """Drive a GPIO pin OUTPUT HIGH or LOW for a user-defined duration, then release it.

    Intended for manual wiring verification — the user can confirm the expected
    voltage on the pin with a multimeter while it is being driven.

    duration is clamped to 1–60 seconds; defaults to 3 s.

    Returns a dict: ok (bool), message (str), state (str | None).
    """
    try:
        pin_int = int(pin)
    except (TypeError, ValueError):
        return {"ok": False, "message": f"Invalid pin number: {pin!r}", "state": None}

    if pin_int < 1 or pin_int > 40:
        return {
            "ok": False,
            "message": f"Pin {pin_int} is outside the valid header range (1–40).",
            "state": None,
        }

    level_str = str(level).strip().lower()
    if level_str not in ("high", "low"):
        return {"ok": False, "message": f"Invalid level {level!r} — must be 'high' or 'low'.", "state": None}

    try:
        duration_s = float(duration)
    except (TypeError, ValueError):
        duration_s = 3.0
    # Clamp to a safe range
    duration_s = max(1.0, min(60.0, duration_s))

    value = 1 if level_str == "high" else 0
    state = "HIGH" if value else "LOW"

    chips = sorted(_glob.glob("/dev/gpiochip*"))
    if not chips:
        return {
            "ok": False,
            "message": "No /dev/gpiochip* devices found. Is the GPIO character device available?",
            "state": None,
        }

    try:
        # pin_int is used directly as the BCM GPIO line offset on gpiochip0,
        # matching the behaviour of diag_gpio_test() which documents:
        # "SENSE_LINE_PIN stores the BCM GPIO line offset, used directly."
        _gpio_write_line(chips[0], pin_int, value, duration_s=duration_s)
        dur_label = f"{int(duration_s)} s" if duration_s == int(duration_s) else f"{duration_s} s"
        return {
            "ok": True,
            "message": f"Pin {pin_int} was driven {state} for {dur_label}, then released.",
            "state": state,
        }
    except PermissionError:
        return {
            "ok": False,
            "message": (
                f"Permission denied driving GPIO pin {pin_int}. "
                "Run ModernJVS as root or add the service user to the 'gpio' group."
            ),
            "state": None,
        }
    except OSError as e:
        import errno as _errno
        if e.errno == _errno.EBUSY:
            return {
                "ok": False,
                "message": (
                    f"Pin {pin_int} is held by another process (ModernJVS service is likely running). "
                    "Stop the service first."
                ),
                "state": "IN USE",
            }
        return {"ok": False, "message": f"Error driving GPIO pin {pin_int}: {e}", "state": None}


def diag_gpio_cancel():
    """Signal any in-progress _gpio_write_line hold to release early.

    Called by POST /api/diag/gpio/cancel when the browser navigates away from
    the Diagnostics tab.  Safe to call even when no hold is active.
    """
    _gpio_set_cancel.set()
    return {"ok": True}


def diag_gpio_test(pin):
    """Read the current logic level of a GPIO pin using the Linux GPIO character device.

    Returns a dict with keys: ok (bool), message (str), state (str | None).
    Uses ctypes + kernel ioctl — no external CLI tools or Python C extensions required.

    If a Set HIGH/LOW hold is in progress via _gpio_write_line, the cancel event
    is signalled first and the read is retried for up to ~300 ms to let the other
    thread release the line before giving up with an EBUSY result.
    """
    try:
        pin_int = int(pin)
    except (TypeError, ValueError):
        return {"ok": False, "message": f"Invalid pin number: {pin!r}", "state": None}

    if pin_int < 1 or pin_int > 40:
        return {
            "ok": False,
            "message": f"Pin {pin_int} is outside the valid header range (1–40).",
            "state": None,
        }

    # Discover available gpiochip devices (/dev/gpiochip*)
    chips = sorted(_glob.glob("/dev/gpiochip*"))
    if not chips:
        return {
            "ok": False,
            "message": "No /dev/gpiochip* devices found. Is the GPIO character device available?",
            "state": None,
        }

    # For Raspberry Pi, gpiochip0 is the main BCM GPIO controller.
    # SENSE_LINE_PIN stores the BCM GPIO line offset, used directly.
    chip = chips[0]

    # If a Set HIGH/LOW hold is active on another thread, signal it to release
    # early and retry the read for up to ~300 ms (6 × 50 ms) before falling
    # through to the normal EBUSY path.
    _gpio_set_cancel.set()

    import errno as _errno
    last_err = None
    for _attempt in range(7):
        try:
            val = _gpio_read_line(chip, pin_int)
            _gpio_set_cancel.clear()
            state = "HIGH" if val else "LOW"
            return {
                "ok": True,
                "message": f"Pin {pin_int} on {chip} is {state}.",
                "state": state,
            }
        except PermissionError:
            _gpio_set_cancel.clear()
            return {
                "ok": False,
                "message": (
                    f"Permission denied reading GPIO pin {pin_int}. "
                    "Run ModernJVS as root or add the service user to the 'gpio' group."
                ),
                "state": None,
            }
        except OSError as e:
            if e.errno == _errno.EBUSY and _attempt < 6:
                # Line still held — wait one polling tick then retry
                time.sleep(0.05)
                last_err = e
                continue
            last_err = e
            break

    _gpio_set_cancel.clear()
    if last_err is not None and last_err.errno == _errno.EBUSY:
        return {
            "ok": True,
            "message": (
                f"Pin {pin_int} is currently held by the ModernJVS daemon "
                "(sense line active). This is expected while the service is running."
            ),
            "state": "IN USE",
        }
    return {"ok": False, "message": f"Error reading GPIO pin {pin_int}: {last_err}", "state": None}


# ---------------------------------------------------------------------------
# Logo helper
# ---------------------------------------------------------------------------

def get_logo_bytes():
    """Return PNG logo bytes, checking the installed path and the repo docs path.

    The installed path (/usr/share/modernjvs/) is tried first.  When running
    directly from the source repository (e.g. during development) the script
    falls back to docs/modernjvs2.png two directory levels above this file.
    """
    # Resolve the script's real location so the fallback works even when the
    # script is run via a symlink or from a different working directory.
    # Expected layout: src/webui/modernjvs-webui  →  ../../docs/modernjvs2.png
    script_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        LOGO_PATH,
        "/usr/share/modernjvs/modernjvs2.png",
        os.path.join(script_dir, "..", "..", "docs", "modernjvs2.png"),
    ]
    for p in candidates:
        try:
            with open(os.path.normpath(p), "rb") as f:
                return f.read()
        except OSError:
            pass
    return None


def get_sticks_bytes():
    """Return PNG Sticks image bytes, checking the installed path and the repo docs path."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        STICKS_PATH,
        "/usr/share/modernjvs/Sticks4.png",
        os.path.join(script_dir, "..", "..", "docs", "Sticks4.png"),
    ]
    for p in candidates:
        try:
            with open(os.path.normpath(p), "rb") as f:
                return f.read()
        except OSError:
            pass
    return None


def _webui_file_candidates(subdir, filename):
    """Return candidate file paths for a WebUI asset, installed path first.

    The installed system path is tried first so that the production layout
    takes precedence over the source tree during development fallback.
    Expected layout: src/webui/<subdir>/<filename>
    Installed layout: /usr/share/modernjvs/webui/<subdir>/<filename>
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    base = WEBUI_STATIC_PATH if subdir == "static" else WEBUI_TEMPLATES_PATH
    return [
        os.path.join(base, filename),
        os.path.join(script_dir, subdir, filename),
    ]


def _read_webui_file(subdir, filename):
    """Read a WebUI text file (template or static asset) from disk."""
    for p in _webui_file_candidates(subdir, filename):
        try:
            with open(os.path.normpath(p), "r", encoding="utf-8") as f:
                return f.read()
        except OSError:
            pass
    return None


def _read_webui_file_bytes(subdir, filename):
    """Read a WebUI binary asset (e.g. a font file) from disk.

    Mirrors :func:`_read_webui_file` but opens the file in binary mode so that
    non-text assets such as TrueType fonts are not corrupted during reading.
    """
    for p in _webui_file_candidates(subdir, filename):
        try:
            with open(os.path.normpath(p), "rb") as f:
                return f.read()
        except OSError:
            pass
    return None


# Build HTML_PAGE now that get_logo_bytes() / get_sticks_bytes() are defined.
def _build_login_page():
    """Build the login page, loading the template from disk and embedding static sysinfo."""
    template = _read_webui_file("templates", "login.html")
    if template is None:
        return "<html><body><p>Error: login.html template not found.</p></body></html>"
    si = get_sysinfo()
    sys_parts = []
    if si.get("libgpiod_version"):
        sys_parts.append("libgpiod v" + si["libgpiod_version"])
    if si.get("kernel_version"):
        sys_parts.append("Kernel " + si["kernel_version"])
    lines = []
    if sys_parts:
        lines.append(" &nbsp;|&nbsp; ".join(sys_parts))
    if si.get("pi_model"):
        lines.append(si["pi_model"])
    if lines:
        footer_info = '<div class="login-footer-info">' + "<br>".join(lines) + "</div>"
    else:
        footer_info = ""
    return template.format(
        logo=_logo_data_uri(),
        sticks=_sticks_data_uri(),
        footer_info=footer_info,
    )

# Done once at module load so every request serves the same cached bytes.
HTML_PAGE  = _build_html_page()
LOGIN_PAGE = _build_login_page()


# ---------------------------------------------------------------------------
# Version helper
# ---------------------------------------------------------------------------

def get_version():
    """Return the installed ModernJVS binary version string."""
    try:
        result = subprocess.run(
            ["modernjvs", "--version"],
            capture_output=True, text=True, timeout=5
        )
        # Take the last non-empty line so that any warning messages printed
        # before the version number (e.g. the debug-mode warning) are ignored.
        lines = [l.strip() for l in (result.stdout + result.stderr).splitlines() if l.strip()]
        if lines:
            return lines[-1]
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        pass
    return "unknown"


# ---------------------------------------------------------------------------
# Connected input devices helper
# ---------------------------------------------------------------------------

# Mirrors FILTERED_DEVICE_PATTERNS in src/controller/input.c (lines 46-71).
# If you add or remove patterns in that C array, update this list to match.
# The C source is the authoritative definition; this list is a read-only copy
# used only to annotate the Devices tab in the WebUI.
_FILTERED_DEVICE_PATTERNS = [
    # Audio/HDMI devices
    "vc4-hdmi", "HDMI", "hdmi", "headphone", "Headphone",
    # Sound devices
    "snd_bcm2835", "snd_hda", "snd_usb", "pcspkr", "PC Speaker",
    # Power management
    "Power Button", "power-button", "Sleep Button", "Lid Switch", "pwr_button",
    # Video/Camera devices
    "Video Bus",
]


def _is_filtered_device(name):
    """Return True if the device name matches any filtered pattern."""
    return any(pat in name for pat in _FILTERED_DEVICE_PATTERNS)


def get_input_devices():
    """Return list of connected /dev/input/event* devices with sysfs names.

    Each entry has: event, name, path, ignored.
    ignored=True means ModernJVS will skip this device (it matches a filter
    pattern in FILTERED_DEVICE_PATTERNS).
    """
    devices = []
    try:
        for event_path in sorted(_glob.glob("/dev/input/event*")):
            event_name = os.path.basename(event_path)
            name = event_name  # fallback if sysfs name not available
            sysfs_name_path = f"/sys/class/input/{event_name}/device/name"
            try:
                with open(sysfs_name_path) as f:
                    name = f.read().strip()
            except OSError:
                pass
            devices.append({
                "event":   event_name,
                "name":    name,
                "path":    event_path,
                "ignored": _is_filtered_device(name),
            })
    except OSError:
        pass
    return devices


# ---------------------------------------------------------------------------
# Bluetooth controller helpers
# ---------------------------------------------------------------------------

# Strict MAC address pattern: exactly six hex pairs separated by colons
_BT_MAC_RE = re.compile(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')
# Pattern to parse "Device AA:BB:CC:DD:EE:FF Some Name" lines from bluetoothctl
_BT_DEVICE_RE = re.compile(r'^Device\s+([0-9A-Fa-f:]{17})\s+(.*)')

# Timeout constants (seconds) for Bluetooth operations
BT_SCAN_TIMEOUT    = 5   # safety margin added on top of BT_SCAN_DURATION for subprocess timeout
BT_SCAN_DURATION   = 8   # seconds bluetoothctl scans before exiting (--timeout flag)
BT_PAIR_TIMEOUT    = 30  # pairing can be slow on first attempt
BT_CONNECT_TIMEOUT = 20  # connection attempt timeout
BT_INFO_TIMEOUT    = 10  # info / trust / remove commands
BT_CONNECT_RETRY_DELAY = 2  # seconds to wait before retrying a failed connection attempt
BT_CONNECT_MAX_RETRIES = 5  # number of automatic retries after an initial failed connect

# Link supervision timeout constants applied to active Bluetooth connections.
BT_SUPERVISION_TIMEOUT_BREDR   = 4800  # 3 s in 0.625 ms BR/EDR slots
BT_SUPERVISION_TIMEOUT_LE      = 300   # 3 s in 10 ms LE units

# LE connection-update (lecup) interval bounds.  The maximum is deliberately
# set to 800 (= 1000 ms) so that the LL_CONNECTION_UPDATE_REQ only changes
# the supervision timeout without forcing controllers to switch to a shorter
# connection interval.  A controller currently using, say, a 15 ms interval
# will keep that interval because 15 ms is already within [7.5 ms, 1000 ms].
# The original code used max = 12 (15 ms), which forced devices with longer
# negotiated intervals to change, causing some LE controllers to drop the link.
BT_SUPERVISION_LE_INTERVAL_MIN = 6     # 7.5 ms  – BLE-spec minimum
BT_SUPERVISION_LE_INTERVAL_MAX = 800   # 1000 ms – permissive; keeps current interval
BT_SUPERVISION_LE_LATENCY      = 0     # no slave latency

# Seconds a Bluetooth device must be continuously connected before the
# supervision timeout is applied.  Applying hcitool commands too soon
# interferes with the HID reporting-mode handshake on BR/EDR controllers
# (e.g. Wii Remotes) and with GATT service discovery on LE controllers
# (e.g. Xbox Wireless Controller).  Sending LL_CONNECTION_UPDATE_REQ during
# active GATT setup can cause LE controllers to reject the parameter update
# and disconnect, even though bluetoothctl connect already returned success.
BT_SUPERVISION_STABLE_PERIOD  = 5

# Known RS-485 / serial adapter VID:PID → human-readable chip name.
# Used by diag_usb_devices() to highlight adapters in the USB inspector.
_USB_RS485_KNOWN = {
    ("0403", "6001"): "FTDI FT232R",
    ("0403", "6010"): "FTDI FT2232",
    ("0403", "6011"): "FTDI FT4232",
    ("0403", "6014"): "FTDI FT232H",
    ("0403", "6015"): "FTDI FT-X",
    ("1a86", "7523"): "CH340",
    ("1a86", "55d4"): "CH343P",
    ("10c4", "ea60"): "CP2102/CP2104",
    ("10c4", "ea70"): "CP210x",
    ("067b", "2303"): "PL2303",
    ("04e2", "1410"): "XR21V1410",
}

# Kernel drivers that expose serial TTY nodes (/dev/ttyUSB* or /dev/ttyACM*).
_USB_SERIAL_DRIVERS = {"ftdi_sio", "ch341", "cdc_acm", "cp210x", "xr_serial", "pl2303"}


def _validate_bt_mac(mac):
    """Return True only if mac is a properly-formatted Bluetooth MAC address."""
    return bool(_BT_MAC_RE.match(str(mac)))


def _is_wiimote(name):
    """Return True if the device name looks like a Nintendo Wii Remote."""
    n = name.lower()
    return any(k in n for k in ("nintendo", "wii", "rvl-cnt"))


def _is_xbox(name):
    """Return True if the device name looks like an Xbox Wireless Controller."""
    n = name.lower()
    return any(k in n for k in ("xbox", "microsoft"))


def _run_bt(*args, timeout=BT_INFO_TIMEOUT):
    """Run a bluetoothctl sub-command and return the CompletedProcess."""
    return subprocess.run(
        ["bluetoothctl"] + list(args),
        capture_output=True, text=True, timeout=timeout,
    )


def _run_bt_piped(commands, timeout=BT_PAIR_TIMEOUT):
    """Send a sequence of newline-separated commands to a single interactive
    bluetoothctl session via stdin and return the CompletedProcess.

    This is required for operations that need the agent to be set within the
    same session (e.g. Xbox controllers need ``agent NoInputNoOutput`` before
    ``pair``).
    """
    return subprocess.run(
        ["bluetoothctl"],
        input="\n".join(commands) + "\n",
        capture_output=True, text=True, timeout=timeout,
    )




def get_bluetooth_paired():
    """Return a list of paired Bluetooth devices with connection status."""
    try:
        result = _run_bt("devices", "Paired")
        devices = []
        for line in result.stdout.splitlines():
            m = _BT_DEVICE_RE.match(line)
            if not m:
                continue
            mac, name = m.group(1), m.group(2).strip()
            info = _run_bt("info", mac)
            connected = "Connected: yes" in info.stdout
            devices.append({"mac": mac, "name": name, "connected": connected})
        return {"devices": devices}
    except Exception as e:
        return {"error": str(e)}


def bluetooth_scan():
    """Scan for nearby Bluetooth devices for ~8 s and return discovered devices.

    Uses `bluetoothctl --timeout N scan on` so that the process exits cleanly
    after N seconds; the BlueZ daemon populates its device cache during this
    time and we query it afterward with `bluetoothctl devices`.
    """
    try:
        # --timeout causes bluetoothctl to scan for exactly BT_SCAN_DURATION
        # seconds and then exit cleanly. The subprocess timeout is set higher
        # to account for startup/shutdown overhead.
        _run_bt(
            "--timeout", str(BT_SCAN_DURATION), "scan", "on",
            timeout=BT_SCAN_DURATION + BT_SCAN_TIMEOUT,
        )

        all_result   = _run_bt("devices")
        paired_result = _run_bt("devices", "Paired")

        paired_macs = set()
        for line in paired_result.stdout.splitlines():
            m = _BT_DEVICE_RE.match(line)
            if m:
                paired_macs.add(m.group(1))

        devices = []
        for line in all_result.stdout.splitlines():
            m = _BT_DEVICE_RE.match(line)
            if not m:
                continue
            mac, name = m.group(1), m.group(2).strip()
            devices.append({
                "mac":     mac,
                "name":    name,
                "paired":  mac in paired_macs,
                "wiimote": _is_wiimote(name),
            })
        return {"devices": devices}
    except Exception as e:
        return {"error": str(e)}


def bluetooth_pair(mac):
    """Pair and connect a Bluetooth device by MAC address.

    - For Wii Remotes the connection sometimes fails on the first attempt;
      the function automatically retries once after a short delay.
    - For Xbox Wireless Controllers (and any device that returns
      AuthenticationFailed with the default agent), the function retries
      using a ``NoInputNoOutput`` agent which tells BlueZ not to require
      any PIN/passkey confirmation.  Xbox controllers must be in pairing
      mode (hold the Pair button on the back until the Xbox button flashes).
    """
    if not _validate_bt_mac(mac):
        return {"error": "Invalid Bluetooth MAC address"}

    try:
        # Resolve name for device-type detection and user-facing messages
        info = _run_bt("info", mac)
        name = ""
        for line in info.stdout.splitlines():
            nm = re.match(r'\s*Name:\s+(.*)', line)
            if nm:
                name = nm.group(1).strip()
                break
        wiimote = _is_wiimote(name)
        xbox    = _is_xbox(name)

        # Trust first so the device can auto-reconnect in future
        _run_bt("trust", mac)

        # First pair attempt using the default agent
        pair_result = _run_bt("pair", mac, timeout=BT_PAIR_TIMEOUT)
        pair_out = (pair_result.stdout + pair_result.stderr).lower()
        pair_ok = (
            pair_result.returncode == 0
            or "successful" in pair_out
            or "already paired" in pair_out
        )

        # If pairing failed with AuthenticationFailed (common for Xbox
        # controllers and other devices that require NoInputNoOutput agent),
        # retry in a piped session with the appropriate agent set first.
        if not pair_ok and "authenticationfailed" in pair_out.replace(" ", ""):
            retry_result = _run_bt_piped([
                "agent NoInputNoOutput",
                "default-agent",
                f"pair {mac}",
                "quit",
            ])
            retry_out = (retry_result.stdout + retry_result.stderr).lower()
            pair_ok = (
                retry_result.returncode == 0
                or "successful" in retry_out
                or "already paired" in retry_out
            )
            if pair_ok:
                pair_out = retry_out  # use retry output for subsequent checks

        if not pair_ok:
            detail = (pair_result.stdout.strip() + "\n" + pair_result.stderr.strip()).strip()
            if "authenticationfailed" in pair_out.replace(" ", ""):
                if xbox:
                    return {
                        "error": (
                            "Pairing failed (Authentication Failed). "
                            "Make sure the Xbox controller is in pairing mode: "
                            "hold the Pair button (back of controller) until the "
                            "Xbox button flashes rapidly, then try again."
                        )
                    }
                return {
                    "error": (
                        "Pairing failed (Authentication Failed). "
                        "Make sure the controller is in pairing mode and try again. "
                        f"Detail: {detail}"
                    )
                }
            return {"error": f"Pairing failed: {detail}"}

        # Connect – first attempt
        conn_result = _run_bt("connect", mac, timeout=BT_CONNECT_TIMEOUT)
        conn_out = (conn_result.stdout + conn_result.stderr).lower()
        conn_ok = conn_result.returncode == 0 or "successful" in conn_out

        # Some devices need multiple connect attempts after pairing
        for _ in range(BT_CONNECT_MAX_RETRIES):
            if conn_ok:
                break
            time.sleep(BT_CONNECT_RETRY_DELAY)
            conn_result = _run_bt("connect", mac, timeout=BT_CONNECT_TIMEOUT)
            conn_out = (conn_result.stdout + conn_result.stderr).lower()
            conn_ok = conn_result.returncode == 0 or "successful" in conn_out

        if conn_ok:
            return {"ok": True, "name": name}

        # Paired but couldn't connect – still a partial success; give
        # device-appropriate reconnection guidance.
        if wiimote:
            reconnect_tip = "Try pressing 1+2 on the Wii Remote again to reconnect."
        elif xbox:
            reconnect_tip = (
                "Press the Xbox button to reconnect. "
                "If that fails, press the Pair button to force reconnection."
            )
        else:
            reconnect_tip = "Try turning the controller off and on again to reconnect."

        return {
            "ok": True,
            "warning": (
                f"Paired successfully, but the connection attempt failed. {reconnect_tip}"
            ),
            "name": name,
        }
    except Exception as e:
        return {"error": str(e)}


def bluetooth_remove(mac):
    """Remove (unpair) a Bluetooth device by MAC address."""
    if not _validate_bt_mac(mac):
        return {"error": "Invalid Bluetooth MAC address"}
    try:
        result = _run_bt("remove", mac)
        out = (result.stdout + result.stderr).lower()
        if result.returncode == 0 or "removed" in out:
            return {"ok": True}
        return {"error": (result.stdout + result.stderr).strip()}
    except Exception as e:
        return {"error": str(e)}


def bluetooth_connect(mac):
    """Connect to an already-paired Bluetooth device by MAC address.

    Retries once for Wii Remotes, which often need a second attempt.
    Returns {"ok": True} on success, or {"ok": True, "warning": ...} if the
    connection attempt did not succeed but the device is still paired.
    """
    if not _validate_bt_mac(mac):
        return {"error": "Invalid Bluetooth MAC address"}
    try:
        # Resolve device name for type-specific handling
        info = _run_bt("info", mac)
        name = ""
        for line in info.stdout.splitlines():
            nm = re.match(r'\s*Name:\s+(.*)', line)
            if nm:
                name = nm.group(1).strip()
                break
        wiimote = _is_wiimote(name)
        xbox    = _is_xbox(name)

        conn_result = _run_bt("connect", mac, timeout=BT_CONNECT_TIMEOUT)
        conn_out = (conn_result.stdout + conn_result.stderr).lower()
        conn_ok = conn_result.returncode == 0 or "successful" in conn_out

        # Some devices need multiple connect attempts
        for _ in range(BT_CONNECT_MAX_RETRIES):
            if conn_ok:
                break
            time.sleep(BT_CONNECT_RETRY_DELAY)
            conn_result = _run_bt("connect", mac, timeout=BT_CONNECT_TIMEOUT)
            conn_out = (conn_result.stdout + conn_result.stderr).lower()
            conn_ok = conn_result.returncode == 0 or "successful" in conn_out

        if conn_ok:
            return {"ok": True}

        if wiimote:
            reconnect_tip = "Try pressing 1+2 on the Wii Remote to reconnect."
        elif xbox:
            reconnect_tip = (
                "Press the Xbox button to reconnect. "
                "If that fails, press the Pair button to force reconnection."
            )
        else:
            reconnect_tip = "Try turning the controller off and on again to reconnect."

        return {
            "ok": True,
            "warning": f"Connection attempt failed. {reconnect_tip}",
        }
    except Exception as e:
        return {"error": str(e)}


def get_bluetooth_status():
    """Return a dict describing the Bluetooth environment on this host.

    Fields:
      pi_model        — raw model string from /proc/device-tree/model (may be "")
      is_dietpi       — True when running on DietPi (uses dietpi-config, not raspi-config)
      hci_present     — True if at least one HCI Bluetooth adapter is visible
      bluez_available — True if bluetoothctl is on PATH
      bt_service_running — True if systemd bluetooth.service is active
      rfkill_soft_blocked — True if BT is soft-blocked by rfkill
    """
    # ---- Raspberry Pi model detection ----
    pi_model = ""
    try:
        with open("/proc/device-tree/model", "r", encoding="utf-8", errors="replace") as f:
            pi_model = f.read().strip().rstrip("\x00")
    except OSError:
        pass

    # ---- HCI adapter presence ----
    hci_present = False
    try:
        bt_dir = "/sys/class/bluetooth"
        hci_present = os.path.isdir(bt_dir) and next(os.scandir(bt_dir), None) is not None
    except OSError:
        pass

    # ---- BlueZ availability ----
    bluez_available = shutil.which("bluetoothctl") is not None

    # ---- bluetooth.service state ----
    bt_service_running = False
    try:
        r = subprocess.run(
            ["systemctl", "is-active", "bluetooth"],
            capture_output=True, text=True, timeout=5,
        )
        bt_service_running = r.stdout.strip() == "active"
    except Exception:
        pass

    # ---- rfkill soft-block ----
    rfkill_soft_blocked = False
    try:
        r = subprocess.run(
            ["rfkill", "list", "bluetooth"],
            capture_output=True, text=True, timeout=5,
        )
        rfkill_soft_blocked = "Soft blocked: yes" in r.stdout
    except Exception:
        pass

    # ---- DietPi detection ----
    is_dietpi = os.path.isfile("/etc/dietpi/.version")

    return {
        "pi_model":             pi_model,
        "is_dietpi":            is_dietpi,
        "hci_present":          hci_present,
        "bluez_available":      bluez_available,
        "bt_service_running":   bt_service_running,
        "rfkill_soft_blocked":  rfkill_soft_blocked,
    }


def setup_usb_bluetooth():
    """Install BlueZ packages and enable the bluetooth service.

    - Installs bluetooth, bluez, and bluez-tools via apt-get.
    - Enables the bluetooth systemd service.
    - Returns {"ok": True, "output": [lines]}.
    """
    output_lines = []

    # ---- Install BlueZ packages ----
    packages = ["bluetooth", "bluez", "bluez-tools"]
    output_lines.append("Updating package lists…")
    try:
        r = subprocess.run(
            ["apt-get", "update", "-qq"],
            capture_output=True, text=True, timeout=120,
        )
        if r.returncode != 0:
            detail = (r.stdout + "\n" + r.stderr).strip()
            return {"error": f"apt-get update failed: {detail}"}
        output_lines.append("✓ Package lists updated.")

        output_lines.append(f"Installing {', '.join(packages)}…")
        r = subprocess.run(
            ["apt-get", "install", "-y", "-qq"] + packages,
            capture_output=True, text=True, timeout=180,
        )
        if r.returncode != 0:
            detail = (r.stdout + "\n" + r.stderr).strip()
            return {"error": f"Package install failed: {detail}"}
        output_lines.append("✓ Packages installed successfully.")
    except subprocess.TimeoutExpired:
        return {
            "error": (
                "Package installation timed out. "
                "Run manually: sudo apt install bluetooth bluez bluez-tools"
            )
        }
    except FileNotFoundError:
        return {
            "error": (
                "apt-get not found. Install packages manually: "
                "sudo apt install bluetooth bluez bluez-tools"
            )
        }

    # ---- Enable the bluetooth service ----
    try:
        subprocess.run(
            ["systemctl", "enable", "--now", "bluetooth"],
            capture_output=True, text=True, timeout=15,
        )
        output_lines.append("✓ Bluetooth service enabled.")
    except Exception:
        pass

    return {"ok": True, "output": output_lines}


def set_bluetooth_supervision_timeout():
    """Apply a 3-second BR/EDR link supervision timeout to active ACL connections.

    Only BR/EDR (ACL) connections are updated via ``hcitool lst <address> 4800``
    (4800 × 0.625 ms = 3 s).

    LE connections use ``hcitool lecup <handle> … 300`` with a permissive
    max connection interval of BT_SUPERVISION_LE_INTERVAL_MAX (1000 ms).
    The wide interval range ensures the controller keeps its current interval;
    only the supervision timeout is effectively changed.

    Returns {"ok": True, "output": [...lines], "count": N} on success, or
    {"ok": True, "partial": True, "output": [...lines]} if some connections
    could not be updated, or {"error": ...} on a hard failure.
    """
    if not shutil.which("hcitool"):
        return {"error": "hcitool not found. hcitool was removed from BlueZ >= 5.65 — the automatic background supervision timeout handles this instead."}

    try:
        r = subprocess.run(
            ["hcitool", "con"],
            capture_output=True, text=True, timeout=5,
        )
    except Exception as e:
        return {"error": f"Failed to list connections: {e}"}

    output_lines = []
    failed = False
    count = 0

    for line in r.stdout.splitlines():
        # Lines look like:
        #   < ACL XX:XX:XX:XX:XX:XX handle N state 1 lm MASTER  (BR/EDR)
        #   < LE  XX:XX:XX:XX:XX:XX handle N state 1 lm MASTER  (LE)
        parts = line.split()
        if len(parts) < 5 or parts[0] != '<' or "handle" not in parts:
            continue
        try:
            handle_idx = parts.index("handle")
            if handle_idx + 1 >= len(parts):
                continue
            conn_type = parts[1]   # "ACL" or "LE"
            address   = parts[2]
            handle    = parts[handle_idx + 1]
        except (IndexError, ValueError):
            continue

        if not _validate_bt_mac(address):
            output_lines.append(f"⚠ Skipping connection with unexpected address format: {address}")
            continue

        try:
            if conn_type == "ACL":
                sub = subprocess.run(
                    ["hcitool", "lst", address, str(BT_SUPERVISION_TIMEOUT_BREDR)],
                    capture_output=True, text=True, timeout=5,
                )
                if sub.returncode == 0:
                    output_lines.append(
                        f"✓ Set supervision timeout to 3 s for {address} (handle {handle}) [BR/EDR]"
                    )
                    count += 1
                else:
                    output_lines.append(
                        f"✗ Failed for {address} [BR/EDR]: {(sub.stdout + sub.stderr).strip()}"
                    )
                    failed = True
            elif conn_type == "LE":
                sub = subprocess.run(
                    ["hcitool", "lecup", handle,
                     str(BT_SUPERVISION_LE_INTERVAL_MIN),
                     str(BT_SUPERVISION_LE_INTERVAL_MAX),
                     str(BT_SUPERVISION_LE_LATENCY),
                     str(BT_SUPERVISION_TIMEOUT_LE)],
                    capture_output=True, text=True, timeout=5,
                )
                if sub.returncode == 0:
                    output_lines.append(
                        f"✓ Set supervision timeout to 3 s for {address} (handle {handle}) [LE]"
                    )
                    count += 1
                else:
                    output_lines.append(
                        f"✗ Failed for {address} [LE]: {(sub.stdout + sub.stderr).strip()}"
                    )
                    failed = True
            else:
                output_lines.append(
                    f"⚠ Skipping unknown connection type '{conn_type}' for {address}"
                )
        except Exception as e:
            output_lines.append(f"✗ Error processing {address}: {e}")
            failed = True

    if count == 0 and not failed:
        output_lines.append("No active Bluetooth connections found.")

    if failed:
        return {"ok": True, "partial": True, "output": output_lines}
    return {"ok": True, "output": output_lines, "count": count}


class WebUIHandler(http.server.BaseHTTPRequestHandler):
    """Simple HTTP handler that serves the WebUI and its JSON API."""

    def log_message(self, fmt, *args):  # silence default Apache-style log
        pass

    # ---- access control ----

    def _check_client_ip(self):
        """Return True if the client is on a private/local network.

        Returns False and sends a 403 HTML page if the client IP is public,
        preventing internet exposure even when the Pi has an internet connection.
        """
        client_ip = self.client_address[0]
        if not is_private_ip(client_ip):
            self._access_denied(client_ip)
            return False
        return True

    def _get_session_token(self):
        """Extract the session token from the Cookie request header."""
        cookie_header = self.headers.get("Cookie", "")
        for part in cookie_header.split(";"):
            part = part.strip()
            if part.startswith(SESSION_COOKIE_NAME + "="):
                return part[len(SESSION_COOKIE_NAME) + 1:]
        return None

    def _check_auth(self):
        """Return True if the request is authenticated (or no password is set).

        Sends a 302 redirect to /login and returns False when a password is
        configured and the request carries no valid session cookie.
        """
        if read_password_hash() is None:
            return True   # password protection disabled
        if is_valid_session(self._get_session_token()):
            return True
        self._redirect_to_login()
        return False

    def _redirect_to_login(self):
        """Send a 302 redirect to /login, preserving the original path as ?next=."""
        # Strip CR/LF from the user-supplied path to prevent HTTP response splitting.
        requested = urllib.parse.urlparse(self.path).path.translate(
            str.maketrans("", "", "\r\n")
        )
        target = "/login"
        if requested and requested not in ("/", "/login", "/index.html"):
            target += "?" + urllib.parse.urlencode({"next": requested})
        self.send_response(HTTPStatus.FOUND)
        self.send_header("Location", target)
        self.send_header("Content-Length", 0)
        self.end_headers()

    def _access_denied(self, client_ip):
        html = _ACCESS_DENIED_HTML.format(client_ip=client_ip)
        data = html.encode("utf-8")
        self.send_response(HTTPStatus.FORBIDDEN)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", len(data))
        self.end_headers()
        self.wfile.write(data)

    # ---- routing ----

    def do_GET(self):
        if not self._check_client_ip():
            return

        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        # Login page is always accessible (needed when password is set)
        if path == "/login":
            if not read_password_hash():
                self.send_response(HTTPStatus.FOUND)
                self.send_header("Location", "/")
                self.send_header("Content-Length", 0)
                self.end_headers()
                return
            self._send_html(LOGIN_PAGE)
            return

        # These two endpoints are needed by the login page (theme + version badge)
        # and are read-only / non-sensitive, so serve them without auth.
        if path == "/api/version":
            self._json({"version": get_version()})
            return
        if path == "/api/webui/settings":
            self._json(read_webui_settings())
            return

        # Static assets (CSS/JS/fonts) are served without auth – they contain no
        # sensitive data and are required by both the login page and the main UI.
        # Font files: any *.woff2/woff/otf/ttf directly under /static/fonts/ is
        # allowed; [^/]+ prevents directory-traversal attacks.
        if path in ("/static/style.css", "/static/app.js",
                    "/static/login.css", "/static/login.js") or \
                re.fullmatch(r'/static/fonts/[^/]+\.(woff2|woff|otf|ttf)', path):
            self._serve_static(path)
            return

        if not self._check_auth():
            return

        if path == "/" or path == "/index.html":
            self._send_html(HTML_PAGE)
        elif path == "/logo":
            self._serve_logo()
        elif path == "/sticks":
            self._serve_sticks()
        elif path == "/api/status":
            self._json(get_service_status())
        elif path == "/api/config":
            self._json(config_to_api(read_config()))
        elif path == "/api/sysinfo":
            self._json(get_sysinfo())
        elif path == "/api/logs":
            try:
                lines = int(query.get("lines", ["100"])[0])
            except (ValueError, IndexError):
                lines = 100
            lines = max(10, min(lines, 1000))
            self._json({"lines": get_logs(lines)})
        elif path == "/api/logs/download":
            try:
                lines = int(query.get("lines", ["500"])[0])
            except (ValueError, IndexError):
                lines = 500
            lines = max(10, min(lines, 5000))
            text = "\n".join(get_logs(lines))
            data = text.encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Disposition",
                             f'attachment; filename="{SERVICE_NAME}.log"')
            self.send_header("Content-Length", len(data))
            self.end_headers()
            self.wfile.write(data)
        elif path == "/api/ios":
            self._json({"ios": list_dir(IOS_PATH)})
        elif path == "/api/games":
            self._json({"games": list_dir(GAMES_PATH)})
        elif path == "/api/devices":
            self._json({"devices": list_dir(DEVICES_PATH)})
        elif path == "/api/input_devices":
            self._json({"devices": get_input_devices()})
        elif path == "/api/profiles/list":
            self._json({
                "games":   list_dir(GAMES_PATH),
                "devices": list_dir(DEVICES_PATH),
                "ios":     list_dir(IOS_PATH),
            })
        elif path == "/api/profiles/read":
            type_ = query.get("type", [""])[0]
            name  = os.path.basename(query.get("name", [""])[0])
            fpath = _resolve_profile_path(type_, name)
            if fpath is None:
                self._json({"error": "Invalid type or name."}, HTTPStatus.BAD_REQUEST)
                return
            try:
                with open(fpath, "r", errors="replace") as f:
                    content = f.read()
                self._json({"content": content})
            except FileNotFoundError:
                self._json({"error": "File not found."}, HTTPStatus.NOT_FOUND)
            except OSError as e:
                self._json({"error": str(e)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif path == "/api/profiles/download":
            type_ = query.get("type", [""])[0]
            name  = os.path.basename(query.get("name", [""])[0])
            fpath = _resolve_profile_path(type_, name)
            if fpath is None:
                self._json({"error": "Invalid type or name."}, HTTPStatus.BAD_REQUEST)
                return
            try:
                with open(fpath, "rb") as f:
                    data = f.read()
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                # Derive filename from the resolved path (not raw user input) and
                # strip CRLF/quotes to prevent HTTP response splitting (py/header-injection).
                safe_dl_name = re.sub(r'[\r\n"]', '', os.path.basename(fpath))
                self.send_header("Content-Disposition",
                                 f'attachment; filename="{safe_dl_name}"')
                self.send_header("Content-Length", len(data))
                self.end_headers()
                self.wfile.write(data)
            except FileNotFoundError:
                self._json({"error": "File not found."}, HTTPStatus.NOT_FOUND)
            except OSError as e:
                self._json({"error": str(e)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif path == "/api/input/test":
            device = os.path.basename(query.get("device", [""])[0])
            if not re.match(r'^event\d+$', device):
                self._json({"error": "Invalid device."}, HTTPStatus.BAD_REQUEST)
                return
            dev_path = "/dev/input/" + device
            if not os.path.exists(dev_path):
                self._json({"error": "Device not found."}, HTTPStatus.NOT_FOUND)
                return
            _INPUT_EVENT_FMT = "llHHi"
            _INPUT_EVENT_SIZE = struct.calcsize(_INPUT_EVENT_FMT)
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()
            try:
                fd = os.open(dev_path, os.O_RDONLY | os.O_NONBLOCK)
                try:
                    deadline    = time.time() + INPUT_TEST_TIMEOUT_SECONDS
                    last_event  = time.time()
                    buf         = b""
                    while time.time() < deadline:
                        now = time.time()
                        remaining = deadline - now
                        silence   = now - last_event
                        if silence >= 2.0:
                            msg = b'data: {"keepalive":true}\n\n'
                            self.wfile.write(msg)
                            self.wfile.flush()
                            last_event = now
                        try:
                            chunk = os.read(fd, _INPUT_EVENT_SIZE * 16)
                            buf += chunk
                            last_event = time.time()
                        except BlockingIOError:
                            time.sleep(0.05)
                            continue
                        while len(buf) >= _INPUT_EVENT_SIZE:
                            rec = buf[:_INPUT_EVENT_SIZE]
                            buf = buf[_INPUT_EVENT_SIZE:]
                            _, _, ev_type, code, value = struct.unpack(_INPUT_EVENT_FMT, rec)
                            payload = json.dumps({"type": ev_type, "code": code, "value": value})
                            msg = f"data: {payload}\n\n".encode("utf-8")
                            self.wfile.write(msg)
                            self.wfile.flush()
                except OSError as e:
                    err_msg = ("data: " + json.dumps({"error": str(e)}) + "\n\n").encode("utf-8")
                    try:
                        self.wfile.write(err_msg)
                        self.wfile.flush()
                    except OSError:
                        pass
                finally:
                    os.close(fd)
            except OSError as e:
                err_msg = ("data: " + json.dumps({"error": str(e)}) + "\n\n").encode("utf-8")
                try:
                    self.wfile.write(err_msg)
                    self.wfile.flush()
                except OSError:
                    pass
        elif path == "/api/bluetooth/paired":
            self._json(get_bluetooth_paired())
        elif path == "/api/bluetooth/status":
            self._json(get_bluetooth_status())
        elif path == "/api/webui/password/status":
            self._json({"passwordSet": read_password_hash() is not None})
        elif path == "/api/sessions/list":
            self._json({"sessions": list_sessions(), "password_set": read_password_hash() is not None})
        elif path == "/api/audit/log":
            lines_param = query.get("lines", ["200"])[0]
            try:
                n = min(1000, max(1, int(lines_param)))
            except ValueError:
                n = 200
            try:
                with _audit_lock, open(AUDIT_LOG_PATH, "r", errors="replace") as f:
                    all_lines = f.readlines()
                self._json({"lines": all_lines[-n:]})
            except FileNotFoundError:
                self._json({"lines": []})
            except OSError as e:
                self._json({"error": str(e)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif path == "/api/diag/serial/ports":
            # Return a list of /dev/ttyUSB* and /dev/ttyAMA* devices present on the system
            ports = sorted(
                _glob.glob("/dev/ttyUSB*") +
                _glob.glob("/dev/ttyAMA*") +
                _glob.glob("/dev/ttyS*")
            )
            self._json({"ports": ports})
        elif path == "/api/diag/usb/devices":
            self._json(diag_usb_devices())
        else:
            self._not_found()

    def do_POST(self):
        if not self._check_client_ip():
            return

        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        # Login endpoint is always accessible – no auth check required
        if path == "/api/login":
            self._handle_api_login()
            return

        # All other POST routes require authentication when a password is set
        if not self._check_auth():
            return

        # Binary upload must be routed BEFORE _read_body() to avoid
        # attempting to UTF-8 decode raw image bytes.
        if path == "/api/profiles/upload":
            self._handle_profile_upload()
            return

        body = self._read_body()
        if body is None:
            return

        if path == "/api/config":
            try:
                data = json.loads(body) if body else {}
            except json.JSONDecodeError:
                self._json({"error": "Invalid JSON"}, HTTPStatus.BAD_REQUEST)
                return
            ok, msg = write_config(data)
            if ok:
                audit_log("Config updated", ip=self.client_address[0])
                self._json({"ok": True})
            else:
                self._json({"error": msg}, HTTPStatus.INTERNAL_SERVER_ERROR)

        elif path == "/api/control":
            try:
                data = json.loads(body) if body else {}
            except json.JSONDecodeError:
                self._json({"error": "Invalid JSON"}, HTTPStatus.BAD_REQUEST)
                return
            action = data.get("action", "")
            if action not in ("start", "stop", "restart"):
                self._json({"error": "Invalid action"}, HTTPStatus.BAD_REQUEST)
                return
            ok, msg = systemctl(action, SERVICE_NAME)
            if ok:
                audit_log(f"Service {action}", SERVICE_NAME, ip=self.client_address[0])
                # Daemon always starts with test mode inactive; reset the
                # in-memory mirror so the next status poll reflects reality.
                if action in ("start", "restart"):
                    global _test_button_active
                    with _test_button_lock:
                        _test_button_active = False
                self._json({"ok": True})
            else:
                self._json({"error": msg}, HTTPStatus.INTERNAL_SERVER_ERROR)

        elif path == "/api/control/test_button":
            ok, active, err = toggle_test_button()
            if ok:
                audit_log(
                    "Test mode " + ("activated" if active else "deactivated"),
                    ip=self.client_address[0],
                )
                self._json({"ok": True, "test_button_active": active,
                            "jvs_connected": get_jvs_connection_status()})
            else:
                self._json({"error": err}, HTTPStatus.INTERNAL_SERVER_ERROR)

        elif path == "/api/webui/restart":
            # Send the response BEFORE restarting — systemctl kills this
            # process immediately, so schedule it on a short timer so the
            # HTTP response can be flushed first.
            audit_log("WebUI restart", ip=self.client_address[0])
            def _do_restart():
                ok, msg = systemctl("restart", WEBUI_SERVICE_NAME)
                if not ok:
                    print(f"[webui] WARNING: WebUI restart failed: {msg}", flush=True)
            threading.Timer(0.5, _do_restart).start()
            self._json({"ok": True})

        elif path == "/api/system/reboot":
            audit_log("System reboot requested", ip=self.client_address[0])
            def _do_reboot():
                subprocess.run(["systemctl", "reboot"], check=False)
            threading.Timer(0.5, _do_reboot).start()
            self._json({"ok": True})

        elif path == "/api/system/shutdown":
            audit_log("System shutdown requested", ip=self.client_address[0])
            def _do_shutdown():
                subprocess.run(["systemctl", "poweroff"], check=False)
            threading.Timer(0.5, _do_shutdown).start()
            self._json({"ok": True})

        elif path == "/api/webui/settings":
            try:
                data = json.loads(body) if body else {}
            except json.JSONDecodeError:
                self._json({"error": "Invalid JSON"}, HTTPStatus.BAD_REQUEST)
                return
            ok, msg = write_webui_settings(data)
            if ok:
                self._json({"ok": True})
            else:
                self._json({"error": msg}, HTTPStatus.INTERNAL_SERVER_ERROR)

        elif path == "/api/bluetooth/scan":
            self._json(bluetooth_scan())

        elif path == "/api/bluetooth/pair":
            try:
                data = json.loads(body) if body else {}
            except json.JSONDecodeError:
                self._json({"error": "Invalid JSON"}, HTTPStatus.BAD_REQUEST)
                return
            result = bluetooth_pair(data.get("mac", ""))
            if result.get("ok"):
                audit_log("BT pair", data.get("mac", ""), ip=self.client_address[0])
            self._json(result)

        elif path == "/api/bluetooth/remove":
            try:
                data = json.loads(body) if body else {}
            except json.JSONDecodeError:
                self._json({"error": "Invalid JSON"}, HTTPStatus.BAD_REQUEST)
                return
            result = bluetooth_remove(data.get("mac", ""))
            if result.get("ok"):
                audit_log("BT remove", data.get("mac", ""), ip=self.client_address[0])
            self._json(result)

        elif path == "/api/bluetooth/connect":
            try:
                data = json.loads(body) if body else {}
            except json.JSONDecodeError:
                self._json({"error": "Invalid JSON"}, HTTPStatus.BAD_REQUEST)
                return
            result = bluetooth_connect(data.get("mac", ""))
            if result.get("ok") and not result.get("warning"):
                audit_log("BT connect", data.get("mac", ""), ip=self.client_address[0])
            self._json(result)

        elif path == "/api/bluetooth/setup_usb":
            self._json(setup_usb_bluetooth())

        elif path == "/api/bluetooth/set_supervision_timeout":
            self._json(set_bluetooth_supervision_timeout())

        elif path == "/api/webui/password":
            try:
                data = json.loads(body) if body else {}
            except json.JSONDecodeError:
                self._json({"error": "Invalid JSON"}, HTTPStatus.BAD_REQUEST)
                return
            password = data.get("password", "")
            if not password:
                self._json({"error": "Password cannot be empty."}, HTTPStatus.BAD_REQUEST)
                return
            if len(password) < 8:
                self._json({"error": "Password must be at least 8 characters."}, HTTPStatus.BAD_REQUEST)
                return
            if len(password) > 128:
                self._json({"error": "Password is too long."}, HTTPStatus.BAD_REQUEST)
                return
            try:
                _write_password_hash(hash_password(password))
                invalidate_all_sessions()
                audit_log("Password changed", ip=self.client_address[0])
                # Re-authenticate the current user so they aren't immediately logged out
                token = create_session(ip=self.client_address[0])
                resp  = json.dumps({"ok": True}).encode("utf-8")
                cookie = (
                    f"{SESSION_COOKIE_NAME}={token}; HttpOnly; SameSite=Strict; "
                    f"Max-Age={SESSION_MAX_AGE}; Path=/"
                )
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", len(resp))
                self.send_header("Set-Cookie", cookie)
                self.end_headers()
                self.wfile.write(resp)
            except OSError as e:
                self._json({"error": str(e)}, HTTPStatus.INTERNAL_SERVER_ERROR)

        elif path == "/api/webui/password/clear":
            if clear_password_file():
                invalidate_all_sessions()
                audit_log("Password cleared", ip=self.client_address[0])
                self._json({"ok": True})
            else:
                self._json({"error": "Failed to remove password file."}, HTTPStatus.INTERNAL_SERVER_ERROR)

        elif path == "/api/profiles/write":
            try:
                data = json.loads(body) if body else {}
            except json.JSONDecodeError:
                self._json({"error": "Invalid JSON"}, HTTPStatus.BAD_REQUEST)
                return
            type_ = data.get("type", "")
            name  = os.path.basename(data.get("name", ""))
            content = data.get("content", "")
            fpath = _resolve_profile_path(type_, name)
            if fpath is None:
                self._json({"error": "Invalid type or name."}, HTTPStatus.BAD_REQUEST)
                return
            if not isinstance(content, str):
                self._json({"error": "content must be a string."}, HTTPStatus.BAD_REQUEST)
                return
            if len(content) > MAX_PROFILE_CONTENT_CHARS:
                self._json({"error": f"Content too large (max {MAX_PROFILE_CONTENT_CHARS} chars)."}, HTTPStatus.BAD_REQUEST)
                return
            tmp = fpath + ".tmp"
            try:
                os.makedirs(os.path.dirname(fpath), exist_ok=True)
                with open(tmp, "w") as f:
                    f.write(content)
                os.replace(tmp, fpath)
                audit_log(f"Profile write", f"{type_}/{name}", ip=self.client_address[0])
                self._json({"ok": True})
            except OSError as e:
                self._json({"error": str(e)}, HTTPStatus.INTERNAL_SERVER_ERROR)

        elif path == "/api/profiles/delete":
            try:
                data = json.loads(body) if body else {}
            except json.JSONDecodeError:
                self._json({"error": "Invalid JSON"}, HTTPStatus.BAD_REQUEST)
                return
            type_ = data.get("type", "")
            name  = os.path.basename(data.get("name", ""))
            fpath = _resolve_profile_path(type_, name)
            if fpath is None:
                self._json({"error": "Invalid type or name."}, HTTPStatus.BAD_REQUEST)
                return
            try:
                os.remove(fpath)
                audit_log(f"Profile delete", f"{type_}/{name}", ip=self.client_address[0])
                self._json({"ok": True})
            except FileNotFoundError:
                self._json({"error": "File not found."}, HTTPStatus.NOT_FOUND)
            except OSError as e:
                self._json({"error": str(e)}, HTTPStatus.INTERNAL_SERVER_ERROR)

        elif path == "/api/profiles/rename":
            try:
                data = json.loads(body) if body else {}
            except json.JSONDecodeError:
                self._json({"error": "Invalid JSON"}, HTTPStatus.BAD_REQUEST)
                return
            type_    = data.get("type", "")
            name     = os.path.basename(data.get("name", ""))
            new_name = os.path.basename(data.get("new_name", ""))
            fpath     = _resolve_profile_path(type_, name)
            new_fpath = _resolve_profile_path(type_, new_name)
            if fpath is None or new_fpath is None:
                self._json({"error": "Invalid type or name."}, HTTPStatus.BAD_REQUEST)
                return
            if fpath == new_fpath:
                self._json({"error": "New name is the same as the old name."}, HTTPStatus.BAD_REQUEST)
                return
            try:
                if not os.path.exists(fpath):
                    self._json({"error": "File not found."}, HTTPStatus.NOT_FOUND)
                    return
                if os.path.exists(new_fpath):
                    self._json({"error": "A file with that name already exists."}, HTTPStatus.CONFLICT)
                    return
                os.rename(fpath, new_fpath)
                audit_log(f"Profile rename", f"{type_}/{name} -> {new_name}", ip=self.client_address[0])
                self._json({"ok": True})
            except OSError as e:
                self._json({"error": str(e)}, HTTPStatus.INTERNAL_SERVER_ERROR)

        elif path == "/api/sessions/invalidate_all":
            current = self._get_session_token()
            invalidate_other_sessions(current)
            audit_log("Sessions invalidated (kept current)", ip=self.client_address[0])
            self._json({"ok": True})

        elif path == "/api/diag/serial":
            try:
                data = json.loads(body) if body else {}
            except json.JSONDecodeError:
                self._json({"error": "Invalid JSON"}, HTTPStatus.BAD_REQUEST)
                return
            device = data.get("device", "").strip()
            if not device:
                # Fall back to the currently configured DEVICE_PATH
                device = read_config().get("DEVICE_PATH", "")
            self._json(diag_serial_test(device))

        elif path == "/api/diag/jvs/probe":
            try:
                data = json.loads(body) if body else {}
            except json.JSONDecodeError:
                self._json({"error": "Invalid JSON"}, HTTPStatus.BAD_REQUEST)
                return
            device = data.get("device", "").strip()
            if not device:
                # Fall back to the currently configured DEVICE_PATH
                device = read_config().get("DEVICE_PATH", "")
            self._json(diag_jvs_probe(device))

        elif path == "/api/diag/jvs/monitor":
            try:
                data = json.loads(body) if body else {}
            except json.JSONDecodeError:
                self._json({"error": "Invalid JSON"}, HTTPStatus.BAD_REQUEST)
                return
            device = data.get("device", "").strip()
            if not device:
                # Fall back to the currently configured DEVICE_PATH
                device = read_config().get("DEVICE_PATH", "")
            self._json(diag_jvs_monitor(device))

        elif path == "/api/diag/gpio":
            try:
                data = json.loads(body) if body else {}
            except json.JSONDecodeError:
                self._json({"error": "Invalid JSON"}, HTTPStatus.BAD_REQUEST)
                return
            pin = data.get("pin", "")
            if pin == "":
                # Fall back to the currently configured SENSE_LINE_PIN
                pin = read_config().get("SENSE_LINE_PIN", "26")
            self._json(diag_gpio_test(pin))

        elif path == "/api/diag/gpio/set":
            try:
                data = json.loads(body) if body else {}
            except json.JSONDecodeError:
                self._json({"error": "Invalid JSON"}, HTTPStatus.BAD_REQUEST)
                return
            pin      = data.get("pin", "")
            level    = data.get("level", "")
            duration = data.get("duration", 3)
            if pin == "":
                pin = read_config().get("SENSE_LINE_PIN", "26")
            self._json(diag_gpio_set(pin, level, duration))

        elif path == "/api/diag/gpio/cancel":
            self._json(diag_gpio_cancel())

        else:
            self._not_found()

    # ---- login handler ----

    def _handle_api_login(self):
        """Validate password and issue a session cookie on success."""
        body = self._read_body()
        if body is None:
            return
        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            self._json({"error": "Invalid JSON"}, HTTPStatus.BAD_REQUEST)
            return
        password     = data.get("password", "")
        stored_hash  = read_password_hash()
        if stored_hash is None:
            # Password protection is not enabled – login endpoint is not needed.
            self._json({"error": "Password protection is not enabled."}, HTTPStatus.BAD_REQUEST)
            return
        if not verify_password(password, stored_hash):
            self._json({"error": "Incorrect password."}, HTTPStatus.UNAUTHORIZED)
            return
        audit_log("Login", ip=self.client_address[0])
        token  = create_session(ip=self.client_address[0])
        resp   = json.dumps({"ok": True}).encode("utf-8")
        cookie = (
            f"{SESSION_COOKIE_NAME}={token}; HttpOnly; SameSite=Strict; "
            f"Max-Age={SESSION_MAX_AGE}; Path=/"
        )
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(resp))
        self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(resp)

    # ---- response helpers ----

    def _read_body(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
        except (ValueError, TypeError):
            length = 0
        if length < 0 or length > MAX_POST_BODY_BYTES:
            self._json({"error": "Request body too large."}, HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
            return None
        return self.rfile.read(length).decode("utf-8") if length else ""

    def _read_raw_body(self):
        """Read the raw request body as bytes (for binary uploads)."""
        try:
            length = int(self.headers.get("Content-Length", 0))
        except (ValueError, TypeError):
            length = 0
        return self.rfile.read(length) if length else b""

    def _handle_profile_upload(self):
        """Accept a profile file upload via binary POST with X-Profile-Type/Name headers."""
        type_ = self.headers.get("X-Profile-Type", "")
        name  = os.path.basename(self.headers.get("X-Profile-Name", ""))
        fpath = _resolve_profile_path(type_, name)
        if fpath is None:
            self._json({"error": "Invalid type or name."}, HTTPStatus.BAD_REQUEST)
            return
        try:
            content_length = int(self.headers.get("Content-Length", 0))
        except (ValueError, TypeError):
            content_length = 0
        if content_length < 0:
            self._json({"error": "Invalid Content-Length."}, HTTPStatus.BAD_REQUEST)
            return
        if content_length > MAX_PROFILE_UPLOAD_BYTES:
            self._json(
                {"error": f"File too large. Maximum size is {MAX_PROFILE_UPLOAD_BYTES // 1024} KB."},
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
            )
            return
        raw = self.rfile.read(content_length) if content_length else b""
        if not raw:
            self._json({"error": "Empty upload."}, HTTPStatus.BAD_REQUEST)
            return
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            self._json({"error": "File must be valid UTF-8 text."}, HTTPStatus.BAD_REQUEST)
            return
        tmp = fpath + ".tmp"
        try:
            os.makedirs(os.path.dirname(fpath), exist_ok=True)
            with open(tmp, "w") as f:
                f.write(text)
            os.replace(tmp, fpath)
            self._json({"ok": True, "size": len(raw)})
        except OSError as e:
            self._json({"error": str(e)}, HTTPStatus.INTERNAL_SERVER_ERROR)

    def _send_html(self, html):
        data = html.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", len(data))
        self.end_headers()
        self.wfile.write(data)

    def _json(self, obj, status=HTTPStatus.OK):
        data = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(data))
        self.end_headers()
        self.wfile.write(data)

    def _serve_logo(self):
        logo = get_logo_bytes()
        if logo is None:
            self._not_found()
            return
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "image/png")
        self.send_header("Content-Length", len(logo))
        self.send_header("Cache-Control", "max-age=86400")
        self.end_headers()
        self.wfile.write(logo)

    def _serve_sticks(self):
        sticks = get_sticks_bytes()
        if sticks is None:
            self._not_found()
            return
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "image/png")
        self.send_header("Content-Length", len(sticks))
        self.send_header("Cache-Control", "max-age=86400")
        self.end_headers()
        self.wfile.write(sticks)

    def _serve_static(self, path):
        """Serve a static CSS, JS, or font file from the webui static directory."""
        _TEXT_CONTENT_TYPES = {
            ".css": "text/css; charset=utf-8",
            ".js":  "application/javascript; charset=utf-8",
        }
        _BINARY_CONTENT_TYPES = {
            ".ttf":   "font/ttf",
            ".otf":   "font/otf",
            ".woff":  "font/woff",
            ".woff2": "font/woff2",
        }
        filename = os.path.basename(path)
        # For fonts served from a subdirectory, preserve the relative subpath
        # within static/ so the file is found at static/fonts/font.ttf.
        static_prefix = "/static/"
        rel_path = path[len(static_prefix):] if path.startswith(static_prefix) else filename
        ext = os.path.splitext(filename)[1]
        if ext in _TEXT_CONTENT_TYPES:
            content = _read_webui_file("static", rel_path)
            if content is None:
                self._not_found()
                return
            data = content.encode("utf-8")
            content_type = _TEXT_CONTENT_TYPES[ext]
        elif ext in _BINARY_CONTENT_TYPES:
            data = _read_webui_file_bytes("static", rel_path)
            if data is None:
                self._not_found()
                return
            content_type = _BINARY_CONTENT_TYPES[ext]
        else:
            self._not_found()
            return
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", len(data))
        self.send_header("Cache-Control", "max-age=3600")
        self.end_headers()
        self.wfile.write(data)

    def _not_found(self):
        self._json({"error": "Not found"}, HTTPStatus.NOT_FOUND)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _apply_supervision_timeout_for_connection(conn_type, address, handle):
    """Apply the link supervision timeout to a single Bluetooth connection.

    For LE connections a valid HCI handle is required; ``hcitool lecup`` is
    called with a deliberately permissive max connection interval
    (BT_SUPERVISION_LE_INTERVAL_MAX = 1000 ms) so that the controller keeps
    its current interval and only the supervision timeout is effectively
    extended.  This avoids the controller-level disconnection that occurred
    with the original aggressive 15 ms max interval.

    For BR/EDR (ACL) connections ``hcitool lst <address>`` is used.

    Returns True on success, False on failure or when parameters are unusable.
    """
    try:
        if conn_type == "LE":
            if not handle or handle == "?":
                return False  # Cannot update without a valid HCI handle.
            sub = subprocess.run(
                ["hcitool", "lecup", handle,
                 str(BT_SUPERVISION_LE_INTERVAL_MIN),
                 str(BT_SUPERVISION_LE_INTERVAL_MAX),
                 str(BT_SUPERVISION_LE_LATENCY),
                 str(BT_SUPERVISION_TIMEOUT_LE)],
                capture_output=True, text=True, timeout=5,
            )
            if sub.returncode == 0:
                print(f"[webui] BT supervision: set 3 s timeout for {address} (handle {handle}) [LE]", flush=True)
                return True
            else:
                print(f"[webui] BT supervision: failed for {address} [LE]: {(sub.stdout + sub.stderr).strip()}", flush=True)
        else:
            # ACL (BR/EDR): hcitool lst takes the device address directly.
            sub = subprocess.run(
                ["hcitool", "lst", address, str(BT_SUPERVISION_TIMEOUT_BREDR)],
                capture_output=True, text=True, timeout=5,
            )
            if sub.returncode == 0:
                handle_info = f" (handle {handle})" if handle and handle != "?" else ""
                print(f"[webui] BT supervision: set 3 s timeout for {address}{handle_info} [BR/EDR]", flush=True)
                return True
            else:
                print(f"[webui] BT supervision: failed for {address} [BR/EDR]: {(sub.stdout + sub.stderr).strip()}", flush=True)
    except Exception as e:
        print(f"[webui] BT supervision: error processing {address}: {e}", flush=True)
    return False


def _hcitool_connection_info():
    """Return a dict mapping Bluetooth address → (conn_type, handle) from
    ``hcitool con``.

    This is a best-effort call; an empty dict is returned on any failure so
    that callers can fall back gracefully.
    """
    info = {}
    if not shutil.which("hcitool"):
        return info
    try:
        r = subprocess.run(
            ["hcitool", "con"],
            capture_output=True, text=True, timeout=5,
        )
        for line in r.stdout.splitlines():
            parts = line.split()
            # Minimum valid line: "< ACL/LE <address> handle <N>" = 5 tokens
            if len(parts) < 5 or parts[0] != '<' or "handle" not in parts:
                continue
            try:
                handle_idx = parts.index("handle")
                if handle_idx + 1 >= len(parts):
                    continue
                conn_type = parts[1]
                address   = parts[2]
                handle    = parts[handle_idx + 1]
            except (IndexError, ValueError):
                continue
            if _validate_bt_mac(address):
                info[address] = (conn_type, handle)
    except Exception:
        pass
    return info


def _supervision_timeout_loop():
    """Background thread: watch for new Bluetooth connections and apply the
    3-second link supervision timeout.

    Both **LE connections** (e.g. Xbox Wireless Controller) and **BR/EDR
    connections** (e.g. Wii Remote) are processed only after
    BT_SUPERVISION_STABLE_PERIOD seconds of continuous connection.

    Applying supervision commands too soon interferes with the HID
    reporting-mode handshake on BR/EDR controllers and with GATT service
    discovery on LE controllers.  In particular, sending
    ``LL_CONNECTION_UPDATE_REQ`` (via ``hcitool lecup``) during active GATT
    setup causes some LE controllers (e.g. Xbox Wireless Controller) to reject
    the parameter update and disconnect, even though ``bluetoothctl connect``
    already returned success.  Waiting for BT_SUPERVISION_STABLE_PERIOD ensures
    GATT is complete before the supervision timeout is adjusted.

    The ``first_seen`` dict tracks when each address was first observed as
    connected.  Disconnected devices are pruned from both ``first_seen`` and
    ``seen`` so that a subsequent reconnect restarts the timing from scratch.

    ``hcitool`` was removed from BlueZ >= 5.65.  The loop runs regardless; if
    ``hcitool`` is absent, supervision commands silently no-op.
    """
    if not shutil.which("bluetoothctl"):
        return

    # Addresses whose supervision timeout has already been applied.
    seen = set()
    # Addresses first observed as connected; maps address -> monotonic timestamp.
    first_seen = {}

    while True:
        try:
            r = subprocess.run(
                ["bluetoothctl", "devices", "Connected"],
                capture_output=True, text=True, timeout=5,
            )
            current = set()
            for line in r.stdout.splitlines():
                m = _BT_DEVICE_RE.match(line.strip())
                if not m:
                    continue
                address = m.group(1)
                if _validate_bt_mac(address):
                    current.add(address)

            now = time.monotonic()

            # Record first-seen time for devices that just appeared.
            for address in current - seen - set(first_seen):
                first_seen[address] = now

            # Process all connections that have not yet been handled.
            pending = {a for a in current if a in first_seen and a not in seen}
            if pending:
                hci_info = _hcitool_connection_info() if shutil.which("hcitool") else {}
                for address in pending:
                    conn_type, handle = hci_info.get(address, ("ACL", "?"))
                    age = now - first_seen[address]

                    if age >= BT_SUPERVISION_STABLE_PERIOD:
                        if hci_info and address not in hci_info:
                            print(f"[webui] BT supervision: no HCI info for {address}, assuming BR/EDR", flush=True)
                        _apply_supervision_timeout_for_connection(conn_type, address, handle)
                        seen.add(address)
                    # else: not yet at stable period; check next tick.

            # Forget disconnected devices so reconnects are processed from scratch.
            seen &= current
            first_seen = {a: t for a, t in first_seen.items() if a in current}
        except Exception as e:
            print(f"[webui] WARNING: BT supervision watch error: {e}", flush=True)
        time.sleep(1)


def main():
    t = threading.Thread(target=_supervision_timeout_loop, daemon=True)
    t.start()
    server = http.server.ThreadingHTTPServer(("0.0.0.0", WEBUI_PORT), WebUIHandler)
    print(f"ModernJVS WebUI running on http://0.0.0.0:{WEBUI_PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()


if __name__ == "__main__":
    main()
