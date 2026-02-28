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
import pty
import re
import secrets
import select
import shutil
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
SERVICE_NAME = "modernjvs"
WEBUI_SERVICE_NAME = "modernjvs-webui"

MAX_SETTING_STRING_LENGTH = 64  # cap per string field in webui-settings.json
MAX_PROFILE_UPLOAD_BYTES = 256 * 1024      # 256 KB hard cap for profile files
MAX_PROFILE_NAME_LENGTH = 64               # max filename length for profile files
MAX_PROFILE_CONTENT_CHARS = 65536         # max content length for profile writes
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

# Session cookie settings
SESSION_COOKIE_NAME = "mjvs_session"
SESSION_MAX_AGE     = 7 * 24 * 3600   # 7 days

_SETTINGS_DEFAULTS = {
    "theme":          "black",
    "compact":        False,
    "noAnim":         False,
}

_settings_lock = threading.Lock()


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
    """Append one line to the WebUI audit log (best-effort, never raises)."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    parts = [f"[{timestamp}]", action]
    if detail:
        parts.append(f"- {detail}")
    if ip:
        parts.append(f"(from {ip})")
    line = " ".join(parts) + "\n"
    try:
        with _audit_lock:
            with open(AUDIT_LOG_PATH, "a") as f:
                f.write(line)
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

# Login page shown to unauthenticated visitors when a password is set
_LOGIN_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en" data-theme="black">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ModernJVS WebUI \u2014 Login</title>
<link rel="icon" type="image/png" href="{sticks}">
<style>
  :root{{--bg:#000000;--surface:#0a0a0a;--card:#111111;--border:#1f1f1f;
        --accent:#970011;--text:#e2e2f0;--muted:#888888;--red:#ff5555;
        --radius:8px;--font:'Segoe UI',system-ui,sans-serif;}}
  *,*::before,*::after{{box-sizing:border-box;margin:0;padding:0;}}
  body{{background:var(--bg);color:var(--text);font-family:var(--font);
       min-height:100vh;display:flex;flex-direction:column;
       align-items:center;justify-content:center;}}
  /* ---- theme variable overrides ---- */
  [data-theme="dark"]{{--bg:#0d0d14;--surface:#16161f;--card:#1e1e2e;--border:#2e2e42;--accent:#970011;--text:#e2e2f0;--muted:#7878a0;}}
  [data-theme="light"]{{--bg:#f0f0f5;--surface:#e0e0ea;--card:#ffffff;--border:#c4c4d4;--accent:#000000;--text:#1a1a2e;--muted:#55558a;}}
  [data-theme="midnight"]{{--bg:#080c18;--surface:#0d1528;--card:#111c38;--border:#1a2d54;--accent:#3b82f6;--text:#c5d8f5;--muted:#4d6a9a;}}
  [data-theme="dracula"]{{--bg:#1e1f29;--surface:#282a36;--card:#313442;--border:#44475a;--accent:#bd93f9;--text:#f8f8f2;--muted:#6272a4;}}
  [data-theme="terminal"]{{--bg:#0a0f0a;--surface:#0d150d;--card:#111c11;--border:#1a2e1a;--accent:#50fa7b;--text:#a0f0a0;--muted:#4a8a4a;}}
  [data-theme="ocean"]{{--bg:#020c18;--surface:#051422;--card:#071c30;--border:#0c2e4a;--accent:#0ea5e9;--text:#e0f4ff;--muted:#4a7e99;}}
  [data-theme="sunset"]{{--bg:#1a0800;--surface:#261000;--card:#2d1400;--border:#4a2000;--accent:#f97316;--text:#fde8cc;--muted:#8a5a2a;}}
  [data-theme="forest"]{{--bg:#030d03;--surface:#071507;--card:#091a09;--border:#0f2a10;--accent:#22c55e;--text:#d0f0d0;--muted:#3a7a45;}}
  [data-theme="purple"]{{--bg:#0d0018;--surface:#130025;--card:#1a0030;--border:#2c004d;--accent:#a855f7;--text:#f0e0ff;--muted:#6e3f99;}}
  [data-theme="neon"]{{--bg:#00080d;--surface:#001018;--card:#001820;--border:#002a38;--accent:#06b6d4;--text:#cffafe;--muted:#2e7a8a;}}
  [data-theme="rose"]{{--bg:#1a0010;--surface:#240018;--card:#2e0020;--border:#480038;--accent:#f43f5e;--text:#ffe0e8;--muted:#883a5a;}}
  [data-theme="amber"]{{--bg:#0d0600;--surface:#180e00;--card:#1e1000;--border:#321a00;--accent:#f59e0b;--text:#fef3c7;--muted:#7a5820;}}
  [data-theme="solarized"]{{--bg:#002b36;--surface:#04323f;--card:#073642;--border:#0d4f5e;--accent:#2aa198;--text:#fdf6e3;--muted:#657b83;}}
  /* ---- logo tint per theme ---- */
  [data-theme="dark"] #logo,[data-theme="black"] #logo{{filter:none;}}
  [data-theme="light"] #logo{{filter:brightness(0) saturate(0);}}
  [data-theme="midnight"] #logo{{filter:hue-rotate(212deg) saturate(1.1);}}
  [data-theme="dracula"] #logo{{filter:hue-rotate(268deg) saturate(1.2);}}
  [data-theme="terminal"] #logo{{filter:hue-rotate(148deg) saturate(1.2);}}
  [data-theme="ocean"] #logo{{filter:hue-rotate(208deg) saturate(1.2);}}
  [data-theme="sunset"] #logo{{filter:hue-rotate(36deg) saturate(1.2);}}
  [data-theme="forest"] #logo{{filter:hue-rotate(148deg) saturate(1.2);}}
  [data-theme="purple"] #logo{{filter:hue-rotate(278deg) saturate(1.2);}}
  [data-theme="neon"] #logo{{filter:hue-rotate(196deg) saturate(1.2);}}
  [data-theme="rose"] #logo{{filter:hue-rotate(4deg) saturate(1.1);}}
  [data-theme="amber"] #logo{{filter:hue-rotate(50deg) saturate(1.2);}}
  [data-theme="solarized"] #logo{{filter:hue-rotate(192deg) saturate(0.9);}}
  /* ---- sticks decoration ---- */
  .sticks-corner{{position:fixed;bottom:12px;right:12px;width:150px;opacity:0.23;pointer-events:none;z-index:0;}}
  [data-theme="dark"] #sticks,[data-theme="black"] #sticks{{filter:hue-rotate(330deg) saturate(1.1) brightness(0.75);}}
  [data-theme="light"] #sticks{{filter:grayscale(1) brightness(0.5);}}
  [data-theme="midnight"] #sticks{{filter:hue-rotate(182deg) saturate(1.1);}}
  [data-theme="dracula"] #sticks{{filter:hue-rotate(238deg) saturate(1.2);}}
  [data-theme="terminal"] #sticks{{filter:hue-rotate(118deg) saturate(1.2);}}
  [data-theme="ocean"] #sticks{{filter:hue-rotate(178deg) saturate(1.2);}}
  [data-theme="sunset"] #sticks{{filter:hue-rotate(6deg) saturate(1.2);}}
  [data-theme="forest"] #sticks{{filter:hue-rotate(118deg) saturate(1.2);}}
  [data-theme="purple"] #sticks{{filter:hue-rotate(248deg) saturate(1.2);}}
  [data-theme="neon"] #sticks{{filter:hue-rotate(166deg) saturate(1.2);}}
  [data-theme="rose"] #sticks{{filter:hue-rotate(334deg) saturate(1.1);}}
  [data-theme="amber"] #sticks{{filter:hue-rotate(20deg) saturate(1.2);}}
  [data-theme="solarized"] #sticks{{filter:hue-rotate(162deg) saturate(0.9);}}
  /* ---- login card ---- */
  .box{{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);
        padding:2.5rem;width:100%;max-width:360px;box-shadow:0 8px 32px rgba(0,0,0,.5);
        position:relative;z-index:1;}}
  .hdr{{text-align:center;margin-bottom:1.75rem;}}
  .hdr img{{max-height:48px;width:auto;max-width:100%;}}
  .hdr h1{{font-size:1.1rem;color:var(--muted);font-weight:400;margin-top:.4rem;}}
  /* Version badge pinned to top-left corner */
  .ver-badge{{position:fixed;top:0.6rem;left:0.75rem;font-size:0.72rem;
              color:var(--muted);background:var(--surface);
              border:1px solid var(--border);border-radius:4px;
              padding:0.15rem 0.4rem;white-space:nowrap;z-index:10;}}
  label{{display:block;font-size:.82rem;color:var(--muted);text-transform:uppercase;
         letter-spacing:.06em;margin-bottom:.3rem;}}
  input[type=password]{{width:100%;background:var(--surface);border:1px solid var(--border);
    border-radius:4px;color:var(--text);padding:.55rem .75rem;font-size:.95rem;
    margin-bottom:1.25rem;font-family:var(--font);}}
  input[type=password]:focus{{outline:none;border-color:var(--accent);}}
  button{{width:100%;background:var(--accent);color:#fff;border:none;border-radius:4px;
          padding:.65rem;font-size:.95rem;cursor:pointer;transition:opacity .15s;
          font-family:var(--font);}}
  button:hover{{opacity:.85;}}
  .err{{color:var(--red);font-size:.85rem;margin-top:.75rem;text-align:center;min-height:1.2em;}}
  /* ---- footer ---- */
  footer{{position:relative;z-index:1;text-align:center;}}
  .login-footer-info{{margin-top:0.75rem;font-size:0.72rem;color:var(--muted);line-height:1.7;}}
  /* On mobile, sticks moves below the login card */
  @media(max-width:640px){{
    .sticks-corner{{position:static;display:block;width:clamp(80px,30vw,130px);opacity:0.23;
                    margin:0.5rem auto 0;pointer-events:none;}}
  }}
  @media(max-width:400px){{
    .box{{padding:1.75rem 1.25rem;}}
  }}
</style></head>
<body>
<div class="ver-badge" id="lVer" style="display:none"></div>
<div class="box">
  <div class="hdr">
    <img id="logo" src="{logo}" alt="ModernJVS">
    <h1>WebUI</h1>
  </div>
  <label for="lPw">Password</label>
  <input type="password" id="lPw" autocomplete="current-password" autofocus
         onkeydown="if(event.key==='Enter')doLogin()">
  <button onclick="doLogin()">&#128275; Unlock</button>
  <div class="err" id="lErr"></div>
</div>
<footer>
  {footer_info}
  <img id="sticks" src="{sticks}" alt="" class="sticks-corner">
</footer>
<script>
async function doLogin(){{
  const pw=document.getElementById('lPw').value;
  const err=document.getElementById('lErr');
  err.textContent='';
  if(!pw){{err.textContent='Please enter a password.';return;}}
  try{{
    const r=await fetch('/api/login',{{method:'POST',
      headers:{{'Content-Type':'application/json'}},
      body:JSON.stringify({{password:pw}})}});
    const d=await r.json();
    if(d.ok){{
      const next=new URLSearchParams(window.location.search).get('next')||'/';
      window.location.href=next;
    }}else{{
      err.textContent=d.error||'Incorrect password.';
      document.getElementById('lPw').select();
    }}
  }}catch(e){{err.textContent='Network error: '+e;}}
}}
// Apply saved theme
function updateFavicon(theme){{
  var filters={{
    dark:'hue-rotate(330deg) saturate(1.1) brightness(0.75)',
    black:'hue-rotate(330deg) saturate(1.1) brightness(0.75)',
    light:'grayscale(1) brightness(0.5)',
    midnight:'hue-rotate(182deg) saturate(1.1)',
    dracula:'hue-rotate(238deg) saturate(1.2)',
    terminal:'hue-rotate(118deg) saturate(1.2)',
    ocean:'hue-rotate(178deg) saturate(1.2)',
    sunset:'hue-rotate(6deg) saturate(1.2)',
    forest:'hue-rotate(118deg) saturate(1.2)',
    purple:'hue-rotate(248deg) saturate(1.2)',
    neon:'hue-rotate(166deg) saturate(1.2)',
    rose:'hue-rotate(334deg) saturate(1.1)',
    amber:'hue-rotate(20deg) saturate(1.2)',
    solarized:'hue-rotate(162deg) saturate(0.9)'
  }};
  var src=document.getElementById('sticks');
  var link=document.querySelector("link[rel='icon']");
  if(!src||!link)return;
  var c=document.createElement('canvas');
  c.width=c.height=32;
  var ctx=c.getContext('2d');
  ctx.filter=filters[theme]||filters.black;
  ctx.drawImage(src,0,0,32,32);
  link.href=c.toDataURL();
}}
fetch('/api/webui/settings').then(r=>r.json()).then(s=>{{
  if(s&&s.theme){{
    document.documentElement.setAttribute('data-theme',s.theme);
    updateFavicon(s.theme);
  }}
}}).catch(()=>{{}});
// Show version badge
fetch('/api/version').then(r=>r.json()).then(d=>{{
  if(d.version&&d.version!=='unknown'){{
    const b=document.getElementById('lVer');
    if(b){{b.textContent='v'+d.version;b.style.display='';}}
  }}
}}).catch(()=>{{}});
</script>
</body></html>
"""

# ---------------------------------------------------------------------------
# xterm.js 5.3.0 + @xterm/addon-fit 0.11.0 – bundled locally (base64-encoded)
# ---------------------------------------------------------------------------
_XTERM_JS_B64 = (
    "IWZ1bmN0aW9uKGUsdCl7aWYoIm9iamVjdCI9PXR5cGVvZiBleHBvcnRzJiYib2JqZWN0Ij09dHlwZW9mIG1vZHVsZSltb2R1bGUuZXhwb3J0cz10KCk7ZWxz"
    "ZSBpZigiZnVuY3Rpb24iPT10eXBlb2YgZGVmaW5lJiZkZWZpbmUuYW1kKWRlZmluZShbXSx0KTtlbHNle3ZhciBpPXQoKTtmb3IodmFyIHMgaW4gaSkoIm9i"
    "amVjdCI9PXR5cGVvZiBleHBvcnRzP2V4cG9ydHM6ZSlbc109aVtzXX19KHNlbGYsKCgpPT4oKCk9PnsidXNlIHN0cmljdCI7dmFyIGU9ezQ1Njc6ZnVuY3Rp"
    "b24oZSx0LGkpe3ZhciBzPXRoaXMmJnRoaXMuX19kZWNvcmF0ZXx8ZnVuY3Rpb24oZSx0LGkscyl7dmFyIHIsbj1hcmd1bWVudHMubGVuZ3RoLG89bjwzP3Q6"
    "bnVsbD09PXM/cz1PYmplY3QuZ2V0T3duUHJvcGVydHlEZXNjcmlwdG9yKHQsaSk6cztpZigib2JqZWN0Ij09dHlwZW9mIFJlZmxlY3QmJiJmdW5jdGlvbiI9"
    "PXR5cGVvZiBSZWZsZWN0LmRlY29yYXRlKW89UmVmbGVjdC5kZWNvcmF0ZShlLHQsaSxzKTtlbHNlIGZvcih2YXIgYT1lLmxlbmd0aC0xO2E+PTA7YS0tKShy"
    "PWVbYV0pJiYobz0objwzP3Iobyk6bj4zP3IodCxpLG8pOnIodCxpKSl8fG8pO3JldHVybiBuPjMmJm8mJk9iamVjdC5kZWZpbmVQcm9wZXJ0eSh0LGksbyks"
    "b30scj10aGlzJiZ0aGlzLl9fcGFyYW18fGZ1bmN0aW9uKGUsdCl7cmV0dXJuIGZ1bmN0aW9uKGkscyl7dChpLHMsZSl9fTtPYmplY3QuZGVmaW5lUHJvcGVy"
    "dHkodCwiX19lc01vZHVsZSIse3ZhbHVlOiEwfSksdC5BY2Nlc3NpYmlsaXR5TWFuYWdlcj12b2lkIDA7Y29uc3Qgbj1pKDkwNDIpLG89aSg2MTE0KSxhPWko"
    "OTkyNCksaD1pKDg0NCksYz1pKDU1OTYpLGw9aSg0NzI1KSxkPWkoMzY1Nik7bGV0IF89dC5BY2Nlc3NpYmlsaXR5TWFuYWdlcj1jbGFzcyBleHRlbmRzIGgu"
    "RGlzcG9zYWJsZXtjb25zdHJ1Y3RvcihlLHQpe3N1cGVyKCksdGhpcy5fdGVybWluYWw9ZSx0aGlzLl9yZW5kZXJTZXJ2aWNlPXQsdGhpcy5fbGl2ZVJlZ2lv"
    "bkxpbmVDb3VudD0wLHRoaXMuX2NoYXJzVG9Db25zdW1lPVtdLHRoaXMuX2NoYXJzVG9Bbm5vdW5jZT0iIix0aGlzLl9hY2Nlc3NpYmlsaXR5Q29udGFpbmVy"
    "PWRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpLHRoaXMuX2FjY2Vzc2liaWxpdHlDb250YWluZXIuY2xhc3NMaXN0LmFkZCgieHRlcm0tYWNjZXNzaWJp"
    "bGl0eSIpLHRoaXMuX3Jvd0NvbnRhaW5lcj1kb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKSx0aGlzLl9yb3dDb250YWluZXIuc2V0QXR0cmlidXRlKCJy"
    "b2xlIiwibGlzdCIpLHRoaXMuX3Jvd0NvbnRhaW5lci5jbGFzc0xpc3QuYWRkKCJ4dGVybS1hY2Nlc3NpYmlsaXR5LXRyZWUiKSx0aGlzLl9yb3dFbGVtZW50"
    "cz1bXTtmb3IobGV0IGU9MDtlPHRoaXMuX3Rlcm1pbmFsLnJvd3M7ZSsrKXRoaXMuX3Jvd0VsZW1lbnRzW2VdPXRoaXMuX2NyZWF0ZUFjY2Vzc2liaWxpdHlU"
    "cmVlTm9kZSgpLHRoaXMuX3Jvd0NvbnRhaW5lci5hcHBlbmRDaGlsZCh0aGlzLl9yb3dFbGVtZW50c1tlXSk7aWYodGhpcy5fdG9wQm91bmRhcnlGb2N1c0xp"
    "c3RlbmVyPWU9PnRoaXMuX2hhbmRsZUJvdW5kYXJ5Rm9jdXMoZSwwKSx0aGlzLl9ib3R0b21Cb3VuZGFyeUZvY3VzTGlzdGVuZXI9ZT0+dGhpcy5faGFuZGxl"
    "Qm91bmRhcnlGb2N1cyhlLDEpLHRoaXMuX3Jvd0VsZW1lbnRzWzBdLmFkZEV2ZW50TGlzdGVuZXIoImZvY3VzIix0aGlzLl90b3BCb3VuZGFyeUZvY3VzTGlz"
    "dGVuZXIpLHRoaXMuX3Jvd0VsZW1lbnRzW3RoaXMuX3Jvd0VsZW1lbnRzLmxlbmd0aC0xXS5hZGRFdmVudExpc3RlbmVyKCJmb2N1cyIsdGhpcy5fYm90dG9t"
    "Qm91bmRhcnlGb2N1c0xpc3RlbmVyKSx0aGlzLl9yZWZyZXNoUm93c0RpbWVuc2lvbnMoKSx0aGlzLl9hY2Nlc3NpYmlsaXR5Q29udGFpbmVyLmFwcGVuZENo"
    "aWxkKHRoaXMuX3Jvd0NvbnRhaW5lciksdGhpcy5fbGl2ZVJlZ2lvbj1kb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKSx0aGlzLl9saXZlUmVnaW9uLmNs"
    "YXNzTGlzdC5hZGQoImxpdmUtcmVnaW9uIiksdGhpcy5fbGl2ZVJlZ2lvbi5zZXRBdHRyaWJ1dGUoImFyaWEtbGl2ZSIsImFzc2VydGl2ZSIpLHRoaXMuX2Fj"
    "Y2Vzc2liaWxpdHlDb250YWluZXIuYXBwZW5kQ2hpbGQodGhpcy5fbGl2ZVJlZ2lvbiksdGhpcy5fbGl2ZVJlZ2lvbkRlYm91bmNlcj10aGlzLnJlZ2lzdGVy"
    "KG5ldyBhLlRpbWVCYXNlZERlYm91bmNlcih0aGlzLl9yZW5kZXJSb3dzLmJpbmQodGhpcykpKSwhdGhpcy5fdGVybWluYWwuZWxlbWVudCl0aHJvdyBuZXcg"
    "RXJyb3IoIkNhbm5vdCBlbmFibGUgYWNjZXNzaWJpbGl0eSBiZWZvcmUgVGVybWluYWwub3BlbiIpO3RoaXMuX3Rlcm1pbmFsLmVsZW1lbnQuaW5zZXJ0QWRq"
    "YWNlbnRFbGVtZW50KCJhZnRlcmJlZ2luIix0aGlzLl9hY2Nlc3NpYmlsaXR5Q29udGFpbmVyKSx0aGlzLnJlZ2lzdGVyKHRoaXMuX3Rlcm1pbmFsLm9uUmVz"
    "aXplKChlPT50aGlzLl9oYW5kbGVSZXNpemUoZS5yb3dzKSkpKSx0aGlzLnJlZ2lzdGVyKHRoaXMuX3Rlcm1pbmFsLm9uUmVuZGVyKChlPT50aGlzLl9yZWZy"
    "ZXNoUm93cyhlLnN0YXJ0LGUuZW5kKSkpKSx0aGlzLnJlZ2lzdGVyKHRoaXMuX3Rlcm1pbmFsLm9uU2Nyb2xsKCgoKT0+dGhpcy5fcmVmcmVzaFJvd3MoKSkp"
    "KSx0aGlzLnJlZ2lzdGVyKHRoaXMuX3Rlcm1pbmFsLm9uQTExeUNoYXIoKGU9PnRoaXMuX2hhbmRsZUNoYXIoZSkpKSksdGhpcy5yZWdpc3Rlcih0aGlzLl90"
    "ZXJtaW5hbC5vbkxpbmVGZWVkKCgoKT0+dGhpcy5faGFuZGxlQ2hhcigiXG4iKSkpKSx0aGlzLnJlZ2lzdGVyKHRoaXMuX3Rlcm1pbmFsLm9uQTExeVRhYigo"
    "ZT0+dGhpcy5faGFuZGxlVGFiKGUpKSkpLHRoaXMucmVnaXN0ZXIodGhpcy5fdGVybWluYWwub25LZXkoKGU9PnRoaXMuX2hhbmRsZUtleShlLmtleSkpKSks"
    "dGhpcy5yZWdpc3Rlcih0aGlzLl90ZXJtaW5hbC5vbkJsdXIoKCgpPT50aGlzLl9jbGVhckxpdmVSZWdpb24oKSkpKSx0aGlzLnJlZ2lzdGVyKHRoaXMuX3Jl"
    "bmRlclNlcnZpY2Uub25EaW1lbnNpb25zQ2hhbmdlKCgoKT0+dGhpcy5fcmVmcmVzaFJvd3NEaW1lbnNpb25zKCkpKSksdGhpcy5fc2NyZWVuRHByTW9uaXRv"
    "cj1uZXcgYy5TY3JlZW5EcHJNb25pdG9yKHdpbmRvdyksdGhpcy5yZWdpc3Rlcih0aGlzLl9zY3JlZW5EcHJNb25pdG9yKSx0aGlzLl9zY3JlZW5EcHJNb25p"
    "dG9yLnNldExpc3RlbmVyKCgoKT0+dGhpcy5fcmVmcmVzaFJvd3NEaW1lbnNpb25zKCkpKSx0aGlzLnJlZ2lzdGVyKCgwLGQuYWRkRGlzcG9zYWJsZURvbUxp"
    "c3RlbmVyKSh3aW5kb3csInJlc2l6ZSIsKCgpPT50aGlzLl9yZWZyZXNoUm93c0RpbWVuc2lvbnMoKSkpKSx0aGlzLl9yZWZyZXNoUm93cygpLHRoaXMucmVn"
    "aXN0ZXIoKDAsaC50b0Rpc3Bvc2FibGUpKCgoKT0+e3RoaXMuX2FjY2Vzc2liaWxpdHlDb250YWluZXIucmVtb3ZlKCksdGhpcy5fcm93RWxlbWVudHMubGVu"
    "Z3RoPTB9KSkpfV9oYW5kbGVUYWIoZSl7Zm9yKGxldCB0PTA7dDxlO3QrKyl0aGlzLl9oYW5kbGVDaGFyKCIgIil9X2hhbmRsZUNoYXIoZSl7dGhpcy5fbGl2"
    "ZVJlZ2lvbkxpbmVDb3VudDwyMSYmKHRoaXMuX2NoYXJzVG9Db25zdW1lLmxlbmd0aD4wP3RoaXMuX2NoYXJzVG9Db25zdW1lLnNoaWZ0KCkhPT1lJiYodGhp"
    "cy5fY2hhcnNUb0Fubm91bmNlKz1lKTp0aGlzLl9jaGFyc1RvQW5ub3VuY2UrPWUsIlxuIj09PWUmJih0aGlzLl9saXZlUmVnaW9uTGluZUNvdW50KyssMjE9"
    "PT10aGlzLl9saXZlUmVnaW9uTGluZUNvdW50JiYodGhpcy5fbGl2ZVJlZ2lvbi50ZXh0Q29udGVudCs9bi50b29NdWNoT3V0cHV0KSksby5pc01hYyYmdGhp"
    "cy5fbGl2ZVJlZ2lvbi50ZXh0Q29udGVudCYmdGhpcy5fbGl2ZVJlZ2lvbi50ZXh0Q29udGVudC5sZW5ndGg+MCYmIXRoaXMuX2xpdmVSZWdpb24ucGFyZW50"
    "Tm9kZSYmc2V0VGltZW91dCgoKCk9Pnt0aGlzLl9hY2Nlc3NpYmlsaXR5Q29udGFpbmVyLmFwcGVuZENoaWxkKHRoaXMuX2xpdmVSZWdpb24pfSksMCkpfV9j"
    "bGVhckxpdmVSZWdpb24oKXt0aGlzLl9saXZlUmVnaW9uLnRleHRDb250ZW50PSIiLHRoaXMuX2xpdmVSZWdpb25MaW5lQ291bnQ9MCxvLmlzTWFjJiZ0aGlz"
    "Ll9saXZlUmVnaW9uLnJlbW92ZSgpfV9oYW5kbGVLZXkoZSl7dGhpcy5fY2xlYXJMaXZlUmVnaW9uKCksL1xwe0NvbnRyb2x9L3UudGVzdChlKXx8dGhpcy5f"
    "Y2hhcnNUb0NvbnN1bWUucHVzaChlKX1fcmVmcmVzaFJvd3MoZSx0KXt0aGlzLl9saXZlUmVnaW9uRGVib3VuY2VyLnJlZnJlc2goZSx0LHRoaXMuX3Rlcm1p"
    "bmFsLnJvd3MpfV9yZW5kZXJSb3dzKGUsdCl7Y29uc3QgaT10aGlzLl90ZXJtaW5hbC5idWZmZXIscz1pLmxpbmVzLmxlbmd0aC50b1N0cmluZygpO2Zvcihs"
    "ZXQgcj1lO3I8PXQ7cisrKXtjb25zdCBlPWkudHJhbnNsYXRlQnVmZmVyTGluZVRvU3RyaW5nKGkueWRpc3ArciwhMCksdD0oaS55ZGlzcCtyKzEpLnRvU3Ry"
    "aW5nKCksbj10aGlzLl9yb3dFbGVtZW50c1tyXTtuJiYoMD09PWUubGVuZ3RoP24uaW5uZXJUZXh0PSLCoCI6bi50ZXh0Q29udGVudD1lLG4uc2V0QXR0cmli"
    "dXRlKCJhcmlhLXBvc2luc2V0Iix0KSxuLnNldEF0dHJpYnV0ZSgiYXJpYS1zZXRzaXplIixzKSl9dGhpcy5fYW5ub3VuY2VDaGFyYWN0ZXJzKCl9X2Fubm91"
    "bmNlQ2hhcmFjdGVycygpezAhPT10aGlzLl9jaGFyc1RvQW5ub3VuY2UubGVuZ3RoJiYodGhpcy5fbGl2ZVJlZ2lvbi50ZXh0Q29udGVudCs9dGhpcy5fY2hh"
    "cnNUb0Fubm91bmNlLHRoaXMuX2NoYXJzVG9Bbm5vdW5jZT0iIil9X2hhbmRsZUJvdW5kYXJ5Rm9jdXMoZSx0KXtjb25zdCBpPWUudGFyZ2V0LHM9dGhpcy5f"
    "cm93RWxlbWVudHNbMD09PXQ/MTp0aGlzLl9yb3dFbGVtZW50cy5sZW5ndGgtMl07aWYoaS5nZXRBdHRyaWJ1dGUoImFyaWEtcG9zaW5zZXQiKT09PSgwPT09"
    "dD8iMSI6YCR7dGhpcy5fdGVybWluYWwuYnVmZmVyLmxpbmVzLmxlbmd0aH1gKSlyZXR1cm47aWYoZS5yZWxhdGVkVGFyZ2V0IT09cylyZXR1cm47bGV0IHIs"
    "bjtpZigwPT09dD8ocj1pLG49dGhpcy5fcm93RWxlbWVudHMucG9wKCksdGhpcy5fcm93Q29udGFpbmVyLnJlbW92ZUNoaWxkKG4pKToocj10aGlzLl9yb3dF"
    "bGVtZW50cy5zaGlmdCgpLG49aSx0aGlzLl9yb3dDb250YWluZXIucmVtb3ZlQ2hpbGQocikpLHIucmVtb3ZlRXZlbnRMaXN0ZW5lcigiZm9jdXMiLHRoaXMu"
    "X3RvcEJvdW5kYXJ5Rm9jdXNMaXN0ZW5lciksbi5yZW1vdmVFdmVudExpc3RlbmVyKCJmb2N1cyIsdGhpcy5fYm90dG9tQm91bmRhcnlGb2N1c0xpc3RlbmVy"
    "KSwwPT09dCl7Y29uc3QgZT10aGlzLl9jcmVhdGVBY2Nlc3NpYmlsaXR5VHJlZU5vZGUoKTt0aGlzLl9yb3dFbGVtZW50cy51bnNoaWZ0KGUpLHRoaXMuX3Jv"
    "d0NvbnRhaW5lci5pbnNlcnRBZGphY2VudEVsZW1lbnQoImFmdGVyYmVnaW4iLGUpfWVsc2V7Y29uc3QgZT10aGlzLl9jcmVhdGVBY2Nlc3NpYmlsaXR5VHJl"
    "ZU5vZGUoKTt0aGlzLl9yb3dFbGVtZW50cy5wdXNoKGUpLHRoaXMuX3Jvd0NvbnRhaW5lci5hcHBlbmRDaGlsZChlKX10aGlzLl9yb3dFbGVtZW50c1swXS5h"
    "ZGRFdmVudExpc3RlbmVyKCJmb2N1cyIsdGhpcy5fdG9wQm91bmRhcnlGb2N1c0xpc3RlbmVyKSx0aGlzLl9yb3dFbGVtZW50c1t0aGlzLl9yb3dFbGVtZW50"
    "cy5sZW5ndGgtMV0uYWRkRXZlbnRMaXN0ZW5lcigiZm9jdXMiLHRoaXMuX2JvdHRvbUJvdW5kYXJ5Rm9jdXNMaXN0ZW5lciksdGhpcy5fdGVybWluYWwuc2Ny"
    "b2xsTGluZXMoMD09PXQ/LTE6MSksdGhpcy5fcm93RWxlbWVudHNbMD09PXQ/MTp0aGlzLl9yb3dFbGVtZW50cy5sZW5ndGgtMl0uZm9jdXMoKSxlLnByZXZl"
    "bnREZWZhdWx0KCksZS5zdG9wSW1tZWRpYXRlUHJvcGFnYXRpb24oKX1faGFuZGxlUmVzaXplKGUpe3RoaXMuX3Jvd0VsZW1lbnRzW3RoaXMuX3Jvd0VsZW1l"
    "bnRzLmxlbmd0aC0xXS5yZW1vdmVFdmVudExpc3RlbmVyKCJmb2N1cyIsdGhpcy5fYm90dG9tQm91bmRhcnlGb2N1c0xpc3RlbmVyKTtmb3IobGV0IGU9dGhp"
    "cy5fcm93Q29udGFpbmVyLmNoaWxkcmVuLmxlbmd0aDtlPHRoaXMuX3Rlcm1pbmFsLnJvd3M7ZSsrKXRoaXMuX3Jvd0VsZW1lbnRzW2VdPXRoaXMuX2NyZWF0"
    "ZUFjY2Vzc2liaWxpdHlUcmVlTm9kZSgpLHRoaXMuX3Jvd0NvbnRhaW5lci5hcHBlbmRDaGlsZCh0aGlzLl9yb3dFbGVtZW50c1tlXSk7Zm9yKDt0aGlzLl9y"
    "b3dFbGVtZW50cy5sZW5ndGg+ZTspdGhpcy5fcm93Q29udGFpbmVyLnJlbW92ZUNoaWxkKHRoaXMuX3Jvd0VsZW1lbnRzLnBvcCgpKTt0aGlzLl9yb3dFbGVt"
    "ZW50c1t0aGlzLl9yb3dFbGVtZW50cy5sZW5ndGgtMV0uYWRkRXZlbnRMaXN0ZW5lcigiZm9jdXMiLHRoaXMuX2JvdHRvbUJvdW5kYXJ5Rm9jdXNMaXN0ZW5l"
    "ciksdGhpcy5fcmVmcmVzaFJvd3NEaW1lbnNpb25zKCl9X2NyZWF0ZUFjY2Vzc2liaWxpdHlUcmVlTm9kZSgpe2NvbnN0IGU9ZG9jdW1lbnQuY3JlYXRlRWxl"
    "bWVudCgiZGl2Iik7cmV0dXJuIGUuc2V0QXR0cmlidXRlKCJyb2xlIiwibGlzdGl0ZW0iKSxlLnRhYkluZGV4PS0xLHRoaXMuX3JlZnJlc2hSb3dEaW1lbnNp"
    "b25zKGUpLGV9X3JlZnJlc2hSb3dzRGltZW5zaW9ucygpe2lmKHRoaXMuX3JlbmRlclNlcnZpY2UuZGltZW5zaW9ucy5jc3MuY2VsbC5oZWlnaHQpe3RoaXMu"
    "X2FjY2Vzc2liaWxpdHlDb250YWluZXIuc3R5bGUud2lkdGg9YCR7dGhpcy5fcmVuZGVyU2VydmljZS5kaW1lbnNpb25zLmNzcy5jYW52YXMud2lkdGh9cHhg"
    "LHRoaXMuX3Jvd0VsZW1lbnRzLmxlbmd0aCE9PXRoaXMuX3Rlcm1pbmFsLnJvd3MmJnRoaXMuX2hhbmRsZVJlc2l6ZSh0aGlzLl90ZXJtaW5hbC5yb3dzKTtm"
    "b3IobGV0IGU9MDtlPHRoaXMuX3Rlcm1pbmFsLnJvd3M7ZSsrKXRoaXMuX3JlZnJlc2hSb3dEaW1lbnNpb25zKHRoaXMuX3Jvd0VsZW1lbnRzW2VdKX19X3Jl"
    "ZnJlc2hSb3dEaW1lbnNpb25zKGUpe2Uuc3R5bGUuaGVpZ2h0PWAke3RoaXMuX3JlbmRlclNlcnZpY2UuZGltZW5zaW9ucy5jc3MuY2VsbC5oZWlnaHR9cHhg"
    "fX07dC5BY2Nlc3NpYmlsaXR5TWFuYWdlcj1fPXMoW3IoMSxsLklSZW5kZXJTZXJ2aWNlKV0sXyl9LDM2MTQ6KGUsdCk9PntmdW5jdGlvbiBpKGUpe3JldHVy"
    "biBlLnJlcGxhY2UoL1xyP1xuL2csIlxyIil9ZnVuY3Rpb24gcyhlLHQpe3JldHVybiB0PyIbWzIwMH4iK2UrIhtbMjAxfiI6ZX1mdW5jdGlvbiByKGUsdCxy"
    "LG4pe2U9cyhlPWkoZSksci5kZWNQcml2YXRlTW9kZXMuYnJhY2tldGVkUGFzdGVNb2RlJiYhMCE9PW4ucmF3T3B0aW9ucy5pZ25vcmVCcmFja2V0ZWRQYXN0"
    "ZU1vZGUpLHIudHJpZ2dlckRhdGFFdmVudChlLCEwKSx0LnZhbHVlPSIifWZ1bmN0aW9uIG4oZSx0LGkpe2NvbnN0IHM9aS5nZXRCb3VuZGluZ0NsaWVudFJl"
    "Y3QoKSxyPWUuY2xpZW50WC1zLmxlZnQtMTAsbj1lLmNsaWVudFktcy50b3AtMTA7dC5zdHlsZS53aWR0aD0iMjBweCIsdC5zdHlsZS5oZWlnaHQ9IjIwcHgi"
    "LHQuc3R5bGUubGVmdD1gJHtyfXB4YCx0LnN0eWxlLnRvcD1gJHtufXB4YCx0LnN0eWxlLnpJbmRleD0iMTAwMCIsdC5mb2N1cygpfU9iamVjdC5kZWZpbmVQ"
    "cm9wZXJ0eSh0LCJfX2VzTW9kdWxlIix7dmFsdWU6ITB9KSx0LnJpZ2h0Q2xpY2tIYW5kbGVyPXQubW92ZVRleHRBcmVhVW5kZXJNb3VzZUN1cnNvcj10LnBh"
    "c3RlPXQuaGFuZGxlUGFzdGVFdmVudD10LmNvcHlIYW5kbGVyPXQuYnJhY2tldFRleHRGb3JQYXN0ZT10LnByZXBhcmVUZXh0Rm9yVGVybWluYWw9dm9pZCAw"
    "LHQucHJlcGFyZVRleHRGb3JUZXJtaW5hbD1pLHQuYnJhY2tldFRleHRGb3JQYXN0ZT1zLHQuY29weUhhbmRsZXI9ZnVuY3Rpb24oZSx0KXtlLmNsaXBib2Fy"
    "ZERhdGEmJmUuY2xpcGJvYXJkRGF0YS5zZXREYXRhKCJ0ZXh0L3BsYWluIix0LnNlbGVjdGlvblRleHQpLGUucHJldmVudERlZmF1bHQoKX0sdC5oYW5kbGVQ"
    "YXN0ZUV2ZW50PWZ1bmN0aW9uKGUsdCxpLHMpe2Uuc3RvcFByb3BhZ2F0aW9uKCksZS5jbGlwYm9hcmREYXRhJiZyKGUuY2xpcGJvYXJkRGF0YS5nZXREYXRh"
    "KCJ0ZXh0L3BsYWluIiksdCxpLHMpfSx0LnBhc3RlPXIsdC5tb3ZlVGV4dEFyZWFVbmRlck1vdXNlQ3Vyc29yPW4sdC5yaWdodENsaWNrSGFuZGxlcj1mdW5j"
    "dGlvbihlLHQsaSxzLHIpe24oZSx0LGkpLHImJnMucmlnaHRDbGlja1NlbGVjdChlKSx0LnZhbHVlPXMuc2VsZWN0aW9uVGV4dCx0LnNlbGVjdCgpfX0sNzIz"
    "OTooZSx0LGkpPT57T2JqZWN0LmRlZmluZVByb3BlcnR5KHQsIl9fZXNNb2R1bGUiLHt2YWx1ZTohMH0pLHQuQ29sb3JDb250cmFzdENhY2hlPXZvaWQgMDtj"
    "b25zdCBzPWkoMTUwNSk7dC5Db2xvckNvbnRyYXN0Q2FjaGU9Y2xhc3N7Y29uc3RydWN0b3IoKXt0aGlzLl9jb2xvcj1uZXcgcy5Ud29LZXlNYXAsdGhpcy5f"
    "Y3NzPW5ldyBzLlR3b0tleU1hcH1zZXRDc3MoZSx0LGkpe3RoaXMuX2Nzcy5zZXQoZSx0LGkpfWdldENzcyhlLHQpe3JldHVybiB0aGlzLl9jc3MuZ2V0KGUs"
    "dCl9c2V0Q29sb3IoZSx0LGkpe3RoaXMuX2NvbG9yLnNldChlLHQsaSl9Z2V0Q29sb3IoZSx0KXtyZXR1cm4gdGhpcy5fY29sb3IuZ2V0KGUsdCl9Y2xlYXIo"
    "KXt0aGlzLl9jb2xvci5jbGVhcigpLHRoaXMuX2Nzcy5jbGVhcigpfX19LDM2NTY6KGUsdCk9PntPYmplY3QuZGVmaW5lUHJvcGVydHkodCwiX19lc01vZHVs"
    "ZSIse3ZhbHVlOiEwfSksdC5hZGREaXNwb3NhYmxlRG9tTGlzdGVuZXI9dm9pZCAwLHQuYWRkRGlzcG9zYWJsZURvbUxpc3RlbmVyPWZ1bmN0aW9uKGUsdCxp"
    "LHMpe2UuYWRkRXZlbnRMaXN0ZW5lcih0LGkscyk7bGV0IHI9ITE7cmV0dXJue2Rpc3Bvc2U6KCk9PntyfHwocj0hMCxlLnJlbW92ZUV2ZW50TGlzdGVuZXIo"
    "dCxpLHMpKX19fX0sNjQ2NTpmdW5jdGlvbihlLHQsaSl7dmFyIHM9dGhpcyYmdGhpcy5fX2RlY29yYXRlfHxmdW5jdGlvbihlLHQsaSxzKXt2YXIgcixuPWFy"
    "Z3VtZW50cy5sZW5ndGgsbz1uPDM/dDpudWxsPT09cz9zPU9iamVjdC5nZXRPd25Qcm9wZXJ0eURlc2NyaXB0b3IodCxpKTpzO2lmKCJvYmplY3QiPT10eXBl"
    "b2YgUmVmbGVjdCYmImZ1bmN0aW9uIj09dHlwZW9mIFJlZmxlY3QuZGVjb3JhdGUpbz1SZWZsZWN0LmRlY29yYXRlKGUsdCxpLHMpO2Vsc2UgZm9yKHZhciBh"
    "PWUubGVuZ3RoLTE7YT49MDthLS0pKHI9ZVthXSkmJihvPShuPDM/cihvKTpuPjM/cih0LGksbyk6cih0LGkpKXx8byk7cmV0dXJuIG4+MyYmbyYmT2JqZWN0"
    "LmRlZmluZVByb3BlcnR5KHQsaSxvKSxvfSxyPXRoaXMmJnRoaXMuX19wYXJhbXx8ZnVuY3Rpb24oZSx0KXtyZXR1cm4gZnVuY3Rpb24oaSxzKXt0KGkscyxl"
    "KX19O09iamVjdC5kZWZpbmVQcm9wZXJ0eSh0LCJfX2VzTW9kdWxlIix7dmFsdWU6ITB9KSx0LkxpbmtpZmllcjI9dm9pZCAwO2NvbnN0IG49aSgzNjU2KSxv"
    "PWkoODQ2MCksYT1pKDg0NCksaD1pKDI1ODUpO2xldCBjPXQuTGlua2lmaWVyMj1jbGFzcyBleHRlbmRzIGEuRGlzcG9zYWJsZXtnZXQgY3VycmVudExpbmso"
    "KXtyZXR1cm4gdGhpcy5fY3VycmVudExpbmt9Y29uc3RydWN0b3IoZSl7c3VwZXIoKSx0aGlzLl9idWZmZXJTZXJ2aWNlPWUsdGhpcy5fbGlua1Byb3ZpZGVy"
    "cz1bXSx0aGlzLl9saW5rQ2FjaGVEaXNwb3NhYmxlcz1bXSx0aGlzLl9pc01vdXNlT3V0PSEwLHRoaXMuX3dhc1Jlc2l6ZWQ9ITEsdGhpcy5fYWN0aXZlTGlu"
    "ZT0tMSx0aGlzLl9vblNob3dMaW5rVW5kZXJsaW5lPXRoaXMucmVnaXN0ZXIobmV3IG8uRXZlbnRFbWl0dGVyKSx0aGlzLm9uU2hvd0xpbmtVbmRlcmxpbmU9"
    "dGhpcy5fb25TaG93TGlua1VuZGVybGluZS5ldmVudCx0aGlzLl9vbkhpZGVMaW5rVW5kZXJsaW5lPXRoaXMucmVnaXN0ZXIobmV3IG8uRXZlbnRFbWl0dGVy"
    "KSx0aGlzLm9uSGlkZUxpbmtVbmRlcmxpbmU9dGhpcy5fb25IaWRlTGlua1VuZGVybGluZS5ldmVudCx0aGlzLnJlZ2lzdGVyKCgwLGEuZ2V0RGlzcG9zZUFy"
    "cmF5RGlzcG9zYWJsZSkodGhpcy5fbGlua0NhY2hlRGlzcG9zYWJsZXMpKSx0aGlzLnJlZ2lzdGVyKCgwLGEudG9EaXNwb3NhYmxlKSgoKCk9Pnt0aGlzLl9s"
    "YXN0TW91c2VFdmVudD12b2lkIDB9KSkpLHRoaXMucmVnaXN0ZXIodGhpcy5fYnVmZmVyU2VydmljZS5vblJlc2l6ZSgoKCk9Pnt0aGlzLl9jbGVhckN1cnJl"
    "bnRMaW5rKCksdGhpcy5fd2FzUmVzaXplZD0hMH0pKSl9cmVnaXN0ZXJMaW5rUHJvdmlkZXIoZSl7cmV0dXJuIHRoaXMuX2xpbmtQcm92aWRlcnMucHVzaChl"
    "KSx7ZGlzcG9zZTooKT0+e2NvbnN0IHQ9dGhpcy5fbGlua1Byb3ZpZGVycy5pbmRleE9mKGUpOy0xIT09dCYmdGhpcy5fbGlua1Byb3ZpZGVycy5zcGxpY2Uo"
    "dCwxKX19fWF0dGFjaFRvRG9tKGUsdCxpKXt0aGlzLl9lbGVtZW50PWUsdGhpcy5fbW91c2VTZXJ2aWNlPXQsdGhpcy5fcmVuZGVyU2VydmljZT1pLHRoaXMu"
    "cmVnaXN0ZXIoKDAsbi5hZGREaXNwb3NhYmxlRG9tTGlzdGVuZXIpKHRoaXMuX2VsZW1lbnQsIm1vdXNlbGVhdmUiLCgoKT0+e3RoaXMuX2lzTW91c2VPdXQ9"
    "ITAsdGhpcy5fY2xlYXJDdXJyZW50TGluaygpfSkpKSx0aGlzLnJlZ2lzdGVyKCgwLG4uYWRkRGlzcG9zYWJsZURvbUxpc3RlbmVyKSh0aGlzLl9lbGVtZW50"
    "LCJtb3VzZW1vdmUiLHRoaXMuX2hhbmRsZU1vdXNlTW92ZS5iaW5kKHRoaXMpKSksdGhpcy5yZWdpc3RlcigoMCxuLmFkZERpc3Bvc2FibGVEb21MaXN0ZW5l"
    "cikodGhpcy5fZWxlbWVudCwibW91c2Vkb3duIix0aGlzLl9oYW5kbGVNb3VzZURvd24uYmluZCh0aGlzKSkpLHRoaXMucmVnaXN0ZXIoKDAsbi5hZGREaXNw"
    "b3NhYmxlRG9tTGlzdGVuZXIpKHRoaXMuX2VsZW1lbnQsIm1vdXNldXAiLHRoaXMuX2hhbmRsZU1vdXNlVXAuYmluZCh0aGlzKSkpfV9oYW5kbGVNb3VzZU1v"
    "dmUoZSl7aWYodGhpcy5fbGFzdE1vdXNlRXZlbnQ9ZSwhdGhpcy5fZWxlbWVudHx8IXRoaXMuX21vdXNlU2VydmljZSlyZXR1cm47Y29uc3QgdD10aGlzLl9w"
    "b3NpdGlvbkZyb21Nb3VzZUV2ZW50KGUsdGhpcy5fZWxlbWVudCx0aGlzLl9tb3VzZVNlcnZpY2UpO2lmKCF0KXJldHVybjt0aGlzLl9pc01vdXNlT3V0PSEx"
    "O2NvbnN0IGk9ZS5jb21wb3NlZFBhdGgoKTtmb3IobGV0IGU9MDtlPGkubGVuZ3RoO2UrKyl7Y29uc3QgdD1pW2VdO2lmKHQuY2xhc3NMaXN0LmNvbnRhaW5z"
    "KCJ4dGVybSIpKWJyZWFrO2lmKHQuY2xhc3NMaXN0LmNvbnRhaW5zKCJ4dGVybS1ob3ZlciIpKXJldHVybn10aGlzLl9sYXN0QnVmZmVyQ2VsbCYmdC54PT09"
    "dGhpcy5fbGFzdEJ1ZmZlckNlbGwueCYmdC55PT09dGhpcy5fbGFzdEJ1ZmZlckNlbGwueXx8KHRoaXMuX2hhbmRsZUhvdmVyKHQpLHRoaXMuX2xhc3RCdWZm"
    "ZXJDZWxsPXQpfV9oYW5kbGVIb3ZlcihlKXtpZih0aGlzLl9hY3RpdmVMaW5lIT09ZS55fHx0aGlzLl93YXNSZXNpemVkKXJldHVybiB0aGlzLl9jbGVhckN1"
    "cnJlbnRMaW5rKCksdGhpcy5fYXNrRm9yTGluayhlLCExKSx2b2lkKHRoaXMuX3dhc1Jlc2l6ZWQ9ITEpO3RoaXMuX2N1cnJlbnRMaW5rJiZ0aGlzLl9saW5r"
    "QXRQb3NpdGlvbih0aGlzLl9jdXJyZW50TGluay5saW5rLGUpfHwodGhpcy5fY2xlYXJDdXJyZW50TGluaygpLHRoaXMuX2Fza0ZvckxpbmsoZSwhMCkpfV9h"
    "c2tGb3JMaW5rKGUsdCl7dmFyIGksczt0aGlzLl9hY3RpdmVQcm92aWRlclJlcGxpZXMmJnR8fChudWxsPT09KGk9dGhpcy5fYWN0aXZlUHJvdmlkZXJSZXBs"
    "aWVzKXx8dm9pZCAwPT09aXx8aS5mb3JFYWNoKChlPT57bnVsbD09ZXx8ZS5mb3JFYWNoKChlPT57ZS5saW5rLmRpc3Bvc2UmJmUubGluay5kaXNwb3NlKCl9"
    "KSl9KSksdGhpcy5fYWN0aXZlUHJvdmlkZXJSZXBsaWVzPW5ldyBNYXAsdGhpcy5fYWN0aXZlTGluZT1lLnkpO2xldCByPSExO2Zvcihjb25zdFtpLG5db2Yg"
    "dGhpcy5fbGlua1Byb3ZpZGVycy5lbnRyaWVzKCkpdD8obnVsbD09PShzPXRoaXMuX2FjdGl2ZVByb3ZpZGVyUmVwbGllcyl8fHZvaWQgMD09PXM/dm9pZCAw"
    "OnMuZ2V0KGkpKSYmKHI9dGhpcy5fY2hlY2tMaW5rUHJvdmlkZXJSZXN1bHQoaSxlLHIpKTpuLnByb3ZpZGVMaW5rcyhlLnksKHQ9Pnt2YXIgcyxuO2lmKHRo"
    "aXMuX2lzTW91c2VPdXQpcmV0dXJuO2NvbnN0IG89bnVsbD09dD92b2lkIDA6dC5tYXAoKGU9Pih7bGluazplfSkpKTtudWxsPT09KHM9dGhpcy5fYWN0aXZl"
    "UHJvdmlkZXJSZXBsaWVzKXx8dm9pZCAwPT09c3x8cy5zZXQoaSxvKSxyPXRoaXMuX2NoZWNrTGlua1Byb3ZpZGVyUmVzdWx0KGksZSxyKSwobnVsbD09PShu"
    "PXRoaXMuX2FjdGl2ZVByb3ZpZGVyUmVwbGllcyl8fHZvaWQgMD09PW4/dm9pZCAwOm4uc2l6ZSk9PT10aGlzLl9saW5rUHJvdmlkZXJzLmxlbmd0aCYmdGhp"
    "cy5fcmVtb3ZlSW50ZXJzZWN0aW5nTGlua3MoZS55LHRoaXMuX2FjdGl2ZVByb3ZpZGVyUmVwbGllcyl9KSl9X3JlbW92ZUludGVyc2VjdGluZ0xpbmtzKGUs"
    "dCl7Y29uc3QgaT1uZXcgU2V0O2ZvcihsZXQgcz0wO3M8dC5zaXplO3MrKyl7Y29uc3Qgcj10LmdldChzKTtpZihyKWZvcihsZXQgdD0wO3Q8ci5sZW5ndGg7"
    "dCsrKXtjb25zdCBzPXJbdF0sbj1zLmxpbmsucmFuZ2Uuc3RhcnQueTxlPzA6cy5saW5rLnJhbmdlLnN0YXJ0Lngsbz1zLmxpbmsucmFuZ2UuZW5kLnk+ZT90"
    "aGlzLl9idWZmZXJTZXJ2aWNlLmNvbHM6cy5saW5rLnJhbmdlLmVuZC54O2ZvcihsZXQgZT1uO2U8PW87ZSsrKXtpZihpLmhhcyhlKSl7ci5zcGxpY2UodC0t"
    "LDEpO2JyZWFrfWkuYWRkKGUpfX19fV9jaGVja0xpbmtQcm92aWRlclJlc3VsdChlLHQsaSl7dmFyIHM7aWYoIXRoaXMuX2FjdGl2ZVByb3ZpZGVyUmVwbGll"
    "cylyZXR1cm4gaTtjb25zdCByPXRoaXMuX2FjdGl2ZVByb3ZpZGVyUmVwbGllcy5nZXQoZSk7bGV0IG49ITE7Zm9yKGxldCB0PTA7dDxlO3QrKyl0aGlzLl9h"
    "Y3RpdmVQcm92aWRlclJlcGxpZXMuaGFzKHQpJiYhdGhpcy5fYWN0aXZlUHJvdmlkZXJSZXBsaWVzLmdldCh0KXx8KG49ITApO2lmKCFuJiZyKXtjb25zdCBl"
    "PXIuZmluZCgoZT0+dGhpcy5fbGlua0F0UG9zaXRpb24oZS5saW5rLHQpKSk7ZSYmKGk9ITAsdGhpcy5faGFuZGxlTmV3TGluayhlKSl9aWYodGhpcy5fYWN0"
    "aXZlUHJvdmlkZXJSZXBsaWVzLnNpemU9PT10aGlzLl9saW5rUHJvdmlkZXJzLmxlbmd0aCYmIWkpZm9yKGxldCBlPTA7ZTx0aGlzLl9hY3RpdmVQcm92aWRl"
    "clJlcGxpZXMuc2l6ZTtlKyspe2NvbnN0IHI9bnVsbD09PShzPXRoaXMuX2FjdGl2ZVByb3ZpZGVyUmVwbGllcy5nZXQoZSkpfHx2b2lkIDA9PT1zP3ZvaWQg"
    "MDpzLmZpbmQoKGU9PnRoaXMuX2xpbmtBdFBvc2l0aW9uKGUubGluayx0KSkpO2lmKHIpe2k9ITAsdGhpcy5faGFuZGxlTmV3TGluayhyKTticmVha319cmV0"
    "dXJuIGl9X2hhbmRsZU1vdXNlRG93bigpe3RoaXMuX21vdXNlRG93bkxpbms9dGhpcy5fY3VycmVudExpbmt9X2hhbmRsZU1vdXNlVXAoZSl7aWYoIXRoaXMu"
    "X2VsZW1lbnR8fCF0aGlzLl9tb3VzZVNlcnZpY2V8fCF0aGlzLl9jdXJyZW50TGluaylyZXR1cm47Y29uc3QgdD10aGlzLl9wb3NpdGlvbkZyb21Nb3VzZUV2"
    "ZW50KGUsdGhpcy5fZWxlbWVudCx0aGlzLl9tb3VzZVNlcnZpY2UpO3QmJnRoaXMuX21vdXNlRG93bkxpbms9PT10aGlzLl9jdXJyZW50TGluayYmdGhpcy5f"
    "bGlua0F0UG9zaXRpb24odGhpcy5fY3VycmVudExpbmsubGluayx0KSYmdGhpcy5fY3VycmVudExpbmsubGluay5hY3RpdmF0ZShlLHRoaXMuX2N1cnJlbnRM"
    "aW5rLmxpbmsudGV4dCl9X2NsZWFyQ3VycmVudExpbmsoZSx0KXt0aGlzLl9lbGVtZW50JiZ0aGlzLl9jdXJyZW50TGluayYmdGhpcy5fbGFzdE1vdXNlRXZl"
    "bnQmJighZXx8IXR8fHRoaXMuX2N1cnJlbnRMaW5rLmxpbmsucmFuZ2Uuc3RhcnQueT49ZSYmdGhpcy5fY3VycmVudExpbmsubGluay5yYW5nZS5lbmQueTw9"
    "dCkmJih0aGlzLl9saW5rTGVhdmUodGhpcy5fZWxlbWVudCx0aGlzLl9jdXJyZW50TGluay5saW5rLHRoaXMuX2xhc3RNb3VzZUV2ZW50KSx0aGlzLl9jdXJy"
    "ZW50TGluaz12b2lkIDAsKDAsYS5kaXNwb3NlQXJyYXkpKHRoaXMuX2xpbmtDYWNoZURpc3Bvc2FibGVzKSl9X2hhbmRsZU5ld0xpbmsoZSl7aWYoIXRoaXMu"
    "X2VsZW1lbnR8fCF0aGlzLl9sYXN0TW91c2VFdmVudHx8IXRoaXMuX21vdXNlU2VydmljZSlyZXR1cm47Y29uc3QgdD10aGlzLl9wb3NpdGlvbkZyb21Nb3Vz"
    "ZUV2ZW50KHRoaXMuX2xhc3RNb3VzZUV2ZW50LHRoaXMuX2VsZW1lbnQsdGhpcy5fbW91c2VTZXJ2aWNlKTt0JiZ0aGlzLl9saW5rQXRQb3NpdGlvbihlLmxp"
    "bmssdCkmJih0aGlzLl9jdXJyZW50TGluaz1lLHRoaXMuX2N1cnJlbnRMaW5rLnN0YXRlPXtkZWNvcmF0aW9uczp7dW5kZXJsaW5lOnZvaWQgMD09PWUubGlu"
    "ay5kZWNvcmF0aW9uc3x8ZS5saW5rLmRlY29yYXRpb25zLnVuZGVybGluZSxwb2ludGVyQ3Vyc29yOnZvaWQgMD09PWUubGluay5kZWNvcmF0aW9uc3x8ZS5s"
    "aW5rLmRlY29yYXRpb25zLnBvaW50ZXJDdXJzb3J9LGlzSG92ZXJlZDohMH0sdGhpcy5fbGlua0hvdmVyKHRoaXMuX2VsZW1lbnQsZS5saW5rLHRoaXMuX2xh"
    "c3RNb3VzZUV2ZW50KSxlLmxpbmsuZGVjb3JhdGlvbnM9e30sT2JqZWN0LmRlZmluZVByb3BlcnRpZXMoZS5saW5rLmRlY29yYXRpb25zLHtwb2ludGVyQ3Vy"
    "c29yOntnZXQ6KCk9Pnt2YXIgZSx0O3JldHVybiBudWxsPT09KHQ9bnVsbD09PShlPXRoaXMuX2N1cnJlbnRMaW5rKXx8dm9pZCAwPT09ZT92b2lkIDA6ZS5z"
    "dGF0ZSl8fHZvaWQgMD09PXQ/dm9pZCAwOnQuZGVjb3JhdGlvbnMucG9pbnRlckN1cnNvcn0sc2V0OmU9Pnt2YXIgdCxpOyhudWxsPT09KHQ9dGhpcy5fY3Vy"
    "cmVudExpbmspfHx2b2lkIDA9PT10P3ZvaWQgMDp0LnN0YXRlKSYmdGhpcy5fY3VycmVudExpbmsuc3RhdGUuZGVjb3JhdGlvbnMucG9pbnRlckN1cnNvciE9"
    "PWUmJih0aGlzLl9jdXJyZW50TGluay5zdGF0ZS5kZWNvcmF0aW9ucy5wb2ludGVyQ3Vyc29yPWUsdGhpcy5fY3VycmVudExpbmsuc3RhdGUuaXNIb3ZlcmVk"
    "JiYobnVsbD09PShpPXRoaXMuX2VsZW1lbnQpfHx2b2lkIDA9PT1pfHxpLmNsYXNzTGlzdC50b2dnbGUoInh0ZXJtLWN1cnNvci1wb2ludGVyIixlKSkpfX0s"
    "dW5kZXJsaW5lOntnZXQ6KCk9Pnt2YXIgZSx0O3JldHVybiBudWxsPT09KHQ9bnVsbD09PShlPXRoaXMuX2N1cnJlbnRMaW5rKXx8dm9pZCAwPT09ZT92b2lk"
    "IDA6ZS5zdGF0ZSl8fHZvaWQgMD09PXQ/dm9pZCAwOnQuZGVjb3JhdGlvbnMudW5kZXJsaW5lfSxzZXQ6dD0+e3ZhciBpLHMscjsobnVsbD09PShpPXRoaXMu"
    "X2N1cnJlbnRMaW5rKXx8dm9pZCAwPT09aT92b2lkIDA6aS5zdGF0ZSkmJihudWxsPT09KHI9bnVsbD09PShzPXRoaXMuX2N1cnJlbnRMaW5rKXx8dm9pZCAw"
    "PT09cz92b2lkIDA6cy5zdGF0ZSl8fHZvaWQgMD09PXI/dm9pZCAwOnIuZGVjb3JhdGlvbnMudW5kZXJsaW5lKSE9PXQmJih0aGlzLl9jdXJyZW50TGluay5z"
    "dGF0ZS5kZWNvcmF0aW9ucy51bmRlcmxpbmU9dCx0aGlzLl9jdXJyZW50TGluay5zdGF0ZS5pc0hvdmVyZWQmJnRoaXMuX2ZpcmVVbmRlcmxpbmVFdmVudChl"
    "LmxpbmssdCkpfX19KSx0aGlzLl9yZW5kZXJTZXJ2aWNlJiZ0aGlzLl9saW5rQ2FjaGVEaXNwb3NhYmxlcy5wdXNoKHRoaXMuX3JlbmRlclNlcnZpY2Uub25S"
    "ZW5kZXJlZFZpZXdwb3J0Q2hhbmdlKChlPT57aWYoIXRoaXMuX2N1cnJlbnRMaW5rKXJldHVybjtjb25zdCB0PTA9PT1lLnN0YXJ0PzA6ZS5zdGFydCsxK3Ro"
    "aXMuX2J1ZmZlclNlcnZpY2UuYnVmZmVyLnlkaXNwLGk9dGhpcy5fYnVmZmVyU2VydmljZS5idWZmZXIueWRpc3ArMStlLmVuZDtpZih0aGlzLl9jdXJyZW50"
    "TGluay5saW5rLnJhbmdlLnN0YXJ0Lnk+PXQmJnRoaXMuX2N1cnJlbnRMaW5rLmxpbmsucmFuZ2UuZW5kLnk8PWkmJih0aGlzLl9jbGVhckN1cnJlbnRMaW5r"
    "KHQsaSksdGhpcy5fbGFzdE1vdXNlRXZlbnQmJnRoaXMuX2VsZW1lbnQpKXtjb25zdCBlPXRoaXMuX3Bvc2l0aW9uRnJvbU1vdXNlRXZlbnQodGhpcy5fbGFz"
    "dE1vdXNlRXZlbnQsdGhpcy5fZWxlbWVudCx0aGlzLl9tb3VzZVNlcnZpY2UpO2UmJnRoaXMuX2Fza0ZvckxpbmsoZSwhMSl9fSkpKSl9X2xpbmtIb3Zlcihl"
    "LHQsaSl7dmFyIHM7KG51bGw9PT0ocz10aGlzLl9jdXJyZW50TGluayl8fHZvaWQgMD09PXM/dm9pZCAwOnMuc3RhdGUpJiYodGhpcy5fY3VycmVudExpbmsu"
    "c3RhdGUuaXNIb3ZlcmVkPSEwLHRoaXMuX2N1cnJlbnRMaW5rLnN0YXRlLmRlY29yYXRpb25zLnVuZGVybGluZSYmdGhpcy5fZmlyZVVuZGVybGluZUV2ZW50"
    "KHQsITApLHRoaXMuX2N1cnJlbnRMaW5rLnN0YXRlLmRlY29yYXRpb25zLnBvaW50ZXJDdXJzb3ImJmUuY2xhc3NMaXN0LmFkZCgieHRlcm0tY3Vyc29yLXBv"
    "aW50ZXIiKSksdC5ob3ZlciYmdC5ob3ZlcihpLHQudGV4dCl9X2ZpcmVVbmRlcmxpbmVFdmVudChlLHQpe2NvbnN0IGk9ZS5yYW5nZSxzPXRoaXMuX2J1ZmZl"
    "clNlcnZpY2UuYnVmZmVyLnlkaXNwLHI9dGhpcy5fY3JlYXRlTGlua1VuZGVybGluZUV2ZW50KGkuc3RhcnQueC0xLGkuc3RhcnQueS1zLTEsaS5lbmQueCxp"
    "LmVuZC55LXMtMSx2b2lkIDApOyh0P3RoaXMuX29uU2hvd0xpbmtVbmRlcmxpbmU6dGhpcy5fb25IaWRlTGlua1VuZGVybGluZSkuZmlyZShyKX1fbGlua0xl"
    "YXZlKGUsdCxpKXt2YXIgczsobnVsbD09PShzPXRoaXMuX2N1cnJlbnRMaW5rKXx8dm9pZCAwPT09cz92b2lkIDA6cy5zdGF0ZSkmJih0aGlzLl9jdXJyZW50"
    "TGluay5zdGF0ZS5pc0hvdmVyZWQ9ITEsdGhpcy5fY3VycmVudExpbmsuc3RhdGUuZGVjb3JhdGlvbnMudW5kZXJsaW5lJiZ0aGlzLl9maXJlVW5kZXJsaW5l"
    "RXZlbnQodCwhMSksdGhpcy5fY3VycmVudExpbmsuc3RhdGUuZGVjb3JhdGlvbnMucG9pbnRlckN1cnNvciYmZS5jbGFzc0xpc3QucmVtb3ZlKCJ4dGVybS1j"
    "dXJzb3ItcG9pbnRlciIpKSx0LmxlYXZlJiZ0LmxlYXZlKGksdC50ZXh0KX1fbGlua0F0UG9zaXRpb24oZSx0KXtjb25zdCBpPWUucmFuZ2Uuc3RhcnQueSp0"
    "aGlzLl9idWZmZXJTZXJ2aWNlLmNvbHMrZS5yYW5nZS5zdGFydC54LHM9ZS5yYW5nZS5lbmQueSp0aGlzLl9idWZmZXJTZXJ2aWNlLmNvbHMrZS5yYW5nZS5l"
    "bmQueCxyPXQueSp0aGlzLl9idWZmZXJTZXJ2aWNlLmNvbHMrdC54O3JldHVybiBpPD1yJiZyPD1zfV9wb3NpdGlvbkZyb21Nb3VzZUV2ZW50KGUsdCxpKXtj"
    "b25zdCBzPWkuZ2V0Q29vcmRzKGUsdCx0aGlzLl9idWZmZXJTZXJ2aWNlLmNvbHMsdGhpcy5fYnVmZmVyU2VydmljZS5yb3dzKTtpZihzKXJldHVybnt4OnNb"
    "MF0seTpzWzFdK3RoaXMuX2J1ZmZlclNlcnZpY2UuYnVmZmVyLnlkaXNwfX1fY3JlYXRlTGlua1VuZGVybGluZUV2ZW50KGUsdCxpLHMscil7cmV0dXJue3gx"
    "OmUseTE6dCx4MjppLHkyOnMsY29sczp0aGlzLl9idWZmZXJTZXJ2aWNlLmNvbHMsZmc6cn19fTt0LkxpbmtpZmllcjI9Yz1zKFtyKDAsaC5JQnVmZmVyU2Vy"
    "dmljZSldLGMpfSw5MDQyOihlLHQpPT57T2JqZWN0LmRlZmluZVByb3BlcnR5KHQsIl9fZXNNb2R1bGUiLHt2YWx1ZTohMH0pLHQudG9vTXVjaE91dHB1dD10"
    "LnByb21wdExhYmVsPXZvaWQgMCx0LnByb21wdExhYmVsPSJUZXJtaW5hbCBpbnB1dCIsdC50b29NdWNoT3V0cHV0PSJUb28gbXVjaCBvdXRwdXQgdG8gYW5u"
    "b3VuY2UsIG5hdmlnYXRlIHRvIHJvd3MgbWFudWFsbHkgdG8gcmVhZCJ9LDM3MzA6ZnVuY3Rpb24oZSx0LGkpe3ZhciBzPXRoaXMmJnRoaXMuX19kZWNvcmF0"
    "ZXx8ZnVuY3Rpb24oZSx0LGkscyl7dmFyIHIsbj1hcmd1bWVudHMubGVuZ3RoLG89bjwzP3Q6bnVsbD09PXM/cz1PYmplY3QuZ2V0T3duUHJvcGVydHlEZXNj"
    "cmlwdG9yKHQsaSk6cztpZigib2JqZWN0Ij09dHlwZW9mIFJlZmxlY3QmJiJmdW5jdGlvbiI9PXR5cGVvZiBSZWZsZWN0LmRlY29yYXRlKW89UmVmbGVjdC5k"
    "ZWNvcmF0ZShlLHQsaSxzKTtlbHNlIGZvcih2YXIgYT1lLmxlbmd0aC0xO2E+PTA7YS0tKShyPWVbYV0pJiYobz0objwzP3Iobyk6bj4zP3IodCxpLG8pOnIo"
    "dCxpKSl8fG8pO3JldHVybiBuPjMmJm8mJk9iamVjdC5kZWZpbmVQcm9wZXJ0eSh0LGksbyksb30scj10aGlzJiZ0aGlzLl9fcGFyYW18fGZ1bmN0aW9uKGUs"
    "dCl7cmV0dXJuIGZ1bmN0aW9uKGkscyl7dChpLHMsZSl9fTtPYmplY3QuZGVmaW5lUHJvcGVydHkodCwiX19lc01vZHVsZSIse3ZhbHVlOiEwfSksdC5Pc2NM"
    "aW5rUHJvdmlkZXI9dm9pZCAwO2NvbnN0IG49aSg1MTEpLG89aSgyNTg1KTtsZXQgYT10Lk9zY0xpbmtQcm92aWRlcj1jbGFzc3tjb25zdHJ1Y3RvcihlLHQs"
    "aSl7dGhpcy5fYnVmZmVyU2VydmljZT1lLHRoaXMuX29wdGlvbnNTZXJ2aWNlPXQsdGhpcy5fb3NjTGlua1NlcnZpY2U9aX1wcm92aWRlTGlua3MoZSx0KXt2"
    "YXIgaTtjb25zdCBzPXRoaXMuX2J1ZmZlclNlcnZpY2UuYnVmZmVyLmxpbmVzLmdldChlLTEpO2lmKCFzKXJldHVybiB2b2lkIHQodm9pZCAwKTtjb25zdCBy"
    "PVtdLG89dGhpcy5fb3B0aW9uc1NlcnZpY2UucmF3T3B0aW9ucy5saW5rSGFuZGxlcixhPW5ldyBuLkNlbGxEYXRhLGM9cy5nZXRUcmltbWVkTGVuZ3RoKCk7"
    "bGV0IGw9LTEsZD0tMSxfPSExO2ZvcihsZXQgdD0wO3Q8Yzt0KyspaWYoLTEhPT1kfHxzLmhhc0NvbnRlbnQodCkpe2lmKHMubG9hZENlbGwodCxhKSxhLmhh"
    "c0V4dGVuZGVkQXR0cnMoKSYmYS5leHRlbmRlZC51cmxJZCl7aWYoLTE9PT1kKXtkPXQsbD1hLmV4dGVuZGVkLnVybElkO2NvbnRpbnVlfV89YS5leHRlbmRl"
    "ZC51cmxJZCE9PWx9ZWxzZS0xIT09ZCYmKF89ITApO2lmKF98fC0xIT09ZCYmdD09PWMtMSl7Y29uc3Qgcz1udWxsPT09KGk9dGhpcy5fb3NjTGlua1NlcnZp"
    "Y2UuZ2V0TGlua0RhdGEobCkpfHx2b2lkIDA9PT1pP3ZvaWQgMDppLnVyaTtpZihzKXtjb25zdCBpPXtzdGFydDp7eDpkKzEseTplfSxlbmQ6e3g6dCsoX3x8"
    "dCE9PWMtMT8wOjEpLHk6ZX19O2xldCBuPSExO2lmKCEobnVsbD09bz92b2lkIDA6by5hbGxvd05vbkh0dHBQcm90b2NvbHMpKXRyeXtjb25zdCBlPW5ldyBV"
    "Ukwocyk7WyJodHRwOiIsImh0dHBzOiJdLmluY2x1ZGVzKGUucHJvdG9jb2wpfHwobj0hMCl9Y2F0Y2goZSl7bj0hMH1ufHxyLnB1c2goe3RleHQ6cyxyYW5n"
    "ZTppLGFjdGl2YXRlOihlLHQpPT5vP28uYWN0aXZhdGUoZSx0LGkpOmgoMCx0KSxob3ZlcjooZSx0KT0+e3ZhciBzO3JldHVybiBudWxsPT09KHM9bnVsbD09"
    "bz92b2lkIDA6by5ob3Zlcil8fHZvaWQgMD09PXM/dm9pZCAwOnMuY2FsbChvLGUsdCxpKX0sbGVhdmU6KGUsdCk9Pnt2YXIgcztyZXR1cm4gbnVsbD09PShz"
    "PW51bGw9PW8/dm9pZCAwOm8ubGVhdmUpfHx2b2lkIDA9PT1zP3ZvaWQgMDpzLmNhbGwobyxlLHQsaSl9fSl9Xz0hMSxhLmhhc0V4dGVuZGVkQXR0cnMoKSYm"
    "YS5leHRlbmRlZC51cmxJZD8oZD10LGw9YS5leHRlbmRlZC51cmxJZCk6KGQ9LTEsbD0tMSl9fXQocil9fTtmdW5jdGlvbiBoKGUsdCl7aWYoY29uZmlybShg"
    "RG8geW91IHdhbnQgdG8gbmF2aWdhdGUgdG8gJHt0fT9cblxuV0FSTklORzogVGhpcyBsaW5rIGNvdWxkIHBvdGVudGlhbGx5IGJlIGRhbmdlcm91c2ApKXtj"
    "b25zdCBlPXdpbmRvdy5vcGVuKCk7aWYoZSl7dHJ5e2Uub3BlbmVyPW51bGx9Y2F0Y2goZSl7fWUubG9jYXRpb24uaHJlZj10fWVsc2UgY29uc29sZS53YXJu"
    "KCJPcGVuaW5nIGxpbmsgYmxvY2tlZCBhcyBvcGVuZXIgY291bGQgbm90IGJlIGNsZWFyZWQiKX19dC5Pc2NMaW5rUHJvdmlkZXI9YT1zKFtyKDAsby5JQnVm"
    "ZmVyU2VydmljZSkscigxLG8uSU9wdGlvbnNTZXJ2aWNlKSxyKDIsby5JT3NjTGlua1NlcnZpY2UpXSxhKX0sNjE5MzooZSx0KT0+e09iamVjdC5kZWZpbmVQ"
    "cm9wZXJ0eSh0LCJfX2VzTW9kdWxlIix7dmFsdWU6ITB9KSx0LlJlbmRlckRlYm91bmNlcj12b2lkIDAsdC5SZW5kZXJEZWJvdW5jZXI9Y2xhc3N7Y29uc3Ry"
    "dWN0b3IoZSx0KXt0aGlzLl9wYXJlbnRXaW5kb3c9ZSx0aGlzLl9yZW5kZXJDYWxsYmFjaz10LHRoaXMuX3JlZnJlc2hDYWxsYmFja3M9W119ZGlzcG9zZSgp"
    "e3RoaXMuX2FuaW1hdGlvbkZyYW1lJiYodGhpcy5fcGFyZW50V2luZG93LmNhbmNlbEFuaW1hdGlvbkZyYW1lKHRoaXMuX2FuaW1hdGlvbkZyYW1lKSx0aGlz"
    "Ll9hbmltYXRpb25GcmFtZT12b2lkIDApfWFkZFJlZnJlc2hDYWxsYmFjayhlKXtyZXR1cm4gdGhpcy5fcmVmcmVzaENhbGxiYWNrcy5wdXNoKGUpLHRoaXMu"
    "X2FuaW1hdGlvbkZyYW1lfHwodGhpcy5fYW5pbWF0aW9uRnJhbWU9dGhpcy5fcGFyZW50V2luZG93LnJlcXVlc3RBbmltYXRpb25GcmFtZSgoKCk9PnRoaXMu"
    "X2lubmVyUmVmcmVzaCgpKSkpLHRoaXMuX2FuaW1hdGlvbkZyYW1lfXJlZnJlc2goZSx0LGkpe3RoaXMuX3Jvd0NvdW50PWksZT12b2lkIDAhPT1lP2U6MCx0"
    "PXZvaWQgMCE9PXQ/dDp0aGlzLl9yb3dDb3VudC0xLHRoaXMuX3Jvd1N0YXJ0PXZvaWQgMCE9PXRoaXMuX3Jvd1N0YXJ0P01hdGgubWluKHRoaXMuX3Jvd1N0"
    "YXJ0LGUpOmUsdGhpcy5fcm93RW5kPXZvaWQgMCE9PXRoaXMuX3Jvd0VuZD9NYXRoLm1heCh0aGlzLl9yb3dFbmQsdCk6dCx0aGlzLl9hbmltYXRpb25GcmFt"
    "ZXx8KHRoaXMuX2FuaW1hdGlvbkZyYW1lPXRoaXMuX3BhcmVudFdpbmRvdy5yZXF1ZXN0QW5pbWF0aW9uRnJhbWUoKCgpPT50aGlzLl9pbm5lclJlZnJlc2go"
    "KSkpKX1faW5uZXJSZWZyZXNoKCl7aWYodGhpcy5fYW5pbWF0aW9uRnJhbWU9dm9pZCAwLHZvaWQgMD09PXRoaXMuX3Jvd1N0YXJ0fHx2b2lkIDA9PT10aGlz"
    "Ll9yb3dFbmR8fHZvaWQgMD09PXRoaXMuX3Jvd0NvdW50KXJldHVybiB2b2lkIHRoaXMuX3J1blJlZnJlc2hDYWxsYmFja3MoKTtjb25zdCBlPU1hdGgubWF4"
    "KHRoaXMuX3Jvd1N0YXJ0LDApLHQ9TWF0aC5taW4odGhpcy5fcm93RW5kLHRoaXMuX3Jvd0NvdW50LTEpO3RoaXMuX3Jvd1N0YXJ0PXZvaWQgMCx0aGlzLl9y"
    "b3dFbmQ9dm9pZCAwLHRoaXMuX3JlbmRlckNhbGxiYWNrKGUsdCksdGhpcy5fcnVuUmVmcmVzaENhbGxiYWNrcygpfV9ydW5SZWZyZXNoQ2FsbGJhY2tzKCl7"
    "Zm9yKGNvbnN0IGUgb2YgdGhpcy5fcmVmcmVzaENhbGxiYWNrcyllKDApO3RoaXMuX3JlZnJlc2hDYWxsYmFja3M9W119fX0sNTU5NjooZSx0LGkpPT57T2Jq"
    "ZWN0LmRlZmluZVByb3BlcnR5KHQsIl9fZXNNb2R1bGUiLHt2YWx1ZTohMH0pLHQuU2NyZWVuRHByTW9uaXRvcj12b2lkIDA7Y29uc3Qgcz1pKDg0NCk7Y2xh"
    "c3MgciBleHRlbmRzIHMuRGlzcG9zYWJsZXtjb25zdHJ1Y3RvcihlKXtzdXBlcigpLHRoaXMuX3BhcmVudFdpbmRvdz1lLHRoaXMuX2N1cnJlbnREZXZpY2VQ"
    "aXhlbFJhdGlvPXRoaXMuX3BhcmVudFdpbmRvdy5kZXZpY2VQaXhlbFJhdGlvLHRoaXMucmVnaXN0ZXIoKDAscy50b0Rpc3Bvc2FibGUpKCgoKT0+e3RoaXMu"
    "Y2xlYXJMaXN0ZW5lcigpfSkpKX1zZXRMaXN0ZW5lcihlKXt0aGlzLl9saXN0ZW5lciYmdGhpcy5jbGVhckxpc3RlbmVyKCksdGhpcy5fbGlzdGVuZXI9ZSx0"
    "aGlzLl9vdXRlckxpc3RlbmVyPSgpPT57dGhpcy5fbGlzdGVuZXImJih0aGlzLl9saXN0ZW5lcih0aGlzLl9wYXJlbnRXaW5kb3cuZGV2aWNlUGl4ZWxSYXRp"
    "byx0aGlzLl9jdXJyZW50RGV2aWNlUGl4ZWxSYXRpbyksdGhpcy5fdXBkYXRlRHByKCkpfSx0aGlzLl91cGRhdGVEcHIoKX1fdXBkYXRlRHByKCl7dmFyIGU7"
    "dGhpcy5fb3V0ZXJMaXN0ZW5lciYmKG51bGw9PT0oZT10aGlzLl9yZXNvbHV0aW9uTWVkaWFNYXRjaExpc3QpfHx2b2lkIDA9PT1lfHxlLnJlbW92ZUxpc3Rl"
    "bmVyKHRoaXMuX291dGVyTGlzdGVuZXIpLHRoaXMuX2N1cnJlbnREZXZpY2VQaXhlbFJhdGlvPXRoaXMuX3BhcmVudFdpbmRvdy5kZXZpY2VQaXhlbFJhdGlv"
    "LHRoaXMuX3Jlc29sdXRpb25NZWRpYU1hdGNoTGlzdD10aGlzLl9wYXJlbnRXaW5kb3cubWF0Y2hNZWRpYShgc2NyZWVuIGFuZCAocmVzb2x1dGlvbjogJHt0"
    "aGlzLl9wYXJlbnRXaW5kb3cuZGV2aWNlUGl4ZWxSYXRpb31kcHB4KWApLHRoaXMuX3Jlc29sdXRpb25NZWRpYU1hdGNoTGlzdC5hZGRMaXN0ZW5lcih0aGlz"
    "Ll9vdXRlckxpc3RlbmVyKSl9Y2xlYXJMaXN0ZW5lcigpe3RoaXMuX3Jlc29sdXRpb25NZWRpYU1hdGNoTGlzdCYmdGhpcy5fbGlzdGVuZXImJnRoaXMuX291"
    "dGVyTGlzdGVuZXImJih0aGlzLl9yZXNvbHV0aW9uTWVkaWFNYXRjaExpc3QucmVtb3ZlTGlzdGVuZXIodGhpcy5fb3V0ZXJMaXN0ZW5lciksdGhpcy5fcmVz"
    "b2x1dGlvbk1lZGlhTWF0Y2hMaXN0PXZvaWQgMCx0aGlzLl9saXN0ZW5lcj12b2lkIDAsdGhpcy5fb3V0ZXJMaXN0ZW5lcj12b2lkIDApfX10LlNjcmVlbkRw"
    "ck1vbml0b3I9cn0sMzIzNjooZSx0LGkpPT57T2JqZWN0LmRlZmluZVByb3BlcnR5KHQsIl9fZXNNb2R1bGUiLHt2YWx1ZTohMH0pLHQuVGVybWluYWw9dm9p"
    "ZCAwO2NvbnN0IHM9aSgzNjE0KSxyPWkoMzY1Niksbj1pKDY0NjUpLG89aSg5MDQyKSxhPWkoMzczMCksaD1pKDE2ODApLGM9aSgzMTA3KSxsPWkoNTc0NCks"
    "ZD1pKDI5NTApLF89aSgxMjk2KSx1PWkoNDI4KSxmPWkoNDI2OSksdj1pKDUxMTQpLHA9aSg4OTM0KSxnPWkoMzIzMCksbT1pKDkzMTIpLFM9aSg0NzI1KSxD"
    "PWkoNjczMSksYj1pKDgwNTUpLHk9aSg4OTY5KSx3PWkoODQ2MCksRT1pKDg0NCksaz1pKDYxMTQpLEw9aSg4NDM3KSxEPWkoMjU4NCksUj1pKDczOTkpLHg9"
    "aSg1OTQxKSxBPWkoOTA3NCksQj1pKDI1ODUpLFQ9aSg1NDM1KSxNPWkoNDU2NyksTz0idW5kZWZpbmVkIiE9dHlwZW9mIHdpbmRvdz93aW5kb3cuZG9jdW1l"
    "bnQ6bnVsbDtjbGFzcyBQIGV4dGVuZHMgeS5Db3JlVGVybWluYWx7Z2V0IG9uRm9jdXMoKXtyZXR1cm4gdGhpcy5fb25Gb2N1cy5ldmVudH1nZXQgb25CbHVy"
    "KCl7cmV0dXJuIHRoaXMuX29uQmx1ci5ldmVudH1nZXQgb25BMTF5Q2hhcigpe3JldHVybiB0aGlzLl9vbkExMXlDaGFyRW1pdHRlci5ldmVudH1nZXQgb25B"
    "MTF5VGFiKCl7cmV0dXJuIHRoaXMuX29uQTExeVRhYkVtaXR0ZXIuZXZlbnR9Z2V0IG9uV2lsbE9wZW4oKXtyZXR1cm4gdGhpcy5fb25XaWxsT3Blbi5ldmVu"
    "dH1jb25zdHJ1Y3RvcihlPXt9KXtzdXBlcihlKSx0aGlzLmJyb3dzZXI9ayx0aGlzLl9rZXlEb3duSGFuZGxlZD0hMSx0aGlzLl9rZXlEb3duU2Vlbj0hMSx0"
    "aGlzLl9rZXlQcmVzc0hhbmRsZWQ9ITEsdGhpcy5fdW5wcm9jZXNzZWREZWFkS2V5PSExLHRoaXMuX2FjY2Vzc2liaWxpdHlNYW5hZ2VyPXRoaXMucmVnaXN0"
    "ZXIobmV3IEUuTXV0YWJsZURpc3Bvc2FibGUpLHRoaXMuX29uQ3Vyc29yTW92ZT10aGlzLnJlZ2lzdGVyKG5ldyB3LkV2ZW50RW1pdHRlciksdGhpcy5vbkN1"
    "cnNvck1vdmU9dGhpcy5fb25DdXJzb3JNb3ZlLmV2ZW50LHRoaXMuX29uS2V5PXRoaXMucmVnaXN0ZXIobmV3IHcuRXZlbnRFbWl0dGVyKSx0aGlzLm9uS2V5"
    "PXRoaXMuX29uS2V5LmV2ZW50LHRoaXMuX29uUmVuZGVyPXRoaXMucmVnaXN0ZXIobmV3IHcuRXZlbnRFbWl0dGVyKSx0aGlzLm9uUmVuZGVyPXRoaXMuX29u"
    "UmVuZGVyLmV2ZW50LHRoaXMuX29uU2VsZWN0aW9uQ2hhbmdlPXRoaXMucmVnaXN0ZXIobmV3IHcuRXZlbnRFbWl0dGVyKSx0aGlzLm9uU2VsZWN0aW9uQ2hh"
    "bmdlPXRoaXMuX29uU2VsZWN0aW9uQ2hhbmdlLmV2ZW50LHRoaXMuX29uVGl0bGVDaGFuZ2U9dGhpcy5yZWdpc3RlcihuZXcgdy5FdmVudEVtaXR0ZXIpLHRo"
    "aXMub25UaXRsZUNoYW5nZT10aGlzLl9vblRpdGxlQ2hhbmdlLmV2ZW50LHRoaXMuX29uQmVsbD10aGlzLnJlZ2lzdGVyKG5ldyB3LkV2ZW50RW1pdHRlciks"
    "dGhpcy5vbkJlbGw9dGhpcy5fb25CZWxsLmV2ZW50LHRoaXMuX29uRm9jdXM9dGhpcy5yZWdpc3RlcihuZXcgdy5FdmVudEVtaXR0ZXIpLHRoaXMuX29uQmx1"
    "cj10aGlzLnJlZ2lzdGVyKG5ldyB3LkV2ZW50RW1pdHRlciksdGhpcy5fb25BMTF5Q2hhckVtaXR0ZXI9dGhpcy5yZWdpc3RlcihuZXcgdy5FdmVudEVtaXR0"
    "ZXIpLHRoaXMuX29uQTExeVRhYkVtaXR0ZXI9dGhpcy5yZWdpc3RlcihuZXcgdy5FdmVudEVtaXR0ZXIpLHRoaXMuX29uV2lsbE9wZW49dGhpcy5yZWdpc3Rl"
    "cihuZXcgdy5FdmVudEVtaXR0ZXIpLHRoaXMuX3NldHVwKCksdGhpcy5saW5raWZpZXIyPXRoaXMucmVnaXN0ZXIodGhpcy5faW5zdGFudGlhdGlvblNlcnZp"
    "Y2UuY3JlYXRlSW5zdGFuY2Uobi5MaW5raWZpZXIyKSksdGhpcy5saW5raWZpZXIyLnJlZ2lzdGVyTGlua1Byb3ZpZGVyKHRoaXMuX2luc3RhbnRpYXRpb25T"
    "ZXJ2aWNlLmNyZWF0ZUluc3RhbmNlKGEuT3NjTGlua1Byb3ZpZGVyKSksdGhpcy5fZGVjb3JhdGlvblNlcnZpY2U9dGhpcy5faW5zdGFudGlhdGlvblNlcnZp"
    "Y2UuY3JlYXRlSW5zdGFuY2UoQS5EZWNvcmF0aW9uU2VydmljZSksdGhpcy5faW5zdGFudGlhdGlvblNlcnZpY2Uuc2V0U2VydmljZShCLklEZWNvcmF0aW9u"
    "U2VydmljZSx0aGlzLl9kZWNvcmF0aW9uU2VydmljZSksdGhpcy5yZWdpc3Rlcih0aGlzLl9pbnB1dEhhbmRsZXIub25SZXF1ZXN0QmVsbCgoKCk9PnRoaXMu"
    "X29uQmVsbC5maXJlKCkpKSksdGhpcy5yZWdpc3Rlcih0aGlzLl9pbnB1dEhhbmRsZXIub25SZXF1ZXN0UmVmcmVzaFJvd3MoKChlLHQpPT50aGlzLnJlZnJl"
    "c2goZSx0KSkpKSx0aGlzLnJlZ2lzdGVyKHRoaXMuX2lucHV0SGFuZGxlci5vblJlcXVlc3RTZW5kRm9jdXMoKCgpPT50aGlzLl9yZXBvcnRGb2N1cygpKSkp"
    "LHRoaXMucmVnaXN0ZXIodGhpcy5faW5wdXRIYW5kbGVyLm9uUmVxdWVzdFJlc2V0KCgoKT0+dGhpcy5yZXNldCgpKSkpLHRoaXMucmVnaXN0ZXIodGhpcy5f"
    "aW5wdXRIYW5kbGVyLm9uUmVxdWVzdFdpbmRvd3NPcHRpb25zUmVwb3J0KChlPT50aGlzLl9yZXBvcnRXaW5kb3dzT3B0aW9ucyhlKSkpKSx0aGlzLnJlZ2lz"
    "dGVyKHRoaXMuX2lucHV0SGFuZGxlci5vbkNvbG9yKChlPT50aGlzLl9oYW5kbGVDb2xvckV2ZW50KGUpKSkpLHRoaXMucmVnaXN0ZXIoKDAsdy5mb3J3YXJk"
    "RXZlbnQpKHRoaXMuX2lucHV0SGFuZGxlci5vbkN1cnNvck1vdmUsdGhpcy5fb25DdXJzb3JNb3ZlKSksdGhpcy5yZWdpc3RlcigoMCx3LmZvcndhcmRFdmVu"
    "dCkodGhpcy5faW5wdXRIYW5kbGVyLm9uVGl0bGVDaGFuZ2UsdGhpcy5fb25UaXRsZUNoYW5nZSkpLHRoaXMucmVnaXN0ZXIoKDAsdy5mb3J3YXJkRXZlbnQp"
    "KHRoaXMuX2lucHV0SGFuZGxlci5vbkExMXlDaGFyLHRoaXMuX29uQTExeUNoYXJFbWl0dGVyKSksdGhpcy5yZWdpc3RlcigoMCx3LmZvcndhcmRFdmVudCko"
    "dGhpcy5faW5wdXRIYW5kbGVyLm9uQTExeVRhYix0aGlzLl9vbkExMXlUYWJFbWl0dGVyKSksdGhpcy5yZWdpc3Rlcih0aGlzLl9idWZmZXJTZXJ2aWNlLm9u"
    "UmVzaXplKChlPT50aGlzLl9hZnRlclJlc2l6ZShlLmNvbHMsZS5yb3dzKSkpKSx0aGlzLnJlZ2lzdGVyKCgwLEUudG9EaXNwb3NhYmxlKSgoKCk9Pnt2YXIg"
    "ZSx0O3RoaXMuX2N1c3RvbUtleUV2ZW50SGFuZGxlcj12b2lkIDAsbnVsbD09PSh0PW51bGw9PT0oZT10aGlzLmVsZW1lbnQpfHx2b2lkIDA9PT1lP3ZvaWQg"
    "MDplLnBhcmVudE5vZGUpfHx2b2lkIDA9PT10fHx0LnJlbW92ZUNoaWxkKHRoaXMuZWxlbWVudCl9KSkpfV9oYW5kbGVDb2xvckV2ZW50KGUpe2lmKHRoaXMu"
    "X3RoZW1lU2VydmljZSlmb3IoY29uc3QgdCBvZiBlKXtsZXQgZSxpPSIiO3N3aXRjaCh0LmluZGV4KXtjYXNlIDI1NjplPSJmb3JlZ3JvdW5kIixpPSIxMCI7"
    "YnJlYWs7Y2FzZSAyNTc6ZT0iYmFja2dyb3VuZCIsaT0iMTEiO2JyZWFrO2Nhc2UgMjU4OmU9ImN1cnNvciIsaT0iMTIiO2JyZWFrO2RlZmF1bHQ6ZT0iYW5z"
    "aSIsaT0iNDsiK3QuaW5kZXh9c3dpdGNoKHQudHlwZSl7Y2FzZSAwOmNvbnN0IHM9Yi5jb2xvci50b0NvbG9yUkdCKCJhbnNpIj09PWU/dGhpcy5fdGhlbWVT"
    "ZXJ2aWNlLmNvbG9ycy5hbnNpW3QuaW5kZXhdOnRoaXMuX3RoZW1lU2VydmljZS5jb2xvcnNbZV0pO3RoaXMuY29yZVNlcnZpY2UudHJpZ2dlckRhdGFFdmVu"
    "dChgJHtELkMwLkVTQ31dJHtpfTskeygwLHgudG9SZ2JTdHJpbmcpKHMpfSR7RC5DMV9FU0NBUEVELlNUfWApO2JyZWFrO2Nhc2UgMTppZigiYW5zaSI9PT1l"
    "KXRoaXMuX3RoZW1lU2VydmljZS5tb2RpZnlDb2xvcnMoKGU9PmUuYW5zaVt0LmluZGV4XT1iLnJnYmEudG9Db2xvciguLi50LmNvbG9yKSkpO2Vsc2V7Y29u"
    "c3QgaT1lO3RoaXMuX3RoZW1lU2VydmljZS5tb2RpZnlDb2xvcnMoKGU9PmVbaV09Yi5yZ2JhLnRvQ29sb3IoLi4udC5jb2xvcikpKX1icmVhaztjYXNlIDI6"
    "dGhpcy5fdGhlbWVTZXJ2aWNlLnJlc3RvcmVDb2xvcih0LmluZGV4KX19fV9zZXR1cCgpe3N1cGVyLl9zZXR1cCgpLHRoaXMuX2N1c3RvbUtleUV2ZW50SGFu"
    "ZGxlcj12b2lkIDB9Z2V0IGJ1ZmZlcigpe3JldHVybiB0aGlzLmJ1ZmZlcnMuYWN0aXZlfWZvY3VzKCl7dGhpcy50ZXh0YXJlYSYmdGhpcy50ZXh0YXJlYS5m"
    "b2N1cyh7cHJldmVudFNjcm9sbDohMH0pfV9oYW5kbGVTY3JlZW5SZWFkZXJNb2RlT3B0aW9uQ2hhbmdlKGUpe2U/IXRoaXMuX2FjY2Vzc2liaWxpdHlNYW5h"
    "Z2VyLnZhbHVlJiZ0aGlzLl9yZW5kZXJTZXJ2aWNlJiYodGhpcy5fYWNjZXNzaWJpbGl0eU1hbmFnZXIudmFsdWU9dGhpcy5faW5zdGFudGlhdGlvblNlcnZp"
    "Y2UuY3JlYXRlSW5zdGFuY2UoTS5BY2Nlc3NpYmlsaXR5TWFuYWdlcix0aGlzKSk6dGhpcy5fYWNjZXNzaWJpbGl0eU1hbmFnZXIuY2xlYXIoKX1faGFuZGxl"
    "VGV4dEFyZWFGb2N1cyhlKXt0aGlzLmNvcmVTZXJ2aWNlLmRlY1ByaXZhdGVNb2Rlcy5zZW5kRm9jdXMmJnRoaXMuY29yZVNlcnZpY2UudHJpZ2dlckRhdGFF"
    "dmVudChELkMwLkVTQysiW0kiKSx0aGlzLnVwZGF0ZUN1cnNvclN0eWxlKGUpLHRoaXMuZWxlbWVudC5jbGFzc0xpc3QuYWRkKCJmb2N1cyIpLHRoaXMuX3No"
    "b3dDdXJzb3IoKSx0aGlzLl9vbkZvY3VzLmZpcmUoKX1ibHVyKCl7dmFyIGU7cmV0dXJuIG51bGw9PT0oZT10aGlzLnRleHRhcmVhKXx8dm9pZCAwPT09ZT92"
    "b2lkIDA6ZS5ibHVyKCl9X2hhbmRsZVRleHRBcmVhQmx1cigpe3RoaXMudGV4dGFyZWEudmFsdWU9IiIsdGhpcy5yZWZyZXNoKHRoaXMuYnVmZmVyLnksdGhp"
    "cy5idWZmZXIueSksdGhpcy5jb3JlU2VydmljZS5kZWNQcml2YXRlTW9kZXMuc2VuZEZvY3VzJiZ0aGlzLmNvcmVTZXJ2aWNlLnRyaWdnZXJEYXRhRXZlbnQo"
    "RC5DMC5FU0MrIltPIiksdGhpcy5lbGVtZW50LmNsYXNzTGlzdC5yZW1vdmUoImZvY3VzIiksdGhpcy5fb25CbHVyLmZpcmUoKX1fc3luY1RleHRBcmVhKCl7"
    "aWYoIXRoaXMudGV4dGFyZWF8fCF0aGlzLmJ1ZmZlci5pc0N1cnNvckluVmlld3BvcnR8fHRoaXMuX2NvbXBvc2l0aW9uSGVscGVyLmlzQ29tcG9zaW5nfHwh"
    "dGhpcy5fcmVuZGVyU2VydmljZSlyZXR1cm47Y29uc3QgZT10aGlzLmJ1ZmZlci55YmFzZSt0aGlzLmJ1ZmZlci55LHQ9dGhpcy5idWZmZXIubGluZXMuZ2V0"
    "KGUpO2lmKCF0KXJldHVybjtjb25zdCBpPU1hdGgubWluKHRoaXMuYnVmZmVyLngsdGhpcy5jb2xzLTEpLHM9dGhpcy5fcmVuZGVyU2VydmljZS5kaW1lbnNp"
    "b25zLmNzcy5jZWxsLmhlaWdodCxyPXQuZ2V0V2lkdGgoaSksbj10aGlzLl9yZW5kZXJTZXJ2aWNlLmRpbWVuc2lvbnMuY3NzLmNlbGwud2lkdGgqcixvPXRo"
    "aXMuYnVmZmVyLnkqdGhpcy5fcmVuZGVyU2VydmljZS5kaW1lbnNpb25zLmNzcy5jZWxsLmhlaWdodCxhPWkqdGhpcy5fcmVuZGVyU2VydmljZS5kaW1lbnNp"
    "b25zLmNzcy5jZWxsLndpZHRoO3RoaXMudGV4dGFyZWEuc3R5bGUubGVmdD1hKyJweCIsdGhpcy50ZXh0YXJlYS5zdHlsZS50b3A9bysicHgiLHRoaXMudGV4"
    "dGFyZWEuc3R5bGUud2lkdGg9bisicHgiLHRoaXMudGV4dGFyZWEuc3R5bGUuaGVpZ2h0PXMrInB4Iix0aGlzLnRleHRhcmVhLnN0eWxlLmxpbmVIZWlnaHQ9"
    "cysicHgiLHRoaXMudGV4dGFyZWEuc3R5bGUuekluZGV4PSItNSJ9X2luaXRHbG9iYWwoKXt0aGlzLl9iaW5kS2V5cygpLHRoaXMucmVnaXN0ZXIoKDAsci5h"
    "ZGREaXNwb3NhYmxlRG9tTGlzdGVuZXIpKHRoaXMuZWxlbWVudCwiY29weSIsKGU9Pnt0aGlzLmhhc1NlbGVjdGlvbigpJiYoMCxzLmNvcHlIYW5kbGVyKShl"
    "LHRoaXMuX3NlbGVjdGlvblNlcnZpY2UpfSkpKTtjb25zdCBlPWU9PigwLHMuaGFuZGxlUGFzdGVFdmVudCkoZSx0aGlzLnRleHRhcmVhLHRoaXMuY29yZVNl"
    "cnZpY2UsdGhpcy5vcHRpb25zU2VydmljZSk7dGhpcy5yZWdpc3RlcigoMCxyLmFkZERpc3Bvc2FibGVEb21MaXN0ZW5lcikodGhpcy50ZXh0YXJlYSwicGFz"
    "dGUiLGUpKSx0aGlzLnJlZ2lzdGVyKCgwLHIuYWRkRGlzcG9zYWJsZURvbUxpc3RlbmVyKSh0aGlzLmVsZW1lbnQsInBhc3RlIixlKSksay5pc0ZpcmVmb3g/"
    "dGhpcy5yZWdpc3RlcigoMCxyLmFkZERpc3Bvc2FibGVEb21MaXN0ZW5lcikodGhpcy5lbGVtZW50LCJtb3VzZWRvd24iLChlPT57Mj09PWUuYnV0dG9uJiYo"
    "MCxzLnJpZ2h0Q2xpY2tIYW5kbGVyKShlLHRoaXMudGV4dGFyZWEsdGhpcy5zY3JlZW5FbGVtZW50LHRoaXMuX3NlbGVjdGlvblNlcnZpY2UsdGhpcy5vcHRp"
    "b25zLnJpZ2h0Q2xpY2tTZWxlY3RzV29yZCl9KSkpOnRoaXMucmVnaXN0ZXIoKDAsci5hZGREaXNwb3NhYmxlRG9tTGlzdGVuZXIpKHRoaXMuZWxlbWVudCwi"
    "Y29udGV4dG1lbnUiLChlPT57KDAscy5yaWdodENsaWNrSGFuZGxlcikoZSx0aGlzLnRleHRhcmVhLHRoaXMuc2NyZWVuRWxlbWVudCx0aGlzLl9zZWxlY3Rp"
    "b25TZXJ2aWNlLHRoaXMub3B0aW9ucy5yaWdodENsaWNrU2VsZWN0c1dvcmQpfSkpKSxrLmlzTGludXgmJnRoaXMucmVnaXN0ZXIoKDAsci5hZGREaXNwb3Nh"
    "YmxlRG9tTGlzdGVuZXIpKHRoaXMuZWxlbWVudCwiYXV4Y2xpY2siLChlPT57MT09PWUuYnV0dG9uJiYoMCxzLm1vdmVUZXh0QXJlYVVuZGVyTW91c2VDdXJz"
    "b3IpKGUsdGhpcy50ZXh0YXJlYSx0aGlzLnNjcmVlbkVsZW1lbnQpfSkpKX1fYmluZEtleXMoKXt0aGlzLnJlZ2lzdGVyKCgwLHIuYWRkRGlzcG9zYWJsZURv"
    "bUxpc3RlbmVyKSh0aGlzLnRleHRhcmVhLCJrZXl1cCIsKGU9PnRoaXMuX2tleVVwKGUpKSwhMCkpLHRoaXMucmVnaXN0ZXIoKDAsci5hZGREaXNwb3NhYmxl"
    "RG9tTGlzdGVuZXIpKHRoaXMudGV4dGFyZWEsImtleWRvd24iLChlPT50aGlzLl9rZXlEb3duKGUpKSwhMCkpLHRoaXMucmVnaXN0ZXIoKDAsci5hZGREaXNw"
    "b3NhYmxlRG9tTGlzdGVuZXIpKHRoaXMudGV4dGFyZWEsImtleXByZXNzIiwoZT0+dGhpcy5fa2V5UHJlc3MoZSkpLCEwKSksdGhpcy5yZWdpc3RlcigoMCxy"
    "LmFkZERpc3Bvc2FibGVEb21MaXN0ZW5lcikodGhpcy50ZXh0YXJlYSwiY29tcG9zaXRpb25zdGFydCIsKCgpPT50aGlzLl9jb21wb3NpdGlvbkhlbHBlci5j"
    "b21wb3NpdGlvbnN0YXJ0KCkpKSksdGhpcy5yZWdpc3RlcigoMCxyLmFkZERpc3Bvc2FibGVEb21MaXN0ZW5lcikodGhpcy50ZXh0YXJlYSwiY29tcG9zaXRp"
    "b251cGRhdGUiLChlPT50aGlzLl9jb21wb3NpdGlvbkhlbHBlci5jb21wb3NpdGlvbnVwZGF0ZShlKSkpKSx0aGlzLnJlZ2lzdGVyKCgwLHIuYWRkRGlzcG9z"
    "YWJsZURvbUxpc3RlbmVyKSh0aGlzLnRleHRhcmVhLCJjb21wb3NpdGlvbmVuZCIsKCgpPT50aGlzLl9jb21wb3NpdGlvbkhlbHBlci5jb21wb3NpdGlvbmVu"
    "ZCgpKSkpLHRoaXMucmVnaXN0ZXIoKDAsci5hZGREaXNwb3NhYmxlRG9tTGlzdGVuZXIpKHRoaXMudGV4dGFyZWEsImlucHV0IiwoZT0+dGhpcy5faW5wdXRF"
    "dmVudChlKSksITApKSx0aGlzLnJlZ2lzdGVyKHRoaXMub25SZW5kZXIoKCgpPT50aGlzLl9jb21wb3NpdGlvbkhlbHBlci51cGRhdGVDb21wb3NpdGlvbkVs"
    "ZW1lbnRzKCkpKSl9b3BlbihlKXt2YXIgdDtpZighZSl0aHJvdyBuZXcgRXJyb3IoIlRlcm1pbmFsIHJlcXVpcmVzIGEgcGFyZW50IGVsZW1lbnQuIik7ZS5p"
    "c0Nvbm5lY3RlZHx8dGhpcy5fbG9nU2VydmljZS5kZWJ1ZygiVGVybWluYWwub3BlbiB3YXMgY2FsbGVkIG9uIGFuIGVsZW1lbnQgdGhhdCB3YXMgbm90IGF0"
    "dGFjaGVkIHRvIHRoZSBET00iKSx0aGlzLl9kb2N1bWVudD1lLm93bmVyRG9jdW1lbnQsdGhpcy5lbGVtZW50PXRoaXMuX2RvY3VtZW50LmNyZWF0ZUVsZW1l"
    "bnQoImRpdiIpLHRoaXMuZWxlbWVudC5kaXI9Imx0ciIsdGhpcy5lbGVtZW50LmNsYXNzTGlzdC5hZGQoInRlcm1pbmFsIiksdGhpcy5lbGVtZW50LmNsYXNz"
    "TGlzdC5hZGQoInh0ZXJtIiksZS5hcHBlbmRDaGlsZCh0aGlzLmVsZW1lbnQpO2NvbnN0IGk9Ty5jcmVhdGVEb2N1bWVudEZyYWdtZW50KCk7dGhpcy5fdmll"
    "d3BvcnRFbGVtZW50PU8uY3JlYXRlRWxlbWVudCgiZGl2IiksdGhpcy5fdmlld3BvcnRFbGVtZW50LmNsYXNzTGlzdC5hZGQoInh0ZXJtLXZpZXdwb3J0Iiks"
    "aS5hcHBlbmRDaGlsZCh0aGlzLl92aWV3cG9ydEVsZW1lbnQpLHRoaXMuX3ZpZXdwb3J0U2Nyb2xsQXJlYT1PLmNyZWF0ZUVsZW1lbnQoImRpdiIpLHRoaXMu"
    "X3ZpZXdwb3J0U2Nyb2xsQXJlYS5jbGFzc0xpc3QuYWRkKCJ4dGVybS1zY3JvbGwtYXJlYSIpLHRoaXMuX3ZpZXdwb3J0RWxlbWVudC5hcHBlbmRDaGlsZCh0"
    "aGlzLl92aWV3cG9ydFNjcm9sbEFyZWEpLHRoaXMuc2NyZWVuRWxlbWVudD1PLmNyZWF0ZUVsZW1lbnQoImRpdiIpLHRoaXMuc2NyZWVuRWxlbWVudC5jbGFz"
    "c0xpc3QuYWRkKCJ4dGVybS1zY3JlZW4iKSx0aGlzLl9oZWxwZXJDb250YWluZXI9Ty5jcmVhdGVFbGVtZW50KCJkaXYiKSx0aGlzLl9oZWxwZXJDb250YWlu"
    "ZXIuY2xhc3NMaXN0LmFkZCgieHRlcm0taGVscGVycyIpLHRoaXMuc2NyZWVuRWxlbWVudC5hcHBlbmRDaGlsZCh0aGlzLl9oZWxwZXJDb250YWluZXIpLGku"
    "YXBwZW5kQ2hpbGQodGhpcy5zY3JlZW5FbGVtZW50KSx0aGlzLnRleHRhcmVhPU8uY3JlYXRlRWxlbWVudCgidGV4dGFyZWEiKSx0aGlzLnRleHRhcmVhLmNs"
    "YXNzTGlzdC5hZGQoInh0ZXJtLWhlbHBlci10ZXh0YXJlYSIpLHRoaXMudGV4dGFyZWEuc2V0QXR0cmlidXRlKCJhcmlhLWxhYmVsIixvLnByb21wdExhYmVs"
    "KSxrLmlzQ2hyb21lT1N8fHRoaXMudGV4dGFyZWEuc2V0QXR0cmlidXRlKCJhcmlhLW11bHRpbGluZSIsImZhbHNlIiksdGhpcy50ZXh0YXJlYS5zZXRBdHRy"
    "aWJ1dGUoImF1dG9jb3JyZWN0Iiwib2ZmIiksdGhpcy50ZXh0YXJlYS5zZXRBdHRyaWJ1dGUoImF1dG9jYXBpdGFsaXplIiwib2ZmIiksdGhpcy50ZXh0YXJl"
    "YS5zZXRBdHRyaWJ1dGUoInNwZWxsY2hlY2siLCJmYWxzZSIpLHRoaXMudGV4dGFyZWEudGFiSW5kZXg9MCx0aGlzLl9jb3JlQnJvd3NlclNlcnZpY2U9dGhp"
    "cy5faW5zdGFudGlhdGlvblNlcnZpY2UuY3JlYXRlSW5zdGFuY2Uodi5Db3JlQnJvd3NlclNlcnZpY2UsdGhpcy50ZXh0YXJlYSxudWxsIT09KHQ9dGhpcy5f"
    "ZG9jdW1lbnQuZGVmYXVsdFZpZXcpJiZ2b2lkIDAhPT10P3Q6d2luZG93KSx0aGlzLl9pbnN0YW50aWF0aW9uU2VydmljZS5zZXRTZXJ2aWNlKFMuSUNvcmVC"
    "cm93c2VyU2VydmljZSx0aGlzLl9jb3JlQnJvd3NlclNlcnZpY2UpLHRoaXMucmVnaXN0ZXIoKDAsci5hZGREaXNwb3NhYmxlRG9tTGlzdGVuZXIpKHRoaXMu"
    "dGV4dGFyZWEsImZvY3VzIiwoZT0+dGhpcy5faGFuZGxlVGV4dEFyZWFGb2N1cyhlKSkpKSx0aGlzLnJlZ2lzdGVyKCgwLHIuYWRkRGlzcG9zYWJsZURvbUxp"
    "c3RlbmVyKSh0aGlzLnRleHRhcmVhLCJibHVyIiwoKCk9PnRoaXMuX2hhbmRsZVRleHRBcmVhQmx1cigpKSkpLHRoaXMuX2hlbHBlckNvbnRhaW5lci5hcHBl"
    "bmRDaGlsZCh0aGlzLnRleHRhcmVhKSx0aGlzLl9jaGFyU2l6ZVNlcnZpY2U9dGhpcy5faW5zdGFudGlhdGlvblNlcnZpY2UuY3JlYXRlSW5zdGFuY2UodS5D"
    "aGFyU2l6ZVNlcnZpY2UsdGhpcy5fZG9jdW1lbnQsdGhpcy5faGVscGVyQ29udGFpbmVyKSx0aGlzLl9pbnN0YW50aWF0aW9uU2VydmljZS5zZXRTZXJ2aWNl"
    "KFMuSUNoYXJTaXplU2VydmljZSx0aGlzLl9jaGFyU2l6ZVNlcnZpY2UpLHRoaXMuX3RoZW1lU2VydmljZT10aGlzLl9pbnN0YW50aWF0aW9uU2VydmljZS5j"
    "cmVhdGVJbnN0YW5jZShDLlRoZW1lU2VydmljZSksdGhpcy5faW5zdGFudGlhdGlvblNlcnZpY2Uuc2V0U2VydmljZShTLklUaGVtZVNlcnZpY2UsdGhpcy5f"
    "dGhlbWVTZXJ2aWNlKSx0aGlzLl9jaGFyYWN0ZXJKb2luZXJTZXJ2aWNlPXRoaXMuX2luc3RhbnRpYXRpb25TZXJ2aWNlLmNyZWF0ZUluc3RhbmNlKGYuQ2hh"
    "cmFjdGVySm9pbmVyU2VydmljZSksdGhpcy5faW5zdGFudGlhdGlvblNlcnZpY2Uuc2V0U2VydmljZShTLklDaGFyYWN0ZXJKb2luZXJTZXJ2aWNlLHRoaXMu"
    "X2NoYXJhY3RlckpvaW5lclNlcnZpY2UpLHRoaXMuX3JlbmRlclNlcnZpY2U9dGhpcy5yZWdpc3Rlcih0aGlzLl9pbnN0YW50aWF0aW9uU2VydmljZS5jcmVh"
    "dGVJbnN0YW5jZShnLlJlbmRlclNlcnZpY2UsdGhpcy5yb3dzLHRoaXMuc2NyZWVuRWxlbWVudCkpLHRoaXMuX2luc3RhbnRpYXRpb25TZXJ2aWNlLnNldFNl"
    "cnZpY2UoUy5JUmVuZGVyU2VydmljZSx0aGlzLl9yZW5kZXJTZXJ2aWNlKSx0aGlzLnJlZ2lzdGVyKHRoaXMuX3JlbmRlclNlcnZpY2Uub25SZW5kZXJlZFZp"
    "ZXdwb3J0Q2hhbmdlKChlPT50aGlzLl9vblJlbmRlci5maXJlKGUpKSkpLHRoaXMub25SZXNpemUoKGU9PnRoaXMuX3JlbmRlclNlcnZpY2UucmVzaXplKGUu"
    "Y29scyxlLnJvd3MpKSksdGhpcy5fY29tcG9zaXRpb25WaWV3PU8uY3JlYXRlRWxlbWVudCgiZGl2IiksdGhpcy5fY29tcG9zaXRpb25WaWV3LmNsYXNzTGlz"
    "dC5hZGQoImNvbXBvc2l0aW9uLXZpZXciKSx0aGlzLl9jb21wb3NpdGlvbkhlbHBlcj10aGlzLl9pbnN0YW50aWF0aW9uU2VydmljZS5jcmVhdGVJbnN0YW5j"
    "ZShkLkNvbXBvc2l0aW9uSGVscGVyLHRoaXMudGV4dGFyZWEsdGhpcy5fY29tcG9zaXRpb25WaWV3KSx0aGlzLl9oZWxwZXJDb250YWluZXIuYXBwZW5kQ2hp"
    "bGQodGhpcy5fY29tcG9zaXRpb25WaWV3KSx0aGlzLmVsZW1lbnQuYXBwZW5kQ2hpbGQoaSk7dHJ5e3RoaXMuX29uV2lsbE9wZW4uZmlyZSh0aGlzLmVsZW1l"
    "bnQpfWNhdGNoKGUpe310aGlzLl9yZW5kZXJTZXJ2aWNlLmhhc1JlbmRlcmVyKCl8fHRoaXMuX3JlbmRlclNlcnZpY2Uuc2V0UmVuZGVyZXIodGhpcy5fY3Jl"
    "YXRlUmVuZGVyZXIoKSksdGhpcy5fbW91c2VTZXJ2aWNlPXRoaXMuX2luc3RhbnRpYXRpb25TZXJ2aWNlLmNyZWF0ZUluc3RhbmNlKHAuTW91c2VTZXJ2aWNl"
    "KSx0aGlzLl9pbnN0YW50aWF0aW9uU2VydmljZS5zZXRTZXJ2aWNlKFMuSU1vdXNlU2VydmljZSx0aGlzLl9tb3VzZVNlcnZpY2UpLHRoaXMudmlld3BvcnQ9"
    "dGhpcy5faW5zdGFudGlhdGlvblNlcnZpY2UuY3JlYXRlSW5zdGFuY2UoaC5WaWV3cG9ydCx0aGlzLl92aWV3cG9ydEVsZW1lbnQsdGhpcy5fdmlld3BvcnRT"
    "Y3JvbGxBcmVhKSx0aGlzLnZpZXdwb3J0Lm9uUmVxdWVzdFNjcm9sbExpbmVzKChlPT50aGlzLnNjcm9sbExpbmVzKGUuYW1vdW50LGUuc3VwcHJlc3NTY3Jv"
    "bGxFdmVudCwxKSkpLHRoaXMucmVnaXN0ZXIodGhpcy5faW5wdXRIYW5kbGVyLm9uUmVxdWVzdFN5bmNTY3JvbGxCYXIoKCgpPT50aGlzLnZpZXdwb3J0LnN5"
    "bmNTY3JvbGxBcmVhKCkpKSksdGhpcy5yZWdpc3Rlcih0aGlzLnZpZXdwb3J0KSx0aGlzLnJlZ2lzdGVyKHRoaXMub25DdXJzb3JNb3ZlKCgoKT0+e3RoaXMu"
    "X3JlbmRlclNlcnZpY2UuaGFuZGxlQ3Vyc29yTW92ZSgpLHRoaXMuX3N5bmNUZXh0QXJlYSgpfSkpKSx0aGlzLnJlZ2lzdGVyKHRoaXMub25SZXNpemUoKCgp"
    "PT50aGlzLl9yZW5kZXJTZXJ2aWNlLmhhbmRsZVJlc2l6ZSh0aGlzLmNvbHMsdGhpcy5yb3dzKSkpKSx0aGlzLnJlZ2lzdGVyKHRoaXMub25CbHVyKCgoKT0+"
    "dGhpcy5fcmVuZGVyU2VydmljZS5oYW5kbGVCbHVyKCkpKSksdGhpcy5yZWdpc3Rlcih0aGlzLm9uRm9jdXMoKCgpPT50aGlzLl9yZW5kZXJTZXJ2aWNlLmhh"
    "bmRsZUZvY3VzKCkpKSksdGhpcy5yZWdpc3Rlcih0aGlzLl9yZW5kZXJTZXJ2aWNlLm9uRGltZW5zaW9uc0NoYW5nZSgoKCk9PnRoaXMudmlld3BvcnQuc3lu"
    "Y1Njcm9sbEFyZWEoKSkpKSx0aGlzLl9zZWxlY3Rpb25TZXJ2aWNlPXRoaXMucmVnaXN0ZXIodGhpcy5faW5zdGFudGlhdGlvblNlcnZpY2UuY3JlYXRlSW5z"
    "dGFuY2UobS5TZWxlY3Rpb25TZXJ2aWNlLHRoaXMuZWxlbWVudCx0aGlzLnNjcmVlbkVsZW1lbnQsdGhpcy5saW5raWZpZXIyKSksdGhpcy5faW5zdGFudGlh"
    "dGlvblNlcnZpY2Uuc2V0U2VydmljZShTLklTZWxlY3Rpb25TZXJ2aWNlLHRoaXMuX3NlbGVjdGlvblNlcnZpY2UpLHRoaXMucmVnaXN0ZXIodGhpcy5fc2Vs"
    "ZWN0aW9uU2VydmljZS5vblJlcXVlc3RTY3JvbGxMaW5lcygoZT0+dGhpcy5zY3JvbGxMaW5lcyhlLmFtb3VudCxlLnN1cHByZXNzU2Nyb2xsRXZlbnQpKSkp"
    "LHRoaXMucmVnaXN0ZXIodGhpcy5fc2VsZWN0aW9uU2VydmljZS5vblNlbGVjdGlvbkNoYW5nZSgoKCk9PnRoaXMuX29uU2VsZWN0aW9uQ2hhbmdlLmZpcmUo"
    "KSkpKSx0aGlzLnJlZ2lzdGVyKHRoaXMuX3NlbGVjdGlvblNlcnZpY2Uub25SZXF1ZXN0UmVkcmF3KChlPT50aGlzLl9yZW5kZXJTZXJ2aWNlLmhhbmRsZVNl"
    "bGVjdGlvbkNoYW5nZWQoZS5zdGFydCxlLmVuZCxlLmNvbHVtblNlbGVjdE1vZGUpKSkpLHRoaXMucmVnaXN0ZXIodGhpcy5fc2VsZWN0aW9uU2VydmljZS5v"
    "bkxpbnV4TW91c2VTZWxlY3Rpb24oKGU9Pnt0aGlzLnRleHRhcmVhLnZhbHVlPWUsdGhpcy50ZXh0YXJlYS5mb2N1cygpLHRoaXMudGV4dGFyZWEuc2VsZWN0"
    "KCl9KSkpLHRoaXMucmVnaXN0ZXIodGhpcy5fb25TY3JvbGwuZXZlbnQoKGU9Pnt0aGlzLnZpZXdwb3J0LnN5bmNTY3JvbGxBcmVhKCksdGhpcy5fc2VsZWN0"
    "aW9uU2VydmljZS5yZWZyZXNoKCl9KSkpLHRoaXMucmVnaXN0ZXIoKDAsci5hZGREaXNwb3NhYmxlRG9tTGlzdGVuZXIpKHRoaXMuX3ZpZXdwb3J0RWxlbWVu"
    "dCwic2Nyb2xsIiwoKCk9PnRoaXMuX3NlbGVjdGlvblNlcnZpY2UucmVmcmVzaCgpKSkpLHRoaXMubGlua2lmaWVyMi5hdHRhY2hUb0RvbSh0aGlzLnNjcmVl"
    "bkVsZW1lbnQsdGhpcy5fbW91c2VTZXJ2aWNlLHRoaXMuX3JlbmRlclNlcnZpY2UpLHRoaXMucmVnaXN0ZXIodGhpcy5faW5zdGFudGlhdGlvblNlcnZpY2Uu"
    "Y3JlYXRlSW5zdGFuY2UoYy5CdWZmZXJEZWNvcmF0aW9uUmVuZGVyZXIsdGhpcy5zY3JlZW5FbGVtZW50KSksdGhpcy5yZWdpc3RlcigoMCxyLmFkZERpc3Bv"
    "c2FibGVEb21MaXN0ZW5lcikodGhpcy5lbGVtZW50LCJtb3VzZWRvd24iLChlPT50aGlzLl9zZWxlY3Rpb25TZXJ2aWNlLmhhbmRsZU1vdXNlRG93bihlKSkp"
    "KSx0aGlzLmNvcmVNb3VzZVNlcnZpY2UuYXJlTW91c2VFdmVudHNBY3RpdmU/KHRoaXMuX3NlbGVjdGlvblNlcnZpY2UuZGlzYWJsZSgpLHRoaXMuZWxlbWVu"
    "dC5jbGFzc0xpc3QuYWRkKCJlbmFibGUtbW91c2UtZXZlbnRzIikpOnRoaXMuX3NlbGVjdGlvblNlcnZpY2UuZW5hYmxlKCksdGhpcy5vcHRpb25zLnNjcmVl"
    "blJlYWRlck1vZGUmJih0aGlzLl9hY2Nlc3NpYmlsaXR5TWFuYWdlci52YWx1ZT10aGlzLl9pbnN0YW50aWF0aW9uU2VydmljZS5jcmVhdGVJbnN0YW5jZShN"
    "LkFjY2Vzc2liaWxpdHlNYW5hZ2VyLHRoaXMpKSx0aGlzLnJlZ2lzdGVyKHRoaXMub3B0aW9uc1NlcnZpY2Uub25TcGVjaWZpY09wdGlvbkNoYW5nZSgic2Ny"
    "ZWVuUmVhZGVyTW9kZSIsKGU9PnRoaXMuX2hhbmRsZVNjcmVlblJlYWRlck1vZGVPcHRpb25DaGFuZ2UoZSkpKSksdGhpcy5vcHRpb25zLm92ZXJ2aWV3UnVs"
    "ZXJXaWR0aCYmKHRoaXMuX292ZXJ2aWV3UnVsZXJSZW5kZXJlcj10aGlzLnJlZ2lzdGVyKHRoaXMuX2luc3RhbnRpYXRpb25TZXJ2aWNlLmNyZWF0ZUluc3Rh"
    "bmNlKGwuT3ZlcnZpZXdSdWxlclJlbmRlcmVyLHRoaXMuX3ZpZXdwb3J0RWxlbWVudCx0aGlzLnNjcmVlbkVsZW1lbnQpKSksdGhpcy5vcHRpb25zU2Vydmlj"
    "ZS5vblNwZWNpZmljT3B0aW9uQ2hhbmdlKCJvdmVydmlld1J1bGVyV2lkdGgiLChlPT57IXRoaXMuX292ZXJ2aWV3UnVsZXJSZW5kZXJlciYmZSYmdGhpcy5f"
    "dmlld3BvcnRFbGVtZW50JiZ0aGlzLnNjcmVlbkVsZW1lbnQmJih0aGlzLl9vdmVydmlld1J1bGVyUmVuZGVyZXI9dGhpcy5yZWdpc3Rlcih0aGlzLl9pbnN0"
    "YW50aWF0aW9uU2VydmljZS5jcmVhdGVJbnN0YW5jZShsLk92ZXJ2aWV3UnVsZXJSZW5kZXJlcix0aGlzLl92aWV3cG9ydEVsZW1lbnQsdGhpcy5zY3JlZW5F"
    "bGVtZW50KSkpfSkpLHRoaXMuX2NoYXJTaXplU2VydmljZS5tZWFzdXJlKCksdGhpcy5yZWZyZXNoKDAsdGhpcy5yb3dzLTEpLHRoaXMuX2luaXRHbG9iYWwo"
    "KSx0aGlzLmJpbmRNb3VzZSgpfV9jcmVhdGVSZW5kZXJlcigpe3JldHVybiB0aGlzLl9pbnN0YW50aWF0aW9uU2VydmljZS5jcmVhdGVJbnN0YW5jZShfLkRv"
    "bVJlbmRlcmVyLHRoaXMuZWxlbWVudCx0aGlzLnNjcmVlbkVsZW1lbnQsdGhpcy5fdmlld3BvcnRFbGVtZW50LHRoaXMubGlua2lmaWVyMil9YmluZE1vdXNl"
    "KCl7Y29uc3QgZT10aGlzLHQ9dGhpcy5lbGVtZW50O2Z1bmN0aW9uIGkodCl7Y29uc3QgaT1lLl9tb3VzZVNlcnZpY2UuZ2V0TW91c2VSZXBvcnRDb29yZHMo"
    "dCxlLnNjcmVlbkVsZW1lbnQpO2lmKCFpKXJldHVybiExO2xldCBzLHI7c3dpdGNoKHQub3ZlcnJpZGVUeXBlfHx0LnR5cGUpe2Nhc2UibW91c2Vtb3ZlIjpy"
    "PTMyLHZvaWQgMD09PXQuYnV0dG9ucz8ocz0zLHZvaWQgMCE9PXQuYnV0dG9uJiYocz10LmJ1dHRvbjwzP3QuYnV0dG9uOjMpKTpzPTEmdC5idXR0b25zPzA6"
    "NCZ0LmJ1dHRvbnM/MToyJnQuYnV0dG9ucz8yOjM7YnJlYWs7Y2FzZSJtb3VzZXVwIjpyPTAscz10LmJ1dHRvbjwzP3QuYnV0dG9uOjM7YnJlYWs7Y2FzZSJt"
    "b3VzZWRvd24iOnI9MSxzPXQuYnV0dG9uPDM/dC5idXR0b246MzticmVhaztjYXNlIndoZWVsIjppZigwPT09ZS52aWV3cG9ydC5nZXRMaW5lc1Njcm9sbGVk"
    "KHQpKXJldHVybiExO3I9dC5kZWx0YVk8MD8wOjEscz00O2JyZWFrO2RlZmF1bHQ6cmV0dXJuITF9cmV0dXJuISh2b2lkIDA9PT1yfHx2b2lkIDA9PT1zfHxz"
    "PjQpJiZlLmNvcmVNb3VzZVNlcnZpY2UudHJpZ2dlck1vdXNlRXZlbnQoe2NvbDppLmNvbCxyb3c6aS5yb3cseDppLngseTppLnksYnV0dG9uOnMsYWN0aW9u"
    "OnIsY3RybDp0LmN0cmxLZXksYWx0OnQuYWx0S2V5LHNoaWZ0OnQuc2hpZnRLZXl9KX1jb25zdCBzPXttb3VzZXVwOm51bGwsd2hlZWw6bnVsbCxtb3VzZWRy"
    "YWc6bnVsbCxtb3VzZW1vdmU6bnVsbH0sbj17bW91c2V1cDplPT4oaShlKSxlLmJ1dHRvbnN8fCh0aGlzLl9kb2N1bWVudC5yZW1vdmVFdmVudExpc3RlbmVy"
    "KCJtb3VzZXVwIixzLm1vdXNldXApLHMubW91c2VkcmFnJiZ0aGlzLl9kb2N1bWVudC5yZW1vdmVFdmVudExpc3RlbmVyKCJtb3VzZW1vdmUiLHMubW91c2Vk"
    "cmFnKSksdGhpcy5jYW5jZWwoZSkpLHdoZWVsOmU9PihpKGUpLHRoaXMuY2FuY2VsKGUsITApKSxtb3VzZWRyYWc6ZT0+e2UuYnV0dG9ucyYmaShlKX0sbW91"
    "c2Vtb3ZlOmU9PntlLmJ1dHRvbnN8fGkoZSl9fTt0aGlzLnJlZ2lzdGVyKHRoaXMuY29yZU1vdXNlU2VydmljZS5vblByb3RvY29sQ2hhbmdlKChlPT57ZT8o"
    "ImRlYnVnIj09PXRoaXMub3B0aW9uc1NlcnZpY2UucmF3T3B0aW9ucy5sb2dMZXZlbCYmdGhpcy5fbG9nU2VydmljZS5kZWJ1ZygiQmluZGluZyB0byBtb3Vz"
    "ZSBldmVudHM6Iix0aGlzLmNvcmVNb3VzZVNlcnZpY2UuZXhwbGFpbkV2ZW50cyhlKSksdGhpcy5lbGVtZW50LmNsYXNzTGlzdC5hZGQoImVuYWJsZS1tb3Vz"
    "ZS1ldmVudHMiKSx0aGlzLl9zZWxlY3Rpb25TZXJ2aWNlLmRpc2FibGUoKSk6KHRoaXMuX2xvZ1NlcnZpY2UuZGVidWcoIlVuYmluZGluZyBmcm9tIG1vdXNl"
    "IGV2ZW50cy4iKSx0aGlzLmVsZW1lbnQuY2xhc3NMaXN0LnJlbW92ZSgiZW5hYmxlLW1vdXNlLWV2ZW50cyIpLHRoaXMuX3NlbGVjdGlvblNlcnZpY2UuZW5h"
    "YmxlKCkpLDgmZT9zLm1vdXNlbW92ZXx8KHQuYWRkRXZlbnRMaXN0ZW5lcigibW91c2Vtb3ZlIixuLm1vdXNlbW92ZSkscy5tb3VzZW1vdmU9bi5tb3VzZW1v"
    "dmUpOih0LnJlbW92ZUV2ZW50TGlzdGVuZXIoIm1vdXNlbW92ZSIscy5tb3VzZW1vdmUpLHMubW91c2Vtb3ZlPW51bGwpLDE2JmU/cy53aGVlbHx8KHQuYWRk"
    "RXZlbnRMaXN0ZW5lcigid2hlZWwiLG4ud2hlZWwse3Bhc3NpdmU6ITF9KSxzLndoZWVsPW4ud2hlZWwpOih0LnJlbW92ZUV2ZW50TGlzdGVuZXIoIndoZWVs"
    "IixzLndoZWVsKSxzLndoZWVsPW51bGwpLDImZT9zLm1vdXNldXB8fCh0LmFkZEV2ZW50TGlzdGVuZXIoIm1vdXNldXAiLG4ubW91c2V1cCkscy5tb3VzZXVw"
    "PW4ubW91c2V1cCk6KHRoaXMuX2RvY3VtZW50LnJlbW92ZUV2ZW50TGlzdGVuZXIoIm1vdXNldXAiLHMubW91c2V1cCksdC5yZW1vdmVFdmVudExpc3RlbmVy"
    "KCJtb3VzZXVwIixzLm1vdXNldXApLHMubW91c2V1cD1udWxsKSw0JmU/cy5tb3VzZWRyYWd8fChzLm1vdXNlZHJhZz1uLm1vdXNlZHJhZyk6KHRoaXMuX2Rv"
    "Y3VtZW50LnJlbW92ZUV2ZW50TGlzdGVuZXIoIm1vdXNlbW92ZSIscy5tb3VzZWRyYWcpLHMubW91c2VkcmFnPW51bGwpfSkpKSx0aGlzLmNvcmVNb3VzZVNl"
    "cnZpY2UuYWN0aXZlUHJvdG9jb2w9dGhpcy5jb3JlTW91c2VTZXJ2aWNlLmFjdGl2ZVByb3RvY29sLHRoaXMucmVnaXN0ZXIoKDAsci5hZGREaXNwb3NhYmxl"
    "RG9tTGlzdGVuZXIpKHQsIm1vdXNlZG93biIsKGU9PntpZihlLnByZXZlbnREZWZhdWx0KCksdGhpcy5mb2N1cygpLHRoaXMuY29yZU1vdXNlU2VydmljZS5h"
    "cmVNb3VzZUV2ZW50c0FjdGl2ZSYmIXRoaXMuX3NlbGVjdGlvblNlcnZpY2Uuc2hvdWxkRm9yY2VTZWxlY3Rpb24oZSkpcmV0dXJuIGkoZSkscy5tb3VzZXVw"
    "JiZ0aGlzLl9kb2N1bWVudC5hZGRFdmVudExpc3RlbmVyKCJtb3VzZXVwIixzLm1vdXNldXApLHMubW91c2VkcmFnJiZ0aGlzLl9kb2N1bWVudC5hZGRFdmVu"
    "dExpc3RlbmVyKCJtb3VzZW1vdmUiLHMubW91c2VkcmFnKSx0aGlzLmNhbmNlbChlKX0pKSksdGhpcy5yZWdpc3RlcigoMCxyLmFkZERpc3Bvc2FibGVEb21M"
    "aXN0ZW5lcikodCwid2hlZWwiLChlPT57aWYoIXMud2hlZWwpe2lmKCF0aGlzLmJ1ZmZlci5oYXNTY3JvbGxiYWNrKXtjb25zdCB0PXRoaXMudmlld3BvcnQu"
    "Z2V0TGluZXNTY3JvbGxlZChlKTtpZigwPT09dClyZXR1cm47Y29uc3QgaT1ELkMwLkVTQysodGhpcy5jb3JlU2VydmljZS5kZWNQcml2YXRlTW9kZXMuYXBw"
    "bGljYXRpb25DdXJzb3JLZXlzPyJPIjoiWyIpKyhlLmRlbHRhWTwwPyJBIjoiQiIpO2xldCBzPSIiO2ZvcihsZXQgZT0wO2U8TWF0aC5hYnModCk7ZSsrKXMr"
    "PWk7cmV0dXJuIHRoaXMuY29yZVNlcnZpY2UudHJpZ2dlckRhdGFFdmVudChzLCEwKSx0aGlzLmNhbmNlbChlLCEwKX1yZXR1cm4gdGhpcy52aWV3cG9ydC5o"
    "YW5kbGVXaGVlbChlKT90aGlzLmNhbmNlbChlKTp2b2lkIDB9fSkse3Bhc3NpdmU6ITF9KSksdGhpcy5yZWdpc3RlcigoMCxyLmFkZERpc3Bvc2FibGVEb21M"
    "aXN0ZW5lcikodCwidG91Y2hzdGFydCIsKGU9PntpZighdGhpcy5jb3JlTW91c2VTZXJ2aWNlLmFyZU1vdXNlRXZlbnRzQWN0aXZlKXJldHVybiB0aGlzLnZp"
    "ZXdwb3J0LmhhbmRsZVRvdWNoU3RhcnQoZSksdGhpcy5jYW5jZWwoZSl9KSx7cGFzc2l2ZTohMH0pKSx0aGlzLnJlZ2lzdGVyKCgwLHIuYWRkRGlzcG9zYWJs"
    "ZURvbUxpc3RlbmVyKSh0LCJ0b3VjaG1vdmUiLChlPT57aWYoIXRoaXMuY29yZU1vdXNlU2VydmljZS5hcmVNb3VzZUV2ZW50c0FjdGl2ZSlyZXR1cm4gdGhp"
    "cy52aWV3cG9ydC5oYW5kbGVUb3VjaE1vdmUoZSk/dm9pZCAwOnRoaXMuY2FuY2VsKGUpfSkse3Bhc3NpdmU6ITF9KSl9cmVmcmVzaChlLHQpe3ZhciBpO251"
    "bGw9PT0oaT10aGlzLl9yZW5kZXJTZXJ2aWNlKXx8dm9pZCAwPT09aXx8aS5yZWZyZXNoUm93cyhlLHQpfXVwZGF0ZUN1cnNvclN0eWxlKGUpe3ZhciB0Oyhu"
    "dWxsPT09KHQ9dGhpcy5fc2VsZWN0aW9uU2VydmljZSl8fHZvaWQgMD09PXQ/dm9pZCAwOnQuc2hvdWxkQ29sdW1uU2VsZWN0KGUpKT90aGlzLmVsZW1lbnQu"
    "Y2xhc3NMaXN0LmFkZCgiY29sdW1uLXNlbGVjdCIpOnRoaXMuZWxlbWVudC5jbGFzc0xpc3QucmVtb3ZlKCJjb2x1bW4tc2VsZWN0Iil9X3Nob3dDdXJzb3Io"
    "KXt0aGlzLmNvcmVTZXJ2aWNlLmlzQ3Vyc29ySW5pdGlhbGl6ZWR8fCh0aGlzLmNvcmVTZXJ2aWNlLmlzQ3Vyc29ySW5pdGlhbGl6ZWQ9ITAsdGhpcy5yZWZy"
    "ZXNoKHRoaXMuYnVmZmVyLnksdGhpcy5idWZmZXIueSkpfXNjcm9sbExpbmVzKGUsdCxpPTApe3ZhciBzOzE9PT1pPyhzdXBlci5zY3JvbGxMaW5lcyhlLHQs"
    "aSksdGhpcy5yZWZyZXNoKDAsdGhpcy5yb3dzLTEpKTpudWxsPT09KHM9dGhpcy52aWV3cG9ydCl8fHZvaWQgMD09PXN8fHMuc2Nyb2xsTGluZXMoZSl9cGFz"
    "dGUoZSl7KDAscy5wYXN0ZSkoZSx0aGlzLnRleHRhcmVhLHRoaXMuY29yZVNlcnZpY2UsdGhpcy5vcHRpb25zU2VydmljZSl9YXR0YWNoQ3VzdG9tS2V5RXZl"
    "bnRIYW5kbGVyKGUpe3RoaXMuX2N1c3RvbUtleUV2ZW50SGFuZGxlcj1lfXJlZ2lzdGVyTGlua1Byb3ZpZGVyKGUpe3JldHVybiB0aGlzLmxpbmtpZmllcjIu"
    "cmVnaXN0ZXJMaW5rUHJvdmlkZXIoZSl9cmVnaXN0ZXJDaGFyYWN0ZXJKb2luZXIoZSl7aWYoIXRoaXMuX2NoYXJhY3RlckpvaW5lclNlcnZpY2UpdGhyb3cg"
    "bmV3IEVycm9yKCJUZXJtaW5hbCBtdXN0IGJlIG9wZW5lZCBmaXJzdCIpO2NvbnN0IHQ9dGhpcy5fY2hhcmFjdGVySm9pbmVyU2VydmljZS5yZWdpc3Rlcihl"
    "KTtyZXR1cm4gdGhpcy5yZWZyZXNoKDAsdGhpcy5yb3dzLTEpLHR9ZGVyZWdpc3RlckNoYXJhY3RlckpvaW5lcihlKXtpZighdGhpcy5fY2hhcmFjdGVySm9p"
    "bmVyU2VydmljZSl0aHJvdyBuZXcgRXJyb3IoIlRlcm1pbmFsIG11c3QgYmUgb3BlbmVkIGZpcnN0Iik7dGhpcy5fY2hhcmFjdGVySm9pbmVyU2VydmljZS5k"
    "ZXJlZ2lzdGVyKGUpJiZ0aGlzLnJlZnJlc2goMCx0aGlzLnJvd3MtMSl9Z2V0IG1hcmtlcnMoKXtyZXR1cm4gdGhpcy5idWZmZXIubWFya2Vyc31yZWdpc3Rl"
    "ck1hcmtlcihlKXtyZXR1cm4gdGhpcy5idWZmZXIuYWRkTWFya2VyKHRoaXMuYnVmZmVyLnliYXNlK3RoaXMuYnVmZmVyLnkrZSl9cmVnaXN0ZXJEZWNvcmF0"
    "aW9uKGUpe3JldHVybiB0aGlzLl9kZWNvcmF0aW9uU2VydmljZS5yZWdpc3RlckRlY29yYXRpb24oZSl9aGFzU2VsZWN0aW9uKCl7cmV0dXJuISF0aGlzLl9z"
    "ZWxlY3Rpb25TZXJ2aWNlJiZ0aGlzLl9zZWxlY3Rpb25TZXJ2aWNlLmhhc1NlbGVjdGlvbn1zZWxlY3QoZSx0LGkpe3RoaXMuX3NlbGVjdGlvblNlcnZpY2Uu"
    "c2V0U2VsZWN0aW9uKGUsdCxpKX1nZXRTZWxlY3Rpb24oKXtyZXR1cm4gdGhpcy5fc2VsZWN0aW9uU2VydmljZT90aGlzLl9zZWxlY3Rpb25TZXJ2aWNlLnNl"
    "bGVjdGlvblRleHQ6IiJ9Z2V0U2VsZWN0aW9uUG9zaXRpb24oKXtpZih0aGlzLl9zZWxlY3Rpb25TZXJ2aWNlJiZ0aGlzLl9zZWxlY3Rpb25TZXJ2aWNlLmhh"
    "c1NlbGVjdGlvbilyZXR1cm57c3RhcnQ6e3g6dGhpcy5fc2VsZWN0aW9uU2VydmljZS5zZWxlY3Rpb25TdGFydFswXSx5OnRoaXMuX3NlbGVjdGlvblNlcnZp"
    "Y2Uuc2VsZWN0aW9uU3RhcnRbMV19LGVuZDp7eDp0aGlzLl9zZWxlY3Rpb25TZXJ2aWNlLnNlbGVjdGlvbkVuZFswXSx5OnRoaXMuX3NlbGVjdGlvblNlcnZp"
    "Y2Uuc2VsZWN0aW9uRW5kWzFdfX19Y2xlYXJTZWxlY3Rpb24oKXt2YXIgZTtudWxsPT09KGU9dGhpcy5fc2VsZWN0aW9uU2VydmljZSl8fHZvaWQgMD09PWV8"
    "fGUuY2xlYXJTZWxlY3Rpb24oKX1zZWxlY3RBbGwoKXt2YXIgZTtudWxsPT09KGU9dGhpcy5fc2VsZWN0aW9uU2VydmljZSl8fHZvaWQgMD09PWV8fGUuc2Vs"
    "ZWN0QWxsKCl9c2VsZWN0TGluZXMoZSx0KXt2YXIgaTtudWxsPT09KGk9dGhpcy5fc2VsZWN0aW9uU2VydmljZSl8fHZvaWQgMD09PWl8fGkuc2VsZWN0TGlu"
    "ZXMoZSx0KX1fa2V5RG93bihlKXtpZih0aGlzLl9rZXlEb3duSGFuZGxlZD0hMSx0aGlzLl9rZXlEb3duU2Vlbj0hMCx0aGlzLl9jdXN0b21LZXlFdmVudEhh"
    "bmRsZXImJiExPT09dGhpcy5fY3VzdG9tS2V5RXZlbnRIYW5kbGVyKGUpKXJldHVybiExO2NvbnN0IHQ9dGhpcy5icm93c2VyLmlzTWFjJiZ0aGlzLm9wdGlv"
    "bnMubWFjT3B0aW9uSXNNZXRhJiZlLmFsdEtleTtpZighdCYmIXRoaXMuX2NvbXBvc2l0aW9uSGVscGVyLmtleWRvd24oZSkpcmV0dXJuIHRoaXMub3B0aW9u"
    "cy5zY3JvbGxPblVzZXJJbnB1dCYmdGhpcy5idWZmZXIueWJhc2UhPT10aGlzLmJ1ZmZlci55ZGlzcCYmdGhpcy5zY3JvbGxUb0JvdHRvbSgpLCExO3R8fCJE"
    "ZWFkIiE9PWUua2V5JiYiQWx0R3JhcGgiIT09ZS5rZXl8fCh0aGlzLl91bnByb2Nlc3NlZERlYWRLZXk9ITApO2NvbnN0IGk9KDAsUi5ldmFsdWF0ZUtleWJv"
    "YXJkRXZlbnQpKGUsdGhpcy5jb3JlU2VydmljZS5kZWNQcml2YXRlTW9kZXMuYXBwbGljYXRpb25DdXJzb3JLZXlzLHRoaXMuYnJvd3Nlci5pc01hYyx0aGlz"
    "Lm9wdGlvbnMubWFjT3B0aW9uSXNNZXRhKTtpZih0aGlzLnVwZGF0ZUN1cnNvclN0eWxlKGUpLDM9PT1pLnR5cGV8fDI9PT1pLnR5cGUpe2NvbnN0IHQ9dGhp"
    "cy5yb3dzLTE7cmV0dXJuIHRoaXMuc2Nyb2xsTGluZXMoMj09PWkudHlwZT8tdDp0KSx0aGlzLmNhbmNlbChlLCEwKX1yZXR1cm4gMT09PWkudHlwZSYmdGhp"
    "cy5zZWxlY3RBbGwoKSwhIXRoaXMuX2lzVGhpcmRMZXZlbFNoaWZ0KHRoaXMuYnJvd3NlcixlKXx8KGkuY2FuY2VsJiZ0aGlzLmNhbmNlbChlLCEwKSwhaS5r"
    "ZXl8fCEhKGUua2V5JiYhZS5jdHJsS2V5JiYhZS5hbHRLZXkmJiFlLm1ldGFLZXkmJjE9PT1lLmtleS5sZW5ndGgmJmUua2V5LmNoYXJDb2RlQXQoMCk+PTY1"
    "JiZlLmtleS5jaGFyQ29kZUF0KDApPD05MCl8fCh0aGlzLl91bnByb2Nlc3NlZERlYWRLZXk/KHRoaXMuX3VucHJvY2Vzc2VkRGVhZEtleT0hMSwhMCk6KGku"
    "a2V5IT09RC5DMC5FVFgmJmkua2V5IT09RC5DMC5DUnx8KHRoaXMudGV4dGFyZWEudmFsdWU9IiIpLHRoaXMuX29uS2V5LmZpcmUoe2tleTppLmtleSxkb21F"
    "dmVudDplfSksdGhpcy5fc2hvd0N1cnNvcigpLHRoaXMuY29yZVNlcnZpY2UudHJpZ2dlckRhdGFFdmVudChpLmtleSwhMCksIXRoaXMub3B0aW9uc1NlcnZp"
    "Y2UucmF3T3B0aW9ucy5zY3JlZW5SZWFkZXJNb2RlfHxlLmFsdEtleXx8ZS5jdHJsS2V5P3RoaXMuY2FuY2VsKGUsITApOnZvaWQodGhpcy5fa2V5RG93bkhh"
    "bmRsZWQ9ITApKSkpfV9pc1RoaXJkTGV2ZWxTaGlmdChlLHQpe2NvbnN0IGk9ZS5pc01hYyYmIXRoaXMub3B0aW9ucy5tYWNPcHRpb25Jc01ldGEmJnQuYWx0"
    "S2V5JiYhdC5jdHJsS2V5JiYhdC5tZXRhS2V5fHxlLmlzV2luZG93cyYmdC5hbHRLZXkmJnQuY3RybEtleSYmIXQubWV0YUtleXx8ZS5pc1dpbmRvd3MmJnQu"
    "Z2V0TW9kaWZpZXJTdGF0ZSgiQWx0R3JhcGgiKTtyZXR1cm4ia2V5cHJlc3MiPT09dC50eXBlP2k6aSYmKCF0LmtleUNvZGV8fHQua2V5Q29kZT40Nyl9X2tl"
    "eVVwKGUpe3RoaXMuX2tleURvd25TZWVuPSExLHRoaXMuX2N1c3RvbUtleUV2ZW50SGFuZGxlciYmITE9PT10aGlzLl9jdXN0b21LZXlFdmVudEhhbmRsZXIo"
    "ZSl8fChmdW5jdGlvbihlKXtyZXR1cm4gMTY9PT1lLmtleUNvZGV8fDE3PT09ZS5rZXlDb2RlfHwxOD09PWUua2V5Q29kZX0oZSl8fHRoaXMuZm9jdXMoKSx0"
    "aGlzLnVwZGF0ZUN1cnNvclN0eWxlKGUpLHRoaXMuX2tleVByZXNzSGFuZGxlZD0hMSl9X2tleVByZXNzKGUpe2xldCB0O2lmKHRoaXMuX2tleVByZXNzSGFu"
    "ZGxlZD0hMSx0aGlzLl9rZXlEb3duSGFuZGxlZClyZXR1cm4hMTtpZih0aGlzLl9jdXN0b21LZXlFdmVudEhhbmRsZXImJiExPT09dGhpcy5fY3VzdG9tS2V5"
    "RXZlbnRIYW5kbGVyKGUpKXJldHVybiExO2lmKHRoaXMuY2FuY2VsKGUpLGUuY2hhckNvZGUpdD1lLmNoYXJDb2RlO2Vsc2UgaWYobnVsbD09PWUud2hpY2h8"
    "fHZvaWQgMD09PWUud2hpY2gpdD1lLmtleUNvZGU7ZWxzZXtpZigwPT09ZS53aGljaHx8MD09PWUuY2hhckNvZGUpcmV0dXJuITE7dD1lLndoaWNofXJldHVy"
    "biEoIXR8fChlLmFsdEtleXx8ZS5jdHJsS2V5fHxlLm1ldGFLZXkpJiYhdGhpcy5faXNUaGlyZExldmVsU2hpZnQodGhpcy5icm93c2VyLGUpfHwodD1TdHJp"
    "bmcuZnJvbUNoYXJDb2RlKHQpLHRoaXMuX29uS2V5LmZpcmUoe2tleTp0LGRvbUV2ZW50OmV9KSx0aGlzLl9zaG93Q3Vyc29yKCksdGhpcy5jb3JlU2Vydmlj"
    "ZS50cmlnZ2VyRGF0YUV2ZW50KHQsITApLHRoaXMuX2tleVByZXNzSGFuZGxlZD0hMCx0aGlzLl91bnByb2Nlc3NlZERlYWRLZXk9ITEsMCkpfV9pbnB1dEV2"
    "ZW50KGUpe2lmKGUuZGF0YSYmImluc2VydFRleHQiPT09ZS5pbnB1dFR5cGUmJighZS5jb21wb3NlZHx8IXRoaXMuX2tleURvd25TZWVuKSYmIXRoaXMub3B0"
    "aW9uc1NlcnZpY2UucmF3T3B0aW9ucy5zY3JlZW5SZWFkZXJNb2RlKXtpZih0aGlzLl9rZXlQcmVzc0hhbmRsZWQpcmV0dXJuITE7dGhpcy5fdW5wcm9jZXNz"
    "ZWREZWFkS2V5PSExO2NvbnN0IHQ9ZS5kYXRhO3JldHVybiB0aGlzLmNvcmVTZXJ2aWNlLnRyaWdnZXJEYXRhRXZlbnQodCwhMCksdGhpcy5jYW5jZWwoZSks"
    "ITB9cmV0dXJuITF9cmVzaXplKGUsdCl7ZSE9PXRoaXMuY29sc3x8dCE9PXRoaXMucm93cz9zdXBlci5yZXNpemUoZSx0KTp0aGlzLl9jaGFyU2l6ZVNlcnZp"
    "Y2UmJiF0aGlzLl9jaGFyU2l6ZVNlcnZpY2UuaGFzVmFsaWRTaXplJiZ0aGlzLl9jaGFyU2l6ZVNlcnZpY2UubWVhc3VyZSgpfV9hZnRlclJlc2l6ZShlLHQp"
    "e3ZhciBpLHM7bnVsbD09PShpPXRoaXMuX2NoYXJTaXplU2VydmljZSl8fHZvaWQgMD09PWl8fGkubWVhc3VyZSgpLG51bGw9PT0ocz10aGlzLnZpZXdwb3J0"
    "KXx8dm9pZCAwPT09c3x8cy5zeW5jU2Nyb2xsQXJlYSghMCl9Y2xlYXIoKXt2YXIgZTtpZigwIT09dGhpcy5idWZmZXIueWJhc2V8fDAhPT10aGlzLmJ1ZmZl"
    "ci55KXt0aGlzLmJ1ZmZlci5jbGVhckFsbE1hcmtlcnMoKSx0aGlzLmJ1ZmZlci5saW5lcy5zZXQoMCx0aGlzLmJ1ZmZlci5saW5lcy5nZXQodGhpcy5idWZm"
    "ZXIueWJhc2UrdGhpcy5idWZmZXIueSkpLHRoaXMuYnVmZmVyLmxpbmVzLmxlbmd0aD0xLHRoaXMuYnVmZmVyLnlkaXNwPTAsdGhpcy5idWZmZXIueWJhc2U9"
    "MCx0aGlzLmJ1ZmZlci55PTA7Zm9yKGxldCBlPTE7ZTx0aGlzLnJvd3M7ZSsrKXRoaXMuYnVmZmVyLmxpbmVzLnB1c2godGhpcy5idWZmZXIuZ2V0QmxhbmtM"
    "aW5lKEwuREVGQVVMVF9BVFRSX0RBVEEpKTt0aGlzLl9vblNjcm9sbC5maXJlKHtwb3NpdGlvbjp0aGlzLmJ1ZmZlci55ZGlzcCxzb3VyY2U6MH0pLG51bGw9"
    "PT0oZT10aGlzLnZpZXdwb3J0KXx8dm9pZCAwPT09ZXx8ZS5yZXNldCgpLHRoaXMucmVmcmVzaCgwLHRoaXMucm93cy0xKX19cmVzZXQoKXt2YXIgZSx0O3Ro"
    "aXMub3B0aW9ucy5yb3dzPXRoaXMucm93cyx0aGlzLm9wdGlvbnMuY29scz10aGlzLmNvbHM7Y29uc3QgaT10aGlzLl9jdXN0b21LZXlFdmVudEhhbmRsZXI7"
    "dGhpcy5fc2V0dXAoKSxzdXBlci5yZXNldCgpLG51bGw9PT0oZT10aGlzLl9zZWxlY3Rpb25TZXJ2aWNlKXx8dm9pZCAwPT09ZXx8ZS5yZXNldCgpLHRoaXMu"
    "X2RlY29yYXRpb25TZXJ2aWNlLnJlc2V0KCksbnVsbD09PSh0PXRoaXMudmlld3BvcnQpfHx2b2lkIDA9PT10fHx0LnJlc2V0KCksdGhpcy5fY3VzdG9tS2V5"
    "RXZlbnRIYW5kbGVyPWksdGhpcy5yZWZyZXNoKDAsdGhpcy5yb3dzLTEpfWNsZWFyVGV4dHVyZUF0bGFzKCl7dmFyIGU7bnVsbD09PShlPXRoaXMuX3JlbmRl"
    "clNlcnZpY2UpfHx2b2lkIDA9PT1lfHxlLmNsZWFyVGV4dHVyZUF0bGFzKCl9X3JlcG9ydEZvY3VzKCl7dmFyIGU7KG51bGw9PT0oZT10aGlzLmVsZW1lbnQp"
    "fHx2b2lkIDA9PT1lP3ZvaWQgMDplLmNsYXNzTGlzdC5jb250YWlucygiZm9jdXMiKSk/dGhpcy5jb3JlU2VydmljZS50cmlnZ2VyRGF0YUV2ZW50KEQuQzAu"
    "RVNDKyJbSSIpOnRoaXMuY29yZVNlcnZpY2UudHJpZ2dlckRhdGFFdmVudChELkMwLkVTQysiW08iKX1fcmVwb3J0V2luZG93c09wdGlvbnMoZSl7aWYodGhp"
    "cy5fcmVuZGVyU2VydmljZSlzd2l0Y2goZSl7Y2FzZSBULldpbmRvd3NPcHRpb25zUmVwb3J0VHlwZS5HRVRfV0lOX1NJWkVfUElYRUxTOmNvbnN0IGU9dGhp"
    "cy5fcmVuZGVyU2VydmljZS5kaW1lbnNpb25zLmNzcy5jYW52YXMud2lkdGgudG9GaXhlZCgwKSx0PXRoaXMuX3JlbmRlclNlcnZpY2UuZGltZW5zaW9ucy5j"
    "c3MuY2FudmFzLmhlaWdodC50b0ZpeGVkKDApO3RoaXMuY29yZVNlcnZpY2UudHJpZ2dlckRhdGFFdmVudChgJHtELkMwLkVTQ31bNDske3R9OyR7ZX10YCk7"
    "YnJlYWs7Y2FzZSBULldpbmRvd3NPcHRpb25zUmVwb3J0VHlwZS5HRVRfQ0VMTF9TSVpFX1BJWEVMUzpjb25zdCBpPXRoaXMuX3JlbmRlclNlcnZpY2UuZGlt"
    "ZW5zaW9ucy5jc3MuY2VsbC53aWR0aC50b0ZpeGVkKDApLHM9dGhpcy5fcmVuZGVyU2VydmljZS5kaW1lbnNpb25zLmNzcy5jZWxsLmhlaWdodC50b0ZpeGVk"
    "KDApO3RoaXMuY29yZVNlcnZpY2UudHJpZ2dlckRhdGFFdmVudChgJHtELkMwLkVTQ31bNjske3N9OyR7aX10YCl9fWNhbmNlbChlLHQpe2lmKHRoaXMub3B0"
    "aW9ucy5jYW5jZWxFdmVudHN8fHQpcmV0dXJuIGUucHJldmVudERlZmF1bHQoKSxlLnN0b3BQcm9wYWdhdGlvbigpLCExfX10LlRlcm1pbmFsPVB9LDk5MjQ6"
    "KGUsdCk9PntPYmplY3QuZGVmaW5lUHJvcGVydHkodCwiX19lc01vZHVsZSIse3ZhbHVlOiEwfSksdC5UaW1lQmFzZWREZWJvdW5jZXI9dm9pZCAwLHQuVGlt"
    "ZUJhc2VkRGVib3VuY2VyPWNsYXNze2NvbnN0cnVjdG9yKGUsdD0xZTMpe3RoaXMuX3JlbmRlckNhbGxiYWNrPWUsdGhpcy5fZGVib3VuY2VUaHJlc2hvbGRN"
    "Uz10LHRoaXMuX2xhc3RSZWZyZXNoTXM9MCx0aGlzLl9hZGRpdGlvbmFsUmVmcmVzaFJlcXVlc3RlZD0hMX1kaXNwb3NlKCl7dGhpcy5fcmVmcmVzaFRpbWVv"
    "dXRJRCYmY2xlYXJUaW1lb3V0KHRoaXMuX3JlZnJlc2hUaW1lb3V0SUQpfXJlZnJlc2goZSx0LGkpe3RoaXMuX3Jvd0NvdW50PWksZT12b2lkIDAhPT1lP2U6"
    "MCx0PXZvaWQgMCE9PXQ/dDp0aGlzLl9yb3dDb3VudC0xLHRoaXMuX3Jvd1N0YXJ0PXZvaWQgMCE9PXRoaXMuX3Jvd1N0YXJ0P01hdGgubWluKHRoaXMuX3Jv"
    "d1N0YXJ0LGUpOmUsdGhpcy5fcm93RW5kPXZvaWQgMCE9PXRoaXMuX3Jvd0VuZD9NYXRoLm1heCh0aGlzLl9yb3dFbmQsdCk6dDtjb25zdCBzPURhdGUubm93"
    "KCk7aWYocy10aGlzLl9sYXN0UmVmcmVzaE1zPj10aGlzLl9kZWJvdW5jZVRocmVzaG9sZE1TKXRoaXMuX2xhc3RSZWZyZXNoTXM9cyx0aGlzLl9pbm5lclJl"
    "ZnJlc2goKTtlbHNlIGlmKCF0aGlzLl9hZGRpdGlvbmFsUmVmcmVzaFJlcXVlc3RlZCl7Y29uc3QgZT1zLXRoaXMuX2xhc3RSZWZyZXNoTXMsdD10aGlzLl9k"
    "ZWJvdW5jZVRocmVzaG9sZE1TLWU7dGhpcy5fYWRkaXRpb25hbFJlZnJlc2hSZXF1ZXN0ZWQ9ITAsdGhpcy5fcmVmcmVzaFRpbWVvdXRJRD13aW5kb3cuc2V0"
    "VGltZW91dCgoKCk9Pnt0aGlzLl9sYXN0UmVmcmVzaE1zPURhdGUubm93KCksdGhpcy5faW5uZXJSZWZyZXNoKCksdGhpcy5fYWRkaXRpb25hbFJlZnJlc2hS"
    "ZXF1ZXN0ZWQ9ITEsdGhpcy5fcmVmcmVzaFRpbWVvdXRJRD12b2lkIDB9KSx0KX19X2lubmVyUmVmcmVzaCgpe2lmKHZvaWQgMD09PXRoaXMuX3Jvd1N0YXJ0"
    "fHx2b2lkIDA9PT10aGlzLl9yb3dFbmR8fHZvaWQgMD09PXRoaXMuX3Jvd0NvdW50KXJldHVybjtjb25zdCBlPU1hdGgubWF4KHRoaXMuX3Jvd1N0YXJ0LDAp"
    "LHQ9TWF0aC5taW4odGhpcy5fcm93RW5kLHRoaXMuX3Jvd0NvdW50LTEpO3RoaXMuX3Jvd1N0YXJ0PXZvaWQgMCx0aGlzLl9yb3dFbmQ9dm9pZCAwLHRoaXMu"
    "X3JlbmRlckNhbGxiYWNrKGUsdCl9fX0sMTY4MDpmdW5jdGlvbihlLHQsaSl7dmFyIHM9dGhpcyYmdGhpcy5fX2RlY29yYXRlfHxmdW5jdGlvbihlLHQsaSxz"
    "KXt2YXIgcixuPWFyZ3VtZW50cy5sZW5ndGgsbz1uPDM/dDpudWxsPT09cz9zPU9iamVjdC5nZXRPd25Qcm9wZXJ0eURlc2NyaXB0b3IodCxpKTpzO2lmKCJv"
    "YmplY3QiPT10eXBlb2YgUmVmbGVjdCYmImZ1bmN0aW9uIj09dHlwZW9mIFJlZmxlY3QuZGVjb3JhdGUpbz1SZWZsZWN0LmRlY29yYXRlKGUsdCxpLHMpO2Vs"
    "c2UgZm9yKHZhciBhPWUubGVuZ3RoLTE7YT49MDthLS0pKHI9ZVthXSkmJihvPShuPDM/cihvKTpuPjM/cih0LGksbyk6cih0LGkpKXx8byk7cmV0dXJuIG4+"
    "MyYmbyYmT2JqZWN0LmRlZmluZVByb3BlcnR5KHQsaSxvKSxvfSxyPXRoaXMmJnRoaXMuX19wYXJhbXx8ZnVuY3Rpb24oZSx0KXtyZXR1cm4gZnVuY3Rpb24o"
    "aSxzKXt0KGkscyxlKX19O09iamVjdC5kZWZpbmVQcm9wZXJ0eSh0LCJfX2VzTW9kdWxlIix7dmFsdWU6ITB9KSx0LlZpZXdwb3J0PXZvaWQgMDtjb25zdCBu"
    "PWkoMzY1Niksbz1pKDQ3MjUpLGE9aSg4NDYwKSxoPWkoODQ0KSxjPWkoMjU4NSk7bGV0IGw9dC5WaWV3cG9ydD1jbGFzcyBleHRlbmRzIGguRGlzcG9zYWJs"
    "ZXtjb25zdHJ1Y3RvcihlLHQsaSxzLHIsbyxoLGMpe3N1cGVyKCksdGhpcy5fdmlld3BvcnRFbGVtZW50PWUsdGhpcy5fc2Nyb2xsQXJlYT10LHRoaXMuX2J1"
    "ZmZlclNlcnZpY2U9aSx0aGlzLl9vcHRpb25zU2VydmljZT1zLHRoaXMuX2NoYXJTaXplU2VydmljZT1yLHRoaXMuX3JlbmRlclNlcnZpY2U9byx0aGlzLl9j"
    "b3JlQnJvd3NlclNlcnZpY2U9aCx0aGlzLnNjcm9sbEJhcldpZHRoPTAsdGhpcy5fY3VycmVudFJvd0hlaWdodD0wLHRoaXMuX2N1cnJlbnREZXZpY2VDZWxs"
    "SGVpZ2h0PTAsdGhpcy5fbGFzdFJlY29yZGVkQnVmZmVyTGVuZ3RoPTAsdGhpcy5fbGFzdFJlY29yZGVkVmlld3BvcnRIZWlnaHQ9MCx0aGlzLl9sYXN0UmVj"
    "b3JkZWRCdWZmZXJIZWlnaHQ9MCx0aGlzLl9sYXN0VG91Y2hZPTAsdGhpcy5fbGFzdFNjcm9sbFRvcD0wLHRoaXMuX3doZWVsUGFydGlhbFNjcm9sbD0wLHRo"
    "aXMuX3JlZnJlc2hBbmltYXRpb25GcmFtZT1udWxsLHRoaXMuX2lnbm9yZU5leHRTY3JvbGxFdmVudD0hMSx0aGlzLl9zbW9vdGhTY3JvbGxTdGF0ZT17c3Rh"
    "cnRUaW1lOjAsb3JpZ2luOi0xLHRhcmdldDotMX0sdGhpcy5fb25SZXF1ZXN0U2Nyb2xsTGluZXM9dGhpcy5yZWdpc3RlcihuZXcgYS5FdmVudEVtaXR0ZXIp"
    "LHRoaXMub25SZXF1ZXN0U2Nyb2xsTGluZXM9dGhpcy5fb25SZXF1ZXN0U2Nyb2xsTGluZXMuZXZlbnQsdGhpcy5zY3JvbGxCYXJXaWR0aD10aGlzLl92aWV3"
    "cG9ydEVsZW1lbnQub2Zmc2V0V2lkdGgtdGhpcy5fc2Nyb2xsQXJlYS5vZmZzZXRXaWR0aHx8MTUsdGhpcy5yZWdpc3RlcigoMCxuLmFkZERpc3Bvc2FibGVE"
    "b21MaXN0ZW5lcikodGhpcy5fdmlld3BvcnRFbGVtZW50LCJzY3JvbGwiLHRoaXMuX2hhbmRsZVNjcm9sbC5iaW5kKHRoaXMpKSksdGhpcy5fYWN0aXZlQnVm"
    "ZmVyPXRoaXMuX2J1ZmZlclNlcnZpY2UuYnVmZmVyLHRoaXMucmVnaXN0ZXIodGhpcy5fYnVmZmVyU2VydmljZS5idWZmZXJzLm9uQnVmZmVyQWN0aXZhdGUo"
    "KGU9PnRoaXMuX2FjdGl2ZUJ1ZmZlcj1lLmFjdGl2ZUJ1ZmZlcikpKSx0aGlzLl9yZW5kZXJEaW1lbnNpb25zPXRoaXMuX3JlbmRlclNlcnZpY2UuZGltZW5z"
    "aW9ucyx0aGlzLnJlZ2lzdGVyKHRoaXMuX3JlbmRlclNlcnZpY2Uub25EaW1lbnNpb25zQ2hhbmdlKChlPT50aGlzLl9yZW5kZXJEaW1lbnNpb25zPWUpKSks"
    "dGhpcy5faGFuZGxlVGhlbWVDaGFuZ2UoYy5jb2xvcnMpLHRoaXMucmVnaXN0ZXIoYy5vbkNoYW5nZUNvbG9ycygoZT0+dGhpcy5faGFuZGxlVGhlbWVDaGFu"
    "Z2UoZSkpKSksdGhpcy5yZWdpc3Rlcih0aGlzLl9vcHRpb25zU2VydmljZS5vblNwZWNpZmljT3B0aW9uQ2hhbmdlKCJzY3JvbGxiYWNrIiwoKCk9PnRoaXMu"
    "c3luY1Njcm9sbEFyZWEoKSkpKSxzZXRUaW1lb3V0KCgoKT0+dGhpcy5zeW5jU2Nyb2xsQXJlYSgpKSl9X2hhbmRsZVRoZW1lQ2hhbmdlKGUpe3RoaXMuX3Zp"
    "ZXdwb3J0RWxlbWVudC5zdHlsZS5iYWNrZ3JvdW5kQ29sb3I9ZS5iYWNrZ3JvdW5kLmNzc31yZXNldCgpe3RoaXMuX2N1cnJlbnRSb3dIZWlnaHQ9MCx0aGlz"
    "Ll9jdXJyZW50RGV2aWNlQ2VsbEhlaWdodD0wLHRoaXMuX2xhc3RSZWNvcmRlZEJ1ZmZlckxlbmd0aD0wLHRoaXMuX2xhc3RSZWNvcmRlZFZpZXdwb3J0SGVp"
    "Z2h0PTAsdGhpcy5fbGFzdFJlY29yZGVkQnVmZmVySGVpZ2h0PTAsdGhpcy5fbGFzdFRvdWNoWT0wLHRoaXMuX2xhc3RTY3JvbGxUb3A9MCx0aGlzLl9jb3Jl"
    "QnJvd3NlclNlcnZpY2Uud2luZG93LnJlcXVlc3RBbmltYXRpb25GcmFtZSgoKCk9PnRoaXMuc3luY1Njcm9sbEFyZWEoKSkpfV9yZWZyZXNoKGUpe2lmKGUp"
    "cmV0dXJuIHRoaXMuX2lubmVyUmVmcmVzaCgpLHZvaWQobnVsbCE9PXRoaXMuX3JlZnJlc2hBbmltYXRpb25GcmFtZSYmdGhpcy5fY29yZUJyb3dzZXJTZXJ2"
    "aWNlLndpbmRvdy5jYW5jZWxBbmltYXRpb25GcmFtZSh0aGlzLl9yZWZyZXNoQW5pbWF0aW9uRnJhbWUpKTtudWxsPT09dGhpcy5fcmVmcmVzaEFuaW1hdGlv"
    "bkZyYW1lJiYodGhpcy5fcmVmcmVzaEFuaW1hdGlvbkZyYW1lPXRoaXMuX2NvcmVCcm93c2VyU2VydmljZS53aW5kb3cucmVxdWVzdEFuaW1hdGlvbkZyYW1l"
    "KCgoKT0+dGhpcy5faW5uZXJSZWZyZXNoKCkpKSl9X2lubmVyUmVmcmVzaCgpe2lmKHRoaXMuX2NoYXJTaXplU2VydmljZS5oZWlnaHQ+MCl7dGhpcy5fY3Vy"
    "cmVudFJvd0hlaWdodD10aGlzLl9yZW5kZXJTZXJ2aWNlLmRpbWVuc2lvbnMuZGV2aWNlLmNlbGwuaGVpZ2h0L3RoaXMuX2NvcmVCcm93c2VyU2VydmljZS5k"
    "cHIsdGhpcy5fY3VycmVudERldmljZUNlbGxIZWlnaHQ9dGhpcy5fcmVuZGVyU2VydmljZS5kaW1lbnNpb25zLmRldmljZS5jZWxsLmhlaWdodCx0aGlzLl9s"
    "YXN0UmVjb3JkZWRWaWV3cG9ydEhlaWdodD10aGlzLl92aWV3cG9ydEVsZW1lbnQub2Zmc2V0SGVpZ2h0O2NvbnN0IGU9TWF0aC5yb3VuZCh0aGlzLl9jdXJy"
    "ZW50Um93SGVpZ2h0KnRoaXMuX2xhc3RSZWNvcmRlZEJ1ZmZlckxlbmd0aCkrKHRoaXMuX2xhc3RSZWNvcmRlZFZpZXdwb3J0SGVpZ2h0LXRoaXMuX3JlbmRl"
    "clNlcnZpY2UuZGltZW5zaW9ucy5jc3MuY2FudmFzLmhlaWdodCk7dGhpcy5fbGFzdFJlY29yZGVkQnVmZmVySGVpZ2h0IT09ZSYmKHRoaXMuX2xhc3RSZWNv"
    "cmRlZEJ1ZmZlckhlaWdodD1lLHRoaXMuX3Njcm9sbEFyZWEuc3R5bGUuaGVpZ2h0PXRoaXMuX2xhc3RSZWNvcmRlZEJ1ZmZlckhlaWdodCsicHgiKX1jb25z"
    "dCBlPXRoaXMuX2J1ZmZlclNlcnZpY2UuYnVmZmVyLnlkaXNwKnRoaXMuX2N1cnJlbnRSb3dIZWlnaHQ7dGhpcy5fdmlld3BvcnRFbGVtZW50LnNjcm9sbFRv"
    "cCE9PWUmJih0aGlzLl9pZ25vcmVOZXh0U2Nyb2xsRXZlbnQ9ITAsdGhpcy5fdmlld3BvcnRFbGVtZW50LnNjcm9sbFRvcD1lKSx0aGlzLl9yZWZyZXNoQW5p"
    "bWF0aW9uRnJhbWU9bnVsbH1zeW5jU2Nyb2xsQXJlYShlPSExKXtpZih0aGlzLl9sYXN0UmVjb3JkZWRCdWZmZXJMZW5ndGghPT10aGlzLl9idWZmZXJTZXJ2"
    "aWNlLmJ1ZmZlci5saW5lcy5sZW5ndGgpcmV0dXJuIHRoaXMuX2xhc3RSZWNvcmRlZEJ1ZmZlckxlbmd0aD10aGlzLl9idWZmZXJTZXJ2aWNlLmJ1ZmZlci5s"
    "aW5lcy5sZW5ndGgsdm9pZCB0aGlzLl9yZWZyZXNoKGUpO3RoaXMuX2xhc3RSZWNvcmRlZFZpZXdwb3J0SGVpZ2h0PT09dGhpcy5fcmVuZGVyU2VydmljZS5k"
    "aW1lbnNpb25zLmNzcy5jYW52YXMuaGVpZ2h0JiZ0aGlzLl9sYXN0U2Nyb2xsVG9wPT09dGhpcy5fYWN0aXZlQnVmZmVyLnlkaXNwKnRoaXMuX2N1cnJlbnRS"
    "b3dIZWlnaHQmJnRoaXMuX3JlbmRlckRpbWVuc2lvbnMuZGV2aWNlLmNlbGwuaGVpZ2h0PT09dGhpcy5fY3VycmVudERldmljZUNlbGxIZWlnaHR8fHRoaXMu"
    "X3JlZnJlc2goZSl9X2hhbmRsZVNjcm9sbChlKXtpZih0aGlzLl9sYXN0U2Nyb2xsVG9wPXRoaXMuX3ZpZXdwb3J0RWxlbWVudC5zY3JvbGxUb3AsIXRoaXMu"
    "X3ZpZXdwb3J0RWxlbWVudC5vZmZzZXRQYXJlbnQpcmV0dXJuO2lmKHRoaXMuX2lnbm9yZU5leHRTY3JvbGxFdmVudClyZXR1cm4gdGhpcy5faWdub3JlTmV4"
    "dFNjcm9sbEV2ZW50PSExLHZvaWQgdGhpcy5fb25SZXF1ZXN0U2Nyb2xsTGluZXMuZmlyZSh7YW1vdW50OjAsc3VwcHJlc3NTY3JvbGxFdmVudDohMH0pO2Nv"
    "bnN0IHQ9TWF0aC5yb3VuZCh0aGlzLl9sYXN0U2Nyb2xsVG9wL3RoaXMuX2N1cnJlbnRSb3dIZWlnaHQpLXRoaXMuX2J1ZmZlclNlcnZpY2UuYnVmZmVyLnlk"
    "aXNwO3RoaXMuX29uUmVxdWVzdFNjcm9sbExpbmVzLmZpcmUoe2Ftb3VudDp0LHN1cHByZXNzU2Nyb2xsRXZlbnQ6ITB9KX1fc21vb3RoU2Nyb2xsKCl7aWYo"
    "dGhpcy5faXNEaXNwb3NlZHx8LTE9PT10aGlzLl9zbW9vdGhTY3JvbGxTdGF0ZS5vcmlnaW58fC0xPT09dGhpcy5fc21vb3RoU2Nyb2xsU3RhdGUudGFyZ2V0"
    "KXJldHVybjtjb25zdCBlPXRoaXMuX3Ntb290aFNjcm9sbFBlcmNlbnQoKTt0aGlzLl92aWV3cG9ydEVsZW1lbnQuc2Nyb2xsVG9wPXRoaXMuX3Ntb290aFNj"
    "cm9sbFN0YXRlLm9yaWdpbitNYXRoLnJvdW5kKGUqKHRoaXMuX3Ntb290aFNjcm9sbFN0YXRlLnRhcmdldC10aGlzLl9zbW9vdGhTY3JvbGxTdGF0ZS5vcmln"
    "aW4pKSxlPDE/dGhpcy5fY29yZUJyb3dzZXJTZXJ2aWNlLndpbmRvdy5yZXF1ZXN0QW5pbWF0aW9uRnJhbWUoKCgpPT50aGlzLl9zbW9vdGhTY3JvbGwoKSkp"
    "OnRoaXMuX2NsZWFyU21vb3RoU2Nyb2xsU3RhdGUoKX1fc21vb3RoU2Nyb2xsUGVyY2VudCgpe3JldHVybiB0aGlzLl9vcHRpb25zU2VydmljZS5yYXdPcHRp"
    "b25zLnNtb290aFNjcm9sbER1cmF0aW9uJiZ0aGlzLl9zbW9vdGhTY3JvbGxTdGF0ZS5zdGFydFRpbWU/TWF0aC5tYXgoTWF0aC5taW4oKERhdGUubm93KCkt"
    "dGhpcy5fc21vb3RoU2Nyb2xsU3RhdGUuc3RhcnRUaW1lKS90aGlzLl9vcHRpb25zU2VydmljZS5yYXdPcHRpb25zLnNtb290aFNjcm9sbER1cmF0aW9uLDEp"
    "LDApOjF9X2NsZWFyU21vb3RoU2Nyb2xsU3RhdGUoKXt0aGlzLl9zbW9vdGhTY3JvbGxTdGF0ZS5zdGFydFRpbWU9MCx0aGlzLl9zbW9vdGhTY3JvbGxTdGF0"
    "ZS5vcmlnaW49LTEsdGhpcy5fc21vb3RoU2Nyb2xsU3RhdGUudGFyZ2V0PS0xfV9idWJibGVTY3JvbGwoZSx0KXtjb25zdCBpPXRoaXMuX3ZpZXdwb3J0RWxl"
    "bWVudC5zY3JvbGxUb3ArdGhpcy5fbGFzdFJlY29yZGVkVmlld3BvcnRIZWlnaHQ7cmV0dXJuISh0PDAmJjAhPT10aGlzLl92aWV3cG9ydEVsZW1lbnQuc2Ny"
    "b2xsVG9wfHx0PjAmJmk8dGhpcy5fbGFzdFJlY29yZGVkQnVmZmVySGVpZ2h0KXx8KGUuY2FuY2VsYWJsZSYmZS5wcmV2ZW50RGVmYXVsdCgpLCExKX1oYW5k"
    "bGVXaGVlbChlKXtjb25zdCB0PXRoaXMuX2dldFBpeGVsc1Njcm9sbGVkKGUpO3JldHVybiAwIT09dCYmKHRoaXMuX29wdGlvbnNTZXJ2aWNlLnJhd09wdGlv"
    "bnMuc21vb3RoU2Nyb2xsRHVyYXRpb24/KHRoaXMuX3Ntb290aFNjcm9sbFN0YXRlLnN0YXJ0VGltZT1EYXRlLm5vdygpLHRoaXMuX3Ntb290aFNjcm9sbFBl"
    "cmNlbnQoKTwxPyh0aGlzLl9zbW9vdGhTY3JvbGxTdGF0ZS5vcmlnaW49dGhpcy5fdmlld3BvcnRFbGVtZW50LnNjcm9sbFRvcCwtMT09PXRoaXMuX3Ntb290"
    "aFNjcm9sbFN0YXRlLnRhcmdldD90aGlzLl9zbW9vdGhTY3JvbGxTdGF0ZS50YXJnZXQ9dGhpcy5fdmlld3BvcnRFbGVtZW50LnNjcm9sbFRvcCt0OnRoaXMu"
    "X3Ntb290aFNjcm9sbFN0YXRlLnRhcmdldCs9dCx0aGlzLl9zbW9vdGhTY3JvbGxTdGF0ZS50YXJnZXQ9TWF0aC5tYXgoTWF0aC5taW4odGhpcy5fc21vb3Ro"
    "U2Nyb2xsU3RhdGUudGFyZ2V0LHRoaXMuX3ZpZXdwb3J0RWxlbWVudC5zY3JvbGxIZWlnaHQpLDApLHRoaXMuX3Ntb290aFNjcm9sbCgpKTp0aGlzLl9jbGVh"
    "clNtb290aFNjcm9sbFN0YXRlKCkpOnRoaXMuX3ZpZXdwb3J0RWxlbWVudC5zY3JvbGxUb3ArPXQsdGhpcy5fYnViYmxlU2Nyb2xsKGUsdCkpfXNjcm9sbExp"
    "bmVzKGUpe2lmKDAhPT1lKWlmKHRoaXMuX29wdGlvbnNTZXJ2aWNlLnJhd09wdGlvbnMuc21vb3RoU2Nyb2xsRHVyYXRpb24pe2NvbnN0IHQ9ZSp0aGlzLl9j"
    "dXJyZW50Um93SGVpZ2h0O3RoaXMuX3Ntb290aFNjcm9sbFN0YXRlLnN0YXJ0VGltZT1EYXRlLm5vdygpLHRoaXMuX3Ntb290aFNjcm9sbFBlcmNlbnQoKTwx"
    "Pyh0aGlzLl9zbW9vdGhTY3JvbGxTdGF0ZS5vcmlnaW49dGhpcy5fdmlld3BvcnRFbGVtZW50LnNjcm9sbFRvcCx0aGlzLl9zbW9vdGhTY3JvbGxTdGF0ZS50"
    "YXJnZXQ9dGhpcy5fc21vb3RoU2Nyb2xsU3RhdGUub3JpZ2luK3QsdGhpcy5fc21vb3RoU2Nyb2xsU3RhdGUudGFyZ2V0PU1hdGgubWF4KE1hdGgubWluKHRo"
    "aXMuX3Ntb290aFNjcm9sbFN0YXRlLnRhcmdldCx0aGlzLl92aWV3cG9ydEVsZW1lbnQuc2Nyb2xsSGVpZ2h0KSwwKSx0aGlzLl9zbW9vdGhTY3JvbGwoKSk6"
    "dGhpcy5fY2xlYXJTbW9vdGhTY3JvbGxTdGF0ZSgpfWVsc2UgdGhpcy5fb25SZXF1ZXN0U2Nyb2xsTGluZXMuZmlyZSh7YW1vdW50OmUsc3VwcHJlc3NTY3Jv"
    "bGxFdmVudDohMX0pfV9nZXRQaXhlbHNTY3JvbGxlZChlKXtpZigwPT09ZS5kZWx0YVl8fGUuc2hpZnRLZXkpcmV0dXJuIDA7bGV0IHQ9dGhpcy5fYXBwbHlT"
    "Y3JvbGxNb2RpZmllcihlLmRlbHRhWSxlKTtyZXR1cm4gZS5kZWx0YU1vZGU9PT1XaGVlbEV2ZW50LkRPTV9ERUxUQV9MSU5FP3QqPXRoaXMuX2N1cnJlbnRS"
    "b3dIZWlnaHQ6ZS5kZWx0YU1vZGU9PT1XaGVlbEV2ZW50LkRPTV9ERUxUQV9QQUdFJiYodCo9dGhpcy5fY3VycmVudFJvd0hlaWdodCp0aGlzLl9idWZmZXJT"
    "ZXJ2aWNlLnJvd3MpLHR9Z2V0QnVmZmVyRWxlbWVudHMoZSx0KXt2YXIgaTtsZXQgcyxyPSIiO2NvbnN0IG49W10sbz1udWxsIT10P3Q6dGhpcy5fYnVmZmVy"
    "U2VydmljZS5idWZmZXIubGluZXMubGVuZ3RoLGE9dGhpcy5fYnVmZmVyU2VydmljZS5idWZmZXIubGluZXM7Zm9yKGxldCB0PWU7dDxvO3QrKyl7Y29uc3Qg"
    "ZT1hLmdldCh0KTtpZighZSljb250aW51ZTtjb25zdCBvPW51bGw9PT0oaT1hLmdldCh0KzEpKXx8dm9pZCAwPT09aT92b2lkIDA6aS5pc1dyYXBwZWQ7aWYo"
    "cis9ZS50cmFuc2xhdGVUb1N0cmluZyghbyksIW98fHQ9PT1hLmxlbmd0aC0xKXtjb25zdCBlPWRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpO2UudGV4"
    "dENvbnRlbnQ9cixuLnB1c2goZSksci5sZW5ndGg+MCYmKHM9ZSkscj0iIn19cmV0dXJue2J1ZmZlckVsZW1lbnRzOm4sY3Vyc29yRWxlbWVudDpzfX1nZXRM"
    "aW5lc1Njcm9sbGVkKGUpe2lmKDA9PT1lLmRlbHRhWXx8ZS5zaGlmdEtleSlyZXR1cm4gMDtsZXQgdD10aGlzLl9hcHBseVNjcm9sbE1vZGlmaWVyKGUuZGVs"
    "dGFZLGUpO3JldHVybiBlLmRlbHRhTW9kZT09PVdoZWVsRXZlbnQuRE9NX0RFTFRBX1BJWEVMPyh0Lz10aGlzLl9jdXJyZW50Um93SGVpZ2h0KzAsdGhpcy5f"
    "d2hlZWxQYXJ0aWFsU2Nyb2xsKz10LHQ9TWF0aC5mbG9vcihNYXRoLmFicyh0aGlzLl93aGVlbFBhcnRpYWxTY3JvbGwpKSoodGhpcy5fd2hlZWxQYXJ0aWFs"
    "U2Nyb2xsPjA/MTotMSksdGhpcy5fd2hlZWxQYXJ0aWFsU2Nyb2xsJT0xKTplLmRlbHRhTW9kZT09PVdoZWVsRXZlbnQuRE9NX0RFTFRBX1BBR0UmJih0Kj10"
    "aGlzLl9idWZmZXJTZXJ2aWNlLnJvd3MpLHR9X2FwcGx5U2Nyb2xsTW9kaWZpZXIoZSx0KXtjb25zdCBpPXRoaXMuX29wdGlvbnNTZXJ2aWNlLnJhd09wdGlv"
    "bnMuZmFzdFNjcm9sbE1vZGlmaWVyO3JldHVybiJhbHQiPT09aSYmdC5hbHRLZXl8fCJjdHJsIj09PWkmJnQuY3RybEtleXx8InNoaWZ0Ij09PWkmJnQuc2hp"
    "ZnRLZXk/ZSp0aGlzLl9vcHRpb25zU2VydmljZS5yYXdPcHRpb25zLmZhc3RTY3JvbGxTZW5zaXRpdml0eSp0aGlzLl9vcHRpb25zU2VydmljZS5yYXdPcHRp"
    "b25zLnNjcm9sbFNlbnNpdGl2aXR5OmUqdGhpcy5fb3B0aW9uc1NlcnZpY2UucmF3T3B0aW9ucy5zY3JvbGxTZW5zaXRpdml0eX1oYW5kbGVUb3VjaFN0YXJ0"
    "KGUpe3RoaXMuX2xhc3RUb3VjaFk9ZS50b3VjaGVzWzBdLnBhZ2VZfWhhbmRsZVRvdWNoTW92ZShlKXtjb25zdCB0PXRoaXMuX2xhc3RUb3VjaFktZS50b3Vj"
    "aGVzWzBdLnBhZ2VZO3JldHVybiB0aGlzLl9sYXN0VG91Y2hZPWUudG91Y2hlc1swXS5wYWdlWSwwIT09dCYmKHRoaXMuX3ZpZXdwb3J0RWxlbWVudC5zY3Jv"
    "bGxUb3ArPXQsdGhpcy5fYnViYmxlU2Nyb2xsKGUsdCkpfX07dC5WaWV3cG9ydD1sPXMoW3IoMixjLklCdWZmZXJTZXJ2aWNlKSxyKDMsYy5JT3B0aW9uc1Nl"
    "cnZpY2UpLHIoNCxvLklDaGFyU2l6ZVNlcnZpY2UpLHIoNSxvLklSZW5kZXJTZXJ2aWNlKSxyKDYsby5JQ29yZUJyb3dzZXJTZXJ2aWNlKSxyKDcsby5JVGhl"
    "bWVTZXJ2aWNlKV0sbCl9LDMxMDc6ZnVuY3Rpb24oZSx0LGkpe3ZhciBzPXRoaXMmJnRoaXMuX19kZWNvcmF0ZXx8ZnVuY3Rpb24oZSx0LGkscyl7dmFyIHIs"
    "bj1hcmd1bWVudHMubGVuZ3RoLG89bjwzP3Q6bnVsbD09PXM/cz1PYmplY3QuZ2V0T3duUHJvcGVydHlEZXNjcmlwdG9yKHQsaSk6cztpZigib2JqZWN0Ij09"
    "dHlwZW9mIFJlZmxlY3QmJiJmdW5jdGlvbiI9PXR5cGVvZiBSZWZsZWN0LmRlY29yYXRlKW89UmVmbGVjdC5kZWNvcmF0ZShlLHQsaSxzKTtlbHNlIGZvcih2"
    "YXIgYT1lLmxlbmd0aC0xO2E+PTA7YS0tKShyPWVbYV0pJiYobz0objwzP3Iobyk6bj4zP3IodCxpLG8pOnIodCxpKSl8fG8pO3JldHVybiBuPjMmJm8mJk9i"
    "amVjdC5kZWZpbmVQcm9wZXJ0eSh0LGksbyksb30scj10aGlzJiZ0aGlzLl9fcGFyYW18fGZ1bmN0aW9uKGUsdCl7cmV0dXJuIGZ1bmN0aW9uKGkscyl7dChp"
    "LHMsZSl9fTtPYmplY3QuZGVmaW5lUHJvcGVydHkodCwiX19lc01vZHVsZSIse3ZhbHVlOiEwfSksdC5CdWZmZXJEZWNvcmF0aW9uUmVuZGVyZXI9dm9pZCAw"
    "O2NvbnN0IG49aSgzNjU2KSxvPWkoNDcyNSksYT1pKDg0NCksaD1pKDI1ODUpO2xldCBjPXQuQnVmZmVyRGVjb3JhdGlvblJlbmRlcmVyPWNsYXNzIGV4dGVu"
    "ZHMgYS5EaXNwb3NhYmxle2NvbnN0cnVjdG9yKGUsdCxpLHMpe3N1cGVyKCksdGhpcy5fc2NyZWVuRWxlbWVudD1lLHRoaXMuX2J1ZmZlclNlcnZpY2U9dCx0"
    "aGlzLl9kZWNvcmF0aW9uU2VydmljZT1pLHRoaXMuX3JlbmRlclNlcnZpY2U9cyx0aGlzLl9kZWNvcmF0aW9uRWxlbWVudHM9bmV3IE1hcCx0aGlzLl9hbHRC"
    "dWZmZXJJc0FjdGl2ZT0hMSx0aGlzLl9kaW1lbnNpb25zQ2hhbmdlZD0hMSx0aGlzLl9jb250YWluZXI9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iiks"
    "dGhpcy5fY29udGFpbmVyLmNsYXNzTGlzdC5hZGQoInh0ZXJtLWRlY29yYXRpb24tY29udGFpbmVyIiksdGhpcy5fc2NyZWVuRWxlbWVudC5hcHBlbmRDaGls"
    "ZCh0aGlzLl9jb250YWluZXIpLHRoaXMucmVnaXN0ZXIodGhpcy5fcmVuZGVyU2VydmljZS5vblJlbmRlcmVkVmlld3BvcnRDaGFuZ2UoKCgpPT50aGlzLl9k"
    "b1JlZnJlc2hEZWNvcmF0aW9ucygpKSkpLHRoaXMucmVnaXN0ZXIodGhpcy5fcmVuZGVyU2VydmljZS5vbkRpbWVuc2lvbnNDaGFuZ2UoKCgpPT57dGhpcy5f"
    "ZGltZW5zaW9uc0NoYW5nZWQ9ITAsdGhpcy5fcXVldWVSZWZyZXNoKCl9KSkpLHRoaXMucmVnaXN0ZXIoKDAsbi5hZGREaXNwb3NhYmxlRG9tTGlzdGVuZXIp"
    "KHdpbmRvdywicmVzaXplIiwoKCk9PnRoaXMuX3F1ZXVlUmVmcmVzaCgpKSkpLHRoaXMucmVnaXN0ZXIodGhpcy5fYnVmZmVyU2VydmljZS5idWZmZXJzLm9u"
    "QnVmZmVyQWN0aXZhdGUoKCgpPT57dGhpcy5fYWx0QnVmZmVySXNBY3RpdmU9dGhpcy5fYnVmZmVyU2VydmljZS5idWZmZXI9PT10aGlzLl9idWZmZXJTZXJ2"
    "aWNlLmJ1ZmZlcnMuYWx0fSkpKSx0aGlzLnJlZ2lzdGVyKHRoaXMuX2RlY29yYXRpb25TZXJ2aWNlLm9uRGVjb3JhdGlvblJlZ2lzdGVyZWQoKCgpPT50aGlz"
    "Ll9xdWV1ZVJlZnJlc2goKSkpKSx0aGlzLnJlZ2lzdGVyKHRoaXMuX2RlY29yYXRpb25TZXJ2aWNlLm9uRGVjb3JhdGlvblJlbW92ZWQoKGU9PnRoaXMuX3Jl"
    "bW92ZURlY29yYXRpb24oZSkpKSksdGhpcy5yZWdpc3RlcigoMCxhLnRvRGlzcG9zYWJsZSkoKCgpPT57dGhpcy5fY29udGFpbmVyLnJlbW92ZSgpLHRoaXMu"
    "X2RlY29yYXRpb25FbGVtZW50cy5jbGVhcigpfSkpKX1fcXVldWVSZWZyZXNoKCl7dm9pZCAwPT09dGhpcy5fYW5pbWF0aW9uRnJhbWUmJih0aGlzLl9hbmlt"
    "YXRpb25GcmFtZT10aGlzLl9yZW5kZXJTZXJ2aWNlLmFkZFJlZnJlc2hDYWxsYmFjaygoKCk9Pnt0aGlzLl9kb1JlZnJlc2hEZWNvcmF0aW9ucygpLHRoaXMu"
    "X2FuaW1hdGlvbkZyYW1lPXZvaWQgMH0pKSl9X2RvUmVmcmVzaERlY29yYXRpb25zKCl7Zm9yKGNvbnN0IGUgb2YgdGhpcy5fZGVjb3JhdGlvblNlcnZpY2Uu"
    "ZGVjb3JhdGlvbnMpdGhpcy5fcmVuZGVyRGVjb3JhdGlvbihlKTt0aGlzLl9kaW1lbnNpb25zQ2hhbmdlZD0hMX1fcmVuZGVyRGVjb3JhdGlvbihlKXt0aGlz"
    "Ll9yZWZyZXNoU3R5bGUoZSksdGhpcy5fZGltZW5zaW9uc0NoYW5nZWQmJnRoaXMuX3JlZnJlc2hYUG9zaXRpb24oZSl9X2NyZWF0ZUVsZW1lbnQoZSl7dmFy"
    "IHQsaTtjb25zdCBzPWRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpO3MuY2xhc3NMaXN0LmFkZCgieHRlcm0tZGVjb3JhdGlvbiIpLHMuY2xhc3NMaXN0"
    "LnRvZ2dsZSgieHRlcm0tZGVjb3JhdGlvbi10b3AtbGF5ZXIiLCJ0b3AiPT09KG51bGw9PT0odD1udWxsPT1lP3ZvaWQgMDplLm9wdGlvbnMpfHx2b2lkIDA9"
    "PT10P3ZvaWQgMDp0LmxheWVyKSkscy5zdHlsZS53aWR0aD1gJHtNYXRoLnJvdW5kKChlLm9wdGlvbnMud2lkdGh8fDEpKnRoaXMuX3JlbmRlclNlcnZpY2Uu"
    "ZGltZW5zaW9ucy5jc3MuY2VsbC53aWR0aCl9cHhgLHMuc3R5bGUuaGVpZ2h0PShlLm9wdGlvbnMuaGVpZ2h0fHwxKSp0aGlzLl9yZW5kZXJTZXJ2aWNlLmRp"
    "bWVuc2lvbnMuY3NzLmNlbGwuaGVpZ2h0KyJweCIscy5zdHlsZS50b3A9KGUubWFya2VyLmxpbmUtdGhpcy5fYnVmZmVyU2VydmljZS5idWZmZXJzLmFjdGl2"
    "ZS55ZGlzcCkqdGhpcy5fcmVuZGVyU2VydmljZS5kaW1lbnNpb25zLmNzcy5jZWxsLmhlaWdodCsicHgiLHMuc3R5bGUubGluZUhlaWdodD1gJHt0aGlzLl9y"
    "ZW5kZXJTZXJ2aWNlLmRpbWVuc2lvbnMuY3NzLmNlbGwuaGVpZ2h0fXB4YDtjb25zdCByPW51bGwhPT0oaT1lLm9wdGlvbnMueCkmJnZvaWQgMCE9PWk/aTow"
    "O3JldHVybiByJiZyPnRoaXMuX2J1ZmZlclNlcnZpY2UuY29scyYmKHMuc3R5bGUuZGlzcGxheT0ibm9uZSIpLHRoaXMuX3JlZnJlc2hYUG9zaXRpb24oZSxz"
    "KSxzfV9yZWZyZXNoU3R5bGUoZSl7Y29uc3QgdD1lLm1hcmtlci5saW5lLXRoaXMuX2J1ZmZlclNlcnZpY2UuYnVmZmVycy5hY3RpdmUueWRpc3A7aWYodDww"
    "fHx0Pj10aGlzLl9idWZmZXJTZXJ2aWNlLnJvd3MpZS5lbGVtZW50JiYoZS5lbGVtZW50LnN0eWxlLmRpc3BsYXk9Im5vbmUiLGUub25SZW5kZXJFbWl0dGVy"
    "LmZpcmUoZS5lbGVtZW50KSk7ZWxzZXtsZXQgaT10aGlzLl9kZWNvcmF0aW9uRWxlbWVudHMuZ2V0KGUpO2l8fChpPXRoaXMuX2NyZWF0ZUVsZW1lbnQoZSks"
    "ZS5lbGVtZW50PWksdGhpcy5fZGVjb3JhdGlvbkVsZW1lbnRzLnNldChlLGkpLHRoaXMuX2NvbnRhaW5lci5hcHBlbmRDaGlsZChpKSxlLm9uRGlzcG9zZSgo"
    "KCk9Pnt0aGlzLl9kZWNvcmF0aW9uRWxlbWVudHMuZGVsZXRlKGUpLGkucmVtb3ZlKCl9KSkpLGkuc3R5bGUudG9wPXQqdGhpcy5fcmVuZGVyU2VydmljZS5k"
    "aW1lbnNpb25zLmNzcy5jZWxsLmhlaWdodCsicHgiLGkuc3R5bGUuZGlzcGxheT10aGlzLl9hbHRCdWZmZXJJc0FjdGl2ZT8ibm9uZSI6ImJsb2NrIixlLm9u"
    "UmVuZGVyRW1pdHRlci5maXJlKGkpfX1fcmVmcmVzaFhQb3NpdGlvbihlLHQ9ZS5lbGVtZW50KXt2YXIgaTtpZighdClyZXR1cm47Y29uc3Qgcz1udWxsIT09"
    "KGk9ZS5vcHRpb25zLngpJiZ2b2lkIDAhPT1pP2k6MDsicmlnaHQiPT09KGUub3B0aW9ucy5hbmNob3J8fCJsZWZ0Iik/dC5zdHlsZS5yaWdodD1zP3MqdGhp"
    "cy5fcmVuZGVyU2VydmljZS5kaW1lbnNpb25zLmNzcy5jZWxsLndpZHRoKyJweCI6IiI6dC5zdHlsZS5sZWZ0PXM/cyp0aGlzLl9yZW5kZXJTZXJ2aWNlLmRp"
    "bWVuc2lvbnMuY3NzLmNlbGwud2lkdGgrInB4IjoiIn1fcmVtb3ZlRGVjb3JhdGlvbihlKXt2YXIgdDtudWxsPT09KHQ9dGhpcy5fZGVjb3JhdGlvbkVsZW1l"
    "bnRzLmdldChlKSl8fHZvaWQgMD09PXR8fHQucmVtb3ZlKCksdGhpcy5fZGVjb3JhdGlvbkVsZW1lbnRzLmRlbGV0ZShlKSxlLmRpc3Bvc2UoKX19O3QuQnVm"
    "ZmVyRGVjb3JhdGlvblJlbmRlcmVyPWM9cyhbcigxLGguSUJ1ZmZlclNlcnZpY2UpLHIoMixoLklEZWNvcmF0aW9uU2VydmljZSkscigzLG8uSVJlbmRlclNl"
    "cnZpY2UpXSxjKX0sNTg3MTooZSx0KT0+e09iamVjdC5kZWZpbmVQcm9wZXJ0eSh0LCJfX2VzTW9kdWxlIix7dmFsdWU6ITB9KSx0LkNvbG9yWm9uZVN0b3Jl"
    "PXZvaWQgMCx0LkNvbG9yWm9uZVN0b3JlPWNsYXNze2NvbnN0cnVjdG9yKCl7dGhpcy5fem9uZXM9W10sdGhpcy5fem9uZVBvb2w9W10sdGhpcy5fem9uZVBv"
    "b2xJbmRleD0wLHRoaXMuX2xpbmVQYWRkaW5nPXtmdWxsOjAsbGVmdDowLGNlbnRlcjowLHJpZ2h0OjB9fWdldCB6b25lcygpe3JldHVybiB0aGlzLl96b25l"
    "UG9vbC5sZW5ndGg9TWF0aC5taW4odGhpcy5fem9uZVBvb2wubGVuZ3RoLHRoaXMuX3pvbmVzLmxlbmd0aCksdGhpcy5fem9uZXN9Y2xlYXIoKXt0aGlzLl96"
    "b25lcy5sZW5ndGg9MCx0aGlzLl96b25lUG9vbEluZGV4PTB9YWRkRGVjb3JhdGlvbihlKXtpZihlLm9wdGlvbnMub3ZlcnZpZXdSdWxlck9wdGlvbnMpe2Zv"
    "cihjb25zdCB0IG9mIHRoaXMuX3pvbmVzKWlmKHQuY29sb3I9PT1lLm9wdGlvbnMub3ZlcnZpZXdSdWxlck9wdGlvbnMuY29sb3ImJnQucG9zaXRpb249PT1l"
    "Lm9wdGlvbnMub3ZlcnZpZXdSdWxlck9wdGlvbnMucG9zaXRpb24pe2lmKHRoaXMuX2xpbmVJbnRlcnNlY3RzWm9uZSh0LGUubWFya2VyLmxpbmUpKXJldHVy"
    "bjtpZih0aGlzLl9saW5lQWRqYWNlbnRUb1pvbmUodCxlLm1hcmtlci5saW5lLGUub3B0aW9ucy5vdmVydmlld1J1bGVyT3B0aW9ucy5wb3NpdGlvbikpcmV0"
    "dXJuIHZvaWQgdGhpcy5fYWRkTGluZVRvWm9uZSh0LGUubWFya2VyLmxpbmUpfWlmKHRoaXMuX3pvbmVQb29sSW5kZXg8dGhpcy5fem9uZVBvb2wubGVuZ3Ro"
    "KXJldHVybiB0aGlzLl96b25lUG9vbFt0aGlzLl96b25lUG9vbEluZGV4XS5jb2xvcj1lLm9wdGlvbnMub3ZlcnZpZXdSdWxlck9wdGlvbnMuY29sb3IsdGhp"
    "cy5fem9uZVBvb2xbdGhpcy5fem9uZVBvb2xJbmRleF0ucG9zaXRpb249ZS5vcHRpb25zLm92ZXJ2aWV3UnVsZXJPcHRpb25zLnBvc2l0aW9uLHRoaXMuX3pv"
    "bmVQb29sW3RoaXMuX3pvbmVQb29sSW5kZXhdLnN0YXJ0QnVmZmVyTGluZT1lLm1hcmtlci5saW5lLHRoaXMuX3pvbmVQb29sW3RoaXMuX3pvbmVQb29sSW5k"
    "ZXhdLmVuZEJ1ZmZlckxpbmU9ZS5tYXJrZXIubGluZSx2b2lkIHRoaXMuX3pvbmVzLnB1c2godGhpcy5fem9uZVBvb2xbdGhpcy5fem9uZVBvb2xJbmRleCsr"
    "XSk7dGhpcy5fem9uZXMucHVzaCh7Y29sb3I6ZS5vcHRpb25zLm92ZXJ2aWV3UnVsZXJPcHRpb25zLmNvbG9yLHBvc2l0aW9uOmUub3B0aW9ucy5vdmVydmll"
    "d1J1bGVyT3B0aW9ucy5wb3NpdGlvbixzdGFydEJ1ZmZlckxpbmU6ZS5tYXJrZXIubGluZSxlbmRCdWZmZXJMaW5lOmUubWFya2VyLmxpbmV9KSx0aGlzLl96"
    "b25lUG9vbC5wdXNoKHRoaXMuX3pvbmVzW3RoaXMuX3pvbmVzLmxlbmd0aC0xXSksdGhpcy5fem9uZVBvb2xJbmRleCsrfX1zZXRQYWRkaW5nKGUpe3RoaXMu"
    "X2xpbmVQYWRkaW5nPWV9X2xpbmVJbnRlcnNlY3RzWm9uZShlLHQpe3JldHVybiB0Pj1lLnN0YXJ0QnVmZmVyTGluZSYmdDw9ZS5lbmRCdWZmZXJMaW5lfV9s"
    "aW5lQWRqYWNlbnRUb1pvbmUoZSx0LGkpe3JldHVybiB0Pj1lLnN0YXJ0QnVmZmVyTGluZS10aGlzLl9saW5lUGFkZGluZ1tpfHwiZnVsbCJdJiZ0PD1lLmVu"
    "ZEJ1ZmZlckxpbmUrdGhpcy5fbGluZVBhZGRpbmdbaXx8ImZ1bGwiXX1fYWRkTGluZVRvWm9uZShlLHQpe2Uuc3RhcnRCdWZmZXJMaW5lPU1hdGgubWluKGUu"
    "c3RhcnRCdWZmZXJMaW5lLHQpLGUuZW5kQnVmZmVyTGluZT1NYXRoLm1heChlLmVuZEJ1ZmZlckxpbmUsdCl9fX0sNTc0NDpmdW5jdGlvbihlLHQsaSl7dmFy"
    "IHM9dGhpcyYmdGhpcy5fX2RlY29yYXRlfHxmdW5jdGlvbihlLHQsaSxzKXt2YXIgcixuPWFyZ3VtZW50cy5sZW5ndGgsbz1uPDM/dDpudWxsPT09cz9zPU9i"
    "amVjdC5nZXRPd25Qcm9wZXJ0eURlc2NyaXB0b3IodCxpKTpzO2lmKCJvYmplY3QiPT10eXBlb2YgUmVmbGVjdCYmImZ1bmN0aW9uIj09dHlwZW9mIFJlZmxl"
    "Y3QuZGVjb3JhdGUpbz1SZWZsZWN0LmRlY29yYXRlKGUsdCxpLHMpO2Vsc2UgZm9yKHZhciBhPWUubGVuZ3RoLTE7YT49MDthLS0pKHI9ZVthXSkmJihvPShu"
    "PDM/cihvKTpuPjM/cih0LGksbyk6cih0LGkpKXx8byk7cmV0dXJuIG4+MyYmbyYmT2JqZWN0LmRlZmluZVByb3BlcnR5KHQsaSxvKSxvfSxyPXRoaXMmJnRo"
    "aXMuX19wYXJhbXx8ZnVuY3Rpb24oZSx0KXtyZXR1cm4gZnVuY3Rpb24oaSxzKXt0KGkscyxlKX19O09iamVjdC5kZWZpbmVQcm9wZXJ0eSh0LCJfX2VzTW9k"
    "dWxlIix7dmFsdWU6ITB9KSx0Lk92ZXJ2aWV3UnVsZXJSZW5kZXJlcj12b2lkIDA7Y29uc3Qgbj1pKDU4NzEpLG89aSgzNjU2KSxhPWkoNDcyNSksaD1pKDg0"
    "NCksYz1pKDI1ODUpLGw9e2Z1bGw6MCxsZWZ0OjAsY2VudGVyOjAscmlnaHQ6MH0sZD17ZnVsbDowLGxlZnQ6MCxjZW50ZXI6MCxyaWdodDowfSxfPXtmdWxs"
    "OjAsbGVmdDowLGNlbnRlcjowLHJpZ2h0OjB9O2xldCB1PXQuT3ZlcnZpZXdSdWxlclJlbmRlcmVyPWNsYXNzIGV4dGVuZHMgaC5EaXNwb3NhYmxle2dldCBf"
    "d2lkdGgoKXtyZXR1cm4gdGhpcy5fb3B0aW9uc1NlcnZpY2Uub3B0aW9ucy5vdmVydmlld1J1bGVyV2lkdGh8fDB9Y29uc3RydWN0b3IoZSx0LGkscyxyLG8s"
    "YSl7dmFyIGM7c3VwZXIoKSx0aGlzLl92aWV3cG9ydEVsZW1lbnQ9ZSx0aGlzLl9zY3JlZW5FbGVtZW50PXQsdGhpcy5fYnVmZmVyU2VydmljZT1pLHRoaXMu"
    "X2RlY29yYXRpb25TZXJ2aWNlPXMsdGhpcy5fcmVuZGVyU2VydmljZT1yLHRoaXMuX29wdGlvbnNTZXJ2aWNlPW8sdGhpcy5fY29yZUJyb3dzZVNlcnZpY2U9"
    "YSx0aGlzLl9jb2xvclpvbmVTdG9yZT1uZXcgbi5Db2xvclpvbmVTdG9yZSx0aGlzLl9zaG91bGRVcGRhdGVEaW1lbnNpb25zPSEwLHRoaXMuX3Nob3VsZFVw"
    "ZGF0ZUFuY2hvcj0hMCx0aGlzLl9sYXN0S25vd25CdWZmZXJMZW5ndGg9MCx0aGlzLl9jYW52YXM9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiY2FudmFzIiks"
    "dGhpcy5fY2FudmFzLmNsYXNzTGlzdC5hZGQoInh0ZXJtLWRlY29yYXRpb24tb3ZlcnZpZXctcnVsZXIiKSx0aGlzLl9yZWZyZXNoQ2FudmFzRGltZW5zaW9u"
    "cygpLG51bGw9PT0oYz10aGlzLl92aWV3cG9ydEVsZW1lbnQucGFyZW50RWxlbWVudCl8fHZvaWQgMD09PWN8fGMuaW5zZXJ0QmVmb3JlKHRoaXMuX2NhbnZh"
    "cyx0aGlzLl92aWV3cG9ydEVsZW1lbnQpO2NvbnN0IGw9dGhpcy5fY2FudmFzLmdldENvbnRleHQoIjJkIik7aWYoIWwpdGhyb3cgbmV3IEVycm9yKCJDdHgg"
    "Y2Fubm90IGJlIG51bGwiKTt0aGlzLl9jdHg9bCx0aGlzLl9yZWdpc3RlckRlY29yYXRpb25MaXN0ZW5lcnMoKSx0aGlzLl9yZWdpc3RlckJ1ZmZlckNoYW5n"
    "ZUxpc3RlbmVycygpLHRoaXMuX3JlZ2lzdGVyRGltZW5zaW9uQ2hhbmdlTGlzdGVuZXJzKCksdGhpcy5yZWdpc3RlcigoMCxoLnRvRGlzcG9zYWJsZSkoKCgp"
    "PT57dmFyIGU7bnVsbD09PShlPXRoaXMuX2NhbnZhcyl8fHZvaWQgMD09PWV8fGUucmVtb3ZlKCl9KSkpfV9yZWdpc3RlckRlY29yYXRpb25MaXN0ZW5lcnMo"
    "KXt0aGlzLnJlZ2lzdGVyKHRoaXMuX2RlY29yYXRpb25TZXJ2aWNlLm9uRGVjb3JhdGlvblJlZ2lzdGVyZWQoKCgpPT50aGlzLl9xdWV1ZVJlZnJlc2godm9p"
    "ZCAwLCEwKSkpKSx0aGlzLnJlZ2lzdGVyKHRoaXMuX2RlY29yYXRpb25TZXJ2aWNlLm9uRGVjb3JhdGlvblJlbW92ZWQoKCgpPT50aGlzLl9xdWV1ZVJlZnJl"
    "c2godm9pZCAwLCEwKSkpKX1fcmVnaXN0ZXJCdWZmZXJDaGFuZ2VMaXN0ZW5lcnMoKXt0aGlzLnJlZ2lzdGVyKHRoaXMuX3JlbmRlclNlcnZpY2Uub25SZW5k"
    "ZXJlZFZpZXdwb3J0Q2hhbmdlKCgoKT0+dGhpcy5fcXVldWVSZWZyZXNoKCkpKSksdGhpcy5yZWdpc3Rlcih0aGlzLl9idWZmZXJTZXJ2aWNlLmJ1ZmZlcnMu"
    "b25CdWZmZXJBY3RpdmF0ZSgoKCk9Pnt0aGlzLl9jYW52YXMuc3R5bGUuZGlzcGxheT10aGlzLl9idWZmZXJTZXJ2aWNlLmJ1ZmZlcj09PXRoaXMuX2J1ZmZl"
    "clNlcnZpY2UuYnVmZmVycy5hbHQ/Im5vbmUiOiJibG9jayJ9KSkpLHRoaXMucmVnaXN0ZXIodGhpcy5fYnVmZmVyU2VydmljZS5vblNjcm9sbCgoKCk9Pnt0"
    "aGlzLl9sYXN0S25vd25CdWZmZXJMZW5ndGghPT10aGlzLl9idWZmZXJTZXJ2aWNlLmJ1ZmZlcnMubm9ybWFsLmxpbmVzLmxlbmd0aCYmKHRoaXMuX3JlZnJl"
    "c2hEcmF3SGVpZ2h0Q29uc3RhbnRzKCksdGhpcy5fcmVmcmVzaENvbG9yWm9uZVBhZGRpbmcoKSl9KSkpfV9yZWdpc3RlckRpbWVuc2lvbkNoYW5nZUxpc3Rl"
    "bmVycygpe3RoaXMucmVnaXN0ZXIodGhpcy5fcmVuZGVyU2VydmljZS5vblJlbmRlcigoKCk9Pnt0aGlzLl9jb250YWluZXJIZWlnaHQmJnRoaXMuX2NvbnRh"
    "aW5lckhlaWdodD09PXRoaXMuX3NjcmVlbkVsZW1lbnQuY2xpZW50SGVpZ2h0fHwodGhpcy5fcXVldWVSZWZyZXNoKCEwKSx0aGlzLl9jb250YWluZXJIZWln"
    "aHQ9dGhpcy5fc2NyZWVuRWxlbWVudC5jbGllbnRIZWlnaHQpfSkpKSx0aGlzLnJlZ2lzdGVyKHRoaXMuX29wdGlvbnNTZXJ2aWNlLm9uU3BlY2lmaWNPcHRp"
    "b25DaGFuZ2UoIm92ZXJ2aWV3UnVsZXJXaWR0aCIsKCgpPT50aGlzLl9xdWV1ZVJlZnJlc2goITApKSkpLHRoaXMucmVnaXN0ZXIoKDAsby5hZGREaXNwb3Nh"
    "YmxlRG9tTGlzdGVuZXIpKHRoaXMuX2NvcmVCcm93c2VTZXJ2aWNlLndpbmRvdywicmVzaXplIiwoKCk9PnRoaXMuX3F1ZXVlUmVmcmVzaCghMCkpKSksdGhp"
    "cy5fcXVldWVSZWZyZXNoKCEwKX1fcmVmcmVzaERyYXdDb25zdGFudHMoKXtjb25zdCBlPU1hdGguZmxvb3IodGhpcy5fY2FudmFzLndpZHRoLzMpLHQ9TWF0"
    "aC5jZWlsKHRoaXMuX2NhbnZhcy53aWR0aC8zKTtkLmZ1bGw9dGhpcy5fY2FudmFzLndpZHRoLGQubGVmdD1lLGQuY2VudGVyPXQsZC5yaWdodD1lLHRoaXMu"
    "X3JlZnJlc2hEcmF3SGVpZ2h0Q29uc3RhbnRzKCksXy5mdWxsPTAsXy5sZWZ0PTAsXy5jZW50ZXI9ZC5sZWZ0LF8ucmlnaHQ9ZC5sZWZ0K2QuY2VudGVyfV9y"
    "ZWZyZXNoRHJhd0hlaWdodENvbnN0YW50cygpe2wuZnVsbD1NYXRoLnJvdW5kKDIqdGhpcy5fY29yZUJyb3dzZVNlcnZpY2UuZHByKTtjb25zdCBlPXRoaXMu"
    "X2NhbnZhcy5oZWlnaHQvdGhpcy5fYnVmZmVyU2VydmljZS5idWZmZXIubGluZXMubGVuZ3RoLHQ9TWF0aC5yb3VuZChNYXRoLm1heChNYXRoLm1pbihlLDEy"
    "KSw2KSp0aGlzLl9jb3JlQnJvd3NlU2VydmljZS5kcHIpO2wubGVmdD10LGwuY2VudGVyPXQsbC5yaWdodD10fV9yZWZyZXNoQ29sb3Jab25lUGFkZGluZygp"
    "e3RoaXMuX2NvbG9yWm9uZVN0b3JlLnNldFBhZGRpbmcoe2Z1bGw6TWF0aC5mbG9vcih0aGlzLl9idWZmZXJTZXJ2aWNlLmJ1ZmZlcnMuYWN0aXZlLmxpbmVz"
    "Lmxlbmd0aC8odGhpcy5fY2FudmFzLmhlaWdodC0xKSpsLmZ1bGwpLGxlZnQ6TWF0aC5mbG9vcih0aGlzLl9idWZmZXJTZXJ2aWNlLmJ1ZmZlcnMuYWN0aXZl"
    "LmxpbmVzLmxlbmd0aC8odGhpcy5fY2FudmFzLmhlaWdodC0xKSpsLmxlZnQpLGNlbnRlcjpNYXRoLmZsb29yKHRoaXMuX2J1ZmZlclNlcnZpY2UuYnVmZmVy"
    "cy5hY3RpdmUubGluZXMubGVuZ3RoLyh0aGlzLl9jYW52YXMuaGVpZ2h0LTEpKmwuY2VudGVyKSxyaWdodDpNYXRoLmZsb29yKHRoaXMuX2J1ZmZlclNlcnZp"
    "Y2UuYnVmZmVycy5hY3RpdmUubGluZXMubGVuZ3RoLyh0aGlzLl9jYW52YXMuaGVpZ2h0LTEpKmwucmlnaHQpfSksdGhpcy5fbGFzdEtub3duQnVmZmVyTGVu"
    "Z3RoPXRoaXMuX2J1ZmZlclNlcnZpY2UuYnVmZmVycy5ub3JtYWwubGluZXMubGVuZ3RofV9yZWZyZXNoQ2FudmFzRGltZW5zaW9ucygpe3RoaXMuX2NhbnZh"
    "cy5zdHlsZS53aWR0aD1gJHt0aGlzLl93aWR0aH1weGAsdGhpcy5fY2FudmFzLndpZHRoPU1hdGgucm91bmQodGhpcy5fd2lkdGgqdGhpcy5fY29yZUJyb3dz"
    "ZVNlcnZpY2UuZHByKSx0aGlzLl9jYW52YXMuc3R5bGUuaGVpZ2h0PWAke3RoaXMuX3NjcmVlbkVsZW1lbnQuY2xpZW50SGVpZ2h0fXB4YCx0aGlzLl9jYW52"
    "YXMuaGVpZ2h0PU1hdGgucm91bmQodGhpcy5fc2NyZWVuRWxlbWVudC5jbGllbnRIZWlnaHQqdGhpcy5fY29yZUJyb3dzZVNlcnZpY2UuZHByKSx0aGlzLl9y"
    "ZWZyZXNoRHJhd0NvbnN0YW50cygpLHRoaXMuX3JlZnJlc2hDb2xvclpvbmVQYWRkaW5nKCl9X3JlZnJlc2hEZWNvcmF0aW9ucygpe3RoaXMuX3Nob3VsZFVw"
    "ZGF0ZURpbWVuc2lvbnMmJnRoaXMuX3JlZnJlc2hDYW52YXNEaW1lbnNpb25zKCksdGhpcy5fY3R4LmNsZWFyUmVjdCgwLDAsdGhpcy5fY2FudmFzLndpZHRo"
    "LHRoaXMuX2NhbnZhcy5oZWlnaHQpLHRoaXMuX2NvbG9yWm9uZVN0b3JlLmNsZWFyKCk7Zm9yKGNvbnN0IGUgb2YgdGhpcy5fZGVjb3JhdGlvblNlcnZpY2Uu"
    "ZGVjb3JhdGlvbnMpdGhpcy5fY29sb3Jab25lU3RvcmUuYWRkRGVjb3JhdGlvbihlKTt0aGlzLl9jdHgubGluZVdpZHRoPTE7Y29uc3QgZT10aGlzLl9jb2xv"
    "clpvbmVTdG9yZS56b25lcztmb3IoY29uc3QgdCBvZiBlKSJmdWxsIiE9PXQucG9zaXRpb24mJnRoaXMuX3JlbmRlckNvbG9yWm9uZSh0KTtmb3IoY29uc3Qg"
    "dCBvZiBlKSJmdWxsIj09PXQucG9zaXRpb24mJnRoaXMuX3JlbmRlckNvbG9yWm9uZSh0KTt0aGlzLl9zaG91bGRVcGRhdGVEaW1lbnNpb25zPSExLHRoaXMu"
    "X3Nob3VsZFVwZGF0ZUFuY2hvcj0hMX1fcmVuZGVyQ29sb3Jab25lKGUpe3RoaXMuX2N0eC5maWxsU3R5bGU9ZS5jb2xvcix0aGlzLl9jdHguZmlsbFJlY3Qo"
    "X1tlLnBvc2l0aW9ufHwiZnVsbCJdLE1hdGgucm91bmQoKHRoaXMuX2NhbnZhcy5oZWlnaHQtMSkqKGUuc3RhcnRCdWZmZXJMaW5lL3RoaXMuX2J1ZmZlclNl"
    "cnZpY2UuYnVmZmVycy5hY3RpdmUubGluZXMubGVuZ3RoKS1sW2UucG9zaXRpb258fCJmdWxsIl0vMiksZFtlLnBvc2l0aW9ufHwiZnVsbCJdLE1hdGgucm91"
    "bmQoKHRoaXMuX2NhbnZhcy5oZWlnaHQtMSkqKChlLmVuZEJ1ZmZlckxpbmUtZS5zdGFydEJ1ZmZlckxpbmUpL3RoaXMuX2J1ZmZlclNlcnZpY2UuYnVmZmVy"
    "cy5hY3RpdmUubGluZXMubGVuZ3RoKStsW2UucG9zaXRpb258fCJmdWxsIl0pKX1fcXVldWVSZWZyZXNoKGUsdCl7dGhpcy5fc2hvdWxkVXBkYXRlRGltZW5z"
    "aW9ucz1lfHx0aGlzLl9zaG91bGRVcGRhdGVEaW1lbnNpb25zLHRoaXMuX3Nob3VsZFVwZGF0ZUFuY2hvcj10fHx0aGlzLl9zaG91bGRVcGRhdGVBbmNob3Is"
    "dm9pZCAwPT09dGhpcy5fYW5pbWF0aW9uRnJhbWUmJih0aGlzLl9hbmltYXRpb25GcmFtZT10aGlzLl9jb3JlQnJvd3NlU2VydmljZS53aW5kb3cucmVxdWVz"
    "dEFuaW1hdGlvbkZyYW1lKCgoKT0+e3RoaXMuX3JlZnJlc2hEZWNvcmF0aW9ucygpLHRoaXMuX2FuaW1hdGlvbkZyYW1lPXZvaWQgMH0pKSl9fTt0Lk92ZXJ2"
    "aWV3UnVsZXJSZW5kZXJlcj11PXMoW3IoMixjLklCdWZmZXJTZXJ2aWNlKSxyKDMsYy5JRGVjb3JhdGlvblNlcnZpY2UpLHIoNCxhLklSZW5kZXJTZXJ2aWNl"
    "KSxyKDUsYy5JT3B0aW9uc1NlcnZpY2UpLHIoNixhLklDb3JlQnJvd3NlclNlcnZpY2UpXSx1KX0sMjk1MDpmdW5jdGlvbihlLHQsaSl7dmFyIHM9dGhpcyYm"
    "dGhpcy5fX2RlY29yYXRlfHxmdW5jdGlvbihlLHQsaSxzKXt2YXIgcixuPWFyZ3VtZW50cy5sZW5ndGgsbz1uPDM/dDpudWxsPT09cz9zPU9iamVjdC5nZXRP"
    "d25Qcm9wZXJ0eURlc2NyaXB0b3IodCxpKTpzO2lmKCJvYmplY3QiPT10eXBlb2YgUmVmbGVjdCYmImZ1bmN0aW9uIj09dHlwZW9mIFJlZmxlY3QuZGVjb3Jh"
    "dGUpbz1SZWZsZWN0LmRlY29yYXRlKGUsdCxpLHMpO2Vsc2UgZm9yKHZhciBhPWUubGVuZ3RoLTE7YT49MDthLS0pKHI9ZVthXSkmJihvPShuPDM/cihvKTpu"
    "PjM/cih0LGksbyk6cih0LGkpKXx8byk7cmV0dXJuIG4+MyYmbyYmT2JqZWN0LmRlZmluZVByb3BlcnR5KHQsaSxvKSxvfSxyPXRoaXMmJnRoaXMuX19wYXJh"
    "bXx8ZnVuY3Rpb24oZSx0KXtyZXR1cm4gZnVuY3Rpb24oaSxzKXt0KGkscyxlKX19O09iamVjdC5kZWZpbmVQcm9wZXJ0eSh0LCJfX2VzTW9kdWxlIix7dmFs"
    "dWU6ITB9KSx0LkNvbXBvc2l0aW9uSGVscGVyPXZvaWQgMDtjb25zdCBuPWkoNDcyNSksbz1pKDI1ODUpLGE9aSgyNTg0KTtsZXQgaD10LkNvbXBvc2l0aW9u"
    "SGVscGVyPWNsYXNze2dldCBpc0NvbXBvc2luZygpe3JldHVybiB0aGlzLl9pc0NvbXBvc2luZ31jb25zdHJ1Y3RvcihlLHQsaSxzLHIsbil7dGhpcy5fdGV4"
    "dGFyZWE9ZSx0aGlzLl9jb21wb3NpdGlvblZpZXc9dCx0aGlzLl9idWZmZXJTZXJ2aWNlPWksdGhpcy5fb3B0aW9uc1NlcnZpY2U9cyx0aGlzLl9jb3JlU2Vy"
    "dmljZT1yLHRoaXMuX3JlbmRlclNlcnZpY2U9bix0aGlzLl9pc0NvbXBvc2luZz0hMSx0aGlzLl9pc1NlbmRpbmdDb21wb3NpdGlvbj0hMSx0aGlzLl9jb21w"
    "b3NpdGlvblBvc2l0aW9uPXtzdGFydDowLGVuZDowfSx0aGlzLl9kYXRhQWxyZWFkeVNlbnQ9IiJ9Y29tcG9zaXRpb25zdGFydCgpe3RoaXMuX2lzQ29tcG9z"
    "aW5nPSEwLHRoaXMuX2NvbXBvc2l0aW9uUG9zaXRpb24uc3RhcnQ9dGhpcy5fdGV4dGFyZWEudmFsdWUubGVuZ3RoLHRoaXMuX2NvbXBvc2l0aW9uVmlldy50"
    "ZXh0Q29udGVudD0iIix0aGlzLl9kYXRhQWxyZWFkeVNlbnQ9IiIsdGhpcy5fY29tcG9zaXRpb25WaWV3LmNsYXNzTGlzdC5hZGQoImFjdGl2ZSIpfWNvbXBv"
    "c2l0aW9udXBkYXRlKGUpe3RoaXMuX2NvbXBvc2l0aW9uVmlldy50ZXh0Q29udGVudD1lLmRhdGEsdGhpcy51cGRhdGVDb21wb3NpdGlvbkVsZW1lbnRzKCks"
    "c2V0VGltZW91dCgoKCk9Pnt0aGlzLl9jb21wb3NpdGlvblBvc2l0aW9uLmVuZD10aGlzLl90ZXh0YXJlYS52YWx1ZS5sZW5ndGh9KSwwKX1jb21wb3NpdGlv"
    "bmVuZCgpe3RoaXMuX2ZpbmFsaXplQ29tcG9zaXRpb24oITApfWtleWRvd24oZSl7aWYodGhpcy5faXNDb21wb3Npbmd8fHRoaXMuX2lzU2VuZGluZ0NvbXBv"
    "c2l0aW9uKXtpZigyMjk9PT1lLmtleUNvZGUpcmV0dXJuITE7aWYoMTY9PT1lLmtleUNvZGV8fDE3PT09ZS5rZXlDb2RlfHwxOD09PWUua2V5Q29kZSlyZXR1"
    "cm4hMTt0aGlzLl9maW5hbGl6ZUNvbXBvc2l0aW9uKCExKX1yZXR1cm4gMjI5IT09ZS5rZXlDb2RlfHwodGhpcy5faGFuZGxlQW55VGV4dGFyZWFDaGFuZ2Vz"
    "KCksITEpfV9maW5hbGl6ZUNvbXBvc2l0aW9uKGUpe2lmKHRoaXMuX2NvbXBvc2l0aW9uVmlldy5jbGFzc0xpc3QucmVtb3ZlKCJhY3RpdmUiKSx0aGlzLl9p"
    "c0NvbXBvc2luZz0hMSxlKXtjb25zdCBlPXtzdGFydDp0aGlzLl9jb21wb3NpdGlvblBvc2l0aW9uLnN0YXJ0LGVuZDp0aGlzLl9jb21wb3NpdGlvblBvc2l0"
    "aW9uLmVuZH07dGhpcy5faXNTZW5kaW5nQ29tcG9zaXRpb249ITAsc2V0VGltZW91dCgoKCk9PntpZih0aGlzLl9pc1NlbmRpbmdDb21wb3NpdGlvbil7bGV0"
    "IHQ7dGhpcy5faXNTZW5kaW5nQ29tcG9zaXRpb249ITEsZS5zdGFydCs9dGhpcy5fZGF0YUFscmVhZHlTZW50Lmxlbmd0aCx0PXRoaXMuX2lzQ29tcG9zaW5n"
    "P3RoaXMuX3RleHRhcmVhLnZhbHVlLnN1YnN0cmluZyhlLnN0YXJ0LGUuZW5kKTp0aGlzLl90ZXh0YXJlYS52YWx1ZS5zdWJzdHJpbmcoZS5zdGFydCksdC5s"
    "ZW5ndGg+MCYmdGhpcy5fY29yZVNlcnZpY2UudHJpZ2dlckRhdGFFdmVudCh0LCEwKX19KSwwKX1lbHNle3RoaXMuX2lzU2VuZGluZ0NvbXBvc2l0aW9uPSEx"
    "O2NvbnN0IGU9dGhpcy5fdGV4dGFyZWEudmFsdWUuc3Vic3RyaW5nKHRoaXMuX2NvbXBvc2l0aW9uUG9zaXRpb24uc3RhcnQsdGhpcy5fY29tcG9zaXRpb25Q"
    "b3NpdGlvbi5lbmQpO3RoaXMuX2NvcmVTZXJ2aWNlLnRyaWdnZXJEYXRhRXZlbnQoZSwhMCl9fV9oYW5kbGVBbnlUZXh0YXJlYUNoYW5nZXMoKXtjb25zdCBl"
    "PXRoaXMuX3RleHRhcmVhLnZhbHVlO3NldFRpbWVvdXQoKCgpPT57aWYoIXRoaXMuX2lzQ29tcG9zaW5nKXtjb25zdCB0PXRoaXMuX3RleHRhcmVhLnZhbHVl"
    "LGk9dC5yZXBsYWNlKGUsIiIpO3RoaXMuX2RhdGFBbHJlYWR5U2VudD1pLHQubGVuZ3RoPmUubGVuZ3RoP3RoaXMuX2NvcmVTZXJ2aWNlLnRyaWdnZXJEYXRh"
    "RXZlbnQoaSwhMCk6dC5sZW5ndGg8ZS5sZW5ndGg/dGhpcy5fY29yZVNlcnZpY2UudHJpZ2dlckRhdGFFdmVudChgJHthLkMwLkRFTH1gLCEwKTp0Lmxlbmd0"
    "aD09PWUubGVuZ3RoJiZ0IT09ZSYmdGhpcy5fY29yZVNlcnZpY2UudHJpZ2dlckRhdGFFdmVudCh0LCEwKX19KSwwKX11cGRhdGVDb21wb3NpdGlvbkVsZW1l"
    "bnRzKGUpe2lmKHRoaXMuX2lzQ29tcG9zaW5nKXtpZih0aGlzLl9idWZmZXJTZXJ2aWNlLmJ1ZmZlci5pc0N1cnNvckluVmlld3BvcnQpe2NvbnN0IGU9TWF0"
    "aC5taW4odGhpcy5fYnVmZmVyU2VydmljZS5idWZmZXIueCx0aGlzLl9idWZmZXJTZXJ2aWNlLmNvbHMtMSksdD10aGlzLl9yZW5kZXJTZXJ2aWNlLmRpbWVu"
    "c2lvbnMuY3NzLmNlbGwuaGVpZ2h0LGk9dGhpcy5fYnVmZmVyU2VydmljZS5idWZmZXIueSp0aGlzLl9yZW5kZXJTZXJ2aWNlLmRpbWVuc2lvbnMuY3NzLmNl"
    "bGwuaGVpZ2h0LHM9ZSp0aGlzLl9yZW5kZXJTZXJ2aWNlLmRpbWVuc2lvbnMuY3NzLmNlbGwud2lkdGg7dGhpcy5fY29tcG9zaXRpb25WaWV3LnN0eWxlLmxl"
    "ZnQ9cysicHgiLHRoaXMuX2NvbXBvc2l0aW9uVmlldy5zdHlsZS50b3A9aSsicHgiLHRoaXMuX2NvbXBvc2l0aW9uVmlldy5zdHlsZS5oZWlnaHQ9dCsicHgi"
    "LHRoaXMuX2NvbXBvc2l0aW9uVmlldy5zdHlsZS5saW5lSGVpZ2h0PXQrInB4Iix0aGlzLl9jb21wb3NpdGlvblZpZXcuc3R5bGUuZm9udEZhbWlseT10aGlz"
    "Ll9vcHRpb25zU2VydmljZS5yYXdPcHRpb25zLmZvbnRGYW1pbHksdGhpcy5fY29tcG9zaXRpb25WaWV3LnN0eWxlLmZvbnRTaXplPXRoaXMuX29wdGlvbnNT"
    "ZXJ2aWNlLnJhd09wdGlvbnMuZm9udFNpemUrInB4Ijtjb25zdCByPXRoaXMuX2NvbXBvc2l0aW9uVmlldy5nZXRCb3VuZGluZ0NsaWVudFJlY3QoKTt0aGlz"
    "Ll90ZXh0YXJlYS5zdHlsZS5sZWZ0PXMrInB4Iix0aGlzLl90ZXh0YXJlYS5zdHlsZS50b3A9aSsicHgiLHRoaXMuX3RleHRhcmVhLnN0eWxlLndpZHRoPU1h"
    "dGgubWF4KHIud2lkdGgsMSkrInB4Iix0aGlzLl90ZXh0YXJlYS5zdHlsZS5oZWlnaHQ9TWF0aC5tYXgoci5oZWlnaHQsMSkrInB4Iix0aGlzLl90ZXh0YXJl"
    "YS5zdHlsZS5saW5lSGVpZ2h0PXIuaGVpZ2h0KyJweCJ9ZXx8c2V0VGltZW91dCgoKCk9PnRoaXMudXBkYXRlQ29tcG9zaXRpb25FbGVtZW50cyghMCkpLDAp"
    "fX19O3QuQ29tcG9zaXRpb25IZWxwZXI9aD1zKFtyKDIsby5JQnVmZmVyU2VydmljZSkscigzLG8uSU9wdGlvbnNTZXJ2aWNlKSxyKDQsby5JQ29yZVNlcnZp"
    "Y2UpLHIoNSxuLklSZW5kZXJTZXJ2aWNlKV0saCl9LDk4MDY6KGUsdCk9PntmdW5jdGlvbiBpKGUsdCxpKXtjb25zdCBzPWkuZ2V0Qm91bmRpbmdDbGllbnRS"
    "ZWN0KCkscj1lLmdldENvbXB1dGVkU3R5bGUoaSksbj1wYXJzZUludChyLmdldFByb3BlcnR5VmFsdWUoInBhZGRpbmctbGVmdCIpKSxvPXBhcnNlSW50KHIu"
    "Z2V0UHJvcGVydHlWYWx1ZSgicGFkZGluZy10b3AiKSk7cmV0dXJuW3QuY2xpZW50WC1zLmxlZnQtbix0LmNsaWVudFktcy50b3Atb119T2JqZWN0LmRlZmlu"
    "ZVByb3BlcnR5KHQsIl9fZXNNb2R1bGUiLHt2YWx1ZTohMH0pLHQuZ2V0Q29vcmRzPXQuZ2V0Q29vcmRzUmVsYXRpdmVUb0VsZW1lbnQ9dm9pZCAwLHQuZ2V0"
    "Q29vcmRzUmVsYXRpdmVUb0VsZW1lbnQ9aSx0LmdldENvb3Jkcz1mdW5jdGlvbihlLHQscyxyLG4sbyxhLGgsYyl7aWYoIW8pcmV0dXJuO2NvbnN0IGw9aShl"
    "LHQscyk7cmV0dXJuIGw/KGxbMF09TWF0aC5jZWlsKChsWzBdKyhjP2EvMjowKSkvYSksbFsxXT1NYXRoLmNlaWwobFsxXS9oKSxsWzBdPU1hdGgubWluKE1h"
    "dGgubWF4KGxbMF0sMSkscisoYz8xOjApKSxsWzFdPU1hdGgubWluKE1hdGgubWF4KGxbMV0sMSksbiksbCk6dm9pZCAwfX0sOTUwNDooZSx0LGkpPT57T2Jq"
    "ZWN0LmRlZmluZVByb3BlcnR5KHQsIl9fZXNNb2R1bGUiLHt2YWx1ZTohMH0pLHQubW92ZVRvQ2VsbFNlcXVlbmNlPXZvaWQgMDtjb25zdCBzPWkoMjU4NCk7"
    "ZnVuY3Rpb24gcihlLHQsaSxzKXtjb25zdCByPWUtbihlLGkpLGE9dC1uKHQsaSksbD1NYXRoLmFicyhyLWEpLWZ1bmN0aW9uKGUsdCxpKXtsZXQgcz0wO2Nv"
    "bnN0IHI9ZS1uKGUsaSksYT10LW4odCxpKTtmb3IobGV0IG49MDtuPE1hdGguYWJzKHItYSk7bisrKXtjb25zdCBhPSJBIj09PW8oZSx0KT8tMToxLGg9aS5i"
    "dWZmZXIubGluZXMuZ2V0KHIrYSpuKTsobnVsbD09aD92b2lkIDA6aC5pc1dyYXBwZWQpJiZzKyt9cmV0dXJuIHN9KGUsdCxpKTtyZXR1cm4gYyhsLGgobyhl"
    "LHQpLHMpKX1mdW5jdGlvbiBuKGUsdCl7bGV0IGk9MCxzPXQuYnVmZmVyLmxpbmVzLmdldChlKSxyPW51bGw9PXM/dm9pZCAwOnMuaXNXcmFwcGVkO2Zvcig7"
    "ciYmZT49MCYmZTx0LnJvd3M7KWkrKyxzPXQuYnVmZmVyLmxpbmVzLmdldCgtLWUpLHI9bnVsbD09cz92b2lkIDA6cy5pc1dyYXBwZWQ7cmV0dXJuIGl9ZnVu"
    "Y3Rpb24gbyhlLHQpe3JldHVybiBlPnQ/IkEiOiJCIn1mdW5jdGlvbiBhKGUsdCxpLHMscixuKXtsZXQgbz1lLGE9dCxoPSIiO2Zvcig7byE9PWl8fGEhPT1z"
    "OylvKz1yPzE6LTEsciYmbz5uLmNvbHMtMT8oaCs9bi5idWZmZXIudHJhbnNsYXRlQnVmZmVyTGluZVRvU3RyaW5nKGEsITEsZSxvKSxvPTAsZT0wLGErKyk6"
    "IXImJm88MCYmKGgrPW4uYnVmZmVyLnRyYW5zbGF0ZUJ1ZmZlckxpbmVUb1N0cmluZyhhLCExLDAsZSsxKSxvPW4uY29scy0xLGU9byxhLS0pO3JldHVybiBo"
    "K24uYnVmZmVyLnRyYW5zbGF0ZUJ1ZmZlckxpbmVUb1N0cmluZyhhLCExLGUsbyl9ZnVuY3Rpb24gaChlLHQpe2NvbnN0IGk9dD8iTyI6IlsiO3JldHVybiBz"
    "LkMwLkVTQytpK2V9ZnVuY3Rpb24gYyhlLHQpe2U9TWF0aC5mbG9vcihlKTtsZXQgaT0iIjtmb3IobGV0IHM9MDtzPGU7cysrKWkrPXQ7cmV0dXJuIGl9dC5t"
    "b3ZlVG9DZWxsU2VxdWVuY2U9ZnVuY3Rpb24oZSx0LGkscyl7Y29uc3Qgbz1pLmJ1ZmZlci54LGw9aS5idWZmZXIueTtpZighaS5idWZmZXIuaGFzU2Nyb2xs"
    "YmFjaylyZXR1cm4gZnVuY3Rpb24oZSx0LGkscyxvLGwpe3JldHVybiAwPT09cih0LHMsbyxsKS5sZW5ndGg/IiI6YyhhKGUsdCxlLHQtbih0LG8pLCExLG8p"
    "Lmxlbmd0aCxoKCJEIixsKSl9KG8sbCwwLHQsaSxzKStyKGwsdCxpLHMpK2Z1bmN0aW9uKGUsdCxpLHMsbyxsKXtsZXQgZDtkPXIodCxzLG8sbCkubGVuZ3Ro"
    "PjA/cy1uKHMsbyk6dDtjb25zdCBfPXMsdT1mdW5jdGlvbihlLHQsaSxzLG8sYSl7bGV0IGg7cmV0dXJuIGg9cihpLHMsbyxhKS5sZW5ndGg+MD9zLW4ocyxv"
    "KTp0LGU8aSYmaDw9c3x8ZT49aSYmaDxzPyJDIjoiRCJ9KGUsdCxpLHMsbyxsKTtyZXR1cm4gYyhhKGUsZCxpLF8sIkMiPT09dSxvKS5sZW5ndGgsaCh1LGwp"
    "KX0obyxsLGUsdCxpLHMpO2xldCBkO2lmKGw9PT10KXJldHVybiBkPW8+ZT8iRCI6IkMiLGMoTWF0aC5hYnMoby1lKSxoKGQscykpO2Q9bD50PyJEIjoiQyI7"
    "Y29uc3QgXz1NYXRoLmFicyhsLXQpO3JldHVybiBjKGZ1bmN0aW9uKGUsdCl7cmV0dXJuIHQuY29scy1lfShsPnQ/ZTpvLGkpKyhfLTEpKmkuY29scysxKygo"
    "bD50P286ZSktMSksaChkLHMpKX19LDEyOTY6ZnVuY3Rpb24oZSx0LGkpe3ZhciBzPXRoaXMmJnRoaXMuX19kZWNvcmF0ZXx8ZnVuY3Rpb24oZSx0LGkscyl7"
    "dmFyIHIsbj1hcmd1bWVudHMubGVuZ3RoLG89bjwzP3Q6bnVsbD09PXM/cz1PYmplY3QuZ2V0T3duUHJvcGVydHlEZXNjcmlwdG9yKHQsaSk6cztpZigib2Jq"
    "ZWN0Ij09dHlwZW9mIFJlZmxlY3QmJiJmdW5jdGlvbiI9PXR5cGVvZiBSZWZsZWN0LmRlY29yYXRlKW89UmVmbGVjdC5kZWNvcmF0ZShlLHQsaSxzKTtlbHNl"
    "IGZvcih2YXIgYT1lLmxlbmd0aC0xO2E+PTA7YS0tKShyPWVbYV0pJiYobz0objwzP3Iobyk6bj4zP3IodCxpLG8pOnIodCxpKSl8fG8pO3JldHVybiBuPjMm"
    "Jm8mJk9iamVjdC5kZWZpbmVQcm9wZXJ0eSh0LGksbyksb30scj10aGlzJiZ0aGlzLl9fcGFyYW18fGZ1bmN0aW9uKGUsdCl7cmV0dXJuIGZ1bmN0aW9uKGks"
    "cyl7dChpLHMsZSl9fTtPYmplY3QuZGVmaW5lUHJvcGVydHkodCwiX19lc01vZHVsZSIse3ZhbHVlOiEwfSksdC5Eb21SZW5kZXJlcj12b2lkIDA7Y29uc3Qg"
    "bj1pKDM3ODcpLG89aSgyNTUwKSxhPWkoMjIyMyksaD1pKDYxNzEpLGM9aSg0NzI1KSxsPWkoODA1NSksZD1pKDg0NjApLF89aSg4NDQpLHU9aSgyNTg1KSxm"
    "PSJ4dGVybS1kb20tcmVuZGVyZXItb3duZXItIix2PSJ4dGVybS1yb3dzIixwPSJ4dGVybS1mZy0iLGc9Inh0ZXJtLWJnLSIsbT0ieHRlcm0tZm9jdXMiLFM9"
    "Inh0ZXJtLXNlbGVjdGlvbiI7bGV0IEM9MSxiPXQuRG9tUmVuZGVyZXI9Y2xhc3MgZXh0ZW5kcyBfLkRpc3Bvc2FibGV7Y29uc3RydWN0b3IoZSx0LGkscyxy"
    "LGEsYyxsLHUscCl7c3VwZXIoKSx0aGlzLl9lbGVtZW50PWUsdGhpcy5fc2NyZWVuRWxlbWVudD10LHRoaXMuX3ZpZXdwb3J0RWxlbWVudD1pLHRoaXMuX2xp"
    "bmtpZmllcjI9cyx0aGlzLl9jaGFyU2l6ZVNlcnZpY2U9YSx0aGlzLl9vcHRpb25zU2VydmljZT1jLHRoaXMuX2J1ZmZlclNlcnZpY2U9bCx0aGlzLl9jb3Jl"
    "QnJvd3NlclNlcnZpY2U9dSx0aGlzLl90aGVtZVNlcnZpY2U9cCx0aGlzLl90ZXJtaW5hbENsYXNzPUMrKyx0aGlzLl9yb3dFbGVtZW50cz1bXSx0aGlzLm9u"
    "UmVxdWVzdFJlZHJhdz10aGlzLnJlZ2lzdGVyKG5ldyBkLkV2ZW50RW1pdHRlcikuZXZlbnQsdGhpcy5fcm93Q29udGFpbmVyPWRvY3VtZW50LmNyZWF0ZUVs"
    "ZW1lbnQoImRpdiIpLHRoaXMuX3Jvd0NvbnRhaW5lci5jbGFzc0xpc3QuYWRkKHYpLHRoaXMuX3Jvd0NvbnRhaW5lci5zdHlsZS5saW5lSGVpZ2h0PSJub3Jt"
    "YWwiLHRoaXMuX3Jvd0NvbnRhaW5lci5zZXRBdHRyaWJ1dGUoImFyaWEtaGlkZGVuIiwidHJ1ZSIpLHRoaXMuX3JlZnJlc2hSb3dFbGVtZW50cyh0aGlzLl9i"
    "dWZmZXJTZXJ2aWNlLmNvbHMsdGhpcy5fYnVmZmVyU2VydmljZS5yb3dzKSx0aGlzLl9zZWxlY3Rpb25Db250YWluZXI9ZG9jdW1lbnQuY3JlYXRlRWxlbWVu"
    "dCgiZGl2IiksdGhpcy5fc2VsZWN0aW9uQ29udGFpbmVyLmNsYXNzTGlzdC5hZGQoUyksdGhpcy5fc2VsZWN0aW9uQ29udGFpbmVyLnNldEF0dHJpYnV0ZSgi"
    "YXJpYS1oaWRkZW4iLCJ0cnVlIiksdGhpcy5kaW1lbnNpb25zPSgwLGguY3JlYXRlUmVuZGVyRGltZW5zaW9ucykoKSx0aGlzLl91cGRhdGVEaW1lbnNpb25z"
    "KCksdGhpcy5yZWdpc3Rlcih0aGlzLl9vcHRpb25zU2VydmljZS5vbk9wdGlvbkNoYW5nZSgoKCk9PnRoaXMuX2hhbmRsZU9wdGlvbnNDaGFuZ2VkKCkpKSks"
    "dGhpcy5yZWdpc3Rlcih0aGlzLl90aGVtZVNlcnZpY2Uub25DaGFuZ2VDb2xvcnMoKGU9PnRoaXMuX2luamVjdENzcyhlKSkpKSx0aGlzLl9pbmplY3RDc3Mo"
    "dGhpcy5fdGhlbWVTZXJ2aWNlLmNvbG9ycyksdGhpcy5fcm93RmFjdG9yeT1yLmNyZWF0ZUluc3RhbmNlKG4uRG9tUmVuZGVyZXJSb3dGYWN0b3J5LGRvY3Vt"
    "ZW50KSx0aGlzLl9lbGVtZW50LmNsYXNzTGlzdC5hZGQoZit0aGlzLl90ZXJtaW5hbENsYXNzKSx0aGlzLl9zY3JlZW5FbGVtZW50LmFwcGVuZENoaWxkKHRo"
    "aXMuX3Jvd0NvbnRhaW5lciksdGhpcy5fc2NyZWVuRWxlbWVudC5hcHBlbmRDaGlsZCh0aGlzLl9zZWxlY3Rpb25Db250YWluZXIpLHRoaXMucmVnaXN0ZXIo"
    "dGhpcy5fbGlua2lmaWVyMi5vblNob3dMaW5rVW5kZXJsaW5lKChlPT50aGlzLl9oYW5kbGVMaW5rSG92ZXIoZSkpKSksdGhpcy5yZWdpc3Rlcih0aGlzLl9s"
    "aW5raWZpZXIyLm9uSGlkZUxpbmtVbmRlcmxpbmUoKGU9PnRoaXMuX2hhbmRsZUxpbmtMZWF2ZShlKSkpKSx0aGlzLnJlZ2lzdGVyKCgwLF8udG9EaXNwb3Nh"
    "YmxlKSgoKCk9Pnt0aGlzLl9lbGVtZW50LmNsYXNzTGlzdC5yZW1vdmUoZit0aGlzLl90ZXJtaW5hbENsYXNzKSx0aGlzLl9yb3dDb250YWluZXIucmVtb3Zl"
    "KCksdGhpcy5fc2VsZWN0aW9uQ29udGFpbmVyLnJlbW92ZSgpLHRoaXMuX3dpZHRoQ2FjaGUuZGlzcG9zZSgpLHRoaXMuX3RoZW1lU3R5bGVFbGVtZW50LnJl"
    "bW92ZSgpLHRoaXMuX2RpbWVuc2lvbnNTdHlsZUVsZW1lbnQucmVtb3ZlKCl9KSkpLHRoaXMuX3dpZHRoQ2FjaGU9bmV3IG8uV2lkdGhDYWNoZShkb2N1bWVu"
    "dCksdGhpcy5fd2lkdGhDYWNoZS5zZXRGb250KHRoaXMuX29wdGlvbnNTZXJ2aWNlLnJhd09wdGlvbnMuZm9udEZhbWlseSx0aGlzLl9vcHRpb25zU2Vydmlj"
    "ZS5yYXdPcHRpb25zLmZvbnRTaXplLHRoaXMuX29wdGlvbnNTZXJ2aWNlLnJhd09wdGlvbnMuZm9udFdlaWdodCx0aGlzLl9vcHRpb25zU2VydmljZS5yYXdP"
    "cHRpb25zLmZvbnRXZWlnaHRCb2xkKSx0aGlzLl9zZXREZWZhdWx0U3BhY2luZygpfV91cGRhdGVEaW1lbnNpb25zKCl7Y29uc3QgZT10aGlzLl9jb3JlQnJv"
    "d3NlclNlcnZpY2UuZHByO3RoaXMuZGltZW5zaW9ucy5kZXZpY2UuY2hhci53aWR0aD10aGlzLl9jaGFyU2l6ZVNlcnZpY2Uud2lkdGgqZSx0aGlzLmRpbWVu"
    "c2lvbnMuZGV2aWNlLmNoYXIuaGVpZ2h0PU1hdGguY2VpbCh0aGlzLl9jaGFyU2l6ZVNlcnZpY2UuaGVpZ2h0KmUpLHRoaXMuZGltZW5zaW9ucy5kZXZpY2Uu"
    "Y2VsbC53aWR0aD10aGlzLmRpbWVuc2lvbnMuZGV2aWNlLmNoYXIud2lkdGgrTWF0aC5yb3VuZCh0aGlzLl9vcHRpb25zU2VydmljZS5yYXdPcHRpb25zLmxl"
    "dHRlclNwYWNpbmcpLHRoaXMuZGltZW5zaW9ucy5kZXZpY2UuY2VsbC5oZWlnaHQ9TWF0aC5mbG9vcih0aGlzLmRpbWVuc2lvbnMuZGV2aWNlLmNoYXIuaGVp"
    "Z2h0KnRoaXMuX29wdGlvbnNTZXJ2aWNlLnJhd09wdGlvbnMubGluZUhlaWdodCksdGhpcy5kaW1lbnNpb25zLmRldmljZS5jaGFyLmxlZnQ9MCx0aGlzLmRp"
    "bWVuc2lvbnMuZGV2aWNlLmNoYXIudG9wPTAsdGhpcy5kaW1lbnNpb25zLmRldmljZS5jYW52YXMud2lkdGg9dGhpcy5kaW1lbnNpb25zLmRldmljZS5jZWxs"
    "LndpZHRoKnRoaXMuX2J1ZmZlclNlcnZpY2UuY29scyx0aGlzLmRpbWVuc2lvbnMuZGV2aWNlLmNhbnZhcy5oZWlnaHQ9dGhpcy5kaW1lbnNpb25zLmRldmlj"
    "ZS5jZWxsLmhlaWdodCp0aGlzLl9idWZmZXJTZXJ2aWNlLnJvd3MsdGhpcy5kaW1lbnNpb25zLmNzcy5jYW52YXMud2lkdGg9TWF0aC5yb3VuZCh0aGlzLmRp"
    "bWVuc2lvbnMuZGV2aWNlLmNhbnZhcy53aWR0aC9lKSx0aGlzLmRpbWVuc2lvbnMuY3NzLmNhbnZhcy5oZWlnaHQ9TWF0aC5yb3VuZCh0aGlzLmRpbWVuc2lv"
    "bnMuZGV2aWNlLmNhbnZhcy5oZWlnaHQvZSksdGhpcy5kaW1lbnNpb25zLmNzcy5jZWxsLndpZHRoPXRoaXMuZGltZW5zaW9ucy5jc3MuY2FudmFzLndpZHRo"
    "L3RoaXMuX2J1ZmZlclNlcnZpY2UuY29scyx0aGlzLmRpbWVuc2lvbnMuY3NzLmNlbGwuaGVpZ2h0PXRoaXMuZGltZW5zaW9ucy5jc3MuY2FudmFzLmhlaWdo"
    "dC90aGlzLl9idWZmZXJTZXJ2aWNlLnJvd3M7Zm9yKGNvbnN0IGUgb2YgdGhpcy5fcm93RWxlbWVudHMpZS5zdHlsZS53aWR0aD1gJHt0aGlzLmRpbWVuc2lv"
    "bnMuY3NzLmNhbnZhcy53aWR0aH1weGAsZS5zdHlsZS5oZWlnaHQ9YCR7dGhpcy5kaW1lbnNpb25zLmNzcy5jZWxsLmhlaWdodH1weGAsZS5zdHlsZS5saW5l"
    "SGVpZ2h0PWAke3RoaXMuZGltZW5zaW9ucy5jc3MuY2VsbC5oZWlnaHR9cHhgLGUuc3R5bGUub3ZlcmZsb3c9ImhpZGRlbiI7dGhpcy5fZGltZW5zaW9uc1N0"
    "eWxlRWxlbWVudHx8KHRoaXMuX2RpbWVuc2lvbnNTdHlsZUVsZW1lbnQ9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3R5bGUiKSx0aGlzLl9zY3JlZW5FbGVt"
    "ZW50LmFwcGVuZENoaWxkKHRoaXMuX2RpbWVuc2lvbnNTdHlsZUVsZW1lbnQpKTtjb25zdCB0PWAke3RoaXMuX3Rlcm1pbmFsU2VsZWN0b3J9IC4ke3Z9IHNw"
    "YW4geyBkaXNwbGF5OiBpbmxpbmUtYmxvY2s7IGhlaWdodDogMTAwJTsgdmVydGljYWwtYWxpZ246IHRvcDt9YDt0aGlzLl9kaW1lbnNpb25zU3R5bGVFbGVt"
    "ZW50LnRleHRDb250ZW50PXQsdGhpcy5fc2VsZWN0aW9uQ29udGFpbmVyLnN0eWxlLmhlaWdodD10aGlzLl92aWV3cG9ydEVsZW1lbnQuc3R5bGUuaGVpZ2h0"
    "LHRoaXMuX3NjcmVlbkVsZW1lbnQuc3R5bGUud2lkdGg9YCR7dGhpcy5kaW1lbnNpb25zLmNzcy5jYW52YXMud2lkdGh9cHhgLHRoaXMuX3NjcmVlbkVsZW1l"
    "bnQuc3R5bGUuaGVpZ2h0PWAke3RoaXMuZGltZW5zaW9ucy5jc3MuY2FudmFzLmhlaWdodH1weGB9X2luamVjdENzcyhlKXt0aGlzLl90aGVtZVN0eWxlRWxl"
    "bWVudHx8KHRoaXMuX3RoZW1lU3R5bGVFbGVtZW50PWRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInN0eWxlIiksdGhpcy5fc2NyZWVuRWxlbWVudC5hcHBlbmRD"
    "aGlsZCh0aGlzLl90aGVtZVN0eWxlRWxlbWVudCkpO2xldCB0PWAke3RoaXMuX3Rlcm1pbmFsU2VsZWN0b3J9IC4ke3Z9IHsgY29sb3I6ICR7ZS5mb3JlZ3Jv"
    "dW5kLmNzc307IGZvbnQtZmFtaWx5OiAke3RoaXMuX29wdGlvbnNTZXJ2aWNlLnJhd09wdGlvbnMuZm9udEZhbWlseX07IGZvbnQtc2l6ZTogJHt0aGlzLl9v"
    "cHRpb25zU2VydmljZS5yYXdPcHRpb25zLmZvbnRTaXplfXB4OyBmb250LWtlcm5pbmc6IG5vbmU7IHdoaXRlLXNwYWNlOiBwcmV9YDt0Kz1gJHt0aGlzLl90"
    "ZXJtaW5hbFNlbGVjdG9yfSAuJHt2fSAueHRlcm0tZGltIHsgY29sb3I6ICR7bC5jb2xvci5tdWx0aXBseU9wYWNpdHkoZS5mb3JlZ3JvdW5kLC41KS5jc3N9"
    "O31gLHQrPWAke3RoaXMuX3Rlcm1pbmFsU2VsZWN0b3J9IHNwYW46bm90KC54dGVybS1ib2xkKSB7IGZvbnQtd2VpZ2h0OiAke3RoaXMuX29wdGlvbnNTZXJ2"
    "aWNlLnJhd09wdGlvbnMuZm9udFdlaWdodH07fSR7dGhpcy5fdGVybWluYWxTZWxlY3Rvcn0gc3Bhbi54dGVybS1ib2xkIHsgZm9udC13ZWlnaHQ6ICR7dGhp"
    "cy5fb3B0aW9uc1NlcnZpY2UucmF3T3B0aW9ucy5mb250V2VpZ2h0Qm9sZH07fSR7dGhpcy5fdGVybWluYWxTZWxlY3Rvcn0gc3Bhbi54dGVybS1pdGFsaWMg"
    "eyBmb250LXN0eWxlOiBpdGFsaWM7fWAsdCs9IkBrZXlmcmFtZXMgYmxpbmtfYm94X3NoYWRvd18iK3RoaXMuX3Rlcm1pbmFsQ2xhc3MrIiB7IDUwJSB7ICBi"
    "b3JkZXItYm90dG9tLXN0eWxlOiBoaWRkZW47IH19Iix0Kz0iQGtleWZyYW1lcyBibGlua19ibG9ja18iK3RoaXMuX3Rlcm1pbmFsQ2xhc3MrIiB7IDAlIHsi"
    "K2AgIGJhY2tncm91bmQtY29sb3I6ICR7ZS5jdXJzb3IuY3NzfTtgK2AgIGNvbG9yOiAke2UuY3Vyc29yQWNjZW50LmNzc307IH0gNTAlIHsgIGJhY2tncm91"
    "bmQtY29sb3I6IGluaGVyaXQ7YCtgICBjb2xvcjogJHtlLmN1cnNvci5jc3N9OyB9fWAsdCs9YCR7dGhpcy5fdGVybWluYWxTZWxlY3Rvcn0gLiR7dn0uJHtt"
    "fSAueHRlcm0tY3Vyc29yLnh0ZXJtLWN1cnNvci1ibGluazpub3QoLnh0ZXJtLWN1cnNvci1ibG9jaykgeyBhbmltYXRpb246IGJsaW5rX2JveF9zaGFkb3df"
    "YCt0aGlzLl90ZXJtaW5hbENsYXNzKyIgMXMgc3RlcC1lbmQgaW5maW5pdGU7fSIrYCR7dGhpcy5fdGVybWluYWxTZWxlY3Rvcn0gLiR7dn0uJHttfSAueHRl"
    "cm0tY3Vyc29yLnh0ZXJtLWN1cnNvci1ibGluay54dGVybS1jdXJzb3ItYmxvY2sgeyBhbmltYXRpb246IGJsaW5rX2Jsb2NrX2ArdGhpcy5fdGVybWluYWxD"
    "bGFzcysiIDFzIHN0ZXAtZW5kIGluZmluaXRlO30iK2Ake3RoaXMuX3Rlcm1pbmFsU2VsZWN0b3J9IC4ke3Z9IC54dGVybS1jdXJzb3IueHRlcm0tY3Vyc29y"
    "LWJsb2NrIHtgK2AgYmFja2dyb3VuZC1jb2xvcjogJHtlLmN1cnNvci5jc3N9O2ArYCBjb2xvcjogJHtlLmN1cnNvckFjY2VudC5jc3N9O31gK2Ake3RoaXMu"
    "X3Rlcm1pbmFsU2VsZWN0b3J9IC4ke3Z9IC54dGVybS1jdXJzb3IueHRlcm0tY3Vyc29yLW91dGxpbmUge2ArYCBvdXRsaW5lOiAxcHggc29saWQgJHtlLmN1"
    "cnNvci5jc3N9OyBvdXRsaW5lLW9mZnNldDogLTFweDt9YCtgJHt0aGlzLl90ZXJtaW5hbFNlbGVjdG9yfSAuJHt2fSAueHRlcm0tY3Vyc29yLnh0ZXJtLWN1"
    "cnNvci1iYXIge2ArYCBib3gtc2hhZG93OiAke3RoaXMuX29wdGlvbnNTZXJ2aWNlLnJhd09wdGlvbnMuY3Vyc29yV2lkdGh9cHggMCAwICR7ZS5jdXJzb3Iu"
    "Y3NzfSBpbnNldDt9YCtgJHt0aGlzLl90ZXJtaW5hbFNlbGVjdG9yfSAuJHt2fSAueHRlcm0tY3Vyc29yLnh0ZXJtLWN1cnNvci11bmRlcmxpbmUge2ArYCBi"
    "b3JkZXItYm90dG9tOiAxcHggJHtlLmN1cnNvci5jc3N9OyBib3JkZXItYm90dG9tLXN0eWxlOiBzb2xpZDsgaGVpZ2h0OiBjYWxjKDEwMCUgLSAxcHgpO31g"
    "LHQrPWAke3RoaXMuX3Rlcm1pbmFsU2VsZWN0b3J9IC4ke1N9IHsgcG9zaXRpb246IGFic29sdXRlOyB0b3A6IDA7IGxlZnQ6IDA7IHotaW5kZXg6IDE7IHBv"
    "aW50ZXItZXZlbnRzOiBub25lO30ke3RoaXMuX3Rlcm1pbmFsU2VsZWN0b3J9LmZvY3VzIC4ke1N9IGRpdiB7IHBvc2l0aW9uOiBhYnNvbHV0ZTsgYmFja2dy"
    "b3VuZC1jb2xvcjogJHtlLnNlbGVjdGlvbkJhY2tncm91bmRPcGFxdWUuY3NzfTt9JHt0aGlzLl90ZXJtaW5hbFNlbGVjdG9yfSAuJHtTfSBkaXYgeyBwb3Np"
    "dGlvbjogYWJzb2x1dGU7IGJhY2tncm91bmQtY29sb3I6ICR7ZS5zZWxlY3Rpb25JbmFjdGl2ZUJhY2tncm91bmRPcGFxdWUuY3NzfTt9YDtmb3IoY29uc3Rb"
    "aSxzXW9mIGUuYW5zaS5lbnRyaWVzKCkpdCs9YCR7dGhpcy5fdGVybWluYWxTZWxlY3Rvcn0gLiR7cH0ke2l9IHsgY29sb3I6ICR7cy5jc3N9OyB9JHt0aGlz"
    "Ll90ZXJtaW5hbFNlbGVjdG9yfSAuJHtwfSR7aX0ueHRlcm0tZGltIHsgY29sb3I6ICR7bC5jb2xvci5tdWx0aXBseU9wYWNpdHkocywuNSkuY3NzfTsgfSR7"
    "dGhpcy5fdGVybWluYWxTZWxlY3Rvcn0gLiR7Z30ke2l9IHsgYmFja2dyb3VuZC1jb2xvcjogJHtzLmNzc307IH1gO3QrPWAke3RoaXMuX3Rlcm1pbmFsU2Vs"
    "ZWN0b3J9IC4ke3B9JHthLklOVkVSVEVEX0RFRkFVTFRfQ09MT1J9IHsgY29sb3I6ICR7bC5jb2xvci5vcGFxdWUoZS5iYWNrZ3JvdW5kKS5jc3N9OyB9JHt0"
    "aGlzLl90ZXJtaW5hbFNlbGVjdG9yfSAuJHtwfSR7YS5JTlZFUlRFRF9ERUZBVUxUX0NPTE9SfS54dGVybS1kaW0geyBjb2xvcjogJHtsLmNvbG9yLm11bHRp"
    "cGx5T3BhY2l0eShsLmNvbG9yLm9wYXF1ZShlLmJhY2tncm91bmQpLC41KS5jc3N9OyB9JHt0aGlzLl90ZXJtaW5hbFNlbGVjdG9yfSAuJHtnfSR7YS5JTlZF"
    "UlRFRF9ERUZBVUxUX0NPTE9SfSB7IGJhY2tncm91bmQtY29sb3I6ICR7ZS5mb3JlZ3JvdW5kLmNzc307IH1gLHRoaXMuX3RoZW1lU3R5bGVFbGVtZW50LnRl"
    "eHRDb250ZW50PXR9X3NldERlZmF1bHRTcGFjaW5nKCl7Y29uc3QgZT10aGlzLmRpbWVuc2lvbnMuY3NzLmNlbGwud2lkdGgtdGhpcy5fd2lkdGhDYWNoZS5n"
    "ZXQoIlciLCExLCExKTt0aGlzLl9yb3dDb250YWluZXIuc3R5bGUubGV0dGVyU3BhY2luZz1gJHtlfXB4YCx0aGlzLl9yb3dGYWN0b3J5LmRlZmF1bHRTcGFj"
    "aW5nPWV9aGFuZGxlRGV2aWNlUGl4ZWxSYXRpb0NoYW5nZSgpe3RoaXMuX3VwZGF0ZURpbWVuc2lvbnMoKSx0aGlzLl93aWR0aENhY2hlLmNsZWFyKCksdGhp"
    "cy5fc2V0RGVmYXVsdFNwYWNpbmcoKX1fcmVmcmVzaFJvd0VsZW1lbnRzKGUsdCl7Zm9yKGxldCBlPXRoaXMuX3Jvd0VsZW1lbnRzLmxlbmd0aDtlPD10O2Ur"
    "Kyl7Y29uc3QgZT1kb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTt0aGlzLl9yb3dDb250YWluZXIuYXBwZW5kQ2hpbGQoZSksdGhpcy5fcm93RWxlbWVu"
    "dHMucHVzaChlKX1mb3IoO3RoaXMuX3Jvd0VsZW1lbnRzLmxlbmd0aD50Oyl0aGlzLl9yb3dDb250YWluZXIucmVtb3ZlQ2hpbGQodGhpcy5fcm93RWxlbWVu"
    "dHMucG9wKCkpfWhhbmRsZVJlc2l6ZShlLHQpe3RoaXMuX3JlZnJlc2hSb3dFbGVtZW50cyhlLHQpLHRoaXMuX3VwZGF0ZURpbWVuc2lvbnMoKX1oYW5kbGVD"
    "aGFyU2l6ZUNoYW5nZWQoKXt0aGlzLl91cGRhdGVEaW1lbnNpb25zKCksdGhpcy5fd2lkdGhDYWNoZS5jbGVhcigpLHRoaXMuX3NldERlZmF1bHRTcGFjaW5n"
    "KCl9aGFuZGxlQmx1cigpe3RoaXMuX3Jvd0NvbnRhaW5lci5jbGFzc0xpc3QucmVtb3ZlKG0pfWhhbmRsZUZvY3VzKCl7dGhpcy5fcm93Q29udGFpbmVyLmNs"
    "YXNzTGlzdC5hZGQobSksdGhpcy5yZW5kZXJSb3dzKHRoaXMuX2J1ZmZlclNlcnZpY2UuYnVmZmVyLnksdGhpcy5fYnVmZmVyU2VydmljZS5idWZmZXIueSl9"
    "aGFuZGxlU2VsZWN0aW9uQ2hhbmdlZChlLHQsaSl7aWYodGhpcy5fc2VsZWN0aW9uQ29udGFpbmVyLnJlcGxhY2VDaGlsZHJlbigpLHRoaXMuX3Jvd0ZhY3Rv"
    "cnkuaGFuZGxlU2VsZWN0aW9uQ2hhbmdlZChlLHQsaSksdGhpcy5yZW5kZXJSb3dzKDAsdGhpcy5fYnVmZmVyU2VydmljZS5yb3dzLTEpLCFlfHwhdClyZXR1"
    "cm47Y29uc3Qgcz1lWzFdLXRoaXMuX2J1ZmZlclNlcnZpY2UuYnVmZmVyLnlkaXNwLHI9dFsxXS10aGlzLl9idWZmZXJTZXJ2aWNlLmJ1ZmZlci55ZGlzcCxu"
    "PU1hdGgubWF4KHMsMCksbz1NYXRoLm1pbihyLHRoaXMuX2J1ZmZlclNlcnZpY2Uucm93cy0xKTtpZihuPj10aGlzLl9idWZmZXJTZXJ2aWNlLnJvd3N8fG88"
    "MClyZXR1cm47Y29uc3QgYT1kb2N1bWVudC5jcmVhdGVEb2N1bWVudEZyYWdtZW50KCk7aWYoaSl7Y29uc3QgaT1lWzBdPnRbMF07YS5hcHBlbmRDaGlsZCh0"
    "aGlzLl9jcmVhdGVTZWxlY3Rpb25FbGVtZW50KG4saT90WzBdOmVbMF0saT9lWzBdOnRbMF0sby1uKzEpKX1lbHNle2NvbnN0IGk9cz09PW4/ZVswXTowLGg9"
    "bj09PXI/dFswXTp0aGlzLl9idWZmZXJTZXJ2aWNlLmNvbHM7YS5hcHBlbmRDaGlsZCh0aGlzLl9jcmVhdGVTZWxlY3Rpb25FbGVtZW50KG4saSxoKSk7Y29u"
    "c3QgYz1vLW4tMTtpZihhLmFwcGVuZENoaWxkKHRoaXMuX2NyZWF0ZVNlbGVjdGlvbkVsZW1lbnQobisxLDAsdGhpcy5fYnVmZmVyU2VydmljZS5jb2xzLGMp"
    "KSxuIT09byl7Y29uc3QgZT1yPT09bz90WzBdOnRoaXMuX2J1ZmZlclNlcnZpY2UuY29sczthLmFwcGVuZENoaWxkKHRoaXMuX2NyZWF0ZVNlbGVjdGlvbkVs"
    "ZW1lbnQobywwLGUpKX19dGhpcy5fc2VsZWN0aW9uQ29udGFpbmVyLmFwcGVuZENoaWxkKGEpfV9jcmVhdGVTZWxlY3Rpb25FbGVtZW50KGUsdCxpLHM9MSl7"
    "Y29uc3Qgcj1kb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTtyZXR1cm4gci5zdHlsZS5oZWlnaHQ9cyp0aGlzLmRpbWVuc2lvbnMuY3NzLmNlbGwuaGVp"
    "Z2h0KyJweCIsci5zdHlsZS50b3A9ZSp0aGlzLmRpbWVuc2lvbnMuY3NzLmNlbGwuaGVpZ2h0KyJweCIsci5zdHlsZS5sZWZ0PXQqdGhpcy5kaW1lbnNpb25z"
    "LmNzcy5jZWxsLndpZHRoKyJweCIsci5zdHlsZS53aWR0aD10aGlzLmRpbWVuc2lvbnMuY3NzLmNlbGwud2lkdGgqKGktdCkrInB4IixyfWhhbmRsZUN1cnNv"
    "ck1vdmUoKXt9X2hhbmRsZU9wdGlvbnNDaGFuZ2VkKCl7dGhpcy5fdXBkYXRlRGltZW5zaW9ucygpLHRoaXMuX2luamVjdENzcyh0aGlzLl90aGVtZVNlcnZp"
    "Y2UuY29sb3JzKSx0aGlzLl93aWR0aENhY2hlLnNldEZvbnQodGhpcy5fb3B0aW9uc1NlcnZpY2UucmF3T3B0aW9ucy5mb250RmFtaWx5LHRoaXMuX29wdGlv"
    "bnNTZXJ2aWNlLnJhd09wdGlvbnMuZm9udFNpemUsdGhpcy5fb3B0aW9uc1NlcnZpY2UucmF3T3B0aW9ucy5mb250V2VpZ2h0LHRoaXMuX29wdGlvbnNTZXJ2"
    "aWNlLnJhd09wdGlvbnMuZm9udFdlaWdodEJvbGQpLHRoaXMuX3NldERlZmF1bHRTcGFjaW5nKCl9Y2xlYXIoKXtmb3IoY29uc3QgZSBvZiB0aGlzLl9yb3dF"
    "bGVtZW50cyllLnJlcGxhY2VDaGlsZHJlbigpfXJlbmRlclJvd3MoZSx0KXtjb25zdCBpPXRoaXMuX2J1ZmZlclNlcnZpY2UuYnVmZmVyLHM9aS55YmFzZStp"
    "Lnkscj1NYXRoLm1pbihpLngsdGhpcy5fYnVmZmVyU2VydmljZS5jb2xzLTEpLG49dGhpcy5fb3B0aW9uc1NlcnZpY2UucmF3T3B0aW9ucy5jdXJzb3JCbGlu"
    "ayxvPXRoaXMuX29wdGlvbnNTZXJ2aWNlLnJhd09wdGlvbnMuY3Vyc29yU3R5bGUsYT10aGlzLl9vcHRpb25zU2VydmljZS5yYXdPcHRpb25zLmN1cnNvcklu"
    "YWN0aXZlU3R5bGU7Zm9yKGxldCBoPWU7aDw9dDtoKyspe2NvbnN0IGU9aCtpLnlkaXNwLHQ9dGhpcy5fcm93RWxlbWVudHNbaF0sYz1pLmxpbmVzLmdldChl"
    "KTtpZighdHx8IWMpYnJlYWs7dC5yZXBsYWNlQ2hpbGRyZW4oLi4udGhpcy5fcm93RmFjdG9yeS5jcmVhdGVSb3coYyxlLGU9PT1zLG8sYSxyLG4sdGhpcy5k"
    "aW1lbnNpb25zLmNzcy5jZWxsLndpZHRoLHRoaXMuX3dpZHRoQ2FjaGUsLTEsLTEpKX19Z2V0IF90ZXJtaW5hbFNlbGVjdG9yKCl7cmV0dXJuYC4ke2Z9JHt0"
    "aGlzLl90ZXJtaW5hbENsYXNzfWB9X2hhbmRsZUxpbmtIb3ZlcihlKXt0aGlzLl9zZXRDZWxsVW5kZXJsaW5lKGUueDEsZS54MixlLnkxLGUueTIsZS5jb2xz"
    "LCEwKX1faGFuZGxlTGlua0xlYXZlKGUpe3RoaXMuX3NldENlbGxVbmRlcmxpbmUoZS54MSxlLngyLGUueTEsZS55MixlLmNvbHMsITEpfV9zZXRDZWxsVW5k"
    "ZXJsaW5lKGUsdCxpLHMscixuKXtpPDAmJihlPTApLHM8MCYmKHQ9MCk7Y29uc3Qgbz10aGlzLl9idWZmZXJTZXJ2aWNlLnJvd3MtMTtpPU1hdGgubWF4KE1h"
    "dGgubWluKGksbyksMCkscz1NYXRoLm1heChNYXRoLm1pbihzLG8pLDApLHI9TWF0aC5taW4ocix0aGlzLl9idWZmZXJTZXJ2aWNlLmNvbHMpO2NvbnN0IGE9"
    "dGhpcy5fYnVmZmVyU2VydmljZS5idWZmZXIsaD1hLnliYXNlK2EueSxjPU1hdGgubWluKGEueCxyLTEpLGw9dGhpcy5fb3B0aW9uc1NlcnZpY2UucmF3T3B0"
    "aW9ucy5jdXJzb3JCbGluayxkPXRoaXMuX29wdGlvbnNTZXJ2aWNlLnJhd09wdGlvbnMuY3Vyc29yU3R5bGUsXz10aGlzLl9vcHRpb25zU2VydmljZS5yYXdP"
    "cHRpb25zLmN1cnNvckluYWN0aXZlU3R5bGU7Zm9yKGxldCBvPWk7bzw9czsrK28pe2NvbnN0IHU9bythLnlkaXNwLGY9dGhpcy5fcm93RWxlbWVudHNbb10s"
    "dj1hLmxpbmVzLmdldCh1KTtpZighZnx8IXYpYnJlYWs7Zi5yZXBsYWNlQ2hpbGRyZW4oLi4udGhpcy5fcm93RmFjdG9yeS5jcmVhdGVSb3codix1LHU9PT1o"
    "LGQsXyxjLGwsdGhpcy5kaW1lbnNpb25zLmNzcy5jZWxsLndpZHRoLHRoaXMuX3dpZHRoQ2FjaGUsbj9vPT09aT9lOjA6LTEsbj8obz09PXM/dDpyKS0xOi0x"
    "KSl9fX07dC5Eb21SZW5kZXJlcj1iPXMoW3IoNCx1LklJbnN0YW50aWF0aW9uU2VydmljZSkscig1LGMuSUNoYXJTaXplU2VydmljZSkscig2LHUuSU9wdGlv"
    "bnNTZXJ2aWNlKSxyKDcsdS5JQnVmZmVyU2VydmljZSkscig4LGMuSUNvcmVCcm93c2VyU2VydmljZSkscig5LGMuSVRoZW1lU2VydmljZSldLGIpfSwzNzg3"
    "OmZ1bmN0aW9uKGUsdCxpKXt2YXIgcz10aGlzJiZ0aGlzLl9fZGVjb3JhdGV8fGZ1bmN0aW9uKGUsdCxpLHMpe3ZhciByLG49YXJndW1lbnRzLmxlbmd0aCxv"
    "PW48Mz90Om51bGw9PT1zP3M9T2JqZWN0LmdldE93blByb3BlcnR5RGVzY3JpcHRvcih0LGkpOnM7aWYoIm9iamVjdCI9PXR5cGVvZiBSZWZsZWN0JiYiZnVu"
    "Y3Rpb24iPT10eXBlb2YgUmVmbGVjdC5kZWNvcmF0ZSlvPVJlZmxlY3QuZGVjb3JhdGUoZSx0LGkscyk7ZWxzZSBmb3IodmFyIGE9ZS5sZW5ndGgtMTthPj0w"
    "O2EtLSkocj1lW2FdKSYmKG89KG48Mz9yKG8pOm4+Mz9yKHQsaSxvKTpyKHQsaSkpfHxvKTtyZXR1cm4gbj4zJiZvJiZPYmplY3QuZGVmaW5lUHJvcGVydHko"
    "dCxpLG8pLG99LHI9dGhpcyYmdGhpcy5fX3BhcmFtfHxmdW5jdGlvbihlLHQpe3JldHVybiBmdW5jdGlvbihpLHMpe3QoaSxzLGUpfX07T2JqZWN0LmRlZmlu"
    "ZVByb3BlcnR5KHQsIl9fZXNNb2R1bGUiLHt2YWx1ZTohMH0pLHQuRG9tUmVuZGVyZXJSb3dGYWN0b3J5PXZvaWQgMDtjb25zdCBuPWkoMjIyMyksbz1pKDY0"
    "MyksYT1pKDUxMSksaD1pKDI1ODUpLGM9aSg4MDU1KSxsPWkoNDcyNSksZD1pKDQyNjkpLF89aSg2MTcxKSx1PWkoMzczNCk7bGV0IGY9dC5Eb21SZW5kZXJl"
    "clJvd0ZhY3Rvcnk9Y2xhc3N7Y29uc3RydWN0b3IoZSx0LGkscyxyLG4sbyl7dGhpcy5fZG9jdW1lbnQ9ZSx0aGlzLl9jaGFyYWN0ZXJKb2luZXJTZXJ2aWNl"
    "PXQsdGhpcy5fb3B0aW9uc1NlcnZpY2U9aSx0aGlzLl9jb3JlQnJvd3NlclNlcnZpY2U9cyx0aGlzLl9jb3JlU2VydmljZT1yLHRoaXMuX2RlY29yYXRpb25T"
    "ZXJ2aWNlPW4sdGhpcy5fdGhlbWVTZXJ2aWNlPW8sdGhpcy5fd29ya0NlbGw9bmV3IGEuQ2VsbERhdGEsdGhpcy5fY29sdW1uU2VsZWN0TW9kZT0hMSx0aGlz"
    "LmRlZmF1bHRTcGFjaW5nPTB9aGFuZGxlU2VsZWN0aW9uQ2hhbmdlZChlLHQsaSl7dGhpcy5fc2VsZWN0aW9uU3RhcnQ9ZSx0aGlzLl9zZWxlY3Rpb25FbmQ9"
    "dCx0aGlzLl9jb2x1bW5TZWxlY3RNb2RlPWl9Y3JlYXRlUm93KGUsdCxpLHMscixhLGgsbCxfLGYscCl7Y29uc3QgZz1bXSxtPXRoaXMuX2NoYXJhY3Rlckpv"
    "aW5lclNlcnZpY2UuZ2V0Sm9pbmVkQ2hhcmFjdGVycyh0KSxTPXRoaXMuX3RoZW1lU2VydmljZS5jb2xvcnM7bGV0IEMsYj1lLmdldE5vQmdUcmltbWVkTGVu"
    "Z3RoKCk7aSYmYjxhKzEmJihiPWErMSk7bGV0IHk9MCx3PSIiLEU9MCxrPTAsTD0wLEQ9ITEsUj0wLHg9ITEsQT0wO2NvbnN0IEI9W10sVD0tMSE9PWYmJi0x"
    "IT09cDtmb3IobGV0IE09MDtNPGI7TSsrKXtlLmxvYWRDZWxsKE0sdGhpcy5fd29ya0NlbGwpO2xldCBiPXRoaXMuX3dvcmtDZWxsLmdldFdpZHRoKCk7aWYo"
    "MD09PWIpY29udGludWU7bGV0IE89ITEsUD1NLEk9dGhpcy5fd29ya0NlbGw7aWYobS5sZW5ndGg+MCYmTT09PW1bMF1bMF0pe089ITA7Y29uc3QgdD1tLnNo"
    "aWZ0KCk7ST1uZXcgZC5Kb2luZWRDZWxsRGF0YSh0aGlzLl93b3JrQ2VsbCxlLnRyYW5zbGF0ZVRvU3RyaW5nKCEwLHRbMF0sdFsxXSksdFsxXS10WzBdKSxQ"
    "PXRbMV0tMSxiPUkuZ2V0V2lkdGgoKX1jb25zdCBIPXRoaXMuX2lzQ2VsbEluU2VsZWN0aW9uKE0sdCksRj1pJiZNPT09YSxXPVQmJk0+PWYmJk08PXA7bGV0"
    "IFU9ITE7dGhpcy5fZGVjb3JhdGlvblNlcnZpY2UuZm9yRWFjaERlY29yYXRpb25BdENlbGwoTSx0LHZvaWQgMCwoZT0+e1U9ITB9KSk7bGV0IE49SS5nZXRD"
    "aGFycygpfHxvLldISVRFU1BBQ0VfQ0VMTF9DSEFSO2lmKCIgIj09PU4mJihJLmlzVW5kZXJsaW5lKCl8fEkuaXNPdmVybGluZSgpKSYmKE49IsKgIiksQT1i"
    "KmwtXy5nZXQoTixJLmlzQm9sZCgpLEkuaXNJdGFsaWMoKSksQyl7aWYoeSYmKEgmJnh8fCFIJiYheCYmSS5iZz09PUUpJiYoSCYmeCYmUy5zZWxlY3Rpb25G"
    "b3JlZ3JvdW5kfHxJLmZnPT09aykmJkkuZXh0ZW5kZWQuZXh0PT09TCYmVz09PUQmJkE9PT1SJiYhRiYmIU8mJiFVKXt3Kz1OLHkrKztjb250aW51ZX15JiYo"
    "Qy50ZXh0Q29udGVudD13KSxDPXRoaXMuX2RvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInNwYW4iKSx5PTAsdz0iIn1lbHNlIEM9dGhpcy5fZG9jdW1lbnQuY3Jl"
    "YXRlRWxlbWVudCgic3BhbiIpO2lmKEU9SS5iZyxrPUkuZmcsTD1JLmV4dGVuZGVkLmV4dCxEPVcsUj1BLHg9SCxPJiZhPj1NJiZhPD1QJiYoYT1NKSwhdGhp"
    "cy5fY29yZVNlcnZpY2UuaXNDdXJzb3JIaWRkZW4mJkYpaWYoQi5wdXNoKCJ4dGVybS1jdXJzb3IiKSx0aGlzLl9jb3JlQnJvd3NlclNlcnZpY2UuaXNGb2N1"
    "c2VkKWgmJkIucHVzaCgieHRlcm0tY3Vyc29yLWJsaW5rIiksQi5wdXNoKCJiYXIiPT09cz8ieHRlcm0tY3Vyc29yLWJhciI6InVuZGVybGluZSI9PT1zPyJ4"
    "dGVybS1jdXJzb3ItdW5kZXJsaW5lIjoieHRlcm0tY3Vyc29yLWJsb2NrIik7ZWxzZSBpZihyKXN3aXRjaChyKXtjYXNlIm91dGxpbmUiOkIucHVzaCgieHRl"
    "cm0tY3Vyc29yLW91dGxpbmUiKTticmVhaztjYXNlImJsb2NrIjpCLnB1c2goInh0ZXJtLWN1cnNvci1ibG9jayIpO2JyZWFrO2Nhc2UiYmFyIjpCLnB1c2go"
    "Inh0ZXJtLWN1cnNvci1iYXIiKTticmVhaztjYXNlInVuZGVybGluZSI6Qi5wdXNoKCJ4dGVybS1jdXJzb3ItdW5kZXJsaW5lIil9aWYoSS5pc0JvbGQoKSYm"
    "Qi5wdXNoKCJ4dGVybS1ib2xkIiksSS5pc0l0YWxpYygpJiZCLnB1c2goInh0ZXJtLWl0YWxpYyIpLEkuaXNEaW0oKSYmQi5wdXNoKCJ4dGVybS1kaW0iKSx3"
    "PUkuaXNJbnZpc2libGUoKT9vLldISVRFU1BBQ0VfQ0VMTF9DSEFSOkkuZ2V0Q2hhcnMoKXx8by5XSElURVNQQUNFX0NFTExfQ0hBUixJLmlzVW5kZXJsaW5l"
    "KCkmJihCLnB1c2goYHh0ZXJtLXVuZGVybGluZS0ke0kuZXh0ZW5kZWQudW5kZXJsaW5lU3R5bGV9YCksIiAiPT09dyYmKHc9IsKgIiksIUkuaXNVbmRlcmxp"
    "bmVDb2xvckRlZmF1bHQoKSkpaWYoSS5pc1VuZGVybGluZUNvbG9yUkdCKCkpQy5zdHlsZS50ZXh0RGVjb3JhdGlvbkNvbG9yPWByZ2IoJHt1LkF0dHJpYnV0"
    "ZURhdGEudG9Db2xvclJHQihJLmdldFVuZGVybGluZUNvbG9yKCkpLmpvaW4oIiwiKX0pYDtlbHNle2xldCBlPUkuZ2V0VW5kZXJsaW5lQ29sb3IoKTt0aGlz"
    "Ll9vcHRpb25zU2VydmljZS5yYXdPcHRpb25zLmRyYXdCb2xkVGV4dEluQnJpZ2h0Q29sb3JzJiZJLmlzQm9sZCgpJiZlPDgmJihlKz04KSxDLnN0eWxlLnRl"
    "eHREZWNvcmF0aW9uQ29sb3I9Uy5hbnNpW2VdLmNzc31JLmlzT3ZlcmxpbmUoKSYmKEIucHVzaCgieHRlcm0tb3ZlcmxpbmUiKSwiICI9PT13JiYodz0iwqAi"
    "KSksSS5pc1N0cmlrZXRocm91Z2goKSYmQi5wdXNoKCJ4dGVybS1zdHJpa2V0aHJvdWdoIiksVyYmKEMuc3R5bGUudGV4dERlY29yYXRpb249InVuZGVybGlu"
    "ZSIpO2xldCAkPUkuZ2V0RmdDb2xvcigpLGo9SS5nZXRGZ0NvbG9yTW9kZSgpLHo9SS5nZXRCZ0NvbG9yKCksSz1JLmdldEJnQ29sb3JNb2RlKCk7Y29uc3Qg"
    "cT0hIUkuaXNJbnZlcnNlKCk7aWYocSl7Y29uc3QgZT0kOyQ9eix6PWU7Y29uc3QgdD1qO2o9SyxLPXR9bGV0IFYsRyxYLEo9ITE7c3dpdGNoKHRoaXMuX2Rl"
    "Y29yYXRpb25TZXJ2aWNlLmZvckVhY2hEZWNvcmF0aW9uQXRDZWxsKE0sdCx2b2lkIDAsKGU9PnsidG9wIiE9PWUub3B0aW9ucy5sYXllciYmSnx8KGUuYmFj"
    "a2dyb3VuZENvbG9yUkdCJiYoSz01MDMzMTY0OCx6PWUuYmFja2dyb3VuZENvbG9yUkdCLnJnYmE+PjgmMTY3NzcyMTUsVj1lLmJhY2tncm91bmRDb2xvclJH"
    "QiksZS5mb3JlZ3JvdW5kQ29sb3JSR0ImJihqPTUwMzMxNjQ4LCQ9ZS5mb3JlZ3JvdW5kQ29sb3JSR0IucmdiYT4+OCYxNjc3NzIxNSxHPWUuZm9yZWdyb3Vu"
    "ZENvbG9yUkdCKSxKPSJ0b3AiPT09ZS5vcHRpb25zLmxheWVyKX0pKSwhSiYmSCYmKFY9dGhpcy5fY29yZUJyb3dzZXJTZXJ2aWNlLmlzRm9jdXNlZD9TLnNl"
    "bGVjdGlvbkJhY2tncm91bmRPcGFxdWU6Uy5zZWxlY3Rpb25JbmFjdGl2ZUJhY2tncm91bmRPcGFxdWUsej1WLnJnYmE+PjgmMTY3NzcyMTUsSz01MDMzMTY0"
    "OCxKPSEwLFMuc2VsZWN0aW9uRm9yZWdyb3VuZCYmKGo9NTAzMzE2NDgsJD1TLnNlbGVjdGlvbkZvcmVncm91bmQucmdiYT4+OCYxNjc3NzIxNSxHPVMuc2Vs"
    "ZWN0aW9uRm9yZWdyb3VuZCkpLEomJkIucHVzaCgieHRlcm0tZGVjb3JhdGlvbi10b3AiKSxLKXtjYXNlIDE2Nzc3MjE2OmNhc2UgMzM1NTQ0MzI6WD1TLmFu"
    "c2lbel0sQi5wdXNoKGB4dGVybS1iZy0ke3p9YCk7YnJlYWs7Y2FzZSA1MDMzMTY0ODpYPWMucmdiYS50b0NvbG9yKHo+PjE2LHo+PjgmMjU1LDI1NSZ6KSx0"
    "aGlzLl9hZGRTdHlsZShDLGBiYWNrZ3JvdW5kLWNvbG9yOiMke3YoKHo+Pj4wKS50b1N0cmluZygxNiksIjAiLDYpfWApO2JyZWFrO2RlZmF1bHQ6cT8oWD1T"
    "LmZvcmVncm91bmQsQi5wdXNoKGB4dGVybS1iZy0ke24uSU5WRVJURURfREVGQVVMVF9DT0xPUn1gKSk6WD1TLmJhY2tncm91bmR9c3dpdGNoKFZ8fEkuaXNE"
    "aW0oKSYmKFY9Yy5jb2xvci5tdWx0aXBseU9wYWNpdHkoWCwuNSkpLGope2Nhc2UgMTY3NzcyMTY6Y2FzZSAzMzU1NDQzMjpJLmlzQm9sZCgpJiYkPDgmJnRo"
    "aXMuX29wdGlvbnNTZXJ2aWNlLnJhd09wdGlvbnMuZHJhd0JvbGRUZXh0SW5CcmlnaHRDb2xvcnMmJigkKz04KSx0aGlzLl9hcHBseU1pbmltdW1Db250cmFz"
    "dChDLFgsUy5hbnNpWyRdLEksVix2b2lkIDApfHxCLnB1c2goYHh0ZXJtLWZnLSR7JH1gKTticmVhaztjYXNlIDUwMzMxNjQ4OmNvbnN0IGU9Yy5yZ2JhLnRv"
    "Q29sb3IoJD4+MTYmMjU1LCQ+PjgmMjU1LDI1NSYkKTt0aGlzLl9hcHBseU1pbmltdW1Db250cmFzdChDLFgsZSxJLFYsRyl8fHRoaXMuX2FkZFN0eWxlKEMs"
    "YGNvbG9yOiMke3YoJC50b1N0cmluZygxNiksIjAiLDYpfWApO2JyZWFrO2RlZmF1bHQ6dGhpcy5fYXBwbHlNaW5pbXVtQ29udHJhc3QoQyxYLFMuZm9yZWdy"
    "b3VuZCxJLFYsdm9pZCAwKXx8cSYmQi5wdXNoKGB4dGVybS1mZy0ke24uSU5WRVJURURfREVGQVVMVF9DT0xPUn1gKX1CLmxlbmd0aCYmKEMuY2xhc3NOYW1l"
    "PUIuam9pbigiICIpLEIubGVuZ3RoPTApLEZ8fE98fFU/Qy50ZXh0Q29udGVudD13OnkrKyxBIT09dGhpcy5kZWZhdWx0U3BhY2luZyYmKEMuc3R5bGUubGV0"
    "dGVyU3BhY2luZz1gJHtBfXB4YCksZy5wdXNoKEMpLE09UH1yZXR1cm4gQyYmeSYmKEMudGV4dENvbnRlbnQ9dyksZ31fYXBwbHlNaW5pbXVtQ29udHJhc3Qo"
    "ZSx0LGkscyxyLG4pe2lmKDE9PT10aGlzLl9vcHRpb25zU2VydmljZS5yYXdPcHRpb25zLm1pbmltdW1Db250cmFzdFJhdGlvfHwoMCxfLmV4Y2x1ZGVGcm9t"
    "Q29udHJhc3RSYXRpb0RlbWFuZHMpKHMuZ2V0Q29kZSgpKSlyZXR1cm4hMTtjb25zdCBvPXRoaXMuX2dldENvbnRyYXN0Q2FjaGUocyk7bGV0IGE7aWYocnx8"
    "bnx8KGE9by5nZXRDb2xvcih0LnJnYmEsaS5yZ2JhKSksdm9pZCAwPT09YSl7Y29uc3QgZT10aGlzLl9vcHRpb25zU2VydmljZS5yYXdPcHRpb25zLm1pbmlt"
    "dW1Db250cmFzdFJhdGlvLyhzLmlzRGltKCk/MjoxKTthPWMuY29sb3IuZW5zdXJlQ29udHJhc3RSYXRpbyhyfHx0LG58fGksZSksby5zZXRDb2xvcigocnx8"
    "dCkucmdiYSwobnx8aSkucmdiYSxudWxsIT1hP2E6bnVsbCl9cmV0dXJuISFhJiYodGhpcy5fYWRkU3R5bGUoZSxgY29sb3I6JHthLmNzc31gKSwhMCl9X2dl"
    "dENvbnRyYXN0Q2FjaGUoZSl7cmV0dXJuIGUuaXNEaW0oKT90aGlzLl90aGVtZVNlcnZpY2UuY29sb3JzLmhhbGZDb250cmFzdENhY2hlOnRoaXMuX3RoZW1l"
    "U2VydmljZS5jb2xvcnMuY29udHJhc3RDYWNoZX1fYWRkU3R5bGUoZSx0KXtlLnNldEF0dHJpYnV0ZSgic3R5bGUiLGAke2UuZ2V0QXR0cmlidXRlKCJzdHls"
    "ZSIpfHwiIn0ke3R9O2ApfV9pc0NlbGxJblNlbGVjdGlvbihlLHQpe2NvbnN0IGk9dGhpcy5fc2VsZWN0aW9uU3RhcnQscz10aGlzLl9zZWxlY3Rpb25FbmQ7"
    "cmV0dXJuISghaXx8IXMpJiYodGhpcy5fY29sdW1uU2VsZWN0TW9kZT9pWzBdPD1zWzBdP2U+PWlbMF0mJnQ+PWlbMV0mJmU8c1swXSYmdDw9c1sxXTplPGlb"
    "MF0mJnQ+PWlbMV0mJmU+PXNbMF0mJnQ8PXNbMV06dD5pWzFdJiZ0PHNbMV18fGlbMV09PT1zWzFdJiZ0PT09aVsxXSYmZT49aVswXSYmZTxzWzBdfHxpWzFd"
    "PHNbMV0mJnQ9PT1zWzFdJiZlPHNbMF18fGlbMV08c1sxXSYmdD09PWlbMV0mJmU+PWlbMF0pfX07ZnVuY3Rpb24gdihlLHQsaSl7Zm9yKDtlLmxlbmd0aDxp"
    "OyllPXQrZTtyZXR1cm4gZX10LkRvbVJlbmRlcmVyUm93RmFjdG9yeT1mPXMoW3IoMSxsLklDaGFyYWN0ZXJKb2luZXJTZXJ2aWNlKSxyKDIsaC5JT3B0aW9u"
    "c1NlcnZpY2UpLHIoMyxsLklDb3JlQnJvd3NlclNlcnZpY2UpLHIoNCxoLklDb3JlU2VydmljZSkscig1LGguSURlY29yYXRpb25TZXJ2aWNlKSxyKDYsbC5J"
    "VGhlbWVTZXJ2aWNlKV0sZil9LDI1NTA6KGUsdCk9PntPYmplY3QuZGVmaW5lUHJvcGVydHkodCwiX19lc01vZHVsZSIse3ZhbHVlOiEwfSksdC5XaWR0aENh"
    "Y2hlPXZvaWQgMCx0LldpZHRoQ2FjaGU9Y2xhc3N7Y29uc3RydWN0b3IoZSl7dGhpcy5fZmxhdD1uZXcgRmxvYXQzMkFycmF5KDI1NiksdGhpcy5fZm9udD0i"
    "Iix0aGlzLl9mb250U2l6ZT0wLHRoaXMuX3dlaWdodD0ibm9ybWFsIix0aGlzLl93ZWlnaHRCb2xkPSJib2xkIix0aGlzLl9tZWFzdXJlRWxlbWVudHM9W10s"
    "dGhpcy5fY29udGFpbmVyPWUuY3JlYXRlRWxlbWVudCgiZGl2IiksdGhpcy5fY29udGFpbmVyLnN0eWxlLnBvc2l0aW9uPSJhYnNvbHV0ZSIsdGhpcy5fY29u"
    "dGFpbmVyLnN0eWxlLnRvcD0iLTUwMDAwcHgiLHRoaXMuX2NvbnRhaW5lci5zdHlsZS53aWR0aD0iNTAwMDBweCIsdGhpcy5fY29udGFpbmVyLnN0eWxlLndo"
    "aXRlU3BhY2U9InByZSIsdGhpcy5fY29udGFpbmVyLnN0eWxlLmZvbnRLZXJuaW5nPSJub25lIjtjb25zdCB0PWUuY3JlYXRlRWxlbWVudCgic3BhbiIpLGk9"
    "ZS5jcmVhdGVFbGVtZW50KCJzcGFuIik7aS5zdHlsZS5mb250V2VpZ2h0PSJib2xkIjtjb25zdCBzPWUuY3JlYXRlRWxlbWVudCgic3BhbiIpO3Muc3R5bGUu"
    "Zm9udFN0eWxlPSJpdGFsaWMiO2NvbnN0IHI9ZS5jcmVhdGVFbGVtZW50KCJzcGFuIik7ci5zdHlsZS5mb250V2VpZ2h0PSJib2xkIixyLnN0eWxlLmZvbnRT"
    "dHlsZT0iaXRhbGljIix0aGlzLl9tZWFzdXJlRWxlbWVudHM9W3QsaSxzLHJdLHRoaXMuX2NvbnRhaW5lci5hcHBlbmRDaGlsZCh0KSx0aGlzLl9jb250YWlu"
    "ZXIuYXBwZW5kQ2hpbGQoaSksdGhpcy5fY29udGFpbmVyLmFwcGVuZENoaWxkKHMpLHRoaXMuX2NvbnRhaW5lci5hcHBlbmRDaGlsZChyKSxlLmJvZHkuYXBw"
    "ZW5kQ2hpbGQodGhpcy5fY29udGFpbmVyKSx0aGlzLmNsZWFyKCl9ZGlzcG9zZSgpe3RoaXMuX2NvbnRhaW5lci5yZW1vdmUoKSx0aGlzLl9tZWFzdXJlRWxl"
    "bWVudHMubGVuZ3RoPTAsdGhpcy5faG9sZXk9dm9pZCAwfWNsZWFyKCl7dGhpcy5fZmxhdC5maWxsKC05OTk5KSx0aGlzLl9ob2xleT1uZXcgTWFwfXNldEZv"
    "bnQoZSx0LGkscyl7ZT09PXRoaXMuX2ZvbnQmJnQ9PT10aGlzLl9mb250U2l6ZSYmaT09PXRoaXMuX3dlaWdodCYmcz09PXRoaXMuX3dlaWdodEJvbGR8fCh0"
    "aGlzLl9mb250PWUsdGhpcy5fZm9udFNpemU9dCx0aGlzLl93ZWlnaHQ9aSx0aGlzLl93ZWlnaHRCb2xkPXMsdGhpcy5fY29udGFpbmVyLnN0eWxlLmZvbnRG"
    "YW1pbHk9dGhpcy5fZm9udCx0aGlzLl9jb250YWluZXIuc3R5bGUuZm9udFNpemU9YCR7dGhpcy5fZm9udFNpemV9cHhgLHRoaXMuX21lYXN1cmVFbGVtZW50"
    "c1swXS5zdHlsZS5mb250V2VpZ2h0PWAke2l9YCx0aGlzLl9tZWFzdXJlRWxlbWVudHNbMV0uc3R5bGUuZm9udFdlaWdodD1gJHtzfWAsdGhpcy5fbWVhc3Vy"
    "ZUVsZW1lbnRzWzJdLnN0eWxlLmZvbnRXZWlnaHQ9YCR7aX1gLHRoaXMuX21lYXN1cmVFbGVtZW50c1szXS5zdHlsZS5mb250V2VpZ2h0PWAke3N9YCx0aGlz"
    "LmNsZWFyKCkpfWdldChlLHQsaSl7bGV0IHM9MDtpZighdCYmIWkmJjE9PT1lLmxlbmd0aCYmKHM9ZS5jaGFyQ29kZUF0KDApKTwyNTYpcmV0dXJuLTk5OTkh"
    "PT10aGlzLl9mbGF0W3NdP3RoaXMuX2ZsYXRbc106dGhpcy5fZmxhdFtzXT10aGlzLl9tZWFzdXJlKGUsMCk7bGV0IHI9ZTt0JiYocis9IkIiKSxpJiYocis9"
    "IkkiKTtsZXQgbj10aGlzLl9ob2xleS5nZXQocik7aWYodm9pZCAwPT09bil7bGV0IHM9MDt0JiYoc3w9MSksaSYmKHN8PTIpLG49dGhpcy5fbWVhc3VyZShl"
    "LHMpLHRoaXMuX2hvbGV5LnNldChyLG4pfXJldHVybiBufV9tZWFzdXJlKGUsdCl7Y29uc3QgaT10aGlzLl9tZWFzdXJlRWxlbWVudHNbdF07cmV0dXJuIGku"
    "dGV4dENvbnRlbnQ9ZS5yZXBlYXQoMzIpLGkub2Zmc2V0V2lkdGgvMzJ9fX0sMjIyMzooZSx0LGkpPT57T2JqZWN0LmRlZmluZVByb3BlcnR5KHQsIl9fZXNN"
    "b2R1bGUiLHt2YWx1ZTohMH0pLHQuVEVYVF9CQVNFTElORT10LkRJTV9PUEFDSVRZPXQuSU5WRVJURURfREVGQVVMVF9DT0xPUj12b2lkIDA7Y29uc3Qgcz1p"
    "KDYxMTQpO3QuSU5WRVJURURfREVGQVVMVF9DT0xPUj0yNTcsdC5ESU1fT1BBQ0lUWT0uNSx0LlRFWFRfQkFTRUxJTkU9cy5pc0ZpcmVmb3h8fHMuaXNMZWdh"
    "Y3lFZGdlPyJib3R0b20iOiJpZGVvZ3JhcGhpYyJ9LDYxNzE6KGUsdCk9PntmdW5jdGlvbiBpKGUpe3JldHVybiA1NzUwODw9ZSYmZTw9NTc1NTh9T2JqZWN0"
    "LmRlZmluZVByb3BlcnR5KHQsIl9fZXNNb2R1bGUiLHt2YWx1ZTohMH0pLHQuY3JlYXRlUmVuZGVyRGltZW5zaW9ucz10LmV4Y2x1ZGVGcm9tQ29udHJhc3RS"
    "YXRpb0RlbWFuZHM9dC5pc1Jlc3RyaWN0ZWRQb3dlcmxpbmVHbHlwaD10LmlzUG93ZXJsaW5lR2x5cGg9dC50aHJvd0lmRmFsc3k9dm9pZCAwLHQudGhyb3dJ"
    "ZkZhbHN5PWZ1bmN0aW9uKGUpe2lmKCFlKXRocm93IG5ldyBFcnJvcigidmFsdWUgbXVzdCBub3QgYmUgZmFsc3kiKTtyZXR1cm4gZX0sdC5pc1Bvd2VybGlu"
    "ZUdseXBoPWksdC5pc1Jlc3RyaWN0ZWRQb3dlcmxpbmVHbHlwaD1mdW5jdGlvbihlKXtyZXR1cm4gNTc1MjA8PWUmJmU8PTU3NTI3fSx0LmV4Y2x1ZGVGcm9t"
    "Q29udHJhc3RSYXRpb0RlbWFuZHM9ZnVuY3Rpb24oZSl7cmV0dXJuIGkoZSl8fGZ1bmN0aW9uKGUpe3JldHVybiA5NDcyPD1lJiZlPD05NjMxfShlKX0sdC5j"
    "cmVhdGVSZW5kZXJEaW1lbnNpb25zPWZ1bmN0aW9uKCl7cmV0dXJue2Nzczp7Y2FudmFzOnt3aWR0aDowLGhlaWdodDowfSxjZWxsOnt3aWR0aDowLGhlaWdo"
    "dDowfX0sZGV2aWNlOntjYW52YXM6e3dpZHRoOjAsaGVpZ2h0OjB9LGNlbGw6e3dpZHRoOjAsaGVpZ2h0OjB9LGNoYXI6e3dpZHRoOjAsaGVpZ2h0OjAsbGVm"
    "dDowLHRvcDowfX19fX0sNDU2OihlLHQpPT57T2JqZWN0LmRlZmluZVByb3BlcnR5KHQsIl9fZXNNb2R1bGUiLHt2YWx1ZTohMH0pLHQuU2VsZWN0aW9uTW9k"
    "ZWw9dm9pZCAwLHQuU2VsZWN0aW9uTW9kZWw9Y2xhc3N7Y29uc3RydWN0b3IoZSl7dGhpcy5fYnVmZmVyU2VydmljZT1lLHRoaXMuaXNTZWxlY3RBbGxBY3Rp"
    "dmU9ITEsdGhpcy5zZWxlY3Rpb25TdGFydExlbmd0aD0wfWNsZWFyU2VsZWN0aW9uKCl7dGhpcy5zZWxlY3Rpb25TdGFydD12b2lkIDAsdGhpcy5zZWxlY3Rp"
    "b25FbmQ9dm9pZCAwLHRoaXMuaXNTZWxlY3RBbGxBY3RpdmU9ITEsdGhpcy5zZWxlY3Rpb25TdGFydExlbmd0aD0wfWdldCBmaW5hbFNlbGVjdGlvblN0YXJ0"
    "KCl7cmV0dXJuIHRoaXMuaXNTZWxlY3RBbGxBY3RpdmU/WzAsMF06dGhpcy5zZWxlY3Rpb25FbmQmJnRoaXMuc2VsZWN0aW9uU3RhcnQmJnRoaXMuYXJlU2Vs"
    "ZWN0aW9uVmFsdWVzUmV2ZXJzZWQoKT90aGlzLnNlbGVjdGlvbkVuZDp0aGlzLnNlbGVjdGlvblN0YXJ0fWdldCBmaW5hbFNlbGVjdGlvbkVuZCgpe2lmKHRo"
    "aXMuaXNTZWxlY3RBbGxBY3RpdmUpcmV0dXJuW3RoaXMuX2J1ZmZlclNlcnZpY2UuY29scyx0aGlzLl9idWZmZXJTZXJ2aWNlLmJ1ZmZlci55YmFzZSt0aGlz"
    "Ll9idWZmZXJTZXJ2aWNlLnJvd3MtMV07aWYodGhpcy5zZWxlY3Rpb25TdGFydCl7aWYoIXRoaXMuc2VsZWN0aW9uRW5kfHx0aGlzLmFyZVNlbGVjdGlvblZh"
    "bHVlc1JldmVyc2VkKCkpe2NvbnN0IGU9dGhpcy5zZWxlY3Rpb25TdGFydFswXSt0aGlzLnNlbGVjdGlvblN0YXJ0TGVuZ3RoO3JldHVybiBlPnRoaXMuX2J1"
    "ZmZlclNlcnZpY2UuY29scz9lJXRoaXMuX2J1ZmZlclNlcnZpY2UuY29scz09MD9bdGhpcy5fYnVmZmVyU2VydmljZS5jb2xzLHRoaXMuc2VsZWN0aW9uU3Rh"
    "cnRbMV0rTWF0aC5mbG9vcihlL3RoaXMuX2J1ZmZlclNlcnZpY2UuY29scyktMV06W2UldGhpcy5fYnVmZmVyU2VydmljZS5jb2xzLHRoaXMuc2VsZWN0aW9u"
    "U3RhcnRbMV0rTWF0aC5mbG9vcihlL3RoaXMuX2J1ZmZlclNlcnZpY2UuY29scyldOltlLHRoaXMuc2VsZWN0aW9uU3RhcnRbMV1dfWlmKHRoaXMuc2VsZWN0"
    "aW9uU3RhcnRMZW5ndGgmJnRoaXMuc2VsZWN0aW9uRW5kWzFdPT09dGhpcy5zZWxlY3Rpb25TdGFydFsxXSl7Y29uc3QgZT10aGlzLnNlbGVjdGlvblN0YXJ0"
    "WzBdK3RoaXMuc2VsZWN0aW9uU3RhcnRMZW5ndGg7cmV0dXJuIGU+dGhpcy5fYnVmZmVyU2VydmljZS5jb2xzP1tlJXRoaXMuX2J1ZmZlclNlcnZpY2UuY29s"
    "cyx0aGlzLnNlbGVjdGlvblN0YXJ0WzFdK01hdGguZmxvb3IoZS90aGlzLl9idWZmZXJTZXJ2aWNlLmNvbHMpXTpbTWF0aC5tYXgoZSx0aGlzLnNlbGVjdGlv"
    "bkVuZFswXSksdGhpcy5zZWxlY3Rpb25FbmRbMV1dfXJldHVybiB0aGlzLnNlbGVjdGlvbkVuZH19YXJlU2VsZWN0aW9uVmFsdWVzUmV2ZXJzZWQoKXtjb25z"
    "dCBlPXRoaXMuc2VsZWN0aW9uU3RhcnQsdD10aGlzLnNlbGVjdGlvbkVuZDtyZXR1cm4hKCFlfHwhdCkmJihlWzFdPnRbMV18fGVbMV09PT10WzFdJiZlWzBd"
    "PnRbMF0pfWhhbmRsZVRyaW0oZSl7cmV0dXJuIHRoaXMuc2VsZWN0aW9uU3RhcnQmJih0aGlzLnNlbGVjdGlvblN0YXJ0WzFdLT1lKSx0aGlzLnNlbGVjdGlv"
    "bkVuZCYmKHRoaXMuc2VsZWN0aW9uRW5kWzFdLT1lKSx0aGlzLnNlbGVjdGlvbkVuZCYmdGhpcy5zZWxlY3Rpb25FbmRbMV08MD8odGhpcy5jbGVhclNlbGVj"
    "dGlvbigpLCEwKToodGhpcy5zZWxlY3Rpb25TdGFydCYmdGhpcy5zZWxlY3Rpb25TdGFydFsxXTwwJiYodGhpcy5zZWxlY3Rpb25TdGFydFsxXT0wKSwhMSl9"
    "fX0sNDI4OmZ1bmN0aW9uKGUsdCxpKXt2YXIgcz10aGlzJiZ0aGlzLl9fZGVjb3JhdGV8fGZ1bmN0aW9uKGUsdCxpLHMpe3ZhciByLG49YXJndW1lbnRzLmxl"
    "bmd0aCxvPW48Mz90Om51bGw9PT1zP3M9T2JqZWN0LmdldE93blByb3BlcnR5RGVzY3JpcHRvcih0LGkpOnM7aWYoIm9iamVjdCI9PXR5cGVvZiBSZWZsZWN0"
    "JiYiZnVuY3Rpb24iPT10eXBlb2YgUmVmbGVjdC5kZWNvcmF0ZSlvPVJlZmxlY3QuZGVjb3JhdGUoZSx0LGkscyk7ZWxzZSBmb3IodmFyIGE9ZS5sZW5ndGgt"
    "MTthPj0wO2EtLSkocj1lW2FdKSYmKG89KG48Mz9yKG8pOm4+Mz9yKHQsaSxvKTpyKHQsaSkpfHxvKTtyZXR1cm4gbj4zJiZvJiZPYmplY3QuZGVmaW5lUHJv"
    "cGVydHkodCxpLG8pLG99LHI9dGhpcyYmdGhpcy5fX3BhcmFtfHxmdW5jdGlvbihlLHQpe3JldHVybiBmdW5jdGlvbihpLHMpe3QoaSxzLGUpfX07T2JqZWN0"
    "LmRlZmluZVByb3BlcnR5KHQsIl9fZXNNb2R1bGUiLHt2YWx1ZTohMH0pLHQuQ2hhclNpemVTZXJ2aWNlPXZvaWQgMDtjb25zdCBuPWkoMjU4NSksbz1pKDg0"
    "NjApLGE9aSg4NDQpO2xldCBoPXQuQ2hhclNpemVTZXJ2aWNlPWNsYXNzIGV4dGVuZHMgYS5EaXNwb3NhYmxle2dldCBoYXNWYWxpZFNpemUoKXtyZXR1cm4g"
    "dGhpcy53aWR0aD4wJiZ0aGlzLmhlaWdodD4wfWNvbnN0cnVjdG9yKGUsdCxpKXtzdXBlcigpLHRoaXMuX29wdGlvbnNTZXJ2aWNlPWksdGhpcy53aWR0aD0w"
    "LHRoaXMuaGVpZ2h0PTAsdGhpcy5fb25DaGFyU2l6ZUNoYW5nZT10aGlzLnJlZ2lzdGVyKG5ldyBvLkV2ZW50RW1pdHRlciksdGhpcy5vbkNoYXJTaXplQ2hh"
    "bmdlPXRoaXMuX29uQ2hhclNpemVDaGFuZ2UuZXZlbnQsdGhpcy5fbWVhc3VyZVN0cmF0ZWd5PW5ldyBjKGUsdCx0aGlzLl9vcHRpb25zU2VydmljZSksdGhp"
    "cy5yZWdpc3Rlcih0aGlzLl9vcHRpb25zU2VydmljZS5vbk11bHRpcGxlT3B0aW9uQ2hhbmdlKFsiZm9udEZhbWlseSIsImZvbnRTaXplIl0sKCgpPT50aGlz"
    "Lm1lYXN1cmUoKSkpKX1tZWFzdXJlKCl7Y29uc3QgZT10aGlzLl9tZWFzdXJlU3RyYXRlZ3kubWVhc3VyZSgpO2Uud2lkdGg9PT10aGlzLndpZHRoJiZlLmhl"
    "aWdodD09PXRoaXMuaGVpZ2h0fHwodGhpcy53aWR0aD1lLndpZHRoLHRoaXMuaGVpZ2h0PWUuaGVpZ2h0LHRoaXMuX29uQ2hhclNpemVDaGFuZ2UuZmlyZSgp"
    "KX19O3QuQ2hhclNpemVTZXJ2aWNlPWg9cyhbcigyLG4uSU9wdGlvbnNTZXJ2aWNlKV0saCk7Y2xhc3MgY3tjb25zdHJ1Y3RvcihlLHQsaSl7dGhpcy5fZG9j"
    "dW1lbnQ9ZSx0aGlzLl9wYXJlbnRFbGVtZW50PXQsdGhpcy5fb3B0aW9uc1NlcnZpY2U9aSx0aGlzLl9yZXN1bHQ9e3dpZHRoOjAsaGVpZ2h0OjB9LHRoaXMu"
    "X21lYXN1cmVFbGVtZW50PXRoaXMuX2RvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInNwYW4iKSx0aGlzLl9tZWFzdXJlRWxlbWVudC5jbGFzc0xpc3QuYWRkKCJ4"
    "dGVybS1jaGFyLW1lYXN1cmUtZWxlbWVudCIpLHRoaXMuX21lYXN1cmVFbGVtZW50LnRleHRDb250ZW50PSJXIi5yZXBlYXQoMzIpLHRoaXMuX21lYXN1cmVF"
    "bGVtZW50LnNldEF0dHJpYnV0ZSgiYXJpYS1oaWRkZW4iLCJ0cnVlIiksdGhpcy5fbWVhc3VyZUVsZW1lbnQuc3R5bGUud2hpdGVTcGFjZT0icHJlIix0aGlz"
    "Ll9tZWFzdXJlRWxlbWVudC5zdHlsZS5mb250S2VybmluZz0ibm9uZSIsdGhpcy5fcGFyZW50RWxlbWVudC5hcHBlbmRDaGlsZCh0aGlzLl9tZWFzdXJlRWxl"
    "bWVudCl9bWVhc3VyZSgpe3RoaXMuX21lYXN1cmVFbGVtZW50LnN0eWxlLmZvbnRGYW1pbHk9dGhpcy5fb3B0aW9uc1NlcnZpY2UucmF3T3B0aW9ucy5mb250"
    "RmFtaWx5LHRoaXMuX21lYXN1cmVFbGVtZW50LnN0eWxlLmZvbnRTaXplPWAke3RoaXMuX29wdGlvbnNTZXJ2aWNlLnJhd09wdGlvbnMuZm9udFNpemV9cHhg"
    "O2NvbnN0IGU9e2hlaWdodDpOdW1iZXIodGhpcy5fbWVhc3VyZUVsZW1lbnQub2Zmc2V0SGVpZ2h0KSx3aWR0aDpOdW1iZXIodGhpcy5fbWVhc3VyZUVsZW1l"
    "bnQub2Zmc2V0V2lkdGgpfTtyZXR1cm4gMCE9PWUud2lkdGgmJjAhPT1lLmhlaWdodCYmKHRoaXMuX3Jlc3VsdC53aWR0aD1lLndpZHRoLzMyLHRoaXMuX3Jl"
    "c3VsdC5oZWlnaHQ9TWF0aC5jZWlsKGUuaGVpZ2h0KSksdGhpcy5fcmVzdWx0fX19LDQyNjk6ZnVuY3Rpb24oZSx0LGkpe3ZhciBzPXRoaXMmJnRoaXMuX19k"
    "ZWNvcmF0ZXx8ZnVuY3Rpb24oZSx0LGkscyl7dmFyIHIsbj1hcmd1bWVudHMubGVuZ3RoLG89bjwzP3Q6bnVsbD09PXM/cz1PYmplY3QuZ2V0T3duUHJvcGVy"
    "dHlEZXNjcmlwdG9yKHQsaSk6cztpZigib2JqZWN0Ij09dHlwZW9mIFJlZmxlY3QmJiJmdW5jdGlvbiI9PXR5cGVvZiBSZWZsZWN0LmRlY29yYXRlKW89UmVm"
    "bGVjdC5kZWNvcmF0ZShlLHQsaSxzKTtlbHNlIGZvcih2YXIgYT1lLmxlbmd0aC0xO2E+PTA7YS0tKShyPWVbYV0pJiYobz0objwzP3Iobyk6bj4zP3IodCxp"
    "LG8pOnIodCxpKSl8fG8pO3JldHVybiBuPjMmJm8mJk9iamVjdC5kZWZpbmVQcm9wZXJ0eSh0LGksbyksb30scj10aGlzJiZ0aGlzLl9fcGFyYW18fGZ1bmN0"
    "aW9uKGUsdCl7cmV0dXJuIGZ1bmN0aW9uKGkscyl7dChpLHMsZSl9fTtPYmplY3QuZGVmaW5lUHJvcGVydHkodCwiX19lc01vZHVsZSIse3ZhbHVlOiEwfSks"
    "dC5DaGFyYWN0ZXJKb2luZXJTZXJ2aWNlPXQuSm9pbmVkQ2VsbERhdGE9dm9pZCAwO2NvbnN0IG49aSgzNzM0KSxvPWkoNjQzKSxhPWkoNTExKSxoPWkoMjU4"
    "NSk7Y2xhc3MgYyBleHRlbmRzIG4uQXR0cmlidXRlRGF0YXtjb25zdHJ1Y3RvcihlLHQsaSl7c3VwZXIoKSx0aGlzLmNvbnRlbnQ9MCx0aGlzLmNvbWJpbmVk"
    "RGF0YT0iIix0aGlzLmZnPWUuZmcsdGhpcy5iZz1lLmJnLHRoaXMuY29tYmluZWREYXRhPXQsdGhpcy5fd2lkdGg9aX1pc0NvbWJpbmVkKCl7cmV0dXJuIDIw"
    "OTcxNTJ9Z2V0V2lkdGgoKXtyZXR1cm4gdGhpcy5fd2lkdGh9Z2V0Q2hhcnMoKXtyZXR1cm4gdGhpcy5jb21iaW5lZERhdGF9Z2V0Q29kZSgpe3JldHVybiAy"
    "MDk3MTUxfXNldEZyb21DaGFyRGF0YShlKXt0aHJvdyBuZXcgRXJyb3IoIm5vdCBpbXBsZW1lbnRlZCIpfWdldEFzQ2hhckRhdGEoKXtyZXR1cm5bdGhpcy5m"
    "Zyx0aGlzLmdldENoYXJzKCksdGhpcy5nZXRXaWR0aCgpLHRoaXMuZ2V0Q29kZSgpXX19dC5Kb2luZWRDZWxsRGF0YT1jO2xldCBsPXQuQ2hhcmFjdGVySm9p"
    "bmVyU2VydmljZT1jbGFzcyBle2NvbnN0cnVjdG9yKGUpe3RoaXMuX2J1ZmZlclNlcnZpY2U9ZSx0aGlzLl9jaGFyYWN0ZXJKb2luZXJzPVtdLHRoaXMuX25l"
    "eHRDaGFyYWN0ZXJKb2luZXJJZD0wLHRoaXMuX3dvcmtDZWxsPW5ldyBhLkNlbGxEYXRhfXJlZ2lzdGVyKGUpe2NvbnN0IHQ9e2lkOnRoaXMuX25leHRDaGFy"
    "YWN0ZXJKb2luZXJJZCsrLGhhbmRsZXI6ZX07cmV0dXJuIHRoaXMuX2NoYXJhY3RlckpvaW5lcnMucHVzaCh0KSx0LmlkfWRlcmVnaXN0ZXIoZSl7Zm9yKGxl"
    "dCB0PTA7dDx0aGlzLl9jaGFyYWN0ZXJKb2luZXJzLmxlbmd0aDt0KyspaWYodGhpcy5fY2hhcmFjdGVySm9pbmVyc1t0XS5pZD09PWUpcmV0dXJuIHRoaXMu"
    "X2NoYXJhY3RlckpvaW5lcnMuc3BsaWNlKHQsMSksITA7cmV0dXJuITF9Z2V0Sm9pbmVkQ2hhcmFjdGVycyhlKXtpZigwPT09dGhpcy5fY2hhcmFjdGVySm9p"
    "bmVycy5sZW5ndGgpcmV0dXJuW107Y29uc3QgdD10aGlzLl9idWZmZXJTZXJ2aWNlLmJ1ZmZlci5saW5lcy5nZXQoZSk7aWYoIXR8fDA9PT10Lmxlbmd0aCly"
    "ZXR1cm5bXTtjb25zdCBpPVtdLHM9dC50cmFuc2xhdGVUb1N0cmluZyghMCk7bGV0IHI9MCxuPTAsYT0wLGg9dC5nZXRGZygwKSxjPXQuZ2V0QmcoMCk7Zm9y"
    "KGxldCBlPTA7ZTx0LmdldFRyaW1tZWRMZW5ndGgoKTtlKyspaWYodC5sb2FkQ2VsbChlLHRoaXMuX3dvcmtDZWxsKSwwIT09dGhpcy5fd29ya0NlbGwuZ2V0"
    "V2lkdGgoKSl7aWYodGhpcy5fd29ya0NlbGwuZmchPT1ofHx0aGlzLl93b3JrQ2VsbC5iZyE9PWMpe2lmKGUtcj4xKXtjb25zdCBlPXRoaXMuX2dldEpvaW5l"
    "ZFJhbmdlcyhzLGEsbix0LHIpO2ZvcihsZXQgdD0wO3Q8ZS5sZW5ndGg7dCsrKWkucHVzaChlW3RdKX1yPWUsYT1uLGg9dGhpcy5fd29ya0NlbGwuZmcsYz10"
    "aGlzLl93b3JrQ2VsbC5iZ31uKz10aGlzLl93b3JrQ2VsbC5nZXRDaGFycygpLmxlbmd0aHx8by5XSElURVNQQUNFX0NFTExfQ0hBUi5sZW5ndGh9aWYodGhp"
    "cy5fYnVmZmVyU2VydmljZS5jb2xzLXI+MSl7Y29uc3QgZT10aGlzLl9nZXRKb2luZWRSYW5nZXMocyxhLG4sdCxyKTtmb3IobGV0IHQ9MDt0PGUubGVuZ3Ro"
    "O3QrKylpLnB1c2goZVt0XSl9cmV0dXJuIGl9X2dldEpvaW5lZFJhbmdlcyh0LGkscyxyLG4pe2NvbnN0IG89dC5zdWJzdHJpbmcoaSxzKTtsZXQgYT1bXTt0"
    "cnl7YT10aGlzLl9jaGFyYWN0ZXJKb2luZXJzWzBdLmhhbmRsZXIobyl9Y2F0Y2goZSl7Y29uc29sZS5lcnJvcihlKX1mb3IobGV0IHQ9MTt0PHRoaXMuX2No"
    "YXJhY3RlckpvaW5lcnMubGVuZ3RoO3QrKyl0cnl7Y29uc3QgaT10aGlzLl9jaGFyYWN0ZXJKb2luZXJzW3RdLmhhbmRsZXIobyk7Zm9yKGxldCB0PTA7dDxp"
    "Lmxlbmd0aDt0KyspZS5fbWVyZ2VSYW5nZXMoYSxpW3RdKX1jYXRjaChlKXtjb25zb2xlLmVycm9yKGUpfXJldHVybiB0aGlzLl9zdHJpbmdSYW5nZXNUb0Nl"
    "bGxSYW5nZXMoYSxyLG4pLGF9X3N0cmluZ1Jhbmdlc1RvQ2VsbFJhbmdlcyhlLHQsaSl7bGV0IHM9MCxyPSExLG49MCxhPWVbc107aWYoYSl7Zm9yKGxldCBo"
    "PWk7aDx0aGlzLl9idWZmZXJTZXJ2aWNlLmNvbHM7aCsrKXtjb25zdCBpPXQuZ2V0V2lkdGgoaCksYz10LmdldFN0cmluZyhoKS5sZW5ndGh8fG8uV0hJVEVT"
    "UEFDRV9DRUxMX0NIQVIubGVuZ3RoO2lmKDAhPT1pKXtpZighciYmYVswXTw9biYmKGFbMF09aCxyPSEwKSxhWzFdPD1uKXtpZihhWzFdPWgsYT1lWysrc10s"
    "IWEpYnJlYWs7YVswXTw9bj8oYVswXT1oLHI9ITApOnI9ITF9bis9Y319YSYmKGFbMV09dGhpcy5fYnVmZmVyU2VydmljZS5jb2xzKX19c3RhdGljIF9tZXJn"
    "ZVJhbmdlcyhlLHQpe2xldCBpPSExO2ZvcihsZXQgcz0wO3M8ZS5sZW5ndGg7cysrKXtjb25zdCByPWVbc107aWYoaSl7aWYodFsxXTw9clswXSlyZXR1cm4g"
    "ZVtzLTFdWzFdPXRbMV0sZTtpZih0WzFdPD1yWzFdKXJldHVybiBlW3MtMV1bMV09TWF0aC5tYXgodFsxXSxyWzFdKSxlLnNwbGljZShzLDEpLGU7ZS5zcGxp"
    "Y2UocywxKSxzLS19ZWxzZXtpZih0WzFdPD1yWzBdKXJldHVybiBlLnNwbGljZShzLDAsdCksZTtpZih0WzFdPD1yWzFdKXJldHVybiByWzBdPU1hdGgubWlu"
    "KHRbMF0sclswXSksZTt0WzBdPHJbMV0mJihyWzBdPU1hdGgubWluKHRbMF0sclswXSksaT0hMCl9fXJldHVybiBpP2VbZS5sZW5ndGgtMV1bMV09dFsxXTpl"
    "LnB1c2godCksZX19O3QuQ2hhcmFjdGVySm9pbmVyU2VydmljZT1sPXMoW3IoMCxoLklCdWZmZXJTZXJ2aWNlKV0sbCl9LDUxMTQ6KGUsdCk9PntPYmplY3Qu"
    "ZGVmaW5lUHJvcGVydHkodCwiX19lc01vZHVsZSIse3ZhbHVlOiEwfSksdC5Db3JlQnJvd3NlclNlcnZpY2U9dm9pZCAwLHQuQ29yZUJyb3dzZXJTZXJ2aWNl"
    "PWNsYXNze2NvbnN0cnVjdG9yKGUsdCl7dGhpcy5fdGV4dGFyZWE9ZSx0aGlzLndpbmRvdz10LHRoaXMuX2lzRm9jdXNlZD0hMSx0aGlzLl9jYWNoZWRJc0Zv"
    "Y3VzZWQ9dm9pZCAwLHRoaXMuX3RleHRhcmVhLmFkZEV2ZW50TGlzdGVuZXIoImZvY3VzIiwoKCk9PnRoaXMuX2lzRm9jdXNlZD0hMCkpLHRoaXMuX3RleHRh"
    "cmVhLmFkZEV2ZW50TGlzdGVuZXIoImJsdXIiLCgoKT0+dGhpcy5faXNGb2N1c2VkPSExKSl9Z2V0IGRwcigpe3JldHVybiB0aGlzLndpbmRvdy5kZXZpY2VQ"
    "aXhlbFJhdGlvfWdldCBpc0ZvY3VzZWQoKXtyZXR1cm4gdm9pZCAwPT09dGhpcy5fY2FjaGVkSXNGb2N1c2VkJiYodGhpcy5fY2FjaGVkSXNGb2N1c2VkPXRo"
    "aXMuX2lzRm9jdXNlZCYmdGhpcy5fdGV4dGFyZWEub3duZXJEb2N1bWVudC5oYXNGb2N1cygpLHF1ZXVlTWljcm90YXNrKCgoKT0+dGhpcy5fY2FjaGVkSXNG"
    "b2N1c2VkPXZvaWQgMCkpKSx0aGlzLl9jYWNoZWRJc0ZvY3VzZWR9fX0sODkzNDpmdW5jdGlvbihlLHQsaSl7dmFyIHM9dGhpcyYmdGhpcy5fX2RlY29yYXRl"
    "fHxmdW5jdGlvbihlLHQsaSxzKXt2YXIgcixuPWFyZ3VtZW50cy5sZW5ndGgsbz1uPDM/dDpudWxsPT09cz9zPU9iamVjdC5nZXRPd25Qcm9wZXJ0eURlc2Ny"
    "aXB0b3IodCxpKTpzO2lmKCJvYmplY3QiPT10eXBlb2YgUmVmbGVjdCYmImZ1bmN0aW9uIj09dHlwZW9mIFJlZmxlY3QuZGVjb3JhdGUpbz1SZWZsZWN0LmRl"
    "Y29yYXRlKGUsdCxpLHMpO2Vsc2UgZm9yKHZhciBhPWUubGVuZ3RoLTE7YT49MDthLS0pKHI9ZVthXSkmJihvPShuPDM/cihvKTpuPjM/cih0LGksbyk6cih0"
    "LGkpKXx8byk7cmV0dXJuIG4+MyYmbyYmT2JqZWN0LmRlZmluZVByb3BlcnR5KHQsaSxvKSxvfSxyPXRoaXMmJnRoaXMuX19wYXJhbXx8ZnVuY3Rpb24oZSx0"
    "KXtyZXR1cm4gZnVuY3Rpb24oaSxzKXt0KGkscyxlKX19O09iamVjdC5kZWZpbmVQcm9wZXJ0eSh0LCJfX2VzTW9kdWxlIix7dmFsdWU6ITB9KSx0Lk1vdXNl"
    "U2VydmljZT12b2lkIDA7Y29uc3Qgbj1pKDQ3MjUpLG89aSg5ODA2KTtsZXQgYT10Lk1vdXNlU2VydmljZT1jbGFzc3tjb25zdHJ1Y3RvcihlLHQpe3RoaXMu"
    "X3JlbmRlclNlcnZpY2U9ZSx0aGlzLl9jaGFyU2l6ZVNlcnZpY2U9dH1nZXRDb29yZHMoZSx0LGkscyxyKXtyZXR1cm4oMCxvLmdldENvb3Jkcykod2luZG93"
    "LGUsdCxpLHMsdGhpcy5fY2hhclNpemVTZXJ2aWNlLmhhc1ZhbGlkU2l6ZSx0aGlzLl9yZW5kZXJTZXJ2aWNlLmRpbWVuc2lvbnMuY3NzLmNlbGwud2lkdGgs"
    "dGhpcy5fcmVuZGVyU2VydmljZS5kaW1lbnNpb25zLmNzcy5jZWxsLmhlaWdodCxyKX1nZXRNb3VzZVJlcG9ydENvb3JkcyhlLHQpe2NvbnN0IGk9KDAsby5n"
    "ZXRDb29yZHNSZWxhdGl2ZVRvRWxlbWVudCkod2luZG93LGUsdCk7aWYodGhpcy5fY2hhclNpemVTZXJ2aWNlLmhhc1ZhbGlkU2l6ZSlyZXR1cm4gaVswXT1N"
    "YXRoLm1pbihNYXRoLm1heChpWzBdLDApLHRoaXMuX3JlbmRlclNlcnZpY2UuZGltZW5zaW9ucy5jc3MuY2FudmFzLndpZHRoLTEpLGlbMV09TWF0aC5taW4o"
    "TWF0aC5tYXgoaVsxXSwwKSx0aGlzLl9yZW5kZXJTZXJ2aWNlLmRpbWVuc2lvbnMuY3NzLmNhbnZhcy5oZWlnaHQtMSkse2NvbDpNYXRoLmZsb29yKGlbMF0v"
    "dGhpcy5fcmVuZGVyU2VydmljZS5kaW1lbnNpb25zLmNzcy5jZWxsLndpZHRoKSxyb3c6TWF0aC5mbG9vcihpWzFdL3RoaXMuX3JlbmRlclNlcnZpY2UuZGlt"
    "ZW5zaW9ucy5jc3MuY2VsbC5oZWlnaHQpLHg6TWF0aC5mbG9vcihpWzBdKSx5Ok1hdGguZmxvb3IoaVsxXSl9fX07dC5Nb3VzZVNlcnZpY2U9YT1zKFtyKDAs"
    "bi5JUmVuZGVyU2VydmljZSkscigxLG4uSUNoYXJTaXplU2VydmljZSldLGEpfSwzMjMwOmZ1bmN0aW9uKGUsdCxpKXt2YXIgcz10aGlzJiZ0aGlzLl9fZGVj"
    "b3JhdGV8fGZ1bmN0aW9uKGUsdCxpLHMpe3ZhciByLG49YXJndW1lbnRzLmxlbmd0aCxvPW48Mz90Om51bGw9PT1zP3M9T2JqZWN0LmdldE93blByb3BlcnR5"
    "RGVzY3JpcHRvcih0LGkpOnM7aWYoIm9iamVjdCI9PXR5cGVvZiBSZWZsZWN0JiYiZnVuY3Rpb24iPT10eXBlb2YgUmVmbGVjdC5kZWNvcmF0ZSlvPVJlZmxl"
    "Y3QuZGVjb3JhdGUoZSx0LGkscyk7ZWxzZSBmb3IodmFyIGE9ZS5sZW5ndGgtMTthPj0wO2EtLSkocj1lW2FdKSYmKG89KG48Mz9yKG8pOm4+Mz9yKHQsaSxv"
    "KTpyKHQsaSkpfHxvKTtyZXR1cm4gbj4zJiZvJiZPYmplY3QuZGVmaW5lUHJvcGVydHkodCxpLG8pLG99LHI9dGhpcyYmdGhpcy5fX3BhcmFtfHxmdW5jdGlv"
    "bihlLHQpe3JldHVybiBmdW5jdGlvbihpLHMpe3QoaSxzLGUpfX07T2JqZWN0LmRlZmluZVByb3BlcnR5KHQsIl9fZXNNb2R1bGUiLHt2YWx1ZTohMH0pLHQu"
    "UmVuZGVyU2VydmljZT12b2lkIDA7Y29uc3Qgbj1pKDM2NTYpLG89aSg2MTkzKSxhPWkoNTU5NiksaD1pKDQ3MjUpLGM9aSg4NDYwKSxsPWkoODQ0KSxkPWko"
    "NzIyNiksXz1pKDI1ODUpO2xldCB1PXQuUmVuZGVyU2VydmljZT1jbGFzcyBleHRlbmRzIGwuRGlzcG9zYWJsZXtnZXQgZGltZW5zaW9ucygpe3JldHVybiB0"
    "aGlzLl9yZW5kZXJlci52YWx1ZS5kaW1lbnNpb25zfWNvbnN0cnVjdG9yKGUsdCxpLHMscixoLF8sdSl7aWYoc3VwZXIoKSx0aGlzLl9yb3dDb3VudD1lLHRo"
    "aXMuX2NoYXJTaXplU2VydmljZT1zLHRoaXMuX3JlbmRlcmVyPXRoaXMucmVnaXN0ZXIobmV3IGwuTXV0YWJsZURpc3Bvc2FibGUpLHRoaXMuX3BhdXNlZFJl"
    "c2l6ZVRhc2s9bmV3IGQuRGVib3VuY2VkSWRsZVRhc2ssdGhpcy5faXNQYXVzZWQ9ITEsdGhpcy5fbmVlZHNGdWxsUmVmcmVzaD0hMSx0aGlzLl9pc05leHRS"
    "ZW5kZXJSZWRyYXdPbmx5PSEwLHRoaXMuX25lZWRzU2VsZWN0aW9uUmVmcmVzaD0hMSx0aGlzLl9jYW52YXNXaWR0aD0wLHRoaXMuX2NhbnZhc0hlaWdodD0w"
    "LHRoaXMuX3NlbGVjdGlvblN0YXRlPXtzdGFydDp2b2lkIDAsZW5kOnZvaWQgMCxjb2x1bW5TZWxlY3RNb2RlOiExfSx0aGlzLl9vbkRpbWVuc2lvbnNDaGFu"
    "Z2U9dGhpcy5yZWdpc3RlcihuZXcgYy5FdmVudEVtaXR0ZXIpLHRoaXMub25EaW1lbnNpb25zQ2hhbmdlPXRoaXMuX29uRGltZW5zaW9uc0NoYW5nZS5ldmVu"
    "dCx0aGlzLl9vblJlbmRlcmVkVmlld3BvcnRDaGFuZ2U9dGhpcy5yZWdpc3RlcihuZXcgYy5FdmVudEVtaXR0ZXIpLHRoaXMub25SZW5kZXJlZFZpZXdwb3J0"
    "Q2hhbmdlPXRoaXMuX29uUmVuZGVyZWRWaWV3cG9ydENoYW5nZS5ldmVudCx0aGlzLl9vblJlbmRlcj10aGlzLnJlZ2lzdGVyKG5ldyBjLkV2ZW50RW1pdHRl"
    "ciksdGhpcy5vblJlbmRlcj10aGlzLl9vblJlbmRlci5ldmVudCx0aGlzLl9vblJlZnJlc2hSZXF1ZXN0PXRoaXMucmVnaXN0ZXIobmV3IGMuRXZlbnRFbWl0"
    "dGVyKSx0aGlzLm9uUmVmcmVzaFJlcXVlc3Q9dGhpcy5fb25SZWZyZXNoUmVxdWVzdC5ldmVudCx0aGlzLl9yZW5kZXJEZWJvdW5jZXI9bmV3IG8uUmVuZGVy"
    "RGVib3VuY2VyKF8ud2luZG93LCgoZSx0KT0+dGhpcy5fcmVuZGVyUm93cyhlLHQpKSksdGhpcy5yZWdpc3Rlcih0aGlzLl9yZW5kZXJEZWJvdW5jZXIpLHRo"
    "aXMuX3NjcmVlbkRwck1vbml0b3I9bmV3IGEuU2NyZWVuRHByTW9uaXRvcihfLndpbmRvdyksdGhpcy5fc2NyZWVuRHByTW9uaXRvci5zZXRMaXN0ZW5lcigo"
    "KCk9PnRoaXMuaGFuZGxlRGV2aWNlUGl4ZWxSYXRpb0NoYW5nZSgpKSksdGhpcy5yZWdpc3Rlcih0aGlzLl9zY3JlZW5EcHJNb25pdG9yKSx0aGlzLnJlZ2lz"
    "dGVyKGgub25SZXNpemUoKCgpPT50aGlzLl9mdWxsUmVmcmVzaCgpKSkpLHRoaXMucmVnaXN0ZXIoaC5idWZmZXJzLm9uQnVmZmVyQWN0aXZhdGUoKCgpPT57"
    "dmFyIGU7cmV0dXJuIG51bGw9PT0oZT10aGlzLl9yZW5kZXJlci52YWx1ZSl8fHZvaWQgMD09PWU/dm9pZCAwOmUuY2xlYXIoKX0pKSksdGhpcy5yZWdpc3Rl"
    "cihpLm9uT3B0aW9uQ2hhbmdlKCgoKT0+dGhpcy5faGFuZGxlT3B0aW9uc0NoYW5nZWQoKSkpKSx0aGlzLnJlZ2lzdGVyKHRoaXMuX2NoYXJTaXplU2Vydmlj"
    "ZS5vbkNoYXJTaXplQ2hhbmdlKCgoKT0+dGhpcy5oYW5kbGVDaGFyU2l6ZUNoYW5nZWQoKSkpKSx0aGlzLnJlZ2lzdGVyKHIub25EZWNvcmF0aW9uUmVnaXN0"
    "ZXJlZCgoKCk9PnRoaXMuX2Z1bGxSZWZyZXNoKCkpKSksdGhpcy5yZWdpc3RlcihyLm9uRGVjb3JhdGlvblJlbW92ZWQoKCgpPT50aGlzLl9mdWxsUmVmcmVz"
    "aCgpKSkpLHRoaXMucmVnaXN0ZXIoaS5vbk11bHRpcGxlT3B0aW9uQ2hhbmdlKFsiY3VzdG9tR2x5cGhzIiwiZHJhd0JvbGRUZXh0SW5CcmlnaHRDb2xvcnMi"
    "LCJsZXR0ZXJTcGFjaW5nIiwibGluZUhlaWdodCIsImZvbnRGYW1pbHkiLCJmb250U2l6ZSIsImZvbnRXZWlnaHQiLCJmb250V2VpZ2h0Qm9sZCIsIm1pbmlt"
    "dW1Db250cmFzdFJhdGlvIl0sKCgpPT57dGhpcy5jbGVhcigpLHRoaXMuaGFuZGxlUmVzaXplKGguY29scyxoLnJvd3MpLHRoaXMuX2Z1bGxSZWZyZXNoKCl9"
    "KSkpLHRoaXMucmVnaXN0ZXIoaS5vbk11bHRpcGxlT3B0aW9uQ2hhbmdlKFsiY3Vyc29yQmxpbmsiLCJjdXJzb3JTdHlsZSJdLCgoKT0+dGhpcy5yZWZyZXNo"
    "Um93cyhoLmJ1ZmZlci55LGguYnVmZmVyLnksITApKSkpLHRoaXMucmVnaXN0ZXIoKDAsbi5hZGREaXNwb3NhYmxlRG9tTGlzdGVuZXIpKF8ud2luZG93LCJy"
    "ZXNpemUiLCgoKT0+dGhpcy5oYW5kbGVEZXZpY2VQaXhlbFJhdGlvQ2hhbmdlKCkpKSksdGhpcy5yZWdpc3Rlcih1Lm9uQ2hhbmdlQ29sb3JzKCgoKT0+dGhp"
    "cy5fZnVsbFJlZnJlc2goKSkpKSwiSW50ZXJzZWN0aW9uT2JzZXJ2ZXIiaW4gXy53aW5kb3cpe2NvbnN0IGU9bmV3IF8ud2luZG93LkludGVyc2VjdGlvbk9i"
    "c2VydmVyKChlPT50aGlzLl9oYW5kbGVJbnRlcnNlY3Rpb25DaGFuZ2UoZVtlLmxlbmd0aC0xXSkpLHt0aHJlc2hvbGQ6MH0pO2Uub2JzZXJ2ZSh0KSx0aGlz"
    "LnJlZ2lzdGVyKHtkaXNwb3NlOigpPT5lLmRpc2Nvbm5lY3QoKX0pfX1faGFuZGxlSW50ZXJzZWN0aW9uQ2hhbmdlKGUpe3RoaXMuX2lzUGF1c2VkPXZvaWQg"
    "MD09PWUuaXNJbnRlcnNlY3Rpbmc/MD09PWUuaW50ZXJzZWN0aW9uUmF0aW86IWUuaXNJbnRlcnNlY3RpbmcsdGhpcy5faXNQYXVzZWR8fHRoaXMuX2NoYXJT"
    "aXplU2VydmljZS5oYXNWYWxpZFNpemV8fHRoaXMuX2NoYXJTaXplU2VydmljZS5tZWFzdXJlKCksIXRoaXMuX2lzUGF1c2VkJiZ0aGlzLl9uZWVkc0Z1bGxS"
    "ZWZyZXNoJiYodGhpcy5fcGF1c2VkUmVzaXplVGFzay5mbHVzaCgpLHRoaXMucmVmcmVzaFJvd3MoMCx0aGlzLl9yb3dDb3VudC0xKSx0aGlzLl9uZWVkc0Z1"
    "bGxSZWZyZXNoPSExKX1yZWZyZXNoUm93cyhlLHQsaT0hMSl7dGhpcy5faXNQYXVzZWQ/dGhpcy5fbmVlZHNGdWxsUmVmcmVzaD0hMDooaXx8KHRoaXMuX2lz"
    "TmV4dFJlbmRlclJlZHJhd09ubHk9ITEpLHRoaXMuX3JlbmRlckRlYm91bmNlci5yZWZyZXNoKGUsdCx0aGlzLl9yb3dDb3VudCkpfV9yZW5kZXJSb3dzKGUs"
    "dCl7dGhpcy5fcmVuZGVyZXIudmFsdWUmJihlPU1hdGgubWluKGUsdGhpcy5fcm93Q291bnQtMSksdD1NYXRoLm1pbih0LHRoaXMuX3Jvd0NvdW50LTEpLHRo"
    "aXMuX3JlbmRlcmVyLnZhbHVlLnJlbmRlclJvd3MoZSx0KSx0aGlzLl9uZWVkc1NlbGVjdGlvblJlZnJlc2gmJih0aGlzLl9yZW5kZXJlci52YWx1ZS5oYW5k"
    "bGVTZWxlY3Rpb25DaGFuZ2VkKHRoaXMuX3NlbGVjdGlvblN0YXRlLnN0YXJ0LHRoaXMuX3NlbGVjdGlvblN0YXRlLmVuZCx0aGlzLl9zZWxlY3Rpb25TdGF0"
    "ZS5jb2x1bW5TZWxlY3RNb2RlKSx0aGlzLl9uZWVkc1NlbGVjdGlvblJlZnJlc2g9ITEpLHRoaXMuX2lzTmV4dFJlbmRlclJlZHJhd09ubHl8fHRoaXMuX29u"
    "UmVuZGVyZWRWaWV3cG9ydENoYW5nZS5maXJlKHtzdGFydDplLGVuZDp0fSksdGhpcy5fb25SZW5kZXIuZmlyZSh7c3RhcnQ6ZSxlbmQ6dH0pLHRoaXMuX2lz"
    "TmV4dFJlbmRlclJlZHJhd09ubHk9ITApfXJlc2l6ZShlLHQpe3RoaXMuX3Jvd0NvdW50PXQsdGhpcy5fZmlyZU9uQ2FudmFzUmVzaXplKCl9X2hhbmRsZU9w"
    "dGlvbnNDaGFuZ2VkKCl7dGhpcy5fcmVuZGVyZXIudmFsdWUmJih0aGlzLnJlZnJlc2hSb3dzKDAsdGhpcy5fcm93Q291bnQtMSksdGhpcy5fZmlyZU9uQ2Fu"
    "dmFzUmVzaXplKCkpfV9maXJlT25DYW52YXNSZXNpemUoKXt0aGlzLl9yZW5kZXJlci52YWx1ZSYmKHRoaXMuX3JlbmRlcmVyLnZhbHVlLmRpbWVuc2lvbnMu"
    "Y3NzLmNhbnZhcy53aWR0aD09PXRoaXMuX2NhbnZhc1dpZHRoJiZ0aGlzLl9yZW5kZXJlci52YWx1ZS5kaW1lbnNpb25zLmNzcy5jYW52YXMuaGVpZ2h0PT09"
    "dGhpcy5fY2FudmFzSGVpZ2h0fHx0aGlzLl9vbkRpbWVuc2lvbnNDaGFuZ2UuZmlyZSh0aGlzLl9yZW5kZXJlci52YWx1ZS5kaW1lbnNpb25zKSl9aGFzUmVu"
    "ZGVyZXIoKXtyZXR1cm4hIXRoaXMuX3JlbmRlcmVyLnZhbHVlfXNldFJlbmRlcmVyKGUpe3RoaXMuX3JlbmRlcmVyLnZhbHVlPWUsdGhpcy5fcmVuZGVyZXIu"
    "dmFsdWUub25SZXF1ZXN0UmVkcmF3KChlPT50aGlzLnJlZnJlc2hSb3dzKGUuc3RhcnQsZS5lbmQsITApKSksdGhpcy5fbmVlZHNTZWxlY3Rpb25SZWZyZXNo"
    "PSEwLHRoaXMuX2Z1bGxSZWZyZXNoKCl9YWRkUmVmcmVzaENhbGxiYWNrKGUpe3JldHVybiB0aGlzLl9yZW5kZXJEZWJvdW5jZXIuYWRkUmVmcmVzaENhbGxi"
    "YWNrKGUpfV9mdWxsUmVmcmVzaCgpe3RoaXMuX2lzUGF1c2VkP3RoaXMuX25lZWRzRnVsbFJlZnJlc2g9ITA6dGhpcy5yZWZyZXNoUm93cygwLHRoaXMuX3Jv"
    "d0NvdW50LTEpfWNsZWFyVGV4dHVyZUF0bGFzKCl7dmFyIGUsdDt0aGlzLl9yZW5kZXJlci52YWx1ZSYmKG51bGw9PT0odD0oZT10aGlzLl9yZW5kZXJlci52"
    "YWx1ZSkuY2xlYXJUZXh0dXJlQXRsYXMpfHx2b2lkIDA9PT10fHx0LmNhbGwoZSksdGhpcy5fZnVsbFJlZnJlc2goKSl9aGFuZGxlRGV2aWNlUGl4ZWxSYXRp"
    "b0NoYW5nZSgpe3RoaXMuX2NoYXJTaXplU2VydmljZS5tZWFzdXJlKCksdGhpcy5fcmVuZGVyZXIudmFsdWUmJih0aGlzLl9yZW5kZXJlci52YWx1ZS5oYW5k"
    "bGVEZXZpY2VQaXhlbFJhdGlvQ2hhbmdlKCksdGhpcy5yZWZyZXNoUm93cygwLHRoaXMuX3Jvd0NvdW50LTEpKX1oYW5kbGVSZXNpemUoZSx0KXt0aGlzLl9y"
    "ZW5kZXJlci52YWx1ZSYmKHRoaXMuX2lzUGF1c2VkP3RoaXMuX3BhdXNlZFJlc2l6ZVRhc2suc2V0KCgoKT0+dGhpcy5fcmVuZGVyZXIudmFsdWUuaGFuZGxl"
    "UmVzaXplKGUsdCkpKTp0aGlzLl9yZW5kZXJlci52YWx1ZS5oYW5kbGVSZXNpemUoZSx0KSx0aGlzLl9mdWxsUmVmcmVzaCgpKX1oYW5kbGVDaGFyU2l6ZUNo"
    "YW5nZWQoKXt2YXIgZTtudWxsPT09KGU9dGhpcy5fcmVuZGVyZXIudmFsdWUpfHx2b2lkIDA9PT1lfHxlLmhhbmRsZUNoYXJTaXplQ2hhbmdlZCgpfWhhbmRs"
    "ZUJsdXIoKXt2YXIgZTtudWxsPT09KGU9dGhpcy5fcmVuZGVyZXIudmFsdWUpfHx2b2lkIDA9PT1lfHxlLmhhbmRsZUJsdXIoKX1oYW5kbGVGb2N1cygpe3Zh"
    "ciBlO251bGw9PT0oZT10aGlzLl9yZW5kZXJlci52YWx1ZSl8fHZvaWQgMD09PWV8fGUuaGFuZGxlRm9jdXMoKX1oYW5kbGVTZWxlY3Rpb25DaGFuZ2VkKGUs"
    "dCxpKXt2YXIgczt0aGlzLl9zZWxlY3Rpb25TdGF0ZS5zdGFydD1lLHRoaXMuX3NlbGVjdGlvblN0YXRlLmVuZD10LHRoaXMuX3NlbGVjdGlvblN0YXRlLmNv"
    "bHVtblNlbGVjdE1vZGU9aSxudWxsPT09KHM9dGhpcy5fcmVuZGVyZXIudmFsdWUpfHx2b2lkIDA9PT1zfHxzLmhhbmRsZVNlbGVjdGlvbkNoYW5nZWQoZSx0"
    "LGkpfWhhbmRsZUN1cnNvck1vdmUoKXt2YXIgZTtudWxsPT09KGU9dGhpcy5fcmVuZGVyZXIudmFsdWUpfHx2b2lkIDA9PT1lfHxlLmhhbmRsZUN1cnNvck1v"
    "dmUoKX1jbGVhcigpe3ZhciBlO251bGw9PT0oZT10aGlzLl9yZW5kZXJlci52YWx1ZSl8fHZvaWQgMD09PWV8fGUuY2xlYXIoKX19O3QuUmVuZGVyU2Vydmlj"
    "ZT11PXMoW3IoMixfLklPcHRpb25zU2VydmljZSkscigzLGguSUNoYXJTaXplU2VydmljZSkscig0LF8uSURlY29yYXRpb25TZXJ2aWNlKSxyKDUsXy5JQnVm"
    "ZmVyU2VydmljZSkscig2LGguSUNvcmVCcm93c2VyU2VydmljZSkscig3LGguSVRoZW1lU2VydmljZSldLHUpfSw5MzEyOmZ1bmN0aW9uKGUsdCxpKXt2YXIg"
    "cz10aGlzJiZ0aGlzLl9fZGVjb3JhdGV8fGZ1bmN0aW9uKGUsdCxpLHMpe3ZhciByLG49YXJndW1lbnRzLmxlbmd0aCxvPW48Mz90Om51bGw9PT1zP3M9T2Jq"
    "ZWN0LmdldE93blByb3BlcnR5RGVzY3JpcHRvcih0LGkpOnM7aWYoIm9iamVjdCI9PXR5cGVvZiBSZWZsZWN0JiYiZnVuY3Rpb24iPT10eXBlb2YgUmVmbGVj"
    "dC5kZWNvcmF0ZSlvPVJlZmxlY3QuZGVjb3JhdGUoZSx0LGkscyk7ZWxzZSBmb3IodmFyIGE9ZS5sZW5ndGgtMTthPj0wO2EtLSkocj1lW2FdKSYmKG89KG48"
    "Mz9yKG8pOm4+Mz9yKHQsaSxvKTpyKHQsaSkpfHxvKTtyZXR1cm4gbj4zJiZvJiZPYmplY3QuZGVmaW5lUHJvcGVydHkodCxpLG8pLG99LHI9dGhpcyYmdGhp"
    "cy5fX3BhcmFtfHxmdW5jdGlvbihlLHQpe3JldHVybiBmdW5jdGlvbihpLHMpe3QoaSxzLGUpfX07T2JqZWN0LmRlZmluZVByb3BlcnR5KHQsIl9fZXNNb2R1"
    "bGUiLHt2YWx1ZTohMH0pLHQuU2VsZWN0aW9uU2VydmljZT12b2lkIDA7Y29uc3Qgbj1pKDk4MDYpLG89aSg5NTA0KSxhPWkoNDU2KSxoPWkoNDcyNSksYz1p"
    "KDg0NjApLGw9aSg4NDQpLGQ9aSg2MTE0KSxfPWkoNDg0MSksdT1pKDUxMSksZj1pKDI1ODUpLHY9U3RyaW5nLmZyb21DaGFyQ29kZSgxNjApLHA9bmV3IFJl"
    "Z0V4cCh2LCJnIik7bGV0IGc9dC5TZWxlY3Rpb25TZXJ2aWNlPWNsYXNzIGV4dGVuZHMgbC5EaXNwb3NhYmxle2NvbnN0cnVjdG9yKGUsdCxpLHMscixuLG8s"
    "aCxkKXtzdXBlcigpLHRoaXMuX2VsZW1lbnQ9ZSx0aGlzLl9zY3JlZW5FbGVtZW50PXQsdGhpcy5fbGlua2lmaWVyPWksdGhpcy5fYnVmZmVyU2VydmljZT1z"
    "LHRoaXMuX2NvcmVTZXJ2aWNlPXIsdGhpcy5fbW91c2VTZXJ2aWNlPW4sdGhpcy5fb3B0aW9uc1NlcnZpY2U9byx0aGlzLl9yZW5kZXJTZXJ2aWNlPWgsdGhp"
    "cy5fY29yZUJyb3dzZXJTZXJ2aWNlPWQsdGhpcy5fZHJhZ1Njcm9sbEFtb3VudD0wLHRoaXMuX2VuYWJsZWQ9ITAsdGhpcy5fd29ya0NlbGw9bmV3IHUuQ2Vs"
    "bERhdGEsdGhpcy5fbW91c2VEb3duVGltZVN0YW1wPTAsdGhpcy5fb2xkSGFzU2VsZWN0aW9uPSExLHRoaXMuX29sZFNlbGVjdGlvblN0YXJ0PXZvaWQgMCx0"
    "aGlzLl9vbGRTZWxlY3Rpb25FbmQ9dm9pZCAwLHRoaXMuX29uTGludXhNb3VzZVNlbGVjdGlvbj10aGlzLnJlZ2lzdGVyKG5ldyBjLkV2ZW50RW1pdHRlciks"
    "dGhpcy5vbkxpbnV4TW91c2VTZWxlY3Rpb249dGhpcy5fb25MaW51eE1vdXNlU2VsZWN0aW9uLmV2ZW50LHRoaXMuX29uUmVkcmF3UmVxdWVzdD10aGlzLnJl"
    "Z2lzdGVyKG5ldyBjLkV2ZW50RW1pdHRlciksdGhpcy5vblJlcXVlc3RSZWRyYXc9dGhpcy5fb25SZWRyYXdSZXF1ZXN0LmV2ZW50LHRoaXMuX29uU2VsZWN0"
    "aW9uQ2hhbmdlPXRoaXMucmVnaXN0ZXIobmV3IGMuRXZlbnRFbWl0dGVyKSx0aGlzLm9uU2VsZWN0aW9uQ2hhbmdlPXRoaXMuX29uU2VsZWN0aW9uQ2hhbmdl"
    "LmV2ZW50LHRoaXMuX29uUmVxdWVzdFNjcm9sbExpbmVzPXRoaXMucmVnaXN0ZXIobmV3IGMuRXZlbnRFbWl0dGVyKSx0aGlzLm9uUmVxdWVzdFNjcm9sbExp"
    "bmVzPXRoaXMuX29uUmVxdWVzdFNjcm9sbExpbmVzLmV2ZW50LHRoaXMuX21vdXNlTW92ZUxpc3RlbmVyPWU9PnRoaXMuX2hhbmRsZU1vdXNlTW92ZShlKSx0"
    "aGlzLl9tb3VzZVVwTGlzdGVuZXI9ZT0+dGhpcy5faGFuZGxlTW91c2VVcChlKSx0aGlzLl9jb3JlU2VydmljZS5vblVzZXJJbnB1dCgoKCk9Pnt0aGlzLmhh"
    "c1NlbGVjdGlvbiYmdGhpcy5jbGVhclNlbGVjdGlvbigpfSkpLHRoaXMuX3RyaW1MaXN0ZW5lcj10aGlzLl9idWZmZXJTZXJ2aWNlLmJ1ZmZlci5saW5lcy5v"
    "blRyaW0oKGU9PnRoaXMuX2hhbmRsZVRyaW0oZSkpKSx0aGlzLnJlZ2lzdGVyKHRoaXMuX2J1ZmZlclNlcnZpY2UuYnVmZmVycy5vbkJ1ZmZlckFjdGl2YXRl"
    "KChlPT50aGlzLl9oYW5kbGVCdWZmZXJBY3RpdmF0ZShlKSkpKSx0aGlzLmVuYWJsZSgpLHRoaXMuX21vZGVsPW5ldyBhLlNlbGVjdGlvbk1vZGVsKHRoaXMu"
    "X2J1ZmZlclNlcnZpY2UpLHRoaXMuX2FjdGl2ZVNlbGVjdGlvbk1vZGU9MCx0aGlzLnJlZ2lzdGVyKCgwLGwudG9EaXNwb3NhYmxlKSgoKCk9Pnt0aGlzLl9y"
    "ZW1vdmVNb3VzZURvd25MaXN0ZW5lcnMoKX0pKSl9cmVzZXQoKXt0aGlzLmNsZWFyU2VsZWN0aW9uKCl9ZGlzYWJsZSgpe3RoaXMuY2xlYXJTZWxlY3Rpb24o"
    "KSx0aGlzLl9lbmFibGVkPSExfWVuYWJsZSgpe3RoaXMuX2VuYWJsZWQ9ITB9Z2V0IHNlbGVjdGlvblN0YXJ0KCl7cmV0dXJuIHRoaXMuX21vZGVsLmZpbmFs"
    "U2VsZWN0aW9uU3RhcnR9Z2V0IHNlbGVjdGlvbkVuZCgpe3JldHVybiB0aGlzLl9tb2RlbC5maW5hbFNlbGVjdGlvbkVuZH1nZXQgaGFzU2VsZWN0aW9uKCl7"
    "Y29uc3QgZT10aGlzLl9tb2RlbC5maW5hbFNlbGVjdGlvblN0YXJ0LHQ9dGhpcy5fbW9kZWwuZmluYWxTZWxlY3Rpb25FbmQ7cmV0dXJuISghZXx8IXR8fGVb"
    "MF09PT10WzBdJiZlWzFdPT09dFsxXSl9Z2V0IHNlbGVjdGlvblRleHQoKXtjb25zdCBlPXRoaXMuX21vZGVsLmZpbmFsU2VsZWN0aW9uU3RhcnQsdD10aGlz"
    "Ll9tb2RlbC5maW5hbFNlbGVjdGlvbkVuZDtpZighZXx8IXQpcmV0dXJuIiI7Y29uc3QgaT10aGlzLl9idWZmZXJTZXJ2aWNlLmJ1ZmZlcixzPVtdO2lmKDM9"
    "PT10aGlzLl9hY3RpdmVTZWxlY3Rpb25Nb2RlKXtpZihlWzBdPT09dFswXSlyZXR1cm4iIjtjb25zdCByPWVbMF08dFswXT9lWzBdOnRbMF0sbj1lWzBdPHRb"
    "MF0/dFswXTplWzBdO2ZvcihsZXQgbz1lWzFdO288PXRbMV07bysrKXtjb25zdCBlPWkudHJhbnNsYXRlQnVmZmVyTGluZVRvU3RyaW5nKG8sITAscixuKTtz"
    "LnB1c2goZSl9fWVsc2V7Y29uc3Qgcj1lWzFdPT09dFsxXT90WzBdOnZvaWQgMDtzLnB1c2goaS50cmFuc2xhdGVCdWZmZXJMaW5lVG9TdHJpbmcoZVsxXSwh"
    "MCxlWzBdLHIpKTtmb3IobGV0IHI9ZVsxXSsxO3I8PXRbMV0tMTtyKyspe2NvbnN0IGU9aS5saW5lcy5nZXQociksdD1pLnRyYW5zbGF0ZUJ1ZmZlckxpbmVU"
    "b1N0cmluZyhyLCEwKTsobnVsbD09ZT92b2lkIDA6ZS5pc1dyYXBwZWQpP3Nbcy5sZW5ndGgtMV0rPXQ6cy5wdXNoKHQpfWlmKGVbMV0hPT10WzFdKXtjb25z"
    "dCBlPWkubGluZXMuZ2V0KHRbMV0pLHI9aS50cmFuc2xhdGVCdWZmZXJMaW5lVG9TdHJpbmcodFsxXSwhMCwwLHRbMF0pO2UmJmUuaXNXcmFwcGVkP3Nbcy5s"
    "ZW5ndGgtMV0rPXI6cy5wdXNoKHIpfX1yZXR1cm4gcy5tYXAoKGU9PmUucmVwbGFjZShwLCIgIikpKS5qb2luKGQuaXNXaW5kb3dzPyJcclxuIjoiXG4iKX1j"
    "bGVhclNlbGVjdGlvbigpe3RoaXMuX21vZGVsLmNsZWFyU2VsZWN0aW9uKCksdGhpcy5fcmVtb3ZlTW91c2VEb3duTGlzdGVuZXJzKCksdGhpcy5yZWZyZXNo"
    "KCksdGhpcy5fb25TZWxlY3Rpb25DaGFuZ2UuZmlyZSgpfXJlZnJlc2goZSl7dGhpcy5fcmVmcmVzaEFuaW1hdGlvbkZyYW1lfHwodGhpcy5fcmVmcmVzaEFu"
    "aW1hdGlvbkZyYW1lPXRoaXMuX2NvcmVCcm93c2VyU2VydmljZS53aW5kb3cucmVxdWVzdEFuaW1hdGlvbkZyYW1lKCgoKT0+dGhpcy5fcmVmcmVzaCgpKSkp"
    "LGQuaXNMaW51eCYmZSYmdGhpcy5zZWxlY3Rpb25UZXh0Lmxlbmd0aCYmdGhpcy5fb25MaW51eE1vdXNlU2VsZWN0aW9uLmZpcmUodGhpcy5zZWxlY3Rpb25U"
    "ZXh0KX1fcmVmcmVzaCgpe3RoaXMuX3JlZnJlc2hBbmltYXRpb25GcmFtZT12b2lkIDAsdGhpcy5fb25SZWRyYXdSZXF1ZXN0LmZpcmUoe3N0YXJ0OnRoaXMu"
    "X21vZGVsLmZpbmFsU2VsZWN0aW9uU3RhcnQsZW5kOnRoaXMuX21vZGVsLmZpbmFsU2VsZWN0aW9uRW5kLGNvbHVtblNlbGVjdE1vZGU6Mz09PXRoaXMuX2Fj"
    "dGl2ZVNlbGVjdGlvbk1vZGV9KX1faXNDbGlja0luU2VsZWN0aW9uKGUpe2NvbnN0IHQ9dGhpcy5fZ2V0TW91c2VCdWZmZXJDb29yZHMoZSksaT10aGlzLl9t"
    "b2RlbC5maW5hbFNlbGVjdGlvblN0YXJ0LHM9dGhpcy5fbW9kZWwuZmluYWxTZWxlY3Rpb25FbmQ7cmV0dXJuISEoaSYmcyYmdCkmJnRoaXMuX2FyZUNvb3Jk"
    "c0luU2VsZWN0aW9uKHQsaSxzKX1pc0NlbGxJblNlbGVjdGlvbihlLHQpe2NvbnN0IGk9dGhpcy5fbW9kZWwuZmluYWxTZWxlY3Rpb25TdGFydCxzPXRoaXMu"
    "X21vZGVsLmZpbmFsU2VsZWN0aW9uRW5kO3JldHVybiEoIWl8fCFzKSYmdGhpcy5fYXJlQ29vcmRzSW5TZWxlY3Rpb24oW2UsdF0saSxzKX1fYXJlQ29vcmRz"
    "SW5TZWxlY3Rpb24oZSx0LGkpe3JldHVybiBlWzFdPnRbMV0mJmVbMV08aVsxXXx8dFsxXT09PWlbMV0mJmVbMV09PT10WzFdJiZlWzBdPj10WzBdJiZlWzBd"
    "PGlbMF18fHRbMV08aVsxXSYmZVsxXT09PWlbMV0mJmVbMF08aVswXXx8dFsxXTxpWzFdJiZlWzFdPT09dFsxXSYmZVswXT49dFswXX1fc2VsZWN0V29yZEF0"
    "Q3Vyc29yKGUsdCl7dmFyIGkscztjb25zdCByPW51bGw9PT0ocz1udWxsPT09KGk9dGhpcy5fbGlua2lmaWVyLmN1cnJlbnRMaW5rKXx8dm9pZCAwPT09aT92"
    "b2lkIDA6aS5saW5rKXx8dm9pZCAwPT09cz92b2lkIDA6cy5yYW5nZTtpZihyKXJldHVybiB0aGlzLl9tb2RlbC5zZWxlY3Rpb25TdGFydD1bci5zdGFydC54"
    "LTEsci5zdGFydC55LTFdLHRoaXMuX21vZGVsLnNlbGVjdGlvblN0YXJ0TGVuZ3RoPSgwLF8uZ2V0UmFuZ2VMZW5ndGgpKHIsdGhpcy5fYnVmZmVyU2Vydmlj"
    "ZS5jb2xzKSx0aGlzLl9tb2RlbC5zZWxlY3Rpb25FbmQ9dm9pZCAwLCEwO2NvbnN0IG49dGhpcy5fZ2V0TW91c2VCdWZmZXJDb29yZHMoZSk7cmV0dXJuISFu"
    "JiYodGhpcy5fc2VsZWN0V29yZEF0KG4sdCksdGhpcy5fbW9kZWwuc2VsZWN0aW9uRW5kPXZvaWQgMCwhMCl9c2VsZWN0QWxsKCl7dGhpcy5fbW9kZWwuaXNT"
    "ZWxlY3RBbGxBY3RpdmU9ITAsdGhpcy5yZWZyZXNoKCksdGhpcy5fb25TZWxlY3Rpb25DaGFuZ2UuZmlyZSgpfXNlbGVjdExpbmVzKGUsdCl7dGhpcy5fbW9k"
    "ZWwuY2xlYXJTZWxlY3Rpb24oKSxlPU1hdGgubWF4KGUsMCksdD1NYXRoLm1pbih0LHRoaXMuX2J1ZmZlclNlcnZpY2UuYnVmZmVyLmxpbmVzLmxlbmd0aC0x"
    "KSx0aGlzLl9tb2RlbC5zZWxlY3Rpb25TdGFydD1bMCxlXSx0aGlzLl9tb2RlbC5zZWxlY3Rpb25FbmQ9W3RoaXMuX2J1ZmZlclNlcnZpY2UuY29scyx0XSx0"
    "aGlzLnJlZnJlc2goKSx0aGlzLl9vblNlbGVjdGlvbkNoYW5nZS5maXJlKCl9X2hhbmRsZVRyaW0oZSl7dGhpcy5fbW9kZWwuaGFuZGxlVHJpbShlKSYmdGhp"
    "cy5yZWZyZXNoKCl9X2dldE1vdXNlQnVmZmVyQ29vcmRzKGUpe2NvbnN0IHQ9dGhpcy5fbW91c2VTZXJ2aWNlLmdldENvb3JkcyhlLHRoaXMuX3NjcmVlbkVs"
    "ZW1lbnQsdGhpcy5fYnVmZmVyU2VydmljZS5jb2xzLHRoaXMuX2J1ZmZlclNlcnZpY2Uucm93cywhMCk7aWYodClyZXR1cm4gdFswXS0tLHRbMV0tLSx0WzFd"
    "Kz10aGlzLl9idWZmZXJTZXJ2aWNlLmJ1ZmZlci55ZGlzcCx0fV9nZXRNb3VzZUV2ZW50U2Nyb2xsQW1vdW50KGUpe2xldCB0PSgwLG4uZ2V0Q29vcmRzUmVs"
    "YXRpdmVUb0VsZW1lbnQpKHRoaXMuX2NvcmVCcm93c2VyU2VydmljZS53aW5kb3csZSx0aGlzLl9zY3JlZW5FbGVtZW50KVsxXTtjb25zdCBpPXRoaXMuX3Jl"
    "bmRlclNlcnZpY2UuZGltZW5zaW9ucy5jc3MuY2FudmFzLmhlaWdodDtyZXR1cm4gdD49MCYmdDw9aT8wOih0PmkmJih0LT1pKSx0PU1hdGgubWluKE1hdGgu"
    "bWF4KHQsLTUwKSw1MCksdC89NTAsdC9NYXRoLmFicyh0KStNYXRoLnJvdW5kKDE0KnQpKX1zaG91bGRGb3JjZVNlbGVjdGlvbihlKXtyZXR1cm4gZC5pc01h"
    "Yz9lLmFsdEtleSYmdGhpcy5fb3B0aW9uc1NlcnZpY2UucmF3T3B0aW9ucy5tYWNPcHRpb25DbGlja0ZvcmNlc1NlbGVjdGlvbjplLnNoaWZ0S2V5fWhhbmRs"
    "ZU1vdXNlRG93bihlKXtpZih0aGlzLl9tb3VzZURvd25UaW1lU3RhbXA9ZS50aW1lU3RhbXAsKDIhPT1lLmJ1dHRvbnx8IXRoaXMuaGFzU2VsZWN0aW9uKSYm"
    "MD09PWUuYnV0dG9uKXtpZighdGhpcy5fZW5hYmxlZCl7aWYoIXRoaXMuc2hvdWxkRm9yY2VTZWxlY3Rpb24oZSkpcmV0dXJuO2Uuc3RvcFByb3BhZ2F0aW9u"
    "KCl9ZS5wcmV2ZW50RGVmYXVsdCgpLHRoaXMuX2RyYWdTY3JvbGxBbW91bnQ9MCx0aGlzLl9lbmFibGVkJiZlLnNoaWZ0S2V5P3RoaXMuX2hhbmRsZUluY3Jl"
    "bWVudGFsQ2xpY2soZSk6MT09PWUuZGV0YWlsP3RoaXMuX2hhbmRsZVNpbmdsZUNsaWNrKGUpOjI9PT1lLmRldGFpbD90aGlzLl9oYW5kbGVEb3VibGVDbGlj"
    "ayhlKTozPT09ZS5kZXRhaWwmJnRoaXMuX2hhbmRsZVRyaXBsZUNsaWNrKGUpLHRoaXMuX2FkZE1vdXNlRG93bkxpc3RlbmVycygpLHRoaXMucmVmcmVzaCgh"
    "MCl9fV9hZGRNb3VzZURvd25MaXN0ZW5lcnMoKXt0aGlzLl9zY3JlZW5FbGVtZW50Lm93bmVyRG9jdW1lbnQmJih0aGlzLl9zY3JlZW5FbGVtZW50Lm93bmVy"
    "RG9jdW1lbnQuYWRkRXZlbnRMaXN0ZW5lcigibW91c2Vtb3ZlIix0aGlzLl9tb3VzZU1vdmVMaXN0ZW5lciksdGhpcy5fc2NyZWVuRWxlbWVudC5vd25lckRv"
    "Y3VtZW50LmFkZEV2ZW50TGlzdGVuZXIoIm1vdXNldXAiLHRoaXMuX21vdXNlVXBMaXN0ZW5lcikpLHRoaXMuX2RyYWdTY3JvbGxJbnRlcnZhbFRpbWVyPXRo"
    "aXMuX2NvcmVCcm93c2VyU2VydmljZS53aW5kb3cuc2V0SW50ZXJ2YWwoKCgpPT50aGlzLl9kcmFnU2Nyb2xsKCkpLDUwKX1fcmVtb3ZlTW91c2VEb3duTGlz"
    "dGVuZXJzKCl7dGhpcy5fc2NyZWVuRWxlbWVudC5vd25lckRvY3VtZW50JiYodGhpcy5fc2NyZWVuRWxlbWVudC5vd25lckRvY3VtZW50LnJlbW92ZUV2ZW50"
    "TGlzdGVuZXIoIm1vdXNlbW92ZSIsdGhpcy5fbW91c2VNb3ZlTGlzdGVuZXIpLHRoaXMuX3NjcmVlbkVsZW1lbnQub3duZXJEb2N1bWVudC5yZW1vdmVFdmVu"
    "dExpc3RlbmVyKCJtb3VzZXVwIix0aGlzLl9tb3VzZVVwTGlzdGVuZXIpKSx0aGlzLl9jb3JlQnJvd3NlclNlcnZpY2Uud2luZG93LmNsZWFySW50ZXJ2YWwo"
    "dGhpcy5fZHJhZ1Njcm9sbEludGVydmFsVGltZXIpLHRoaXMuX2RyYWdTY3JvbGxJbnRlcnZhbFRpbWVyPXZvaWQgMH1faGFuZGxlSW5jcmVtZW50YWxDbGlj"
    "ayhlKXt0aGlzLl9tb2RlbC5zZWxlY3Rpb25TdGFydCYmKHRoaXMuX21vZGVsLnNlbGVjdGlvbkVuZD10aGlzLl9nZXRNb3VzZUJ1ZmZlckNvb3JkcyhlKSl9"
    "X2hhbmRsZVNpbmdsZUNsaWNrKGUpe2lmKHRoaXMuX21vZGVsLnNlbGVjdGlvblN0YXJ0TGVuZ3RoPTAsdGhpcy5fbW9kZWwuaXNTZWxlY3RBbGxBY3RpdmU9"
    "ITEsdGhpcy5fYWN0aXZlU2VsZWN0aW9uTW9kZT10aGlzLnNob3VsZENvbHVtblNlbGVjdChlKT8zOjAsdGhpcy5fbW9kZWwuc2VsZWN0aW9uU3RhcnQ9dGhp"
    "cy5fZ2V0TW91c2VCdWZmZXJDb29yZHMoZSksIXRoaXMuX21vZGVsLnNlbGVjdGlvblN0YXJ0KXJldHVybjt0aGlzLl9tb2RlbC5zZWxlY3Rpb25FbmQ9dm9p"
    "ZCAwO2NvbnN0IHQ9dGhpcy5fYnVmZmVyU2VydmljZS5idWZmZXIubGluZXMuZ2V0KHRoaXMuX21vZGVsLnNlbGVjdGlvblN0YXJ0WzFdKTt0JiZ0Lmxlbmd0"
    "aCE9PXRoaXMuX21vZGVsLnNlbGVjdGlvblN0YXJ0WzBdJiYwPT09dC5oYXNXaWR0aCh0aGlzLl9tb2RlbC5zZWxlY3Rpb25TdGFydFswXSkmJnRoaXMuX21v"
    "ZGVsLnNlbGVjdGlvblN0YXJ0WzBdKyt9X2hhbmRsZURvdWJsZUNsaWNrKGUpe3RoaXMuX3NlbGVjdFdvcmRBdEN1cnNvcihlLCEwKSYmKHRoaXMuX2FjdGl2"
    "ZVNlbGVjdGlvbk1vZGU9MSl9X2hhbmRsZVRyaXBsZUNsaWNrKGUpe2NvbnN0IHQ9dGhpcy5fZ2V0TW91c2VCdWZmZXJDb29yZHMoZSk7dCYmKHRoaXMuX2Fj"
    "dGl2ZVNlbGVjdGlvbk1vZGU9Mix0aGlzLl9zZWxlY3RMaW5lQXQodFsxXSkpfXNob3VsZENvbHVtblNlbGVjdChlKXtyZXR1cm4gZS5hbHRLZXkmJiEoZC5p"
    "c01hYyYmdGhpcy5fb3B0aW9uc1NlcnZpY2UucmF3T3B0aW9ucy5tYWNPcHRpb25DbGlja0ZvcmNlc1NlbGVjdGlvbil9X2hhbmRsZU1vdXNlTW92ZShlKXtp"
    "ZihlLnN0b3BJbW1lZGlhdGVQcm9wYWdhdGlvbigpLCF0aGlzLl9tb2RlbC5zZWxlY3Rpb25TdGFydClyZXR1cm47Y29uc3QgdD10aGlzLl9tb2RlbC5zZWxl"
    "Y3Rpb25FbmQ/W3RoaXMuX21vZGVsLnNlbGVjdGlvbkVuZFswXSx0aGlzLl9tb2RlbC5zZWxlY3Rpb25FbmRbMV1dOm51bGw7aWYodGhpcy5fbW9kZWwuc2Vs"
    "ZWN0aW9uRW5kPXRoaXMuX2dldE1vdXNlQnVmZmVyQ29vcmRzKGUpLCF0aGlzLl9tb2RlbC5zZWxlY3Rpb25FbmQpcmV0dXJuIHZvaWQgdGhpcy5yZWZyZXNo"
    "KCEwKTsyPT09dGhpcy5fYWN0aXZlU2VsZWN0aW9uTW9kZT90aGlzLl9tb2RlbC5zZWxlY3Rpb25FbmRbMV08dGhpcy5fbW9kZWwuc2VsZWN0aW9uU3RhcnRb"
    "MV0/dGhpcy5fbW9kZWwuc2VsZWN0aW9uRW5kWzBdPTA6dGhpcy5fbW9kZWwuc2VsZWN0aW9uRW5kWzBdPXRoaXMuX2J1ZmZlclNlcnZpY2UuY29sczoxPT09"
    "dGhpcy5fYWN0aXZlU2VsZWN0aW9uTW9kZSYmdGhpcy5fc2VsZWN0VG9Xb3JkQXQodGhpcy5fbW9kZWwuc2VsZWN0aW9uRW5kKSx0aGlzLl9kcmFnU2Nyb2xs"
    "QW1vdW50PXRoaXMuX2dldE1vdXNlRXZlbnRTY3JvbGxBbW91bnQoZSksMyE9PXRoaXMuX2FjdGl2ZVNlbGVjdGlvbk1vZGUmJih0aGlzLl9kcmFnU2Nyb2xs"
    "QW1vdW50PjA/dGhpcy5fbW9kZWwuc2VsZWN0aW9uRW5kWzBdPXRoaXMuX2J1ZmZlclNlcnZpY2UuY29sczp0aGlzLl9kcmFnU2Nyb2xsQW1vdW50PDAmJih0"
    "aGlzLl9tb2RlbC5zZWxlY3Rpb25FbmRbMF09MCkpO2NvbnN0IGk9dGhpcy5fYnVmZmVyU2VydmljZS5idWZmZXI7aWYodGhpcy5fbW9kZWwuc2VsZWN0aW9u"
    "RW5kWzFdPGkubGluZXMubGVuZ3RoKXtjb25zdCBlPWkubGluZXMuZ2V0KHRoaXMuX21vZGVsLnNlbGVjdGlvbkVuZFsxXSk7ZSYmMD09PWUuaGFzV2lkdGgo"
    "dGhpcy5fbW9kZWwuc2VsZWN0aW9uRW5kWzBdKSYmdGhpcy5fbW9kZWwuc2VsZWN0aW9uRW5kWzBdKyt9dCYmdFswXT09PXRoaXMuX21vZGVsLnNlbGVjdGlv"
    "bkVuZFswXSYmdFsxXT09PXRoaXMuX21vZGVsLnNlbGVjdGlvbkVuZFsxXXx8dGhpcy5yZWZyZXNoKCEwKX1fZHJhZ1Njcm9sbCgpe2lmKHRoaXMuX21vZGVs"
    "LnNlbGVjdGlvbkVuZCYmdGhpcy5fbW9kZWwuc2VsZWN0aW9uU3RhcnQmJnRoaXMuX2RyYWdTY3JvbGxBbW91bnQpe3RoaXMuX29uUmVxdWVzdFNjcm9sbExp"
    "bmVzLmZpcmUoe2Ftb3VudDp0aGlzLl9kcmFnU2Nyb2xsQW1vdW50LHN1cHByZXNzU2Nyb2xsRXZlbnQ6ITF9KTtjb25zdCBlPXRoaXMuX2J1ZmZlclNlcnZp"
    "Y2UuYnVmZmVyO3RoaXMuX2RyYWdTY3JvbGxBbW91bnQ+MD8oMyE9PXRoaXMuX2FjdGl2ZVNlbGVjdGlvbk1vZGUmJih0aGlzLl9tb2RlbC5zZWxlY3Rpb25F"
    "bmRbMF09dGhpcy5fYnVmZmVyU2VydmljZS5jb2xzKSx0aGlzLl9tb2RlbC5zZWxlY3Rpb25FbmRbMV09TWF0aC5taW4oZS55ZGlzcCt0aGlzLl9idWZmZXJT"
    "ZXJ2aWNlLnJvd3MsZS5saW5lcy5sZW5ndGgtMSkpOigzIT09dGhpcy5fYWN0aXZlU2VsZWN0aW9uTW9kZSYmKHRoaXMuX21vZGVsLnNlbGVjdGlvbkVuZFsw"
    "XT0wKSx0aGlzLl9tb2RlbC5zZWxlY3Rpb25FbmRbMV09ZS55ZGlzcCksdGhpcy5yZWZyZXNoKCl9fV9oYW5kbGVNb3VzZVVwKGUpe2NvbnN0IHQ9ZS50aW1l"
    "U3RhbXAtdGhpcy5fbW91c2VEb3duVGltZVN0YW1wO2lmKHRoaXMuX3JlbW92ZU1vdXNlRG93bkxpc3RlbmVycygpLHRoaXMuc2VsZWN0aW9uVGV4dC5sZW5n"
    "dGg8PTEmJnQ8NTAwJiZlLmFsdEtleSYmdGhpcy5fb3B0aW9uc1NlcnZpY2UucmF3T3B0aW9ucy5hbHRDbGlja01vdmVzQ3Vyc29yKXtpZih0aGlzLl9idWZm"
    "ZXJTZXJ2aWNlLmJ1ZmZlci55YmFzZT09PXRoaXMuX2J1ZmZlclNlcnZpY2UuYnVmZmVyLnlkaXNwKXtjb25zdCB0PXRoaXMuX21vdXNlU2VydmljZS5nZXRD"
    "b29yZHMoZSx0aGlzLl9lbGVtZW50LHRoaXMuX2J1ZmZlclNlcnZpY2UuY29scyx0aGlzLl9idWZmZXJTZXJ2aWNlLnJvd3MsITEpO2lmKHQmJnZvaWQgMCE9"
    "PXRbMF0mJnZvaWQgMCE9PXRbMV0pe2NvbnN0IGU9KDAsby5tb3ZlVG9DZWxsU2VxdWVuY2UpKHRbMF0tMSx0WzFdLTEsdGhpcy5fYnVmZmVyU2VydmljZSx0"
    "aGlzLl9jb3JlU2VydmljZS5kZWNQcml2YXRlTW9kZXMuYXBwbGljYXRpb25DdXJzb3JLZXlzKTt0aGlzLl9jb3JlU2VydmljZS50cmlnZ2VyRGF0YUV2ZW50"
    "KGUsITApfX19ZWxzZSB0aGlzLl9maXJlRXZlbnRJZlNlbGVjdGlvbkNoYW5nZWQoKX1fZmlyZUV2ZW50SWZTZWxlY3Rpb25DaGFuZ2VkKCl7Y29uc3QgZT10"
    "aGlzLl9tb2RlbC5maW5hbFNlbGVjdGlvblN0YXJ0LHQ9dGhpcy5fbW9kZWwuZmluYWxTZWxlY3Rpb25FbmQsaT0hKCFlfHwhdHx8ZVswXT09PXRbMF0mJmVb"
    "MV09PT10WzFdKTtpP2UmJnQmJih0aGlzLl9vbGRTZWxlY3Rpb25TdGFydCYmdGhpcy5fb2xkU2VsZWN0aW9uRW5kJiZlWzBdPT09dGhpcy5fb2xkU2VsZWN0"
    "aW9uU3RhcnRbMF0mJmVbMV09PT10aGlzLl9vbGRTZWxlY3Rpb25TdGFydFsxXSYmdFswXT09PXRoaXMuX29sZFNlbGVjdGlvbkVuZFswXSYmdFsxXT09PXRo"
    "aXMuX29sZFNlbGVjdGlvbkVuZFsxXXx8dGhpcy5fZmlyZU9uU2VsZWN0aW9uQ2hhbmdlKGUsdCxpKSk6dGhpcy5fb2xkSGFzU2VsZWN0aW9uJiZ0aGlzLl9m"
    "aXJlT25TZWxlY3Rpb25DaGFuZ2UoZSx0LGkpfV9maXJlT25TZWxlY3Rpb25DaGFuZ2UoZSx0LGkpe3RoaXMuX29sZFNlbGVjdGlvblN0YXJ0PWUsdGhpcy5f"
    "b2xkU2VsZWN0aW9uRW5kPXQsdGhpcy5fb2xkSGFzU2VsZWN0aW9uPWksdGhpcy5fb25TZWxlY3Rpb25DaGFuZ2UuZmlyZSgpfV9oYW5kbGVCdWZmZXJBY3Rp"
    "dmF0ZShlKXt0aGlzLmNsZWFyU2VsZWN0aW9uKCksdGhpcy5fdHJpbUxpc3RlbmVyLmRpc3Bvc2UoKSx0aGlzLl90cmltTGlzdGVuZXI9ZS5hY3RpdmVCdWZm"
    "ZXIubGluZXMub25UcmltKChlPT50aGlzLl9oYW5kbGVUcmltKGUpKSl9X2NvbnZlcnRWaWV3cG9ydENvbFRvQ2hhcmFjdGVySW5kZXgoZSx0KXtsZXQgaT10"
    "O2ZvcihsZXQgcz0wO3Q+PXM7cysrKXtjb25zdCByPWUubG9hZENlbGwocyx0aGlzLl93b3JrQ2VsbCkuZ2V0Q2hhcnMoKS5sZW5ndGg7MD09PXRoaXMuX3dv"
    "cmtDZWxsLmdldFdpZHRoKCk/aS0tOnI+MSYmdCE9PXMmJihpKz1yLTEpfXJldHVybiBpfXNldFNlbGVjdGlvbihlLHQsaSl7dGhpcy5fbW9kZWwuY2xlYXJT"
    "ZWxlY3Rpb24oKSx0aGlzLl9yZW1vdmVNb3VzZURvd25MaXN0ZW5lcnMoKSx0aGlzLl9tb2RlbC5zZWxlY3Rpb25TdGFydD1bZSx0XSx0aGlzLl9tb2RlbC5z"
    "ZWxlY3Rpb25TdGFydExlbmd0aD1pLHRoaXMucmVmcmVzaCgpLHRoaXMuX2ZpcmVFdmVudElmU2VsZWN0aW9uQ2hhbmdlZCgpfXJpZ2h0Q2xpY2tTZWxlY3Qo"
    "ZSl7dGhpcy5faXNDbGlja0luU2VsZWN0aW9uKGUpfHwodGhpcy5fc2VsZWN0V29yZEF0Q3Vyc29yKGUsITEpJiZ0aGlzLnJlZnJlc2goITApLHRoaXMuX2Zp"
    "cmVFdmVudElmU2VsZWN0aW9uQ2hhbmdlZCgpKX1fZ2V0V29yZEF0KGUsdCxpPSEwLHM9ITApe2lmKGVbMF0+PXRoaXMuX2J1ZmZlclNlcnZpY2UuY29scyly"
    "ZXR1cm47Y29uc3Qgcj10aGlzLl9idWZmZXJTZXJ2aWNlLmJ1ZmZlcixuPXIubGluZXMuZ2V0KGVbMV0pO2lmKCFuKXJldHVybjtjb25zdCBvPXIudHJhbnNs"
    "YXRlQnVmZmVyTGluZVRvU3RyaW5nKGVbMV0sITEpO2xldCBhPXRoaXMuX2NvbnZlcnRWaWV3cG9ydENvbFRvQ2hhcmFjdGVySW5kZXgobixlWzBdKSxoPWE7"
    "Y29uc3QgYz1lWzBdLWE7bGV0IGw9MCxkPTAsXz0wLHU9MDtpZigiICI9PT1vLmNoYXJBdChhKSl7Zm9yKDthPjAmJiIgIj09PW8uY2hhckF0KGEtMSk7KWEt"
    "LTtmb3IoO2g8by5sZW5ndGgmJiIgIj09PW8uY2hhckF0KGgrMSk7KWgrK31lbHNle2xldCB0PWVbMF0saT1lWzBdOzA9PT1uLmdldFdpZHRoKHQpJiYobCsr"
    "LHQtLSksMj09PW4uZ2V0V2lkdGgoaSkmJihkKyssaSsrKTtjb25zdCBzPW4uZ2V0U3RyaW5nKGkpLmxlbmd0aDtmb3Iocz4xJiYodSs9cy0xLGgrPXMtMSk7"
    "dD4wJiZhPjAmJiF0aGlzLl9pc0NoYXJXb3JkU2VwYXJhdG9yKG4ubG9hZENlbGwodC0xLHRoaXMuX3dvcmtDZWxsKSk7KXtuLmxvYWRDZWxsKHQtMSx0aGlz"
    "Ll93b3JrQ2VsbCk7Y29uc3QgZT10aGlzLl93b3JrQ2VsbC5nZXRDaGFycygpLmxlbmd0aDswPT09dGhpcy5fd29ya0NlbGwuZ2V0V2lkdGgoKT8obCsrLHQt"
    "LSk6ZT4xJiYoXys9ZS0xLGEtPWUtMSksYS0tLHQtLX1mb3IoO2k8bi5sZW5ndGgmJmgrMTxvLmxlbmd0aCYmIXRoaXMuX2lzQ2hhcldvcmRTZXBhcmF0b3Io"
    "bi5sb2FkQ2VsbChpKzEsdGhpcy5fd29ya0NlbGwpKTspe24ubG9hZENlbGwoaSsxLHRoaXMuX3dvcmtDZWxsKTtjb25zdCBlPXRoaXMuX3dvcmtDZWxsLmdl"
    "dENoYXJzKCkubGVuZ3RoOzI9PT10aGlzLl93b3JrQ2VsbC5nZXRXaWR0aCgpPyhkKyssaSsrKTplPjEmJih1Kz1lLTEsaCs9ZS0xKSxoKyssaSsrfX1oKys7"
    "bGV0IGY9YStjLWwrXyx2PU1hdGgubWluKHRoaXMuX2J1ZmZlclNlcnZpY2UuY29scyxoLWErbCtkLV8tdSk7aWYodHx8IiIhPT1vLnNsaWNlKGEsaCkudHJp"
    "bSgpKXtpZihpJiYwPT09ZiYmMzIhPT1uLmdldENvZGVQb2ludCgwKSl7Y29uc3QgdD1yLmxpbmVzLmdldChlWzFdLTEpO2lmKHQmJm4uaXNXcmFwcGVkJiYz"
    "MiE9PXQuZ2V0Q29kZVBvaW50KHRoaXMuX2J1ZmZlclNlcnZpY2UuY29scy0xKSl7Y29uc3QgdD10aGlzLl9nZXRXb3JkQXQoW3RoaXMuX2J1ZmZlclNlcnZp"
    "Y2UuY29scy0xLGVbMV0tMV0sITEsITAsITEpO2lmKHQpe2NvbnN0IGU9dGhpcy5fYnVmZmVyU2VydmljZS5jb2xzLXQuc3RhcnQ7Zi09ZSx2Kz1lfX19aWYo"
    "cyYmZit2PT09dGhpcy5fYnVmZmVyU2VydmljZS5jb2xzJiYzMiE9PW4uZ2V0Q29kZVBvaW50KHRoaXMuX2J1ZmZlclNlcnZpY2UuY29scy0xKSl7Y29uc3Qg"
    "dD1yLmxpbmVzLmdldChlWzFdKzEpO2lmKChudWxsPT10P3ZvaWQgMDp0LmlzV3JhcHBlZCkmJjMyIT09dC5nZXRDb2RlUG9pbnQoMCkpe2NvbnN0IHQ9dGhp"
    "cy5fZ2V0V29yZEF0KFswLGVbMV0rMV0sITEsITEsITApO3QmJih2Kz10Lmxlbmd0aCl9fXJldHVybntzdGFydDpmLGxlbmd0aDp2fX19X3NlbGVjdFdvcmRB"
    "dChlLHQpe2NvbnN0IGk9dGhpcy5fZ2V0V29yZEF0KGUsdCk7aWYoaSl7Zm9yKDtpLnN0YXJ0PDA7KWkuc3RhcnQrPXRoaXMuX2J1ZmZlclNlcnZpY2UuY29s"
    "cyxlWzFdLS07dGhpcy5fbW9kZWwuc2VsZWN0aW9uU3RhcnQ9W2kuc3RhcnQsZVsxXV0sdGhpcy5fbW9kZWwuc2VsZWN0aW9uU3RhcnRMZW5ndGg9aS5sZW5n"
    "dGh9fV9zZWxlY3RUb1dvcmRBdChlKXtjb25zdCB0PXRoaXMuX2dldFdvcmRBdChlLCEwKTtpZih0KXtsZXQgaT1lWzFdO2Zvcig7dC5zdGFydDwwOyl0LnN0"
    "YXJ0Kz10aGlzLl9idWZmZXJTZXJ2aWNlLmNvbHMsaS0tO2lmKCF0aGlzLl9tb2RlbC5hcmVTZWxlY3Rpb25WYWx1ZXNSZXZlcnNlZCgpKWZvcig7dC5zdGFy"
    "dCt0Lmxlbmd0aD50aGlzLl9idWZmZXJTZXJ2aWNlLmNvbHM7KXQubGVuZ3RoLT10aGlzLl9idWZmZXJTZXJ2aWNlLmNvbHMsaSsrO3RoaXMuX21vZGVsLnNl"
    "bGVjdGlvbkVuZD1bdGhpcy5fbW9kZWwuYXJlU2VsZWN0aW9uVmFsdWVzUmV2ZXJzZWQoKT90LnN0YXJ0OnQuc3RhcnQrdC5sZW5ndGgsaV19fV9pc0NoYXJX"
    "b3JkU2VwYXJhdG9yKGUpe3JldHVybiAwIT09ZS5nZXRXaWR0aCgpJiZ0aGlzLl9vcHRpb25zU2VydmljZS5yYXdPcHRpb25zLndvcmRTZXBhcmF0b3IuaW5k"
    "ZXhPZihlLmdldENoYXJzKCkpPj0wfV9zZWxlY3RMaW5lQXQoZSl7Y29uc3QgdD10aGlzLl9idWZmZXJTZXJ2aWNlLmJ1ZmZlci5nZXRXcmFwcGVkUmFuZ2VG"
    "b3JMaW5lKGUpLGk9e3N0YXJ0Ont4OjAseTp0LmZpcnN0fSxlbmQ6e3g6dGhpcy5fYnVmZmVyU2VydmljZS5jb2xzLTEseTp0Lmxhc3R9fTt0aGlzLl9tb2Rl"
    "bC5zZWxlY3Rpb25TdGFydD1bMCx0LmZpcnN0XSx0aGlzLl9tb2RlbC5zZWxlY3Rpb25FbmQ9dm9pZCAwLHRoaXMuX21vZGVsLnNlbGVjdGlvblN0YXJ0TGVu"
    "Z3RoPSgwLF8uZ2V0UmFuZ2VMZW5ndGgpKGksdGhpcy5fYnVmZmVyU2VydmljZS5jb2xzKX19O3QuU2VsZWN0aW9uU2VydmljZT1nPXMoW3IoMyxmLklCdWZm"
    "ZXJTZXJ2aWNlKSxyKDQsZi5JQ29yZVNlcnZpY2UpLHIoNSxoLklNb3VzZVNlcnZpY2UpLHIoNixmLklPcHRpb25zU2VydmljZSkscig3LGguSVJlbmRlclNl"
    "cnZpY2UpLHIoOCxoLklDb3JlQnJvd3NlclNlcnZpY2UpXSxnKX0sNDcyNTooZSx0LGkpPT57T2JqZWN0LmRlZmluZVByb3BlcnR5KHQsIl9fZXNNb2R1bGUi"
    "LHt2YWx1ZTohMH0pLHQuSVRoZW1lU2VydmljZT10LklDaGFyYWN0ZXJKb2luZXJTZXJ2aWNlPXQuSVNlbGVjdGlvblNlcnZpY2U9dC5JUmVuZGVyU2Vydmlj"
    "ZT10LklNb3VzZVNlcnZpY2U9dC5JQ29yZUJyb3dzZXJTZXJ2aWNlPXQuSUNoYXJTaXplU2VydmljZT12b2lkIDA7Y29uc3Qgcz1pKDgzNDMpO3QuSUNoYXJT"
    "aXplU2VydmljZT0oMCxzLmNyZWF0ZURlY29yYXRvcikoIkNoYXJTaXplU2VydmljZSIpLHQuSUNvcmVCcm93c2VyU2VydmljZT0oMCxzLmNyZWF0ZURlY29y"
    "YXRvcikoIkNvcmVCcm93c2VyU2VydmljZSIpLHQuSU1vdXNlU2VydmljZT0oMCxzLmNyZWF0ZURlY29yYXRvcikoIk1vdXNlU2VydmljZSIpLHQuSVJlbmRl"
    "clNlcnZpY2U9KDAscy5jcmVhdGVEZWNvcmF0b3IpKCJSZW5kZXJTZXJ2aWNlIiksdC5JU2VsZWN0aW9uU2VydmljZT0oMCxzLmNyZWF0ZURlY29yYXRvciko"
    "IlNlbGVjdGlvblNlcnZpY2UiKSx0LklDaGFyYWN0ZXJKb2luZXJTZXJ2aWNlPSgwLHMuY3JlYXRlRGVjb3JhdG9yKSgiQ2hhcmFjdGVySm9pbmVyU2Vydmlj"
    "ZSIpLHQuSVRoZW1lU2VydmljZT0oMCxzLmNyZWF0ZURlY29yYXRvcikoIlRoZW1lU2VydmljZSIpfSw2NzMxOmZ1bmN0aW9uKGUsdCxpKXt2YXIgcz10aGlz"
    "JiZ0aGlzLl9fZGVjb3JhdGV8fGZ1bmN0aW9uKGUsdCxpLHMpe3ZhciByLG49YXJndW1lbnRzLmxlbmd0aCxvPW48Mz90Om51bGw9PT1zP3M9T2JqZWN0Lmdl"
    "dE93blByb3BlcnR5RGVzY3JpcHRvcih0LGkpOnM7aWYoIm9iamVjdCI9PXR5cGVvZiBSZWZsZWN0JiYiZnVuY3Rpb24iPT10eXBlb2YgUmVmbGVjdC5kZWNv"
    "cmF0ZSlvPVJlZmxlY3QuZGVjb3JhdGUoZSx0LGkscyk7ZWxzZSBmb3IodmFyIGE9ZS5sZW5ndGgtMTthPj0wO2EtLSkocj1lW2FdKSYmKG89KG48Mz9yKG8p"
    "Om4+Mz9yKHQsaSxvKTpyKHQsaSkpfHxvKTtyZXR1cm4gbj4zJiZvJiZPYmplY3QuZGVmaW5lUHJvcGVydHkodCxpLG8pLG99LHI9dGhpcyYmdGhpcy5fX3Bh"
    "cmFtfHxmdW5jdGlvbihlLHQpe3JldHVybiBmdW5jdGlvbihpLHMpe3QoaSxzLGUpfX07T2JqZWN0LmRlZmluZVByb3BlcnR5KHQsIl9fZXNNb2R1bGUiLHt2"
    "YWx1ZTohMH0pLHQuVGhlbWVTZXJ2aWNlPXQuREVGQVVMVF9BTlNJX0NPTE9SUz12b2lkIDA7Y29uc3Qgbj1pKDcyMzkpLG89aSg4MDU1KSxhPWkoODQ2MCks"
    "aD1pKDg0NCksYz1pKDI1ODUpLGw9by5jc3MudG9Db2xvcigiI2ZmZmZmZiIpLGQ9by5jc3MudG9Db2xvcigiIzAwMDAwMCIpLF89by5jc3MudG9Db2xvcigi"
    "I2ZmZmZmZiIpLHU9by5jc3MudG9Db2xvcigiIzAwMDAwMCIpLGY9e2NzczoicmdiYSgyNTUsIDI1NSwgMjU1LCAwLjMpIixyZ2JhOjQyOTQ5NjcxMTd9O3Qu"
    "REVGQVVMVF9BTlNJX0NPTE9SUz1PYmplY3QuZnJlZXplKCgoKT0+e2NvbnN0IGU9W28uY3NzLnRvQ29sb3IoIiMyZTM0MzYiKSxvLmNzcy50b0NvbG9yKCIj"
    "Y2MwMDAwIiksby5jc3MudG9Db2xvcigiIzRlOWEwNiIpLG8uY3NzLnRvQ29sb3IoIiNjNGEwMDAiKSxvLmNzcy50b0NvbG9yKCIjMzQ2NWE0Iiksby5jc3Mu"
    "dG9Db2xvcigiIzc1NTA3YiIpLG8uY3NzLnRvQ29sb3IoIiMwNjk4OWEiKSxvLmNzcy50b0NvbG9yKCIjZDNkN2NmIiksby5jc3MudG9Db2xvcigiIzU1NTc1"
    "MyIpLG8uY3NzLnRvQ29sb3IoIiNlZjI5MjkiKSxvLmNzcy50b0NvbG9yKCIjOGFlMjM0Iiksby5jc3MudG9Db2xvcigiI2ZjZTk0ZiIpLG8uY3NzLnRvQ29s"
    "b3IoIiM3MjlmY2YiKSxvLmNzcy50b0NvbG9yKCIjYWQ3ZmE4Iiksby5jc3MudG9Db2xvcigiIzM0ZTJlMiIpLG8uY3NzLnRvQ29sb3IoIiNlZWVlZWMiKV0s"
    "dD1bMCw5NSwxMzUsMTc1LDIxNSwyNTVdO2ZvcihsZXQgaT0wO2k8MjE2O2krKyl7Y29uc3Qgcz10W2kvMzYlNnwwXSxyPXRbaS82JTZ8MF0sbj10W2klNl07"
    "ZS5wdXNoKHtjc3M6by5jaGFubmVscy50b0NzcyhzLHIsbikscmdiYTpvLmNoYW5uZWxzLnRvUmdiYShzLHIsbil9KX1mb3IobGV0IHQ9MDt0PDI0O3QrKyl7"
    "Y29uc3QgaT04KzEwKnQ7ZS5wdXNoKHtjc3M6by5jaGFubmVscy50b0NzcyhpLGksaSkscmdiYTpvLmNoYW5uZWxzLnRvUmdiYShpLGksaSl9KX1yZXR1cm4g"
    "ZX0pKCkpO2xldCB2PXQuVGhlbWVTZXJ2aWNlPWNsYXNzIGV4dGVuZHMgaC5EaXNwb3NhYmxle2dldCBjb2xvcnMoKXtyZXR1cm4gdGhpcy5fY29sb3JzfWNv"
    "bnN0cnVjdG9yKGUpe3N1cGVyKCksdGhpcy5fb3B0aW9uc1NlcnZpY2U9ZSx0aGlzLl9jb250cmFzdENhY2hlPW5ldyBuLkNvbG9yQ29udHJhc3RDYWNoZSx0"
    "aGlzLl9oYWxmQ29udHJhc3RDYWNoZT1uZXcgbi5Db2xvckNvbnRyYXN0Q2FjaGUsdGhpcy5fb25DaGFuZ2VDb2xvcnM9dGhpcy5yZWdpc3RlcihuZXcgYS5F"
    "dmVudEVtaXR0ZXIpLHRoaXMub25DaGFuZ2VDb2xvcnM9dGhpcy5fb25DaGFuZ2VDb2xvcnMuZXZlbnQsdGhpcy5fY29sb3JzPXtmb3JlZ3JvdW5kOmwsYmFj"
    "a2dyb3VuZDpkLGN1cnNvcjpfLGN1cnNvckFjY2VudDp1LHNlbGVjdGlvbkZvcmVncm91bmQ6dm9pZCAwLHNlbGVjdGlvbkJhY2tncm91bmRUcmFuc3BhcmVu"
    "dDpmLHNlbGVjdGlvbkJhY2tncm91bmRPcGFxdWU6by5jb2xvci5ibGVuZChkLGYpLHNlbGVjdGlvbkluYWN0aXZlQmFja2dyb3VuZFRyYW5zcGFyZW50OmYs"
    "c2VsZWN0aW9uSW5hY3RpdmVCYWNrZ3JvdW5kT3BhcXVlOm8uY29sb3IuYmxlbmQoZCxmKSxhbnNpOnQuREVGQVVMVF9BTlNJX0NPTE9SUy5zbGljZSgpLGNv"
    "bnRyYXN0Q2FjaGU6dGhpcy5fY29udHJhc3RDYWNoZSxoYWxmQ29udHJhc3RDYWNoZTp0aGlzLl9oYWxmQ29udHJhc3RDYWNoZX0sdGhpcy5fdXBkYXRlUmVz"
    "dG9yZUNvbG9ycygpLHRoaXMuX3NldFRoZW1lKHRoaXMuX29wdGlvbnNTZXJ2aWNlLnJhd09wdGlvbnMudGhlbWUpLHRoaXMucmVnaXN0ZXIodGhpcy5fb3B0"
    "aW9uc1NlcnZpY2Uub25TcGVjaWZpY09wdGlvbkNoYW5nZSgibWluaW11bUNvbnRyYXN0UmF0aW8iLCgoKT0+dGhpcy5fY29udHJhc3RDYWNoZS5jbGVhcigp"
    "KSkpLHRoaXMucmVnaXN0ZXIodGhpcy5fb3B0aW9uc1NlcnZpY2Uub25TcGVjaWZpY09wdGlvbkNoYW5nZSgidGhlbWUiLCgoKT0+dGhpcy5fc2V0VGhlbWUo"
    "dGhpcy5fb3B0aW9uc1NlcnZpY2UucmF3T3B0aW9ucy50aGVtZSkpKSl9X3NldFRoZW1lKGU9e30pe2NvbnN0IGk9dGhpcy5fY29sb3JzO2lmKGkuZm9yZWdy"
    "b3VuZD1wKGUuZm9yZWdyb3VuZCxsKSxpLmJhY2tncm91bmQ9cChlLmJhY2tncm91bmQsZCksaS5jdXJzb3I9cChlLmN1cnNvcixfKSxpLmN1cnNvckFjY2Vu"
    "dD1wKGUuY3Vyc29yQWNjZW50LHUpLGkuc2VsZWN0aW9uQmFja2dyb3VuZFRyYW5zcGFyZW50PXAoZS5zZWxlY3Rpb25CYWNrZ3JvdW5kLGYpLGkuc2VsZWN0"
    "aW9uQmFja2dyb3VuZE9wYXF1ZT1vLmNvbG9yLmJsZW5kKGkuYmFja2dyb3VuZCxpLnNlbGVjdGlvbkJhY2tncm91bmRUcmFuc3BhcmVudCksaS5zZWxlY3Rp"
    "b25JbmFjdGl2ZUJhY2tncm91bmRUcmFuc3BhcmVudD1wKGUuc2VsZWN0aW9uSW5hY3RpdmVCYWNrZ3JvdW5kLGkuc2VsZWN0aW9uQmFja2dyb3VuZFRyYW5z"
    "cGFyZW50KSxpLnNlbGVjdGlvbkluYWN0aXZlQmFja2dyb3VuZE9wYXF1ZT1vLmNvbG9yLmJsZW5kKGkuYmFja2dyb3VuZCxpLnNlbGVjdGlvbkluYWN0aXZl"
    "QmFja2dyb3VuZFRyYW5zcGFyZW50KSxpLnNlbGVjdGlvbkZvcmVncm91bmQ9ZS5zZWxlY3Rpb25Gb3JlZ3JvdW5kP3AoZS5zZWxlY3Rpb25Gb3JlZ3JvdW5k"
    "LG8uTlVMTF9DT0xPUik6dm9pZCAwLGkuc2VsZWN0aW9uRm9yZWdyb3VuZD09PW8uTlVMTF9DT0xPUiYmKGkuc2VsZWN0aW9uRm9yZWdyb3VuZD12b2lkIDAp"
    "LG8uY29sb3IuaXNPcGFxdWUoaS5zZWxlY3Rpb25CYWNrZ3JvdW5kVHJhbnNwYXJlbnQpKXtjb25zdCBlPS4zO2kuc2VsZWN0aW9uQmFja2dyb3VuZFRyYW5z"
    "cGFyZW50PW8uY29sb3Iub3BhY2l0eShpLnNlbGVjdGlvbkJhY2tncm91bmRUcmFuc3BhcmVudCxlKX1pZihvLmNvbG9yLmlzT3BhcXVlKGkuc2VsZWN0aW9u"
    "SW5hY3RpdmVCYWNrZ3JvdW5kVHJhbnNwYXJlbnQpKXtjb25zdCBlPS4zO2kuc2VsZWN0aW9uSW5hY3RpdmVCYWNrZ3JvdW5kVHJhbnNwYXJlbnQ9by5jb2xv"
    "ci5vcGFjaXR5KGkuc2VsZWN0aW9uSW5hY3RpdmVCYWNrZ3JvdW5kVHJhbnNwYXJlbnQsZSl9aWYoaS5hbnNpPXQuREVGQVVMVF9BTlNJX0NPTE9SUy5zbGlj"
    "ZSgpLGkuYW5zaVswXT1wKGUuYmxhY2ssdC5ERUZBVUxUX0FOU0lfQ09MT1JTWzBdKSxpLmFuc2lbMV09cChlLnJlZCx0LkRFRkFVTFRfQU5TSV9DT0xPUlNb"
    "MV0pLGkuYW5zaVsyXT1wKGUuZ3JlZW4sdC5ERUZBVUxUX0FOU0lfQ09MT1JTWzJdKSxpLmFuc2lbM109cChlLnllbGxvdyx0LkRFRkFVTFRfQU5TSV9DT0xP"
    "UlNbM10pLGkuYW5zaVs0XT1wKGUuYmx1ZSx0LkRFRkFVTFRfQU5TSV9DT0xPUlNbNF0pLGkuYW5zaVs1XT1wKGUubWFnZW50YSx0LkRFRkFVTFRfQU5TSV9D"
    "T0xPUlNbNV0pLGkuYW5zaVs2XT1wKGUuY3lhbix0LkRFRkFVTFRfQU5TSV9DT0xPUlNbNl0pLGkuYW5zaVs3XT1wKGUud2hpdGUsdC5ERUZBVUxUX0FOU0lf"
    "Q09MT1JTWzddKSxpLmFuc2lbOF09cChlLmJyaWdodEJsYWNrLHQuREVGQVVMVF9BTlNJX0NPTE9SU1s4XSksaS5hbnNpWzldPXAoZS5icmlnaHRSZWQsdC5E"
    "RUZBVUxUX0FOU0lfQ09MT1JTWzldKSxpLmFuc2lbMTBdPXAoZS5icmlnaHRHcmVlbix0LkRFRkFVTFRfQU5TSV9DT0xPUlNbMTBdKSxpLmFuc2lbMTFdPXAo"
    "ZS5icmlnaHRZZWxsb3csdC5ERUZBVUxUX0FOU0lfQ09MT1JTWzExXSksaS5hbnNpWzEyXT1wKGUuYnJpZ2h0Qmx1ZSx0LkRFRkFVTFRfQU5TSV9DT0xPUlNb"
    "MTJdKSxpLmFuc2lbMTNdPXAoZS5icmlnaHRNYWdlbnRhLHQuREVGQVVMVF9BTlNJX0NPTE9SU1sxM10pLGkuYW5zaVsxNF09cChlLmJyaWdodEN5YW4sdC5E"
    "RUZBVUxUX0FOU0lfQ09MT1JTWzE0XSksaS5hbnNpWzE1XT1wKGUuYnJpZ2h0V2hpdGUsdC5ERUZBVUxUX0FOU0lfQ09MT1JTWzE1XSksZS5leHRlbmRlZEFu"
    "c2kpe2NvbnN0IHM9TWF0aC5taW4oaS5hbnNpLmxlbmd0aC0xNixlLmV4dGVuZGVkQW5zaS5sZW5ndGgpO2ZvcihsZXQgcj0wO3I8cztyKyspaS5hbnNpW3Ir"
    "MTZdPXAoZS5leHRlbmRlZEFuc2lbcl0sdC5ERUZBVUxUX0FOU0lfQ09MT1JTW3IrMTZdKX10aGlzLl9jb250cmFzdENhY2hlLmNsZWFyKCksdGhpcy5faGFs"
    "ZkNvbnRyYXN0Q2FjaGUuY2xlYXIoKSx0aGlzLl91cGRhdGVSZXN0b3JlQ29sb3JzKCksdGhpcy5fb25DaGFuZ2VDb2xvcnMuZmlyZSh0aGlzLmNvbG9ycyl9"
    "cmVzdG9yZUNvbG9yKGUpe3RoaXMuX3Jlc3RvcmVDb2xvcihlKSx0aGlzLl9vbkNoYW5nZUNvbG9ycy5maXJlKHRoaXMuY29sb3JzKX1fcmVzdG9yZUNvbG9y"
    "KGUpe2lmKHZvaWQgMCE9PWUpc3dpdGNoKGUpe2Nhc2UgMjU2OnRoaXMuX2NvbG9ycy5mb3JlZ3JvdW5kPXRoaXMuX3Jlc3RvcmVDb2xvcnMuZm9yZWdyb3Vu"
    "ZDticmVhaztjYXNlIDI1Nzp0aGlzLl9jb2xvcnMuYmFja2dyb3VuZD10aGlzLl9yZXN0b3JlQ29sb3JzLmJhY2tncm91bmQ7YnJlYWs7Y2FzZSAyNTg6dGhp"
    "cy5fY29sb3JzLmN1cnNvcj10aGlzLl9yZXN0b3JlQ29sb3JzLmN1cnNvcjticmVhaztkZWZhdWx0OnRoaXMuX2NvbG9ycy5hbnNpW2VdPXRoaXMuX3Jlc3Rv"
    "cmVDb2xvcnMuYW5zaVtlXX1lbHNlIGZvcihsZXQgZT0wO2U8dGhpcy5fcmVzdG9yZUNvbG9ycy5hbnNpLmxlbmd0aDsrK2UpdGhpcy5fY29sb3JzLmFuc2lb"
    "ZV09dGhpcy5fcmVzdG9yZUNvbG9ycy5hbnNpW2VdfW1vZGlmeUNvbG9ycyhlKXtlKHRoaXMuX2NvbG9ycyksdGhpcy5fb25DaGFuZ2VDb2xvcnMuZmlyZSh0"
    "aGlzLmNvbG9ycyl9X3VwZGF0ZVJlc3RvcmVDb2xvcnMoKXt0aGlzLl9yZXN0b3JlQ29sb3JzPXtmb3JlZ3JvdW5kOnRoaXMuX2NvbG9ycy5mb3JlZ3JvdW5k"
    "LGJhY2tncm91bmQ6dGhpcy5fY29sb3JzLmJhY2tncm91bmQsY3Vyc29yOnRoaXMuX2NvbG9ycy5jdXJzb3IsYW5zaTp0aGlzLl9jb2xvcnMuYW5zaS5zbGlj"
    "ZSgpfX19O2Z1bmN0aW9uIHAoZSx0KXtpZih2b2lkIDAhPT1lKXRyeXtyZXR1cm4gby5jc3MudG9Db2xvcihlKX1jYXRjaChlKXt9cmV0dXJuIHR9dC5UaGVt"
    "ZVNlcnZpY2U9dj1zKFtyKDAsYy5JT3B0aW9uc1NlcnZpY2UpXSx2KX0sNjM0OTooZSx0LGkpPT57T2JqZWN0LmRlZmluZVByb3BlcnR5KHQsIl9fZXNNb2R1"
    "bGUiLHt2YWx1ZTohMH0pLHQuQ2lyY3VsYXJMaXN0PXZvaWQgMDtjb25zdCBzPWkoODQ2MCkscj1pKDg0NCk7Y2xhc3MgbiBleHRlbmRzIHIuRGlzcG9zYWJs"
    "ZXtjb25zdHJ1Y3RvcihlKXtzdXBlcigpLHRoaXMuX21heExlbmd0aD1lLHRoaXMub25EZWxldGVFbWl0dGVyPXRoaXMucmVnaXN0ZXIobmV3IHMuRXZlbnRF"
    "bWl0dGVyKSx0aGlzLm9uRGVsZXRlPXRoaXMub25EZWxldGVFbWl0dGVyLmV2ZW50LHRoaXMub25JbnNlcnRFbWl0dGVyPXRoaXMucmVnaXN0ZXIobmV3IHMu"
    "RXZlbnRFbWl0dGVyKSx0aGlzLm9uSW5zZXJ0PXRoaXMub25JbnNlcnRFbWl0dGVyLmV2ZW50LHRoaXMub25UcmltRW1pdHRlcj10aGlzLnJlZ2lzdGVyKG5l"
    "dyBzLkV2ZW50RW1pdHRlciksdGhpcy5vblRyaW09dGhpcy5vblRyaW1FbWl0dGVyLmV2ZW50LHRoaXMuX2FycmF5PW5ldyBBcnJheSh0aGlzLl9tYXhMZW5n"
    "dGgpLHRoaXMuX3N0YXJ0SW5kZXg9MCx0aGlzLl9sZW5ndGg9MH1nZXQgbWF4TGVuZ3RoKCl7cmV0dXJuIHRoaXMuX21heExlbmd0aH1zZXQgbWF4TGVuZ3Ro"
    "KGUpe2lmKHRoaXMuX21heExlbmd0aD09PWUpcmV0dXJuO2NvbnN0IHQ9bmV3IEFycmF5KGUpO2ZvcihsZXQgaT0wO2k8TWF0aC5taW4oZSx0aGlzLmxlbmd0"
    "aCk7aSsrKXRbaV09dGhpcy5fYXJyYXlbdGhpcy5fZ2V0Q3ljbGljSW5kZXgoaSldO3RoaXMuX2FycmF5PXQsdGhpcy5fbWF4TGVuZ3RoPWUsdGhpcy5fc3Rh"
    "cnRJbmRleD0wfWdldCBsZW5ndGgoKXtyZXR1cm4gdGhpcy5fbGVuZ3RofXNldCBsZW5ndGgoZSl7aWYoZT50aGlzLl9sZW5ndGgpZm9yKGxldCB0PXRoaXMu"
    "X2xlbmd0aDt0PGU7dCsrKXRoaXMuX2FycmF5W3RdPXZvaWQgMDt0aGlzLl9sZW5ndGg9ZX1nZXQoZSl7cmV0dXJuIHRoaXMuX2FycmF5W3RoaXMuX2dldEN5"
    "Y2xpY0luZGV4KGUpXX1zZXQoZSx0KXt0aGlzLl9hcnJheVt0aGlzLl9nZXRDeWNsaWNJbmRleChlKV09dH1wdXNoKGUpe3RoaXMuX2FycmF5W3RoaXMuX2dl"
    "dEN5Y2xpY0luZGV4KHRoaXMuX2xlbmd0aCldPWUsdGhpcy5fbGVuZ3RoPT09dGhpcy5fbWF4TGVuZ3RoPyh0aGlzLl9zdGFydEluZGV4PSsrdGhpcy5fc3Rh"
    "cnRJbmRleCV0aGlzLl9tYXhMZW5ndGgsdGhpcy5vblRyaW1FbWl0dGVyLmZpcmUoMSkpOnRoaXMuX2xlbmd0aCsrfXJlY3ljbGUoKXtpZih0aGlzLl9sZW5n"
    "dGghPT10aGlzLl9tYXhMZW5ndGgpdGhyb3cgbmV3IEVycm9yKCJDYW4gb25seSByZWN5Y2xlIHdoZW4gdGhlIGJ1ZmZlciBpcyBmdWxsIik7cmV0dXJuIHRo"
    "aXMuX3N0YXJ0SW5kZXg9Kyt0aGlzLl9zdGFydEluZGV4JXRoaXMuX21heExlbmd0aCx0aGlzLm9uVHJpbUVtaXR0ZXIuZmlyZSgxKSx0aGlzLl9hcnJheVt0"
    "aGlzLl9nZXRDeWNsaWNJbmRleCh0aGlzLl9sZW5ndGgtMSldfWdldCBpc0Z1bGwoKXtyZXR1cm4gdGhpcy5fbGVuZ3RoPT09dGhpcy5fbWF4TGVuZ3RofXBv"
    "cCgpe3JldHVybiB0aGlzLl9hcnJheVt0aGlzLl9nZXRDeWNsaWNJbmRleCh0aGlzLl9sZW5ndGgtLS0xKV19c3BsaWNlKGUsdCwuLi5pKXtpZih0KXtmb3Io"
    "bGV0IGk9ZTtpPHRoaXMuX2xlbmd0aC10O2krKyl0aGlzLl9hcnJheVt0aGlzLl9nZXRDeWNsaWNJbmRleChpKV09dGhpcy5fYXJyYXlbdGhpcy5fZ2V0Q3lj"
    "bGljSW5kZXgoaSt0KV07dGhpcy5fbGVuZ3RoLT10LHRoaXMub25EZWxldGVFbWl0dGVyLmZpcmUoe2luZGV4OmUsYW1vdW50OnR9KX1mb3IobGV0IHQ9dGhp"
    "cy5fbGVuZ3RoLTE7dD49ZTt0LS0pdGhpcy5fYXJyYXlbdGhpcy5fZ2V0Q3ljbGljSW5kZXgodCtpLmxlbmd0aCldPXRoaXMuX2FycmF5W3RoaXMuX2dldEN5"
    "Y2xpY0luZGV4KHQpXTtmb3IobGV0IHQ9MDt0PGkubGVuZ3RoO3QrKyl0aGlzLl9hcnJheVt0aGlzLl9nZXRDeWNsaWNJbmRleChlK3QpXT1pW3RdO2lmKGku"
    "bGVuZ3RoJiZ0aGlzLm9uSW5zZXJ0RW1pdHRlci5maXJlKHtpbmRleDplLGFtb3VudDppLmxlbmd0aH0pLHRoaXMuX2xlbmd0aCtpLmxlbmd0aD50aGlzLl9t"
    "YXhMZW5ndGgpe2NvbnN0IGU9dGhpcy5fbGVuZ3RoK2kubGVuZ3RoLXRoaXMuX21heExlbmd0aDt0aGlzLl9zdGFydEluZGV4Kz1lLHRoaXMuX2xlbmd0aD10"
    "aGlzLl9tYXhMZW5ndGgsdGhpcy5vblRyaW1FbWl0dGVyLmZpcmUoZSl9ZWxzZSB0aGlzLl9sZW5ndGgrPWkubGVuZ3RofXRyaW1TdGFydChlKXtlPnRoaXMu"
    "X2xlbmd0aCYmKGU9dGhpcy5fbGVuZ3RoKSx0aGlzLl9zdGFydEluZGV4Kz1lLHRoaXMuX2xlbmd0aC09ZSx0aGlzLm9uVHJpbUVtaXR0ZXIuZmlyZShlKX1z"
    "aGlmdEVsZW1lbnRzKGUsdCxpKXtpZighKHQ8PTApKXtpZihlPDB8fGU+PXRoaXMuX2xlbmd0aCl0aHJvdyBuZXcgRXJyb3IoInN0YXJ0IGFyZ3VtZW50IG91"
    "dCBvZiByYW5nZSIpO2lmKGUraTwwKXRocm93IG5ldyBFcnJvcigiQ2Fubm90IHNoaWZ0IGVsZW1lbnRzIGluIGxpc3QgYmV5b25kIGluZGV4IDAiKTtpZihp"
    "PjApe2ZvcihsZXQgcz10LTE7cz49MDtzLS0pdGhpcy5zZXQoZStzK2ksdGhpcy5nZXQoZStzKSk7Y29uc3Qgcz1lK3QraS10aGlzLl9sZW5ndGg7aWYocz4w"
    "KWZvcih0aGlzLl9sZW5ndGgrPXM7dGhpcy5fbGVuZ3RoPnRoaXMuX21heExlbmd0aDspdGhpcy5fbGVuZ3RoLS0sdGhpcy5fc3RhcnRJbmRleCsrLHRoaXMu"
    "b25UcmltRW1pdHRlci5maXJlKDEpfWVsc2UgZm9yKGxldCBzPTA7czx0O3MrKyl0aGlzLnNldChlK3MraSx0aGlzLmdldChlK3MpKX19X2dldEN5Y2xpY0lu"
    "ZGV4KGUpe3JldHVybih0aGlzLl9zdGFydEluZGV4K2UpJXRoaXMuX21heExlbmd0aH19dC5DaXJjdWxhckxpc3Q9bn0sMTQzOTooZSx0KT0+e09iamVjdC5k"
    "ZWZpbmVQcm9wZXJ0eSh0LCJfX2VzTW9kdWxlIix7dmFsdWU6ITB9KSx0LmNsb25lPXZvaWQgMCx0LmNsb25lPWZ1bmN0aW9uIGUodCxpPTUpe2lmKCJvYmpl"
    "Y3QiIT10eXBlb2YgdClyZXR1cm4gdDtjb25zdCBzPUFycmF5LmlzQXJyYXkodCk/W106e307Zm9yKGNvbnN0IHIgaW4gdClzW3JdPWk8PTE/dFtyXTp0W3Jd"
    "JiZlKHRbcl0saS0xKTtyZXR1cm4gc319LDgwNTU6KGUsdCxpKT0+e09iamVjdC5kZWZpbmVQcm9wZXJ0eSh0LCJfX2VzTW9kdWxlIix7dmFsdWU6ITB9KSx0"
    "LmNvbnRyYXN0UmF0aW89dC50b1BhZGRlZEhleD10LnJnYmE9dC5yZ2I9dC5jc3M9dC5jb2xvcj10LmNoYW5uZWxzPXQuTlVMTF9DT0xPUj12b2lkIDA7Y29u"
    "c3Qgcz1pKDYxMTQpO2xldCByPTAsbj0wLG89MCxhPTA7dmFyIGgsYyxsLGQsXztmdW5jdGlvbiB1KGUpe2NvbnN0IHQ9ZS50b1N0cmluZygxNik7cmV0dXJu"
    "IHQubGVuZ3RoPDI/IjAiK3Q6dH1mdW5jdGlvbiBmKGUsdCl7cmV0dXJuIGU8dD8odCsuMDUpLyhlKy4wNSk6KGUrLjA1KS8odCsuMDUpfXQuTlVMTF9DT0xP"
    "Uj17Y3NzOiIjMDAwMDAwMDAiLHJnYmE6MH0sZnVuY3Rpb24oZSl7ZS50b0Nzcz1mdW5jdGlvbihlLHQsaSxzKXtyZXR1cm4gdm9pZCAwIT09cz9gIyR7dShl"
    "KX0ke3UodCl9JHt1KGkpfSR7dShzKX1gOmAjJHt1KGUpfSR7dSh0KX0ke3UoaSl9YH0sZS50b1JnYmE9ZnVuY3Rpb24oZSx0LGkscz0yNTUpe3JldHVybihl"
    "PDwyNHx0PDwxNnxpPDw4fHMpPj4+MH19KGh8fCh0LmNoYW5uZWxzPWg9e30pKSxmdW5jdGlvbihlKXtmdW5jdGlvbiB0KGUsdCl7cmV0dXJuIGE9TWF0aC5y"
    "b3VuZCgyNTUqdCksW3IsbixvXT1fLnRvQ2hhbm5lbHMoZS5yZ2JhKSx7Y3NzOmgudG9Dc3MocixuLG8sYSkscmdiYTpoLnRvUmdiYShyLG4sbyxhKX19ZS5i"
    "bGVuZD1mdW5jdGlvbihlLHQpe2lmKGE9KDI1NSZ0LnJnYmEpLzI1NSwxPT09YSlyZXR1cm57Y3NzOnQuY3NzLHJnYmE6dC5yZ2JhfTtjb25zdCBpPXQucmdi"
    "YT4+MjQmMjU1LHM9dC5yZ2JhPj4xNiYyNTUsYz10LnJnYmE+PjgmMjU1LGw9ZS5yZ2JhPj4yNCYyNTUsZD1lLnJnYmE+PjE2JjI1NSxfPWUucmdiYT4+OCYy"
    "NTU7cmV0dXJuIHI9bCtNYXRoLnJvdW5kKChpLWwpKmEpLG49ZCtNYXRoLnJvdW5kKChzLWQpKmEpLG89XytNYXRoLnJvdW5kKChjLV8pKmEpLHtjc3M6aC50"
    "b0NzcyhyLG4sbykscmdiYTpoLnRvUmdiYShyLG4sbyl9fSxlLmlzT3BhcXVlPWZ1bmN0aW9uKGUpe3JldHVybiAyNTU9PSgyNTUmZS5yZ2JhKX0sZS5lbnN1"
    "cmVDb250cmFzdFJhdGlvPWZ1bmN0aW9uKGUsdCxpKXtjb25zdCBzPV8uZW5zdXJlQ29udHJhc3RSYXRpbyhlLnJnYmEsdC5yZ2JhLGkpO2lmKHMpcmV0dXJu"
    "IF8udG9Db2xvcihzPj4yNCYyNTUscz4+MTYmMjU1LHM+PjgmMjU1KX0sZS5vcGFxdWU9ZnVuY3Rpb24oZSl7Y29uc3QgdD0oMjU1fGUucmdiYSk+Pj4wO3Jl"
    "dHVybltyLG4sb109Xy50b0NoYW5uZWxzKHQpLHtjc3M6aC50b0NzcyhyLG4sbykscmdiYTp0fX0sZS5vcGFjaXR5PXQsZS5tdWx0aXBseU9wYWNpdHk9ZnVu"
    "Y3Rpb24oZSxpKXtyZXR1cm4gYT0yNTUmZS5yZ2JhLHQoZSxhKmkvMjU1KX0sZS50b0NvbG9yUkdCPWZ1bmN0aW9uKGUpe3JldHVybltlLnJnYmE+PjI0JjI1"
    "NSxlLnJnYmE+PjE2JjI1NSxlLnJnYmE+PjgmMjU1XX19KGN8fCh0LmNvbG9yPWM9e30pKSxmdW5jdGlvbihlKXtsZXQgdCxpO2lmKCFzLmlzTm9kZSl7Y29u"
    "c3QgZT1kb2N1bWVudC5jcmVhdGVFbGVtZW50KCJjYW52YXMiKTtlLndpZHRoPTEsZS5oZWlnaHQ9MTtjb25zdCBzPWUuZ2V0Q29udGV4dCgiMmQiLHt3aWxs"
    "UmVhZEZyZXF1ZW50bHk6ITB9KTtzJiYodD1zLHQuZ2xvYmFsQ29tcG9zaXRlT3BlcmF0aW9uPSJjb3B5IixpPXQuY3JlYXRlTGluZWFyR3JhZGllbnQoMCww"
    "LDEsMSkpfWUudG9Db2xvcj1mdW5jdGlvbihlKXtpZihlLm1hdGNoKC8jW1xkYS1mXXszLDh9L2kpKXN3aXRjaChlLmxlbmd0aCl7Y2FzZSA0OnJldHVybiBy"
    "PXBhcnNlSW50KGUuc2xpY2UoMSwyKS5yZXBlYXQoMiksMTYpLG49cGFyc2VJbnQoZS5zbGljZSgyLDMpLnJlcGVhdCgyKSwxNiksbz1wYXJzZUludChlLnNs"
    "aWNlKDMsNCkucmVwZWF0KDIpLDE2KSxfLnRvQ29sb3IocixuLG8pO2Nhc2UgNTpyZXR1cm4gcj1wYXJzZUludChlLnNsaWNlKDEsMikucmVwZWF0KDIpLDE2"
    "KSxuPXBhcnNlSW50KGUuc2xpY2UoMiwzKS5yZXBlYXQoMiksMTYpLG89cGFyc2VJbnQoZS5zbGljZSgzLDQpLnJlcGVhdCgyKSwxNiksYT1wYXJzZUludChl"
    "LnNsaWNlKDQsNSkucmVwZWF0KDIpLDE2KSxfLnRvQ29sb3IocixuLG8sYSk7Y2FzZSA3OnJldHVybntjc3M6ZSxyZ2JhOihwYXJzZUludChlLnNsaWNlKDEp"
    "LDE2KTw8OHwyNTUpPj4+MH07Y2FzZSA5OnJldHVybntjc3M6ZSxyZ2JhOnBhcnNlSW50KGUuc2xpY2UoMSksMTYpPj4+MH19Y29uc3Qgcz1lLm1hdGNoKC9y"
    "Z2JhP1woXHMqKFxkezEsM30pXHMqLFxzKihcZHsxLDN9KVxzKixccyooXGR7MSwzfSlccyooLFxzKigwfDF8XGQ/XC4oXGQrKSlccyopP1wpLyk7aWYocyly"
    "ZXR1cm4gcj1wYXJzZUludChzWzFdKSxuPXBhcnNlSW50KHNbMl0pLG89cGFyc2VJbnQoc1szXSksYT1NYXRoLnJvdW5kKDI1NSoodm9pZCAwPT09c1s1XT8x"
    "OnBhcnNlRmxvYXQoc1s1XSkpKSxfLnRvQ29sb3IocixuLG8sYSk7aWYoIXR8fCFpKXRocm93IG5ldyBFcnJvcigiY3NzLnRvQ29sb3I6IFVuc3VwcG9ydGVk"
    "IGNzcyBmb3JtYXQiKTtpZih0LmZpbGxTdHlsZT1pLHQuZmlsbFN0eWxlPWUsInN0cmluZyIhPXR5cGVvZiB0LmZpbGxTdHlsZSl0aHJvdyBuZXcgRXJyb3Io"
    "ImNzcy50b0NvbG9yOiBVbnN1cHBvcnRlZCBjc3MgZm9ybWF0Iik7aWYodC5maWxsUmVjdCgwLDAsMSwxKSxbcixuLG8sYV09dC5nZXRJbWFnZURhdGEoMCww"
    "LDEsMSkuZGF0YSwyNTUhPT1hKXRocm93IG5ldyBFcnJvcigiY3NzLnRvQ29sb3I6IFVuc3VwcG9ydGVkIGNzcyBmb3JtYXQiKTtyZXR1cm57cmdiYTpoLnRv"
    "UmdiYShyLG4sbyxhKSxjc3M6ZX19fShsfHwodC5jc3M9bD17fSkpLGZ1bmN0aW9uKGUpe2Z1bmN0aW9uIHQoZSx0LGkpe2NvbnN0IHM9ZS8yNTUscj10LzI1"
    "NSxuPWkvMjU1O3JldHVybi4yMTI2KihzPD0uMDM5Mjg/cy8xMi45MjpNYXRoLnBvdygocysuMDU1KS8xLjA1NSwyLjQpKSsuNzE1Mioocjw9LjAzOTI4P3Iv"
    "MTIuOTI6TWF0aC5wb3coKHIrLjA1NSkvMS4wNTUsMi40KSkrLjA3MjIqKG48PS4wMzkyOD9uLzEyLjkyOk1hdGgucG93KChuKy4wNTUpLzEuMDU1LDIuNCkp"
    "fWUucmVsYXRpdmVMdW1pbmFuY2U9ZnVuY3Rpb24oZSl7cmV0dXJuIHQoZT4+MTYmMjU1LGU+PjgmMjU1LDI1NSZlKX0sZS5yZWxhdGl2ZUx1bWluYW5jZTI9"
    "dH0oZHx8KHQucmdiPWQ9e30pKSxmdW5jdGlvbihlKXtmdW5jdGlvbiB0KGUsdCxpKXtjb25zdCBzPWU+PjI0JjI1NSxyPWU+PjE2JjI1NSxuPWU+PjgmMjU1"
    "O2xldCBvPXQ+PjI0JjI1NSxhPXQ+PjE2JjI1NSxoPXQ+PjgmMjU1LGM9ZihkLnJlbGF0aXZlTHVtaW5hbmNlMihvLGEsaCksZC5yZWxhdGl2ZUx1bWluYW5j"
    "ZTIocyxyLG4pKTtmb3IoO2M8aSYmKG8+MHx8YT4wfHxoPjApOylvLT1NYXRoLm1heCgwLE1hdGguY2VpbCguMSpvKSksYS09TWF0aC5tYXgoMCxNYXRoLmNl"
    "aWwoLjEqYSkpLGgtPU1hdGgubWF4KDAsTWF0aC5jZWlsKC4xKmgpKSxjPWYoZC5yZWxhdGl2ZUx1bWluYW5jZTIobyxhLGgpLGQucmVsYXRpdmVMdW1pbmFu"
    "Y2UyKHMscixuKSk7cmV0dXJuKG88PDI0fGE8PDE2fGg8PDh8MjU1KT4+PjB9ZnVuY3Rpb24gaShlLHQsaSl7Y29uc3Qgcz1lPj4yNCYyNTUscj1lPj4xNiYy"
    "NTUsbj1lPj44JjI1NTtsZXQgbz10Pj4yNCYyNTUsYT10Pj4xNiYyNTUsaD10Pj44JjI1NSxjPWYoZC5yZWxhdGl2ZUx1bWluYW5jZTIobyxhLGgpLGQucmVs"
    "YXRpdmVMdW1pbmFuY2UyKHMscixuKSk7Zm9yKDtjPGkmJihvPDI1NXx8YTwyNTV8fGg8MjU1KTspbz1NYXRoLm1pbigyNTUsbytNYXRoLmNlaWwoLjEqKDI1"
    "NS1vKSkpLGE9TWF0aC5taW4oMjU1LGErTWF0aC5jZWlsKC4xKigyNTUtYSkpKSxoPU1hdGgubWluKDI1NSxoK01hdGguY2VpbCguMSooMjU1LWgpKSksYz1m"
    "KGQucmVsYXRpdmVMdW1pbmFuY2UyKG8sYSxoKSxkLnJlbGF0aXZlTHVtaW5hbmNlMihzLHIsbikpO3JldHVybihvPDwyNHxhPDwxNnxoPDw4fDI1NSk+Pj4w"
    "fWUuZW5zdXJlQ29udHJhc3RSYXRpbz1mdW5jdGlvbihlLHMscil7Y29uc3Qgbj1kLnJlbGF0aXZlTHVtaW5hbmNlKGU+PjgpLG89ZC5yZWxhdGl2ZUx1bWlu"
    "YW5jZShzPj44KTtpZihmKG4sbyk8cil7aWYobzxuKXtjb25zdCBvPXQoZSxzLHIpLGE9ZihuLGQucmVsYXRpdmVMdW1pbmFuY2Uobz4+OCkpO2lmKGE8cil7"
    "Y29uc3QgdD1pKGUscyxyKTtyZXR1cm4gYT5mKG4sZC5yZWxhdGl2ZUx1bWluYW5jZSh0Pj44KSk/bzp0fXJldHVybiBvfWNvbnN0IGE9aShlLHMsciksaD1m"
    "KG4sZC5yZWxhdGl2ZUx1bWluYW5jZShhPj44KSk7aWYoaDxyKXtjb25zdCBpPXQoZSxzLHIpO3JldHVybiBoPmYobixkLnJlbGF0aXZlTHVtaW5hbmNlKGk+"
    "PjgpKT9hOml9cmV0dXJuIGF9fSxlLnJlZHVjZUx1bWluYW5jZT10LGUuaW5jcmVhc2VMdW1pbmFuY2U9aSxlLnRvQ2hhbm5lbHM9ZnVuY3Rpb24oZSl7cmV0"
    "dXJuW2U+PjI0JjI1NSxlPj4xNiYyNTUsZT4+OCYyNTUsMjU1JmVdfSxlLnRvQ29sb3I9ZnVuY3Rpb24oZSx0LGkscyl7cmV0dXJue2NzczpoLnRvQ3NzKGUs"
    "dCxpLHMpLHJnYmE6aC50b1JnYmEoZSx0LGkscyl9fX0oX3x8KHQucmdiYT1fPXt9KSksdC50b1BhZGRlZEhleD11LHQuY29udHJhc3RSYXRpbz1mfSw4OTY5"
    "OihlLHQsaSk9PntPYmplY3QuZGVmaW5lUHJvcGVydHkodCwiX19lc01vZHVsZSIse3ZhbHVlOiEwfSksdC5Db3JlVGVybWluYWw9dm9pZCAwO2NvbnN0IHM9"
    "aSg4NDQpLHI9aSgyNTg1KSxuPWkoNDM0OCksbz1pKDc4NjYpLGE9aSg3NDQpLGg9aSg3MzAyKSxjPWkoNjk3NSksbD1pKDg0NjApLGQ9aSgxNzUzKSxfPWko"
    "MTQ4MCksdT1pKDc5OTQpLGY9aSg5MjgyKSx2PWkoNTQzNSkscD1pKDU5ODEpLGc9aSgyNjYwKTtsZXQgbT0hMTtjbGFzcyBTIGV4dGVuZHMgcy5EaXNwb3Nh"
    "Ymxle2dldCBvblNjcm9sbCgpe3JldHVybiB0aGlzLl9vblNjcm9sbEFwaXx8KHRoaXMuX29uU2Nyb2xsQXBpPXRoaXMucmVnaXN0ZXIobmV3IGwuRXZlbnRF"
    "bWl0dGVyKSx0aGlzLl9vblNjcm9sbC5ldmVudCgoZT0+e3ZhciB0O251bGw9PT0odD10aGlzLl9vblNjcm9sbEFwaSl8fHZvaWQgMD09PXR8fHQuZmlyZShl"
    "LnBvc2l0aW9uKX0pKSksdGhpcy5fb25TY3JvbGxBcGkuZXZlbnR9Z2V0IGNvbHMoKXtyZXR1cm4gdGhpcy5fYnVmZmVyU2VydmljZS5jb2xzfWdldCByb3dz"
    "KCl7cmV0dXJuIHRoaXMuX2J1ZmZlclNlcnZpY2Uucm93c31nZXQgYnVmZmVycygpe3JldHVybiB0aGlzLl9idWZmZXJTZXJ2aWNlLmJ1ZmZlcnN9Z2V0IG9w"
    "dGlvbnMoKXtyZXR1cm4gdGhpcy5vcHRpb25zU2VydmljZS5vcHRpb25zfXNldCBvcHRpb25zKGUpe2Zvcihjb25zdCB0IGluIGUpdGhpcy5vcHRpb25zU2Vy"
    "dmljZS5vcHRpb25zW3RdPWVbdF19Y29uc3RydWN0b3IoZSl7c3VwZXIoKSx0aGlzLl93aW5kb3dzV3JhcHBpbmdIZXVyaXN0aWNzPXRoaXMucmVnaXN0ZXIo"
    "bmV3IHMuTXV0YWJsZURpc3Bvc2FibGUpLHRoaXMuX29uQmluYXJ5PXRoaXMucmVnaXN0ZXIobmV3IGwuRXZlbnRFbWl0dGVyKSx0aGlzLm9uQmluYXJ5PXRo"
    "aXMuX29uQmluYXJ5LmV2ZW50LHRoaXMuX29uRGF0YT10aGlzLnJlZ2lzdGVyKG5ldyBsLkV2ZW50RW1pdHRlciksdGhpcy5vbkRhdGE9dGhpcy5fb25EYXRh"
    "LmV2ZW50LHRoaXMuX29uTGluZUZlZWQ9dGhpcy5yZWdpc3RlcihuZXcgbC5FdmVudEVtaXR0ZXIpLHRoaXMub25MaW5lRmVlZD10aGlzLl9vbkxpbmVGZWVk"
    "LmV2ZW50LHRoaXMuX29uUmVzaXplPXRoaXMucmVnaXN0ZXIobmV3IGwuRXZlbnRFbWl0dGVyKSx0aGlzLm9uUmVzaXplPXRoaXMuX29uUmVzaXplLmV2ZW50"
    "LHRoaXMuX29uV3JpdGVQYXJzZWQ9dGhpcy5yZWdpc3RlcihuZXcgbC5FdmVudEVtaXR0ZXIpLHRoaXMub25Xcml0ZVBhcnNlZD10aGlzLl9vbldyaXRlUGFy"
    "c2VkLmV2ZW50LHRoaXMuX29uU2Nyb2xsPXRoaXMucmVnaXN0ZXIobmV3IGwuRXZlbnRFbWl0dGVyKSx0aGlzLl9pbnN0YW50aWF0aW9uU2VydmljZT1uZXcg"
    "bi5JbnN0YW50aWF0aW9uU2VydmljZSx0aGlzLm9wdGlvbnNTZXJ2aWNlPXRoaXMucmVnaXN0ZXIobmV3IGguT3B0aW9uc1NlcnZpY2UoZSkpLHRoaXMuX2lu"
    "c3RhbnRpYXRpb25TZXJ2aWNlLnNldFNlcnZpY2Uoci5JT3B0aW9uc1NlcnZpY2UsdGhpcy5vcHRpb25zU2VydmljZSksdGhpcy5fYnVmZmVyU2VydmljZT10"
    "aGlzLnJlZ2lzdGVyKHRoaXMuX2luc3RhbnRpYXRpb25TZXJ2aWNlLmNyZWF0ZUluc3RhbmNlKGEuQnVmZmVyU2VydmljZSkpLHRoaXMuX2luc3RhbnRpYXRp"
    "b25TZXJ2aWNlLnNldFNlcnZpY2Uoci5JQnVmZmVyU2VydmljZSx0aGlzLl9idWZmZXJTZXJ2aWNlKSx0aGlzLl9sb2dTZXJ2aWNlPXRoaXMucmVnaXN0ZXIo"
    "dGhpcy5faW5zdGFudGlhdGlvblNlcnZpY2UuY3JlYXRlSW5zdGFuY2Uoby5Mb2dTZXJ2aWNlKSksdGhpcy5faW5zdGFudGlhdGlvblNlcnZpY2Uuc2V0U2Vy"
    "dmljZShyLklMb2dTZXJ2aWNlLHRoaXMuX2xvZ1NlcnZpY2UpLHRoaXMuY29yZVNlcnZpY2U9dGhpcy5yZWdpc3Rlcih0aGlzLl9pbnN0YW50aWF0aW9uU2Vy"
    "dmljZS5jcmVhdGVJbnN0YW5jZShjLkNvcmVTZXJ2aWNlKSksdGhpcy5faW5zdGFudGlhdGlvblNlcnZpY2Uuc2V0U2VydmljZShyLklDb3JlU2VydmljZSx0"
    "aGlzLmNvcmVTZXJ2aWNlKSx0aGlzLmNvcmVNb3VzZVNlcnZpY2U9dGhpcy5yZWdpc3Rlcih0aGlzLl9pbnN0YW50aWF0aW9uU2VydmljZS5jcmVhdGVJbnN0"
    "YW5jZShkLkNvcmVNb3VzZVNlcnZpY2UpKSx0aGlzLl9pbnN0YW50aWF0aW9uU2VydmljZS5zZXRTZXJ2aWNlKHIuSUNvcmVNb3VzZVNlcnZpY2UsdGhpcy5j"
    "b3JlTW91c2VTZXJ2aWNlKSx0aGlzLnVuaWNvZGVTZXJ2aWNlPXRoaXMucmVnaXN0ZXIodGhpcy5faW5zdGFudGlhdGlvblNlcnZpY2UuY3JlYXRlSW5zdGFu"
    "Y2UoXy5Vbmljb2RlU2VydmljZSkpLHRoaXMuX2luc3RhbnRpYXRpb25TZXJ2aWNlLnNldFNlcnZpY2Uoci5JVW5pY29kZVNlcnZpY2UsdGhpcy51bmljb2Rl"
    "U2VydmljZSksdGhpcy5fY2hhcnNldFNlcnZpY2U9dGhpcy5faW5zdGFudGlhdGlvblNlcnZpY2UuY3JlYXRlSW5zdGFuY2UodS5DaGFyc2V0U2VydmljZSks"
    "dGhpcy5faW5zdGFudGlhdGlvblNlcnZpY2Uuc2V0U2VydmljZShyLklDaGFyc2V0U2VydmljZSx0aGlzLl9jaGFyc2V0U2VydmljZSksdGhpcy5fb3NjTGlu"
    "a1NlcnZpY2U9dGhpcy5faW5zdGFudGlhdGlvblNlcnZpY2UuY3JlYXRlSW5zdGFuY2UoZy5Pc2NMaW5rU2VydmljZSksdGhpcy5faW5zdGFudGlhdGlvblNl"
    "cnZpY2Uuc2V0U2VydmljZShyLklPc2NMaW5rU2VydmljZSx0aGlzLl9vc2NMaW5rU2VydmljZSksdGhpcy5faW5wdXRIYW5kbGVyPXRoaXMucmVnaXN0ZXIo"
    "bmV3IHYuSW5wdXRIYW5kbGVyKHRoaXMuX2J1ZmZlclNlcnZpY2UsdGhpcy5fY2hhcnNldFNlcnZpY2UsdGhpcy5jb3JlU2VydmljZSx0aGlzLl9sb2dTZXJ2"
    "aWNlLHRoaXMub3B0aW9uc1NlcnZpY2UsdGhpcy5fb3NjTGlua1NlcnZpY2UsdGhpcy5jb3JlTW91c2VTZXJ2aWNlLHRoaXMudW5pY29kZVNlcnZpY2UpKSx0"
    "aGlzLnJlZ2lzdGVyKCgwLGwuZm9yd2FyZEV2ZW50KSh0aGlzLl9pbnB1dEhhbmRsZXIub25MaW5lRmVlZCx0aGlzLl9vbkxpbmVGZWVkKSksdGhpcy5yZWdp"
    "c3Rlcih0aGlzLl9pbnB1dEhhbmRsZXIpLHRoaXMucmVnaXN0ZXIoKDAsbC5mb3J3YXJkRXZlbnQpKHRoaXMuX2J1ZmZlclNlcnZpY2Uub25SZXNpemUsdGhp"
    "cy5fb25SZXNpemUpKSx0aGlzLnJlZ2lzdGVyKCgwLGwuZm9yd2FyZEV2ZW50KSh0aGlzLmNvcmVTZXJ2aWNlLm9uRGF0YSx0aGlzLl9vbkRhdGEpKSx0aGlz"
    "LnJlZ2lzdGVyKCgwLGwuZm9yd2FyZEV2ZW50KSh0aGlzLmNvcmVTZXJ2aWNlLm9uQmluYXJ5LHRoaXMuX29uQmluYXJ5KSksdGhpcy5yZWdpc3Rlcih0aGlz"
    "LmNvcmVTZXJ2aWNlLm9uUmVxdWVzdFNjcm9sbFRvQm90dG9tKCgoKT0+dGhpcy5zY3JvbGxUb0JvdHRvbSgpKSkpLHRoaXMucmVnaXN0ZXIodGhpcy5jb3Jl"
    "U2VydmljZS5vblVzZXJJbnB1dCgoKCk9PnRoaXMuX3dyaXRlQnVmZmVyLmhhbmRsZVVzZXJJbnB1dCgpKSkpLHRoaXMucmVnaXN0ZXIodGhpcy5vcHRpb25z"
    "U2VydmljZS5vbk11bHRpcGxlT3B0aW9uQ2hhbmdlKFsid2luZG93c01vZGUiLCJ3aW5kb3dzUHR5Il0sKCgpPT50aGlzLl9oYW5kbGVXaW5kb3dzUHR5T3B0"
    "aW9uQ2hhbmdlKCkpKSksdGhpcy5yZWdpc3Rlcih0aGlzLl9idWZmZXJTZXJ2aWNlLm9uU2Nyb2xsKChlPT57dGhpcy5fb25TY3JvbGwuZmlyZSh7cG9zaXRp"
    "b246dGhpcy5fYnVmZmVyU2VydmljZS5idWZmZXIueWRpc3Asc291cmNlOjB9KSx0aGlzLl9pbnB1dEhhbmRsZXIubWFya1JhbmdlRGlydHkodGhpcy5fYnVm"
    "ZmVyU2VydmljZS5idWZmZXIuc2Nyb2xsVG9wLHRoaXMuX2J1ZmZlclNlcnZpY2UuYnVmZmVyLnNjcm9sbEJvdHRvbSl9KSkpLHRoaXMucmVnaXN0ZXIodGhp"
    "cy5faW5wdXRIYW5kbGVyLm9uU2Nyb2xsKChlPT57dGhpcy5fb25TY3JvbGwuZmlyZSh7cG9zaXRpb246dGhpcy5fYnVmZmVyU2VydmljZS5idWZmZXIueWRp"
    "c3Asc291cmNlOjB9KSx0aGlzLl9pbnB1dEhhbmRsZXIubWFya1JhbmdlRGlydHkodGhpcy5fYnVmZmVyU2VydmljZS5idWZmZXIuc2Nyb2xsVG9wLHRoaXMu"
    "X2J1ZmZlclNlcnZpY2UuYnVmZmVyLnNjcm9sbEJvdHRvbSl9KSkpLHRoaXMuX3dyaXRlQnVmZmVyPXRoaXMucmVnaXN0ZXIobmV3IHAuV3JpdGVCdWZmZXIo"
    "KChlLHQpPT50aGlzLl9pbnB1dEhhbmRsZXIucGFyc2UoZSx0KSkpKSx0aGlzLnJlZ2lzdGVyKCgwLGwuZm9yd2FyZEV2ZW50KSh0aGlzLl93cml0ZUJ1ZmZl"
    "ci5vbldyaXRlUGFyc2VkLHRoaXMuX29uV3JpdGVQYXJzZWQpKX13cml0ZShlLHQpe3RoaXMuX3dyaXRlQnVmZmVyLndyaXRlKGUsdCl9d3JpdGVTeW5jKGUs"
    "dCl7dGhpcy5fbG9nU2VydmljZS5sb2dMZXZlbDw9ci5Mb2dMZXZlbEVudW0uV0FSTiYmIW0mJih0aGlzLl9sb2dTZXJ2aWNlLndhcm4oIndyaXRlU3luYyBp"
    "cyB1bnJlbGlhYmxlIGFuZCB3aWxsIGJlIHJlbW92ZWQgc29vbi4iKSxtPSEwKSx0aGlzLl93cml0ZUJ1ZmZlci53cml0ZVN5bmMoZSx0KX1yZXNpemUoZSx0"
    "KXtpc05hTihlKXx8aXNOYU4odCl8fChlPU1hdGgubWF4KGUsYS5NSU5JTVVNX0NPTFMpLHQ9TWF0aC5tYXgodCxhLk1JTklNVU1fUk9XUyksdGhpcy5fYnVm"
    "ZmVyU2VydmljZS5yZXNpemUoZSx0KSl9c2Nyb2xsKGUsdD0hMSl7dGhpcy5fYnVmZmVyU2VydmljZS5zY3JvbGwoZSx0KX1zY3JvbGxMaW5lcyhlLHQsaSl7"
    "dGhpcy5fYnVmZmVyU2VydmljZS5zY3JvbGxMaW5lcyhlLHQsaSl9c2Nyb2xsUGFnZXMoZSl7dGhpcy5zY3JvbGxMaW5lcyhlKih0aGlzLnJvd3MtMSkpfXNj"
    "cm9sbFRvVG9wKCl7dGhpcy5zY3JvbGxMaW5lcygtdGhpcy5fYnVmZmVyU2VydmljZS5idWZmZXIueWRpc3ApfXNjcm9sbFRvQm90dG9tKCl7dGhpcy5zY3Jv"
    "bGxMaW5lcyh0aGlzLl9idWZmZXJTZXJ2aWNlLmJ1ZmZlci55YmFzZS10aGlzLl9idWZmZXJTZXJ2aWNlLmJ1ZmZlci55ZGlzcCl9c2Nyb2xsVG9MaW5lKGUp"
    "e2NvbnN0IHQ9ZS10aGlzLl9idWZmZXJTZXJ2aWNlLmJ1ZmZlci55ZGlzcDswIT09dCYmdGhpcy5zY3JvbGxMaW5lcyh0KX1yZWdpc3RlckVzY0hhbmRsZXIo"
    "ZSx0KXtyZXR1cm4gdGhpcy5faW5wdXRIYW5kbGVyLnJlZ2lzdGVyRXNjSGFuZGxlcihlLHQpfXJlZ2lzdGVyRGNzSGFuZGxlcihlLHQpe3JldHVybiB0aGlz"
    "Ll9pbnB1dEhhbmRsZXIucmVnaXN0ZXJEY3NIYW5kbGVyKGUsdCl9cmVnaXN0ZXJDc2lIYW5kbGVyKGUsdCl7cmV0dXJuIHRoaXMuX2lucHV0SGFuZGxlci5y"
    "ZWdpc3RlckNzaUhhbmRsZXIoZSx0KX1yZWdpc3Rlck9zY0hhbmRsZXIoZSx0KXtyZXR1cm4gdGhpcy5faW5wdXRIYW5kbGVyLnJlZ2lzdGVyT3NjSGFuZGxl"
    "cihlLHQpfV9zZXR1cCgpe3RoaXMuX2hhbmRsZVdpbmRvd3NQdHlPcHRpb25DaGFuZ2UoKX1yZXNldCgpe3RoaXMuX2lucHV0SGFuZGxlci5yZXNldCgpLHRo"
    "aXMuX2J1ZmZlclNlcnZpY2UucmVzZXQoKSx0aGlzLl9jaGFyc2V0U2VydmljZS5yZXNldCgpLHRoaXMuY29yZVNlcnZpY2UucmVzZXQoKSx0aGlzLmNvcmVN"
    "b3VzZVNlcnZpY2UucmVzZXQoKX1faGFuZGxlV2luZG93c1B0eU9wdGlvbkNoYW5nZSgpe2xldCBlPSExO2NvbnN0IHQ9dGhpcy5vcHRpb25zU2VydmljZS5y"
    "YXdPcHRpb25zLndpbmRvd3NQdHk7dCYmdm9pZCAwIT09dC5idWlsZE51bWJlciYmdm9pZCAwIT09dC5idWlsZE51bWJlcj9lPSEhKCJjb25wdHkiPT09dC5i"
    "YWNrZW5kJiZ0LmJ1aWxkTnVtYmVyPDIxMzc2KTp0aGlzLm9wdGlvbnNTZXJ2aWNlLnJhd09wdGlvbnMud2luZG93c01vZGUmJihlPSEwKSxlP3RoaXMuX2Vu"
    "YWJsZVdpbmRvd3NXcmFwcGluZ0hldXJpc3RpY3MoKTp0aGlzLl93aW5kb3dzV3JhcHBpbmdIZXVyaXN0aWNzLmNsZWFyKCl9X2VuYWJsZVdpbmRvd3NXcmFw"
    "cGluZ0hldXJpc3RpY3MoKXtpZighdGhpcy5fd2luZG93c1dyYXBwaW5nSGV1cmlzdGljcy52YWx1ZSl7Y29uc3QgZT1bXTtlLnB1c2godGhpcy5vbkxpbmVG"
    "ZWVkKGYudXBkYXRlV2luZG93c01vZGVXcmFwcGVkU3RhdGUuYmluZChudWxsLHRoaXMuX2J1ZmZlclNlcnZpY2UpKSksZS5wdXNoKHRoaXMucmVnaXN0ZXJD"
    "c2lIYW5kbGVyKHtmaW5hbDoiSCJ9LCgoKT0+KCgwLGYudXBkYXRlV2luZG93c01vZGVXcmFwcGVkU3RhdGUpKHRoaXMuX2J1ZmZlclNlcnZpY2UpLCExKSkp"
    "KSx0aGlzLl93aW5kb3dzV3JhcHBpbmdIZXVyaXN0aWNzLnZhbHVlPSgwLHMudG9EaXNwb3NhYmxlKSgoKCk9Pntmb3IoY29uc3QgdCBvZiBlKXQuZGlzcG9z"
    "ZSgpfSkpfX19dC5Db3JlVGVybWluYWw9U30sODQ2MDooZSx0KT0+e09iamVjdC5kZWZpbmVQcm9wZXJ0eSh0LCJfX2VzTW9kdWxlIix7dmFsdWU6ITB9KSx0"
    "LmZvcndhcmRFdmVudD10LkV2ZW50RW1pdHRlcj12b2lkIDAsdC5FdmVudEVtaXR0ZXI9Y2xhc3N7Y29uc3RydWN0b3IoKXt0aGlzLl9saXN0ZW5lcnM9W10s"
    "dGhpcy5fZGlzcG9zZWQ9ITF9Z2V0IGV2ZW50KCl7cmV0dXJuIHRoaXMuX2V2ZW50fHwodGhpcy5fZXZlbnQ9ZT0+KHRoaXMuX2xpc3RlbmVycy5wdXNoKGUp"
    "LHtkaXNwb3NlOigpPT57aWYoIXRoaXMuX2Rpc3Bvc2VkKWZvcihsZXQgdD0wO3Q8dGhpcy5fbGlzdGVuZXJzLmxlbmd0aDt0KyspaWYodGhpcy5fbGlzdGVu"
    "ZXJzW3RdPT09ZSlyZXR1cm4gdm9pZCB0aGlzLl9saXN0ZW5lcnMuc3BsaWNlKHQsMSl9fSkpLHRoaXMuX2V2ZW50fWZpcmUoZSx0KXtjb25zdCBpPVtdO2Zv"
    "cihsZXQgZT0wO2U8dGhpcy5fbGlzdGVuZXJzLmxlbmd0aDtlKyspaS5wdXNoKHRoaXMuX2xpc3RlbmVyc1tlXSk7Zm9yKGxldCBzPTA7czxpLmxlbmd0aDtz"
    "KyspaVtzXS5jYWxsKHZvaWQgMCxlLHQpfWRpc3Bvc2UoKXt0aGlzLmNsZWFyTGlzdGVuZXJzKCksdGhpcy5fZGlzcG9zZWQ9ITB9Y2xlYXJMaXN0ZW5lcnMo"
    "KXt0aGlzLl9saXN0ZW5lcnMmJih0aGlzLl9saXN0ZW5lcnMubGVuZ3RoPTApfX0sdC5mb3J3YXJkRXZlbnQ9ZnVuY3Rpb24oZSx0KXtyZXR1cm4gZSgoZT0+"
    "dC5maXJlKGUpKSl9fSw1NDM1OmZ1bmN0aW9uKGUsdCxpKXt2YXIgcz10aGlzJiZ0aGlzLl9fZGVjb3JhdGV8fGZ1bmN0aW9uKGUsdCxpLHMpe3ZhciByLG49"
    "YXJndW1lbnRzLmxlbmd0aCxvPW48Mz90Om51bGw9PT1zP3M9T2JqZWN0LmdldE93blByb3BlcnR5RGVzY3JpcHRvcih0LGkpOnM7aWYoIm9iamVjdCI9PXR5"
    "cGVvZiBSZWZsZWN0JiYiZnVuY3Rpb24iPT10eXBlb2YgUmVmbGVjdC5kZWNvcmF0ZSlvPVJlZmxlY3QuZGVjb3JhdGUoZSx0LGkscyk7ZWxzZSBmb3IodmFy"
    "IGE9ZS5sZW5ndGgtMTthPj0wO2EtLSkocj1lW2FdKSYmKG89KG48Mz9yKG8pOm4+Mz9yKHQsaSxvKTpyKHQsaSkpfHxvKTtyZXR1cm4gbj4zJiZvJiZPYmpl"
    "Y3QuZGVmaW5lUHJvcGVydHkodCxpLG8pLG99LHI9dGhpcyYmdGhpcy5fX3BhcmFtfHxmdW5jdGlvbihlLHQpe3JldHVybiBmdW5jdGlvbihpLHMpe3QoaSxz"
    "LGUpfX07T2JqZWN0LmRlZmluZVByb3BlcnR5KHQsIl9fZXNNb2R1bGUiLHt2YWx1ZTohMH0pLHQuSW5wdXRIYW5kbGVyPXQuV2luZG93c09wdGlvbnNSZXBv"
    "cnRUeXBlPXZvaWQgMDtjb25zdCBuPWkoMjU4NCksbz1pKDcxMTYpLGE9aSgyMDE1KSxoPWkoODQ0KSxjPWkoNDgyKSxsPWkoODQzNyksZD1pKDg0NjApLF89"
    "aSg2NDMpLHU9aSg1MTEpLGY9aSgzNzM0KSx2PWkoMjU4NSkscD1pKDYyNDIpLGc9aSg2MzUxKSxtPWkoNTk0MSksUz17IigiOjAsIikiOjEsIioiOjIsIisi"
    "OjMsIi0iOjEsIi4iOjJ9LEM9MTMxMDcyO2Z1bmN0aW9uIGIoZSx0KXtpZihlPjI0KXJldHVybiB0LnNldFdpbkxpbmVzfHwhMTtzd2l0Y2goZSl7Y2FzZSAx"
    "OnJldHVybiEhdC5yZXN0b3JlV2luO2Nhc2UgMjpyZXR1cm4hIXQubWluaW1pemVXaW47Y2FzZSAzOnJldHVybiEhdC5zZXRXaW5Qb3NpdGlvbjtjYXNlIDQ6"
    "cmV0dXJuISF0LnNldFdpblNpemVQaXhlbHM7Y2FzZSA1OnJldHVybiEhdC5yYWlzZVdpbjtjYXNlIDY6cmV0dXJuISF0Lmxvd2VyV2luO2Nhc2UgNzpyZXR1"
    "cm4hIXQucmVmcmVzaFdpbjtjYXNlIDg6cmV0dXJuISF0LnNldFdpblNpemVDaGFycztjYXNlIDk6cmV0dXJuISF0Lm1heGltaXplV2luO2Nhc2UgMTA6cmV0"
    "dXJuISF0LmZ1bGxzY3JlZW5XaW47Y2FzZSAxMTpyZXR1cm4hIXQuZ2V0V2luU3RhdGU7Y2FzZSAxMzpyZXR1cm4hIXQuZ2V0V2luUG9zaXRpb247Y2FzZSAx"
    "NDpyZXR1cm4hIXQuZ2V0V2luU2l6ZVBpeGVscztjYXNlIDE1OnJldHVybiEhdC5nZXRTY3JlZW5TaXplUGl4ZWxzO2Nhc2UgMTY6cmV0dXJuISF0LmdldENl"
    "bGxTaXplUGl4ZWxzO2Nhc2UgMTg6cmV0dXJuISF0LmdldFdpblNpemVDaGFycztjYXNlIDE5OnJldHVybiEhdC5nZXRTY3JlZW5TaXplQ2hhcnM7Y2FzZSAy"
    "MDpyZXR1cm4hIXQuZ2V0SWNvblRpdGxlO2Nhc2UgMjE6cmV0dXJuISF0LmdldFdpblRpdGxlO2Nhc2UgMjI6cmV0dXJuISF0LnB1c2hUaXRsZTtjYXNlIDIz"
    "OnJldHVybiEhdC5wb3BUaXRsZTtjYXNlIDI0OnJldHVybiEhdC5zZXRXaW5MaW5lc31yZXR1cm4hMX12YXIgeTshZnVuY3Rpb24oZSl7ZVtlLkdFVF9XSU5f"
    "U0laRV9QSVhFTFM9MF09IkdFVF9XSU5fU0laRV9QSVhFTFMiLGVbZS5HRVRfQ0VMTF9TSVpFX1BJWEVMUz0xXT0iR0VUX0NFTExfU0laRV9QSVhFTFMifSh5"
    "fHwodC5XaW5kb3dzT3B0aW9uc1JlcG9ydFR5cGU9eT17fSkpO2xldCB3PTA7Y2xhc3MgRSBleHRlbmRzIGguRGlzcG9zYWJsZXtnZXRBdHRyRGF0YSgpe3Jl"
    "dHVybiB0aGlzLl9jdXJBdHRyRGF0YX1jb25zdHJ1Y3RvcihlLHQsaSxzLHIsaCxfLGYsdj1uZXcgYS5Fc2NhcGVTZXF1ZW5jZVBhcnNlcil7c3VwZXIoKSx0"
    "aGlzLl9idWZmZXJTZXJ2aWNlPWUsdGhpcy5fY2hhcnNldFNlcnZpY2U9dCx0aGlzLl9jb3JlU2VydmljZT1pLHRoaXMuX2xvZ1NlcnZpY2U9cyx0aGlzLl9v"
    "cHRpb25zU2VydmljZT1yLHRoaXMuX29zY0xpbmtTZXJ2aWNlPWgsdGhpcy5fY29yZU1vdXNlU2VydmljZT1fLHRoaXMuX3VuaWNvZGVTZXJ2aWNlPWYsdGhp"
    "cy5fcGFyc2VyPXYsdGhpcy5fcGFyc2VCdWZmZXI9bmV3IFVpbnQzMkFycmF5KDQwOTYpLHRoaXMuX3N0cmluZ0RlY29kZXI9bmV3IGMuU3RyaW5nVG9VdGYz"
    "Mix0aGlzLl91dGY4RGVjb2Rlcj1uZXcgYy5VdGY4VG9VdGYzMix0aGlzLl93b3JrQ2VsbD1uZXcgdS5DZWxsRGF0YSx0aGlzLl93aW5kb3dUaXRsZT0iIix0"
    "aGlzLl9pY29uTmFtZT0iIix0aGlzLl93aW5kb3dUaXRsZVN0YWNrPVtdLHRoaXMuX2ljb25OYW1lU3RhY2s9W10sdGhpcy5fY3VyQXR0ckRhdGE9bC5ERUZB"
    "VUxUX0FUVFJfREFUQS5jbG9uZSgpLHRoaXMuX2VyYXNlQXR0ckRhdGFJbnRlcm5hbD1sLkRFRkFVTFRfQVRUUl9EQVRBLmNsb25lKCksdGhpcy5fb25SZXF1"
    "ZXN0QmVsbD10aGlzLnJlZ2lzdGVyKG5ldyBkLkV2ZW50RW1pdHRlciksdGhpcy5vblJlcXVlc3RCZWxsPXRoaXMuX29uUmVxdWVzdEJlbGwuZXZlbnQsdGhp"
    "cy5fb25SZXF1ZXN0UmVmcmVzaFJvd3M9dGhpcy5yZWdpc3RlcihuZXcgZC5FdmVudEVtaXR0ZXIpLHRoaXMub25SZXF1ZXN0UmVmcmVzaFJvd3M9dGhpcy5f"
    "b25SZXF1ZXN0UmVmcmVzaFJvd3MuZXZlbnQsdGhpcy5fb25SZXF1ZXN0UmVzZXQ9dGhpcy5yZWdpc3RlcihuZXcgZC5FdmVudEVtaXR0ZXIpLHRoaXMub25S"
    "ZXF1ZXN0UmVzZXQ9dGhpcy5fb25SZXF1ZXN0UmVzZXQuZXZlbnQsdGhpcy5fb25SZXF1ZXN0U2VuZEZvY3VzPXRoaXMucmVnaXN0ZXIobmV3IGQuRXZlbnRF"
    "bWl0dGVyKSx0aGlzLm9uUmVxdWVzdFNlbmRGb2N1cz10aGlzLl9vblJlcXVlc3RTZW5kRm9jdXMuZXZlbnQsdGhpcy5fb25SZXF1ZXN0U3luY1Njcm9sbEJh"
    "cj10aGlzLnJlZ2lzdGVyKG5ldyBkLkV2ZW50RW1pdHRlciksdGhpcy5vblJlcXVlc3RTeW5jU2Nyb2xsQmFyPXRoaXMuX29uUmVxdWVzdFN5bmNTY3JvbGxC"
    "YXIuZXZlbnQsdGhpcy5fb25SZXF1ZXN0V2luZG93c09wdGlvbnNSZXBvcnQ9dGhpcy5yZWdpc3RlcihuZXcgZC5FdmVudEVtaXR0ZXIpLHRoaXMub25SZXF1"
    "ZXN0V2luZG93c09wdGlvbnNSZXBvcnQ9dGhpcy5fb25SZXF1ZXN0V2luZG93c09wdGlvbnNSZXBvcnQuZXZlbnQsdGhpcy5fb25BMTF5Q2hhcj10aGlzLnJl"
    "Z2lzdGVyKG5ldyBkLkV2ZW50RW1pdHRlciksdGhpcy5vbkExMXlDaGFyPXRoaXMuX29uQTExeUNoYXIuZXZlbnQsdGhpcy5fb25BMTF5VGFiPXRoaXMucmVn"
    "aXN0ZXIobmV3IGQuRXZlbnRFbWl0dGVyKSx0aGlzLm9uQTExeVRhYj10aGlzLl9vbkExMXlUYWIuZXZlbnQsdGhpcy5fb25DdXJzb3JNb3ZlPXRoaXMucmVn"
    "aXN0ZXIobmV3IGQuRXZlbnRFbWl0dGVyKSx0aGlzLm9uQ3Vyc29yTW92ZT10aGlzLl9vbkN1cnNvck1vdmUuZXZlbnQsdGhpcy5fb25MaW5lRmVlZD10aGlz"
    "LnJlZ2lzdGVyKG5ldyBkLkV2ZW50RW1pdHRlciksdGhpcy5vbkxpbmVGZWVkPXRoaXMuX29uTGluZUZlZWQuZXZlbnQsdGhpcy5fb25TY3JvbGw9dGhpcy5y"
    "ZWdpc3RlcihuZXcgZC5FdmVudEVtaXR0ZXIpLHRoaXMub25TY3JvbGw9dGhpcy5fb25TY3JvbGwuZXZlbnQsdGhpcy5fb25UaXRsZUNoYW5nZT10aGlzLnJl"
    "Z2lzdGVyKG5ldyBkLkV2ZW50RW1pdHRlciksdGhpcy5vblRpdGxlQ2hhbmdlPXRoaXMuX29uVGl0bGVDaGFuZ2UuZXZlbnQsdGhpcy5fb25Db2xvcj10aGlz"
    "LnJlZ2lzdGVyKG5ldyBkLkV2ZW50RW1pdHRlciksdGhpcy5vbkNvbG9yPXRoaXMuX29uQ29sb3IuZXZlbnQsdGhpcy5fcGFyc2VTdGFjaz17cGF1c2VkOiEx"
    "LGN1cnNvclN0YXJ0WDowLGN1cnNvclN0YXJ0WTowLGRlY29kZWRMZW5ndGg6MCxwb3NpdGlvbjowfSx0aGlzLl9zcGVjaWFsQ29sb3JzPVsyNTYsMjU3LDI1"
    "OF0sdGhpcy5yZWdpc3Rlcih0aGlzLl9wYXJzZXIpLHRoaXMuX2RpcnR5Um93VHJhY2tlcj1uZXcgayh0aGlzLl9idWZmZXJTZXJ2aWNlKSx0aGlzLl9hY3Rp"
    "dmVCdWZmZXI9dGhpcy5fYnVmZmVyU2VydmljZS5idWZmZXIsdGhpcy5yZWdpc3Rlcih0aGlzLl9idWZmZXJTZXJ2aWNlLmJ1ZmZlcnMub25CdWZmZXJBY3Rp"
    "dmF0ZSgoZT0+dGhpcy5fYWN0aXZlQnVmZmVyPWUuYWN0aXZlQnVmZmVyKSkpLHRoaXMuX3BhcnNlci5zZXRDc2lIYW5kbGVyRmFsbGJhY2soKChlLHQpPT57"
    "dGhpcy5fbG9nU2VydmljZS5kZWJ1ZygiVW5rbm93biBDU0kgY29kZTogIix7aWRlbnRpZmllcjp0aGlzLl9wYXJzZXIuaWRlbnRUb1N0cmluZyhlKSxwYXJh"
    "bXM6dC50b0FycmF5KCl9KX0pKSx0aGlzLl9wYXJzZXIuc2V0RXNjSGFuZGxlckZhbGxiYWNrKChlPT57dGhpcy5fbG9nU2VydmljZS5kZWJ1ZygiVW5rbm93"
    "biBFU0MgY29kZTogIix7aWRlbnRpZmllcjp0aGlzLl9wYXJzZXIuaWRlbnRUb1N0cmluZyhlKX0pfSkpLHRoaXMuX3BhcnNlci5zZXRFeGVjdXRlSGFuZGxl"
    "ckZhbGxiYWNrKChlPT57dGhpcy5fbG9nU2VydmljZS5kZWJ1ZygiVW5rbm93biBFWEVDVVRFIGNvZGU6ICIse2NvZGU6ZX0pfSkpLHRoaXMuX3BhcnNlci5z"
    "ZXRPc2NIYW5kbGVyRmFsbGJhY2soKChlLHQsaSk9Pnt0aGlzLl9sb2dTZXJ2aWNlLmRlYnVnKCJVbmtub3duIE9TQyBjb2RlOiAiLHtpZGVudGlmaWVyOmUs"
    "YWN0aW9uOnQsZGF0YTppfSl9KSksdGhpcy5fcGFyc2VyLnNldERjc0hhbmRsZXJGYWxsYmFjaygoKGUsdCxpKT0+eyJIT09LIj09PXQmJihpPWkudG9BcnJh"
    "eSgpKSx0aGlzLl9sb2dTZXJ2aWNlLmRlYnVnKCJVbmtub3duIERDUyBjb2RlOiAiLHtpZGVudGlmaWVyOnRoaXMuX3BhcnNlci5pZGVudFRvU3RyaW5nKGUp"
    "LGFjdGlvbjp0LHBheWxvYWQ6aX0pfSkpLHRoaXMuX3BhcnNlci5zZXRQcmludEhhbmRsZXIoKChlLHQsaSk9PnRoaXMucHJpbnQoZSx0LGkpKSksdGhpcy5f"
    "cGFyc2VyLnJlZ2lzdGVyQ3NpSGFuZGxlcih7ZmluYWw6IkAifSwoZT0+dGhpcy5pbnNlcnRDaGFycyhlKSkpLHRoaXMuX3BhcnNlci5yZWdpc3RlckNzaUhh"
    "bmRsZXIoe2ludGVybWVkaWF0ZXM6IiAiLGZpbmFsOiJAIn0sKGU9PnRoaXMuc2Nyb2xsTGVmdChlKSkpLHRoaXMuX3BhcnNlci5yZWdpc3RlckNzaUhhbmRs"
    "ZXIoe2ZpbmFsOiJBIn0sKGU9PnRoaXMuY3Vyc29yVXAoZSkpKSx0aGlzLl9wYXJzZXIucmVnaXN0ZXJDc2lIYW5kbGVyKHtpbnRlcm1lZGlhdGVzOiIgIixm"
    "aW5hbDoiQSJ9LChlPT50aGlzLnNjcm9sbFJpZ2h0KGUpKSksdGhpcy5fcGFyc2VyLnJlZ2lzdGVyQ3NpSGFuZGxlcih7ZmluYWw6IkIifSwoZT0+dGhpcy5j"
    "dXJzb3JEb3duKGUpKSksdGhpcy5fcGFyc2VyLnJlZ2lzdGVyQ3NpSGFuZGxlcih7ZmluYWw6IkMifSwoZT0+dGhpcy5jdXJzb3JGb3J3YXJkKGUpKSksdGhp"
    "cy5fcGFyc2VyLnJlZ2lzdGVyQ3NpSGFuZGxlcih7ZmluYWw6IkQifSwoZT0+dGhpcy5jdXJzb3JCYWNrd2FyZChlKSkpLHRoaXMuX3BhcnNlci5yZWdpc3Rl"
    "ckNzaUhhbmRsZXIoe2ZpbmFsOiJFIn0sKGU9PnRoaXMuY3Vyc29yTmV4dExpbmUoZSkpKSx0aGlzLl9wYXJzZXIucmVnaXN0ZXJDc2lIYW5kbGVyKHtmaW5h"
    "bDoiRiJ9LChlPT50aGlzLmN1cnNvclByZWNlZGluZ0xpbmUoZSkpKSx0aGlzLl9wYXJzZXIucmVnaXN0ZXJDc2lIYW5kbGVyKHtmaW5hbDoiRyJ9LChlPT50"
    "aGlzLmN1cnNvckNoYXJBYnNvbHV0ZShlKSkpLHRoaXMuX3BhcnNlci5yZWdpc3RlckNzaUhhbmRsZXIoe2ZpbmFsOiJIIn0sKGU9PnRoaXMuY3Vyc29yUG9z"
    "aXRpb24oZSkpKSx0aGlzLl9wYXJzZXIucmVnaXN0ZXJDc2lIYW5kbGVyKHtmaW5hbDoiSSJ9LChlPT50aGlzLmN1cnNvckZvcndhcmRUYWIoZSkpKSx0aGlz"
    "Ll9wYXJzZXIucmVnaXN0ZXJDc2lIYW5kbGVyKHtmaW5hbDoiSiJ9LChlPT50aGlzLmVyYXNlSW5EaXNwbGF5KGUsITEpKSksdGhpcy5fcGFyc2VyLnJlZ2lz"
    "dGVyQ3NpSGFuZGxlcih7cHJlZml4OiI/IixmaW5hbDoiSiJ9LChlPT50aGlzLmVyYXNlSW5EaXNwbGF5KGUsITApKSksdGhpcy5fcGFyc2VyLnJlZ2lzdGVy"
    "Q3NpSGFuZGxlcih7ZmluYWw6IksifSwoZT0+dGhpcy5lcmFzZUluTGluZShlLCExKSkpLHRoaXMuX3BhcnNlci5yZWdpc3RlckNzaUhhbmRsZXIoe3ByZWZp"
    "eDoiPyIsZmluYWw6IksifSwoZT0+dGhpcy5lcmFzZUluTGluZShlLCEwKSkpLHRoaXMuX3BhcnNlci5yZWdpc3RlckNzaUhhbmRsZXIoe2ZpbmFsOiJMIn0s"
    "KGU9PnRoaXMuaW5zZXJ0TGluZXMoZSkpKSx0aGlzLl9wYXJzZXIucmVnaXN0ZXJDc2lIYW5kbGVyKHtmaW5hbDoiTSJ9LChlPT50aGlzLmRlbGV0ZUxpbmVz"
    "KGUpKSksdGhpcy5fcGFyc2VyLnJlZ2lzdGVyQ3NpSGFuZGxlcih7ZmluYWw6IlAifSwoZT0+dGhpcy5kZWxldGVDaGFycyhlKSkpLHRoaXMuX3BhcnNlci5y"
    "ZWdpc3RlckNzaUhhbmRsZXIoe2ZpbmFsOiJTIn0sKGU9PnRoaXMuc2Nyb2xsVXAoZSkpKSx0aGlzLl9wYXJzZXIucmVnaXN0ZXJDc2lIYW5kbGVyKHtmaW5h"
    "bDoiVCJ9LChlPT50aGlzLnNjcm9sbERvd24oZSkpKSx0aGlzLl9wYXJzZXIucmVnaXN0ZXJDc2lIYW5kbGVyKHtmaW5hbDoiWCJ9LChlPT50aGlzLmVyYXNl"
    "Q2hhcnMoZSkpKSx0aGlzLl9wYXJzZXIucmVnaXN0ZXJDc2lIYW5kbGVyKHtmaW5hbDoiWiJ9LChlPT50aGlzLmN1cnNvckJhY2t3YXJkVGFiKGUpKSksdGhp"
    "cy5fcGFyc2VyLnJlZ2lzdGVyQ3NpSGFuZGxlcih7ZmluYWw6ImAifSwoZT0+dGhpcy5jaGFyUG9zQWJzb2x1dGUoZSkpKSx0aGlzLl9wYXJzZXIucmVnaXN0"
    "ZXJDc2lIYW5kbGVyKHtmaW5hbDoiYSJ9LChlPT50aGlzLmhQb3NpdGlvblJlbGF0aXZlKGUpKSksdGhpcy5fcGFyc2VyLnJlZ2lzdGVyQ3NpSGFuZGxlcih7"
    "ZmluYWw6ImIifSwoZT0+dGhpcy5yZXBlYXRQcmVjZWRpbmdDaGFyYWN0ZXIoZSkpKSx0aGlzLl9wYXJzZXIucmVnaXN0ZXJDc2lIYW5kbGVyKHtmaW5hbDoi"
    "YyJ9LChlPT50aGlzLnNlbmREZXZpY2VBdHRyaWJ1dGVzUHJpbWFyeShlKSkpLHRoaXMuX3BhcnNlci5yZWdpc3RlckNzaUhhbmRsZXIoe3ByZWZpeDoiPiIs"
    "ZmluYWw6ImMifSwoZT0+dGhpcy5zZW5kRGV2aWNlQXR0cmlidXRlc1NlY29uZGFyeShlKSkpLHRoaXMuX3BhcnNlci5yZWdpc3RlckNzaUhhbmRsZXIoe2Zp"
    "bmFsOiJkIn0sKGU9PnRoaXMubGluZVBvc0Fic29sdXRlKGUpKSksdGhpcy5fcGFyc2VyLnJlZ2lzdGVyQ3NpSGFuZGxlcih7ZmluYWw6ImUifSwoZT0+dGhp"
    "cy52UG9zaXRpb25SZWxhdGl2ZShlKSkpLHRoaXMuX3BhcnNlci5yZWdpc3RlckNzaUhhbmRsZXIoe2ZpbmFsOiJmIn0sKGU9PnRoaXMuaFZQb3NpdGlvbihl"
    "KSkpLHRoaXMuX3BhcnNlci5yZWdpc3RlckNzaUhhbmRsZXIoe2ZpbmFsOiJnIn0sKGU9PnRoaXMudGFiQ2xlYXIoZSkpKSx0aGlzLl9wYXJzZXIucmVnaXN0"
    "ZXJDc2lIYW5kbGVyKHtmaW5hbDoiaCJ9LChlPT50aGlzLnNldE1vZGUoZSkpKSx0aGlzLl9wYXJzZXIucmVnaXN0ZXJDc2lIYW5kbGVyKHtwcmVmaXg6Ij8i"
    "LGZpbmFsOiJoIn0sKGU9PnRoaXMuc2V0TW9kZVByaXZhdGUoZSkpKSx0aGlzLl9wYXJzZXIucmVnaXN0ZXJDc2lIYW5kbGVyKHtmaW5hbDoibCJ9LChlPT50"
    "aGlzLnJlc2V0TW9kZShlKSkpLHRoaXMuX3BhcnNlci5yZWdpc3RlckNzaUhhbmRsZXIoe3ByZWZpeDoiPyIsZmluYWw6ImwifSwoZT0+dGhpcy5yZXNldE1v"
    "ZGVQcml2YXRlKGUpKSksdGhpcy5fcGFyc2VyLnJlZ2lzdGVyQ3NpSGFuZGxlcih7ZmluYWw6Im0ifSwoZT0+dGhpcy5jaGFyQXR0cmlidXRlcyhlKSkpLHRo"
    "aXMuX3BhcnNlci5yZWdpc3RlckNzaUhhbmRsZXIoe2ZpbmFsOiJuIn0sKGU9PnRoaXMuZGV2aWNlU3RhdHVzKGUpKSksdGhpcy5fcGFyc2VyLnJlZ2lzdGVy"
    "Q3NpSGFuZGxlcih7cHJlZml4OiI/IixmaW5hbDoibiJ9LChlPT50aGlzLmRldmljZVN0YXR1c1ByaXZhdGUoZSkpKSx0aGlzLl9wYXJzZXIucmVnaXN0ZXJD"
    "c2lIYW5kbGVyKHtpbnRlcm1lZGlhdGVzOiIhIixmaW5hbDoicCJ9LChlPT50aGlzLnNvZnRSZXNldChlKSkpLHRoaXMuX3BhcnNlci5yZWdpc3RlckNzaUhh"
    "bmRsZXIoe2ludGVybWVkaWF0ZXM6IiAiLGZpbmFsOiJxIn0sKGU9PnRoaXMuc2V0Q3Vyc29yU3R5bGUoZSkpKSx0aGlzLl9wYXJzZXIucmVnaXN0ZXJDc2lI"
    "YW5kbGVyKHtmaW5hbDoiciJ9LChlPT50aGlzLnNldFNjcm9sbFJlZ2lvbihlKSkpLHRoaXMuX3BhcnNlci5yZWdpc3RlckNzaUhhbmRsZXIoe2ZpbmFsOiJz"
    "In0sKGU9PnRoaXMuc2F2ZUN1cnNvcihlKSkpLHRoaXMuX3BhcnNlci5yZWdpc3RlckNzaUhhbmRsZXIoe2ZpbmFsOiJ0In0sKGU9PnRoaXMud2luZG93T3B0"
    "aW9ucyhlKSkpLHRoaXMuX3BhcnNlci5yZWdpc3RlckNzaUhhbmRsZXIoe2ZpbmFsOiJ1In0sKGU9PnRoaXMucmVzdG9yZUN1cnNvcihlKSkpLHRoaXMuX3Bh"
    "cnNlci5yZWdpc3RlckNzaUhhbmRsZXIoe2ludGVybWVkaWF0ZXM6IiciLGZpbmFsOiJ9In0sKGU9PnRoaXMuaW5zZXJ0Q29sdW1ucyhlKSkpLHRoaXMuX3Bh"
    "cnNlci5yZWdpc3RlckNzaUhhbmRsZXIoe2ludGVybWVkaWF0ZXM6IiciLGZpbmFsOiJ+In0sKGU9PnRoaXMuZGVsZXRlQ29sdW1ucyhlKSkpLHRoaXMuX3Bh"
    "cnNlci5yZWdpc3RlckNzaUhhbmRsZXIoe2ludGVybWVkaWF0ZXM6JyInLGZpbmFsOiJxIn0sKGU9PnRoaXMuc2VsZWN0UHJvdGVjdGVkKGUpKSksdGhpcy5f"
    "cGFyc2VyLnJlZ2lzdGVyQ3NpSGFuZGxlcih7aW50ZXJtZWRpYXRlczoiJCIsZmluYWw6InAifSwoZT0+dGhpcy5yZXF1ZXN0TW9kZShlLCEwKSkpLHRoaXMu"
    "X3BhcnNlci5yZWdpc3RlckNzaUhhbmRsZXIoe3ByZWZpeDoiPyIsaW50ZXJtZWRpYXRlczoiJCIsZmluYWw6InAifSwoZT0+dGhpcy5yZXF1ZXN0TW9kZShl"
    "LCExKSkpLHRoaXMuX3BhcnNlci5zZXRFeGVjdXRlSGFuZGxlcihuLkMwLkJFTCwoKCk9PnRoaXMuYmVsbCgpKSksdGhpcy5fcGFyc2VyLnNldEV4ZWN1dGVI"
    "YW5kbGVyKG4uQzAuTEYsKCgpPT50aGlzLmxpbmVGZWVkKCkpKSx0aGlzLl9wYXJzZXIuc2V0RXhlY3V0ZUhhbmRsZXIobi5DMC5WVCwoKCk9PnRoaXMubGlu"
    "ZUZlZWQoKSkpLHRoaXMuX3BhcnNlci5zZXRFeGVjdXRlSGFuZGxlcihuLkMwLkZGLCgoKT0+dGhpcy5saW5lRmVlZCgpKSksdGhpcy5fcGFyc2VyLnNldEV4"
    "ZWN1dGVIYW5kbGVyKG4uQzAuQ1IsKCgpPT50aGlzLmNhcnJpYWdlUmV0dXJuKCkpKSx0aGlzLl9wYXJzZXIuc2V0RXhlY3V0ZUhhbmRsZXIobi5DMC5CUywo"
    "KCk9PnRoaXMuYmFja3NwYWNlKCkpKSx0aGlzLl9wYXJzZXIuc2V0RXhlY3V0ZUhhbmRsZXIobi5DMC5IVCwoKCk9PnRoaXMudGFiKCkpKSx0aGlzLl9wYXJz"
    "ZXIuc2V0RXhlY3V0ZUhhbmRsZXIobi5DMC5TTywoKCk9PnRoaXMuc2hpZnRPdXQoKSkpLHRoaXMuX3BhcnNlci5zZXRFeGVjdXRlSGFuZGxlcihuLkMwLlNJ"
    "LCgoKT0+dGhpcy5zaGlmdEluKCkpKSx0aGlzLl9wYXJzZXIuc2V0RXhlY3V0ZUhhbmRsZXIobi5DMS5JTkQsKCgpPT50aGlzLmluZGV4KCkpKSx0aGlzLl9w"
    "YXJzZXIuc2V0RXhlY3V0ZUhhbmRsZXIobi5DMS5ORUwsKCgpPT50aGlzLm5leHRMaW5lKCkpKSx0aGlzLl9wYXJzZXIuc2V0RXhlY3V0ZUhhbmRsZXIobi5D"
    "MS5IVFMsKCgpPT50aGlzLnRhYlNldCgpKSksdGhpcy5fcGFyc2VyLnJlZ2lzdGVyT3NjSGFuZGxlcigwLG5ldyBwLk9zY0hhbmRsZXIoKGU9Pih0aGlzLnNl"
    "dFRpdGxlKGUpLHRoaXMuc2V0SWNvbk5hbWUoZSksITApKSkpLHRoaXMuX3BhcnNlci5yZWdpc3Rlck9zY0hhbmRsZXIoMSxuZXcgcC5Pc2NIYW5kbGVyKChl"
    "PT50aGlzLnNldEljb25OYW1lKGUpKSkpLHRoaXMuX3BhcnNlci5yZWdpc3Rlck9zY0hhbmRsZXIoMixuZXcgcC5Pc2NIYW5kbGVyKChlPT50aGlzLnNldFRp"
    "dGxlKGUpKSkpLHRoaXMuX3BhcnNlci5yZWdpc3Rlck9zY0hhbmRsZXIoNCxuZXcgcC5Pc2NIYW5kbGVyKChlPT50aGlzLnNldE9yUmVwb3J0SW5kZXhlZENv"
    "bG9yKGUpKSkpLHRoaXMuX3BhcnNlci5yZWdpc3Rlck9zY0hhbmRsZXIoOCxuZXcgcC5Pc2NIYW5kbGVyKChlPT50aGlzLnNldEh5cGVybGluayhlKSkpKSx0"
    "aGlzLl9wYXJzZXIucmVnaXN0ZXJPc2NIYW5kbGVyKDEwLG5ldyBwLk9zY0hhbmRsZXIoKGU9PnRoaXMuc2V0T3JSZXBvcnRGZ0NvbG9yKGUpKSkpLHRoaXMu"
    "X3BhcnNlci5yZWdpc3Rlck9zY0hhbmRsZXIoMTEsbmV3IHAuT3NjSGFuZGxlcigoZT0+dGhpcy5zZXRPclJlcG9ydEJnQ29sb3IoZSkpKSksdGhpcy5fcGFy"
    "c2VyLnJlZ2lzdGVyT3NjSGFuZGxlcigxMixuZXcgcC5Pc2NIYW5kbGVyKChlPT50aGlzLnNldE9yUmVwb3J0Q3Vyc29yQ29sb3IoZSkpKSksdGhpcy5fcGFy"
    "c2VyLnJlZ2lzdGVyT3NjSGFuZGxlcigxMDQsbmV3IHAuT3NjSGFuZGxlcigoZT0+dGhpcy5yZXN0b3JlSW5kZXhlZENvbG9yKGUpKSkpLHRoaXMuX3BhcnNl"
    "ci5yZWdpc3Rlck9zY0hhbmRsZXIoMTEwLG5ldyBwLk9zY0hhbmRsZXIoKGU9PnRoaXMucmVzdG9yZUZnQ29sb3IoZSkpKSksdGhpcy5fcGFyc2VyLnJlZ2lz"
    "dGVyT3NjSGFuZGxlcigxMTEsbmV3IHAuT3NjSGFuZGxlcigoZT0+dGhpcy5yZXN0b3JlQmdDb2xvcihlKSkpKSx0aGlzLl9wYXJzZXIucmVnaXN0ZXJPc2NI"
    "YW5kbGVyKDExMixuZXcgcC5Pc2NIYW5kbGVyKChlPT50aGlzLnJlc3RvcmVDdXJzb3JDb2xvcihlKSkpKSx0aGlzLl9wYXJzZXIucmVnaXN0ZXJFc2NIYW5k"
    "bGVyKHtmaW5hbDoiNyJ9LCgoKT0+dGhpcy5zYXZlQ3Vyc29yKCkpKSx0aGlzLl9wYXJzZXIucmVnaXN0ZXJFc2NIYW5kbGVyKHtmaW5hbDoiOCJ9LCgoKT0+"
    "dGhpcy5yZXN0b3JlQ3Vyc29yKCkpKSx0aGlzLl9wYXJzZXIucmVnaXN0ZXJFc2NIYW5kbGVyKHtmaW5hbDoiRCJ9LCgoKT0+dGhpcy5pbmRleCgpKSksdGhp"
    "cy5fcGFyc2VyLnJlZ2lzdGVyRXNjSGFuZGxlcih7ZmluYWw6IkUifSwoKCk9PnRoaXMubmV4dExpbmUoKSkpLHRoaXMuX3BhcnNlci5yZWdpc3RlckVzY0hh"
    "bmRsZXIoe2ZpbmFsOiJIIn0sKCgpPT50aGlzLnRhYlNldCgpKSksdGhpcy5fcGFyc2VyLnJlZ2lzdGVyRXNjSGFuZGxlcih7ZmluYWw6Ik0ifSwoKCk9PnRo"
    "aXMucmV2ZXJzZUluZGV4KCkpKSx0aGlzLl9wYXJzZXIucmVnaXN0ZXJFc2NIYW5kbGVyKHtmaW5hbDoiPSJ9LCgoKT0+dGhpcy5rZXlwYWRBcHBsaWNhdGlv"
    "bk1vZGUoKSkpLHRoaXMuX3BhcnNlci5yZWdpc3RlckVzY0hhbmRsZXIoe2ZpbmFsOiI+In0sKCgpPT50aGlzLmtleXBhZE51bWVyaWNNb2RlKCkpKSx0aGlz"
    "Ll9wYXJzZXIucmVnaXN0ZXJFc2NIYW5kbGVyKHtmaW5hbDoiYyJ9LCgoKT0+dGhpcy5mdWxsUmVzZXQoKSkpLHRoaXMuX3BhcnNlci5yZWdpc3RlckVzY0hh"
    "bmRsZXIoe2ZpbmFsOiJuIn0sKCgpPT50aGlzLnNldGdMZXZlbCgyKSkpLHRoaXMuX3BhcnNlci5yZWdpc3RlckVzY0hhbmRsZXIoe2ZpbmFsOiJvIn0sKCgp"
    "PT50aGlzLnNldGdMZXZlbCgzKSkpLHRoaXMuX3BhcnNlci5yZWdpc3RlckVzY0hhbmRsZXIoe2ZpbmFsOiJ8In0sKCgpPT50aGlzLnNldGdMZXZlbCgzKSkp"
    "LHRoaXMuX3BhcnNlci5yZWdpc3RlckVzY0hhbmRsZXIoe2ZpbmFsOiJ9In0sKCgpPT50aGlzLnNldGdMZXZlbCgyKSkpLHRoaXMuX3BhcnNlci5yZWdpc3Rl"
    "ckVzY0hhbmRsZXIoe2ZpbmFsOiJ+In0sKCgpPT50aGlzLnNldGdMZXZlbCgxKSkpLHRoaXMuX3BhcnNlci5yZWdpc3RlckVzY0hhbmRsZXIoe2ludGVybWVk"
    "aWF0ZXM6IiUiLGZpbmFsOiJAIn0sKCgpPT50aGlzLnNlbGVjdERlZmF1bHRDaGFyc2V0KCkpKSx0aGlzLl9wYXJzZXIucmVnaXN0ZXJFc2NIYW5kbGVyKHtp"
    "bnRlcm1lZGlhdGVzOiIlIixmaW5hbDoiRyJ9LCgoKT0+dGhpcy5zZWxlY3REZWZhdWx0Q2hhcnNldCgpKSk7Zm9yKGNvbnN0IGUgaW4gby5DSEFSU0VUUyl0"
    "aGlzLl9wYXJzZXIucmVnaXN0ZXJFc2NIYW5kbGVyKHtpbnRlcm1lZGlhdGVzOiIoIixmaW5hbDplfSwoKCk9PnRoaXMuc2VsZWN0Q2hhcnNldCgiKCIrZSkp"
    "KSx0aGlzLl9wYXJzZXIucmVnaXN0ZXJFc2NIYW5kbGVyKHtpbnRlcm1lZGlhdGVzOiIpIixmaW5hbDplfSwoKCk9PnRoaXMuc2VsZWN0Q2hhcnNldCgiKSIr"
    "ZSkpKSx0aGlzLl9wYXJzZXIucmVnaXN0ZXJFc2NIYW5kbGVyKHtpbnRlcm1lZGlhdGVzOiIqIixmaW5hbDplfSwoKCk9PnRoaXMuc2VsZWN0Q2hhcnNldCgi"
    "KiIrZSkpKSx0aGlzLl9wYXJzZXIucmVnaXN0ZXJFc2NIYW5kbGVyKHtpbnRlcm1lZGlhdGVzOiIrIixmaW5hbDplfSwoKCk9PnRoaXMuc2VsZWN0Q2hhcnNl"
    "dCgiKyIrZSkpKSx0aGlzLl9wYXJzZXIucmVnaXN0ZXJFc2NIYW5kbGVyKHtpbnRlcm1lZGlhdGVzOiItIixmaW5hbDplfSwoKCk9PnRoaXMuc2VsZWN0Q2hh"
    "cnNldCgiLSIrZSkpKSx0aGlzLl9wYXJzZXIucmVnaXN0ZXJFc2NIYW5kbGVyKHtpbnRlcm1lZGlhdGVzOiIuIixmaW5hbDplfSwoKCk9PnRoaXMuc2VsZWN0"
    "Q2hhcnNldCgiLiIrZSkpKSx0aGlzLl9wYXJzZXIucmVnaXN0ZXJFc2NIYW5kbGVyKHtpbnRlcm1lZGlhdGVzOiIvIixmaW5hbDplfSwoKCk9PnRoaXMuc2Vs"
    "ZWN0Q2hhcnNldCgiLyIrZSkpKTt0aGlzLl9wYXJzZXIucmVnaXN0ZXJFc2NIYW5kbGVyKHtpbnRlcm1lZGlhdGVzOiIjIixmaW5hbDoiOCJ9LCgoKT0+dGhp"
    "cy5zY3JlZW5BbGlnbm1lbnRQYXR0ZXJuKCkpKSx0aGlzLl9wYXJzZXIuc2V0RXJyb3JIYW5kbGVyKChlPT4odGhpcy5fbG9nU2VydmljZS5lcnJvcigiUGFy"
    "c2luZyBlcnJvcjogIixlKSxlKSkpLHRoaXMuX3BhcnNlci5yZWdpc3RlckRjc0hhbmRsZXIoe2ludGVybWVkaWF0ZXM6IiQiLGZpbmFsOiJxIn0sbmV3IGcu"
    "RGNzSGFuZGxlcigoKGUsdCk9PnRoaXMucmVxdWVzdFN0YXR1c1N0cmluZyhlLHQpKSkpfV9wcmVzZXJ2ZVN0YWNrKGUsdCxpLHMpe3RoaXMuX3BhcnNlU3Rh"
    "Y2sucGF1c2VkPSEwLHRoaXMuX3BhcnNlU3RhY2suY3Vyc29yU3RhcnRYPWUsdGhpcy5fcGFyc2VTdGFjay5jdXJzb3JTdGFydFk9dCx0aGlzLl9wYXJzZVN0"
    "YWNrLmRlY29kZWRMZW5ndGg9aSx0aGlzLl9wYXJzZVN0YWNrLnBvc2l0aW9uPXN9X2xvZ1Nsb3dSZXNvbHZpbmdBc3luYyhlKXt0aGlzLl9sb2dTZXJ2aWNl"
    "LmxvZ0xldmVsPD12LkxvZ0xldmVsRW51bS5XQVJOJiZQcm9taXNlLnJhY2UoW2UsbmV3IFByb21pc2UoKChlLHQpPT5zZXRUaW1lb3V0KCgoKT0+dCgiI1NM"
    "T1dfVElNRU9VVCIpKSw1ZTMpKSldKS5jYXRjaCgoZT0+e2lmKCIjU0xPV19USU1FT1VUIiE9PWUpdGhyb3cgZTtjb25zb2xlLndhcm4oImFzeW5jIHBhcnNl"
    "ciBoYW5kbGVyIHRha2luZyBsb25nZXIgdGhhbiA1MDAwIG1zIil9KSl9X2dldEN1cnJlbnRMaW5rSWQoKXtyZXR1cm4gdGhpcy5fY3VyQXR0ckRhdGEuZXh0"
    "ZW5kZWQudXJsSWR9cGFyc2UoZSx0KXtsZXQgaSxzPXRoaXMuX2FjdGl2ZUJ1ZmZlci54LHI9dGhpcy5fYWN0aXZlQnVmZmVyLnksbj0wO2NvbnN0IG89dGhp"
    "cy5fcGFyc2VTdGFjay5wYXVzZWQ7aWYobyl7aWYoaT10aGlzLl9wYXJzZXIucGFyc2UodGhpcy5fcGFyc2VCdWZmZXIsdGhpcy5fcGFyc2VTdGFjay5kZWNv"
    "ZGVkTGVuZ3RoLHQpKXJldHVybiB0aGlzLl9sb2dTbG93UmVzb2x2aW5nQXN5bmMoaSksaTtzPXRoaXMuX3BhcnNlU3RhY2suY3Vyc29yU3RhcnRYLHI9dGhp"
    "cy5fcGFyc2VTdGFjay5jdXJzb3JTdGFydFksdGhpcy5fcGFyc2VTdGFjay5wYXVzZWQ9ITEsZS5sZW5ndGg+QyYmKG49dGhpcy5fcGFyc2VTdGFjay5wb3Np"
    "dGlvbitDKX1pZih0aGlzLl9sb2dTZXJ2aWNlLmxvZ0xldmVsPD12LkxvZ0xldmVsRW51bS5ERUJVRyYmdGhpcy5fbG9nU2VydmljZS5kZWJ1ZygicGFyc2lu"
    "ZyBkYXRhIisoInN0cmluZyI9PXR5cGVvZiBlP2AgIiR7ZX0iYDpgICIke0FycmF5LnByb3RvdHlwZS5tYXAuY2FsbChlLChlPT5TdHJpbmcuZnJvbUNoYXJD"
    "b2RlKGUpKSkuam9pbigiIil9ImApLCJzdHJpbmciPT10eXBlb2YgZT9lLnNwbGl0KCIiKS5tYXAoKGU9PmUuY2hhckNvZGVBdCgwKSkpOmUpLHRoaXMuX3Bh"
    "cnNlQnVmZmVyLmxlbmd0aDxlLmxlbmd0aCYmdGhpcy5fcGFyc2VCdWZmZXIubGVuZ3RoPEMmJih0aGlzLl9wYXJzZUJ1ZmZlcj1uZXcgVWludDMyQXJyYXko"
    "TWF0aC5taW4oZS5sZW5ndGgsQykpKSxvfHx0aGlzLl9kaXJ0eVJvd1RyYWNrZXIuY2xlYXJSYW5nZSgpLGUubGVuZ3RoPkMpZm9yKGxldCB0PW47dDxlLmxl"
    "bmd0aDt0Kz1DKXtjb25zdCBuPXQrQzxlLmxlbmd0aD90K0M6ZS5sZW5ndGgsbz0ic3RyaW5nIj09dHlwZW9mIGU/dGhpcy5fc3RyaW5nRGVjb2Rlci5kZWNv"
    "ZGUoZS5zdWJzdHJpbmcodCxuKSx0aGlzLl9wYXJzZUJ1ZmZlcik6dGhpcy5fdXRmOERlY29kZXIuZGVjb2RlKGUuc3ViYXJyYXkodCxuKSx0aGlzLl9wYXJz"
    "ZUJ1ZmZlcik7aWYoaT10aGlzLl9wYXJzZXIucGFyc2UodGhpcy5fcGFyc2VCdWZmZXIsbykpcmV0dXJuIHRoaXMuX3ByZXNlcnZlU3RhY2socyxyLG8sdCks"
    "dGhpcy5fbG9nU2xvd1Jlc29sdmluZ0FzeW5jKGkpLGl9ZWxzZSBpZighbyl7Y29uc3QgdD0ic3RyaW5nIj09dHlwZW9mIGU/dGhpcy5fc3RyaW5nRGVjb2Rl"
    "ci5kZWNvZGUoZSx0aGlzLl9wYXJzZUJ1ZmZlcik6dGhpcy5fdXRmOERlY29kZXIuZGVjb2RlKGUsdGhpcy5fcGFyc2VCdWZmZXIpO2lmKGk9dGhpcy5fcGFy"
    "c2VyLnBhcnNlKHRoaXMuX3BhcnNlQnVmZmVyLHQpKXJldHVybiB0aGlzLl9wcmVzZXJ2ZVN0YWNrKHMscix0LDApLHRoaXMuX2xvZ1Nsb3dSZXNvbHZpbmdB"
    "c3luYyhpKSxpfXRoaXMuX2FjdGl2ZUJ1ZmZlci54PT09cyYmdGhpcy5fYWN0aXZlQnVmZmVyLnk9PT1yfHx0aGlzLl9vbkN1cnNvck1vdmUuZmlyZSgpLHRo"
    "aXMuX29uUmVxdWVzdFJlZnJlc2hSb3dzLmZpcmUodGhpcy5fZGlydHlSb3dUcmFja2VyLnN0YXJ0LHRoaXMuX2RpcnR5Um93VHJhY2tlci5lbmQpfXByaW50"
    "KGUsdCxpKXtsZXQgcyxyO2NvbnN0IG49dGhpcy5fY2hhcnNldFNlcnZpY2UuY2hhcnNldCxvPXRoaXMuX29wdGlvbnNTZXJ2aWNlLnJhd09wdGlvbnMuc2Ny"
    "ZWVuUmVhZGVyTW9kZSxhPXRoaXMuX2J1ZmZlclNlcnZpY2UuY29scyxoPXRoaXMuX2NvcmVTZXJ2aWNlLmRlY1ByaXZhdGVNb2Rlcy53cmFwYXJvdW5kLGw9"
    "dGhpcy5fY29yZVNlcnZpY2UubW9kZXMuaW5zZXJ0TW9kZSxkPXRoaXMuX2N1ckF0dHJEYXRhO2xldCB1PXRoaXMuX2FjdGl2ZUJ1ZmZlci5saW5lcy5nZXQo"
    "dGhpcy5fYWN0aXZlQnVmZmVyLnliYXNlK3RoaXMuX2FjdGl2ZUJ1ZmZlci55KTt0aGlzLl9kaXJ0eVJvd1RyYWNrZXIubWFya0RpcnR5KHRoaXMuX2FjdGl2"
    "ZUJ1ZmZlci55KSx0aGlzLl9hY3RpdmVCdWZmZXIueCYmaS10PjAmJjI9PT11LmdldFdpZHRoKHRoaXMuX2FjdGl2ZUJ1ZmZlci54LTEpJiZ1LnNldENlbGxG"
    "cm9tQ29kZVBvaW50KHRoaXMuX2FjdGl2ZUJ1ZmZlci54LTEsMCwxLGQuZmcsZC5iZyxkLmV4dGVuZGVkKTtmb3IobGV0IGY9dDtmPGk7KytmKXtpZihzPWVb"
    "Zl0scj10aGlzLl91bmljb2RlU2VydmljZS53Y3dpZHRoKHMpLHM8MTI3JiZuKXtjb25zdCBlPW5bU3RyaW5nLmZyb21DaGFyQ29kZShzKV07ZSYmKHM9ZS5j"
    "aGFyQ29kZUF0KDApKX1pZihvJiZ0aGlzLl9vbkExMXlDaGFyLmZpcmUoKDAsYy5zdHJpbmdGcm9tQ29kZVBvaW50KShzKSksdGhpcy5fZ2V0Q3VycmVudExp"
    "bmtJZCgpJiZ0aGlzLl9vc2NMaW5rU2VydmljZS5hZGRMaW5lVG9MaW5rKHRoaXMuX2dldEN1cnJlbnRMaW5rSWQoKSx0aGlzLl9hY3RpdmVCdWZmZXIueWJh"
    "c2UrdGhpcy5fYWN0aXZlQnVmZmVyLnkpLHJ8fCF0aGlzLl9hY3RpdmVCdWZmZXIueCl7aWYodGhpcy5fYWN0aXZlQnVmZmVyLngrci0xPj1hKWlmKGgpe2Zv"
    "cig7dGhpcy5fYWN0aXZlQnVmZmVyLng8YTspdS5zZXRDZWxsRnJvbUNvZGVQb2ludCh0aGlzLl9hY3RpdmVCdWZmZXIueCsrLDAsMSxkLmZnLGQuYmcsZC5l"
    "eHRlbmRlZCk7dGhpcy5fYWN0aXZlQnVmZmVyLng9MCx0aGlzLl9hY3RpdmVCdWZmZXIueSsrLHRoaXMuX2FjdGl2ZUJ1ZmZlci55PT09dGhpcy5fYWN0aXZl"
    "QnVmZmVyLnNjcm9sbEJvdHRvbSsxPyh0aGlzLl9hY3RpdmVCdWZmZXIueS0tLHRoaXMuX2J1ZmZlclNlcnZpY2Uuc2Nyb2xsKHRoaXMuX2VyYXNlQXR0ckRh"
    "dGEoKSwhMCkpOih0aGlzLl9hY3RpdmVCdWZmZXIueT49dGhpcy5fYnVmZmVyU2VydmljZS5yb3dzJiYodGhpcy5fYWN0aXZlQnVmZmVyLnk9dGhpcy5fYnVm"
    "ZmVyU2VydmljZS5yb3dzLTEpLHRoaXMuX2FjdGl2ZUJ1ZmZlci5saW5lcy5nZXQodGhpcy5fYWN0aXZlQnVmZmVyLnliYXNlK3RoaXMuX2FjdGl2ZUJ1ZmZl"
    "ci55KS5pc1dyYXBwZWQ9ITApLHU9dGhpcy5fYWN0aXZlQnVmZmVyLmxpbmVzLmdldCh0aGlzLl9hY3RpdmVCdWZmZXIueWJhc2UrdGhpcy5fYWN0aXZlQnVm"
    "ZmVyLnkpfWVsc2UgaWYodGhpcy5fYWN0aXZlQnVmZmVyLng9YS0xLDI9PT1yKWNvbnRpbnVlO2lmKGwmJih1Lmluc2VydENlbGxzKHRoaXMuX2FjdGl2ZUJ1"
    "ZmZlci54LHIsdGhpcy5fYWN0aXZlQnVmZmVyLmdldE51bGxDZWxsKGQpLGQpLDI9PT11LmdldFdpZHRoKGEtMSkmJnUuc2V0Q2VsbEZyb21Db2RlUG9pbnQo"
    "YS0xLF8uTlVMTF9DRUxMX0NPREUsXy5OVUxMX0NFTExfV0lEVEgsZC5mZyxkLmJnLGQuZXh0ZW5kZWQpKSx1LnNldENlbGxGcm9tQ29kZVBvaW50KHRoaXMu"
    "X2FjdGl2ZUJ1ZmZlci54KysscyxyLGQuZmcsZC5iZyxkLmV4dGVuZGVkKSxyPjApZm9yKDstLXI7KXUuc2V0Q2VsbEZyb21Db2RlUG9pbnQodGhpcy5fYWN0"
    "aXZlQnVmZmVyLngrKywwLDAsZC5mZyxkLmJnLGQuZXh0ZW5kZWQpfWVsc2UgdS5nZXRXaWR0aCh0aGlzLl9hY3RpdmVCdWZmZXIueC0xKT91LmFkZENvZGVw"
    "b2ludFRvQ2VsbCh0aGlzLl9hY3RpdmVCdWZmZXIueC0xLHMpOnUuYWRkQ29kZXBvaW50VG9DZWxsKHRoaXMuX2FjdGl2ZUJ1ZmZlci54LTIscyl9aS10PjAm"
    "Jih1LmxvYWRDZWxsKHRoaXMuX2FjdGl2ZUJ1ZmZlci54LTEsdGhpcy5fd29ya0NlbGwpLDI9PT10aGlzLl93b3JrQ2VsbC5nZXRXaWR0aCgpfHx0aGlzLl93"
    "b3JrQ2VsbC5nZXRDb2RlKCk+NjU1MzU/dGhpcy5fcGFyc2VyLnByZWNlZGluZ0NvZGVwb2ludD0wOnRoaXMuX3dvcmtDZWxsLmlzQ29tYmluZWQoKT90aGlz"
    "Ll9wYXJzZXIucHJlY2VkaW5nQ29kZXBvaW50PXRoaXMuX3dvcmtDZWxsLmdldENoYXJzKCkuY2hhckNvZGVBdCgwKTp0aGlzLl9wYXJzZXIucHJlY2VkaW5n"
    "Q29kZXBvaW50PXRoaXMuX3dvcmtDZWxsLmNvbnRlbnQpLHRoaXMuX2FjdGl2ZUJ1ZmZlci54PGEmJmktdD4wJiYwPT09dS5nZXRXaWR0aCh0aGlzLl9hY3Rp"
    "dmVCdWZmZXIueCkmJiF1Lmhhc0NvbnRlbnQodGhpcy5fYWN0aXZlQnVmZmVyLngpJiZ1LnNldENlbGxGcm9tQ29kZVBvaW50KHRoaXMuX2FjdGl2ZUJ1ZmZl"
    "ci54LDAsMSxkLmZnLGQuYmcsZC5leHRlbmRlZCksdGhpcy5fZGlydHlSb3dUcmFja2VyLm1hcmtEaXJ0eSh0aGlzLl9hY3RpdmVCdWZmZXIueSl9cmVnaXN0"
    "ZXJDc2lIYW5kbGVyKGUsdCl7cmV0dXJuInQiIT09ZS5maW5hbHx8ZS5wcmVmaXh8fGUuaW50ZXJtZWRpYXRlcz90aGlzLl9wYXJzZXIucmVnaXN0ZXJDc2lI"
    "YW5kbGVyKGUsdCk6dGhpcy5fcGFyc2VyLnJlZ2lzdGVyQ3NpSGFuZGxlcihlLChlPT4hYihlLnBhcmFtc1swXSx0aGlzLl9vcHRpb25zU2VydmljZS5yYXdP"
    "cHRpb25zLndpbmRvd09wdGlvbnMpfHx0KGUpKSl9cmVnaXN0ZXJEY3NIYW5kbGVyKGUsdCl7cmV0dXJuIHRoaXMuX3BhcnNlci5yZWdpc3RlckRjc0hhbmRs"
    "ZXIoZSxuZXcgZy5EY3NIYW5kbGVyKHQpKX1yZWdpc3RlckVzY0hhbmRsZXIoZSx0KXtyZXR1cm4gdGhpcy5fcGFyc2VyLnJlZ2lzdGVyRXNjSGFuZGxlcihl"
    "LHQpfXJlZ2lzdGVyT3NjSGFuZGxlcihlLHQpe3JldHVybiB0aGlzLl9wYXJzZXIucmVnaXN0ZXJPc2NIYW5kbGVyKGUsbmV3IHAuT3NjSGFuZGxlcih0KSl9"
    "YmVsbCgpe3JldHVybiB0aGlzLl9vblJlcXVlc3RCZWxsLmZpcmUoKSwhMH1saW5lRmVlZCgpe3JldHVybiB0aGlzLl9kaXJ0eVJvd1RyYWNrZXIubWFya0Rp"
    "cnR5KHRoaXMuX2FjdGl2ZUJ1ZmZlci55KSx0aGlzLl9vcHRpb25zU2VydmljZS5yYXdPcHRpb25zLmNvbnZlcnRFb2wmJih0aGlzLl9hY3RpdmVCdWZmZXIu"
    "eD0wKSx0aGlzLl9hY3RpdmVCdWZmZXIueSsrLHRoaXMuX2FjdGl2ZUJ1ZmZlci55PT09dGhpcy5fYWN0aXZlQnVmZmVyLnNjcm9sbEJvdHRvbSsxPyh0aGlz"
    "Ll9hY3RpdmVCdWZmZXIueS0tLHRoaXMuX2J1ZmZlclNlcnZpY2Uuc2Nyb2xsKHRoaXMuX2VyYXNlQXR0ckRhdGEoKSkpOnRoaXMuX2FjdGl2ZUJ1ZmZlci55"
    "Pj10aGlzLl9idWZmZXJTZXJ2aWNlLnJvd3M/dGhpcy5fYWN0aXZlQnVmZmVyLnk9dGhpcy5fYnVmZmVyU2VydmljZS5yb3dzLTE6dGhpcy5fYWN0aXZlQnVm"
    "ZmVyLmxpbmVzLmdldCh0aGlzLl9hY3RpdmVCdWZmZXIueWJhc2UrdGhpcy5fYWN0aXZlQnVmZmVyLnkpLmlzV3JhcHBlZD0hMSx0aGlzLl9hY3RpdmVCdWZm"
    "ZXIueD49dGhpcy5fYnVmZmVyU2VydmljZS5jb2xzJiZ0aGlzLl9hY3RpdmVCdWZmZXIueC0tLHRoaXMuX2RpcnR5Um93VHJhY2tlci5tYXJrRGlydHkodGhp"
    "cy5fYWN0aXZlQnVmZmVyLnkpLHRoaXMuX29uTGluZUZlZWQuZmlyZSgpLCEwfWNhcnJpYWdlUmV0dXJuKCl7cmV0dXJuIHRoaXMuX2FjdGl2ZUJ1ZmZlci54"
    "PTAsITB9YmFja3NwYWNlKCl7dmFyIGU7aWYoIXRoaXMuX2NvcmVTZXJ2aWNlLmRlY1ByaXZhdGVNb2Rlcy5yZXZlcnNlV3JhcGFyb3VuZClyZXR1cm4gdGhp"
    "cy5fcmVzdHJpY3RDdXJzb3IoKSx0aGlzLl9hY3RpdmVCdWZmZXIueD4wJiZ0aGlzLl9hY3RpdmVCdWZmZXIueC0tLCEwO2lmKHRoaXMuX3Jlc3RyaWN0Q3Vy"
    "c29yKHRoaXMuX2J1ZmZlclNlcnZpY2UuY29scyksdGhpcy5fYWN0aXZlQnVmZmVyLng+MCl0aGlzLl9hY3RpdmVCdWZmZXIueC0tO2Vsc2UgaWYoMD09PXRo"
    "aXMuX2FjdGl2ZUJ1ZmZlci54JiZ0aGlzLl9hY3RpdmVCdWZmZXIueT50aGlzLl9hY3RpdmVCdWZmZXIuc2Nyb2xsVG9wJiZ0aGlzLl9hY3RpdmVCdWZmZXIu"
    "eTw9dGhpcy5fYWN0aXZlQnVmZmVyLnNjcm9sbEJvdHRvbSYmKG51bGw9PT0oZT10aGlzLl9hY3RpdmVCdWZmZXIubGluZXMuZ2V0KHRoaXMuX2FjdGl2ZUJ1"
    "ZmZlci55YmFzZSt0aGlzLl9hY3RpdmVCdWZmZXIueSkpfHx2b2lkIDA9PT1lP3ZvaWQgMDplLmlzV3JhcHBlZCkpe3RoaXMuX2FjdGl2ZUJ1ZmZlci5saW5l"
    "cy5nZXQodGhpcy5fYWN0aXZlQnVmZmVyLnliYXNlK3RoaXMuX2FjdGl2ZUJ1ZmZlci55KS5pc1dyYXBwZWQ9ITEsdGhpcy5fYWN0aXZlQnVmZmVyLnktLSx0"
    "aGlzLl9hY3RpdmVCdWZmZXIueD10aGlzLl9idWZmZXJTZXJ2aWNlLmNvbHMtMTtjb25zdCBlPXRoaXMuX2FjdGl2ZUJ1ZmZlci5saW5lcy5nZXQodGhpcy5f"
    "YWN0aXZlQnVmZmVyLnliYXNlK3RoaXMuX2FjdGl2ZUJ1ZmZlci55KTtlLmhhc1dpZHRoKHRoaXMuX2FjdGl2ZUJ1ZmZlci54KSYmIWUuaGFzQ29udGVudCh0"
    "aGlzLl9hY3RpdmVCdWZmZXIueCkmJnRoaXMuX2FjdGl2ZUJ1ZmZlci54LS19cmV0dXJuIHRoaXMuX3Jlc3RyaWN0Q3Vyc29yKCksITB9dGFiKCl7aWYodGhp"
    "cy5fYWN0aXZlQnVmZmVyLng+PXRoaXMuX2J1ZmZlclNlcnZpY2UuY29scylyZXR1cm4hMDtjb25zdCBlPXRoaXMuX2FjdGl2ZUJ1ZmZlci54O3JldHVybiB0"
    "aGlzLl9hY3RpdmVCdWZmZXIueD10aGlzLl9hY3RpdmVCdWZmZXIubmV4dFN0b3AoKSx0aGlzLl9vcHRpb25zU2VydmljZS5yYXdPcHRpb25zLnNjcmVlblJl"
    "YWRlck1vZGUmJnRoaXMuX29uQTExeVRhYi5maXJlKHRoaXMuX2FjdGl2ZUJ1ZmZlci54LWUpLCEwfXNoaWZ0T3V0KCl7cmV0dXJuIHRoaXMuX2NoYXJzZXRT"
    "ZXJ2aWNlLnNldGdMZXZlbCgxKSwhMH1zaGlmdEluKCl7cmV0dXJuIHRoaXMuX2NoYXJzZXRTZXJ2aWNlLnNldGdMZXZlbCgwKSwhMH1fcmVzdHJpY3RDdXJz"
    "b3IoZT10aGlzLl9idWZmZXJTZXJ2aWNlLmNvbHMtMSl7dGhpcy5fYWN0aXZlQnVmZmVyLng9TWF0aC5taW4oZSxNYXRoLm1heCgwLHRoaXMuX2FjdGl2ZUJ1"
    "ZmZlci54KSksdGhpcy5fYWN0aXZlQnVmZmVyLnk9dGhpcy5fY29yZVNlcnZpY2UuZGVjUHJpdmF0ZU1vZGVzLm9yaWdpbj9NYXRoLm1pbih0aGlzLl9hY3Rp"
    "dmVCdWZmZXIuc2Nyb2xsQm90dG9tLE1hdGgubWF4KHRoaXMuX2FjdGl2ZUJ1ZmZlci5zY3JvbGxUb3AsdGhpcy5fYWN0aXZlQnVmZmVyLnkpKTpNYXRoLm1p"
    "bih0aGlzLl9idWZmZXJTZXJ2aWNlLnJvd3MtMSxNYXRoLm1heCgwLHRoaXMuX2FjdGl2ZUJ1ZmZlci55KSksdGhpcy5fZGlydHlSb3dUcmFja2VyLm1hcmtE"
    "aXJ0eSh0aGlzLl9hY3RpdmVCdWZmZXIueSl9X3NldEN1cnNvcihlLHQpe3RoaXMuX2RpcnR5Um93VHJhY2tlci5tYXJrRGlydHkodGhpcy5fYWN0aXZlQnVm"
    "ZmVyLnkpLHRoaXMuX2NvcmVTZXJ2aWNlLmRlY1ByaXZhdGVNb2Rlcy5vcmlnaW4/KHRoaXMuX2FjdGl2ZUJ1ZmZlci54PWUsdGhpcy5fYWN0aXZlQnVmZmVy"
    "Lnk9dGhpcy5fYWN0aXZlQnVmZmVyLnNjcm9sbFRvcCt0KToodGhpcy5fYWN0aXZlQnVmZmVyLng9ZSx0aGlzLl9hY3RpdmVCdWZmZXIueT10KSx0aGlzLl9y"
    "ZXN0cmljdEN1cnNvcigpLHRoaXMuX2RpcnR5Um93VHJhY2tlci5tYXJrRGlydHkodGhpcy5fYWN0aXZlQnVmZmVyLnkpfV9tb3ZlQ3Vyc29yKGUsdCl7dGhp"
    "cy5fcmVzdHJpY3RDdXJzb3IoKSx0aGlzLl9zZXRDdXJzb3IodGhpcy5fYWN0aXZlQnVmZmVyLngrZSx0aGlzLl9hY3RpdmVCdWZmZXIueSt0KX1jdXJzb3JV"
    "cChlKXtjb25zdCB0PXRoaXMuX2FjdGl2ZUJ1ZmZlci55LXRoaXMuX2FjdGl2ZUJ1ZmZlci5zY3JvbGxUb3A7cmV0dXJuIHQ+PTA/dGhpcy5fbW92ZUN1cnNv"
    "cigwLC1NYXRoLm1pbih0LGUucGFyYW1zWzBdfHwxKSk6dGhpcy5fbW92ZUN1cnNvcigwLC0oZS5wYXJhbXNbMF18fDEpKSwhMH1jdXJzb3JEb3duKGUpe2Nv"
    "bnN0IHQ9dGhpcy5fYWN0aXZlQnVmZmVyLnNjcm9sbEJvdHRvbS10aGlzLl9hY3RpdmVCdWZmZXIueTtyZXR1cm4gdD49MD90aGlzLl9tb3ZlQ3Vyc29yKDAs"
    "TWF0aC5taW4odCxlLnBhcmFtc1swXXx8MSkpOnRoaXMuX21vdmVDdXJzb3IoMCxlLnBhcmFtc1swXXx8MSksITB9Y3Vyc29yRm9yd2FyZChlKXtyZXR1cm4g"
    "dGhpcy5fbW92ZUN1cnNvcihlLnBhcmFtc1swXXx8MSwwKSwhMH1jdXJzb3JCYWNrd2FyZChlKXtyZXR1cm4gdGhpcy5fbW92ZUN1cnNvcigtKGUucGFyYW1z"
    "WzBdfHwxKSwwKSwhMH1jdXJzb3JOZXh0TGluZShlKXtyZXR1cm4gdGhpcy5jdXJzb3JEb3duKGUpLHRoaXMuX2FjdGl2ZUJ1ZmZlci54PTAsITB9Y3Vyc29y"
    "UHJlY2VkaW5nTGluZShlKXtyZXR1cm4gdGhpcy5jdXJzb3JVcChlKSx0aGlzLl9hY3RpdmVCdWZmZXIueD0wLCEwfWN1cnNvckNoYXJBYnNvbHV0ZShlKXty"
    "ZXR1cm4gdGhpcy5fc2V0Q3Vyc29yKChlLnBhcmFtc1swXXx8MSktMSx0aGlzLl9hY3RpdmVCdWZmZXIueSksITB9Y3Vyc29yUG9zaXRpb24oZSl7cmV0dXJu"
    "IHRoaXMuX3NldEN1cnNvcihlLmxlbmd0aD49Mj8oZS5wYXJhbXNbMV18fDEpLTE6MCwoZS5wYXJhbXNbMF18fDEpLTEpLCEwfWNoYXJQb3NBYnNvbHV0ZShl"
    "KXtyZXR1cm4gdGhpcy5fc2V0Q3Vyc29yKChlLnBhcmFtc1swXXx8MSktMSx0aGlzLl9hY3RpdmVCdWZmZXIueSksITB9aFBvc2l0aW9uUmVsYXRpdmUoZSl7"
    "cmV0dXJuIHRoaXMuX21vdmVDdXJzb3IoZS5wYXJhbXNbMF18fDEsMCksITB9bGluZVBvc0Fic29sdXRlKGUpe3JldHVybiB0aGlzLl9zZXRDdXJzb3IodGhp"
    "cy5fYWN0aXZlQnVmZmVyLngsKGUucGFyYW1zWzBdfHwxKS0xKSwhMH12UG9zaXRpb25SZWxhdGl2ZShlKXtyZXR1cm4gdGhpcy5fbW92ZUN1cnNvcigwLGUu"
    "cGFyYW1zWzBdfHwxKSwhMH1oVlBvc2l0aW9uKGUpe3JldHVybiB0aGlzLmN1cnNvclBvc2l0aW9uKGUpLCEwfXRhYkNsZWFyKGUpe2NvbnN0IHQ9ZS5wYXJh"
    "bXNbMF07cmV0dXJuIDA9PT10P2RlbGV0ZSB0aGlzLl9hY3RpdmVCdWZmZXIudGFic1t0aGlzLl9hY3RpdmVCdWZmZXIueF06Mz09PXQmJih0aGlzLl9hY3Rp"
    "dmVCdWZmZXIudGFicz17fSksITB9Y3Vyc29yRm9yd2FyZFRhYihlKXtpZih0aGlzLl9hY3RpdmVCdWZmZXIueD49dGhpcy5fYnVmZmVyU2VydmljZS5jb2xz"
    "KXJldHVybiEwO2xldCB0PWUucGFyYW1zWzBdfHwxO2Zvcig7dC0tOyl0aGlzLl9hY3RpdmVCdWZmZXIueD10aGlzLl9hY3RpdmVCdWZmZXIubmV4dFN0b3Ao"
    "KTtyZXR1cm4hMH1jdXJzb3JCYWNrd2FyZFRhYihlKXtpZih0aGlzLl9hY3RpdmVCdWZmZXIueD49dGhpcy5fYnVmZmVyU2VydmljZS5jb2xzKXJldHVybiEw"
    "O2xldCB0PWUucGFyYW1zWzBdfHwxO2Zvcig7dC0tOyl0aGlzLl9hY3RpdmVCdWZmZXIueD10aGlzLl9hY3RpdmVCdWZmZXIucHJldlN0b3AoKTtyZXR1cm4h"
    "MH1zZWxlY3RQcm90ZWN0ZWQoZSl7Y29uc3QgdD1lLnBhcmFtc1swXTtyZXR1cm4gMT09PXQmJih0aGlzLl9jdXJBdHRyRGF0YS5iZ3w9NTM2ODcwOTEyKSwy"
    "IT09dCYmMCE9PXR8fCh0aGlzLl9jdXJBdHRyRGF0YS5iZyY9LTUzNjg3MDkxMyksITB9X2VyYXNlSW5CdWZmZXJMaW5lKGUsdCxpLHM9ITEscj0hMSl7Y29u"
    "c3Qgbj10aGlzLl9hY3RpdmVCdWZmZXIubGluZXMuZ2V0KHRoaXMuX2FjdGl2ZUJ1ZmZlci55YmFzZStlKTtuLnJlcGxhY2VDZWxscyh0LGksdGhpcy5fYWN0"
    "aXZlQnVmZmVyLmdldE51bGxDZWxsKHRoaXMuX2VyYXNlQXR0ckRhdGEoKSksdGhpcy5fZXJhc2VBdHRyRGF0YSgpLHIpLHMmJihuLmlzV3JhcHBlZD0hMSl9"
    "X3Jlc2V0QnVmZmVyTGluZShlLHQ9ITEpe2NvbnN0IGk9dGhpcy5fYWN0aXZlQnVmZmVyLmxpbmVzLmdldCh0aGlzLl9hY3RpdmVCdWZmZXIueWJhc2UrZSk7"
    "aSYmKGkuZmlsbCh0aGlzLl9hY3RpdmVCdWZmZXIuZ2V0TnVsbENlbGwodGhpcy5fZXJhc2VBdHRyRGF0YSgpKSx0KSx0aGlzLl9idWZmZXJTZXJ2aWNlLmJ1"
    "ZmZlci5jbGVhck1hcmtlcnModGhpcy5fYWN0aXZlQnVmZmVyLnliYXNlK2UpLGkuaXNXcmFwcGVkPSExKX1lcmFzZUluRGlzcGxheShlLHQ9ITEpe2xldCBp"
    "O3N3aXRjaCh0aGlzLl9yZXN0cmljdEN1cnNvcih0aGlzLl9idWZmZXJTZXJ2aWNlLmNvbHMpLGUucGFyYW1zWzBdKXtjYXNlIDA6Zm9yKGk9dGhpcy5fYWN0"
    "aXZlQnVmZmVyLnksdGhpcy5fZGlydHlSb3dUcmFja2VyLm1hcmtEaXJ0eShpKSx0aGlzLl9lcmFzZUluQnVmZmVyTGluZShpKyssdGhpcy5fYWN0aXZlQnVm"
    "ZmVyLngsdGhpcy5fYnVmZmVyU2VydmljZS5jb2xzLDA9PT10aGlzLl9hY3RpdmVCdWZmZXIueCx0KTtpPHRoaXMuX2J1ZmZlclNlcnZpY2Uucm93cztpKysp"
    "dGhpcy5fcmVzZXRCdWZmZXJMaW5lKGksdCk7dGhpcy5fZGlydHlSb3dUcmFja2VyLm1hcmtEaXJ0eShpKTticmVhaztjYXNlIDE6Zm9yKGk9dGhpcy5fYWN0"
    "aXZlQnVmZmVyLnksdGhpcy5fZGlydHlSb3dUcmFja2VyLm1hcmtEaXJ0eShpKSx0aGlzLl9lcmFzZUluQnVmZmVyTGluZShpLDAsdGhpcy5fYWN0aXZlQnVm"
    "ZmVyLngrMSwhMCx0KSx0aGlzLl9hY3RpdmVCdWZmZXIueCsxPj10aGlzLl9idWZmZXJTZXJ2aWNlLmNvbHMmJih0aGlzLl9hY3RpdmVCdWZmZXIubGluZXMu"
    "Z2V0KGkrMSkuaXNXcmFwcGVkPSExKTtpLS07KXRoaXMuX3Jlc2V0QnVmZmVyTGluZShpLHQpO3RoaXMuX2RpcnR5Um93VHJhY2tlci5tYXJrRGlydHkoMCk7"
    "YnJlYWs7Y2FzZSAyOmZvcihpPXRoaXMuX2J1ZmZlclNlcnZpY2Uucm93cyx0aGlzLl9kaXJ0eVJvd1RyYWNrZXIubWFya0RpcnR5KGktMSk7aS0tOyl0aGlz"
    "Ll9yZXNldEJ1ZmZlckxpbmUoaSx0KTt0aGlzLl9kaXJ0eVJvd1RyYWNrZXIubWFya0RpcnR5KDApO2JyZWFrO2Nhc2UgMzpjb25zdCBlPXRoaXMuX2FjdGl2"
    "ZUJ1ZmZlci5saW5lcy5sZW5ndGgtdGhpcy5fYnVmZmVyU2VydmljZS5yb3dzO2U+MCYmKHRoaXMuX2FjdGl2ZUJ1ZmZlci5saW5lcy50cmltU3RhcnQoZSks"
    "dGhpcy5fYWN0aXZlQnVmZmVyLnliYXNlPU1hdGgubWF4KHRoaXMuX2FjdGl2ZUJ1ZmZlci55YmFzZS1lLDApLHRoaXMuX2FjdGl2ZUJ1ZmZlci55ZGlzcD1N"
    "YXRoLm1heCh0aGlzLl9hY3RpdmVCdWZmZXIueWRpc3AtZSwwKSx0aGlzLl9vblNjcm9sbC5maXJlKDApKX1yZXR1cm4hMH1lcmFzZUluTGluZShlLHQ9ITEp"
    "e3N3aXRjaCh0aGlzLl9yZXN0cmljdEN1cnNvcih0aGlzLl9idWZmZXJTZXJ2aWNlLmNvbHMpLGUucGFyYW1zWzBdKXtjYXNlIDA6dGhpcy5fZXJhc2VJbkJ1"
    "ZmZlckxpbmUodGhpcy5fYWN0aXZlQnVmZmVyLnksdGhpcy5fYWN0aXZlQnVmZmVyLngsdGhpcy5fYnVmZmVyU2VydmljZS5jb2xzLDA9PT10aGlzLl9hY3Rp"
    "dmVCdWZmZXIueCx0KTticmVhaztjYXNlIDE6dGhpcy5fZXJhc2VJbkJ1ZmZlckxpbmUodGhpcy5fYWN0aXZlQnVmZmVyLnksMCx0aGlzLl9hY3RpdmVCdWZm"
    "ZXIueCsxLCExLHQpO2JyZWFrO2Nhc2UgMjp0aGlzLl9lcmFzZUluQnVmZmVyTGluZSh0aGlzLl9hY3RpdmVCdWZmZXIueSwwLHRoaXMuX2J1ZmZlclNlcnZp"
    "Y2UuY29scywhMCx0KX1yZXR1cm4gdGhpcy5fZGlydHlSb3dUcmFja2VyLm1hcmtEaXJ0eSh0aGlzLl9hY3RpdmVCdWZmZXIueSksITB9aW5zZXJ0TGluZXMo"
    "ZSl7dGhpcy5fcmVzdHJpY3RDdXJzb3IoKTtsZXQgdD1lLnBhcmFtc1swXXx8MTtpZih0aGlzLl9hY3RpdmVCdWZmZXIueT50aGlzLl9hY3RpdmVCdWZmZXIu"
    "c2Nyb2xsQm90dG9tfHx0aGlzLl9hY3RpdmVCdWZmZXIueTx0aGlzLl9hY3RpdmVCdWZmZXIuc2Nyb2xsVG9wKXJldHVybiEwO2NvbnN0IGk9dGhpcy5fYWN0"
    "aXZlQnVmZmVyLnliYXNlK3RoaXMuX2FjdGl2ZUJ1ZmZlci55LHM9dGhpcy5fYnVmZmVyU2VydmljZS5yb3dzLTEtdGhpcy5fYWN0aXZlQnVmZmVyLnNjcm9s"
    "bEJvdHRvbSxyPXRoaXMuX2J1ZmZlclNlcnZpY2Uucm93cy0xK3RoaXMuX2FjdGl2ZUJ1ZmZlci55YmFzZS1zKzE7Zm9yKDt0LS07KXRoaXMuX2FjdGl2ZUJ1"
    "ZmZlci5saW5lcy5zcGxpY2Uoci0xLDEpLHRoaXMuX2FjdGl2ZUJ1ZmZlci5saW5lcy5zcGxpY2UoaSwwLHRoaXMuX2FjdGl2ZUJ1ZmZlci5nZXRCbGFua0xp"
    "bmUodGhpcy5fZXJhc2VBdHRyRGF0YSgpKSk7cmV0dXJuIHRoaXMuX2RpcnR5Um93VHJhY2tlci5tYXJrUmFuZ2VEaXJ0eSh0aGlzLl9hY3RpdmVCdWZmZXIu"
    "eSx0aGlzLl9hY3RpdmVCdWZmZXIuc2Nyb2xsQm90dG9tKSx0aGlzLl9hY3RpdmVCdWZmZXIueD0wLCEwfWRlbGV0ZUxpbmVzKGUpe3RoaXMuX3Jlc3RyaWN0"
    "Q3Vyc29yKCk7bGV0IHQ9ZS5wYXJhbXNbMF18fDE7aWYodGhpcy5fYWN0aXZlQnVmZmVyLnk+dGhpcy5fYWN0aXZlQnVmZmVyLnNjcm9sbEJvdHRvbXx8dGhp"
    "cy5fYWN0aXZlQnVmZmVyLnk8dGhpcy5fYWN0aXZlQnVmZmVyLnNjcm9sbFRvcClyZXR1cm4hMDtjb25zdCBpPXRoaXMuX2FjdGl2ZUJ1ZmZlci55YmFzZSt0"
    "aGlzLl9hY3RpdmVCdWZmZXIueTtsZXQgcztmb3Iocz10aGlzLl9idWZmZXJTZXJ2aWNlLnJvd3MtMS10aGlzLl9hY3RpdmVCdWZmZXIuc2Nyb2xsQm90dG9t"
    "LHM9dGhpcy5fYnVmZmVyU2VydmljZS5yb3dzLTErdGhpcy5fYWN0aXZlQnVmZmVyLnliYXNlLXM7dC0tOyl0aGlzLl9hY3RpdmVCdWZmZXIubGluZXMuc3Bs"
    "aWNlKGksMSksdGhpcy5fYWN0aXZlQnVmZmVyLmxpbmVzLnNwbGljZShzLDAsdGhpcy5fYWN0aXZlQnVmZmVyLmdldEJsYW5rTGluZSh0aGlzLl9lcmFzZUF0"
    "dHJEYXRhKCkpKTtyZXR1cm4gdGhpcy5fZGlydHlSb3dUcmFja2VyLm1hcmtSYW5nZURpcnR5KHRoaXMuX2FjdGl2ZUJ1ZmZlci55LHRoaXMuX2FjdGl2ZUJ1"
    "ZmZlci5zY3JvbGxCb3R0b20pLHRoaXMuX2FjdGl2ZUJ1ZmZlci54PTAsITB9aW5zZXJ0Q2hhcnMoZSl7dGhpcy5fcmVzdHJpY3RDdXJzb3IoKTtjb25zdCB0"
    "PXRoaXMuX2FjdGl2ZUJ1ZmZlci5saW5lcy5nZXQodGhpcy5fYWN0aXZlQnVmZmVyLnliYXNlK3RoaXMuX2FjdGl2ZUJ1ZmZlci55KTtyZXR1cm4gdCYmKHQu"
    "aW5zZXJ0Q2VsbHModGhpcy5fYWN0aXZlQnVmZmVyLngsZS5wYXJhbXNbMF18fDEsdGhpcy5fYWN0aXZlQnVmZmVyLmdldE51bGxDZWxsKHRoaXMuX2VyYXNl"
    "QXR0ckRhdGEoKSksdGhpcy5fZXJhc2VBdHRyRGF0YSgpKSx0aGlzLl9kaXJ0eVJvd1RyYWNrZXIubWFya0RpcnR5KHRoaXMuX2FjdGl2ZUJ1ZmZlci55KSks"
    "ITB9ZGVsZXRlQ2hhcnMoZSl7dGhpcy5fcmVzdHJpY3RDdXJzb3IoKTtjb25zdCB0PXRoaXMuX2FjdGl2ZUJ1ZmZlci5saW5lcy5nZXQodGhpcy5fYWN0aXZl"
    "QnVmZmVyLnliYXNlK3RoaXMuX2FjdGl2ZUJ1ZmZlci55KTtyZXR1cm4gdCYmKHQuZGVsZXRlQ2VsbHModGhpcy5fYWN0aXZlQnVmZmVyLngsZS5wYXJhbXNb"
    "MF18fDEsdGhpcy5fYWN0aXZlQnVmZmVyLmdldE51bGxDZWxsKHRoaXMuX2VyYXNlQXR0ckRhdGEoKSksdGhpcy5fZXJhc2VBdHRyRGF0YSgpKSx0aGlzLl9k"
    "aXJ0eVJvd1RyYWNrZXIubWFya0RpcnR5KHRoaXMuX2FjdGl2ZUJ1ZmZlci55KSksITB9c2Nyb2xsVXAoZSl7bGV0IHQ9ZS5wYXJhbXNbMF18fDE7Zm9yKDt0"
    "LS07KXRoaXMuX2FjdGl2ZUJ1ZmZlci5saW5lcy5zcGxpY2UodGhpcy5fYWN0aXZlQnVmZmVyLnliYXNlK3RoaXMuX2FjdGl2ZUJ1ZmZlci5zY3JvbGxUb3As"
    "MSksdGhpcy5fYWN0aXZlQnVmZmVyLmxpbmVzLnNwbGljZSh0aGlzLl9hY3RpdmVCdWZmZXIueWJhc2UrdGhpcy5fYWN0aXZlQnVmZmVyLnNjcm9sbEJvdHRv"
    "bSwwLHRoaXMuX2FjdGl2ZUJ1ZmZlci5nZXRCbGFua0xpbmUodGhpcy5fZXJhc2VBdHRyRGF0YSgpKSk7cmV0dXJuIHRoaXMuX2RpcnR5Um93VHJhY2tlci5t"
    "YXJrUmFuZ2VEaXJ0eSh0aGlzLl9hY3RpdmVCdWZmZXIuc2Nyb2xsVG9wLHRoaXMuX2FjdGl2ZUJ1ZmZlci5zY3JvbGxCb3R0b20pLCEwfXNjcm9sbERvd24o"
    "ZSl7bGV0IHQ9ZS5wYXJhbXNbMF18fDE7Zm9yKDt0LS07KXRoaXMuX2FjdGl2ZUJ1ZmZlci5saW5lcy5zcGxpY2UodGhpcy5fYWN0aXZlQnVmZmVyLnliYXNl"
    "K3RoaXMuX2FjdGl2ZUJ1ZmZlci5zY3JvbGxCb3R0b20sMSksdGhpcy5fYWN0aXZlQnVmZmVyLmxpbmVzLnNwbGljZSh0aGlzLl9hY3RpdmVCdWZmZXIueWJh"
    "c2UrdGhpcy5fYWN0aXZlQnVmZmVyLnNjcm9sbFRvcCwwLHRoaXMuX2FjdGl2ZUJ1ZmZlci5nZXRCbGFua0xpbmUobC5ERUZBVUxUX0FUVFJfREFUQSkpO3Jl"
    "dHVybiB0aGlzLl9kaXJ0eVJvd1RyYWNrZXIubWFya1JhbmdlRGlydHkodGhpcy5fYWN0aXZlQnVmZmVyLnNjcm9sbFRvcCx0aGlzLl9hY3RpdmVCdWZmZXIu"
    "c2Nyb2xsQm90dG9tKSwhMH1zY3JvbGxMZWZ0KGUpe2lmKHRoaXMuX2FjdGl2ZUJ1ZmZlci55PnRoaXMuX2FjdGl2ZUJ1ZmZlci5zY3JvbGxCb3R0b218fHRo"
    "aXMuX2FjdGl2ZUJ1ZmZlci55PHRoaXMuX2FjdGl2ZUJ1ZmZlci5zY3JvbGxUb3ApcmV0dXJuITA7Y29uc3QgdD1lLnBhcmFtc1swXXx8MTtmb3IobGV0IGU9"
    "dGhpcy5fYWN0aXZlQnVmZmVyLnNjcm9sbFRvcDtlPD10aGlzLl9hY3RpdmVCdWZmZXIuc2Nyb2xsQm90dG9tOysrZSl7Y29uc3QgaT10aGlzLl9hY3RpdmVC"
    "dWZmZXIubGluZXMuZ2V0KHRoaXMuX2FjdGl2ZUJ1ZmZlci55YmFzZStlKTtpLmRlbGV0ZUNlbGxzKDAsdCx0aGlzLl9hY3RpdmVCdWZmZXIuZ2V0TnVsbENl"
    "bGwodGhpcy5fZXJhc2VBdHRyRGF0YSgpKSx0aGlzLl9lcmFzZUF0dHJEYXRhKCkpLGkuaXNXcmFwcGVkPSExfXJldHVybiB0aGlzLl9kaXJ0eVJvd1RyYWNr"
    "ZXIubWFya1JhbmdlRGlydHkodGhpcy5fYWN0aXZlQnVmZmVyLnNjcm9sbFRvcCx0aGlzLl9hY3RpdmVCdWZmZXIuc2Nyb2xsQm90dG9tKSwhMH1zY3JvbGxS"
    "aWdodChlKXtpZih0aGlzLl9hY3RpdmVCdWZmZXIueT50aGlzLl9hY3RpdmVCdWZmZXIuc2Nyb2xsQm90dG9tfHx0aGlzLl9hY3RpdmVCdWZmZXIueTx0aGlz"
    "Ll9hY3RpdmVCdWZmZXIuc2Nyb2xsVG9wKXJldHVybiEwO2NvbnN0IHQ9ZS5wYXJhbXNbMF18fDE7Zm9yKGxldCBlPXRoaXMuX2FjdGl2ZUJ1ZmZlci5zY3Jv"
    "bGxUb3A7ZTw9dGhpcy5fYWN0aXZlQnVmZmVyLnNjcm9sbEJvdHRvbTsrK2Upe2NvbnN0IGk9dGhpcy5fYWN0aXZlQnVmZmVyLmxpbmVzLmdldCh0aGlzLl9h"
    "Y3RpdmVCdWZmZXIueWJhc2UrZSk7aS5pbnNlcnRDZWxscygwLHQsdGhpcy5fYWN0aXZlQnVmZmVyLmdldE51bGxDZWxsKHRoaXMuX2VyYXNlQXR0ckRhdGEo"
    "KSksdGhpcy5fZXJhc2VBdHRyRGF0YSgpKSxpLmlzV3JhcHBlZD0hMX1yZXR1cm4gdGhpcy5fZGlydHlSb3dUcmFja2VyLm1hcmtSYW5nZURpcnR5KHRoaXMu"
    "X2FjdGl2ZUJ1ZmZlci5zY3JvbGxUb3AsdGhpcy5fYWN0aXZlQnVmZmVyLnNjcm9sbEJvdHRvbSksITB9aW5zZXJ0Q29sdW1ucyhlKXtpZih0aGlzLl9hY3Rp"
    "dmVCdWZmZXIueT50aGlzLl9hY3RpdmVCdWZmZXIuc2Nyb2xsQm90dG9tfHx0aGlzLl9hY3RpdmVCdWZmZXIueTx0aGlzLl9hY3RpdmVCdWZmZXIuc2Nyb2xs"
    "VG9wKXJldHVybiEwO2NvbnN0IHQ9ZS5wYXJhbXNbMF18fDE7Zm9yKGxldCBlPXRoaXMuX2FjdGl2ZUJ1ZmZlci5zY3JvbGxUb3A7ZTw9dGhpcy5fYWN0aXZl"
    "QnVmZmVyLnNjcm9sbEJvdHRvbTsrK2Upe2NvbnN0IGk9dGhpcy5fYWN0aXZlQnVmZmVyLmxpbmVzLmdldCh0aGlzLl9hY3RpdmVCdWZmZXIueWJhc2UrZSk7"
    "aS5pbnNlcnRDZWxscyh0aGlzLl9hY3RpdmVCdWZmZXIueCx0LHRoaXMuX2FjdGl2ZUJ1ZmZlci5nZXROdWxsQ2VsbCh0aGlzLl9lcmFzZUF0dHJEYXRhKCkp"
    "LHRoaXMuX2VyYXNlQXR0ckRhdGEoKSksaS5pc1dyYXBwZWQ9ITF9cmV0dXJuIHRoaXMuX2RpcnR5Um93VHJhY2tlci5tYXJrUmFuZ2VEaXJ0eSh0aGlzLl9h"
    "Y3RpdmVCdWZmZXIuc2Nyb2xsVG9wLHRoaXMuX2FjdGl2ZUJ1ZmZlci5zY3JvbGxCb3R0b20pLCEwfWRlbGV0ZUNvbHVtbnMoZSl7aWYodGhpcy5fYWN0aXZl"
    "QnVmZmVyLnk+dGhpcy5fYWN0aXZlQnVmZmVyLnNjcm9sbEJvdHRvbXx8dGhpcy5fYWN0aXZlQnVmZmVyLnk8dGhpcy5fYWN0aXZlQnVmZmVyLnNjcm9sbFRv"
    "cClyZXR1cm4hMDtjb25zdCB0PWUucGFyYW1zWzBdfHwxO2ZvcihsZXQgZT10aGlzLl9hY3RpdmVCdWZmZXIuc2Nyb2xsVG9wO2U8PXRoaXMuX2FjdGl2ZUJ1"
    "ZmZlci5zY3JvbGxCb3R0b207KytlKXtjb25zdCBpPXRoaXMuX2FjdGl2ZUJ1ZmZlci5saW5lcy5nZXQodGhpcy5fYWN0aXZlQnVmZmVyLnliYXNlK2UpO2ku"
    "ZGVsZXRlQ2VsbHModGhpcy5fYWN0aXZlQnVmZmVyLngsdCx0aGlzLl9hY3RpdmVCdWZmZXIuZ2V0TnVsbENlbGwodGhpcy5fZXJhc2VBdHRyRGF0YSgpKSx0"
    "aGlzLl9lcmFzZUF0dHJEYXRhKCkpLGkuaXNXcmFwcGVkPSExfXJldHVybiB0aGlzLl9kaXJ0eVJvd1RyYWNrZXIubWFya1JhbmdlRGlydHkodGhpcy5fYWN0"
    "aXZlQnVmZmVyLnNjcm9sbFRvcCx0aGlzLl9hY3RpdmVCdWZmZXIuc2Nyb2xsQm90dG9tKSwhMH1lcmFzZUNoYXJzKGUpe3RoaXMuX3Jlc3RyaWN0Q3Vyc29y"
    "KCk7Y29uc3QgdD10aGlzLl9hY3RpdmVCdWZmZXIubGluZXMuZ2V0KHRoaXMuX2FjdGl2ZUJ1ZmZlci55YmFzZSt0aGlzLl9hY3RpdmVCdWZmZXIueSk7cmV0"
    "dXJuIHQmJih0LnJlcGxhY2VDZWxscyh0aGlzLl9hY3RpdmVCdWZmZXIueCx0aGlzLl9hY3RpdmVCdWZmZXIueCsoZS5wYXJhbXNbMF18fDEpLHRoaXMuX2Fj"
    "dGl2ZUJ1ZmZlci5nZXROdWxsQ2VsbCh0aGlzLl9lcmFzZUF0dHJEYXRhKCkpLHRoaXMuX2VyYXNlQXR0ckRhdGEoKSksdGhpcy5fZGlydHlSb3dUcmFja2Vy"
    "Lm1hcmtEaXJ0eSh0aGlzLl9hY3RpdmVCdWZmZXIueSkpLCEwfXJlcGVhdFByZWNlZGluZ0NoYXJhY3RlcihlKXtpZighdGhpcy5fcGFyc2VyLnByZWNlZGlu"
    "Z0NvZGVwb2ludClyZXR1cm4hMDtjb25zdCB0PWUucGFyYW1zWzBdfHwxLGk9bmV3IFVpbnQzMkFycmF5KHQpO2ZvcihsZXQgZT0wO2U8dDsrK2UpaVtlXT10"
    "aGlzLl9wYXJzZXIucHJlY2VkaW5nQ29kZXBvaW50O3JldHVybiB0aGlzLnByaW50KGksMCxpLmxlbmd0aCksITB9c2VuZERldmljZUF0dHJpYnV0ZXNQcmlt"
    "YXJ5KGUpe3JldHVybiBlLnBhcmFtc1swXT4wfHwodGhpcy5faXMoInh0ZXJtIil8fHRoaXMuX2lzKCJyeHZ0LXVuaWNvZGUiKXx8dGhpcy5faXMoInNjcmVl"
    "biIpP3RoaXMuX2NvcmVTZXJ2aWNlLnRyaWdnZXJEYXRhRXZlbnQobi5DMC5FU0MrIls/MTsyYyIpOnRoaXMuX2lzKCJsaW51eCIpJiZ0aGlzLl9jb3JlU2Vy"
    "dmljZS50cmlnZ2VyRGF0YUV2ZW50KG4uQzAuRVNDKyJbPzZjIikpLCEwfXNlbmREZXZpY2VBdHRyaWJ1dGVzU2Vjb25kYXJ5KGUpe3JldHVybiBlLnBhcmFt"
    "c1swXT4wfHwodGhpcy5faXMoInh0ZXJtIik/dGhpcy5fY29yZVNlcnZpY2UudHJpZ2dlckRhdGFFdmVudChuLkMwLkVTQysiWz4wOzI3NjswYyIpOnRoaXMu"
    "X2lzKCJyeHZ0LXVuaWNvZGUiKT90aGlzLl9jb3JlU2VydmljZS50cmlnZ2VyRGF0YUV2ZW50KG4uQzAuRVNDKyJbPjg1Ozk1OzBjIik6dGhpcy5faXMoImxp"
    "bnV4Iik/dGhpcy5fY29yZVNlcnZpY2UudHJpZ2dlckRhdGFFdmVudChlLnBhcmFtc1swXSsiYyIpOnRoaXMuX2lzKCJzY3JlZW4iKSYmdGhpcy5fY29yZVNl"
    "cnZpY2UudHJpZ2dlckRhdGFFdmVudChuLkMwLkVTQysiWz44Mzs0MDAwMzswYyIpKSwhMH1faXMoZSl7cmV0dXJuIDA9PT0odGhpcy5fb3B0aW9uc1NlcnZp"
    "Y2UucmF3T3B0aW9ucy50ZXJtTmFtZSsiIikuaW5kZXhPZihlKX1zZXRNb2RlKGUpe2ZvcihsZXQgdD0wO3Q8ZS5sZW5ndGg7dCsrKXN3aXRjaChlLnBhcmFt"
    "c1t0XSl7Y2FzZSA0OnRoaXMuX2NvcmVTZXJ2aWNlLm1vZGVzLmluc2VydE1vZGU9ITA7YnJlYWs7Y2FzZSAyMDp0aGlzLl9vcHRpb25zU2VydmljZS5vcHRp"
    "b25zLmNvbnZlcnRFb2w9ITB9cmV0dXJuITB9c2V0TW9kZVByaXZhdGUoZSl7Zm9yKGxldCB0PTA7dDxlLmxlbmd0aDt0Kyspc3dpdGNoKGUucGFyYW1zW3Rd"
    "KXtjYXNlIDE6dGhpcy5fY29yZVNlcnZpY2UuZGVjUHJpdmF0ZU1vZGVzLmFwcGxpY2F0aW9uQ3Vyc29yS2V5cz0hMDticmVhaztjYXNlIDI6dGhpcy5fY2hh"
    "cnNldFNlcnZpY2Uuc2V0Z0NoYXJzZXQoMCxvLkRFRkFVTFRfQ0hBUlNFVCksdGhpcy5fY2hhcnNldFNlcnZpY2Uuc2V0Z0NoYXJzZXQoMSxvLkRFRkFVTFRf"
    "Q0hBUlNFVCksdGhpcy5fY2hhcnNldFNlcnZpY2Uuc2V0Z0NoYXJzZXQoMixvLkRFRkFVTFRfQ0hBUlNFVCksdGhpcy5fY2hhcnNldFNlcnZpY2Uuc2V0Z0No"
    "YXJzZXQoMyxvLkRFRkFVTFRfQ0hBUlNFVCk7YnJlYWs7Y2FzZSAzOnRoaXMuX29wdGlvbnNTZXJ2aWNlLnJhd09wdGlvbnMud2luZG93T3B0aW9ucy5zZXRX"
    "aW5MaW5lcyYmKHRoaXMuX2J1ZmZlclNlcnZpY2UucmVzaXplKDEzMix0aGlzLl9idWZmZXJTZXJ2aWNlLnJvd3MpLHRoaXMuX29uUmVxdWVzdFJlc2V0LmZp"
    "cmUoKSk7YnJlYWs7Y2FzZSA2OnRoaXMuX2NvcmVTZXJ2aWNlLmRlY1ByaXZhdGVNb2Rlcy5vcmlnaW49ITAsdGhpcy5fc2V0Q3Vyc29yKDAsMCk7YnJlYWs7"
    "Y2FzZSA3OnRoaXMuX2NvcmVTZXJ2aWNlLmRlY1ByaXZhdGVNb2Rlcy53cmFwYXJvdW5kPSEwO2JyZWFrO2Nhc2UgMTI6dGhpcy5fb3B0aW9uc1NlcnZpY2Uu"
    "b3B0aW9ucy5jdXJzb3JCbGluaz0hMDticmVhaztjYXNlIDQ1OnRoaXMuX2NvcmVTZXJ2aWNlLmRlY1ByaXZhdGVNb2Rlcy5yZXZlcnNlV3JhcGFyb3VuZD0h"
    "MDticmVhaztjYXNlIDY2OnRoaXMuX2xvZ1NlcnZpY2UuZGVidWcoIlNlcmlhbCBwb3J0IHJlcXVlc3RlZCBhcHBsaWNhdGlvbiBrZXlwYWQuIiksdGhpcy5f"
    "Y29yZVNlcnZpY2UuZGVjUHJpdmF0ZU1vZGVzLmFwcGxpY2F0aW9uS2V5cGFkPSEwLHRoaXMuX29uUmVxdWVzdFN5bmNTY3JvbGxCYXIuZmlyZSgpO2JyZWFr"
    "O2Nhc2UgOTp0aGlzLl9jb3JlTW91c2VTZXJ2aWNlLmFjdGl2ZVByb3RvY29sPSJYMTAiO2JyZWFrO2Nhc2UgMWUzOnRoaXMuX2NvcmVNb3VzZVNlcnZpY2Uu"
    "YWN0aXZlUHJvdG9jb2w9IlZUMjAwIjticmVhaztjYXNlIDEwMDI6dGhpcy5fY29yZU1vdXNlU2VydmljZS5hY3RpdmVQcm90b2NvbD0iRFJBRyI7YnJlYWs7"
    "Y2FzZSAxMDAzOnRoaXMuX2NvcmVNb3VzZVNlcnZpY2UuYWN0aXZlUHJvdG9jb2w9IkFOWSI7YnJlYWs7Y2FzZSAxMDA0OnRoaXMuX2NvcmVTZXJ2aWNlLmRl"
    "Y1ByaXZhdGVNb2Rlcy5zZW5kRm9jdXM9ITAsdGhpcy5fb25SZXF1ZXN0U2VuZEZvY3VzLmZpcmUoKTticmVhaztjYXNlIDEwMDU6dGhpcy5fbG9nU2Vydmlj"
    "ZS5kZWJ1ZygiREVDU0VUIDEwMDUgbm90IHN1cHBvcnRlZCAoc2VlICMyNTA3KSIpO2JyZWFrO2Nhc2UgMTAwNjp0aGlzLl9jb3JlTW91c2VTZXJ2aWNlLmFj"
    "dGl2ZUVuY29kaW5nPSJTR1IiO2JyZWFrO2Nhc2UgMTAxNTp0aGlzLl9sb2dTZXJ2aWNlLmRlYnVnKCJERUNTRVQgMTAxNSBub3Qgc3VwcG9ydGVkIChzZWUg"
    "IzI1MDcpIik7YnJlYWs7Y2FzZSAxMDE2OnRoaXMuX2NvcmVNb3VzZVNlcnZpY2UuYWN0aXZlRW5jb2Rpbmc9IlNHUl9QSVhFTFMiO2JyZWFrO2Nhc2UgMjU6"
    "dGhpcy5fY29yZVNlcnZpY2UuaXNDdXJzb3JIaWRkZW49ITE7YnJlYWs7Y2FzZSAxMDQ4OnRoaXMuc2F2ZUN1cnNvcigpO2JyZWFrO2Nhc2UgMTA0OTp0aGlz"
    "LnNhdmVDdXJzb3IoKTtjYXNlIDQ3OmNhc2UgMTA0Nzp0aGlzLl9idWZmZXJTZXJ2aWNlLmJ1ZmZlcnMuYWN0aXZhdGVBbHRCdWZmZXIodGhpcy5fZXJhc2VB"
    "dHRyRGF0YSgpKSx0aGlzLl9jb3JlU2VydmljZS5pc0N1cnNvckluaXRpYWxpemVkPSEwLHRoaXMuX29uUmVxdWVzdFJlZnJlc2hSb3dzLmZpcmUoMCx0aGlz"
    "Ll9idWZmZXJTZXJ2aWNlLnJvd3MtMSksdGhpcy5fb25SZXF1ZXN0U3luY1Njcm9sbEJhci5maXJlKCk7YnJlYWs7Y2FzZSAyMDA0OnRoaXMuX2NvcmVTZXJ2"
    "aWNlLmRlY1ByaXZhdGVNb2Rlcy5icmFja2V0ZWRQYXN0ZU1vZGU9ITB9cmV0dXJuITB9cmVzZXRNb2RlKGUpe2ZvcihsZXQgdD0wO3Q8ZS5sZW5ndGg7dCsr"
    "KXN3aXRjaChlLnBhcmFtc1t0XSl7Y2FzZSA0OnRoaXMuX2NvcmVTZXJ2aWNlLm1vZGVzLmluc2VydE1vZGU9ITE7YnJlYWs7Y2FzZSAyMDp0aGlzLl9vcHRp"
    "b25zU2VydmljZS5vcHRpb25zLmNvbnZlcnRFb2w9ITF9cmV0dXJuITB9cmVzZXRNb2RlUHJpdmF0ZShlKXtmb3IobGV0IHQ9MDt0PGUubGVuZ3RoO3QrKylz"
    "d2l0Y2goZS5wYXJhbXNbdF0pe2Nhc2UgMTp0aGlzLl9jb3JlU2VydmljZS5kZWNQcml2YXRlTW9kZXMuYXBwbGljYXRpb25DdXJzb3JLZXlzPSExO2JyZWFr"
    "O2Nhc2UgMzp0aGlzLl9vcHRpb25zU2VydmljZS5yYXdPcHRpb25zLndpbmRvd09wdGlvbnMuc2V0V2luTGluZXMmJih0aGlzLl9idWZmZXJTZXJ2aWNlLnJl"
    "c2l6ZSg4MCx0aGlzLl9idWZmZXJTZXJ2aWNlLnJvd3MpLHRoaXMuX29uUmVxdWVzdFJlc2V0LmZpcmUoKSk7YnJlYWs7Y2FzZSA2OnRoaXMuX2NvcmVTZXJ2"
    "aWNlLmRlY1ByaXZhdGVNb2Rlcy5vcmlnaW49ITEsdGhpcy5fc2V0Q3Vyc29yKDAsMCk7YnJlYWs7Y2FzZSA3OnRoaXMuX2NvcmVTZXJ2aWNlLmRlY1ByaXZh"
    "dGVNb2Rlcy53cmFwYXJvdW5kPSExO2JyZWFrO2Nhc2UgMTI6dGhpcy5fb3B0aW9uc1NlcnZpY2Uub3B0aW9ucy5jdXJzb3JCbGluaz0hMTticmVhaztjYXNl"
    "IDQ1OnRoaXMuX2NvcmVTZXJ2aWNlLmRlY1ByaXZhdGVNb2Rlcy5yZXZlcnNlV3JhcGFyb3VuZD0hMTticmVhaztjYXNlIDY2OnRoaXMuX2xvZ1NlcnZpY2Uu"
    "ZGVidWcoIlN3aXRjaGluZyBiYWNrIHRvIG5vcm1hbCBrZXlwYWQuIiksdGhpcy5fY29yZVNlcnZpY2UuZGVjUHJpdmF0ZU1vZGVzLmFwcGxpY2F0aW9uS2V5"
    "cGFkPSExLHRoaXMuX29uUmVxdWVzdFN5bmNTY3JvbGxCYXIuZmlyZSgpO2JyZWFrO2Nhc2UgOTpjYXNlIDFlMzpjYXNlIDEwMDI6Y2FzZSAxMDAzOnRoaXMu"
    "X2NvcmVNb3VzZVNlcnZpY2UuYWN0aXZlUHJvdG9jb2w9Ik5PTkUiO2JyZWFrO2Nhc2UgMTAwNDp0aGlzLl9jb3JlU2VydmljZS5kZWNQcml2YXRlTW9kZXMu"
    "c2VuZEZvY3VzPSExO2JyZWFrO2Nhc2UgMTAwNTp0aGlzLl9sb2dTZXJ2aWNlLmRlYnVnKCJERUNSU1QgMTAwNSBub3Qgc3VwcG9ydGVkIChzZWUgIzI1MDcp"
    "Iik7YnJlYWs7Y2FzZSAxMDA2OmNhc2UgMTAxNjp0aGlzLl9jb3JlTW91c2VTZXJ2aWNlLmFjdGl2ZUVuY29kaW5nPSJERUZBVUxUIjticmVhaztjYXNlIDEw"
    "MTU6dGhpcy5fbG9nU2VydmljZS5kZWJ1ZygiREVDUlNUIDEwMTUgbm90IHN1cHBvcnRlZCAoc2VlICMyNTA3KSIpO2JyZWFrO2Nhc2UgMjU6dGhpcy5fY29y"
    "ZVNlcnZpY2UuaXNDdXJzb3JIaWRkZW49ITA7YnJlYWs7Y2FzZSAxMDQ4OnRoaXMucmVzdG9yZUN1cnNvcigpO2JyZWFrO2Nhc2UgMTA0OTpjYXNlIDQ3OmNh"
    "c2UgMTA0Nzp0aGlzLl9idWZmZXJTZXJ2aWNlLmJ1ZmZlcnMuYWN0aXZhdGVOb3JtYWxCdWZmZXIoKSwxMDQ5PT09ZS5wYXJhbXNbdF0mJnRoaXMucmVzdG9y"
    "ZUN1cnNvcigpLHRoaXMuX2NvcmVTZXJ2aWNlLmlzQ3Vyc29ySW5pdGlhbGl6ZWQ9ITAsdGhpcy5fb25SZXF1ZXN0UmVmcmVzaFJvd3MuZmlyZSgwLHRoaXMu"
    "X2J1ZmZlclNlcnZpY2Uucm93cy0xKSx0aGlzLl9vblJlcXVlc3RTeW5jU2Nyb2xsQmFyLmZpcmUoKTticmVhaztjYXNlIDIwMDQ6dGhpcy5fY29yZVNlcnZp"
    "Y2UuZGVjUHJpdmF0ZU1vZGVzLmJyYWNrZXRlZFBhc3RlTW9kZT0hMX1yZXR1cm4hMH1yZXF1ZXN0TW9kZShlLHQpe2NvbnN0IGk9dGhpcy5fY29yZVNlcnZp"
    "Y2UuZGVjUHJpdmF0ZU1vZGVzLHthY3RpdmVQcm90b2NvbDpzLGFjdGl2ZUVuY29kaW5nOnJ9PXRoaXMuX2NvcmVNb3VzZVNlcnZpY2Usbz10aGlzLl9jb3Jl"
    "U2VydmljZSx7YnVmZmVyczphLGNvbHM6aH09dGhpcy5fYnVmZmVyU2VydmljZSx7YWN0aXZlOmMsYWx0Omx9PWEsZD10aGlzLl9vcHRpb25zU2VydmljZS5y"
    "YXdPcHRpb25zLF89ZT0+ZT8xOjIsdT1lLnBhcmFtc1swXTtyZXR1cm4gZj11LHY9dD8yPT09dT80OjQ9PT11P18oby5tb2Rlcy5pbnNlcnRNb2RlKToxMj09"
    "PXU/MzoyMD09PXU/XyhkLmNvbnZlcnRFb2wpOjA6MT09PXU/XyhpLmFwcGxpY2F0aW9uQ3Vyc29yS2V5cyk6Mz09PXU/ZC53aW5kb3dPcHRpb25zLnNldFdp"
    "bkxpbmVzPzgwPT09aD8yOjEzMj09PWg/MTowOjA6Nj09PXU/XyhpLm9yaWdpbik6Nz09PXU/XyhpLndyYXBhcm91bmQpOjg9PT11PzM6OT09PXU/XygiWDEw"
    "Ij09PXMpOjEyPT09dT9fKGQuY3Vyc29yQmxpbmspOjI1PT09dT9fKCFvLmlzQ3Vyc29ySGlkZGVuKTo0NT09PXU/XyhpLnJldmVyc2VXcmFwYXJvdW5kKTo2"
    "Nj09PXU/XyhpLmFwcGxpY2F0aW9uS2V5cGFkKTo2Nz09PXU/NDoxZTM9PT11P18oIlZUMjAwIj09PXMpOjEwMDI9PT11P18oIkRSQUciPT09cyk6MTAwMz09"
    "PXU/XygiQU5ZIj09PXMpOjEwMDQ9PT11P18oaS5zZW5kRm9jdXMpOjEwMDU9PT11PzQ6MTAwNj09PXU/XygiU0dSIj09PXIpOjEwMTU9PT11PzQ6MTAxNj09"
    "PXU/XygiU0dSX1BJWEVMUyI9PT1yKToxMDQ4PT09dT8xOjQ3PT09dXx8MTA0Nz09PXV8fDEwNDk9PT11P18oYz09PWwpOjIwMDQ9PT11P18oaS5icmFja2V0"
    "ZWRQYXN0ZU1vZGUpOjAsby50cmlnZ2VyRGF0YUV2ZW50KGAke24uQzAuRVNDfVske3Q/IiI6Ij8ifSR7Zn07JHt2fSR5YCksITA7dmFyIGYsdn1fdXBkYXRl"
    "QXR0ckNvbG9yKGUsdCxpLHMscil7cmV0dXJuIDI9PT10PyhlfD01MDMzMTY0OCxlJj0tMTY3NzcyMTYsZXw9Zi5BdHRyaWJ1dGVEYXRhLmZyb21Db2xvclJH"
    "QihbaSxzLHJdKSk6NT09PXQmJihlJj0tNTAzMzE5MDQsZXw9MzM1NTQ0MzJ8MjU1JmkpLGV9X2V4dHJhY3RDb2xvcihlLHQsaSl7Y29uc3Qgcz1bMCwwLC0x"
    "LDAsMCwwXTtsZXQgcj0wLG49MDtkb3tpZihzW24rcl09ZS5wYXJhbXNbdCtuXSxlLmhhc1N1YlBhcmFtcyh0K24pKXtjb25zdCBpPWUuZ2V0U3ViUGFyYW1z"
    "KHQrbik7bGV0IG89MDtkb3s1PT09c1sxXSYmKHI9MSksc1tuK28rMStyXT1pW29dfXdoaWxlKCsrbzxpLmxlbmd0aCYmbytuKzErcjxzLmxlbmd0aCk7YnJl"
    "YWt9aWYoNT09PXNbMV0mJm4rcj49Mnx8Mj09PXNbMV0mJm4rcj49NSlicmVhaztzWzFdJiYocj0xKX13aGlsZSgrK24rdDxlLmxlbmd0aCYmbityPHMubGVu"
    "Z3RoKTtmb3IobGV0IGU9MjtlPHMubGVuZ3RoOysrZSktMT09PXNbZV0mJihzW2VdPTApO3N3aXRjaChzWzBdKXtjYXNlIDM4OmkuZmc9dGhpcy5fdXBkYXRl"
    "QXR0ckNvbG9yKGkuZmcsc1sxXSxzWzNdLHNbNF0sc1s1XSk7YnJlYWs7Y2FzZSA0ODppLmJnPXRoaXMuX3VwZGF0ZUF0dHJDb2xvcihpLmJnLHNbMV0sc1sz"
    "XSxzWzRdLHNbNV0pO2JyZWFrO2Nhc2UgNTg6aS5leHRlbmRlZD1pLmV4dGVuZGVkLmNsb25lKCksaS5leHRlbmRlZC51bmRlcmxpbmVDb2xvcj10aGlzLl91"
    "cGRhdGVBdHRyQ29sb3IoaS5leHRlbmRlZC51bmRlcmxpbmVDb2xvcixzWzFdLHNbM10sc1s0XSxzWzVdKX1yZXR1cm4gbn1fcHJvY2Vzc1VuZGVybGluZShl"
    "LHQpe3QuZXh0ZW5kZWQ9dC5leHRlbmRlZC5jbG9uZSgpLCghfmV8fGU+NSkmJihlPTEpLHQuZXh0ZW5kZWQudW5kZXJsaW5lU3R5bGU9ZSx0LmZnfD0yNjg0"
    "MzU0NTYsMD09PWUmJih0LmZnJj0tMjY4NDM1NDU3KSx0LnVwZGF0ZUV4dGVuZGVkKCl9X3Byb2Nlc3NTR1IwKGUpe2UuZmc9bC5ERUZBVUxUX0FUVFJfREFU"
    "QS5mZyxlLmJnPWwuREVGQVVMVF9BVFRSX0RBVEEuYmcsZS5leHRlbmRlZD1lLmV4dGVuZGVkLmNsb25lKCksZS5leHRlbmRlZC51bmRlcmxpbmVTdHlsZT0w"
    "LGUuZXh0ZW5kZWQudW5kZXJsaW5lQ29sb3ImPS02NzEwODg2NCxlLnVwZGF0ZUV4dGVuZGVkKCl9Y2hhckF0dHJpYnV0ZXMoZSl7aWYoMT09PWUubGVuZ3Ro"
    "JiYwPT09ZS5wYXJhbXNbMF0pcmV0dXJuIHRoaXMuX3Byb2Nlc3NTR1IwKHRoaXMuX2N1ckF0dHJEYXRhKSwhMDtjb25zdCB0PWUubGVuZ3RoO2xldCBpO2Nv"
    "bnN0IHM9dGhpcy5fY3VyQXR0ckRhdGE7Zm9yKGxldCByPTA7cjx0O3IrKylpPWUucGFyYW1zW3JdLGk+PTMwJiZpPD0zNz8ocy5mZyY9LTUwMzMxOTA0LHMu"
    "Zmd8PTE2Nzc3MjE2fGktMzApOmk+PTQwJiZpPD00Nz8ocy5iZyY9LTUwMzMxOTA0LHMuYmd8PTE2Nzc3MjE2fGktNDApOmk+PTkwJiZpPD05Nz8ocy5mZyY9"
    "LTUwMzMxOTA0LHMuZmd8PTE2Nzc3MjI0fGktOTApOmk+PTEwMCYmaTw9MTA3PyhzLmJnJj0tNTAzMzE5MDQscy5iZ3w9MTY3NzcyMjR8aS0xMDApOjA9PT1p"
    "P3RoaXMuX3Byb2Nlc3NTR1IwKHMpOjE9PT1pP3MuZmd8PTEzNDIxNzcyODozPT09aT9zLmJnfD02NzEwODg2NDo0PT09aT8ocy5mZ3w9MjY4NDM1NDU2LHRo"
    "aXMuX3Byb2Nlc3NVbmRlcmxpbmUoZS5oYXNTdWJQYXJhbXMocik/ZS5nZXRTdWJQYXJhbXMocilbMF06MSxzKSk6NT09PWk/cy5mZ3w9NTM2ODcwOTEyOjc9"
    "PT1pP3MuZmd8PTY3MTA4ODY0Ojg9PT1pP3MuZmd8PTEwNzM3NDE4MjQ6OT09PWk/cy5mZ3w9MjE0NzQ4MzY0ODoyPT09aT9zLmJnfD0xMzQyMTc3Mjg6MjE9"
    "PT1pP3RoaXMuX3Byb2Nlc3NVbmRlcmxpbmUoMixzKToyMj09PWk/KHMuZmcmPS0xMzQyMTc3Mjkscy5iZyY9LTEzNDIxNzcyOSk6MjM9PT1pP3MuYmcmPS02"
    "NzEwODg2NToyND09PWk/KHMuZmcmPS0yNjg0MzU0NTcsdGhpcy5fcHJvY2Vzc1VuZGVybGluZSgwLHMpKToyNT09PWk/cy5mZyY9LTUzNjg3MDkxMzoyNz09"
    "PWk/cy5mZyY9LTY3MTA4ODY1OjI4PT09aT9zLmZnJj0tMTA3Mzc0MTgyNToyOT09PWk/cy5mZyY9MjE0NzQ4MzY0NzozOT09PWk/KHMuZmcmPS02NzEwODg2"
    "NCxzLmZnfD0xNjc3NzIxNSZsLkRFRkFVTFRfQVRUUl9EQVRBLmZnKTo0OT09PWk/KHMuYmcmPS02NzEwODg2NCxzLmJnfD0xNjc3NzIxNSZsLkRFRkFVTFRf"
    "QVRUUl9EQVRBLmJnKTozOD09PWl8fDQ4PT09aXx8NTg9PT1pP3IrPXRoaXMuX2V4dHJhY3RDb2xvcihlLHIscyk6NTM9PT1pP3MuYmd8PTEwNzM3NDE4MjQ6"
    "NTU9PT1pP3MuYmcmPS0xMDczNzQxODI1OjU5PT09aT8ocy5leHRlbmRlZD1zLmV4dGVuZGVkLmNsb25lKCkscy5leHRlbmRlZC51bmRlcmxpbmVDb2xvcj0t"
    "MSxzLnVwZGF0ZUV4dGVuZGVkKCkpOjEwMD09PWk/KHMuZmcmPS02NzEwODg2NCxzLmZnfD0xNjc3NzIxNSZsLkRFRkFVTFRfQVRUUl9EQVRBLmZnLHMuYmcm"
    "PS02NzEwODg2NCxzLmJnfD0xNjc3NzIxNSZsLkRFRkFVTFRfQVRUUl9EQVRBLmJnKTp0aGlzLl9sb2dTZXJ2aWNlLmRlYnVnKCJVbmtub3duIFNHUiBhdHRy"
    "aWJ1dGU6ICVkLiIsaSk7cmV0dXJuITB9ZGV2aWNlU3RhdHVzKGUpe3N3aXRjaChlLnBhcmFtc1swXSl7Y2FzZSA1OnRoaXMuX2NvcmVTZXJ2aWNlLnRyaWdn"
    "ZXJEYXRhRXZlbnQoYCR7bi5DMC5FU0N9WzBuYCk7YnJlYWs7Y2FzZSA2OmNvbnN0IGU9dGhpcy5fYWN0aXZlQnVmZmVyLnkrMSx0PXRoaXMuX2FjdGl2ZUJ1"
    "ZmZlci54KzE7dGhpcy5fY29yZVNlcnZpY2UudHJpZ2dlckRhdGFFdmVudChgJHtuLkMwLkVTQ31bJHtlfTske3R9UmApfXJldHVybiEwfWRldmljZVN0YXR1"
    "c1ByaXZhdGUoZSl7aWYoNj09PWUucGFyYW1zWzBdKXtjb25zdCBlPXRoaXMuX2FjdGl2ZUJ1ZmZlci55KzEsdD10aGlzLl9hY3RpdmVCdWZmZXIueCsxO3Ro"
    "aXMuX2NvcmVTZXJ2aWNlLnRyaWdnZXJEYXRhRXZlbnQoYCR7bi5DMC5FU0N9Wz8ke2V9OyR7dH1SYCl9cmV0dXJuITB9c29mdFJlc2V0KGUpe3JldHVybiB0"
    "aGlzLl9jb3JlU2VydmljZS5pc0N1cnNvckhpZGRlbj0hMSx0aGlzLl9vblJlcXVlc3RTeW5jU2Nyb2xsQmFyLmZpcmUoKSx0aGlzLl9hY3RpdmVCdWZmZXIu"
    "c2Nyb2xsVG9wPTAsdGhpcy5fYWN0aXZlQnVmZmVyLnNjcm9sbEJvdHRvbT10aGlzLl9idWZmZXJTZXJ2aWNlLnJvd3MtMSx0aGlzLl9jdXJBdHRyRGF0YT1s"
    "LkRFRkFVTFRfQVRUUl9EQVRBLmNsb25lKCksdGhpcy5fY29yZVNlcnZpY2UucmVzZXQoKSx0aGlzLl9jaGFyc2V0U2VydmljZS5yZXNldCgpLHRoaXMuX2Fj"
    "dGl2ZUJ1ZmZlci5zYXZlZFg9MCx0aGlzLl9hY3RpdmVCdWZmZXIuc2F2ZWRZPXRoaXMuX2FjdGl2ZUJ1ZmZlci55YmFzZSx0aGlzLl9hY3RpdmVCdWZmZXIu"
    "c2F2ZWRDdXJBdHRyRGF0YS5mZz10aGlzLl9jdXJBdHRyRGF0YS5mZyx0aGlzLl9hY3RpdmVCdWZmZXIuc2F2ZWRDdXJBdHRyRGF0YS5iZz10aGlzLl9jdXJB"
    "dHRyRGF0YS5iZyx0aGlzLl9hY3RpdmVCdWZmZXIuc2F2ZWRDaGFyc2V0PXRoaXMuX2NoYXJzZXRTZXJ2aWNlLmNoYXJzZXQsdGhpcy5fY29yZVNlcnZpY2Uu"
    "ZGVjUHJpdmF0ZU1vZGVzLm9yaWdpbj0hMSwhMH1zZXRDdXJzb3JTdHlsZShlKXtjb25zdCB0PWUucGFyYW1zWzBdfHwxO3N3aXRjaCh0KXtjYXNlIDE6Y2Fz"
    "ZSAyOnRoaXMuX29wdGlvbnNTZXJ2aWNlLm9wdGlvbnMuY3Vyc29yU3R5bGU9ImJsb2NrIjticmVhaztjYXNlIDM6Y2FzZSA0OnRoaXMuX29wdGlvbnNTZXJ2"
    "aWNlLm9wdGlvbnMuY3Vyc29yU3R5bGU9InVuZGVybGluZSI7YnJlYWs7Y2FzZSA1OmNhc2UgNjp0aGlzLl9vcHRpb25zU2VydmljZS5vcHRpb25zLmN1cnNv"
    "clN0eWxlPSJiYXIifWNvbnN0IGk9dCUyPT0xO3JldHVybiB0aGlzLl9vcHRpb25zU2VydmljZS5vcHRpb25zLmN1cnNvckJsaW5rPWksITB9c2V0U2Nyb2xs"
    "UmVnaW9uKGUpe2NvbnN0IHQ9ZS5wYXJhbXNbMF18fDE7bGV0IGk7cmV0dXJuKGUubGVuZ3RoPDJ8fChpPWUucGFyYW1zWzFdKT50aGlzLl9idWZmZXJTZXJ2"
    "aWNlLnJvd3N8fDA9PT1pKSYmKGk9dGhpcy5fYnVmZmVyU2VydmljZS5yb3dzKSxpPnQmJih0aGlzLl9hY3RpdmVCdWZmZXIuc2Nyb2xsVG9wPXQtMSx0aGlz"
    "Ll9hY3RpdmVCdWZmZXIuc2Nyb2xsQm90dG9tPWktMSx0aGlzLl9zZXRDdXJzb3IoMCwwKSksITB9d2luZG93T3B0aW9ucyhlKXtpZighYihlLnBhcmFtc1sw"
    "XSx0aGlzLl9vcHRpb25zU2VydmljZS5yYXdPcHRpb25zLndpbmRvd09wdGlvbnMpKXJldHVybiEwO2NvbnN0IHQ9ZS5sZW5ndGg+MT9lLnBhcmFtc1sxXTow"
    "O3N3aXRjaChlLnBhcmFtc1swXSl7Y2FzZSAxNDoyIT09dCYmdGhpcy5fb25SZXF1ZXN0V2luZG93c09wdGlvbnNSZXBvcnQuZmlyZSh5LkdFVF9XSU5fU0la"
    "RV9QSVhFTFMpO2JyZWFrO2Nhc2UgMTY6dGhpcy5fb25SZXF1ZXN0V2luZG93c09wdGlvbnNSZXBvcnQuZmlyZSh5LkdFVF9DRUxMX1NJWkVfUElYRUxTKTti"
    "cmVhaztjYXNlIDE4OnRoaXMuX2J1ZmZlclNlcnZpY2UmJnRoaXMuX2NvcmVTZXJ2aWNlLnRyaWdnZXJEYXRhRXZlbnQoYCR7bi5DMC5FU0N9Wzg7JHt0aGlz"
    "Ll9idWZmZXJTZXJ2aWNlLnJvd3N9OyR7dGhpcy5fYnVmZmVyU2VydmljZS5jb2xzfXRgKTticmVhaztjYXNlIDIyOjAhPT10JiYyIT09dHx8KHRoaXMuX3dp"
    "bmRvd1RpdGxlU3RhY2sucHVzaCh0aGlzLl93aW5kb3dUaXRsZSksdGhpcy5fd2luZG93VGl0bGVTdGFjay5sZW5ndGg+MTAmJnRoaXMuX3dpbmRvd1RpdGxl"
    "U3RhY2suc2hpZnQoKSksMCE9PXQmJjEhPT10fHwodGhpcy5faWNvbk5hbWVTdGFjay5wdXNoKHRoaXMuX2ljb25OYW1lKSx0aGlzLl9pY29uTmFtZVN0YWNr"
    "Lmxlbmd0aD4xMCYmdGhpcy5faWNvbk5hbWVTdGFjay5zaGlmdCgpKTticmVhaztjYXNlIDIzOjAhPT10JiYyIT09dHx8dGhpcy5fd2luZG93VGl0bGVTdGFj"
    "ay5sZW5ndGgmJnRoaXMuc2V0VGl0bGUodGhpcy5fd2luZG93VGl0bGVTdGFjay5wb3AoKSksMCE9PXQmJjEhPT10fHx0aGlzLl9pY29uTmFtZVN0YWNrLmxl"
    "bmd0aCYmdGhpcy5zZXRJY29uTmFtZSh0aGlzLl9pY29uTmFtZVN0YWNrLnBvcCgpKX1yZXR1cm4hMH1zYXZlQ3Vyc29yKGUpe3JldHVybiB0aGlzLl9hY3Rp"
    "dmVCdWZmZXIuc2F2ZWRYPXRoaXMuX2FjdGl2ZUJ1ZmZlci54LHRoaXMuX2FjdGl2ZUJ1ZmZlci5zYXZlZFk9dGhpcy5fYWN0aXZlQnVmZmVyLnliYXNlK3Ro"
    "aXMuX2FjdGl2ZUJ1ZmZlci55LHRoaXMuX2FjdGl2ZUJ1ZmZlci5zYXZlZEN1ckF0dHJEYXRhLmZnPXRoaXMuX2N1ckF0dHJEYXRhLmZnLHRoaXMuX2FjdGl2"
    "ZUJ1ZmZlci5zYXZlZEN1ckF0dHJEYXRhLmJnPXRoaXMuX2N1ckF0dHJEYXRhLmJnLHRoaXMuX2FjdGl2ZUJ1ZmZlci5zYXZlZENoYXJzZXQ9dGhpcy5fY2hh"
    "cnNldFNlcnZpY2UuY2hhcnNldCwhMH1yZXN0b3JlQ3Vyc29yKGUpe3JldHVybiB0aGlzLl9hY3RpdmVCdWZmZXIueD10aGlzLl9hY3RpdmVCdWZmZXIuc2F2"
    "ZWRYfHwwLHRoaXMuX2FjdGl2ZUJ1ZmZlci55PU1hdGgubWF4KHRoaXMuX2FjdGl2ZUJ1ZmZlci5zYXZlZFktdGhpcy5fYWN0aXZlQnVmZmVyLnliYXNlLDAp"
    "LHRoaXMuX2N1ckF0dHJEYXRhLmZnPXRoaXMuX2FjdGl2ZUJ1ZmZlci5zYXZlZEN1ckF0dHJEYXRhLmZnLHRoaXMuX2N1ckF0dHJEYXRhLmJnPXRoaXMuX2Fj"
    "dGl2ZUJ1ZmZlci5zYXZlZEN1ckF0dHJEYXRhLmJnLHRoaXMuX2NoYXJzZXRTZXJ2aWNlLmNoYXJzZXQ9dGhpcy5fc2F2ZWRDaGFyc2V0LHRoaXMuX2FjdGl2"
    "ZUJ1ZmZlci5zYXZlZENoYXJzZXQmJih0aGlzLl9jaGFyc2V0U2VydmljZS5jaGFyc2V0PXRoaXMuX2FjdGl2ZUJ1ZmZlci5zYXZlZENoYXJzZXQpLHRoaXMu"
    "X3Jlc3RyaWN0Q3Vyc29yKCksITB9c2V0VGl0bGUoZSl7cmV0dXJuIHRoaXMuX3dpbmRvd1RpdGxlPWUsdGhpcy5fb25UaXRsZUNoYW5nZS5maXJlKGUpLCEw"
    "fXNldEljb25OYW1lKGUpe3JldHVybiB0aGlzLl9pY29uTmFtZT1lLCEwfXNldE9yUmVwb3J0SW5kZXhlZENvbG9yKGUpe2NvbnN0IHQ9W10saT1lLnNwbGl0"
    "KCI7Iik7Zm9yKDtpLmxlbmd0aD4xOyl7Y29uc3QgZT1pLnNoaWZ0KCkscz1pLnNoaWZ0KCk7aWYoL15cZCskLy5leGVjKGUpKXtjb25zdCBpPXBhcnNlSW50"
    "KGUpO2lmKEwoaSkpaWYoIj8iPT09cyl0LnB1c2goe3R5cGU6MCxpbmRleDppfSk7ZWxzZXtjb25zdCBlPSgwLG0ucGFyc2VDb2xvcikocyk7ZSYmdC5wdXNo"
    "KHt0eXBlOjEsaW5kZXg6aSxjb2xvcjplfSl9fX1yZXR1cm4gdC5sZW5ndGgmJnRoaXMuX29uQ29sb3IuZmlyZSh0KSwhMH1zZXRIeXBlcmxpbmsoZSl7Y29u"
    "c3QgdD1lLnNwbGl0KCI7Iik7cmV0dXJuISh0Lmxlbmd0aDwyKSYmKHRbMV0/dGhpcy5fY3JlYXRlSHlwZXJsaW5rKHRbMF0sdFsxXSk6IXRbMF0mJnRoaXMu"
    "X2ZpbmlzaEh5cGVybGluaygpKX1fY3JlYXRlSHlwZXJsaW5rKGUsdCl7dGhpcy5fZ2V0Q3VycmVudExpbmtJZCgpJiZ0aGlzLl9maW5pc2hIeXBlcmxpbmso"
    "KTtjb25zdCBpPWUuc3BsaXQoIjoiKTtsZXQgcztjb25zdCByPWkuZmluZEluZGV4KChlPT5lLnN0YXJ0c1dpdGgoImlkPSIpKSk7cmV0dXJuLTEhPT1yJiYo"
    "cz1pW3JdLnNsaWNlKDMpfHx2b2lkIDApLHRoaXMuX2N1ckF0dHJEYXRhLmV4dGVuZGVkPXRoaXMuX2N1ckF0dHJEYXRhLmV4dGVuZGVkLmNsb25lKCksdGhp"
    "cy5fY3VyQXR0ckRhdGEuZXh0ZW5kZWQudXJsSWQ9dGhpcy5fb3NjTGlua1NlcnZpY2UucmVnaXN0ZXJMaW5rKHtpZDpzLHVyaTp0fSksdGhpcy5fY3VyQXR0"
    "ckRhdGEudXBkYXRlRXh0ZW5kZWQoKSwhMH1fZmluaXNoSHlwZXJsaW5rKCl7cmV0dXJuIHRoaXMuX2N1ckF0dHJEYXRhLmV4dGVuZGVkPXRoaXMuX2N1ckF0"
    "dHJEYXRhLmV4dGVuZGVkLmNsb25lKCksdGhpcy5fY3VyQXR0ckRhdGEuZXh0ZW5kZWQudXJsSWQ9MCx0aGlzLl9jdXJBdHRyRGF0YS51cGRhdGVFeHRlbmRl"
    "ZCgpLCEwfV9zZXRPclJlcG9ydFNwZWNpYWxDb2xvcihlLHQpe2NvbnN0IGk9ZS5zcGxpdCgiOyIpO2ZvcihsZXQgZT0wO2U8aS5sZW5ndGgmJiEodD49dGhp"
    "cy5fc3BlY2lhbENvbG9ycy5sZW5ndGgpOysrZSwrK3QpaWYoIj8iPT09aVtlXSl0aGlzLl9vbkNvbG9yLmZpcmUoW3t0eXBlOjAsaW5kZXg6dGhpcy5fc3Bl"
    "Y2lhbENvbG9yc1t0XX1dKTtlbHNle2NvbnN0IHM9KDAsbS5wYXJzZUNvbG9yKShpW2VdKTtzJiZ0aGlzLl9vbkNvbG9yLmZpcmUoW3t0eXBlOjEsaW5kZXg6"
    "dGhpcy5fc3BlY2lhbENvbG9yc1t0XSxjb2xvcjpzfV0pfXJldHVybiEwfXNldE9yUmVwb3J0RmdDb2xvcihlKXtyZXR1cm4gdGhpcy5fc2V0T3JSZXBvcnRT"
    "cGVjaWFsQ29sb3IoZSwwKX1zZXRPclJlcG9ydEJnQ29sb3IoZSl7cmV0dXJuIHRoaXMuX3NldE9yUmVwb3J0U3BlY2lhbENvbG9yKGUsMSl9c2V0T3JSZXBv"
    "cnRDdXJzb3JDb2xvcihlKXtyZXR1cm4gdGhpcy5fc2V0T3JSZXBvcnRTcGVjaWFsQ29sb3IoZSwyKX1yZXN0b3JlSW5kZXhlZENvbG9yKGUpe2lmKCFlKXJl"
    "dHVybiB0aGlzLl9vbkNvbG9yLmZpcmUoW3t0eXBlOjJ9XSksITA7Y29uc3QgdD1bXSxpPWUuc3BsaXQoIjsiKTtmb3IobGV0IGU9MDtlPGkubGVuZ3RoOysr"
    "ZSlpZigvXlxkKyQvLmV4ZWMoaVtlXSkpe2NvbnN0IHM9cGFyc2VJbnQoaVtlXSk7TChzKSYmdC5wdXNoKHt0eXBlOjIsaW5kZXg6c30pfXJldHVybiB0Lmxl"
    "bmd0aCYmdGhpcy5fb25Db2xvci5maXJlKHQpLCEwfXJlc3RvcmVGZ0NvbG9yKGUpe3JldHVybiB0aGlzLl9vbkNvbG9yLmZpcmUoW3t0eXBlOjIsaW5kZXg6"
    "MjU2fV0pLCEwfXJlc3RvcmVCZ0NvbG9yKGUpe3JldHVybiB0aGlzLl9vbkNvbG9yLmZpcmUoW3t0eXBlOjIsaW5kZXg6MjU3fV0pLCEwfXJlc3RvcmVDdXJz"
    "b3JDb2xvcihlKXtyZXR1cm4gdGhpcy5fb25Db2xvci5maXJlKFt7dHlwZToyLGluZGV4OjI1OH1dKSwhMH1uZXh0TGluZSgpe3JldHVybiB0aGlzLl9hY3Rp"
    "dmVCdWZmZXIueD0wLHRoaXMuaW5kZXgoKSwhMH1rZXlwYWRBcHBsaWNhdGlvbk1vZGUoKXtyZXR1cm4gdGhpcy5fbG9nU2VydmljZS5kZWJ1ZygiU2VyaWFs"
    "IHBvcnQgcmVxdWVzdGVkIGFwcGxpY2F0aW9uIGtleXBhZC4iKSx0aGlzLl9jb3JlU2VydmljZS5kZWNQcml2YXRlTW9kZXMuYXBwbGljYXRpb25LZXlwYWQ9"
    "ITAsdGhpcy5fb25SZXF1ZXN0U3luY1Njcm9sbEJhci5maXJlKCksITB9a2V5cGFkTnVtZXJpY01vZGUoKXtyZXR1cm4gdGhpcy5fbG9nU2VydmljZS5kZWJ1"
    "ZygiU3dpdGNoaW5nIGJhY2sgdG8gbm9ybWFsIGtleXBhZC4iKSx0aGlzLl9jb3JlU2VydmljZS5kZWNQcml2YXRlTW9kZXMuYXBwbGljYXRpb25LZXlwYWQ9"
    "ITEsdGhpcy5fb25SZXF1ZXN0U3luY1Njcm9sbEJhci5maXJlKCksITB9c2VsZWN0RGVmYXVsdENoYXJzZXQoKXtyZXR1cm4gdGhpcy5fY2hhcnNldFNlcnZp"
    "Y2Uuc2V0Z0xldmVsKDApLHRoaXMuX2NoYXJzZXRTZXJ2aWNlLnNldGdDaGFyc2V0KDAsby5ERUZBVUxUX0NIQVJTRVQpLCEwfXNlbGVjdENoYXJzZXQoZSl7"
    "cmV0dXJuIDIhPT1lLmxlbmd0aD8odGhpcy5zZWxlY3REZWZhdWx0Q2hhcnNldCgpLCEwKTooIi8iPT09ZVswXXx8dGhpcy5fY2hhcnNldFNlcnZpY2Uuc2V0"
    "Z0NoYXJzZXQoU1tlWzBdXSxvLkNIQVJTRVRTW2VbMV1dfHxvLkRFRkFVTFRfQ0hBUlNFVCksITApfWluZGV4KCl7cmV0dXJuIHRoaXMuX3Jlc3RyaWN0Q3Vy"
    "c29yKCksdGhpcy5fYWN0aXZlQnVmZmVyLnkrKyx0aGlzLl9hY3RpdmVCdWZmZXIueT09PXRoaXMuX2FjdGl2ZUJ1ZmZlci5zY3JvbGxCb3R0b20rMT8odGhp"
    "cy5fYWN0aXZlQnVmZmVyLnktLSx0aGlzLl9idWZmZXJTZXJ2aWNlLnNjcm9sbCh0aGlzLl9lcmFzZUF0dHJEYXRhKCkpKTp0aGlzLl9hY3RpdmVCdWZmZXIu"
    "eT49dGhpcy5fYnVmZmVyU2VydmljZS5yb3dzJiYodGhpcy5fYWN0aXZlQnVmZmVyLnk9dGhpcy5fYnVmZmVyU2VydmljZS5yb3dzLTEpLHRoaXMuX3Jlc3Ry"
    "aWN0Q3Vyc29yKCksITB9dGFiU2V0KCl7cmV0dXJuIHRoaXMuX2FjdGl2ZUJ1ZmZlci50YWJzW3RoaXMuX2FjdGl2ZUJ1ZmZlci54XT0hMCwhMH1yZXZlcnNl"
    "SW5kZXgoKXtpZih0aGlzLl9yZXN0cmljdEN1cnNvcigpLHRoaXMuX2FjdGl2ZUJ1ZmZlci55PT09dGhpcy5fYWN0aXZlQnVmZmVyLnNjcm9sbFRvcCl7Y29u"
    "c3QgZT10aGlzLl9hY3RpdmVCdWZmZXIuc2Nyb2xsQm90dG9tLXRoaXMuX2FjdGl2ZUJ1ZmZlci5zY3JvbGxUb3A7dGhpcy5fYWN0aXZlQnVmZmVyLmxpbmVz"
    "LnNoaWZ0RWxlbWVudHModGhpcy5fYWN0aXZlQnVmZmVyLnliYXNlK3RoaXMuX2FjdGl2ZUJ1ZmZlci55LGUsMSksdGhpcy5fYWN0aXZlQnVmZmVyLmxpbmVz"
    "LnNldCh0aGlzLl9hY3RpdmVCdWZmZXIueWJhc2UrdGhpcy5fYWN0aXZlQnVmZmVyLnksdGhpcy5fYWN0aXZlQnVmZmVyLmdldEJsYW5rTGluZSh0aGlzLl9l"
    "cmFzZUF0dHJEYXRhKCkpKSx0aGlzLl9kaXJ0eVJvd1RyYWNrZXIubWFya1JhbmdlRGlydHkodGhpcy5fYWN0aXZlQnVmZmVyLnNjcm9sbFRvcCx0aGlzLl9h"
    "Y3RpdmVCdWZmZXIuc2Nyb2xsQm90dG9tKX1lbHNlIHRoaXMuX2FjdGl2ZUJ1ZmZlci55LS0sdGhpcy5fcmVzdHJpY3RDdXJzb3IoKTtyZXR1cm4hMH1mdWxs"
    "UmVzZXQoKXtyZXR1cm4gdGhpcy5fcGFyc2VyLnJlc2V0KCksdGhpcy5fb25SZXF1ZXN0UmVzZXQuZmlyZSgpLCEwfXJlc2V0KCl7dGhpcy5fY3VyQXR0ckRh"
    "dGE9bC5ERUZBVUxUX0FUVFJfREFUQS5jbG9uZSgpLHRoaXMuX2VyYXNlQXR0ckRhdGFJbnRlcm5hbD1sLkRFRkFVTFRfQVRUUl9EQVRBLmNsb25lKCl9X2Vy"
    "YXNlQXR0ckRhdGEoKXtyZXR1cm4gdGhpcy5fZXJhc2VBdHRyRGF0YUludGVybmFsLmJnJj0tNjcxMDg4NjQsdGhpcy5fZXJhc2VBdHRyRGF0YUludGVybmFs"
    "LmJnfD02NzEwODg2MyZ0aGlzLl9jdXJBdHRyRGF0YS5iZyx0aGlzLl9lcmFzZUF0dHJEYXRhSW50ZXJuYWx9c2V0Z0xldmVsKGUpe3JldHVybiB0aGlzLl9j"
    "aGFyc2V0U2VydmljZS5zZXRnTGV2ZWwoZSksITB9c2NyZWVuQWxpZ25tZW50UGF0dGVybigpe2NvbnN0IGU9bmV3IHUuQ2VsbERhdGE7ZS5jb250ZW50PTE8"
    "PDIyfCJFIi5jaGFyQ29kZUF0KDApLGUuZmc9dGhpcy5fY3VyQXR0ckRhdGEuZmcsZS5iZz10aGlzLl9jdXJBdHRyRGF0YS5iZyx0aGlzLl9zZXRDdXJzb3Io"
    "MCwwKTtmb3IobGV0IHQ9MDt0PHRoaXMuX2J1ZmZlclNlcnZpY2Uucm93czsrK3Qpe2NvbnN0IGk9dGhpcy5fYWN0aXZlQnVmZmVyLnliYXNlK3RoaXMuX2Fj"
    "dGl2ZUJ1ZmZlci55K3Qscz10aGlzLl9hY3RpdmVCdWZmZXIubGluZXMuZ2V0KGkpO3MmJihzLmZpbGwoZSkscy5pc1dyYXBwZWQ9ITEpfXJldHVybiB0aGlz"
    "Ll9kaXJ0eVJvd1RyYWNrZXIubWFya0FsbERpcnR5KCksdGhpcy5fc2V0Q3Vyc29yKDAsMCksITB9cmVxdWVzdFN0YXR1c1N0cmluZyhlLHQpe2NvbnN0IGk9"
    "dGhpcy5fYnVmZmVyU2VydmljZS5idWZmZXIscz10aGlzLl9vcHRpb25zU2VydmljZS5yYXdPcHRpb25zO3JldHVybihlPT4odGhpcy5fY29yZVNlcnZpY2Uu"
    "dHJpZ2dlckRhdGFFdmVudChgJHtuLkMwLkVTQ30ke2V9JHtuLkMwLkVTQ31cXGApLCEwKSkoJyJxJz09PWU/YFAxJHIke3RoaXMuX2N1ckF0dHJEYXRhLmlz"
    "UHJvdGVjdGVkKCk/MTowfSJxYDonInAnPT09ZT8nUDEkcjYxOzEicCc6InIiPT09ZT9gUDEkciR7aS5zY3JvbGxUb3ArMX07JHtpLnNjcm9sbEJvdHRvbSsx"
    "fXJgOiJtIj09PWU/IlAxJHIwbSI6IiBxIj09PWU/YFAxJHIke3tibG9jazoyLHVuZGVybGluZTo0LGJhcjo2fVtzLmN1cnNvclN0eWxlXS0ocy5jdXJzb3JC"
    "bGluaz8xOjApfSBxYDoiUDAkciIpfW1hcmtSYW5nZURpcnR5KGUsdCl7dGhpcy5fZGlydHlSb3dUcmFja2VyLm1hcmtSYW5nZURpcnR5KGUsdCl9fXQuSW5w"
    "dXRIYW5kbGVyPUU7bGV0IGs9Y2xhc3N7Y29uc3RydWN0b3IoZSl7dGhpcy5fYnVmZmVyU2VydmljZT1lLHRoaXMuY2xlYXJSYW5nZSgpfWNsZWFyUmFuZ2Uo"
    "KXt0aGlzLnN0YXJ0PXRoaXMuX2J1ZmZlclNlcnZpY2UuYnVmZmVyLnksdGhpcy5lbmQ9dGhpcy5fYnVmZmVyU2VydmljZS5idWZmZXIueX1tYXJrRGlydHko"
    "ZSl7ZTx0aGlzLnN0YXJ0P3RoaXMuc3RhcnQ9ZTplPnRoaXMuZW5kJiYodGhpcy5lbmQ9ZSl9bWFya1JhbmdlRGlydHkoZSx0KXtlPnQmJih3PWUsZT10LHQ9"
    "dyksZTx0aGlzLnN0YXJ0JiYodGhpcy5zdGFydD1lKSx0PnRoaXMuZW5kJiYodGhpcy5lbmQ9dCl9bWFya0FsbERpcnR5KCl7dGhpcy5tYXJrUmFuZ2VEaXJ0"
    "eSgwLHRoaXMuX2J1ZmZlclNlcnZpY2Uucm93cy0xKX19O2Z1bmN0aW9uIEwoZSl7cmV0dXJuIDA8PWUmJmU8MjU2fWs9cyhbcigwLHYuSUJ1ZmZlclNlcnZp"
    "Y2UpXSxrKX0sODQ0OihlLHQpPT57ZnVuY3Rpb24gaShlKXtmb3IoY29uc3QgdCBvZiBlKXQuZGlzcG9zZSgpO2UubGVuZ3RoPTB9T2JqZWN0LmRlZmluZVBy"
    "b3BlcnR5KHQsIl9fZXNNb2R1bGUiLHt2YWx1ZTohMH0pLHQuZ2V0RGlzcG9zZUFycmF5RGlzcG9zYWJsZT10LmRpc3Bvc2VBcnJheT10LnRvRGlzcG9zYWJs"
    "ZT10Lk11dGFibGVEaXNwb3NhYmxlPXQuRGlzcG9zYWJsZT12b2lkIDAsdC5EaXNwb3NhYmxlPWNsYXNze2NvbnN0cnVjdG9yKCl7dGhpcy5fZGlzcG9zYWJs"
    "ZXM9W10sdGhpcy5faXNEaXNwb3NlZD0hMX1kaXNwb3NlKCl7dGhpcy5faXNEaXNwb3NlZD0hMDtmb3IoY29uc3QgZSBvZiB0aGlzLl9kaXNwb3NhYmxlcyll"
    "LmRpc3Bvc2UoKTt0aGlzLl9kaXNwb3NhYmxlcy5sZW5ndGg9MH1yZWdpc3RlcihlKXtyZXR1cm4gdGhpcy5fZGlzcG9zYWJsZXMucHVzaChlKSxlfXVucmVn"
    "aXN0ZXIoZSl7Y29uc3QgdD10aGlzLl9kaXNwb3NhYmxlcy5pbmRleE9mKGUpOy0xIT09dCYmdGhpcy5fZGlzcG9zYWJsZXMuc3BsaWNlKHQsMSl9fSx0Lk11"
    "dGFibGVEaXNwb3NhYmxlPWNsYXNze2NvbnN0cnVjdG9yKCl7dGhpcy5faXNEaXNwb3NlZD0hMX1nZXQgdmFsdWUoKXtyZXR1cm4gdGhpcy5faXNEaXNwb3Nl"
    "ZD92b2lkIDA6dGhpcy5fdmFsdWV9c2V0IHZhbHVlKGUpe3ZhciB0O3RoaXMuX2lzRGlzcG9zZWR8fGU9PT10aGlzLl92YWx1ZXx8KG51bGw9PT0odD10aGlz"
    "Ll92YWx1ZSl8fHZvaWQgMD09PXR8fHQuZGlzcG9zZSgpLHRoaXMuX3ZhbHVlPWUpfWNsZWFyKCl7dGhpcy52YWx1ZT12b2lkIDB9ZGlzcG9zZSgpe3ZhciBl"
    "O3RoaXMuX2lzRGlzcG9zZWQ9ITAsbnVsbD09PShlPXRoaXMuX3ZhbHVlKXx8dm9pZCAwPT09ZXx8ZS5kaXNwb3NlKCksdGhpcy5fdmFsdWU9dm9pZCAwfX0s"
    "dC50b0Rpc3Bvc2FibGU9ZnVuY3Rpb24oZSl7cmV0dXJue2Rpc3Bvc2U6ZX19LHQuZGlzcG9zZUFycmF5PWksdC5nZXREaXNwb3NlQXJyYXlEaXNwb3NhYmxl"
    "PWZ1bmN0aW9uKGUpe3JldHVybntkaXNwb3NlOigpPT5pKGUpfX19LDE1MDU6KGUsdCk9PntPYmplY3QuZGVmaW5lUHJvcGVydHkodCwiX19lc01vZHVsZSIs"
    "e3ZhbHVlOiEwfSksdC5Gb3VyS2V5TWFwPXQuVHdvS2V5TWFwPXZvaWQgMDtjbGFzcyBpe2NvbnN0cnVjdG9yKCl7dGhpcy5fZGF0YT17fX1zZXQoZSx0LGkp"
    "e3RoaXMuX2RhdGFbZV18fCh0aGlzLl9kYXRhW2VdPXt9KSx0aGlzLl9kYXRhW2VdW3RdPWl9Z2V0KGUsdCl7cmV0dXJuIHRoaXMuX2RhdGFbZV0/dGhpcy5f"
    "ZGF0YVtlXVt0XTp2b2lkIDB9Y2xlYXIoKXt0aGlzLl9kYXRhPXt9fX10LlR3b0tleU1hcD1pLHQuRm91cktleU1hcD1jbGFzc3tjb25zdHJ1Y3Rvcigpe3Ro"
    "aXMuX2RhdGE9bmV3IGl9c2V0KGUsdCxzLHIsbil7dGhpcy5fZGF0YS5nZXQoZSx0KXx8dGhpcy5fZGF0YS5zZXQoZSx0LG5ldyBpKSx0aGlzLl9kYXRhLmdl"
    "dChlLHQpLnNldChzLHIsbil9Z2V0KGUsdCxpLHMpe3ZhciByO3JldHVybiBudWxsPT09KHI9dGhpcy5fZGF0YS5nZXQoZSx0KSl8fHZvaWQgMD09PXI/dm9p"
    "ZCAwOnIuZ2V0KGkscyl9Y2xlYXIoKXt0aGlzLl9kYXRhLmNsZWFyKCl9fX0sNjExNDooZSx0KT0+e09iamVjdC5kZWZpbmVQcm9wZXJ0eSh0LCJfX2VzTW9k"
    "dWxlIix7dmFsdWU6ITB9KSx0LmlzQ2hyb21lT1M9dC5pc0xpbnV4PXQuaXNXaW5kb3dzPXQuaXNJcGhvbmU9dC5pc0lwYWQ9dC5pc01hYz10LmdldFNhZmFy"
    "aVZlcnNpb249dC5pc1NhZmFyaT10LmlzTGVnYWN5RWRnZT10LmlzRmlyZWZveD10LmlzTm9kZT12b2lkIDAsdC5pc05vZGU9InVuZGVmaW5lZCI9PXR5cGVv"
    "ZiBuYXZpZ2F0b3I7Y29uc3QgaT10LmlzTm9kZT8ibm9kZSI6bmF2aWdhdG9yLnVzZXJBZ2VudCxzPXQuaXNOb2RlPyJub2RlIjpuYXZpZ2F0b3IucGxhdGZv"
    "cm07dC5pc0ZpcmVmb3g9aS5pbmNsdWRlcygiRmlyZWZveCIpLHQuaXNMZWdhY3lFZGdlPWkuaW5jbHVkZXMoIkVkZ2UiKSx0LmlzU2FmYXJpPS9eKCg/IWNo"
    "cm9tZXxhbmRyb2lkKS4pKnNhZmFyaS9pLnRlc3QoaSksdC5nZXRTYWZhcmlWZXJzaW9uPWZ1bmN0aW9uKCl7aWYoIXQuaXNTYWZhcmkpcmV0dXJuIDA7Y29u"
    "c3QgZT1pLm1hdGNoKC9WZXJzaW9uXC8oXGQrKS8pO3JldHVybiBudWxsPT09ZXx8ZS5sZW5ndGg8Mj8wOnBhcnNlSW50KGVbMV0pfSx0LmlzTWFjPVsiTWFj"
    "aW50b3NoIiwiTWFjSW50ZWwiLCJNYWNQUEMiLCJNYWM2OEsiXS5pbmNsdWRlcyhzKSx0LmlzSXBhZD0iaVBhZCI9PT1zLHQuaXNJcGhvbmU9ImlQaG9uZSI9"
    "PT1zLHQuaXNXaW5kb3dzPVsiV2luZG93cyIsIldpbjE2IiwiV2luMzIiLCJXaW5DRSJdLmluY2x1ZGVzKHMpLHQuaXNMaW51eD1zLmluZGV4T2YoIkxpbnV4"
    "Iik+PTAsdC5pc0Nocm9tZU9TPS9cYkNyT1NcYi8udGVzdChpKX0sNjEwNjooZSx0KT0+e09iamVjdC5kZWZpbmVQcm9wZXJ0eSh0LCJfX2VzTW9kdWxlIix7"
    "dmFsdWU6ITB9KSx0LlNvcnRlZExpc3Q9dm9pZCAwO2xldCBpPTA7dC5Tb3J0ZWRMaXN0PWNsYXNze2NvbnN0cnVjdG9yKGUpe3RoaXMuX2dldEtleT1lLHRo"
    "aXMuX2FycmF5PVtdfWNsZWFyKCl7dGhpcy5fYXJyYXkubGVuZ3RoPTB9aW5zZXJ0KGUpezAhPT10aGlzLl9hcnJheS5sZW5ndGg/KGk9dGhpcy5fc2VhcmNo"
    "KHRoaXMuX2dldEtleShlKSksdGhpcy5fYXJyYXkuc3BsaWNlKGksMCxlKSk6dGhpcy5fYXJyYXkucHVzaChlKX1kZWxldGUoZSl7aWYoMD09PXRoaXMuX2Fy"
    "cmF5Lmxlbmd0aClyZXR1cm4hMTtjb25zdCB0PXRoaXMuX2dldEtleShlKTtpZih2b2lkIDA9PT10KXJldHVybiExO2lmKGk9dGhpcy5fc2VhcmNoKHQpLC0x"
    "PT09aSlyZXR1cm4hMTtpZih0aGlzLl9nZXRLZXkodGhpcy5fYXJyYXlbaV0pIT09dClyZXR1cm4hMTtkb3tpZih0aGlzLl9hcnJheVtpXT09PWUpcmV0dXJu"
    "IHRoaXMuX2FycmF5LnNwbGljZShpLDEpLCEwfXdoaWxlKCsraTx0aGlzLl9hcnJheS5sZW5ndGgmJnRoaXMuX2dldEtleSh0aGlzLl9hcnJheVtpXSk9PT10"
    "KTtyZXR1cm4hMX0qZ2V0S2V5SXRlcmF0b3IoZSl7aWYoMCE9PXRoaXMuX2FycmF5Lmxlbmd0aCYmKGk9dGhpcy5fc2VhcmNoKGUpLCEoaTwwfHxpPj10aGlz"
    "Ll9hcnJheS5sZW5ndGgpJiZ0aGlzLl9nZXRLZXkodGhpcy5fYXJyYXlbaV0pPT09ZSkpZG97eWllbGQgdGhpcy5fYXJyYXlbaV19d2hpbGUoKytpPHRoaXMu"
    "X2FycmF5Lmxlbmd0aCYmdGhpcy5fZ2V0S2V5KHRoaXMuX2FycmF5W2ldKT09PWUpfWZvckVhY2hCeUtleShlLHQpe2lmKDAhPT10aGlzLl9hcnJheS5sZW5n"
    "dGgmJihpPXRoaXMuX3NlYXJjaChlKSwhKGk8MHx8aT49dGhpcy5fYXJyYXkubGVuZ3RoKSYmdGhpcy5fZ2V0S2V5KHRoaXMuX2FycmF5W2ldKT09PWUpKWRv"
    "e3QodGhpcy5fYXJyYXlbaV0pfXdoaWxlKCsraTx0aGlzLl9hcnJheS5sZW5ndGgmJnRoaXMuX2dldEtleSh0aGlzLl9hcnJheVtpXSk9PT1lKX12YWx1ZXMo"
    "KXtyZXR1cm5bLi4udGhpcy5fYXJyYXldLnZhbHVlcygpfV9zZWFyY2goZSl7bGV0IHQ9MCxpPXRoaXMuX2FycmF5Lmxlbmd0aC0xO2Zvcig7aT49dDspe2xl"
    "dCBzPXQraT4+MTtjb25zdCByPXRoaXMuX2dldEtleSh0aGlzLl9hcnJheVtzXSk7aWYocj5lKWk9cy0xO2Vsc2V7aWYoIShyPGUpKXtmb3IoO3M+MCYmdGhp"
    "cy5fZ2V0S2V5KHRoaXMuX2FycmF5W3MtMV0pPT09ZTspcy0tO3JldHVybiBzfXQ9cysxfX1yZXR1cm4gdH19fSw3MjI2OihlLHQsaSk9PntPYmplY3QuZGVm"
    "aW5lUHJvcGVydHkodCwiX19lc01vZHVsZSIse3ZhbHVlOiEwfSksdC5EZWJvdW5jZWRJZGxlVGFzaz10LklkbGVUYXNrUXVldWU9dC5Qcmlvcml0eVRhc2tR"
    "dWV1ZT12b2lkIDA7Y29uc3Qgcz1pKDYxMTQpO2NsYXNzIHJ7Y29uc3RydWN0b3IoKXt0aGlzLl90YXNrcz1bXSx0aGlzLl9pPTB9ZW5xdWV1ZShlKXt0aGlz"
    "Ll90YXNrcy5wdXNoKGUpLHRoaXMuX3N0YXJ0KCl9Zmx1c2goKXtmb3IoO3RoaXMuX2k8dGhpcy5fdGFza3MubGVuZ3RoOyl0aGlzLl90YXNrc1t0aGlzLl9p"
    "XSgpfHx0aGlzLl9pKys7dGhpcy5jbGVhcigpfWNsZWFyKCl7dGhpcy5faWRsZUNhbGxiYWNrJiYodGhpcy5fY2FuY2VsQ2FsbGJhY2sodGhpcy5faWRsZUNh"
    "bGxiYWNrKSx0aGlzLl9pZGxlQ2FsbGJhY2s9dm9pZCAwKSx0aGlzLl9pPTAsdGhpcy5fdGFza3MubGVuZ3RoPTB9X3N0YXJ0KCl7dGhpcy5faWRsZUNhbGxi"
    "YWNrfHwodGhpcy5faWRsZUNhbGxiYWNrPXRoaXMuX3JlcXVlc3RDYWxsYmFjayh0aGlzLl9wcm9jZXNzLmJpbmQodGhpcykpKX1fcHJvY2VzcyhlKXt0aGlz"
    "Ll9pZGxlQ2FsbGJhY2s9dm9pZCAwO2xldCB0PTAsaT0wLHM9ZS50aW1lUmVtYWluaW5nKCkscj0wO2Zvcig7dGhpcy5faTx0aGlzLl90YXNrcy5sZW5ndGg7"
    "KXtpZih0PURhdGUubm93KCksdGhpcy5fdGFza3NbdGhpcy5faV0oKXx8dGhpcy5faSsrLHQ9TWF0aC5tYXgoMSxEYXRlLm5vdygpLXQpLGk9TWF0aC5tYXgo"
    "dCxpKSxyPWUudGltZVJlbWFpbmluZygpLDEuNSppPnIpcmV0dXJuIHMtdDwtMjAmJmNvbnNvbGUud2FybihgdGFzayBxdWV1ZSBleGNlZWRlZCBhbGxvdHRl"
    "ZCBkZWFkbGluZSBieSAke01hdGguYWJzKE1hdGgucm91bmQocy10KSl9bXNgKSx2b2lkIHRoaXMuX3N0YXJ0KCk7cz1yfXRoaXMuY2xlYXIoKX19Y2xhc3Mg"
    "biBleHRlbmRzIHJ7X3JlcXVlc3RDYWxsYmFjayhlKXtyZXR1cm4gc2V0VGltZW91dCgoKCk9PmUodGhpcy5fY3JlYXRlRGVhZGxpbmUoMTYpKSkpfV9jYW5j"
    "ZWxDYWxsYmFjayhlKXtjbGVhclRpbWVvdXQoZSl9X2NyZWF0ZURlYWRsaW5lKGUpe2NvbnN0IHQ9RGF0ZS5ub3coKStlO3JldHVybnt0aW1lUmVtYWluaW5n"
    "OigpPT5NYXRoLm1heCgwLHQtRGF0ZS5ub3coKSl9fX10LlByaW9yaXR5VGFza1F1ZXVlPW4sdC5JZGxlVGFza1F1ZXVlPSFzLmlzTm9kZSYmInJlcXVlc3RJ"
    "ZGxlQ2FsbGJhY2siaW4gd2luZG93P2NsYXNzIGV4dGVuZHMgcntfcmVxdWVzdENhbGxiYWNrKGUpe3JldHVybiByZXF1ZXN0SWRsZUNhbGxiYWNrKGUpfV9j"
    "YW5jZWxDYWxsYmFjayhlKXtjYW5jZWxJZGxlQ2FsbGJhY2soZSl9fTpuLHQuRGVib3VuY2VkSWRsZVRhc2s9Y2xhc3N7Y29uc3RydWN0b3IoKXt0aGlzLl9x"
    "dWV1ZT1uZXcgdC5JZGxlVGFza1F1ZXVlfXNldChlKXt0aGlzLl9xdWV1ZS5jbGVhcigpLHRoaXMuX3F1ZXVlLmVucXVldWUoZSl9Zmx1c2goKXt0aGlzLl9x"
    "dWV1ZS5mbHVzaCgpfX19LDkyODI6KGUsdCxpKT0+e09iamVjdC5kZWZpbmVQcm9wZXJ0eSh0LCJfX2VzTW9kdWxlIix7dmFsdWU6ITB9KSx0LnVwZGF0ZVdp"
    "bmRvd3NNb2RlV3JhcHBlZFN0YXRlPXZvaWQgMDtjb25zdCBzPWkoNjQzKTt0LnVwZGF0ZVdpbmRvd3NNb2RlV3JhcHBlZFN0YXRlPWZ1bmN0aW9uKGUpe2Nv"
    "bnN0IHQ9ZS5idWZmZXIubGluZXMuZ2V0KGUuYnVmZmVyLnliYXNlK2UuYnVmZmVyLnktMSksaT1udWxsPT10P3ZvaWQgMDp0LmdldChlLmNvbHMtMSkscj1l"
    "LmJ1ZmZlci5saW5lcy5nZXQoZS5idWZmZXIueWJhc2UrZS5idWZmZXIueSk7ciYmaSYmKHIuaXNXcmFwcGVkPWlbcy5DSEFSX0RBVEFfQ09ERV9JTkRFWF0h"
    "PT1zLk5VTExfQ0VMTF9DT0RFJiZpW3MuQ0hBUl9EQVRBX0NPREVfSU5ERVhdIT09cy5XSElURVNQQUNFX0NFTExfQ09ERSl9fSwzNzM0OihlLHQpPT57T2Jq"
    "ZWN0LmRlZmluZVByb3BlcnR5KHQsIl9fZXNNb2R1bGUiLHt2YWx1ZTohMH0pLHQuRXh0ZW5kZWRBdHRycz10LkF0dHJpYnV0ZURhdGE9dm9pZCAwO2NsYXNz"
    "IGl7Y29uc3RydWN0b3IoKXt0aGlzLmZnPTAsdGhpcy5iZz0wLHRoaXMuZXh0ZW5kZWQ9bmV3IHN9c3RhdGljIHRvQ29sb3JSR0IoZSl7cmV0dXJuW2U+Pj4x"
    "NiYyNTUsZT4+PjgmMjU1LDI1NSZlXX1zdGF0aWMgZnJvbUNvbG9yUkdCKGUpe3JldHVybigyNTUmZVswXSk8PDE2fCgyNTUmZVsxXSk8PDh8MjU1JmVbMl19"
    "Y2xvbmUoKXtjb25zdCBlPW5ldyBpO3JldHVybiBlLmZnPXRoaXMuZmcsZS5iZz10aGlzLmJnLGUuZXh0ZW5kZWQ9dGhpcy5leHRlbmRlZC5jbG9uZSgpLGV9"
    "aXNJbnZlcnNlKCl7cmV0dXJuIDY3MTA4ODY0JnRoaXMuZmd9aXNCb2xkKCl7cmV0dXJuIDEzNDIxNzcyOCZ0aGlzLmZnfWlzVW5kZXJsaW5lKCl7cmV0dXJu"
    "IHRoaXMuaGFzRXh0ZW5kZWRBdHRycygpJiYwIT09dGhpcy5leHRlbmRlZC51bmRlcmxpbmVTdHlsZT8xOjI2ODQzNTQ1NiZ0aGlzLmZnfWlzQmxpbmsoKXty"
    "ZXR1cm4gNTM2ODcwOTEyJnRoaXMuZmd9aXNJbnZpc2libGUoKXtyZXR1cm4gMTA3Mzc0MTgyNCZ0aGlzLmZnfWlzSXRhbGljKCl7cmV0dXJuIDY3MTA4ODY0"
    "JnRoaXMuYmd9aXNEaW0oKXtyZXR1cm4gMTM0MjE3NzI4JnRoaXMuYmd9aXNTdHJpa2V0aHJvdWdoKCl7cmV0dXJuIDIxNDc0ODM2NDgmdGhpcy5mZ31pc1By"
    "b3RlY3RlZCgpe3JldHVybiA1MzY4NzA5MTImdGhpcy5iZ31pc092ZXJsaW5lKCl7cmV0dXJuIDEwNzM3NDE4MjQmdGhpcy5iZ31nZXRGZ0NvbG9yTW9kZSgp"
    "e3JldHVybiA1MDMzMTY0OCZ0aGlzLmZnfWdldEJnQ29sb3JNb2RlKCl7cmV0dXJuIDUwMzMxNjQ4JnRoaXMuYmd9aXNGZ1JHQigpe3JldHVybiA1MDMzMTY0"
    "OD09KDUwMzMxNjQ4JnRoaXMuZmcpfWlzQmdSR0IoKXtyZXR1cm4gNTAzMzE2NDg9PSg1MDMzMTY0OCZ0aGlzLmJnKX1pc0ZnUGFsZXR0ZSgpe3JldHVybiAx"
    "Njc3NzIxNj09KDUwMzMxNjQ4JnRoaXMuZmcpfHwzMzU1NDQzMj09KDUwMzMxNjQ4JnRoaXMuZmcpfWlzQmdQYWxldHRlKCl7cmV0dXJuIDE2Nzc3MjE2PT0o"
    "NTAzMzE2NDgmdGhpcy5iZyl8fDMzNTU0NDMyPT0oNTAzMzE2NDgmdGhpcy5iZyl9aXNGZ0RlZmF1bHQoKXtyZXR1cm4gMD09KDUwMzMxNjQ4JnRoaXMuZmcp"
    "fWlzQmdEZWZhdWx0KCl7cmV0dXJuIDA9PSg1MDMzMTY0OCZ0aGlzLmJnKX1pc0F0dHJpYnV0ZURlZmF1bHQoKXtyZXR1cm4gMD09PXRoaXMuZmcmJjA9PT10"
    "aGlzLmJnfWdldEZnQ29sb3IoKXtzd2l0Y2goNTAzMzE2NDgmdGhpcy5mZyl7Y2FzZSAxNjc3NzIxNjpjYXNlIDMzNTU0NDMyOnJldHVybiAyNTUmdGhpcy5m"
    "ZztjYXNlIDUwMzMxNjQ4OnJldHVybiAxNjc3NzIxNSZ0aGlzLmZnO2RlZmF1bHQ6cmV0dXJuLTF9fWdldEJnQ29sb3IoKXtzd2l0Y2goNTAzMzE2NDgmdGhp"
    "cy5iZyl7Y2FzZSAxNjc3NzIxNjpjYXNlIDMzNTU0NDMyOnJldHVybiAyNTUmdGhpcy5iZztjYXNlIDUwMzMxNjQ4OnJldHVybiAxNjc3NzIxNSZ0aGlzLmJn"
    "O2RlZmF1bHQ6cmV0dXJuLTF9fWhhc0V4dGVuZGVkQXR0cnMoKXtyZXR1cm4gMjY4NDM1NDU2JnRoaXMuYmd9dXBkYXRlRXh0ZW5kZWQoKXt0aGlzLmV4dGVu"
    "ZGVkLmlzRW1wdHkoKT90aGlzLmJnJj0tMjY4NDM1NDU3OnRoaXMuYmd8PTI2ODQzNTQ1Nn1nZXRVbmRlcmxpbmVDb2xvcigpe2lmKDI2ODQzNTQ1NiZ0aGlz"
    "LmJnJiZ+dGhpcy5leHRlbmRlZC51bmRlcmxpbmVDb2xvcilzd2l0Y2goNTAzMzE2NDgmdGhpcy5leHRlbmRlZC51bmRlcmxpbmVDb2xvcil7Y2FzZSAxNjc3"
    "NzIxNjpjYXNlIDMzNTU0NDMyOnJldHVybiAyNTUmdGhpcy5leHRlbmRlZC51bmRlcmxpbmVDb2xvcjtjYXNlIDUwMzMxNjQ4OnJldHVybiAxNjc3NzIxNSZ0"
    "aGlzLmV4dGVuZGVkLnVuZGVybGluZUNvbG9yO2RlZmF1bHQ6cmV0dXJuIHRoaXMuZ2V0RmdDb2xvcigpfXJldHVybiB0aGlzLmdldEZnQ29sb3IoKX1nZXRV"
    "bmRlcmxpbmVDb2xvck1vZGUoKXtyZXR1cm4gMjY4NDM1NDU2JnRoaXMuYmcmJn50aGlzLmV4dGVuZGVkLnVuZGVybGluZUNvbG9yPzUwMzMxNjQ4JnRoaXMu"
    "ZXh0ZW5kZWQudW5kZXJsaW5lQ29sb3I6dGhpcy5nZXRGZ0NvbG9yTW9kZSgpfWlzVW5kZXJsaW5lQ29sb3JSR0IoKXtyZXR1cm4gMjY4NDM1NDU2JnRoaXMu"
    "YmcmJn50aGlzLmV4dGVuZGVkLnVuZGVybGluZUNvbG9yPzUwMzMxNjQ4PT0oNTAzMzE2NDgmdGhpcy5leHRlbmRlZC51bmRlcmxpbmVDb2xvcik6dGhpcy5p"
    "c0ZnUkdCKCl9aXNVbmRlcmxpbmVDb2xvclBhbGV0dGUoKXtyZXR1cm4gMjY4NDM1NDU2JnRoaXMuYmcmJn50aGlzLmV4dGVuZGVkLnVuZGVybGluZUNvbG9y"
    "PzE2Nzc3MjE2PT0oNTAzMzE2NDgmdGhpcy5leHRlbmRlZC51bmRlcmxpbmVDb2xvcil8fDMzNTU0NDMyPT0oNTAzMzE2NDgmdGhpcy5leHRlbmRlZC51bmRl"
    "cmxpbmVDb2xvcik6dGhpcy5pc0ZnUGFsZXR0ZSgpfWlzVW5kZXJsaW5lQ29sb3JEZWZhdWx0KCl7cmV0dXJuIDI2ODQzNTQ1NiZ0aGlzLmJnJiZ+dGhpcy5l"
    "eHRlbmRlZC51bmRlcmxpbmVDb2xvcj8wPT0oNTAzMzE2NDgmdGhpcy5leHRlbmRlZC51bmRlcmxpbmVDb2xvcik6dGhpcy5pc0ZnRGVmYXVsdCgpfWdldFVu"
    "ZGVybGluZVN0eWxlKCl7cmV0dXJuIDI2ODQzNTQ1NiZ0aGlzLmZnPzI2ODQzNTQ1NiZ0aGlzLmJnP3RoaXMuZXh0ZW5kZWQudW5kZXJsaW5lU3R5bGU6MTow"
    "fX10LkF0dHJpYnV0ZURhdGE9aTtjbGFzcyBze2dldCBleHQoKXtyZXR1cm4gdGhpcy5fdXJsSWQ/LTQ2OTc2MjA0OSZ0aGlzLl9leHR8dGhpcy51bmRlcmxp"
    "bmVTdHlsZTw8MjY6dGhpcy5fZXh0fXNldCBleHQoZSl7dGhpcy5fZXh0PWV9Z2V0IHVuZGVybGluZVN0eWxlKCl7cmV0dXJuIHRoaXMuX3VybElkPzU6KDQ2"
    "OTc2MjA0OCZ0aGlzLl9leHQpPj4yNn1zZXQgdW5kZXJsaW5lU3R5bGUoZSl7dGhpcy5fZXh0Jj0tNDY5NzYyMDQ5LHRoaXMuX2V4dHw9ZTw8MjYmNDY5NzYy"
    "MDQ4fWdldCB1bmRlcmxpbmVDb2xvcigpe3JldHVybiA2NzEwODg2MyZ0aGlzLl9leHR9c2V0IHVuZGVybGluZUNvbG9yKGUpe3RoaXMuX2V4dCY9LTY3MTA4"
    "ODY0LHRoaXMuX2V4dHw9NjcxMDg4NjMmZX1nZXQgdXJsSWQoKXtyZXR1cm4gdGhpcy5fdXJsSWR9c2V0IHVybElkKGUpe3RoaXMuX3VybElkPWV9Y29uc3Ry"
    "dWN0b3IoZT0wLHQ9MCl7dGhpcy5fZXh0PTAsdGhpcy5fdXJsSWQ9MCx0aGlzLl9leHQ9ZSx0aGlzLl91cmxJZD10fWNsb25lKCl7cmV0dXJuIG5ldyBzKHRo"
    "aXMuX2V4dCx0aGlzLl91cmxJZCl9aXNFbXB0eSgpe3JldHVybiAwPT09dGhpcy51bmRlcmxpbmVTdHlsZSYmMD09PXRoaXMuX3VybElkfX10LkV4dGVuZGVk"
    "QXR0cnM9c30sOTA5MjooZSx0LGkpPT57T2JqZWN0LmRlZmluZVByb3BlcnR5KHQsIl9fZXNNb2R1bGUiLHt2YWx1ZTohMH0pLHQuQnVmZmVyPXQuTUFYX0JV"
    "RkZFUl9TSVpFPXZvaWQgMDtjb25zdCBzPWkoNjM0OSkscj1pKDcyMjYpLG49aSgzNzM0KSxvPWkoODQzNyksYT1pKDQ2MzQpLGg9aSg1MTEpLGM9aSg2NDMp"
    "LGw9aSg0ODYzKSxkPWkoNzExNik7dC5NQVhfQlVGRkVSX1NJWkU9NDI5NDk2NzI5NSx0LkJ1ZmZlcj1jbGFzc3tjb25zdHJ1Y3RvcihlLHQsaSl7dGhpcy5f"
    "aGFzU2Nyb2xsYmFjaz1lLHRoaXMuX29wdGlvbnNTZXJ2aWNlPXQsdGhpcy5fYnVmZmVyU2VydmljZT1pLHRoaXMueWRpc3A9MCx0aGlzLnliYXNlPTAsdGhp"
    "cy55PTAsdGhpcy54PTAsdGhpcy50YWJzPXt9LHRoaXMuc2F2ZWRZPTAsdGhpcy5zYXZlZFg9MCx0aGlzLnNhdmVkQ3VyQXR0ckRhdGE9by5ERUZBVUxUX0FU"
    "VFJfREFUQS5jbG9uZSgpLHRoaXMuc2F2ZWRDaGFyc2V0PWQuREVGQVVMVF9DSEFSU0VULHRoaXMubWFya2Vycz1bXSx0aGlzLl9udWxsQ2VsbD1oLkNlbGxE"
    "YXRhLmZyb21DaGFyRGF0YShbMCxjLk5VTExfQ0VMTF9DSEFSLGMuTlVMTF9DRUxMX1dJRFRILGMuTlVMTF9DRUxMX0NPREVdKSx0aGlzLl93aGl0ZXNwYWNl"
    "Q2VsbD1oLkNlbGxEYXRhLmZyb21DaGFyRGF0YShbMCxjLldISVRFU1BBQ0VfQ0VMTF9DSEFSLGMuV0hJVEVTUEFDRV9DRUxMX1dJRFRILGMuV0hJVEVTUEFD"
    "RV9DRUxMX0NPREVdKSx0aGlzLl9pc0NsZWFyaW5nPSExLHRoaXMuX21lbW9yeUNsZWFudXBRdWV1ZT1uZXcgci5JZGxlVGFza1F1ZXVlLHRoaXMuX21lbW9y"
    "eUNsZWFudXBQb3NpdGlvbj0wLHRoaXMuX2NvbHM9dGhpcy5fYnVmZmVyU2VydmljZS5jb2xzLHRoaXMuX3Jvd3M9dGhpcy5fYnVmZmVyU2VydmljZS5yb3dz"
    "LHRoaXMubGluZXM9bmV3IHMuQ2lyY3VsYXJMaXN0KHRoaXMuX2dldENvcnJlY3RCdWZmZXJMZW5ndGgodGhpcy5fcm93cykpLHRoaXMuc2Nyb2xsVG9wPTAs"
    "dGhpcy5zY3JvbGxCb3R0b209dGhpcy5fcm93cy0xLHRoaXMuc2V0dXBUYWJTdG9wcygpfWdldE51bGxDZWxsKGUpe3JldHVybiBlPyh0aGlzLl9udWxsQ2Vs"
    "bC5mZz1lLmZnLHRoaXMuX251bGxDZWxsLmJnPWUuYmcsdGhpcy5fbnVsbENlbGwuZXh0ZW5kZWQ9ZS5leHRlbmRlZCk6KHRoaXMuX251bGxDZWxsLmZnPTAs"
    "dGhpcy5fbnVsbENlbGwuYmc9MCx0aGlzLl9udWxsQ2VsbC5leHRlbmRlZD1uZXcgbi5FeHRlbmRlZEF0dHJzKSx0aGlzLl9udWxsQ2VsbH1nZXRXaGl0ZXNw"
    "YWNlQ2VsbChlKXtyZXR1cm4gZT8odGhpcy5fd2hpdGVzcGFjZUNlbGwuZmc9ZS5mZyx0aGlzLl93aGl0ZXNwYWNlQ2VsbC5iZz1lLmJnLHRoaXMuX3doaXRl"
    "c3BhY2VDZWxsLmV4dGVuZGVkPWUuZXh0ZW5kZWQpOih0aGlzLl93aGl0ZXNwYWNlQ2VsbC5mZz0wLHRoaXMuX3doaXRlc3BhY2VDZWxsLmJnPTAsdGhpcy5f"
    "d2hpdGVzcGFjZUNlbGwuZXh0ZW5kZWQ9bmV3IG4uRXh0ZW5kZWRBdHRycyksdGhpcy5fd2hpdGVzcGFjZUNlbGx9Z2V0QmxhbmtMaW5lKGUsdCl7cmV0dXJu"
    "IG5ldyBvLkJ1ZmZlckxpbmUodGhpcy5fYnVmZmVyU2VydmljZS5jb2xzLHRoaXMuZ2V0TnVsbENlbGwoZSksdCl9Z2V0IGhhc1Njcm9sbGJhY2soKXtyZXR1"
    "cm4gdGhpcy5faGFzU2Nyb2xsYmFjayYmdGhpcy5saW5lcy5tYXhMZW5ndGg+dGhpcy5fcm93c31nZXQgaXNDdXJzb3JJblZpZXdwb3J0KCl7Y29uc3QgZT10"
    "aGlzLnliYXNlK3RoaXMueS10aGlzLnlkaXNwO3JldHVybiBlPj0wJiZlPHRoaXMuX3Jvd3N9X2dldENvcnJlY3RCdWZmZXJMZW5ndGgoZSl7aWYoIXRoaXMu"
    "X2hhc1Njcm9sbGJhY2spcmV0dXJuIGU7Y29uc3QgaT1lK3RoaXMuX29wdGlvbnNTZXJ2aWNlLnJhd09wdGlvbnMuc2Nyb2xsYmFjaztyZXR1cm4gaT50Lk1B"
    "WF9CVUZGRVJfU0laRT90Lk1BWF9CVUZGRVJfU0laRTppfWZpbGxWaWV3cG9ydFJvd3MoZSl7aWYoMD09PXRoaXMubGluZXMubGVuZ3RoKXt2b2lkIDA9PT1l"
    "JiYoZT1vLkRFRkFVTFRfQVRUUl9EQVRBKTtsZXQgdD10aGlzLl9yb3dzO2Zvcig7dC0tOyl0aGlzLmxpbmVzLnB1c2godGhpcy5nZXRCbGFua0xpbmUoZSkp"
    "fX1jbGVhcigpe3RoaXMueWRpc3A9MCx0aGlzLnliYXNlPTAsdGhpcy55PTAsdGhpcy54PTAsdGhpcy5saW5lcz1uZXcgcy5DaXJjdWxhckxpc3QodGhpcy5f"
    "Z2V0Q29ycmVjdEJ1ZmZlckxlbmd0aCh0aGlzLl9yb3dzKSksdGhpcy5zY3JvbGxUb3A9MCx0aGlzLnNjcm9sbEJvdHRvbT10aGlzLl9yb3dzLTEsdGhpcy5z"
    "ZXR1cFRhYlN0b3BzKCl9cmVzaXplKGUsdCl7Y29uc3QgaT10aGlzLmdldE51bGxDZWxsKG8uREVGQVVMVF9BVFRSX0RBVEEpO2xldCBzPTA7Y29uc3Qgcj10"
    "aGlzLl9nZXRDb3JyZWN0QnVmZmVyTGVuZ3RoKHQpO2lmKHI+dGhpcy5saW5lcy5tYXhMZW5ndGgmJih0aGlzLmxpbmVzLm1heExlbmd0aD1yKSx0aGlzLmxp"
    "bmVzLmxlbmd0aD4wKXtpZih0aGlzLl9jb2xzPGUpZm9yKGxldCB0PTA7dDx0aGlzLmxpbmVzLmxlbmd0aDt0Kyspcys9K3RoaXMubGluZXMuZ2V0KHQpLnJl"
    "c2l6ZShlLGkpO2xldCBuPTA7aWYodGhpcy5fcm93czx0KWZvcihsZXQgcz10aGlzLl9yb3dzO3M8dDtzKyspdGhpcy5saW5lcy5sZW5ndGg8dCt0aGlzLnli"
    "YXNlJiYodGhpcy5fb3B0aW9uc1NlcnZpY2UucmF3T3B0aW9ucy53aW5kb3dzTW9kZXx8dm9pZCAwIT09dGhpcy5fb3B0aW9uc1NlcnZpY2UucmF3T3B0aW9u"
    "cy53aW5kb3dzUHR5LmJhY2tlbmR8fHZvaWQgMCE9PXRoaXMuX29wdGlvbnNTZXJ2aWNlLnJhd09wdGlvbnMud2luZG93c1B0eS5idWlsZE51bWJlcj90aGlz"
    "LmxpbmVzLnB1c2gobmV3IG8uQnVmZmVyTGluZShlLGkpKTp0aGlzLnliYXNlPjAmJnRoaXMubGluZXMubGVuZ3RoPD10aGlzLnliYXNlK3RoaXMueStuKzE/"
    "KHRoaXMueWJhc2UtLSxuKyssdGhpcy55ZGlzcD4wJiZ0aGlzLnlkaXNwLS0pOnRoaXMubGluZXMucHVzaChuZXcgby5CdWZmZXJMaW5lKGUsaSkpKTtlbHNl"
    "IGZvcihsZXQgZT10aGlzLl9yb3dzO2U+dDtlLS0pdGhpcy5saW5lcy5sZW5ndGg+dCt0aGlzLnliYXNlJiYodGhpcy5saW5lcy5sZW5ndGg+dGhpcy55YmFz"
    "ZSt0aGlzLnkrMT90aGlzLmxpbmVzLnBvcCgpOih0aGlzLnliYXNlKyssdGhpcy55ZGlzcCsrKSk7aWYocjx0aGlzLmxpbmVzLm1heExlbmd0aCl7Y29uc3Qg"
    "ZT10aGlzLmxpbmVzLmxlbmd0aC1yO2U+MCYmKHRoaXMubGluZXMudHJpbVN0YXJ0KGUpLHRoaXMueWJhc2U9TWF0aC5tYXgodGhpcy55YmFzZS1lLDApLHRo"
    "aXMueWRpc3A9TWF0aC5tYXgodGhpcy55ZGlzcC1lLDApLHRoaXMuc2F2ZWRZPU1hdGgubWF4KHRoaXMuc2F2ZWRZLWUsMCkpLHRoaXMubGluZXMubWF4TGVu"
    "Z3RoPXJ9dGhpcy54PU1hdGgubWluKHRoaXMueCxlLTEpLHRoaXMueT1NYXRoLm1pbih0aGlzLnksdC0xKSxuJiYodGhpcy55Kz1uKSx0aGlzLnNhdmVkWD1N"
    "YXRoLm1pbih0aGlzLnNhdmVkWCxlLTEpLHRoaXMuc2Nyb2xsVG9wPTB9aWYodGhpcy5zY3JvbGxCb3R0b209dC0xLHRoaXMuX2lzUmVmbG93RW5hYmxlZCYm"
    "KHRoaXMuX3JlZmxvdyhlLHQpLHRoaXMuX2NvbHM+ZSkpZm9yKGxldCB0PTA7dDx0aGlzLmxpbmVzLmxlbmd0aDt0Kyspcys9K3RoaXMubGluZXMuZ2V0KHQp"
    "LnJlc2l6ZShlLGkpO3RoaXMuX2NvbHM9ZSx0aGlzLl9yb3dzPXQsdGhpcy5fbWVtb3J5Q2xlYW51cFF1ZXVlLmNsZWFyKCkscz4uMSp0aGlzLmxpbmVzLmxl"
    "bmd0aCYmKHRoaXMuX21lbW9yeUNsZWFudXBQb3NpdGlvbj0wLHRoaXMuX21lbW9yeUNsZWFudXBRdWV1ZS5lbnF1ZXVlKCgoKT0+dGhpcy5fYmF0Y2hlZE1l"
    "bW9yeUNsZWFudXAoKSkpKX1fYmF0Y2hlZE1lbW9yeUNsZWFudXAoKXtsZXQgZT0hMDt0aGlzLl9tZW1vcnlDbGVhbnVwUG9zaXRpb24+PXRoaXMubGluZXMu"
    "bGVuZ3RoJiYodGhpcy5fbWVtb3J5Q2xlYW51cFBvc2l0aW9uPTAsZT0hMSk7bGV0IHQ9MDtmb3IoO3RoaXMuX21lbW9yeUNsZWFudXBQb3NpdGlvbjx0aGlz"
    "LmxpbmVzLmxlbmd0aDspaWYodCs9dGhpcy5saW5lcy5nZXQodGhpcy5fbWVtb3J5Q2xlYW51cFBvc2l0aW9uKyspLmNsZWFudXBNZW1vcnkoKSx0PjEwMCly"
    "ZXR1cm4hMDtyZXR1cm4gZX1nZXQgX2lzUmVmbG93RW5hYmxlZCgpe2NvbnN0IGU9dGhpcy5fb3B0aW9uc1NlcnZpY2UucmF3T3B0aW9ucy53aW5kb3dzUHR5"
    "O3JldHVybiBlJiZlLmJ1aWxkTnVtYmVyP3RoaXMuX2hhc1Njcm9sbGJhY2smJiJjb25wdHkiPT09ZS5iYWNrZW5kJiZlLmJ1aWxkTnVtYmVyPj0yMTM3Njp0"
    "aGlzLl9oYXNTY3JvbGxiYWNrJiYhdGhpcy5fb3B0aW9uc1NlcnZpY2UucmF3T3B0aW9ucy53aW5kb3dzTW9kZX1fcmVmbG93KGUsdCl7dGhpcy5fY29scyE9"
    "PWUmJihlPnRoaXMuX2NvbHM/dGhpcy5fcmVmbG93TGFyZ2VyKGUsdCk6dGhpcy5fcmVmbG93U21hbGxlcihlLHQpKX1fcmVmbG93TGFyZ2VyKGUsdCl7Y29u"
    "c3QgaT0oMCxhLnJlZmxvd0xhcmdlckdldExpbmVzVG9SZW1vdmUpKHRoaXMubGluZXMsdGhpcy5fY29scyxlLHRoaXMueWJhc2UrdGhpcy55LHRoaXMuZ2V0"
    "TnVsbENlbGwoby5ERUZBVUxUX0FUVFJfREFUQSkpO2lmKGkubGVuZ3RoPjApe2NvbnN0IHM9KDAsYS5yZWZsb3dMYXJnZXJDcmVhdGVOZXdMYXlvdXQpKHRo"
    "aXMubGluZXMsaSk7KDAsYS5yZWZsb3dMYXJnZXJBcHBseU5ld0xheW91dCkodGhpcy5saW5lcyxzLmxheW91dCksdGhpcy5fcmVmbG93TGFyZ2VyQWRqdXN0"
    "Vmlld3BvcnQoZSx0LHMuY291bnRSZW1vdmVkKX19X3JlZmxvd0xhcmdlckFkanVzdFZpZXdwb3J0KGUsdCxpKXtjb25zdCBzPXRoaXMuZ2V0TnVsbENlbGwo"
    "by5ERUZBVUxUX0FUVFJfREFUQSk7bGV0IHI9aTtmb3IoO3ItLSA+MDspMD09PXRoaXMueWJhc2U/KHRoaXMueT4wJiZ0aGlzLnktLSx0aGlzLmxpbmVzLmxl"
    "bmd0aDx0JiZ0aGlzLmxpbmVzLnB1c2gobmV3IG8uQnVmZmVyTGluZShlLHMpKSk6KHRoaXMueWRpc3A9PT10aGlzLnliYXNlJiZ0aGlzLnlkaXNwLS0sdGhp"
    "cy55YmFzZS0tKTt0aGlzLnNhdmVkWT1NYXRoLm1heCh0aGlzLnNhdmVkWS1pLDApfV9yZWZsb3dTbWFsbGVyKGUsdCl7Y29uc3QgaT10aGlzLmdldE51bGxD"
    "ZWxsKG8uREVGQVVMVF9BVFRSX0RBVEEpLHM9W107bGV0IHI9MDtmb3IobGV0IG49dGhpcy5saW5lcy5sZW5ndGgtMTtuPj0wO24tLSl7bGV0IGg9dGhpcy5s"
    "aW5lcy5nZXQobik7aWYoIWh8fCFoLmlzV3JhcHBlZCYmaC5nZXRUcmltbWVkTGVuZ3RoKCk8PWUpY29udGludWU7Y29uc3QgYz1baF07Zm9yKDtoLmlzV3Jh"
    "cHBlZCYmbj4wOyloPXRoaXMubGluZXMuZ2V0KC0tbiksYy51bnNoaWZ0KGgpO2NvbnN0IGw9dGhpcy55YmFzZSt0aGlzLnk7aWYobD49biYmbDxuK2MubGVu"
    "Z3RoKWNvbnRpbnVlO2NvbnN0IGQ9Y1tjLmxlbmd0aC0xXS5nZXRUcmltbWVkTGVuZ3RoKCksXz0oMCxhLnJlZmxvd1NtYWxsZXJHZXROZXdMaW5lTGVuZ3Ro"
    "cykoYyx0aGlzLl9jb2xzLGUpLHU9Xy5sZW5ndGgtYy5sZW5ndGg7bGV0IGY7Zj0wPT09dGhpcy55YmFzZSYmdGhpcy55IT09dGhpcy5saW5lcy5sZW5ndGgt"
    "MT9NYXRoLm1heCgwLHRoaXMueS10aGlzLmxpbmVzLm1heExlbmd0aCt1KTpNYXRoLm1heCgwLHRoaXMubGluZXMubGVuZ3RoLXRoaXMubGluZXMubWF4TGVu"
    "Z3RoK3UpO2NvbnN0IHY9W107Zm9yKGxldCBlPTA7ZTx1O2UrKyl7Y29uc3QgZT10aGlzLmdldEJsYW5rTGluZShvLkRFRkFVTFRfQVRUUl9EQVRBLCEwKTt2"
    "LnB1c2goZSl9di5sZW5ndGg+MCYmKHMucHVzaCh7c3RhcnQ6bitjLmxlbmd0aCtyLG5ld0xpbmVzOnZ9KSxyKz12Lmxlbmd0aCksYy5wdXNoKC4uLnYpO2xl"
    "dCBwPV8ubGVuZ3RoLTEsZz1fW3BdOzA9PT1nJiYocC0tLGc9X1twXSk7bGV0IG09Yy5sZW5ndGgtdS0xLFM9ZDtmb3IoO20+PTA7KXtjb25zdCBlPU1hdGgu"
    "bWluKFMsZyk7aWYodm9pZCAwPT09Y1twXSlicmVhaztpZihjW3BdLmNvcHlDZWxsc0Zyb20oY1ttXSxTLWUsZy1lLGUsITApLGctPWUsMD09PWcmJihwLS0s"
    "Zz1fW3BdKSxTLT1lLDA9PT1TKXttLS07Y29uc3QgZT1NYXRoLm1heChtLDApO1M9KDAsYS5nZXRXcmFwcGVkTGluZVRyaW1tZWRMZW5ndGgpKGMsZSx0aGlz"
    "Ll9jb2xzKX19Zm9yKGxldCB0PTA7dDxjLmxlbmd0aDt0KyspX1t0XTxlJiZjW3RdLnNldENlbGwoX1t0XSxpKTtsZXQgQz11LWY7Zm9yKDtDLS0gPjA7KTA9"
    "PT10aGlzLnliYXNlP3RoaXMueTx0LTE/KHRoaXMueSsrLHRoaXMubGluZXMucG9wKCkpOih0aGlzLnliYXNlKyssdGhpcy55ZGlzcCsrKTp0aGlzLnliYXNl"
    "PE1hdGgubWluKHRoaXMubGluZXMubWF4TGVuZ3RoLHRoaXMubGluZXMubGVuZ3RoK3IpLXQmJih0aGlzLnliYXNlPT09dGhpcy55ZGlzcCYmdGhpcy55ZGlz"
    "cCsrLHRoaXMueWJhc2UrKyk7dGhpcy5zYXZlZFk9TWF0aC5taW4odGhpcy5zYXZlZFkrdSx0aGlzLnliYXNlK3QtMSl9aWYocy5sZW5ndGg+MCl7Y29uc3Qg"
    "ZT1bXSx0PVtdO2ZvcihsZXQgZT0wO2U8dGhpcy5saW5lcy5sZW5ndGg7ZSsrKXQucHVzaCh0aGlzLmxpbmVzLmdldChlKSk7Y29uc3QgaT10aGlzLmxpbmVz"
    "Lmxlbmd0aDtsZXQgbj1pLTEsbz0wLGE9c1tvXTt0aGlzLmxpbmVzLmxlbmd0aD1NYXRoLm1pbih0aGlzLmxpbmVzLm1heExlbmd0aCx0aGlzLmxpbmVzLmxl"
    "bmd0aCtyKTtsZXQgaD0wO2ZvcihsZXQgYz1NYXRoLm1pbih0aGlzLmxpbmVzLm1heExlbmd0aC0xLGkrci0xKTtjPj0wO2MtLSlpZihhJiZhLnN0YXJ0Pm4r"
    "aCl7Zm9yKGxldCBlPWEubmV3TGluZXMubGVuZ3RoLTE7ZT49MDtlLS0pdGhpcy5saW5lcy5zZXQoYy0tLGEubmV3TGluZXNbZV0pO2MrKyxlLnB1c2goe2lu"
    "ZGV4Om4rMSxhbW91bnQ6YS5uZXdMaW5lcy5sZW5ndGh9KSxoKz1hLm5ld0xpbmVzLmxlbmd0aCxhPXNbKytvXX1lbHNlIHRoaXMubGluZXMuc2V0KGMsdFtu"
    "LS1dKTtsZXQgYz0wO2ZvcihsZXQgdD1lLmxlbmd0aC0xO3Q+PTA7dC0tKWVbdF0uaW5kZXgrPWMsdGhpcy5saW5lcy5vbkluc2VydEVtaXR0ZXIuZmlyZShl"
    "W3RdKSxjKz1lW3RdLmFtb3VudDtjb25zdCBsPU1hdGgubWF4KDAsaStyLXRoaXMubGluZXMubWF4TGVuZ3RoKTtsPjAmJnRoaXMubGluZXMub25UcmltRW1p"
    "dHRlci5maXJlKGwpfX10cmFuc2xhdGVCdWZmZXJMaW5lVG9TdHJpbmcoZSx0LGk9MCxzKXtjb25zdCByPXRoaXMubGluZXMuZ2V0KGUpO3JldHVybiByP3Iu"
    "dHJhbnNsYXRlVG9TdHJpbmcodCxpLHMpOiIifWdldFdyYXBwZWRSYW5nZUZvckxpbmUoZSl7bGV0IHQ9ZSxpPWU7Zm9yKDt0PjAmJnRoaXMubGluZXMuZ2V0"
    "KHQpLmlzV3JhcHBlZDspdC0tO2Zvcig7aSsxPHRoaXMubGluZXMubGVuZ3RoJiZ0aGlzLmxpbmVzLmdldChpKzEpLmlzV3JhcHBlZDspaSsrO3JldHVybntm"
    "aXJzdDp0LGxhc3Q6aX19c2V0dXBUYWJTdG9wcyhlKXtmb3IobnVsbCE9ZT90aGlzLnRhYnNbZV18fChlPXRoaXMucHJldlN0b3AoZSkpOih0aGlzLnRhYnM9"
    "e30sZT0wKTtlPHRoaXMuX2NvbHM7ZSs9dGhpcy5fb3B0aW9uc1NlcnZpY2UucmF3T3B0aW9ucy50YWJTdG9wV2lkdGgpdGhpcy50YWJzW2VdPSEwfXByZXZT"
    "dG9wKGUpe2ZvcihudWxsPT1lJiYoZT10aGlzLngpOyF0aGlzLnRhYnNbLS1lXSYmZT4wOyk7cmV0dXJuIGU+PXRoaXMuX2NvbHM/dGhpcy5fY29scy0xOmU8"
    "MD8wOmV9bmV4dFN0b3AoZSl7Zm9yKG51bGw9PWUmJihlPXRoaXMueCk7IXRoaXMudGFic1srK2VdJiZlPHRoaXMuX2NvbHM7KTtyZXR1cm4gZT49dGhpcy5f"
    "Y29scz90aGlzLl9jb2xzLTE6ZTwwPzA6ZX1jbGVhck1hcmtlcnMoZSl7dGhpcy5faXNDbGVhcmluZz0hMDtmb3IobGV0IHQ9MDt0PHRoaXMubWFya2Vycy5s"
    "ZW5ndGg7dCsrKXRoaXMubWFya2Vyc1t0XS5saW5lPT09ZSYmKHRoaXMubWFya2Vyc1t0XS5kaXNwb3NlKCksdGhpcy5tYXJrZXJzLnNwbGljZSh0LS0sMSkp"
    "O3RoaXMuX2lzQ2xlYXJpbmc9ITF9Y2xlYXJBbGxNYXJrZXJzKCl7dGhpcy5faXNDbGVhcmluZz0hMDtmb3IobGV0IGU9MDtlPHRoaXMubWFya2Vycy5sZW5n"
    "dGg7ZSsrKXRoaXMubWFya2Vyc1tlXS5kaXNwb3NlKCksdGhpcy5tYXJrZXJzLnNwbGljZShlLS0sMSk7dGhpcy5faXNDbGVhcmluZz0hMX1hZGRNYXJrZXIo"
    "ZSl7Y29uc3QgdD1uZXcgbC5NYXJrZXIoZSk7cmV0dXJuIHRoaXMubWFya2Vycy5wdXNoKHQpLHQucmVnaXN0ZXIodGhpcy5saW5lcy5vblRyaW0oKGU9Pnt0"
    "LmxpbmUtPWUsdC5saW5lPDAmJnQuZGlzcG9zZSgpfSkpKSx0LnJlZ2lzdGVyKHRoaXMubGluZXMub25JbnNlcnQoKGU9Pnt0LmxpbmU+PWUuaW5kZXgmJih0"
    "LmxpbmUrPWUuYW1vdW50KX0pKSksdC5yZWdpc3Rlcih0aGlzLmxpbmVzLm9uRGVsZXRlKChlPT57dC5saW5lPj1lLmluZGV4JiZ0LmxpbmU8ZS5pbmRleCtl"
    "LmFtb3VudCYmdC5kaXNwb3NlKCksdC5saW5lPmUuaW5kZXgmJih0LmxpbmUtPWUuYW1vdW50KX0pKSksdC5yZWdpc3Rlcih0Lm9uRGlzcG9zZSgoKCk9PnRo"
    "aXMuX3JlbW92ZU1hcmtlcih0KSkpKSx0fV9yZW1vdmVNYXJrZXIoZSl7dGhpcy5faXNDbGVhcmluZ3x8dGhpcy5tYXJrZXJzLnNwbGljZSh0aGlzLm1hcmtl"
    "cnMuaW5kZXhPZihlKSwxKX19fSw4NDM3OihlLHQsaSk9PntPYmplY3QuZGVmaW5lUHJvcGVydHkodCwiX19lc01vZHVsZSIse3ZhbHVlOiEwfSksdC5CdWZm"
    "ZXJMaW5lPXQuREVGQVVMVF9BVFRSX0RBVEE9dm9pZCAwO2NvbnN0IHM9aSgzNzM0KSxyPWkoNTExKSxuPWkoNjQzKSxvPWkoNDgyKTt0LkRFRkFVTFRfQVRU"
    "Ul9EQVRBPU9iamVjdC5mcmVlemUobmV3IHMuQXR0cmlidXRlRGF0YSk7bGV0IGE9MDtjbGFzcyBoe2NvbnN0cnVjdG9yKGUsdCxpPSExKXt0aGlzLmlzV3Jh"
    "cHBlZD1pLHRoaXMuX2NvbWJpbmVkPXt9LHRoaXMuX2V4dGVuZGVkQXR0cnM9e30sdGhpcy5fZGF0YT1uZXcgVWludDMyQXJyYXkoMyplKTtjb25zdCBzPXR8"
    "fHIuQ2VsbERhdGEuZnJvbUNoYXJEYXRhKFswLG4uTlVMTF9DRUxMX0NIQVIsbi5OVUxMX0NFTExfV0lEVEgsbi5OVUxMX0NFTExfQ09ERV0pO2ZvcihsZXQg"
    "dD0wO3Q8ZTsrK3QpdGhpcy5zZXRDZWxsKHQscyk7dGhpcy5sZW5ndGg9ZX1nZXQoZSl7Y29uc3QgdD10aGlzLl9kYXRhWzMqZSswXSxpPTIwOTcxNTEmdDty"
    "ZXR1cm5bdGhpcy5fZGF0YVszKmUrMV0sMjA5NzE1MiZ0P3RoaXMuX2NvbWJpbmVkW2VdOmk/KDAsby5zdHJpbmdGcm9tQ29kZVBvaW50KShpKToiIix0Pj4y"
    "MiwyMDk3MTUyJnQ/dGhpcy5fY29tYmluZWRbZV0uY2hhckNvZGVBdCh0aGlzLl9jb21iaW5lZFtlXS5sZW5ndGgtMSk6aV19c2V0KGUsdCl7dGhpcy5fZGF0"
    "YVszKmUrMV09dFtuLkNIQVJfREFUQV9BVFRSX0lOREVYXSx0W24uQ0hBUl9EQVRBX0NIQVJfSU5ERVhdLmxlbmd0aD4xPyh0aGlzLl9jb21iaW5lZFtlXT10"
    "WzFdLHRoaXMuX2RhdGFbMyplKzBdPTIwOTcxNTJ8ZXx0W24uQ0hBUl9EQVRBX1dJRFRIX0lOREVYXTw8MjIpOnRoaXMuX2RhdGFbMyplKzBdPXRbbi5DSEFS"
    "X0RBVEFfQ0hBUl9JTkRFWF0uY2hhckNvZGVBdCgwKXx0W24uQ0hBUl9EQVRBX1dJRFRIX0lOREVYXTw8MjJ9Z2V0V2lkdGgoZSl7cmV0dXJuIHRoaXMuX2Rh"
    "dGFbMyplKzBdPj4yMn1oYXNXaWR0aChlKXtyZXR1cm4gMTI1ODI5MTImdGhpcy5fZGF0YVszKmUrMF19Z2V0RmcoZSl7cmV0dXJuIHRoaXMuX2RhdGFbMypl"
    "KzFdfWdldEJnKGUpe3JldHVybiB0aGlzLl9kYXRhWzMqZSsyXX1oYXNDb250ZW50KGUpe3JldHVybiA0MTk0MzAzJnRoaXMuX2RhdGFbMyplKzBdfWdldENv"
    "ZGVQb2ludChlKXtjb25zdCB0PXRoaXMuX2RhdGFbMyplKzBdO3JldHVybiAyMDk3MTUyJnQ/dGhpcy5fY29tYmluZWRbZV0uY2hhckNvZGVBdCh0aGlzLl9j"
    "b21iaW5lZFtlXS5sZW5ndGgtMSk6MjA5NzE1MSZ0fWlzQ29tYmluZWQoZSl7cmV0dXJuIDIwOTcxNTImdGhpcy5fZGF0YVszKmUrMF19Z2V0U3RyaW5nKGUp"
    "e2NvbnN0IHQ9dGhpcy5fZGF0YVszKmUrMF07cmV0dXJuIDIwOTcxNTImdD90aGlzLl9jb21iaW5lZFtlXToyMDk3MTUxJnQ/KDAsby5zdHJpbmdGcm9tQ29k"
    "ZVBvaW50KSgyMDk3MTUxJnQpOiIifWlzUHJvdGVjdGVkKGUpe3JldHVybiA1MzY4NzA5MTImdGhpcy5fZGF0YVszKmUrMl19bG9hZENlbGwoZSx0KXtyZXR1"
    "cm4gYT0zKmUsdC5jb250ZW50PXRoaXMuX2RhdGFbYSswXSx0LmZnPXRoaXMuX2RhdGFbYSsxXSx0LmJnPXRoaXMuX2RhdGFbYSsyXSwyMDk3MTUyJnQuY29u"
    "dGVudCYmKHQuY29tYmluZWREYXRhPXRoaXMuX2NvbWJpbmVkW2VdKSwyNjg0MzU0NTYmdC5iZyYmKHQuZXh0ZW5kZWQ9dGhpcy5fZXh0ZW5kZWRBdHRyc1tl"
    "XSksdH1zZXRDZWxsKGUsdCl7MjA5NzE1MiZ0LmNvbnRlbnQmJih0aGlzLl9jb21iaW5lZFtlXT10LmNvbWJpbmVkRGF0YSksMjY4NDM1NDU2JnQuYmcmJih0"
    "aGlzLl9leHRlbmRlZEF0dHJzW2VdPXQuZXh0ZW5kZWQpLHRoaXMuX2RhdGFbMyplKzBdPXQuY29udGVudCx0aGlzLl9kYXRhWzMqZSsxXT10LmZnLHRoaXMu"
    "X2RhdGFbMyplKzJdPXQuYmd9c2V0Q2VsbEZyb21Db2RlUG9pbnQoZSx0LGkscyxyLG4pezI2ODQzNTQ1NiZyJiYodGhpcy5fZXh0ZW5kZWRBdHRyc1tlXT1u"
    "KSx0aGlzLl9kYXRhWzMqZSswXT10fGk8PDIyLHRoaXMuX2RhdGFbMyplKzFdPXMsdGhpcy5fZGF0YVszKmUrMl09cn1hZGRDb2RlcG9pbnRUb0NlbGwoZSx0"
    "KXtsZXQgaT10aGlzLl9kYXRhWzMqZSswXTsyMDk3MTUyJmk/dGhpcy5fY29tYmluZWRbZV0rPSgwLG8uc3RyaW5nRnJvbUNvZGVQb2ludCkodCk6KDIwOTcx"
    "NTEmaT8odGhpcy5fY29tYmluZWRbZV09KDAsby5zdHJpbmdGcm9tQ29kZVBvaW50KSgyMDk3MTUxJmkpKygwLG8uc3RyaW5nRnJvbUNvZGVQb2ludCkodCks"
    "aSY9LTIwOTcxNTIsaXw9MjA5NzE1Mik6aT10fDE8PDIyLHRoaXMuX2RhdGFbMyplKzBdPWkpfWluc2VydENlbGxzKGUsdCxpLG4pe2lmKChlJT10aGlzLmxl"
    "bmd0aCkmJjI9PT10aGlzLmdldFdpZHRoKGUtMSkmJnRoaXMuc2V0Q2VsbEZyb21Db2RlUG9pbnQoZS0xLDAsMSwobnVsbD09bj92b2lkIDA6bi5mZyl8fDAs"
    "KG51bGw9PW4/dm9pZCAwOm4uYmcpfHwwLChudWxsPT1uP3ZvaWQgMDpuLmV4dGVuZGVkKXx8bmV3IHMuRXh0ZW5kZWRBdHRycyksdDx0aGlzLmxlbmd0aC1l"
    "KXtjb25zdCBzPW5ldyByLkNlbGxEYXRhO2ZvcihsZXQgaT10aGlzLmxlbmd0aC1lLXQtMTtpPj0wOy0taSl0aGlzLnNldENlbGwoZSt0K2ksdGhpcy5sb2Fk"
    "Q2VsbChlK2kscykpO2ZvcihsZXQgcz0wO3M8dDsrK3MpdGhpcy5zZXRDZWxsKGUrcyxpKX1lbHNlIGZvcihsZXQgdD1lO3Q8dGhpcy5sZW5ndGg7Kyt0KXRo"
    "aXMuc2V0Q2VsbCh0LGkpOzI9PT10aGlzLmdldFdpZHRoKHRoaXMubGVuZ3RoLTEpJiZ0aGlzLnNldENlbGxGcm9tQ29kZVBvaW50KHRoaXMubGVuZ3RoLTEs"
    "MCwxLChudWxsPT1uP3ZvaWQgMDpuLmZnKXx8MCwobnVsbD09bj92b2lkIDA6bi5iZyl8fDAsKG51bGw9PW4/dm9pZCAwOm4uZXh0ZW5kZWQpfHxuZXcgcy5F"
    "eHRlbmRlZEF0dHJzKX1kZWxldGVDZWxscyhlLHQsaSxuKXtpZihlJT10aGlzLmxlbmd0aCx0PHRoaXMubGVuZ3RoLWUpe2NvbnN0IHM9bmV3IHIuQ2VsbERh"
    "dGE7Zm9yKGxldCBpPTA7aTx0aGlzLmxlbmd0aC1lLXQ7KytpKXRoaXMuc2V0Q2VsbChlK2ksdGhpcy5sb2FkQ2VsbChlK3QraSxzKSk7Zm9yKGxldCBlPXRo"
    "aXMubGVuZ3RoLXQ7ZTx0aGlzLmxlbmd0aDsrK2UpdGhpcy5zZXRDZWxsKGUsaSl9ZWxzZSBmb3IobGV0IHQ9ZTt0PHRoaXMubGVuZ3RoOysrdCl0aGlzLnNl"
    "dENlbGwodCxpKTtlJiYyPT09dGhpcy5nZXRXaWR0aChlLTEpJiZ0aGlzLnNldENlbGxGcm9tQ29kZVBvaW50KGUtMSwwLDEsKG51bGw9PW4/dm9pZCAwOm4u"
    "ZmcpfHwwLChudWxsPT1uP3ZvaWQgMDpuLmJnKXx8MCwobnVsbD09bj92b2lkIDA6bi5leHRlbmRlZCl8fG5ldyBzLkV4dGVuZGVkQXR0cnMpLDAhPT10aGlz"
    "LmdldFdpZHRoKGUpfHx0aGlzLmhhc0NvbnRlbnQoZSl8fHRoaXMuc2V0Q2VsbEZyb21Db2RlUG9pbnQoZSwwLDEsKG51bGw9PW4/dm9pZCAwOm4uZmcpfHww"
    "LChudWxsPT1uP3ZvaWQgMDpuLmJnKXx8MCwobnVsbD09bj92b2lkIDA6bi5leHRlbmRlZCl8fG5ldyBzLkV4dGVuZGVkQXR0cnMpfXJlcGxhY2VDZWxscyhl"
    "LHQsaSxyLG49ITEpe2lmKG4pZm9yKGUmJjI9PT10aGlzLmdldFdpZHRoKGUtMSkmJiF0aGlzLmlzUHJvdGVjdGVkKGUtMSkmJnRoaXMuc2V0Q2VsbEZyb21D"
    "b2RlUG9pbnQoZS0xLDAsMSwobnVsbD09cj92b2lkIDA6ci5mZyl8fDAsKG51bGw9PXI/dm9pZCAwOnIuYmcpfHwwLChudWxsPT1yP3ZvaWQgMDpyLmV4dGVu"
    "ZGVkKXx8bmV3IHMuRXh0ZW5kZWRBdHRycyksdDx0aGlzLmxlbmd0aCYmMj09PXRoaXMuZ2V0V2lkdGgodC0xKSYmIXRoaXMuaXNQcm90ZWN0ZWQodCkmJnRo"
    "aXMuc2V0Q2VsbEZyb21Db2RlUG9pbnQodCwwLDEsKG51bGw9PXI/dm9pZCAwOnIuZmcpfHwwLChudWxsPT1yP3ZvaWQgMDpyLmJnKXx8MCwobnVsbD09cj92"
    "b2lkIDA6ci5leHRlbmRlZCl8fG5ldyBzLkV4dGVuZGVkQXR0cnMpO2U8dCYmZTx0aGlzLmxlbmd0aDspdGhpcy5pc1Byb3RlY3RlZChlKXx8dGhpcy5zZXRD"
    "ZWxsKGUsaSksZSsrO2Vsc2UgZm9yKGUmJjI9PT10aGlzLmdldFdpZHRoKGUtMSkmJnRoaXMuc2V0Q2VsbEZyb21Db2RlUG9pbnQoZS0xLDAsMSwobnVsbD09"
    "cj92b2lkIDA6ci5mZyl8fDAsKG51bGw9PXI/dm9pZCAwOnIuYmcpfHwwLChudWxsPT1yP3ZvaWQgMDpyLmV4dGVuZGVkKXx8bmV3IHMuRXh0ZW5kZWRBdHRy"
    "cyksdDx0aGlzLmxlbmd0aCYmMj09PXRoaXMuZ2V0V2lkdGgodC0xKSYmdGhpcy5zZXRDZWxsRnJvbUNvZGVQb2ludCh0LDAsMSwobnVsbD09cj92b2lkIDA6"
    "ci5mZyl8fDAsKG51bGw9PXI/dm9pZCAwOnIuYmcpfHwwLChudWxsPT1yP3ZvaWQgMDpyLmV4dGVuZGVkKXx8bmV3IHMuRXh0ZW5kZWRBdHRycyk7ZTx0JiZl"
    "PHRoaXMubGVuZ3RoOyl0aGlzLnNldENlbGwoZSsrLGkpfXJlc2l6ZShlLHQpe2lmKGU9PT10aGlzLmxlbmd0aClyZXR1cm4gNCp0aGlzLl9kYXRhLmxlbmd0"
    "aCoyPHRoaXMuX2RhdGEuYnVmZmVyLmJ5dGVMZW5ndGg7Y29uc3QgaT0zKmU7aWYoZT50aGlzLmxlbmd0aCl7aWYodGhpcy5fZGF0YS5idWZmZXIuYnl0ZUxl"
    "bmd0aD49NCppKXRoaXMuX2RhdGE9bmV3IFVpbnQzMkFycmF5KHRoaXMuX2RhdGEuYnVmZmVyLDAsaSk7ZWxzZXtjb25zdCBlPW5ldyBVaW50MzJBcnJheShp"
    "KTtlLnNldCh0aGlzLl9kYXRhKSx0aGlzLl9kYXRhPWV9Zm9yKGxldCBpPXRoaXMubGVuZ3RoO2k8ZTsrK2kpdGhpcy5zZXRDZWxsKGksdCl9ZWxzZXt0aGlz"
    "Ll9kYXRhPXRoaXMuX2RhdGEuc3ViYXJyYXkoMCxpKTtjb25zdCB0PU9iamVjdC5rZXlzKHRoaXMuX2NvbWJpbmVkKTtmb3IobGV0IGk9MDtpPHQubGVuZ3Ro"
    "O2krKyl7Y29uc3Qgcz1wYXJzZUludCh0W2ldLDEwKTtzPj1lJiZkZWxldGUgdGhpcy5fY29tYmluZWRbc119Y29uc3Qgcz1PYmplY3Qua2V5cyh0aGlzLl9l"
    "eHRlbmRlZEF0dHJzKTtmb3IobGV0IHQ9MDt0PHMubGVuZ3RoO3QrKyl7Y29uc3QgaT1wYXJzZUludChzW3RdLDEwKTtpPj1lJiZkZWxldGUgdGhpcy5fZXh0"
    "ZW5kZWRBdHRyc1tpXX19cmV0dXJuIHRoaXMubGVuZ3RoPWUsNCppKjI8dGhpcy5fZGF0YS5idWZmZXIuYnl0ZUxlbmd0aH1jbGVhbnVwTWVtb3J5KCl7aWYo"
    "NCp0aGlzLl9kYXRhLmxlbmd0aCoyPHRoaXMuX2RhdGEuYnVmZmVyLmJ5dGVMZW5ndGgpe2NvbnN0IGU9bmV3IFVpbnQzMkFycmF5KHRoaXMuX2RhdGEubGVu"
    "Z3RoKTtyZXR1cm4gZS5zZXQodGhpcy5fZGF0YSksdGhpcy5fZGF0YT1lLDF9cmV0dXJuIDB9ZmlsbChlLHQ9ITEpe2lmKHQpZm9yKGxldCB0PTA7dDx0aGlz"
    "Lmxlbmd0aDsrK3QpdGhpcy5pc1Byb3RlY3RlZCh0KXx8dGhpcy5zZXRDZWxsKHQsZSk7ZWxzZXt0aGlzLl9jb21iaW5lZD17fSx0aGlzLl9leHRlbmRlZEF0"
    "dHJzPXt9O2ZvcihsZXQgdD0wO3Q8dGhpcy5sZW5ndGg7Kyt0KXRoaXMuc2V0Q2VsbCh0LGUpfX1jb3B5RnJvbShlKXt0aGlzLmxlbmd0aCE9PWUubGVuZ3Ro"
    "P3RoaXMuX2RhdGE9bmV3IFVpbnQzMkFycmF5KGUuX2RhdGEpOnRoaXMuX2RhdGEuc2V0KGUuX2RhdGEpLHRoaXMubGVuZ3RoPWUubGVuZ3RoLHRoaXMuX2Nv"
    "bWJpbmVkPXt9O2Zvcihjb25zdCB0IGluIGUuX2NvbWJpbmVkKXRoaXMuX2NvbWJpbmVkW3RdPWUuX2NvbWJpbmVkW3RdO3RoaXMuX2V4dGVuZGVkQXR0cnM9"
    "e307Zm9yKGNvbnN0IHQgaW4gZS5fZXh0ZW5kZWRBdHRycyl0aGlzLl9leHRlbmRlZEF0dHJzW3RdPWUuX2V4dGVuZGVkQXR0cnNbdF07dGhpcy5pc1dyYXBw"
    "ZWQ9ZS5pc1dyYXBwZWR9Y2xvbmUoKXtjb25zdCBlPW5ldyBoKDApO2UuX2RhdGE9bmV3IFVpbnQzMkFycmF5KHRoaXMuX2RhdGEpLGUubGVuZ3RoPXRoaXMu"
    "bGVuZ3RoO2Zvcihjb25zdCB0IGluIHRoaXMuX2NvbWJpbmVkKWUuX2NvbWJpbmVkW3RdPXRoaXMuX2NvbWJpbmVkW3RdO2Zvcihjb25zdCB0IGluIHRoaXMu"
    "X2V4dGVuZGVkQXR0cnMpZS5fZXh0ZW5kZWRBdHRyc1t0XT10aGlzLl9leHRlbmRlZEF0dHJzW3RdO3JldHVybiBlLmlzV3JhcHBlZD10aGlzLmlzV3JhcHBl"
    "ZCxlfWdldFRyaW1tZWRMZW5ndGgoKXtmb3IobGV0IGU9dGhpcy5sZW5ndGgtMTtlPj0wOy0tZSlpZig0MTk0MzAzJnRoaXMuX2RhdGFbMyplKzBdKXJldHVy"
    "biBlKyh0aGlzLl9kYXRhWzMqZSswXT4+MjIpO3JldHVybiAwfWdldE5vQmdUcmltbWVkTGVuZ3RoKCl7Zm9yKGxldCBlPXRoaXMubGVuZ3RoLTE7ZT49MDst"
    "LWUpaWYoNDE5NDMwMyZ0aGlzLl9kYXRhWzMqZSswXXx8NTAzMzE2NDgmdGhpcy5fZGF0YVszKmUrMl0pcmV0dXJuIGUrKHRoaXMuX2RhdGFbMyplKzBdPj4y"
    "Mik7cmV0dXJuIDB9Y29weUNlbGxzRnJvbShlLHQsaSxzLHIpe2NvbnN0IG49ZS5fZGF0YTtpZihyKWZvcihsZXQgcj1zLTE7cj49MDtyLS0pe2ZvcihsZXQg"
    "ZT0wO2U8MztlKyspdGhpcy5fZGF0YVszKihpK3IpK2VdPW5bMyoodCtyKStlXTsyNjg0MzU0NTYmblszKih0K3IpKzJdJiYodGhpcy5fZXh0ZW5kZWRBdHRy"
    "c1tpK3JdPWUuX2V4dGVuZGVkQXR0cnNbdCtyXSl9ZWxzZSBmb3IobGV0IHI9MDtyPHM7cisrKXtmb3IobGV0IGU9MDtlPDM7ZSsrKXRoaXMuX2RhdGFbMyoo"
    "aStyKStlXT1uWzMqKHQrcikrZV07MjY4NDM1NDU2Jm5bMyoodCtyKSsyXSYmKHRoaXMuX2V4dGVuZGVkQXR0cnNbaStyXT1lLl9leHRlbmRlZEF0dHJzW3Qr"
    "cl0pfWNvbnN0IG89T2JqZWN0LmtleXMoZS5fY29tYmluZWQpO2ZvcihsZXQgcz0wO3M8by5sZW5ndGg7cysrKXtjb25zdCByPXBhcnNlSW50KG9bc10sMTAp"
    "O3I+PXQmJih0aGlzLl9jb21iaW5lZFtyLXQraV09ZS5fY29tYmluZWRbcl0pfX10cmFuc2xhdGVUb1N0cmluZyhlPSExLHQ9MCxpPXRoaXMubGVuZ3RoKXtl"
    "JiYoaT1NYXRoLm1pbihpLHRoaXMuZ2V0VHJpbW1lZExlbmd0aCgpKSk7bGV0IHM9IiI7Zm9yKDt0PGk7KXtjb25zdCBlPXRoaXMuX2RhdGFbMyp0KzBdLGk9"
    "MjA5NzE1MSZlO3MrPTIwOTcxNTImZT90aGlzLl9jb21iaW5lZFt0XTppPygwLG8uc3RyaW5nRnJvbUNvZGVQb2ludCkoaSk6bi5XSElURVNQQUNFX0NFTExf"
    "Q0hBUix0Kz1lPj4yMnx8MX1yZXR1cm4gc319dC5CdWZmZXJMaW5lPWh9LDQ4NDE6KGUsdCk9PntPYmplY3QuZGVmaW5lUHJvcGVydHkodCwiX19lc01vZHVs"
    "ZSIse3ZhbHVlOiEwfSksdC5nZXRSYW5nZUxlbmd0aD12b2lkIDAsdC5nZXRSYW5nZUxlbmd0aD1mdW5jdGlvbihlLHQpe2lmKGUuc3RhcnQueT5lLmVuZC55"
    "KXRocm93IG5ldyBFcnJvcihgQnVmZmVyIHJhbmdlIGVuZCAoJHtlLmVuZC54fSwgJHtlLmVuZC55fSkgY2Fubm90IGJlIGJlZm9yZSBzdGFydCAoJHtlLnN0"
    "YXJ0Lnh9LCAke2Uuc3RhcnQueX0pYCk7cmV0dXJuIHQqKGUuZW5kLnktZS5zdGFydC55KSsoZS5lbmQueC1lLnN0YXJ0LngrMSl9fSw0NjM0OihlLHQpPT57"
    "ZnVuY3Rpb24gaShlLHQsaSl7aWYodD09PWUubGVuZ3RoLTEpcmV0dXJuIGVbdF0uZ2V0VHJpbW1lZExlbmd0aCgpO2NvbnN0IHM9IWVbdF0uaGFzQ29udGVu"
    "dChpLTEpJiYxPT09ZVt0XS5nZXRXaWR0aChpLTEpLHI9Mj09PWVbdCsxXS5nZXRXaWR0aCgwKTtyZXR1cm4gcyYmcj9pLTE6aX1PYmplY3QuZGVmaW5lUHJv"
    "cGVydHkodCwiX19lc01vZHVsZSIse3ZhbHVlOiEwfSksdC5nZXRXcmFwcGVkTGluZVRyaW1tZWRMZW5ndGg9dC5yZWZsb3dTbWFsbGVyR2V0TmV3TGluZUxl"
    "bmd0aHM9dC5yZWZsb3dMYXJnZXJBcHBseU5ld0xheW91dD10LnJlZmxvd0xhcmdlckNyZWF0ZU5ld0xheW91dD10LnJlZmxvd0xhcmdlckdldExpbmVzVG9S"
    "ZW1vdmU9dm9pZCAwLHQucmVmbG93TGFyZ2VyR2V0TGluZXNUb1JlbW92ZT1mdW5jdGlvbihlLHQscyxyLG4pe2NvbnN0IG89W107Zm9yKGxldCBhPTA7YTxl"
    "Lmxlbmd0aC0xO2ErKyl7bGV0IGg9YSxjPWUuZ2V0KCsraCk7aWYoIWMuaXNXcmFwcGVkKWNvbnRpbnVlO2NvbnN0IGw9W2UuZ2V0KGEpXTtmb3IoO2g8ZS5s"
    "ZW5ndGgmJmMuaXNXcmFwcGVkOylsLnB1c2goYyksYz1lLmdldCgrK2gpO2lmKHI+PWEmJnI8aCl7YSs9bC5sZW5ndGgtMTtjb250aW51ZX1sZXQgZD0wLF89"
    "aShsLGQsdCksdT0xLGY9MDtmb3IoO3U8bC5sZW5ndGg7KXtjb25zdCBlPWkobCx1LHQpLHI9ZS1mLG89cy1fLGE9TWF0aC5taW4ocixvKTtsW2RdLmNvcHlD"
    "ZWxsc0Zyb20obFt1XSxmLF8sYSwhMSksXys9YSxfPT09cyYmKGQrKyxfPTApLGYrPWEsZj09PWUmJih1KyssZj0wKSwwPT09XyYmMCE9PWQmJjI9PT1sW2Qt"
    "MV0uZ2V0V2lkdGgocy0xKSYmKGxbZF0uY29weUNlbGxzRnJvbShsW2QtMV0scy0xLF8rKywxLCExKSxsW2QtMV0uc2V0Q2VsbChzLTEsbikpfWxbZF0ucmVw"
    "bGFjZUNlbGxzKF8scyxuKTtsZXQgdj0wO2ZvcihsZXQgZT1sLmxlbmd0aC0xO2U+MCYmKGU+ZHx8MD09PWxbZV0uZ2V0VHJpbW1lZExlbmd0aCgpKTtlLS0p"
    "disrO3Y+MCYmKG8ucHVzaChhK2wubGVuZ3RoLXYpLG8ucHVzaCh2KSksYSs9bC5sZW5ndGgtMX1yZXR1cm4gb30sdC5yZWZsb3dMYXJnZXJDcmVhdGVOZXdM"
    "YXlvdXQ9ZnVuY3Rpb24oZSx0KXtjb25zdCBpPVtdO2xldCBzPTAscj10W3NdLG49MDtmb3IobGV0IG89MDtvPGUubGVuZ3RoO28rKylpZihyPT09byl7Y29u"
    "c3QgaT10Wysrc107ZS5vbkRlbGV0ZUVtaXR0ZXIuZmlyZSh7aW5kZXg6by1uLGFtb3VudDppfSksbys9aS0xLG4rPWkscj10Wysrc119ZWxzZSBpLnB1c2go"
    "byk7cmV0dXJue2xheW91dDppLGNvdW50UmVtb3ZlZDpufX0sdC5yZWZsb3dMYXJnZXJBcHBseU5ld0xheW91dD1mdW5jdGlvbihlLHQpe2NvbnN0IGk9W107"
    "Zm9yKGxldCBzPTA7czx0Lmxlbmd0aDtzKyspaS5wdXNoKGUuZ2V0KHRbc10pKTtmb3IobGV0IHQ9MDt0PGkubGVuZ3RoO3QrKyllLnNldCh0LGlbdF0pO2Uu"
    "bGVuZ3RoPXQubGVuZ3RofSx0LnJlZmxvd1NtYWxsZXJHZXROZXdMaW5lTGVuZ3Rocz1mdW5jdGlvbihlLHQscyl7Y29uc3Qgcj1bXSxuPWUubWFwKCgocyxy"
    "KT0+aShlLHIsdCkpKS5yZWR1Y2UoKChlLHQpPT5lK3QpKTtsZXQgbz0wLGE9MCxoPTA7Zm9yKDtoPG47KXtpZihuLWg8cyl7ci5wdXNoKG4taCk7YnJlYWt9"
    "bys9cztjb25zdCBjPWkoZSxhLHQpO28+YyYmKG8tPWMsYSsrKTtjb25zdCBsPTI9PT1lW2FdLmdldFdpZHRoKG8tMSk7bCYmby0tO2NvbnN0IGQ9bD9zLTE6"
    "cztyLnB1c2goZCksaCs9ZH1yZXR1cm4gcn0sdC5nZXRXcmFwcGVkTGluZVRyaW1tZWRMZW5ndGg9aX0sNTI5NTooZSx0LGkpPT57T2JqZWN0LmRlZmluZVBy"
    "b3BlcnR5KHQsIl9fZXNNb2R1bGUiLHt2YWx1ZTohMH0pLHQuQnVmZmVyU2V0PXZvaWQgMDtjb25zdCBzPWkoODQ2MCkscj1pKDg0NCksbj1pKDkwOTIpO2Ns"
    "YXNzIG8gZXh0ZW5kcyByLkRpc3Bvc2FibGV7Y29uc3RydWN0b3IoZSx0KXtzdXBlcigpLHRoaXMuX29wdGlvbnNTZXJ2aWNlPWUsdGhpcy5fYnVmZmVyU2Vy"
    "dmljZT10LHRoaXMuX29uQnVmZmVyQWN0aXZhdGU9dGhpcy5yZWdpc3RlcihuZXcgcy5FdmVudEVtaXR0ZXIpLHRoaXMub25CdWZmZXJBY3RpdmF0ZT10aGlz"
    "Ll9vbkJ1ZmZlckFjdGl2YXRlLmV2ZW50LHRoaXMucmVzZXQoKSx0aGlzLnJlZ2lzdGVyKHRoaXMuX29wdGlvbnNTZXJ2aWNlLm9uU3BlY2lmaWNPcHRpb25D"
    "aGFuZ2UoInNjcm9sbGJhY2siLCgoKT0+dGhpcy5yZXNpemUodGhpcy5fYnVmZmVyU2VydmljZS5jb2xzLHRoaXMuX2J1ZmZlclNlcnZpY2Uucm93cykpKSks"
    "dGhpcy5yZWdpc3Rlcih0aGlzLl9vcHRpb25zU2VydmljZS5vblNwZWNpZmljT3B0aW9uQ2hhbmdlKCJ0YWJTdG9wV2lkdGgiLCgoKT0+dGhpcy5zZXR1cFRh"
    "YlN0b3BzKCkpKSl9cmVzZXQoKXt0aGlzLl9ub3JtYWw9bmV3IG4uQnVmZmVyKCEwLHRoaXMuX29wdGlvbnNTZXJ2aWNlLHRoaXMuX2J1ZmZlclNlcnZpY2Up"
    "LHRoaXMuX25vcm1hbC5maWxsVmlld3BvcnRSb3dzKCksdGhpcy5fYWx0PW5ldyBuLkJ1ZmZlcighMSx0aGlzLl9vcHRpb25zU2VydmljZSx0aGlzLl9idWZm"
    "ZXJTZXJ2aWNlKSx0aGlzLl9hY3RpdmVCdWZmZXI9dGhpcy5fbm9ybWFsLHRoaXMuX29uQnVmZmVyQWN0aXZhdGUuZmlyZSh7YWN0aXZlQnVmZmVyOnRoaXMu"
    "X25vcm1hbCxpbmFjdGl2ZUJ1ZmZlcjp0aGlzLl9hbHR9KSx0aGlzLnNldHVwVGFiU3RvcHMoKX1nZXQgYWx0KCl7cmV0dXJuIHRoaXMuX2FsdH1nZXQgYWN0"
    "aXZlKCl7cmV0dXJuIHRoaXMuX2FjdGl2ZUJ1ZmZlcn1nZXQgbm9ybWFsKCl7cmV0dXJuIHRoaXMuX25vcm1hbH1hY3RpdmF0ZU5vcm1hbEJ1ZmZlcigpe3Ro"
    "aXMuX2FjdGl2ZUJ1ZmZlciE9PXRoaXMuX25vcm1hbCYmKHRoaXMuX25vcm1hbC54PXRoaXMuX2FsdC54LHRoaXMuX25vcm1hbC55PXRoaXMuX2FsdC55LHRo"
    "aXMuX2FsdC5jbGVhckFsbE1hcmtlcnMoKSx0aGlzLl9hbHQuY2xlYXIoKSx0aGlzLl9hY3RpdmVCdWZmZXI9dGhpcy5fbm9ybWFsLHRoaXMuX29uQnVmZmVy"
    "QWN0aXZhdGUuZmlyZSh7YWN0aXZlQnVmZmVyOnRoaXMuX25vcm1hbCxpbmFjdGl2ZUJ1ZmZlcjp0aGlzLl9hbHR9KSl9YWN0aXZhdGVBbHRCdWZmZXIoZSl7"
    "dGhpcy5fYWN0aXZlQnVmZmVyIT09dGhpcy5fYWx0JiYodGhpcy5fYWx0LmZpbGxWaWV3cG9ydFJvd3MoZSksdGhpcy5fYWx0Lng9dGhpcy5fbm9ybWFsLngs"
    "dGhpcy5fYWx0Lnk9dGhpcy5fbm9ybWFsLnksdGhpcy5fYWN0aXZlQnVmZmVyPXRoaXMuX2FsdCx0aGlzLl9vbkJ1ZmZlckFjdGl2YXRlLmZpcmUoe2FjdGl2"
    "ZUJ1ZmZlcjp0aGlzLl9hbHQsaW5hY3RpdmVCdWZmZXI6dGhpcy5fbm9ybWFsfSkpfXJlc2l6ZShlLHQpe3RoaXMuX25vcm1hbC5yZXNpemUoZSx0KSx0aGlz"
    "Ll9hbHQucmVzaXplKGUsdCksdGhpcy5zZXR1cFRhYlN0b3BzKGUpfXNldHVwVGFiU3RvcHMoZSl7dGhpcy5fbm9ybWFsLnNldHVwVGFiU3RvcHMoZSksdGhp"
    "cy5fYWx0LnNldHVwVGFiU3RvcHMoZSl9fXQuQnVmZmVyU2V0PW99LDUxMTooZSx0LGkpPT57T2JqZWN0LmRlZmluZVByb3BlcnR5KHQsIl9fZXNNb2R1bGUi"
    "LHt2YWx1ZTohMH0pLHQuQ2VsbERhdGE9dm9pZCAwO2NvbnN0IHM9aSg0ODIpLHI9aSg2NDMpLG49aSgzNzM0KTtjbGFzcyBvIGV4dGVuZHMgbi5BdHRyaWJ1"
    "dGVEYXRhe2NvbnN0cnVjdG9yKCl7c3VwZXIoLi4uYXJndW1lbnRzKSx0aGlzLmNvbnRlbnQ9MCx0aGlzLmZnPTAsdGhpcy5iZz0wLHRoaXMuZXh0ZW5kZWQ9"
    "bmV3IG4uRXh0ZW5kZWRBdHRycyx0aGlzLmNvbWJpbmVkRGF0YT0iIn1zdGF0aWMgZnJvbUNoYXJEYXRhKGUpe2NvbnN0IHQ9bmV3IG87cmV0dXJuIHQuc2V0"
    "RnJvbUNoYXJEYXRhKGUpLHR9aXNDb21iaW5lZCgpe3JldHVybiAyMDk3MTUyJnRoaXMuY29udGVudH1nZXRXaWR0aCgpe3JldHVybiB0aGlzLmNvbnRlbnQ+"
    "PjIyfWdldENoYXJzKCl7cmV0dXJuIDIwOTcxNTImdGhpcy5jb250ZW50P3RoaXMuY29tYmluZWREYXRhOjIwOTcxNTEmdGhpcy5jb250ZW50PygwLHMuc3Ry"
    "aW5nRnJvbUNvZGVQb2ludCkoMjA5NzE1MSZ0aGlzLmNvbnRlbnQpOiIifWdldENvZGUoKXtyZXR1cm4gdGhpcy5pc0NvbWJpbmVkKCk/dGhpcy5jb21iaW5l"
    "ZERhdGEuY2hhckNvZGVBdCh0aGlzLmNvbWJpbmVkRGF0YS5sZW5ndGgtMSk6MjA5NzE1MSZ0aGlzLmNvbnRlbnR9c2V0RnJvbUNoYXJEYXRhKGUpe3RoaXMu"
    "Zmc9ZVtyLkNIQVJfREFUQV9BVFRSX0lOREVYXSx0aGlzLmJnPTA7bGV0IHQ9ITE7aWYoZVtyLkNIQVJfREFUQV9DSEFSX0lOREVYXS5sZW5ndGg+Mil0PSEw"
    "O2Vsc2UgaWYoMj09PWVbci5DSEFSX0RBVEFfQ0hBUl9JTkRFWF0ubGVuZ3RoKXtjb25zdCBpPWVbci5DSEFSX0RBVEFfQ0hBUl9JTkRFWF0uY2hhckNvZGVB"
    "dCgwKTtpZig1NTI5Njw9aSYmaTw9NTYzMTkpe2NvbnN0IHM9ZVtyLkNIQVJfREFUQV9DSEFSX0lOREVYXS5jaGFyQ29kZUF0KDEpOzU2MzIwPD1zJiZzPD01"
    "NzM0Mz90aGlzLmNvbnRlbnQ9MTAyNCooaS01NTI5Nikrcy01NjMyMCs2NTUzNnxlW3IuQ0hBUl9EQVRBX1dJRFRIX0lOREVYXTw8MjI6dD0hMH1lbHNlIHQ9"
    "ITB9ZWxzZSB0aGlzLmNvbnRlbnQ9ZVtyLkNIQVJfREFUQV9DSEFSX0lOREVYXS5jaGFyQ29kZUF0KDApfGVbci5DSEFSX0RBVEFfV0lEVEhfSU5ERVhdPDwy"
    "Mjt0JiYodGhpcy5jb21iaW5lZERhdGE9ZVtyLkNIQVJfREFUQV9DSEFSX0lOREVYXSx0aGlzLmNvbnRlbnQ9MjA5NzE1MnxlW3IuQ0hBUl9EQVRBX1dJRFRI"
    "X0lOREVYXTw8MjIpfWdldEFzQ2hhckRhdGEoKXtyZXR1cm5bdGhpcy5mZyx0aGlzLmdldENoYXJzKCksdGhpcy5nZXRXaWR0aCgpLHRoaXMuZ2V0Q29kZSgp"
    "XX19dC5DZWxsRGF0YT1vfSw2NDM6KGUsdCk9PntPYmplY3QuZGVmaW5lUHJvcGVydHkodCwiX19lc01vZHVsZSIse3ZhbHVlOiEwfSksdC5XSElURVNQQUNF"
    "X0NFTExfQ09ERT10LldISVRFU1BBQ0VfQ0VMTF9XSURUSD10LldISVRFU1BBQ0VfQ0VMTF9DSEFSPXQuTlVMTF9DRUxMX0NPREU9dC5OVUxMX0NFTExfV0lE"
    "VEg9dC5OVUxMX0NFTExfQ0hBUj10LkNIQVJfREFUQV9DT0RFX0lOREVYPXQuQ0hBUl9EQVRBX1dJRFRIX0lOREVYPXQuQ0hBUl9EQVRBX0NIQVJfSU5ERVg9"
    "dC5DSEFSX0RBVEFfQVRUUl9JTkRFWD10LkRFRkFVTFRfRVhUPXQuREVGQVVMVF9BVFRSPXQuREVGQVVMVF9DT0xPUj12b2lkIDAsdC5ERUZBVUxUX0NPTE9S"
    "PTAsdC5ERUZBVUxUX0FUVFI9MjU2fHQuREVGQVVMVF9DT0xPUjw8OSx0LkRFRkFVTFRfRVhUPTAsdC5DSEFSX0RBVEFfQVRUUl9JTkRFWD0wLHQuQ0hBUl9E"
    "QVRBX0NIQVJfSU5ERVg9MSx0LkNIQVJfREFUQV9XSURUSF9JTkRFWD0yLHQuQ0hBUl9EQVRBX0NPREVfSU5ERVg9Myx0Lk5VTExfQ0VMTF9DSEFSPSIiLHQu"
    "TlVMTF9DRUxMX1dJRFRIPTEsdC5OVUxMX0NFTExfQ09ERT0wLHQuV0hJVEVTUEFDRV9DRUxMX0NIQVI9IiAiLHQuV0hJVEVTUEFDRV9DRUxMX1dJRFRIPTEs"
    "dC5XSElURVNQQUNFX0NFTExfQ09ERT0zMn0sNDg2MzooZSx0LGkpPT57T2JqZWN0LmRlZmluZVByb3BlcnR5KHQsIl9fZXNNb2R1bGUiLHt2YWx1ZTohMH0p"
    "LHQuTWFya2VyPXZvaWQgMDtjb25zdCBzPWkoODQ2MCkscj1pKDg0NCk7Y2xhc3MgbntnZXQgaWQoKXtyZXR1cm4gdGhpcy5faWR9Y29uc3RydWN0b3IoZSl7"
    "dGhpcy5saW5lPWUsdGhpcy5pc0Rpc3Bvc2VkPSExLHRoaXMuX2Rpc3Bvc2FibGVzPVtdLHRoaXMuX2lkPW4uX25leHRJZCsrLHRoaXMuX29uRGlzcG9zZT10"
    "aGlzLnJlZ2lzdGVyKG5ldyBzLkV2ZW50RW1pdHRlciksdGhpcy5vbkRpc3Bvc2U9dGhpcy5fb25EaXNwb3NlLmV2ZW50fWRpc3Bvc2UoKXt0aGlzLmlzRGlz"
    "cG9zZWR8fCh0aGlzLmlzRGlzcG9zZWQ9ITAsdGhpcy5saW5lPS0xLHRoaXMuX29uRGlzcG9zZS5maXJlKCksKDAsci5kaXNwb3NlQXJyYXkpKHRoaXMuX2Rp"
    "c3Bvc2FibGVzKSx0aGlzLl9kaXNwb3NhYmxlcy5sZW5ndGg9MCl9cmVnaXN0ZXIoZSl7cmV0dXJuIHRoaXMuX2Rpc3Bvc2FibGVzLnB1c2goZSksZX19dC5N"
    "YXJrZXI9bixuLl9uZXh0SWQ9MX0sNzExNjooZSx0KT0+e09iamVjdC5kZWZpbmVQcm9wZXJ0eSh0LCJfX2VzTW9kdWxlIix7dmFsdWU6ITB9KSx0LkRFRkFV"
    "TFRfQ0hBUlNFVD10LkNIQVJTRVRTPXZvaWQgMCx0LkNIQVJTRVRTPXt9LHQuREVGQVVMVF9DSEFSU0VUPXQuQ0hBUlNFVFMuQix0LkNIQVJTRVRTWzBdPXsi"
    "YCI6IuKXhiIsYToi4paSIixiOiLikIkiLGM6IuKQjCIsZDoi4pCNIixlOiLikIoiLGY6IsKwIixnOiLCsSIsaDoi4pCkIixpOiLikIsiLGo6IuKUmCIsazoi"
    "4pSQIixsOiLilIwiLG06IuKUlCIsbjoi4pS8IixvOiLijroiLHA6IuKOuyIscToi4pSAIixyOiLijrwiLHM6IuKOvSIsdDoi4pScIix1OiLilKQiLHY6IuKU"
    "tCIsdzoi4pSsIix4OiLilIIiLHk6IuKJpCIsejoi4omlIiwieyI6Is+AIiwifCI6IuKJoCIsIn0iOiLCoyIsIn4iOiLCtyJ9LHQuQ0hBUlNFVFMuQT17IiMi"
    "OiLCoyJ9LHQuQ0hBUlNFVFMuQj12b2lkIDAsdC5DSEFSU0VUU1s0XT17IiMiOiLCoyIsIkAiOiLCviIsIlsiOiJpaiIsIlxcIjoiwr0iLCJdIjoifCIsInsi"
    "OiLCqCIsInwiOiJmIiwifSI6IsK8IiwifiI6IsK0In0sdC5DSEFSU0VUUy5DPXQuQ0hBUlNFVFNbNV09eyJbIjoiw4QiLCJcXCI6IsOWIiwiXSI6IsOFIiwi"
    "XiI6IsOcIiwiYCI6IsOpIiwieyI6IsOkIiwifCI6IsO2IiwifSI6IsOlIiwifiI6IsO8In0sdC5DSEFSU0VUUy5SPXsiIyI6IsKjIiwiQCI6IsOgIiwiWyI6"
    "IsKwIiwiXFwiOiLDpyIsIl0iOiLCpyIsInsiOiLDqSIsInwiOiLDuSIsIn0iOiLDqCIsIn4iOiLCqCJ9LHQuQ0hBUlNFVFMuUT17IkAiOiLDoCIsIlsiOiLD"
    "oiIsIlxcIjoiw6ciLCJdIjoiw6oiLCJeIjoiw64iLCJgIjoiw7QiLCJ7Ijoiw6kiLCJ8Ijoiw7kiLCJ9Ijoiw6giLCJ+Ijoiw7sifSx0LkNIQVJTRVRTLks9"
    "eyJAIjoiwqciLCJbIjoiw4QiLCJcXCI6IsOWIiwiXSI6IsOcIiwieyI6IsOkIiwifCI6IsO2IiwifSI6IsO8IiwifiI6IsOfIn0sdC5DSEFSU0VUUy5ZPXsi"
    "IyI6IsKjIiwiQCI6IsKnIiwiWyI6IsKwIiwiXFwiOiLDpyIsIl0iOiLDqSIsImAiOiLDuSIsInsiOiLDoCIsInwiOiLDsiIsIn0iOiLDqCIsIn4iOiLDrCJ9"
    "LHQuQ0hBUlNFVFMuRT10LkNIQVJTRVRTWzZdPXsiQCI6IsOEIiwiWyI6IsOGIiwiXFwiOiLDmCIsIl0iOiLDhSIsIl4iOiLDnCIsImAiOiLDpCIsInsiOiLD"
    "piIsInwiOiLDuCIsIn0iOiLDpSIsIn4iOiLDvCJ9LHQuQ0hBUlNFVFMuWj17IiMiOiLCoyIsIkAiOiLCpyIsIlsiOiLCoSIsIlxcIjoiw5EiLCJdIjoiwr8i"
    "LCJ7IjoiwrAiLCJ8Ijoiw7EiLCJ9Ijoiw6cifSx0LkNIQVJTRVRTLkg9dC5DSEFSU0VUU1s3XT17IkAiOiLDiSIsIlsiOiLDhCIsIlxcIjoiw5YiLCJdIjoi"
    "w4UiLCJeIjoiw5wiLCJgIjoiw6kiLCJ7Ijoiw6QiLCJ8Ijoiw7YiLCJ9Ijoiw6UiLCJ+Ijoiw7wifSx0LkNIQVJTRVRTWyI9Il09eyIjIjoiw7kiLCJAIjoi"
    "w6AiLCJbIjoiw6kiLCJcXCI6IsOnIiwiXSI6IsOqIiwiXiI6IsOuIixfOiLDqCIsImAiOiLDtCIsInsiOiLDpCIsInwiOiLDtiIsIn0iOiLDvCIsIn4iOiLD"
    "uyJ9fSwyNTg0OihlLHQpPT57dmFyIGkscyxyO09iamVjdC5kZWZpbmVQcm9wZXJ0eSh0LCJfX2VzTW9kdWxlIix7dmFsdWU6ITB9KSx0LkMxX0VTQ0FQRUQ9"
    "dC5DMT10LkMwPXZvaWQgMCxmdW5jdGlvbihlKXtlLk5VTD0iXDAiLGUuU09IPSIBIixlLlNUWD0iAiIsZS5FVFg9IgMiLGUuRU9UPSIEIixlLkVOUT0iBSIs"
    "ZS5BQ0s9IgYiLGUuQkVMPSIHIixlLkJTPSJcYiIsZS5IVD0iXHQiLGUuTEY9IlxuIixlLlZUPSJcdiIsZS5GRj0iXGYiLGUuQ1I9IlxyIixlLlNPPSIOIixl"
    "LlNJPSIPIixlLkRMRT0iECIsZS5EQzE9IhEiLGUuREMyPSISIixlLkRDMz0iEyIsZS5EQzQ9IhQiLGUuTkFLPSIVIixlLlNZTj0iFiIsZS5FVEI9IhciLGUu"
    "Q0FOPSIYIixlLkVNPSIZIixlLlNVQj0iGiIsZS5FU0M9IhsiLGUuRlM9IhwiLGUuR1M9Ih0iLGUuUlM9Ih4iLGUuVVM9Ih8iLGUuU1A9IiAiLGUuREVMPSJ/"
    "In0oaXx8KHQuQzA9aT17fSkpLGZ1bmN0aW9uKGUpe2UuUEFEPSLCgCIsZS5IT1A9IsKBIixlLkJQSD0iwoIiLGUuTkJIPSLCgyIsZS5JTkQ9IsKEIixlLk5F"
    "TD0iwoUiLGUuU1NBPSLChiIsZS5FU0E9IsKHIixlLkhUUz0iwogiLGUuSFRKPSLCiSIsZS5WVFM9IsKKIixlLlBMRD0iwosiLGUuUExVPSLCjCIsZS5SST0i"
    "wo0iLGUuU1MyPSLCjiIsZS5TUzM9IsKPIixlLkRDUz0iwpAiLGUuUFUxPSLCkSIsZS5QVTI9IsKSIixlLlNUUz0iwpMiLGUuQ0NIPSLClCIsZS5NVz0iwpUi"
    "LGUuU1BBPSLCliIsZS5FUEE9IsKXIixlLlNPUz0iwpgiLGUuU0dDST0iwpkiLGUuU0NJPSLCmiIsZS5DU0k9IsKbIixlLlNUPSLCnCIsZS5PU0M9IsKdIixl"
    "LlBNPSLCniIsZS5BUEM9IsKfIn0oc3x8KHQuQzE9cz17fSkpLGZ1bmN0aW9uKGUpe2UuU1Q9YCR7aS5FU0N9XFxgfShyfHwodC5DMV9FU0NBUEVEPXI9e30p"
    "KX0sNzM5OTooZSx0LGkpPT57T2JqZWN0LmRlZmluZVByb3BlcnR5KHQsIl9fZXNNb2R1bGUiLHt2YWx1ZTohMH0pLHQuZXZhbHVhdGVLZXlib2FyZEV2ZW50"
    "PXZvaWQgMDtjb25zdCBzPWkoMjU4NCkscj17NDg6WyIwIiwiKSJdLDQ5OlsiMSIsIiEiXSw1MDpbIjIiLCJAIl0sNTE6WyIzIiwiIyJdLDUyOlsiNCIsIiQi"
    "XSw1MzpbIjUiLCIlIl0sNTQ6WyI2IiwiXiJdLDU1OlsiNyIsIiYiXSw1NjpbIjgiLCIqIl0sNTc6WyI5IiwiKCJdLDE4NjpbIjsiLCI6Il0sMTg3OlsiPSIs"
    "IisiXSwxODg6WyIsIiwiPCJdLDE4OTpbIi0iLCJfIl0sMTkwOlsiLiIsIj4iXSwxOTE6WyIvIiwiPyJdLDE5MjpbImAiLCJ+Il0sMjE5OlsiWyIsInsiXSwy"
    "MjA6WyJcXCIsInwiXSwyMjE6WyJdIiwifSJdLDIyMjpbIiciLCciJ119O3QuZXZhbHVhdGVLZXlib2FyZEV2ZW50PWZ1bmN0aW9uKGUsdCxpLG4pe2NvbnN0"
    "IG89e3R5cGU6MCxjYW5jZWw6ITEsa2V5OnZvaWQgMH0sYT0oZS5zaGlmdEtleT8xOjApfChlLmFsdEtleT8yOjApfChlLmN0cmxLZXk/NDowKXwoZS5tZXRh"
    "S2V5Pzg6MCk7c3dpdGNoKGUua2V5Q29kZSl7Y2FzZSAwOiJVSUtleUlucHV0VXBBcnJvdyI9PT1lLmtleT9vLmtleT10P3MuQzAuRVNDKyJPQSI6cy5DMC5F"
    "U0MrIltBIjoiVUlLZXlJbnB1dExlZnRBcnJvdyI9PT1lLmtleT9vLmtleT10P3MuQzAuRVNDKyJPRCI6cy5DMC5FU0MrIltEIjoiVUlLZXlJbnB1dFJpZ2h0"
    "QXJyb3ciPT09ZS5rZXk/by5rZXk9dD9zLkMwLkVTQysiT0MiOnMuQzAuRVNDKyJbQyI6IlVJS2V5SW5wdXREb3duQXJyb3ciPT09ZS5rZXkmJihvLmtleT10"
    "P3MuQzAuRVNDKyJPQiI6cy5DMC5FU0MrIltCIik7YnJlYWs7Y2FzZSA4OmlmKGUuYWx0S2V5KXtvLmtleT1zLkMwLkVTQytzLkMwLkRFTDticmVha31vLmtl"
    "eT1zLkMwLkRFTDticmVhaztjYXNlIDk6aWYoZS5zaGlmdEtleSl7by5rZXk9cy5DMC5FU0MrIltaIjticmVha31vLmtleT1zLkMwLkhULG8uY2FuY2VsPSEw"
    "O2JyZWFrO2Nhc2UgMTM6by5rZXk9ZS5hbHRLZXk/cy5DMC5FU0Mrcy5DMC5DUjpzLkMwLkNSLG8uY2FuY2VsPSEwO2JyZWFrO2Nhc2UgMjc6by5rZXk9cy5D"
    "MC5FU0MsZS5hbHRLZXkmJihvLmtleT1zLkMwLkVTQytzLkMwLkVTQyksby5jYW5jZWw9ITA7YnJlYWs7Y2FzZSAzNzppZihlLm1ldGFLZXkpYnJlYWs7YT8o"
    "by5rZXk9cy5DMC5FU0MrIlsxOyIrKGErMSkrIkQiLG8ua2V5PT09cy5DMC5FU0MrIlsxOzNEIiYmKG8ua2V5PXMuQzAuRVNDKyhpPyJiIjoiWzE7NUQiKSkp"
    "Om8ua2V5PXQ/cy5DMC5FU0MrIk9EIjpzLkMwLkVTQysiW0QiO2JyZWFrO2Nhc2UgMzk6aWYoZS5tZXRhS2V5KWJyZWFrO2E/KG8ua2V5PXMuQzAuRVNDKyJb"
    "MTsiKyhhKzEpKyJDIixvLmtleT09PXMuQzAuRVNDKyJbMTszQyImJihvLmtleT1zLkMwLkVTQysoaT8iZiI6IlsxOzVDIikpKTpvLmtleT10P3MuQzAuRVND"
    "KyJPQyI6cy5DMC5FU0MrIltDIjticmVhaztjYXNlIDM4OmlmKGUubWV0YUtleSlicmVhazthPyhvLmtleT1zLkMwLkVTQysiWzE7IisoYSsxKSsiQSIsaXx8"
    "by5rZXkhPT1zLkMwLkVTQysiWzE7M0EifHwoby5rZXk9cy5DMC5FU0MrIlsxOzVBIikpOm8ua2V5PXQ/cy5DMC5FU0MrIk9BIjpzLkMwLkVTQysiW0EiO2Jy"
    "ZWFrO2Nhc2UgNDA6aWYoZS5tZXRhS2V5KWJyZWFrO2E/KG8ua2V5PXMuQzAuRVNDKyJbMTsiKyhhKzEpKyJCIixpfHxvLmtleSE9PXMuQzAuRVNDKyJbMTsz"
    "QiJ8fChvLmtleT1zLkMwLkVTQysiWzE7NUIiKSk6by5rZXk9dD9zLkMwLkVTQysiT0IiOnMuQzAuRVNDKyJbQiI7YnJlYWs7Y2FzZSA0NTplLnNoaWZ0S2V5"
    "fHxlLmN0cmxLZXl8fChvLmtleT1zLkMwLkVTQysiWzJ+Iik7YnJlYWs7Y2FzZSA0NjpvLmtleT1hP3MuQzAuRVNDKyJbMzsiKyhhKzEpKyJ+IjpzLkMwLkVT"
    "QysiWzN+IjticmVhaztjYXNlIDM2Om8ua2V5PWE/cy5DMC5FU0MrIlsxOyIrKGErMSkrIkgiOnQ/cy5DMC5FU0MrIk9IIjpzLkMwLkVTQysiW0giO2JyZWFr"
    "O2Nhc2UgMzU6by5rZXk9YT9zLkMwLkVTQysiWzE7IisoYSsxKSsiRiI6dD9zLkMwLkVTQysiT0YiOnMuQzAuRVNDKyJbRiI7YnJlYWs7Y2FzZSAzMzplLnNo"
    "aWZ0S2V5P28udHlwZT0yOmUuY3RybEtleT9vLmtleT1zLkMwLkVTQysiWzU7IisoYSsxKSsifiI6by5rZXk9cy5DMC5FU0MrIls1fiI7YnJlYWs7Y2FzZSAz"
    "NDplLnNoaWZ0S2V5P28udHlwZT0zOmUuY3RybEtleT9vLmtleT1zLkMwLkVTQysiWzY7IisoYSsxKSsifiI6by5rZXk9cy5DMC5FU0MrIls2fiI7YnJlYWs7"
    "Y2FzZSAxMTI6by5rZXk9YT9zLkMwLkVTQysiWzE7IisoYSsxKSsiUCI6cy5DMC5FU0MrIk9QIjticmVhaztjYXNlIDExMzpvLmtleT1hP3MuQzAuRVNDKyJb"
    "MTsiKyhhKzEpKyJRIjpzLkMwLkVTQysiT1EiO2JyZWFrO2Nhc2UgMTE0Om8ua2V5PWE/cy5DMC5FU0MrIlsxOyIrKGErMSkrIlIiOnMuQzAuRVNDKyJPUiI7"
    "YnJlYWs7Y2FzZSAxMTU6by5rZXk9YT9zLkMwLkVTQysiWzE7IisoYSsxKSsiUyI6cy5DMC5FU0MrIk9TIjticmVhaztjYXNlIDExNjpvLmtleT1hP3MuQzAu"
    "RVNDKyJbMTU7IisoYSsxKSsifiI6cy5DMC5FU0MrIlsxNX4iO2JyZWFrO2Nhc2UgMTE3Om8ua2V5PWE/cy5DMC5FU0MrIlsxNzsiKyhhKzEpKyJ+IjpzLkMw"
    "LkVTQysiWzE3fiI7YnJlYWs7Y2FzZSAxMTg6by5rZXk9YT9zLkMwLkVTQysiWzE4OyIrKGErMSkrIn4iOnMuQzAuRVNDKyJbMTh+IjticmVhaztjYXNlIDEx"
    "OTpvLmtleT1hP3MuQzAuRVNDKyJbMTk7IisoYSsxKSsifiI6cy5DMC5FU0MrIlsxOX4iO2JyZWFrO2Nhc2UgMTIwOm8ua2V5PWE/cy5DMC5FU0MrIlsyMDsi"
    "KyhhKzEpKyJ+IjpzLkMwLkVTQysiWzIwfiI7YnJlYWs7Y2FzZSAxMjE6by5rZXk9YT9zLkMwLkVTQysiWzIxOyIrKGErMSkrIn4iOnMuQzAuRVNDKyJbMjF+"
    "IjticmVhaztjYXNlIDEyMjpvLmtleT1hP3MuQzAuRVNDKyJbMjM7IisoYSsxKSsifiI6cy5DMC5FU0MrIlsyM34iO2JyZWFrO2Nhc2UgMTIzOm8ua2V5PWE/"
    "cy5DMC5FU0MrIlsyNDsiKyhhKzEpKyJ+IjpzLkMwLkVTQysiWzI0fiI7YnJlYWs7ZGVmYXVsdDppZighZS5jdHJsS2V5fHxlLnNoaWZ0S2V5fHxlLmFsdEtl"
    "eXx8ZS5tZXRhS2V5KWlmKGkmJiFufHwhZS5hbHRLZXl8fGUubWV0YUtleSkhaXx8ZS5hbHRLZXl8fGUuY3RybEtleXx8ZS5zaGlmdEtleXx8IWUubWV0YUtl"
    "eT9lLmtleSYmIWUuY3RybEtleSYmIWUuYWx0S2V5JiYhZS5tZXRhS2V5JiZlLmtleUNvZGU+PTQ4JiYxPT09ZS5rZXkubGVuZ3RoP28ua2V5PWUua2V5OmUu"
    "a2V5JiZlLmN0cmxLZXkmJigiXyI9PT1lLmtleSYmKG8ua2V5PXMuQzAuVVMpLCJAIj09PWUua2V5JiYoby5rZXk9cy5DMC5OVUwpKTo2NT09PWUua2V5Q29k"
    "ZSYmKG8udHlwZT0xKTtlbHNle2NvbnN0IHQ9cltlLmtleUNvZGVdLGk9bnVsbD09dD92b2lkIDA6dFtlLnNoaWZ0S2V5PzE6MF07aWYoaSlvLmtleT1zLkMw"
    "LkVTQytpO2Vsc2UgaWYoZS5rZXlDb2RlPj02NSYmZS5rZXlDb2RlPD05MCl7Y29uc3QgdD1lLmN0cmxLZXk/ZS5rZXlDb2RlLTY0OmUua2V5Q29kZSszMjts"
    "ZXQgaT1TdHJpbmcuZnJvbUNoYXJDb2RlKHQpO2Uuc2hpZnRLZXkmJihpPWkudG9VcHBlckNhc2UoKSksby5rZXk9cy5DMC5FU0MraX1lbHNlIGlmKDMyPT09"
    "ZS5rZXlDb2RlKW8ua2V5PXMuQzAuRVNDKyhlLmN0cmxLZXk/cy5DMC5OVUw6IiAiKTtlbHNlIGlmKCJEZWFkIj09PWUua2V5JiZlLmNvZGUuc3RhcnRzV2l0"
    "aCgiS2V5Iikpe2xldCB0PWUuY29kZS5zbGljZSgzLDQpO2Uuc2hpZnRLZXl8fCh0PXQudG9Mb3dlckNhc2UoKSksby5rZXk9cy5DMC5FU0MrdCxvLmNhbmNl"
    "bD0hMH19ZWxzZSBlLmtleUNvZGU+PTY1JiZlLmtleUNvZGU8PTkwP28ua2V5PVN0cmluZy5mcm9tQ2hhckNvZGUoZS5rZXlDb2RlLTY0KTozMj09PWUua2V5"
    "Q29kZT9vLmtleT1zLkMwLk5VTDplLmtleUNvZGU+PTUxJiZlLmtleUNvZGU8PTU1P28ua2V5PVN0cmluZy5mcm9tQ2hhckNvZGUoZS5rZXlDb2RlLTUxKzI3"
    "KTo1Nj09PWUua2V5Q29kZT9vLmtleT1zLkMwLkRFTDoyMTk9PT1lLmtleUNvZGU/by5rZXk9cy5DMC5FU0M6MjIwPT09ZS5rZXlDb2RlP28ua2V5PXMuQzAu"
    "RlM6MjIxPT09ZS5rZXlDb2RlJiYoby5rZXk9cy5DMC5HUyl9cmV0dXJuIG99fSw0ODI6KGUsdCk9PntPYmplY3QuZGVmaW5lUHJvcGVydHkodCwiX19lc01v"
    "ZHVsZSIse3ZhbHVlOiEwfSksdC5VdGY4VG9VdGYzMj10LlN0cmluZ1RvVXRmMzI9dC51dGYzMlRvU3RyaW5nPXQuc3RyaW5nRnJvbUNvZGVQb2ludD12b2lk"
    "IDAsdC5zdHJpbmdGcm9tQ29kZVBvaW50PWZ1bmN0aW9uKGUpe3JldHVybiBlPjY1NTM1PyhlLT02NTUzNixTdHJpbmcuZnJvbUNoYXJDb2RlKDU1Mjk2Kyhl"
    "Pj4xMCkpK1N0cmluZy5mcm9tQ2hhckNvZGUoZSUxMDI0KzU2MzIwKSk6U3RyaW5nLmZyb21DaGFyQ29kZShlKX0sdC51dGYzMlRvU3RyaW5nPWZ1bmN0aW9u"
    "KGUsdD0wLGk9ZS5sZW5ndGgpe2xldCBzPSIiO2ZvcihsZXQgcj10O3I8aTsrK3Ipe2xldCB0PWVbcl07dD42NTUzNT8odC09NjU1MzYscys9U3RyaW5nLmZy"
    "b21DaGFyQ29kZSg1NTI5NisodD4+MTApKStTdHJpbmcuZnJvbUNoYXJDb2RlKHQlMTAyNCs1NjMyMCkpOnMrPVN0cmluZy5mcm9tQ2hhckNvZGUodCl9cmV0"
    "dXJuIHN9LHQuU3RyaW5nVG9VdGYzMj1jbGFzc3tjb25zdHJ1Y3Rvcigpe3RoaXMuX2ludGVyaW09MH1jbGVhcigpe3RoaXMuX2ludGVyaW09MH1kZWNvZGUo"
    "ZSx0KXtjb25zdCBpPWUubGVuZ3RoO2lmKCFpKXJldHVybiAwO2xldCBzPTAscj0wO2lmKHRoaXMuX2ludGVyaW0pe2NvbnN0IGk9ZS5jaGFyQ29kZUF0KHIr"
    "Kyk7NTYzMjA8PWkmJmk8PTU3MzQzP3RbcysrXT0xMDI0Kih0aGlzLl9pbnRlcmltLTU1Mjk2KStpLTU2MzIwKzY1NTM2Oih0W3MrK109dGhpcy5faW50ZXJp"
    "bSx0W3MrK109aSksdGhpcy5faW50ZXJpbT0wfWZvcihsZXQgbj1yO248aTsrK24pe2NvbnN0IHI9ZS5jaGFyQ29kZUF0KG4pO2lmKDU1Mjk2PD1yJiZyPD01"
    "NjMxOSl7aWYoKytuPj1pKXJldHVybiB0aGlzLl9pbnRlcmltPXIscztjb25zdCBvPWUuY2hhckNvZGVBdChuKTs1NjMyMDw9byYmbzw9NTczNDM/dFtzKytd"
    "PTEwMjQqKHItNTUyOTYpK28tNTYzMjArNjU1MzY6KHRbcysrXT1yLHRbcysrXT1vKX1lbHNlIDY1Mjc5IT09ciYmKHRbcysrXT1yKX1yZXR1cm4gc319LHQu"
    "VXRmOFRvVXRmMzI9Y2xhc3N7Y29uc3RydWN0b3IoKXt0aGlzLmludGVyaW09bmV3IFVpbnQ4QXJyYXkoMyl9Y2xlYXIoKXt0aGlzLmludGVyaW0uZmlsbCgw"
    "KX1kZWNvZGUoZSx0KXtjb25zdCBpPWUubGVuZ3RoO2lmKCFpKXJldHVybiAwO2xldCBzLHIsbixvLGE9MCxoPTAsYz0wO2lmKHRoaXMuaW50ZXJpbVswXSl7"
    "bGV0IHM9ITEscj10aGlzLmludGVyaW1bMF07ciY9MTkyPT0oMjI0JnIpPzMxOjIyND09KDI0MCZyKT8xNTo3O2xldCBuLG89MDtmb3IoOyhuPTYzJnRoaXMu"
    "aW50ZXJpbVsrK29dKSYmbzw0OylyPDw9NixyfD1uO2NvbnN0IGg9MTkyPT0oMjI0JnRoaXMuaW50ZXJpbVswXSk/MjoyMjQ9PSgyNDAmdGhpcy5pbnRlcmlt"
    "WzBdKT8zOjQsbD1oLW87Zm9yKDtjPGw7KXtpZihjPj1pKXJldHVybiAwO2lmKG49ZVtjKytdLDEyOCE9KDE5MiZuKSl7Yy0tLHM9ITA7YnJlYWt9dGhpcy5p"
    "bnRlcmltW28rK109bixyPDw9NixyfD02MyZufXN8fCgyPT09aD9yPDEyOD9jLS06dFthKytdPXI6Mz09PWg/cjwyMDQ4fHxyPj01NTI5NiYmcjw9NTczNDN8"
    "fDY1Mjc5PT09cnx8KHRbYSsrXT1yKTpyPDY1NTM2fHxyPjExMTQxMTF8fCh0W2ErK109cikpLHRoaXMuaW50ZXJpbS5maWxsKDApfWNvbnN0IGw9aS00O2xl"
    "dCBkPWM7Zm9yKDtkPGk7KXtmb3IoOyEoIShkPGwpfHwxMjgmKHM9ZVtkXSl8fDEyOCYocj1lW2QrMV0pfHwxMjgmKG49ZVtkKzJdKXx8MTI4JihvPWVbZCsz"
    "XSkpOyl0W2ErK109cyx0W2ErK109cix0W2ErK109bix0W2ErK109byxkKz00O2lmKHM9ZVtkKytdLHM8MTI4KXRbYSsrXT1zO2Vsc2UgaWYoMTkyPT0oMjI0"
    "JnMpKXtpZihkPj1pKXJldHVybiB0aGlzLmludGVyaW1bMF09cyxhO2lmKHI9ZVtkKytdLDEyOCE9KDE5MiZyKSl7ZC0tO2NvbnRpbnVlfWlmKGg9KDMxJnMp"
    "PDw2fDYzJnIsaDwxMjgpe2QtLTtjb250aW51ZX10W2ErK109aH1lbHNlIGlmKDIyND09KDI0MCZzKSl7aWYoZD49aSlyZXR1cm4gdGhpcy5pbnRlcmltWzBd"
    "PXMsYTtpZihyPWVbZCsrXSwxMjghPSgxOTImcikpe2QtLTtjb250aW51ZX1pZihkPj1pKXJldHVybiB0aGlzLmludGVyaW1bMF09cyx0aGlzLmludGVyaW1b"
    "MV09cixhO2lmKG49ZVtkKytdLDEyOCE9KDE5MiZuKSl7ZC0tO2NvbnRpbnVlfWlmKGg9KDE1JnMpPDwxMnwoNjMmcik8PDZ8NjMmbixoPDIwNDh8fGg+PTU1"
    "Mjk2JiZoPD01NzM0M3x8NjUyNzk9PT1oKWNvbnRpbnVlO3RbYSsrXT1ofWVsc2UgaWYoMjQwPT0oMjQ4JnMpKXtpZihkPj1pKXJldHVybiB0aGlzLmludGVy"
    "aW1bMF09cyxhO2lmKHI9ZVtkKytdLDEyOCE9KDE5MiZyKSl7ZC0tO2NvbnRpbnVlfWlmKGQ+PWkpcmV0dXJuIHRoaXMuaW50ZXJpbVswXT1zLHRoaXMuaW50"
    "ZXJpbVsxXT1yLGE7aWYobj1lW2QrK10sMTI4IT0oMTkyJm4pKXtkLS07Y29udGludWV9aWYoZD49aSlyZXR1cm4gdGhpcy5pbnRlcmltWzBdPXMsdGhpcy5p"
    "bnRlcmltWzFdPXIsdGhpcy5pbnRlcmltWzJdPW4sYTtpZihvPWVbZCsrXSwxMjghPSgxOTImbykpe2QtLTtjb250aW51ZX1pZihoPSg3JnMpPDwxOHwoNjMm"
    "cik8PDEyfCg2MyZuKTw8Nnw2MyZvLGg8NjU1MzZ8fGg+MTExNDExMSljb250aW51ZTt0W2ErK109aH19cmV0dXJuIGF9fX0sMjI1OihlLHQpPT57T2JqZWN0"
    "LmRlZmluZVByb3BlcnR5KHQsIl9fZXNNb2R1bGUiLHt2YWx1ZTohMH0pLHQuVW5pY29kZVY2PXZvaWQgMDtjb25zdCBpPVtbNzY4LDg3OV0sWzExNTUsMTE1"
    "OF0sWzExNjAsMTE2MV0sWzE0MjUsMTQ2OV0sWzE0NzEsMTQ3MV0sWzE0NzMsMTQ3NF0sWzE0NzYsMTQ3N10sWzE0NzksMTQ3OV0sWzE1MzYsMTUzOV0sWzE1"
    "NTIsMTU1N10sWzE2MTEsMTYzMF0sWzE2NDgsMTY0OF0sWzE3NTAsMTc2NF0sWzE3NjcsMTc2OF0sWzE3NzAsMTc3M10sWzE4MDcsMTgwN10sWzE4MDksMTgw"
    "OV0sWzE4NDAsMTg2Nl0sWzE5NTgsMTk2OF0sWzIwMjcsMjAzNV0sWzIzMDUsMjMwNl0sWzIzNjQsMjM2NF0sWzIzNjksMjM3Nl0sWzIzODEsMjM4MV0sWzIz"
    "ODUsMjM4OF0sWzI0MDIsMjQwM10sWzI0MzMsMjQzM10sWzI0OTIsMjQ5Ml0sWzI0OTcsMjUwMF0sWzI1MDksMjUwOV0sWzI1MzAsMjUzMV0sWzI1NjEsMjU2"
    "Ml0sWzI2MjAsMjYyMF0sWzI2MjUsMjYyNl0sWzI2MzEsMjYzMl0sWzI2MzUsMjYzN10sWzI2NzIsMjY3M10sWzI2ODksMjY5MF0sWzI3NDgsMjc0OF0sWzI3"
    "NTMsMjc1N10sWzI3NTksMjc2MF0sWzI3NjUsMjc2NV0sWzI3ODYsMjc4N10sWzI4MTcsMjgxN10sWzI4NzYsMjg3Nl0sWzI4NzksMjg3OV0sWzI4ODEsMjg4"
    "M10sWzI4OTMsMjg5M10sWzI5MDIsMjkwMl0sWzI5NDYsMjk0Nl0sWzMwMDgsMzAwOF0sWzMwMjEsMzAyMV0sWzMxMzQsMzEzNl0sWzMxNDIsMzE0NF0sWzMx"
    "NDYsMzE0OV0sWzMxNTcsMzE1OF0sWzMyNjAsMzI2MF0sWzMyNjMsMzI2M10sWzMyNzAsMzI3MF0sWzMyNzYsMzI3N10sWzMyOTgsMzI5OV0sWzMzOTMsMzM5"
    "NV0sWzM0MDUsMzQwNV0sWzM1MzAsMzUzMF0sWzM1MzgsMzU0MF0sWzM1NDIsMzU0Ml0sWzM2MzMsMzYzM10sWzM2MzYsMzY0Ml0sWzM2NTUsMzY2Ml0sWzM3"
    "NjEsMzc2MV0sWzM3NjQsMzc2OV0sWzM3NzEsMzc3Ml0sWzM3ODQsMzc4OV0sWzM4NjQsMzg2NV0sWzM4OTMsMzg5M10sWzM4OTUsMzg5NV0sWzM4OTcsMzg5"
    "N10sWzM5NTMsMzk2Nl0sWzM5NjgsMzk3Ml0sWzM5NzQsMzk3NV0sWzM5ODQsMzk5MV0sWzM5OTMsNDAyOF0sWzQwMzgsNDAzOF0sWzQxNDEsNDE0NF0sWzQx"
    "NDYsNDE0Nl0sWzQxNTAsNDE1MV0sWzQxNTMsNDE1M10sWzQxODQsNDE4NV0sWzQ0NDgsNDYwN10sWzQ5NTksNDk1OV0sWzU5MDYsNTkwOF0sWzU5MzgsNTk0"
    "MF0sWzU5NzAsNTk3MV0sWzYwMDIsNjAwM10sWzYwNjgsNjA2OV0sWzYwNzEsNjA3N10sWzYwODYsNjA4Nl0sWzYwODksNjA5OV0sWzYxMDksNjEwOV0sWzYx"
    "NTUsNjE1N10sWzYzMTMsNjMxM10sWzY0MzIsNjQzNF0sWzY0MzksNjQ0MF0sWzY0NTAsNjQ1MF0sWzY0NTcsNjQ1OV0sWzY2NzksNjY4MF0sWzY5MTIsNjkx"
    "NV0sWzY5NjQsNjk2NF0sWzY5NjYsNjk3MF0sWzY5NzIsNjk3Ml0sWzY5NzgsNjk3OF0sWzcwMTksNzAyN10sWzc2MTYsNzYyNl0sWzc2NzgsNzY3OV0sWzgy"
    "MDMsODIwN10sWzgyMzQsODIzOF0sWzgyODgsODI5MV0sWzgyOTgsODMwM10sWzg0MDAsODQzMV0sWzEyMzMwLDEyMzM1XSxbMTI0NDEsMTI0NDJdLFs0MzAx"
    "NCw0MzAxNF0sWzQzMDE5LDQzMDE5XSxbNDMwNDUsNDMwNDZdLFs2NDI4Niw2NDI4Nl0sWzY1MDI0LDY1MDM5XSxbNjUwNTYsNjUwNTldLFs2NTI3OSw2NTI3"
    "OV0sWzY1NTI5LDY1NTMxXV0scz1bWzY4MDk3LDY4MDk5XSxbNjgxMDEsNjgxMDJdLFs2ODEwOCw2ODExMV0sWzY4MTUyLDY4MTU0XSxbNjgxNTksNjgxNTld"
    "LFsxMTkxNDMsMTE5MTQ1XSxbMTE5MTU1LDExOTE3MF0sWzExOTE3MywxMTkxNzldLFsxMTkyMTAsMTE5MjEzXSxbMTE5MzYyLDExOTM2NF0sWzkxNzUwNSw5"
    "MTc1MDVdLFs5MTc1MzYsOTE3NjMxXSxbOTE3NzYwLDkxNzk5OV1dO2xldCByO3QuVW5pY29kZVY2PWNsYXNze2NvbnN0cnVjdG9yKCl7aWYodGhpcy52ZXJz"
    "aW9uPSI2Iiwhcil7cj1uZXcgVWludDhBcnJheSg2NTUzNiksci5maWxsKDEpLHJbMF09MCxyLmZpbGwoMCwxLDMyKSxyLmZpbGwoMCwxMjcsMTYwKSxyLmZp"
    "bGwoMiw0MzUyLDQ0NDgpLHJbOTAwMV09MixyWzkwMDJdPTIsci5maWxsKDIsMTE5MDQsNDIxOTIpLHJbMTIzNTFdPTEsci5maWxsKDIsNDQwMzIsNTUyMDQp"
    "LHIuZmlsbCgyLDYzNzQ0LDY0MjU2KSxyLmZpbGwoMiw2NTA0MCw2NTA1MCksci5maWxsKDIsNjUwNzIsNjUxMzYpLHIuZmlsbCgyLDY1MjgwLDY1Mzc3KSxy"
    "LmZpbGwoMiw2NTUwNCw2NTUxMSk7Zm9yKGxldCBlPTA7ZTxpLmxlbmd0aDsrK2Upci5maWxsKDAsaVtlXVswXSxpW2VdWzFdKzEpfX13Y3dpZHRoKGUpe3Jl"
    "dHVybiBlPDMyPzA6ZTwxMjc/MTplPDY1NTM2P3JbZV06ZnVuY3Rpb24oZSx0KXtsZXQgaSxzPTAscj10Lmxlbmd0aC0xO2lmKGU8dFswXVswXXx8ZT50W3Jd"
    "WzFdKXJldHVybiExO2Zvcig7cj49czspaWYoaT1zK3I+PjEsZT50W2ldWzFdKXM9aSsxO2Vsc2V7aWYoIShlPHRbaV1bMF0pKXJldHVybiEwO3I9aS0xfXJl"
    "dHVybiExfShlLHMpPzA6ZT49MTMxMDcyJiZlPD0xOTY2MDV8fGU+PTE5NjYwOCYmZTw9MjYyMTQxPzI6MX19fSw1OTgxOihlLHQsaSk9PntPYmplY3QuZGVm"
    "aW5lUHJvcGVydHkodCwiX19lc01vZHVsZSIse3ZhbHVlOiEwfSksdC5Xcml0ZUJ1ZmZlcj12b2lkIDA7Y29uc3Qgcz1pKDg0NjApLHI9aSg4NDQpO2NsYXNz"
    "IG4gZXh0ZW5kcyByLkRpc3Bvc2FibGV7Y29uc3RydWN0b3IoZSl7c3VwZXIoKSx0aGlzLl9hY3Rpb249ZSx0aGlzLl93cml0ZUJ1ZmZlcj1bXSx0aGlzLl9j"
    "YWxsYmFja3M9W10sdGhpcy5fcGVuZGluZ0RhdGE9MCx0aGlzLl9idWZmZXJPZmZzZXQ9MCx0aGlzLl9pc1N5bmNXcml0aW5nPSExLHRoaXMuX3N5bmNDYWxs"
    "cz0wLHRoaXMuX2RpZFVzZXJJbnB1dD0hMSx0aGlzLl9vbldyaXRlUGFyc2VkPXRoaXMucmVnaXN0ZXIobmV3IHMuRXZlbnRFbWl0dGVyKSx0aGlzLm9uV3Jp"
    "dGVQYXJzZWQ9dGhpcy5fb25Xcml0ZVBhcnNlZC5ldmVudH1oYW5kbGVVc2VySW5wdXQoKXt0aGlzLl9kaWRVc2VySW5wdXQ9ITB9d3JpdGVTeW5jKGUsdCl7"
    "aWYodm9pZCAwIT09dCYmdGhpcy5fc3luY0NhbGxzPnQpcmV0dXJuIHZvaWQodGhpcy5fc3luY0NhbGxzPTApO2lmKHRoaXMuX3BlbmRpbmdEYXRhKz1lLmxl"
    "bmd0aCx0aGlzLl93cml0ZUJ1ZmZlci5wdXNoKGUpLHRoaXMuX2NhbGxiYWNrcy5wdXNoKHZvaWQgMCksdGhpcy5fc3luY0NhbGxzKyssdGhpcy5faXNTeW5j"
    "V3JpdGluZylyZXR1cm47bGV0IGk7Zm9yKHRoaXMuX2lzU3luY1dyaXRpbmc9ITA7aT10aGlzLl93cml0ZUJ1ZmZlci5zaGlmdCgpOyl7dGhpcy5fYWN0aW9u"
    "KGkpO2NvbnN0IGU9dGhpcy5fY2FsbGJhY2tzLnNoaWZ0KCk7ZSYmZSgpfXRoaXMuX3BlbmRpbmdEYXRhPTAsdGhpcy5fYnVmZmVyT2Zmc2V0PTIxNDc0ODM2"
    "NDcsdGhpcy5faXNTeW5jV3JpdGluZz0hMSx0aGlzLl9zeW5jQ2FsbHM9MH13cml0ZShlLHQpe2lmKHRoaXMuX3BlbmRpbmdEYXRhPjVlNyl0aHJvdyBuZXcg"
    "RXJyb3IoIndyaXRlIGRhdGEgZGlzY2FyZGVkLCB1c2UgZmxvdyBjb250cm9sIHRvIGF2b2lkIGxvc2luZyBkYXRhIik7aWYoIXRoaXMuX3dyaXRlQnVmZmVy"
    "Lmxlbmd0aCl7aWYodGhpcy5fYnVmZmVyT2Zmc2V0PTAsdGhpcy5fZGlkVXNlcklucHV0KXJldHVybiB0aGlzLl9kaWRVc2VySW5wdXQ9ITEsdGhpcy5fcGVu"
    "ZGluZ0RhdGErPWUubGVuZ3RoLHRoaXMuX3dyaXRlQnVmZmVyLnB1c2goZSksdGhpcy5fY2FsbGJhY2tzLnB1c2godCksdm9pZCB0aGlzLl9pbm5lcldyaXRl"
    "KCk7c2V0VGltZW91dCgoKCk9PnRoaXMuX2lubmVyV3JpdGUoKSkpfXRoaXMuX3BlbmRpbmdEYXRhKz1lLmxlbmd0aCx0aGlzLl93cml0ZUJ1ZmZlci5wdXNo"
    "KGUpLHRoaXMuX2NhbGxiYWNrcy5wdXNoKHQpfV9pbm5lcldyaXRlKGU9MCx0PSEwKXtjb25zdCBpPWV8fERhdGUubm93KCk7Zm9yKDt0aGlzLl93cml0ZUJ1"
    "ZmZlci5sZW5ndGg+dGhpcy5fYnVmZmVyT2Zmc2V0Oyl7Y29uc3QgZT10aGlzLl93cml0ZUJ1ZmZlclt0aGlzLl9idWZmZXJPZmZzZXRdLHM9dGhpcy5fYWN0"
    "aW9uKGUsdCk7aWYocyl7Y29uc3QgZT1lPT5EYXRlLm5vdygpLWk+PTEyP3NldFRpbWVvdXQoKCgpPT50aGlzLl9pbm5lcldyaXRlKDAsZSkpKTp0aGlzLl9p"
    "bm5lcldyaXRlKGksZSk7cmV0dXJuIHZvaWQgcy5jYXRjaCgoZT0+KHF1ZXVlTWljcm90YXNrKCgoKT0+e3Rocm93IGV9KSksUHJvbWlzZS5yZXNvbHZlKCEx"
    "KSkpKS50aGVuKGUpfWNvbnN0IHI9dGhpcy5fY2FsbGJhY2tzW3RoaXMuX2J1ZmZlck9mZnNldF07aWYociYmcigpLHRoaXMuX2J1ZmZlck9mZnNldCsrLHRo"
    "aXMuX3BlbmRpbmdEYXRhLT1lLmxlbmd0aCxEYXRlLm5vdygpLWk+PTEyKWJyZWFrfXRoaXMuX3dyaXRlQnVmZmVyLmxlbmd0aD50aGlzLl9idWZmZXJPZmZz"
    "ZXQ/KHRoaXMuX2J1ZmZlck9mZnNldD41MCYmKHRoaXMuX3dyaXRlQnVmZmVyPXRoaXMuX3dyaXRlQnVmZmVyLnNsaWNlKHRoaXMuX2J1ZmZlck9mZnNldCks"
    "dGhpcy5fY2FsbGJhY2tzPXRoaXMuX2NhbGxiYWNrcy5zbGljZSh0aGlzLl9idWZmZXJPZmZzZXQpLHRoaXMuX2J1ZmZlck9mZnNldD0wKSxzZXRUaW1lb3V0"
    "KCgoKT0+dGhpcy5faW5uZXJXcml0ZSgpKSkpOih0aGlzLl93cml0ZUJ1ZmZlci5sZW5ndGg9MCx0aGlzLl9jYWxsYmFja3MubGVuZ3RoPTAsdGhpcy5fcGVu"
    "ZGluZ0RhdGE9MCx0aGlzLl9idWZmZXJPZmZzZXQ9MCksdGhpcy5fb25Xcml0ZVBhcnNlZC5maXJlKCl9fXQuV3JpdGVCdWZmZXI9bn0sNTk0MTooZSx0KT0+"
    "e09iamVjdC5kZWZpbmVQcm9wZXJ0eSh0LCJfX2VzTW9kdWxlIix7dmFsdWU6ITB9KSx0LnRvUmdiU3RyaW5nPXQucGFyc2VDb2xvcj12b2lkIDA7Y29uc3Qg"
    "aT0vXihbXGRhLWZdKVwvKFtcZGEtZl0pXC8oW1xkYS1mXSkkfF4oW1xkYS1mXXsyfSlcLyhbXGRhLWZdezJ9KVwvKFtcZGEtZl17Mn0pJHxeKFtcZGEtZl17"
    "M30pXC8oW1xkYS1mXXszfSlcLyhbXGRhLWZdezN9KSR8XihbXGRhLWZdezR9KVwvKFtcZGEtZl17NH0pXC8oW1xkYS1mXXs0fSkkLyxzPS9eW1xkYS1mXSsk"
    "LztmdW5jdGlvbiByKGUsdCl7Y29uc3QgaT1lLnRvU3RyaW5nKDE2KSxzPWkubGVuZ3RoPDI/IjAiK2k6aTtzd2l0Y2godCl7Y2FzZSA0OnJldHVybiBpWzBd"
    "O2Nhc2UgODpyZXR1cm4gcztjYXNlIDEyOnJldHVybihzK3MpLnNsaWNlKDAsMyk7ZGVmYXVsdDpyZXR1cm4gcytzfX10LnBhcnNlQ29sb3I9ZnVuY3Rpb24o"
    "ZSl7aWYoIWUpcmV0dXJuO2xldCB0PWUudG9Mb3dlckNhc2UoKTtpZigwPT09dC5pbmRleE9mKCJyZ2I6Iikpe3Q9dC5zbGljZSg0KTtjb25zdCBlPWkuZXhl"
    "Yyh0KTtpZihlKXtjb25zdCB0PWVbMV0/MTU6ZVs0XT8yNTU6ZVs3XT80MDk1OjY1NTM1O3JldHVybltNYXRoLnJvdW5kKHBhcnNlSW50KGVbMV18fGVbNF18"
    "fGVbN118fGVbMTBdLDE2KS90KjI1NSksTWF0aC5yb3VuZChwYXJzZUludChlWzJdfHxlWzVdfHxlWzhdfHxlWzExXSwxNikvdCoyNTUpLE1hdGgucm91bmQo"
    "cGFyc2VJbnQoZVszXXx8ZVs2XXx8ZVs5XXx8ZVsxMl0sMTYpL3QqMjU1KV19fWVsc2UgaWYoMD09PXQuaW5kZXhPZigiIyIpJiYodD10LnNsaWNlKDEpLHMu"
    "ZXhlYyh0KSYmWzMsNiw5LDEyXS5pbmNsdWRlcyh0Lmxlbmd0aCkpKXtjb25zdCBlPXQubGVuZ3RoLzMsaT1bMCwwLDBdO2ZvcihsZXQgcz0wO3M8MzsrK3Mp"
    "e2NvbnN0IHI9cGFyc2VJbnQodC5zbGljZShlKnMsZSpzK2UpLDE2KTtpW3NdPTE9PT1lP3I8PDQ6Mj09PWU/cjozPT09ZT9yPj40OnI+Pjh9cmV0dXJuIGl9"
    "fSx0LnRvUmdiU3RyaW5nPWZ1bmN0aW9uKGUsdD0xNil7Y29uc3RbaSxzLG5dPWU7cmV0dXJuYHJnYjoke3IoaSx0KX0vJHtyKHMsdCl9LyR7cihuLHQpfWB9"
    "fSw1NzcwOihlLHQpPT57T2JqZWN0LmRlZmluZVByb3BlcnR5KHQsIl9fZXNNb2R1bGUiLHt2YWx1ZTohMH0pLHQuUEFZTE9BRF9MSU1JVD12b2lkIDAsdC5Q"
    "QVlMT0FEX0xJTUlUPTFlN30sNjM1MTooZSx0LGkpPT57T2JqZWN0LmRlZmluZVByb3BlcnR5KHQsIl9fZXNNb2R1bGUiLHt2YWx1ZTohMH0pLHQuRGNzSGFu"
    "ZGxlcj10LkRjc1BhcnNlcj12b2lkIDA7Y29uc3Qgcz1pKDQ4Mikscj1pKDg3NDIpLG49aSg1NzcwKSxvPVtdO3QuRGNzUGFyc2VyPWNsYXNze2NvbnN0cnVj"
    "dG9yKCl7dGhpcy5faGFuZGxlcnM9T2JqZWN0LmNyZWF0ZShudWxsKSx0aGlzLl9hY3RpdmU9byx0aGlzLl9pZGVudD0wLHRoaXMuX2hhbmRsZXJGYj0oKT0+"
    "e30sdGhpcy5fc3RhY2s9e3BhdXNlZDohMSxsb29wUG9zaXRpb246MCxmYWxsVGhyb3VnaDohMX19ZGlzcG9zZSgpe3RoaXMuX2hhbmRsZXJzPU9iamVjdC5j"
    "cmVhdGUobnVsbCksdGhpcy5faGFuZGxlckZiPSgpPT57fSx0aGlzLl9hY3RpdmU9b31yZWdpc3RlckhhbmRsZXIoZSx0KXt2b2lkIDA9PT10aGlzLl9oYW5k"
    "bGVyc1tlXSYmKHRoaXMuX2hhbmRsZXJzW2VdPVtdKTtjb25zdCBpPXRoaXMuX2hhbmRsZXJzW2VdO3JldHVybiBpLnB1c2godCkse2Rpc3Bvc2U6KCk9Pntj"
    "b25zdCBlPWkuaW5kZXhPZih0KTstMSE9PWUmJmkuc3BsaWNlKGUsMSl9fX1jbGVhckhhbmRsZXIoZSl7dGhpcy5faGFuZGxlcnNbZV0mJmRlbGV0ZSB0aGlz"
    "Ll9oYW5kbGVyc1tlXX1zZXRIYW5kbGVyRmFsbGJhY2soZSl7dGhpcy5faGFuZGxlckZiPWV9cmVzZXQoKXtpZih0aGlzLl9hY3RpdmUubGVuZ3RoKWZvcihs"
    "ZXQgZT10aGlzLl9zdGFjay5wYXVzZWQ/dGhpcy5fc3RhY2subG9vcFBvc2l0aW9uLTE6dGhpcy5fYWN0aXZlLmxlbmd0aC0xO2U+PTA7LS1lKXRoaXMuX2Fj"
    "dGl2ZVtlXS51bmhvb2soITEpO3RoaXMuX3N0YWNrLnBhdXNlZD0hMSx0aGlzLl9hY3RpdmU9byx0aGlzLl9pZGVudD0wfWhvb2soZSx0KXtpZih0aGlzLnJl"
    "c2V0KCksdGhpcy5faWRlbnQ9ZSx0aGlzLl9hY3RpdmU9dGhpcy5faGFuZGxlcnNbZV18fG8sdGhpcy5fYWN0aXZlLmxlbmd0aClmb3IobGV0IGU9dGhpcy5f"
    "YWN0aXZlLmxlbmd0aC0xO2U+PTA7ZS0tKXRoaXMuX2FjdGl2ZVtlXS5ob29rKHQpO2Vsc2UgdGhpcy5faGFuZGxlckZiKHRoaXMuX2lkZW50LCJIT09LIix0"
    "KX1wdXQoZSx0LGkpe2lmKHRoaXMuX2FjdGl2ZS5sZW5ndGgpZm9yKGxldCBzPXRoaXMuX2FjdGl2ZS5sZW5ndGgtMTtzPj0wO3MtLSl0aGlzLl9hY3RpdmVb"
    "c10ucHV0KGUsdCxpKTtlbHNlIHRoaXMuX2hhbmRsZXJGYih0aGlzLl9pZGVudCwiUFVUIiwoMCxzLnV0ZjMyVG9TdHJpbmcpKGUsdCxpKSl9dW5ob29rKGUs"
    "dD0hMCl7aWYodGhpcy5fYWN0aXZlLmxlbmd0aCl7bGV0IGk9ITEscz10aGlzLl9hY3RpdmUubGVuZ3RoLTEscj0hMTtpZih0aGlzLl9zdGFjay5wYXVzZWQm"
    "JihzPXRoaXMuX3N0YWNrLmxvb3BQb3NpdGlvbi0xLGk9dCxyPXRoaXMuX3N0YWNrLmZhbGxUaHJvdWdoLHRoaXMuX3N0YWNrLnBhdXNlZD0hMSksIXImJiEx"
    "PT09aSl7Zm9yKDtzPj0wJiYoaT10aGlzLl9hY3RpdmVbc10udW5ob29rKGUpLCEwIT09aSk7cy0tKWlmKGkgaW5zdGFuY2VvZiBQcm9taXNlKXJldHVybiB0"
    "aGlzLl9zdGFjay5wYXVzZWQ9ITAsdGhpcy5fc3RhY2subG9vcFBvc2l0aW9uPXMsdGhpcy5fc3RhY2suZmFsbFRocm91Z2g9ITEsaTtzLS19Zm9yKDtzPj0w"
    "O3MtLSlpZihpPXRoaXMuX2FjdGl2ZVtzXS51bmhvb2soITEpLGkgaW5zdGFuY2VvZiBQcm9taXNlKXJldHVybiB0aGlzLl9zdGFjay5wYXVzZWQ9ITAsdGhp"
    "cy5fc3RhY2subG9vcFBvc2l0aW9uPXMsdGhpcy5fc3RhY2suZmFsbFRocm91Z2g9ITAsaX1lbHNlIHRoaXMuX2hhbmRsZXJGYih0aGlzLl9pZGVudCwiVU5I"
    "T09LIixlKTt0aGlzLl9hY3RpdmU9byx0aGlzLl9pZGVudD0wfX07Y29uc3QgYT1uZXcgci5QYXJhbXM7YS5hZGRQYXJhbSgwKSx0LkRjc0hhbmRsZXI9Y2xh"
    "c3N7Y29uc3RydWN0b3IoZSl7dGhpcy5faGFuZGxlcj1lLHRoaXMuX2RhdGE9IiIsdGhpcy5fcGFyYW1zPWEsdGhpcy5faGl0TGltaXQ9ITF9aG9vayhlKXt0"
    "aGlzLl9wYXJhbXM9ZS5sZW5ndGg+MXx8ZS5wYXJhbXNbMF0/ZS5jbG9uZSgpOmEsdGhpcy5fZGF0YT0iIix0aGlzLl9oaXRMaW1pdD0hMX1wdXQoZSx0LGkp"
    "e3RoaXMuX2hpdExpbWl0fHwodGhpcy5fZGF0YSs9KDAscy51dGYzMlRvU3RyaW5nKShlLHQsaSksdGhpcy5fZGF0YS5sZW5ndGg+bi5QQVlMT0FEX0xJTUlU"
    "JiYodGhpcy5fZGF0YT0iIix0aGlzLl9oaXRMaW1pdD0hMCkpfXVuaG9vayhlKXtsZXQgdD0hMTtpZih0aGlzLl9oaXRMaW1pdCl0PSExO2Vsc2UgaWYoZSYm"
    "KHQ9dGhpcy5faGFuZGxlcih0aGlzLl9kYXRhLHRoaXMuX3BhcmFtcyksdCBpbnN0YW5jZW9mIFByb21pc2UpKXJldHVybiB0LnRoZW4oKGU9Pih0aGlzLl9w"
    "YXJhbXM9YSx0aGlzLl9kYXRhPSIiLHRoaXMuX2hpdExpbWl0PSExLGUpKSk7cmV0dXJuIHRoaXMuX3BhcmFtcz1hLHRoaXMuX2RhdGE9IiIsdGhpcy5faGl0"
    "TGltaXQ9ITEsdH19fSwyMDE1OihlLHQsaSk9PntPYmplY3QuZGVmaW5lUHJvcGVydHkodCwiX19lc01vZHVsZSIse3ZhbHVlOiEwfSksdC5Fc2NhcGVTZXF1"
    "ZW5jZVBhcnNlcj10LlZUNTAwX1RSQU5TSVRJT05fVEFCTEU9dC5UcmFuc2l0aW9uVGFibGU9dm9pZCAwO2NvbnN0IHM9aSg4NDQpLHI9aSg4NzQyKSxuPWko"
    "NjI0Miksbz1pKDYzNTEpO2NsYXNzIGF7Y29uc3RydWN0b3IoZSl7dGhpcy50YWJsZT1uZXcgVWludDhBcnJheShlKX1zZXREZWZhdWx0KGUsdCl7dGhpcy50"
    "YWJsZS5maWxsKGU8PDR8dCl9YWRkKGUsdCxpLHMpe3RoaXMudGFibGVbdDw8OHxlXT1pPDw0fHN9YWRkTWFueShlLHQsaSxzKXtmb3IobGV0IHI9MDtyPGUu"
    "bGVuZ3RoO3IrKyl0aGlzLnRhYmxlW3Q8PDh8ZVtyXV09aTw8NHxzfX10LlRyYW5zaXRpb25UYWJsZT1hO2NvbnN0IGg9MTYwO3QuVlQ1MDBfVFJBTlNJVElP"
    "Tl9UQUJMRT1mdW5jdGlvbigpe2NvbnN0IGU9bmV3IGEoNDA5NSksdD1BcnJheS5hcHBseShudWxsLEFycmF5KDI1NikpLm1hcCgoKGUsdCk9PnQpKSxpPShl"
    "LGkpPT50LnNsaWNlKGUsaSkscz1pKDMyLDEyNykscj1pKDAsMjQpO3IucHVzaCgyNSksci5wdXNoLmFwcGx5KHIsaSgyOCwzMikpO2NvbnN0IG49aSgwLDE0"
    "KTtsZXQgbztmb3IobyBpbiBlLnNldERlZmF1bHQoMSwwKSxlLmFkZE1hbnkocywwLDIsMCksbillLmFkZE1hbnkoWzI0LDI2LDE1MywxNTRdLG8sMywwKSxl"
    "LmFkZE1hbnkoaSgxMjgsMTQ0KSxvLDMsMCksZS5hZGRNYW55KGkoMTQ0LDE1MiksbywzLDApLGUuYWRkKDE1NixvLDAsMCksZS5hZGQoMjcsbywxMSwxKSxl"
    "LmFkZCgxNTcsbyw0LDgpLGUuYWRkTWFueShbMTUyLDE1OCwxNTldLG8sMCw3KSxlLmFkZCgxNTUsbywxMSwzKSxlLmFkZCgxNDQsbywxMSw5KTtyZXR1cm4g"
    "ZS5hZGRNYW55KHIsMCwzLDApLGUuYWRkTWFueShyLDEsMywxKSxlLmFkZCgxMjcsMSwwLDEpLGUuYWRkTWFueShyLDgsMCw4KSxlLmFkZE1hbnkociwzLDMs"
    "MyksZS5hZGQoMTI3LDMsMCwzKSxlLmFkZE1hbnkociw0LDMsNCksZS5hZGQoMTI3LDQsMCw0KSxlLmFkZE1hbnkociw2LDMsNiksZS5hZGRNYW55KHIsNSwz"
    "LDUpLGUuYWRkKDEyNyw1LDAsNSksZS5hZGRNYW55KHIsMiwzLDIpLGUuYWRkKDEyNywyLDAsMiksZS5hZGQoOTMsMSw0LDgpLGUuYWRkTWFueShzLDgsNSw4"
    "KSxlLmFkZCgxMjcsOCw1LDgpLGUuYWRkTWFueShbMTU2LDI3LDI0LDI2LDddLDgsNiwwKSxlLmFkZE1hbnkoaSgyOCwzMiksOCwwLDgpLGUuYWRkTWFueShb"
    "ODgsOTQsOTVdLDEsMCw3KSxlLmFkZE1hbnkocyw3LDAsNyksZS5hZGRNYW55KHIsNywwLDcpLGUuYWRkKDE1Niw3LDAsMCksZS5hZGQoMTI3LDcsMCw3KSxl"
    "LmFkZCg5MSwxLDExLDMpLGUuYWRkTWFueShpKDY0LDEyNyksMyw3LDApLGUuYWRkTWFueShpKDQ4LDYwKSwzLDgsNCksZS5hZGRNYW55KFs2MCw2MSw2Miw2"
    "M10sMyw5LDQpLGUuYWRkTWFueShpKDQ4LDYwKSw0LDgsNCksZS5hZGRNYW55KGkoNjQsMTI3KSw0LDcsMCksZS5hZGRNYW55KFs2MCw2MSw2Miw2M10sNCww"
    "LDYpLGUuYWRkTWFueShpKDMyLDY0KSw2LDAsNiksZS5hZGQoMTI3LDYsMCw2KSxlLmFkZE1hbnkoaSg2NCwxMjcpLDYsMCwwKSxlLmFkZE1hbnkoaSgzMiw0"
    "OCksMyw5LDUpLGUuYWRkTWFueShpKDMyLDQ4KSw1LDksNSksZS5hZGRNYW55KGkoNDgsNjQpLDUsMCw2KSxlLmFkZE1hbnkoaSg2NCwxMjcpLDUsNywwKSxl"
    "LmFkZE1hbnkoaSgzMiw0OCksNCw5LDUpLGUuYWRkTWFueShpKDMyLDQ4KSwxLDksMiksZS5hZGRNYW55KGkoMzIsNDgpLDIsOSwyKSxlLmFkZE1hbnkoaSg0"
    "OCwxMjcpLDIsMTAsMCksZS5hZGRNYW55KGkoNDgsODApLDEsMTAsMCksZS5hZGRNYW55KGkoODEsODgpLDEsMTAsMCksZS5hZGRNYW55KFs4OSw5MCw5Ml0s"
    "MSwxMCwwKSxlLmFkZE1hbnkoaSg5NiwxMjcpLDEsMTAsMCksZS5hZGQoODAsMSwxMSw5KSxlLmFkZE1hbnkociw5LDAsOSksZS5hZGQoMTI3LDksMCw5KSxl"
    "LmFkZE1hbnkoaSgyOCwzMiksOSwwLDkpLGUuYWRkTWFueShpKDMyLDQ4KSw5LDksMTIpLGUuYWRkTWFueShpKDQ4LDYwKSw5LDgsMTApLGUuYWRkTWFueShb"
    "NjAsNjEsNjIsNjNdLDksOSwxMCksZS5hZGRNYW55KHIsMTEsMCwxMSksZS5hZGRNYW55KGkoMzIsMTI4KSwxMSwwLDExKSxlLmFkZE1hbnkoaSgyOCwzMiks"
    "MTEsMCwxMSksZS5hZGRNYW55KHIsMTAsMCwxMCksZS5hZGQoMTI3LDEwLDAsMTApLGUuYWRkTWFueShpKDI4LDMyKSwxMCwwLDEwKSxlLmFkZE1hbnkoaSg0"
    "OCw2MCksMTAsOCwxMCksZS5hZGRNYW55KFs2MCw2MSw2Miw2M10sMTAsMCwxMSksZS5hZGRNYW55KGkoMzIsNDgpLDEwLDksMTIpLGUuYWRkTWFueShyLDEy"
    "LDAsMTIpLGUuYWRkKDEyNywxMiwwLDEyKSxlLmFkZE1hbnkoaSgyOCwzMiksMTIsMCwxMiksZS5hZGRNYW55KGkoMzIsNDgpLDEyLDksMTIpLGUuYWRkTWFu"
    "eShpKDQ4LDY0KSwxMiwwLDExKSxlLmFkZE1hbnkoaSg2NCwxMjcpLDEyLDEyLDEzKSxlLmFkZE1hbnkoaSg2NCwxMjcpLDEwLDEyLDEzKSxlLmFkZE1hbnko"
    "aSg2NCwxMjcpLDksMTIsMTMpLGUuYWRkTWFueShyLDEzLDEzLDEzKSxlLmFkZE1hbnkocywxMywxMywxMyksZS5hZGQoMTI3LDEzLDAsMTMpLGUuYWRkTWFu"
    "eShbMjcsMTU2LDI0LDI2XSwxMywxNCwwKSxlLmFkZChoLDAsMiwwKSxlLmFkZChoLDgsNSw4KSxlLmFkZChoLDYsMCw2KSxlLmFkZChoLDExLDAsMTEpLGUu"
    "YWRkKGgsMTMsMTMsMTMpLGV9KCk7Y2xhc3MgYyBleHRlbmRzIHMuRGlzcG9zYWJsZXtjb25zdHJ1Y3RvcihlPXQuVlQ1MDBfVFJBTlNJVElPTl9UQUJMRSl7"
    "c3VwZXIoKSx0aGlzLl90cmFuc2l0aW9ucz1lLHRoaXMuX3BhcnNlU3RhY2s9e3N0YXRlOjAsaGFuZGxlcnM6W10saGFuZGxlclBvczowLHRyYW5zaXRpb246"
    "MCxjaHVua1BvczowfSx0aGlzLmluaXRpYWxTdGF0ZT0wLHRoaXMuY3VycmVudFN0YXRlPXRoaXMuaW5pdGlhbFN0YXRlLHRoaXMuX3BhcmFtcz1uZXcgci5Q"
    "YXJhbXMsdGhpcy5fcGFyYW1zLmFkZFBhcmFtKDApLHRoaXMuX2NvbGxlY3Q9MCx0aGlzLnByZWNlZGluZ0NvZGVwb2ludD0wLHRoaXMuX3ByaW50SGFuZGxl"
    "ckZiPShlLHQsaSk9Pnt9LHRoaXMuX2V4ZWN1dGVIYW5kbGVyRmI9ZT0+e30sdGhpcy5fY3NpSGFuZGxlckZiPShlLHQpPT57fSx0aGlzLl9lc2NIYW5kbGVy"
    "RmI9ZT0+e30sdGhpcy5fZXJyb3JIYW5kbGVyRmI9ZT0+ZSx0aGlzLl9wcmludEhhbmRsZXI9dGhpcy5fcHJpbnRIYW5kbGVyRmIsdGhpcy5fZXhlY3V0ZUhh"
    "bmRsZXJzPU9iamVjdC5jcmVhdGUobnVsbCksdGhpcy5fY3NpSGFuZGxlcnM9T2JqZWN0LmNyZWF0ZShudWxsKSx0aGlzLl9lc2NIYW5kbGVycz1PYmplY3Qu"
    "Y3JlYXRlKG51bGwpLHRoaXMucmVnaXN0ZXIoKDAscy50b0Rpc3Bvc2FibGUpKCgoKT0+e3RoaXMuX2NzaUhhbmRsZXJzPU9iamVjdC5jcmVhdGUobnVsbCks"
    "dGhpcy5fZXhlY3V0ZUhhbmRsZXJzPU9iamVjdC5jcmVhdGUobnVsbCksdGhpcy5fZXNjSGFuZGxlcnM9T2JqZWN0LmNyZWF0ZShudWxsKX0pKSksdGhpcy5f"
    "b3NjUGFyc2VyPXRoaXMucmVnaXN0ZXIobmV3IG4uT3NjUGFyc2VyKSx0aGlzLl9kY3NQYXJzZXI9dGhpcy5yZWdpc3RlcihuZXcgby5EY3NQYXJzZXIpLHRo"
    "aXMuX2Vycm9ySGFuZGxlcj10aGlzLl9lcnJvckhhbmRsZXJGYix0aGlzLnJlZ2lzdGVyRXNjSGFuZGxlcih7ZmluYWw6IlxcIn0sKCgpPT4hMCkpfV9pZGVu"
    "dGlmaWVyKGUsdD1bNjQsMTI2XSl7bGV0IGk9MDtpZihlLnByZWZpeCl7aWYoZS5wcmVmaXgubGVuZ3RoPjEpdGhyb3cgbmV3IEVycm9yKCJvbmx5IG9uZSBi"
    "eXRlIGFzIHByZWZpeCBzdXBwb3J0ZWQiKTtpZihpPWUucHJlZml4LmNoYXJDb2RlQXQoMCksaSYmNjA+aXx8aT42Myl0aHJvdyBuZXcgRXJyb3IoInByZWZp"
    "eCBtdXN0IGJlIGluIHJhbmdlIDB4M2MgLi4gMHgzZiIpfWlmKGUuaW50ZXJtZWRpYXRlcyl7aWYoZS5pbnRlcm1lZGlhdGVzLmxlbmd0aD4yKXRocm93IG5l"
    "dyBFcnJvcigib25seSB0d28gYnl0ZXMgYXMgaW50ZXJtZWRpYXRlcyBhcmUgc3VwcG9ydGVkIik7Zm9yKGxldCB0PTA7dDxlLmludGVybWVkaWF0ZXMubGVu"
    "Z3RoOysrdCl7Y29uc3Qgcz1lLmludGVybWVkaWF0ZXMuY2hhckNvZGVBdCh0KTtpZigzMj5zfHxzPjQ3KXRocm93IG5ldyBFcnJvcigiaW50ZXJtZWRpYXRl"
    "IG11c3QgYmUgaW4gcmFuZ2UgMHgyMCAuLiAweDJmIik7aTw8PTgsaXw9c319aWYoMSE9PWUuZmluYWwubGVuZ3RoKXRocm93IG5ldyBFcnJvcigiZmluYWwg"
    "bXVzdCBiZSBhIHNpbmdsZSBieXRlIik7Y29uc3Qgcz1lLmZpbmFsLmNoYXJDb2RlQXQoMCk7aWYodFswXT5zfHxzPnRbMV0pdGhyb3cgbmV3IEVycm9yKGBm"
    "aW5hbCBtdXN0IGJlIGluIHJhbmdlICR7dFswXX0gLi4gJHt0WzFdfWApO3JldHVybiBpPDw9OCxpfD1zLGl9aWRlbnRUb1N0cmluZyhlKXtjb25zdCB0PVtd"
    "O2Zvcig7ZTspdC5wdXNoKFN0cmluZy5mcm9tQ2hhckNvZGUoMjU1JmUpKSxlPj49ODtyZXR1cm4gdC5yZXZlcnNlKCkuam9pbigiIil9c2V0UHJpbnRIYW5k"
    "bGVyKGUpe3RoaXMuX3ByaW50SGFuZGxlcj1lfWNsZWFyUHJpbnRIYW5kbGVyKCl7dGhpcy5fcHJpbnRIYW5kbGVyPXRoaXMuX3ByaW50SGFuZGxlckZifXJl"
    "Z2lzdGVyRXNjSGFuZGxlcihlLHQpe2NvbnN0IGk9dGhpcy5faWRlbnRpZmllcihlLFs0OCwxMjZdKTt2b2lkIDA9PT10aGlzLl9lc2NIYW5kbGVyc1tpXSYm"
    "KHRoaXMuX2VzY0hhbmRsZXJzW2ldPVtdKTtjb25zdCBzPXRoaXMuX2VzY0hhbmRsZXJzW2ldO3JldHVybiBzLnB1c2godCkse2Rpc3Bvc2U6KCk9Pntjb25z"
    "dCBlPXMuaW5kZXhPZih0KTstMSE9PWUmJnMuc3BsaWNlKGUsMSl9fX1jbGVhckVzY0hhbmRsZXIoZSl7dGhpcy5fZXNjSGFuZGxlcnNbdGhpcy5faWRlbnRp"
    "ZmllcihlLFs0OCwxMjZdKV0mJmRlbGV0ZSB0aGlzLl9lc2NIYW5kbGVyc1t0aGlzLl9pZGVudGlmaWVyKGUsWzQ4LDEyNl0pXX1zZXRFc2NIYW5kbGVyRmFs"
    "bGJhY2soZSl7dGhpcy5fZXNjSGFuZGxlckZiPWV9c2V0RXhlY3V0ZUhhbmRsZXIoZSx0KXt0aGlzLl9leGVjdXRlSGFuZGxlcnNbZS5jaGFyQ29kZUF0KDAp"
    "XT10fWNsZWFyRXhlY3V0ZUhhbmRsZXIoZSl7dGhpcy5fZXhlY3V0ZUhhbmRsZXJzW2UuY2hhckNvZGVBdCgwKV0mJmRlbGV0ZSB0aGlzLl9leGVjdXRlSGFu"
    "ZGxlcnNbZS5jaGFyQ29kZUF0KDApXX1zZXRFeGVjdXRlSGFuZGxlckZhbGxiYWNrKGUpe3RoaXMuX2V4ZWN1dGVIYW5kbGVyRmI9ZX1yZWdpc3RlckNzaUhh"
    "bmRsZXIoZSx0KXtjb25zdCBpPXRoaXMuX2lkZW50aWZpZXIoZSk7dm9pZCAwPT09dGhpcy5fY3NpSGFuZGxlcnNbaV0mJih0aGlzLl9jc2lIYW5kbGVyc1tp"
    "XT1bXSk7Y29uc3Qgcz10aGlzLl9jc2lIYW5kbGVyc1tpXTtyZXR1cm4gcy5wdXNoKHQpLHtkaXNwb3NlOigpPT57Y29uc3QgZT1zLmluZGV4T2YodCk7LTEh"
    "PT1lJiZzLnNwbGljZShlLDEpfX19Y2xlYXJDc2lIYW5kbGVyKGUpe3RoaXMuX2NzaUhhbmRsZXJzW3RoaXMuX2lkZW50aWZpZXIoZSldJiZkZWxldGUgdGhp"
    "cy5fY3NpSGFuZGxlcnNbdGhpcy5faWRlbnRpZmllcihlKV19c2V0Q3NpSGFuZGxlckZhbGxiYWNrKGUpe3RoaXMuX2NzaUhhbmRsZXJGYj1lfXJlZ2lzdGVy"
    "RGNzSGFuZGxlcihlLHQpe3JldHVybiB0aGlzLl9kY3NQYXJzZXIucmVnaXN0ZXJIYW5kbGVyKHRoaXMuX2lkZW50aWZpZXIoZSksdCl9Y2xlYXJEY3NIYW5k"
    "bGVyKGUpe3RoaXMuX2Rjc1BhcnNlci5jbGVhckhhbmRsZXIodGhpcy5faWRlbnRpZmllcihlKSl9c2V0RGNzSGFuZGxlckZhbGxiYWNrKGUpe3RoaXMuX2Rj"
    "c1BhcnNlci5zZXRIYW5kbGVyRmFsbGJhY2soZSl9cmVnaXN0ZXJPc2NIYW5kbGVyKGUsdCl7cmV0dXJuIHRoaXMuX29zY1BhcnNlci5yZWdpc3RlckhhbmRs"
    "ZXIoZSx0KX1jbGVhck9zY0hhbmRsZXIoZSl7dGhpcy5fb3NjUGFyc2VyLmNsZWFySGFuZGxlcihlKX1zZXRPc2NIYW5kbGVyRmFsbGJhY2soZSl7dGhpcy5f"
    "b3NjUGFyc2VyLnNldEhhbmRsZXJGYWxsYmFjayhlKX1zZXRFcnJvckhhbmRsZXIoZSl7dGhpcy5fZXJyb3JIYW5kbGVyPWV9Y2xlYXJFcnJvckhhbmRsZXIo"
    "KXt0aGlzLl9lcnJvckhhbmRsZXI9dGhpcy5fZXJyb3JIYW5kbGVyRmJ9cmVzZXQoKXt0aGlzLmN1cnJlbnRTdGF0ZT10aGlzLmluaXRpYWxTdGF0ZSx0aGlz"
    "Ll9vc2NQYXJzZXIucmVzZXQoKSx0aGlzLl9kY3NQYXJzZXIucmVzZXQoKSx0aGlzLl9wYXJhbXMucmVzZXQoKSx0aGlzLl9wYXJhbXMuYWRkUGFyYW0oMCks"
    "dGhpcy5fY29sbGVjdD0wLHRoaXMucHJlY2VkaW5nQ29kZXBvaW50PTAsMCE9PXRoaXMuX3BhcnNlU3RhY2suc3RhdGUmJih0aGlzLl9wYXJzZVN0YWNrLnN0"
    "YXRlPTIsdGhpcy5fcGFyc2VTdGFjay5oYW5kbGVycz1bXSl9X3ByZXNlcnZlU3RhY2soZSx0LGkscyxyKXt0aGlzLl9wYXJzZVN0YWNrLnN0YXRlPWUsdGhp"
    "cy5fcGFyc2VTdGFjay5oYW5kbGVycz10LHRoaXMuX3BhcnNlU3RhY2suaGFuZGxlclBvcz1pLHRoaXMuX3BhcnNlU3RhY2sudHJhbnNpdGlvbj1zLHRoaXMu"
    "X3BhcnNlU3RhY2suY2h1bmtQb3M9cn1wYXJzZShlLHQsaSl7bGV0IHMscj0wLG49MCxvPTA7aWYodGhpcy5fcGFyc2VTdGFjay5zdGF0ZSlpZigyPT09dGhp"
    "cy5fcGFyc2VTdGFjay5zdGF0ZSl0aGlzLl9wYXJzZVN0YWNrLnN0YXRlPTAsbz10aGlzLl9wYXJzZVN0YWNrLmNodW5rUG9zKzE7ZWxzZXtpZih2b2lkIDA9"
    "PT1pfHwxPT09dGhpcy5fcGFyc2VTdGFjay5zdGF0ZSl0aHJvdyB0aGlzLl9wYXJzZVN0YWNrLnN0YXRlPTEsbmV3IEVycm9yKCJpbXByb3BlciBjb250aW51"
    "YXRpb24gZHVlIHRvIHByZXZpb3VzIGFzeW5jIGhhbmRsZXIsIGdpdmluZyB1cCBwYXJzaW5nIik7Y29uc3QgdD10aGlzLl9wYXJzZVN0YWNrLmhhbmRsZXJz"
    "O2xldCBuPXRoaXMuX3BhcnNlU3RhY2suaGFuZGxlclBvcy0xO3N3aXRjaCh0aGlzLl9wYXJzZVN0YWNrLnN0YXRlKXtjYXNlIDM6aWYoITE9PT1pJiZuPi0x"
    "KWZvcig7bj49MCYmKHM9dFtuXSh0aGlzLl9wYXJhbXMpLCEwIT09cyk7bi0tKWlmKHMgaW5zdGFuY2VvZiBQcm9taXNlKXJldHVybiB0aGlzLl9wYXJzZVN0"
    "YWNrLmhhbmRsZXJQb3M9bixzO3RoaXMuX3BhcnNlU3RhY2suaGFuZGxlcnM9W107YnJlYWs7Y2FzZSA0OmlmKCExPT09aSYmbj4tMSlmb3IoO24+PTAmJihz"
    "PXRbbl0oKSwhMCE9PXMpO24tLSlpZihzIGluc3RhbmNlb2YgUHJvbWlzZSlyZXR1cm4gdGhpcy5fcGFyc2VTdGFjay5oYW5kbGVyUG9zPW4sczt0aGlzLl9w"
    "YXJzZVN0YWNrLmhhbmRsZXJzPVtdO2JyZWFrO2Nhc2UgNjppZihyPWVbdGhpcy5fcGFyc2VTdGFjay5jaHVua1Bvc10scz10aGlzLl9kY3NQYXJzZXIudW5o"
    "b29rKDI0IT09ciYmMjYhPT1yLGkpLHMpcmV0dXJuIHM7Mjc9PT1yJiYodGhpcy5fcGFyc2VTdGFjay50cmFuc2l0aW9ufD0xKSx0aGlzLl9wYXJhbXMucmVz"
    "ZXQoKSx0aGlzLl9wYXJhbXMuYWRkUGFyYW0oMCksdGhpcy5fY29sbGVjdD0wO2JyZWFrO2Nhc2UgNTppZihyPWVbdGhpcy5fcGFyc2VTdGFjay5jaHVua1Bv"
    "c10scz10aGlzLl9vc2NQYXJzZXIuZW5kKDI0IT09ciYmMjYhPT1yLGkpLHMpcmV0dXJuIHM7Mjc9PT1yJiYodGhpcy5fcGFyc2VTdGFjay50cmFuc2l0aW9u"
    "fD0xKSx0aGlzLl9wYXJhbXMucmVzZXQoKSx0aGlzLl9wYXJhbXMuYWRkUGFyYW0oMCksdGhpcy5fY29sbGVjdD0wfXRoaXMuX3BhcnNlU3RhY2suc3RhdGU9"
    "MCxvPXRoaXMuX3BhcnNlU3RhY2suY2h1bmtQb3MrMSx0aGlzLnByZWNlZGluZ0NvZGVwb2ludD0wLHRoaXMuY3VycmVudFN0YXRlPTE1JnRoaXMuX3BhcnNl"
    "U3RhY2sudHJhbnNpdGlvbn1mb3IobGV0IGk9bztpPHQ7KytpKXtzd2l0Y2gocj1lW2ldLG49dGhpcy5fdHJhbnNpdGlvbnMudGFibGVbdGhpcy5jdXJyZW50"
    "U3RhdGU8PDh8KHI8MTYwP3I6aCldLG4+PjQpe2Nhc2UgMjpmb3IobGV0IHM9aSsxOzsrK3Mpe2lmKHM+PXR8fChyPWVbc10pPDMyfHxyPjEyNiYmcjxoKXt0"
    "aGlzLl9wcmludEhhbmRsZXIoZSxpLHMpLGk9cy0xO2JyZWFrfWlmKCsrcz49dHx8KHI9ZVtzXSk8MzJ8fHI+MTI2JiZyPGgpe3RoaXMuX3ByaW50SGFuZGxl"
    "cihlLGkscyksaT1zLTE7YnJlYWt9aWYoKytzPj10fHwocj1lW3NdKTwzMnx8cj4xMjYmJnI8aCl7dGhpcy5fcHJpbnRIYW5kbGVyKGUsaSxzKSxpPXMtMTti"
    "cmVha31pZigrK3M+PXR8fChyPWVbc10pPDMyfHxyPjEyNiYmcjxoKXt0aGlzLl9wcmludEhhbmRsZXIoZSxpLHMpLGk9cy0xO2JyZWFrfX1icmVhaztjYXNl"
    "IDM6dGhpcy5fZXhlY3V0ZUhhbmRsZXJzW3JdP3RoaXMuX2V4ZWN1dGVIYW5kbGVyc1tyXSgpOnRoaXMuX2V4ZWN1dGVIYW5kbGVyRmIociksdGhpcy5wcmVj"
    "ZWRpbmdDb2RlcG9pbnQ9MDticmVhaztjYXNlIDA6YnJlYWs7Y2FzZSAxOmlmKHRoaXMuX2Vycm9ySGFuZGxlcih7cG9zaXRpb246aSxjb2RlOnIsY3VycmVu"
    "dFN0YXRlOnRoaXMuY3VycmVudFN0YXRlLGNvbGxlY3Q6dGhpcy5fY29sbGVjdCxwYXJhbXM6dGhpcy5fcGFyYW1zLGFib3J0OiExfSkuYWJvcnQpcmV0dXJu"
    "O2JyZWFrO2Nhc2UgNzpjb25zdCBvPXRoaXMuX2NzaUhhbmRsZXJzW3RoaXMuX2NvbGxlY3Q8PDh8cl07bGV0IGE9bz9vLmxlbmd0aC0xOi0xO2Zvcig7YT49"
    "MCYmKHM9b1thXSh0aGlzLl9wYXJhbXMpLCEwIT09cyk7YS0tKWlmKHMgaW5zdGFuY2VvZiBQcm9taXNlKXJldHVybiB0aGlzLl9wcmVzZXJ2ZVN0YWNrKDMs"
    "byxhLG4saSksczthPDAmJnRoaXMuX2NzaUhhbmRsZXJGYih0aGlzLl9jb2xsZWN0PDw4fHIsdGhpcy5fcGFyYW1zKSx0aGlzLnByZWNlZGluZ0NvZGVwb2lu"
    "dD0wO2JyZWFrO2Nhc2UgODpkb3tzd2l0Y2gocil7Y2FzZSA1OTp0aGlzLl9wYXJhbXMuYWRkUGFyYW0oMCk7YnJlYWs7Y2FzZSA1ODp0aGlzLl9wYXJhbXMu"
    "YWRkU3ViUGFyYW0oLTEpO2JyZWFrO2RlZmF1bHQ6dGhpcy5fcGFyYW1zLmFkZERpZ2l0KHItNDgpfX13aGlsZSgrK2k8dCYmKHI9ZVtpXSk+NDcmJnI8NjAp"
    "O2ktLTticmVhaztjYXNlIDk6dGhpcy5fY29sbGVjdDw8PTgsdGhpcy5fY29sbGVjdHw9cjticmVhaztjYXNlIDEwOmNvbnN0IGM9dGhpcy5fZXNjSGFuZGxl"
    "cnNbdGhpcy5fY29sbGVjdDw8OHxyXTtsZXQgbD1jP2MubGVuZ3RoLTE6LTE7Zm9yKDtsPj0wJiYocz1jW2xdKCksITAhPT1zKTtsLS0paWYocyBpbnN0YW5j"
    "ZW9mIFByb21pc2UpcmV0dXJuIHRoaXMuX3ByZXNlcnZlU3RhY2soNCxjLGwsbixpKSxzO2w8MCYmdGhpcy5fZXNjSGFuZGxlckZiKHRoaXMuX2NvbGxlY3Q8"
    "PDh8ciksdGhpcy5wcmVjZWRpbmdDb2RlcG9pbnQ9MDticmVhaztjYXNlIDExOnRoaXMuX3BhcmFtcy5yZXNldCgpLHRoaXMuX3BhcmFtcy5hZGRQYXJhbSgw"
    "KSx0aGlzLl9jb2xsZWN0PTA7YnJlYWs7Y2FzZSAxMjp0aGlzLl9kY3NQYXJzZXIuaG9vayh0aGlzLl9jb2xsZWN0PDw4fHIsdGhpcy5fcGFyYW1zKTticmVh"
    "aztjYXNlIDEzOmZvcihsZXQgcz1pKzE7OysrcylpZihzPj10fHwyND09PShyPWVbc10pfHwyNj09PXJ8fDI3PT09cnx8cj4xMjcmJnI8aCl7dGhpcy5fZGNz"
    "UGFyc2VyLnB1dChlLGkscyksaT1zLTE7YnJlYWt9YnJlYWs7Y2FzZSAxNDppZihzPXRoaXMuX2Rjc1BhcnNlci51bmhvb2soMjQhPT1yJiYyNiE9PXIpLHMp"
    "cmV0dXJuIHRoaXMuX3ByZXNlcnZlU3RhY2soNixbXSwwLG4saSksczsyNz09PXImJihufD0xKSx0aGlzLl9wYXJhbXMucmVzZXQoKSx0aGlzLl9wYXJhbXMu"
    "YWRkUGFyYW0oMCksdGhpcy5fY29sbGVjdD0wLHRoaXMucHJlY2VkaW5nQ29kZXBvaW50PTA7YnJlYWs7Y2FzZSA0OnRoaXMuX29zY1BhcnNlci5zdGFydCgp"
    "O2JyZWFrO2Nhc2UgNTpmb3IobGV0IHM9aSsxOztzKyspaWYocz49dHx8KHI9ZVtzXSk8MzJ8fHI+MTI3JiZyPGgpe3RoaXMuX29zY1BhcnNlci5wdXQoZSxp"
    "LHMpLGk9cy0xO2JyZWFrfWJyZWFrO2Nhc2UgNjppZihzPXRoaXMuX29zY1BhcnNlci5lbmQoMjQhPT1yJiYyNiE9PXIpLHMpcmV0dXJuIHRoaXMuX3ByZXNl"
    "cnZlU3RhY2soNSxbXSwwLG4saSksczsyNz09PXImJihufD0xKSx0aGlzLl9wYXJhbXMucmVzZXQoKSx0aGlzLl9wYXJhbXMuYWRkUGFyYW0oMCksdGhpcy5f"
    "Y29sbGVjdD0wLHRoaXMucHJlY2VkaW5nQ29kZXBvaW50PTB9dGhpcy5jdXJyZW50U3RhdGU9MTUmbn19fXQuRXNjYXBlU2VxdWVuY2VQYXJzZXI9Y30sNjI0"
    "MjooZSx0LGkpPT57T2JqZWN0LmRlZmluZVByb3BlcnR5KHQsIl9fZXNNb2R1bGUiLHt2YWx1ZTohMH0pLHQuT3NjSGFuZGxlcj10Lk9zY1BhcnNlcj12b2lk"
    "IDA7Y29uc3Qgcz1pKDU3NzApLHI9aSg0ODIpLG49W107dC5Pc2NQYXJzZXI9Y2xhc3N7Y29uc3RydWN0b3IoKXt0aGlzLl9zdGF0ZT0wLHRoaXMuX2FjdGl2"
    "ZT1uLHRoaXMuX2lkPS0xLHRoaXMuX2hhbmRsZXJzPU9iamVjdC5jcmVhdGUobnVsbCksdGhpcy5faGFuZGxlckZiPSgpPT57fSx0aGlzLl9zdGFjaz17cGF1"
    "c2VkOiExLGxvb3BQb3NpdGlvbjowLGZhbGxUaHJvdWdoOiExfX1yZWdpc3RlckhhbmRsZXIoZSx0KXt2b2lkIDA9PT10aGlzLl9oYW5kbGVyc1tlXSYmKHRo"
    "aXMuX2hhbmRsZXJzW2VdPVtdKTtjb25zdCBpPXRoaXMuX2hhbmRsZXJzW2VdO3JldHVybiBpLnB1c2godCkse2Rpc3Bvc2U6KCk9Pntjb25zdCBlPWkuaW5k"
    "ZXhPZih0KTstMSE9PWUmJmkuc3BsaWNlKGUsMSl9fX1jbGVhckhhbmRsZXIoZSl7dGhpcy5faGFuZGxlcnNbZV0mJmRlbGV0ZSB0aGlzLl9oYW5kbGVyc1tl"
    "XX1zZXRIYW5kbGVyRmFsbGJhY2soZSl7dGhpcy5faGFuZGxlckZiPWV9ZGlzcG9zZSgpe3RoaXMuX2hhbmRsZXJzPU9iamVjdC5jcmVhdGUobnVsbCksdGhp"
    "cy5faGFuZGxlckZiPSgpPT57fSx0aGlzLl9hY3RpdmU9bn1yZXNldCgpe2lmKDI9PT10aGlzLl9zdGF0ZSlmb3IobGV0IGU9dGhpcy5fc3RhY2sucGF1c2Vk"
    "P3RoaXMuX3N0YWNrLmxvb3BQb3NpdGlvbi0xOnRoaXMuX2FjdGl2ZS5sZW5ndGgtMTtlPj0wOy0tZSl0aGlzLl9hY3RpdmVbZV0uZW5kKCExKTt0aGlzLl9z"
    "dGFjay5wYXVzZWQ9ITEsdGhpcy5fYWN0aXZlPW4sdGhpcy5faWQ9LTEsdGhpcy5fc3RhdGU9MH1fc3RhcnQoKXtpZih0aGlzLl9hY3RpdmU9dGhpcy5faGFu"
    "ZGxlcnNbdGhpcy5faWRdfHxuLHRoaXMuX2FjdGl2ZS5sZW5ndGgpZm9yKGxldCBlPXRoaXMuX2FjdGl2ZS5sZW5ndGgtMTtlPj0wO2UtLSl0aGlzLl9hY3Rp"
    "dmVbZV0uc3RhcnQoKTtlbHNlIHRoaXMuX2hhbmRsZXJGYih0aGlzLl9pZCwiU1RBUlQiKX1fcHV0KGUsdCxpKXtpZih0aGlzLl9hY3RpdmUubGVuZ3RoKWZv"
    "cihsZXQgcz10aGlzLl9hY3RpdmUubGVuZ3RoLTE7cz49MDtzLS0pdGhpcy5fYWN0aXZlW3NdLnB1dChlLHQsaSk7ZWxzZSB0aGlzLl9oYW5kbGVyRmIodGhp"
    "cy5faWQsIlBVVCIsKDAsci51dGYzMlRvU3RyaW5nKShlLHQsaSkpfXN0YXJ0KCl7dGhpcy5yZXNldCgpLHRoaXMuX3N0YXRlPTF9cHV0KGUsdCxpKXtpZigz"
    "IT09dGhpcy5fc3RhdGUpe2lmKDE9PT10aGlzLl9zdGF0ZSlmb3IoO3Q8aTspe2NvbnN0IGk9ZVt0KytdO2lmKDU5PT09aSl7dGhpcy5fc3RhdGU9Mix0aGlz"
    "Ll9zdGFydCgpO2JyZWFrfWlmKGk8NDh8fDU3PGkpcmV0dXJuIHZvaWQodGhpcy5fc3RhdGU9Myk7LTE9PT10aGlzLl9pZCYmKHRoaXMuX2lkPTApLHRoaXMu"
    "X2lkPTEwKnRoaXMuX2lkK2ktNDh9Mj09PXRoaXMuX3N0YXRlJiZpLXQ+MCYmdGhpcy5fcHV0KGUsdCxpKX19ZW5kKGUsdD0hMCl7aWYoMCE9PXRoaXMuX3N0"
    "YXRlKXtpZigzIT09dGhpcy5fc3RhdGUpaWYoMT09PXRoaXMuX3N0YXRlJiZ0aGlzLl9zdGFydCgpLHRoaXMuX2FjdGl2ZS5sZW5ndGgpe2xldCBpPSExLHM9"
    "dGhpcy5fYWN0aXZlLmxlbmd0aC0xLHI9ITE7aWYodGhpcy5fc3RhY2sucGF1c2VkJiYocz10aGlzLl9zdGFjay5sb29wUG9zaXRpb24tMSxpPXQscj10aGlz"
    "Ll9zdGFjay5mYWxsVGhyb3VnaCx0aGlzLl9zdGFjay5wYXVzZWQ9ITEpLCFyJiYhMT09PWkpe2Zvcig7cz49MCYmKGk9dGhpcy5fYWN0aXZlW3NdLmVuZChl"
    "KSwhMCE9PWkpO3MtLSlpZihpIGluc3RhbmNlb2YgUHJvbWlzZSlyZXR1cm4gdGhpcy5fc3RhY2sucGF1c2VkPSEwLHRoaXMuX3N0YWNrLmxvb3BQb3NpdGlv"
    "bj1zLHRoaXMuX3N0YWNrLmZhbGxUaHJvdWdoPSExLGk7cy0tfWZvcig7cz49MDtzLS0paWYoaT10aGlzLl9hY3RpdmVbc10uZW5kKCExKSxpIGluc3RhbmNl"
    "b2YgUHJvbWlzZSlyZXR1cm4gdGhpcy5fc3RhY2sucGF1c2VkPSEwLHRoaXMuX3N0YWNrLmxvb3BQb3NpdGlvbj1zLHRoaXMuX3N0YWNrLmZhbGxUaHJvdWdo"
    "PSEwLGl9ZWxzZSB0aGlzLl9oYW5kbGVyRmIodGhpcy5faWQsIkVORCIsZSk7dGhpcy5fYWN0aXZlPW4sdGhpcy5faWQ9LTEsdGhpcy5fc3RhdGU9MH19fSx0"
    "Lk9zY0hhbmRsZXI9Y2xhc3N7Y29uc3RydWN0b3IoZSl7dGhpcy5faGFuZGxlcj1lLHRoaXMuX2RhdGE9IiIsdGhpcy5faGl0TGltaXQ9ITF9c3RhcnQoKXt0"
    "aGlzLl9kYXRhPSIiLHRoaXMuX2hpdExpbWl0PSExfXB1dChlLHQsaSl7dGhpcy5faGl0TGltaXR8fCh0aGlzLl9kYXRhKz0oMCxyLnV0ZjMyVG9TdHJpbmcp"
    "KGUsdCxpKSx0aGlzLl9kYXRhLmxlbmd0aD5zLlBBWUxPQURfTElNSVQmJih0aGlzLl9kYXRhPSIiLHRoaXMuX2hpdExpbWl0PSEwKSl9ZW5kKGUpe2xldCB0"
    "PSExO2lmKHRoaXMuX2hpdExpbWl0KXQ9ITE7ZWxzZSBpZihlJiYodD10aGlzLl9oYW5kbGVyKHRoaXMuX2RhdGEpLHQgaW5zdGFuY2VvZiBQcm9taXNlKSly"
    "ZXR1cm4gdC50aGVuKChlPT4odGhpcy5fZGF0YT0iIix0aGlzLl9oaXRMaW1pdD0hMSxlKSkpO3JldHVybiB0aGlzLl9kYXRhPSIiLHRoaXMuX2hpdExpbWl0"
    "PSExLHR9fX0sODc0MjooZSx0KT0+e09iamVjdC5kZWZpbmVQcm9wZXJ0eSh0LCJfX2VzTW9kdWxlIix7dmFsdWU6ITB9KSx0LlBhcmFtcz12b2lkIDA7Y29u"
    "c3QgaT0yMTQ3NDgzNjQ3O2NsYXNzIHN7c3RhdGljIGZyb21BcnJheShlKXtjb25zdCB0PW5ldyBzO2lmKCFlLmxlbmd0aClyZXR1cm4gdDtmb3IobGV0IGk9"
    "QXJyYXkuaXNBcnJheShlWzBdKT8xOjA7aTxlLmxlbmd0aDsrK2kpe2NvbnN0IHM9ZVtpXTtpZihBcnJheS5pc0FycmF5KHMpKWZvcihsZXQgZT0wO2U8cy5s"
    "ZW5ndGg7KytlKXQuYWRkU3ViUGFyYW0oc1tlXSk7ZWxzZSB0LmFkZFBhcmFtKHMpfXJldHVybiB0fWNvbnN0cnVjdG9yKGU9MzIsdD0zMil7aWYodGhpcy5t"
    "YXhMZW5ndGg9ZSx0aGlzLm1heFN1YlBhcmFtc0xlbmd0aD10LHQ+MjU2KXRocm93IG5ldyBFcnJvcigibWF4U3ViUGFyYW1zTGVuZ3RoIG11c3Qgbm90IGJl"
    "IGdyZWF0ZXIgdGhhbiAyNTYiKTt0aGlzLnBhcmFtcz1uZXcgSW50MzJBcnJheShlKSx0aGlzLmxlbmd0aD0wLHRoaXMuX3N1YlBhcmFtcz1uZXcgSW50MzJB"
    "cnJheSh0KSx0aGlzLl9zdWJQYXJhbXNMZW5ndGg9MCx0aGlzLl9zdWJQYXJhbXNJZHg9bmV3IFVpbnQxNkFycmF5KGUpLHRoaXMuX3JlamVjdERpZ2l0cz0h"
    "MSx0aGlzLl9yZWplY3RTdWJEaWdpdHM9ITEsdGhpcy5fZGlnaXRJc1N1Yj0hMX1jbG9uZSgpe2NvbnN0IGU9bmV3IHModGhpcy5tYXhMZW5ndGgsdGhpcy5t"
    "YXhTdWJQYXJhbXNMZW5ndGgpO3JldHVybiBlLnBhcmFtcy5zZXQodGhpcy5wYXJhbXMpLGUubGVuZ3RoPXRoaXMubGVuZ3RoLGUuX3N1YlBhcmFtcy5zZXQo"
    "dGhpcy5fc3ViUGFyYW1zKSxlLl9zdWJQYXJhbXNMZW5ndGg9dGhpcy5fc3ViUGFyYW1zTGVuZ3RoLGUuX3N1YlBhcmFtc0lkeC5zZXQodGhpcy5fc3ViUGFy"
    "YW1zSWR4KSxlLl9yZWplY3REaWdpdHM9dGhpcy5fcmVqZWN0RGlnaXRzLGUuX3JlamVjdFN1YkRpZ2l0cz10aGlzLl9yZWplY3RTdWJEaWdpdHMsZS5fZGln"
    "aXRJc1N1Yj10aGlzLl9kaWdpdElzU3ViLGV9dG9BcnJheSgpe2NvbnN0IGU9W107Zm9yKGxldCB0PTA7dDx0aGlzLmxlbmd0aDsrK3Qpe2UucHVzaCh0aGlz"
    "LnBhcmFtc1t0XSk7Y29uc3QgaT10aGlzLl9zdWJQYXJhbXNJZHhbdF0+Pjgscz0yNTUmdGhpcy5fc3ViUGFyYW1zSWR4W3RdO3MtaT4wJiZlLnB1c2goQXJy"
    "YXkucHJvdG90eXBlLnNsaWNlLmNhbGwodGhpcy5fc3ViUGFyYW1zLGkscykpfXJldHVybiBlfXJlc2V0KCl7dGhpcy5sZW5ndGg9MCx0aGlzLl9zdWJQYXJh"
    "bXNMZW5ndGg9MCx0aGlzLl9yZWplY3REaWdpdHM9ITEsdGhpcy5fcmVqZWN0U3ViRGlnaXRzPSExLHRoaXMuX2RpZ2l0SXNTdWI9ITF9YWRkUGFyYW0oZSl7"
    "aWYodGhpcy5fZGlnaXRJc1N1Yj0hMSx0aGlzLmxlbmd0aD49dGhpcy5tYXhMZW5ndGgpdGhpcy5fcmVqZWN0RGlnaXRzPSEwO2Vsc2V7aWYoZTwtMSl0aHJv"
    "dyBuZXcgRXJyb3IoInZhbHVlcyBsZXNzZXIgdGhhbiAtMSBhcmUgbm90IGFsbG93ZWQiKTt0aGlzLl9zdWJQYXJhbXNJZHhbdGhpcy5sZW5ndGhdPXRoaXMu"
    "X3N1YlBhcmFtc0xlbmd0aDw8OHx0aGlzLl9zdWJQYXJhbXNMZW5ndGgsdGhpcy5wYXJhbXNbdGhpcy5sZW5ndGgrK109ZT5pP2k6ZX19YWRkU3ViUGFyYW0o"
    "ZSl7aWYodGhpcy5fZGlnaXRJc1N1Yj0hMCx0aGlzLmxlbmd0aClpZih0aGlzLl9yZWplY3REaWdpdHN8fHRoaXMuX3N1YlBhcmFtc0xlbmd0aD49dGhpcy5t"
    "YXhTdWJQYXJhbXNMZW5ndGgpdGhpcy5fcmVqZWN0U3ViRGlnaXRzPSEwO2Vsc2V7aWYoZTwtMSl0aHJvdyBuZXcgRXJyb3IoInZhbHVlcyBsZXNzZXIgdGhh"
    "biAtMSBhcmUgbm90IGFsbG93ZWQiKTt0aGlzLl9zdWJQYXJhbXNbdGhpcy5fc3ViUGFyYW1zTGVuZ3RoKytdPWU+aT9pOmUsdGhpcy5fc3ViUGFyYW1zSWR4"
    "W3RoaXMubGVuZ3RoLTFdKyt9fWhhc1N1YlBhcmFtcyhlKXtyZXR1cm4oMjU1JnRoaXMuX3N1YlBhcmFtc0lkeFtlXSktKHRoaXMuX3N1YlBhcmFtc0lkeFtl"
    "XT4+OCk+MH1nZXRTdWJQYXJhbXMoZSl7Y29uc3QgdD10aGlzLl9zdWJQYXJhbXNJZHhbZV0+PjgsaT0yNTUmdGhpcy5fc3ViUGFyYW1zSWR4W2VdO3JldHVy"
    "biBpLXQ+MD90aGlzLl9zdWJQYXJhbXMuc3ViYXJyYXkodCxpKTpudWxsfWdldFN1YlBhcmFtc0FsbCgpe2NvbnN0IGU9e307Zm9yKGxldCB0PTA7dDx0aGlz"
    "Lmxlbmd0aDsrK3Qpe2NvbnN0IGk9dGhpcy5fc3ViUGFyYW1zSWR4W3RdPj44LHM9MjU1JnRoaXMuX3N1YlBhcmFtc0lkeFt0XTtzLWk+MCYmKGVbdF09dGhp"
    "cy5fc3ViUGFyYW1zLnNsaWNlKGkscykpfXJldHVybiBlfWFkZERpZ2l0KGUpe2xldCB0O2lmKHRoaXMuX3JlamVjdERpZ2l0c3x8ISh0PXRoaXMuX2RpZ2l0"
    "SXNTdWI/dGhpcy5fc3ViUGFyYW1zTGVuZ3RoOnRoaXMubGVuZ3RoKXx8dGhpcy5fZGlnaXRJc1N1YiYmdGhpcy5fcmVqZWN0U3ViRGlnaXRzKXJldHVybjtj"
    "b25zdCBzPXRoaXMuX2RpZ2l0SXNTdWI/dGhpcy5fc3ViUGFyYW1zOnRoaXMucGFyYW1zLHI9c1t0LTFdO3NbdC0xXT1+cj9NYXRoLm1pbigxMCpyK2UsaSk6"
    "ZX19dC5QYXJhbXM9c30sNTc0MTooZSx0KT0+e09iamVjdC5kZWZpbmVQcm9wZXJ0eSh0LCJfX2VzTW9kdWxlIix7dmFsdWU6ITB9KSx0LkFkZG9uTWFuYWdl"
    "cj12b2lkIDAsdC5BZGRvbk1hbmFnZXI9Y2xhc3N7Y29uc3RydWN0b3IoKXt0aGlzLl9hZGRvbnM9W119ZGlzcG9zZSgpe2ZvcihsZXQgZT10aGlzLl9hZGRv"
    "bnMubGVuZ3RoLTE7ZT49MDtlLS0pdGhpcy5fYWRkb25zW2VdLmluc3RhbmNlLmRpc3Bvc2UoKX1sb2FkQWRkb24oZSx0KXtjb25zdCBpPXtpbnN0YW5jZTp0"
    "LGRpc3Bvc2U6dC5kaXNwb3NlLGlzRGlzcG9zZWQ6ITF9O3RoaXMuX2FkZG9ucy5wdXNoKGkpLHQuZGlzcG9zZT0oKT0+dGhpcy5fd3JhcHBlZEFkZG9uRGlz"
    "cG9zZShpKSx0LmFjdGl2YXRlKGUpfV93cmFwcGVkQWRkb25EaXNwb3NlKGUpe2lmKGUuaXNEaXNwb3NlZClyZXR1cm47bGV0IHQ9LTE7Zm9yKGxldCBpPTA7"
    "aTx0aGlzLl9hZGRvbnMubGVuZ3RoO2krKylpZih0aGlzLl9hZGRvbnNbaV09PT1lKXt0PWk7YnJlYWt9aWYoLTE9PT10KXRocm93IG5ldyBFcnJvcigiQ291"
    "bGQgbm90IGRpc3Bvc2UgYW4gYWRkb24gdGhhdCBoYXMgbm90IGJlZW4gbG9hZGVkIik7ZS5pc0Rpc3Bvc2VkPSEwLGUuZGlzcG9zZS5hcHBseShlLmluc3Rh"
    "bmNlKSx0aGlzLl9hZGRvbnMuc3BsaWNlKHQsMSl9fX0sODc3MTooZSx0LGkpPT57T2JqZWN0LmRlZmluZVByb3BlcnR5KHQsIl9fZXNNb2R1bGUiLHt2YWx1"
    "ZTohMH0pLHQuQnVmZmVyQXBpVmlldz12b2lkIDA7Y29uc3Qgcz1pKDM3ODUpLHI9aSg1MTEpO3QuQnVmZmVyQXBpVmlldz1jbGFzc3tjb25zdHJ1Y3Rvcihl"
    "LHQpe3RoaXMuX2J1ZmZlcj1lLHRoaXMudHlwZT10fWluaXQoZSl7cmV0dXJuIHRoaXMuX2J1ZmZlcj1lLHRoaXN9Z2V0IGN1cnNvclkoKXtyZXR1cm4gdGhp"
    "cy5fYnVmZmVyLnl9Z2V0IGN1cnNvclgoKXtyZXR1cm4gdGhpcy5fYnVmZmVyLnh9Z2V0IHZpZXdwb3J0WSgpe3JldHVybiB0aGlzLl9idWZmZXIueWRpc3B9"
    "Z2V0IGJhc2VZKCl7cmV0dXJuIHRoaXMuX2J1ZmZlci55YmFzZX1nZXQgbGVuZ3RoKCl7cmV0dXJuIHRoaXMuX2J1ZmZlci5saW5lcy5sZW5ndGh9Z2V0TGlu"
    "ZShlKXtjb25zdCB0PXRoaXMuX2J1ZmZlci5saW5lcy5nZXQoZSk7aWYodClyZXR1cm4gbmV3IHMuQnVmZmVyTGluZUFwaVZpZXcodCl9Z2V0TnVsbENlbGwo"
    "KXtyZXR1cm4gbmV3IHIuQ2VsbERhdGF9fX0sMzc4NTooZSx0LGkpPT57T2JqZWN0LmRlZmluZVByb3BlcnR5KHQsIl9fZXNNb2R1bGUiLHt2YWx1ZTohMH0p"
    "LHQuQnVmZmVyTGluZUFwaVZpZXc9dm9pZCAwO2NvbnN0IHM9aSg1MTEpO3QuQnVmZmVyTGluZUFwaVZpZXc9Y2xhc3N7Y29uc3RydWN0b3IoZSl7dGhpcy5f"
    "bGluZT1lfWdldCBpc1dyYXBwZWQoKXtyZXR1cm4gdGhpcy5fbGluZS5pc1dyYXBwZWR9Z2V0IGxlbmd0aCgpe3JldHVybiB0aGlzLl9saW5lLmxlbmd0aH1n"
    "ZXRDZWxsKGUsdCl7aWYoIShlPDB8fGU+PXRoaXMuX2xpbmUubGVuZ3RoKSlyZXR1cm4gdD8odGhpcy5fbGluZS5sb2FkQ2VsbChlLHQpLHQpOnRoaXMuX2xp"
    "bmUubG9hZENlbGwoZSxuZXcgcy5DZWxsRGF0YSl9dHJhbnNsYXRlVG9TdHJpbmcoZSx0LGkpe3JldHVybiB0aGlzLl9saW5lLnRyYW5zbGF0ZVRvU3RyaW5n"
    "KGUsdCxpKX19fSw4Mjg1OihlLHQsaSk9PntPYmplY3QuZGVmaW5lUHJvcGVydHkodCwiX19lc01vZHVsZSIse3ZhbHVlOiEwfSksdC5CdWZmZXJOYW1lc3Bh"
    "Y2VBcGk9dm9pZCAwO2NvbnN0IHM9aSg4NzcxKSxyPWkoODQ2MCksbj1pKDg0NCk7Y2xhc3MgbyBleHRlbmRzIG4uRGlzcG9zYWJsZXtjb25zdHJ1Y3Rvcihl"
    "KXtzdXBlcigpLHRoaXMuX2NvcmU9ZSx0aGlzLl9vbkJ1ZmZlckNoYW5nZT10aGlzLnJlZ2lzdGVyKG5ldyByLkV2ZW50RW1pdHRlciksdGhpcy5vbkJ1ZmZl"
    "ckNoYW5nZT10aGlzLl9vbkJ1ZmZlckNoYW5nZS5ldmVudCx0aGlzLl9ub3JtYWw9bmV3IHMuQnVmZmVyQXBpVmlldyh0aGlzLl9jb3JlLmJ1ZmZlcnMubm9y"
    "bWFsLCJub3JtYWwiKSx0aGlzLl9hbHRlcm5hdGU9bmV3IHMuQnVmZmVyQXBpVmlldyh0aGlzLl9jb3JlLmJ1ZmZlcnMuYWx0LCJhbHRlcm5hdGUiKSx0aGlz"
    "Ll9jb3JlLmJ1ZmZlcnMub25CdWZmZXJBY3RpdmF0ZSgoKCk9PnRoaXMuX29uQnVmZmVyQ2hhbmdlLmZpcmUodGhpcy5hY3RpdmUpKSl9Z2V0IGFjdGl2ZSgp"
    "e2lmKHRoaXMuX2NvcmUuYnVmZmVycy5hY3RpdmU9PT10aGlzLl9jb3JlLmJ1ZmZlcnMubm9ybWFsKXJldHVybiB0aGlzLm5vcm1hbDtpZih0aGlzLl9jb3Jl"
    "LmJ1ZmZlcnMuYWN0aXZlPT09dGhpcy5fY29yZS5idWZmZXJzLmFsdClyZXR1cm4gdGhpcy5hbHRlcm5hdGU7dGhyb3cgbmV3IEVycm9yKCJBY3RpdmUgYnVm"
    "ZmVyIGlzIG5laXRoZXIgbm9ybWFsIG5vciBhbHRlcm5hdGUiKX1nZXQgbm9ybWFsKCl7cmV0dXJuIHRoaXMuX25vcm1hbC5pbml0KHRoaXMuX2NvcmUuYnVm"
    "ZmVycy5ub3JtYWwpfWdldCBhbHRlcm5hdGUoKXtyZXR1cm4gdGhpcy5fYWx0ZXJuYXRlLmluaXQodGhpcy5fY29yZS5idWZmZXJzLmFsdCl9fXQuQnVmZmVy"
    "TmFtZXNwYWNlQXBpPW99LDc5NzU6KGUsdCk9PntPYmplY3QuZGVmaW5lUHJvcGVydHkodCwiX19lc01vZHVsZSIse3ZhbHVlOiEwfSksdC5QYXJzZXJBcGk9"
    "dm9pZCAwLHQuUGFyc2VyQXBpPWNsYXNze2NvbnN0cnVjdG9yKGUpe3RoaXMuX2NvcmU9ZX1yZWdpc3RlckNzaUhhbmRsZXIoZSx0KXtyZXR1cm4gdGhpcy5f"
    "Y29yZS5yZWdpc3RlckNzaUhhbmRsZXIoZSwoZT0+dChlLnRvQXJyYXkoKSkpKX1hZGRDc2lIYW5kbGVyKGUsdCl7cmV0dXJuIHRoaXMucmVnaXN0ZXJDc2lI"
    "YW5kbGVyKGUsdCl9cmVnaXN0ZXJEY3NIYW5kbGVyKGUsdCl7cmV0dXJuIHRoaXMuX2NvcmUucmVnaXN0ZXJEY3NIYW5kbGVyKGUsKChlLGkpPT50KGUsaS50"
    "b0FycmF5KCkpKSl9YWRkRGNzSGFuZGxlcihlLHQpe3JldHVybiB0aGlzLnJlZ2lzdGVyRGNzSGFuZGxlcihlLHQpfXJlZ2lzdGVyRXNjSGFuZGxlcihlLHQp"
    "e3JldHVybiB0aGlzLl9jb3JlLnJlZ2lzdGVyRXNjSGFuZGxlcihlLHQpfWFkZEVzY0hhbmRsZXIoZSx0KXtyZXR1cm4gdGhpcy5yZWdpc3RlckVzY0hhbmRs"
    "ZXIoZSx0KX1yZWdpc3Rlck9zY0hhbmRsZXIoZSx0KXtyZXR1cm4gdGhpcy5fY29yZS5yZWdpc3Rlck9zY0hhbmRsZXIoZSx0KX1hZGRPc2NIYW5kbGVyKGUs"
    "dCl7cmV0dXJuIHRoaXMucmVnaXN0ZXJPc2NIYW5kbGVyKGUsdCl9fX0sNzA5MDooZSx0KT0+e09iamVjdC5kZWZpbmVQcm9wZXJ0eSh0LCJfX2VzTW9kdWxl"
    "Iix7dmFsdWU6ITB9KSx0LlVuaWNvZGVBcGk9dm9pZCAwLHQuVW5pY29kZUFwaT1jbGFzc3tjb25zdHJ1Y3RvcihlKXt0aGlzLl9jb3JlPWV9cmVnaXN0ZXIo"
    "ZSl7dGhpcy5fY29yZS51bmljb2RlU2VydmljZS5yZWdpc3RlcihlKX1nZXQgdmVyc2lvbnMoKXtyZXR1cm4gdGhpcy5fY29yZS51bmljb2RlU2VydmljZS52"
    "ZXJzaW9uc31nZXQgYWN0aXZlVmVyc2lvbigpe3JldHVybiB0aGlzLl9jb3JlLnVuaWNvZGVTZXJ2aWNlLmFjdGl2ZVZlcnNpb259c2V0IGFjdGl2ZVZlcnNp"
    "b24oZSl7dGhpcy5fY29yZS51bmljb2RlU2VydmljZS5hY3RpdmVWZXJzaW9uPWV9fX0sNzQ0OmZ1bmN0aW9uKGUsdCxpKXt2YXIgcz10aGlzJiZ0aGlzLl9f"
    "ZGVjb3JhdGV8fGZ1bmN0aW9uKGUsdCxpLHMpe3ZhciByLG49YXJndW1lbnRzLmxlbmd0aCxvPW48Mz90Om51bGw9PT1zP3M9T2JqZWN0LmdldE93blByb3Bl"
    "cnR5RGVzY3JpcHRvcih0LGkpOnM7aWYoIm9iamVjdCI9PXR5cGVvZiBSZWZsZWN0JiYiZnVuY3Rpb24iPT10eXBlb2YgUmVmbGVjdC5kZWNvcmF0ZSlvPVJl"
    "ZmxlY3QuZGVjb3JhdGUoZSx0LGkscyk7ZWxzZSBmb3IodmFyIGE9ZS5sZW5ndGgtMTthPj0wO2EtLSkocj1lW2FdKSYmKG89KG48Mz9yKG8pOm4+Mz9yKHQs"
    "aSxvKTpyKHQsaSkpfHxvKTtyZXR1cm4gbj4zJiZvJiZPYmplY3QuZGVmaW5lUHJvcGVydHkodCxpLG8pLG99LHI9dGhpcyYmdGhpcy5fX3BhcmFtfHxmdW5j"
    "dGlvbihlLHQpe3JldHVybiBmdW5jdGlvbihpLHMpe3QoaSxzLGUpfX07T2JqZWN0LmRlZmluZVByb3BlcnR5KHQsIl9fZXNNb2R1bGUiLHt2YWx1ZTohMH0p"
    "LHQuQnVmZmVyU2VydmljZT10Lk1JTklNVU1fUk9XUz10Lk1JTklNVU1fQ09MUz12b2lkIDA7Y29uc3Qgbj1pKDg0NjApLG89aSg4NDQpLGE9aSg1Mjk1KSxo"
    "PWkoMjU4NSk7dC5NSU5JTVVNX0NPTFM9Mix0Lk1JTklNVU1fUk9XUz0xO2xldCBjPXQuQnVmZmVyU2VydmljZT1jbGFzcyBleHRlbmRzIG8uRGlzcG9zYWJs"
    "ZXtnZXQgYnVmZmVyKCl7cmV0dXJuIHRoaXMuYnVmZmVycy5hY3RpdmV9Y29uc3RydWN0b3IoZSl7c3VwZXIoKSx0aGlzLmlzVXNlclNjcm9sbGluZz0hMSx0"
    "aGlzLl9vblJlc2l6ZT10aGlzLnJlZ2lzdGVyKG5ldyBuLkV2ZW50RW1pdHRlciksdGhpcy5vblJlc2l6ZT10aGlzLl9vblJlc2l6ZS5ldmVudCx0aGlzLl9v"
    "blNjcm9sbD10aGlzLnJlZ2lzdGVyKG5ldyBuLkV2ZW50RW1pdHRlciksdGhpcy5vblNjcm9sbD10aGlzLl9vblNjcm9sbC5ldmVudCx0aGlzLmNvbHM9TWF0"
    "aC5tYXgoZS5yYXdPcHRpb25zLmNvbHN8fDAsdC5NSU5JTVVNX0NPTFMpLHRoaXMucm93cz1NYXRoLm1heChlLnJhd09wdGlvbnMucm93c3x8MCx0Lk1JTklN"
    "VU1fUk9XUyksdGhpcy5idWZmZXJzPXRoaXMucmVnaXN0ZXIobmV3IGEuQnVmZmVyU2V0KGUsdGhpcykpfXJlc2l6ZShlLHQpe3RoaXMuY29scz1lLHRoaXMu"
    "cm93cz10LHRoaXMuYnVmZmVycy5yZXNpemUoZSx0KSx0aGlzLl9vblJlc2l6ZS5maXJlKHtjb2xzOmUscm93czp0fSl9cmVzZXQoKXt0aGlzLmJ1ZmZlcnMu"
    "cmVzZXQoKSx0aGlzLmlzVXNlclNjcm9sbGluZz0hMX1zY3JvbGwoZSx0PSExKXtjb25zdCBpPXRoaXMuYnVmZmVyO2xldCBzO3M9dGhpcy5fY2FjaGVkQmxh"
    "bmtMaW5lLHMmJnMubGVuZ3RoPT09dGhpcy5jb2xzJiZzLmdldEZnKDApPT09ZS5mZyYmcy5nZXRCZygwKT09PWUuYmd8fChzPWkuZ2V0QmxhbmtMaW5lKGUs"
    "dCksdGhpcy5fY2FjaGVkQmxhbmtMaW5lPXMpLHMuaXNXcmFwcGVkPXQ7Y29uc3Qgcj1pLnliYXNlK2kuc2Nyb2xsVG9wLG49aS55YmFzZStpLnNjcm9sbEJv"
    "dHRvbTtpZigwPT09aS5zY3JvbGxUb3Ape2NvbnN0IGU9aS5saW5lcy5pc0Z1bGw7bj09PWkubGluZXMubGVuZ3RoLTE/ZT9pLmxpbmVzLnJlY3ljbGUoKS5j"
    "b3B5RnJvbShzKTppLmxpbmVzLnB1c2gocy5jbG9uZSgpKTppLmxpbmVzLnNwbGljZShuKzEsMCxzLmNsb25lKCkpLGU/dGhpcy5pc1VzZXJTY3JvbGxpbmcm"
    "JihpLnlkaXNwPU1hdGgubWF4KGkueWRpc3AtMSwwKSk6KGkueWJhc2UrKyx0aGlzLmlzVXNlclNjcm9sbGluZ3x8aS55ZGlzcCsrKX1lbHNle2NvbnN0IGU9"
    "bi1yKzE7aS5saW5lcy5zaGlmdEVsZW1lbnRzKHIrMSxlLTEsLTEpLGkubGluZXMuc2V0KG4scy5jbG9uZSgpKX10aGlzLmlzVXNlclNjcm9sbGluZ3x8KGku"
    "eWRpc3A9aS55YmFzZSksdGhpcy5fb25TY3JvbGwuZmlyZShpLnlkaXNwKX1zY3JvbGxMaW5lcyhlLHQsaSl7Y29uc3Qgcz10aGlzLmJ1ZmZlcjtpZihlPDAp"
    "e2lmKDA9PT1zLnlkaXNwKXJldHVybjt0aGlzLmlzVXNlclNjcm9sbGluZz0hMH1lbHNlIGUrcy55ZGlzcD49cy55YmFzZSYmKHRoaXMuaXNVc2VyU2Nyb2xs"
    "aW5nPSExKTtjb25zdCByPXMueWRpc3A7cy55ZGlzcD1NYXRoLm1heChNYXRoLm1pbihzLnlkaXNwK2Uscy55YmFzZSksMCksciE9PXMueWRpc3AmJih0fHx0"
    "aGlzLl9vblNjcm9sbC5maXJlKHMueWRpc3ApKX19O3QuQnVmZmVyU2VydmljZT1jPXMoW3IoMCxoLklPcHRpb25zU2VydmljZSldLGMpfSw3OTk0OihlLHQp"
    "PT57T2JqZWN0LmRlZmluZVByb3BlcnR5KHQsIl9fZXNNb2R1bGUiLHt2YWx1ZTohMH0pLHQuQ2hhcnNldFNlcnZpY2U9dm9pZCAwLHQuQ2hhcnNldFNlcnZp"
    "Y2U9Y2xhc3N7Y29uc3RydWN0b3IoKXt0aGlzLmdsZXZlbD0wLHRoaXMuX2NoYXJzZXRzPVtdfXJlc2V0KCl7dGhpcy5jaGFyc2V0PXZvaWQgMCx0aGlzLl9j"
    "aGFyc2V0cz1bXSx0aGlzLmdsZXZlbD0wfXNldGdMZXZlbChlKXt0aGlzLmdsZXZlbD1lLHRoaXMuY2hhcnNldD10aGlzLl9jaGFyc2V0c1tlXX1zZXRnQ2hh"
    "cnNldChlLHQpe3RoaXMuX2NoYXJzZXRzW2VdPXQsdGhpcy5nbGV2ZWw9PT1lJiYodGhpcy5jaGFyc2V0PXQpfX19LDE3NTM6ZnVuY3Rpb24oZSx0LGkpe3Zh"
    "ciBzPXRoaXMmJnRoaXMuX19kZWNvcmF0ZXx8ZnVuY3Rpb24oZSx0LGkscyl7dmFyIHIsbj1hcmd1bWVudHMubGVuZ3RoLG89bjwzP3Q6bnVsbD09PXM/cz1P"
    "YmplY3QuZ2V0T3duUHJvcGVydHlEZXNjcmlwdG9yKHQsaSk6cztpZigib2JqZWN0Ij09dHlwZW9mIFJlZmxlY3QmJiJmdW5jdGlvbiI9PXR5cGVvZiBSZWZs"
    "ZWN0LmRlY29yYXRlKW89UmVmbGVjdC5kZWNvcmF0ZShlLHQsaSxzKTtlbHNlIGZvcih2YXIgYT1lLmxlbmd0aC0xO2E+PTA7YS0tKShyPWVbYV0pJiYobz0o"
    "bjwzP3Iobyk6bj4zP3IodCxpLG8pOnIodCxpKSl8fG8pO3JldHVybiBuPjMmJm8mJk9iamVjdC5kZWZpbmVQcm9wZXJ0eSh0LGksbyksb30scj10aGlzJiZ0"
    "aGlzLl9fcGFyYW18fGZ1bmN0aW9uKGUsdCl7cmV0dXJuIGZ1bmN0aW9uKGkscyl7dChpLHMsZSl9fTtPYmplY3QuZGVmaW5lUHJvcGVydHkodCwiX19lc01v"
    "ZHVsZSIse3ZhbHVlOiEwfSksdC5Db3JlTW91c2VTZXJ2aWNlPXZvaWQgMDtjb25zdCBuPWkoMjU4NSksbz1pKDg0NjApLGE9aSg4NDQpLGg9e05PTkU6e2V2"
    "ZW50czowLHJlc3RyaWN0OigpPT4hMX0sWDEwOntldmVudHM6MSxyZXN0cmljdDplPT40IT09ZS5idXR0b24mJjE9PT1lLmFjdGlvbiYmKGUuY3RybD0hMSxl"
    "LmFsdD0hMSxlLnNoaWZ0PSExLCEwKX0sVlQyMDA6e2V2ZW50czoxOSxyZXN0cmljdDplPT4zMiE9PWUuYWN0aW9ufSxEUkFHOntldmVudHM6MjMscmVzdHJp"
    "Y3Q6ZT0+MzIhPT1lLmFjdGlvbnx8MyE9PWUuYnV0dG9ufSxBTlk6e2V2ZW50czozMSxyZXN0cmljdDplPT4hMH19O2Z1bmN0aW9uIGMoZSx0KXtsZXQgaT0o"
    "ZS5jdHJsPzE2OjApfChlLnNoaWZ0PzQ6MCl8KGUuYWx0Pzg6MCk7cmV0dXJuIDQ9PT1lLmJ1dHRvbj8oaXw9NjQsaXw9ZS5hY3Rpb24pOihpfD0zJmUuYnV0"
    "dG9uLDQmZS5idXR0b24mJihpfD02NCksOCZlLmJ1dHRvbiYmKGl8PTEyOCksMzI9PT1lLmFjdGlvbj9pfD0zMjowIT09ZS5hY3Rpb258fHR8fChpfD0zKSks"
    "aX1jb25zdCBsPVN0cmluZy5mcm9tQ2hhckNvZGUsZD17REVGQVVMVDplPT57Y29uc3QgdD1bYyhlLCExKSszMixlLmNvbCszMixlLnJvdyszMl07cmV0dXJu"
    "IHRbMF0+MjU1fHx0WzFdPjI1NXx8dFsyXT4yNTU/IiI6YBtbTSR7bCh0WzBdKX0ke2wodFsxXSl9JHtsKHRbMl0pfWB9LFNHUjplPT57Y29uc3QgdD0wPT09"
    "ZS5hY3Rpb24mJjQhPT1lLmJ1dHRvbj8ibSI6Ik0iO3JldHVybmAbWzwke2MoZSwhMCl9OyR7ZS5jb2x9OyR7ZS5yb3d9JHt0fWB9LFNHUl9QSVhFTFM6ZT0+"
    "e2NvbnN0IHQ9MD09PWUuYWN0aW9uJiY0IT09ZS5idXR0b24/Im0iOiJNIjtyZXR1cm5gG1s8JHtjKGUsITApfTske2UueH07JHtlLnl9JHt0fWB9fTtsZXQg"
    "Xz10LkNvcmVNb3VzZVNlcnZpY2U9Y2xhc3MgZXh0ZW5kcyBhLkRpc3Bvc2FibGV7Y29uc3RydWN0b3IoZSx0KXtzdXBlcigpLHRoaXMuX2J1ZmZlclNlcnZp"
    "Y2U9ZSx0aGlzLl9jb3JlU2VydmljZT10LHRoaXMuX3Byb3RvY29scz17fSx0aGlzLl9lbmNvZGluZ3M9e30sdGhpcy5fYWN0aXZlUHJvdG9jb2w9IiIsdGhp"
    "cy5fYWN0aXZlRW5jb2Rpbmc9IiIsdGhpcy5fbGFzdEV2ZW50PW51bGwsdGhpcy5fb25Qcm90b2NvbENoYW5nZT10aGlzLnJlZ2lzdGVyKG5ldyBvLkV2ZW50"
    "RW1pdHRlciksdGhpcy5vblByb3RvY29sQ2hhbmdlPXRoaXMuX29uUHJvdG9jb2xDaGFuZ2UuZXZlbnQ7Zm9yKGNvbnN0IGUgb2YgT2JqZWN0LmtleXMoaCkp"
    "dGhpcy5hZGRQcm90b2NvbChlLGhbZV0pO2Zvcihjb25zdCBlIG9mIE9iamVjdC5rZXlzKGQpKXRoaXMuYWRkRW5jb2RpbmcoZSxkW2VdKTt0aGlzLnJlc2V0"
    "KCl9YWRkUHJvdG9jb2woZSx0KXt0aGlzLl9wcm90b2NvbHNbZV09dH1hZGRFbmNvZGluZyhlLHQpe3RoaXMuX2VuY29kaW5nc1tlXT10fWdldCBhY3RpdmVQ"
    "cm90b2NvbCgpe3JldHVybiB0aGlzLl9hY3RpdmVQcm90b2NvbH1nZXQgYXJlTW91c2VFdmVudHNBY3RpdmUoKXtyZXR1cm4gMCE9PXRoaXMuX3Byb3RvY29s"
    "c1t0aGlzLl9hY3RpdmVQcm90b2NvbF0uZXZlbnRzfXNldCBhY3RpdmVQcm90b2NvbChlKXtpZighdGhpcy5fcHJvdG9jb2xzW2VdKXRocm93IG5ldyBFcnJv"
    "cihgdW5rbm93biBwcm90b2NvbCAiJHtlfSJgKTt0aGlzLl9hY3RpdmVQcm90b2NvbD1lLHRoaXMuX29uUHJvdG9jb2xDaGFuZ2UuZmlyZSh0aGlzLl9wcm90"
    "b2NvbHNbZV0uZXZlbnRzKX1nZXQgYWN0aXZlRW5jb2RpbmcoKXtyZXR1cm4gdGhpcy5fYWN0aXZlRW5jb2Rpbmd9c2V0IGFjdGl2ZUVuY29kaW5nKGUpe2lm"
    "KCF0aGlzLl9lbmNvZGluZ3NbZV0pdGhyb3cgbmV3IEVycm9yKGB1bmtub3duIGVuY29kaW5nICIke2V9ImApO3RoaXMuX2FjdGl2ZUVuY29kaW5nPWV9cmVz"
    "ZXQoKXt0aGlzLmFjdGl2ZVByb3RvY29sPSJOT05FIix0aGlzLmFjdGl2ZUVuY29kaW5nPSJERUZBVUxUIix0aGlzLl9sYXN0RXZlbnQ9bnVsbH10cmlnZ2Vy"
    "TW91c2VFdmVudChlKXtpZihlLmNvbDwwfHxlLmNvbD49dGhpcy5fYnVmZmVyU2VydmljZS5jb2xzfHxlLnJvdzwwfHxlLnJvdz49dGhpcy5fYnVmZmVyU2Vy"
    "dmljZS5yb3dzKXJldHVybiExO2lmKDQ9PT1lLmJ1dHRvbiYmMzI9PT1lLmFjdGlvbilyZXR1cm4hMTtpZigzPT09ZS5idXR0b24mJjMyIT09ZS5hY3Rpb24p"
    "cmV0dXJuITE7aWYoNCE9PWUuYnV0dG9uJiYoMj09PWUuYWN0aW9ufHwzPT09ZS5hY3Rpb24pKXJldHVybiExO2lmKGUuY29sKyssZS5yb3crKywzMj09PWUu"
    "YWN0aW9uJiZ0aGlzLl9sYXN0RXZlbnQmJnRoaXMuX2VxdWFsRXZlbnRzKHRoaXMuX2xhc3RFdmVudCxlLCJTR1JfUElYRUxTIj09PXRoaXMuX2FjdGl2ZUVu"
    "Y29kaW5nKSlyZXR1cm4hMTtpZighdGhpcy5fcHJvdG9jb2xzW3RoaXMuX2FjdGl2ZVByb3RvY29sXS5yZXN0cmljdChlKSlyZXR1cm4hMTtjb25zdCB0PXRo"
    "aXMuX2VuY29kaW5nc1t0aGlzLl9hY3RpdmVFbmNvZGluZ10oZSk7cmV0dXJuIHQmJigiREVGQVVMVCI9PT10aGlzLl9hY3RpdmVFbmNvZGluZz90aGlzLl9j"
    "b3JlU2VydmljZS50cmlnZ2VyQmluYXJ5RXZlbnQodCk6dGhpcy5fY29yZVNlcnZpY2UudHJpZ2dlckRhdGFFdmVudCh0LCEwKSksdGhpcy5fbGFzdEV2ZW50"
    "PWUsITB9ZXhwbGFpbkV2ZW50cyhlKXtyZXR1cm57ZG93bjohISgxJmUpLHVwOiEhKDImZSksZHJhZzohISg0JmUpLG1vdmU6ISEoOCZlKSx3aGVlbDohISgx"
    "NiZlKX19X2VxdWFsRXZlbnRzKGUsdCxpKXtpZihpKXtpZihlLnghPT10LngpcmV0dXJuITE7aWYoZS55IT09dC55KXJldHVybiExfWVsc2V7aWYoZS5jb2wh"
    "PT10LmNvbClyZXR1cm4hMTtpZihlLnJvdyE9PXQucm93KXJldHVybiExfXJldHVybiBlLmJ1dHRvbj09PXQuYnV0dG9uJiZlLmFjdGlvbj09PXQuYWN0aW9u"
    "JiZlLmN0cmw9PT10LmN0cmwmJmUuYWx0PT09dC5hbHQmJmUuc2hpZnQ9PT10LnNoaWZ0fX07dC5Db3JlTW91c2VTZXJ2aWNlPV89cyhbcigwLG4uSUJ1ZmZl"
    "clNlcnZpY2UpLHIoMSxuLklDb3JlU2VydmljZSldLF8pfSw2OTc1OmZ1bmN0aW9uKGUsdCxpKXt2YXIgcz10aGlzJiZ0aGlzLl9fZGVjb3JhdGV8fGZ1bmN0"
    "aW9uKGUsdCxpLHMpe3ZhciByLG49YXJndW1lbnRzLmxlbmd0aCxvPW48Mz90Om51bGw9PT1zP3M9T2JqZWN0LmdldE93blByb3BlcnR5RGVzY3JpcHRvcih0"
    "LGkpOnM7aWYoIm9iamVjdCI9PXR5cGVvZiBSZWZsZWN0JiYiZnVuY3Rpb24iPT10eXBlb2YgUmVmbGVjdC5kZWNvcmF0ZSlvPVJlZmxlY3QuZGVjb3JhdGUo"
    "ZSx0LGkscyk7ZWxzZSBmb3IodmFyIGE9ZS5sZW5ndGgtMTthPj0wO2EtLSkocj1lW2FdKSYmKG89KG48Mz9yKG8pOm4+Mz9yKHQsaSxvKTpyKHQsaSkpfHxv"
    "KTtyZXR1cm4gbj4zJiZvJiZPYmplY3QuZGVmaW5lUHJvcGVydHkodCxpLG8pLG99LHI9dGhpcyYmdGhpcy5fX3BhcmFtfHxmdW5jdGlvbihlLHQpe3JldHVy"
    "biBmdW5jdGlvbihpLHMpe3QoaSxzLGUpfX07T2JqZWN0LmRlZmluZVByb3BlcnR5KHQsIl9fZXNNb2R1bGUiLHt2YWx1ZTohMH0pLHQuQ29yZVNlcnZpY2U9"
    "dm9pZCAwO2NvbnN0IG49aSgxNDM5KSxvPWkoODQ2MCksYT1pKDg0NCksaD1pKDI1ODUpLGM9T2JqZWN0LmZyZWV6ZSh7aW5zZXJ0TW9kZTohMX0pLGw9T2Jq"
    "ZWN0LmZyZWV6ZSh7YXBwbGljYXRpb25DdXJzb3JLZXlzOiExLGFwcGxpY2F0aW9uS2V5cGFkOiExLGJyYWNrZXRlZFBhc3RlTW9kZTohMSxvcmlnaW46ITEs"
    "cmV2ZXJzZVdyYXBhcm91bmQ6ITEsc2VuZEZvY3VzOiExLHdyYXBhcm91bmQ6ITB9KTtsZXQgZD10LkNvcmVTZXJ2aWNlPWNsYXNzIGV4dGVuZHMgYS5EaXNw"
    "b3NhYmxle2NvbnN0cnVjdG9yKGUsdCxpKXtzdXBlcigpLHRoaXMuX2J1ZmZlclNlcnZpY2U9ZSx0aGlzLl9sb2dTZXJ2aWNlPXQsdGhpcy5fb3B0aW9uc1Nl"
    "cnZpY2U9aSx0aGlzLmlzQ3Vyc29ySW5pdGlhbGl6ZWQ9ITEsdGhpcy5pc0N1cnNvckhpZGRlbj0hMSx0aGlzLl9vbkRhdGE9dGhpcy5yZWdpc3RlcihuZXcg"
    "by5FdmVudEVtaXR0ZXIpLHRoaXMub25EYXRhPXRoaXMuX29uRGF0YS5ldmVudCx0aGlzLl9vblVzZXJJbnB1dD10aGlzLnJlZ2lzdGVyKG5ldyBvLkV2ZW50"
    "RW1pdHRlciksdGhpcy5vblVzZXJJbnB1dD10aGlzLl9vblVzZXJJbnB1dC5ldmVudCx0aGlzLl9vbkJpbmFyeT10aGlzLnJlZ2lzdGVyKG5ldyBvLkV2ZW50"
    "RW1pdHRlciksdGhpcy5vbkJpbmFyeT10aGlzLl9vbkJpbmFyeS5ldmVudCx0aGlzLl9vblJlcXVlc3RTY3JvbGxUb0JvdHRvbT10aGlzLnJlZ2lzdGVyKG5l"
    "dyBvLkV2ZW50RW1pdHRlciksdGhpcy5vblJlcXVlc3RTY3JvbGxUb0JvdHRvbT10aGlzLl9vblJlcXVlc3RTY3JvbGxUb0JvdHRvbS5ldmVudCx0aGlzLm1v"
    "ZGVzPSgwLG4uY2xvbmUpKGMpLHRoaXMuZGVjUHJpdmF0ZU1vZGVzPSgwLG4uY2xvbmUpKGwpfXJlc2V0KCl7dGhpcy5tb2Rlcz0oMCxuLmNsb25lKShjKSx0"
    "aGlzLmRlY1ByaXZhdGVNb2Rlcz0oMCxuLmNsb25lKShsKX10cmlnZ2VyRGF0YUV2ZW50KGUsdD0hMSl7aWYodGhpcy5fb3B0aW9uc1NlcnZpY2UucmF3T3B0"
    "aW9ucy5kaXNhYmxlU3RkaW4pcmV0dXJuO2NvbnN0IGk9dGhpcy5fYnVmZmVyU2VydmljZS5idWZmZXI7dCYmdGhpcy5fb3B0aW9uc1NlcnZpY2UucmF3T3B0"
    "aW9ucy5zY3JvbGxPblVzZXJJbnB1dCYmaS55YmFzZSE9PWkueWRpc3AmJnRoaXMuX29uUmVxdWVzdFNjcm9sbFRvQm90dG9tLmZpcmUoKSx0JiZ0aGlzLl9v"
    "blVzZXJJbnB1dC5maXJlKCksdGhpcy5fbG9nU2VydmljZS5kZWJ1Zyhgc2VuZGluZyBkYXRhICIke2V9ImAsKCgpPT5lLnNwbGl0KCIiKS5tYXAoKGU9PmUu"
    "Y2hhckNvZGVBdCgwKSkpKSksdGhpcy5fb25EYXRhLmZpcmUoZSl9dHJpZ2dlckJpbmFyeUV2ZW50KGUpe3RoaXMuX29wdGlvbnNTZXJ2aWNlLnJhd09wdGlv"
    "bnMuZGlzYWJsZVN0ZGlufHwodGhpcy5fbG9nU2VydmljZS5kZWJ1Zyhgc2VuZGluZyBiaW5hcnkgIiR7ZX0iYCwoKCk9PmUuc3BsaXQoIiIpLm1hcCgoZT0+"
    "ZS5jaGFyQ29kZUF0KDApKSkpKSx0aGlzLl9vbkJpbmFyeS5maXJlKGUpKX19O3QuQ29yZVNlcnZpY2U9ZD1zKFtyKDAsaC5JQnVmZmVyU2VydmljZSkscigx"
    "LGguSUxvZ1NlcnZpY2UpLHIoMixoLklPcHRpb25zU2VydmljZSldLGQpfSw5MDc0OihlLHQsaSk9PntPYmplY3QuZGVmaW5lUHJvcGVydHkodCwiX19lc01v"
    "ZHVsZSIse3ZhbHVlOiEwfSksdC5EZWNvcmF0aW9uU2VydmljZT12b2lkIDA7Y29uc3Qgcz1pKDgwNTUpLHI9aSg4NDYwKSxuPWkoODQ0KSxvPWkoNjEwNik7"
    "bGV0IGE9MCxoPTA7Y2xhc3MgYyBleHRlbmRzIG4uRGlzcG9zYWJsZXtnZXQgZGVjb3JhdGlvbnMoKXtyZXR1cm4gdGhpcy5fZGVjb3JhdGlvbnMudmFsdWVz"
    "KCl9Y29uc3RydWN0b3IoKXtzdXBlcigpLHRoaXMuX2RlY29yYXRpb25zPW5ldyBvLlNvcnRlZExpc3QoKGU9Pm51bGw9PWU/dm9pZCAwOmUubWFya2VyLmxp"
    "bmUpKSx0aGlzLl9vbkRlY29yYXRpb25SZWdpc3RlcmVkPXRoaXMucmVnaXN0ZXIobmV3IHIuRXZlbnRFbWl0dGVyKSx0aGlzLm9uRGVjb3JhdGlvblJlZ2lz"
    "dGVyZWQ9dGhpcy5fb25EZWNvcmF0aW9uUmVnaXN0ZXJlZC5ldmVudCx0aGlzLl9vbkRlY29yYXRpb25SZW1vdmVkPXRoaXMucmVnaXN0ZXIobmV3IHIuRXZl"
    "bnRFbWl0dGVyKSx0aGlzLm9uRGVjb3JhdGlvblJlbW92ZWQ9dGhpcy5fb25EZWNvcmF0aW9uUmVtb3ZlZC5ldmVudCx0aGlzLnJlZ2lzdGVyKCgwLG4udG9E"
    "aXNwb3NhYmxlKSgoKCk9PnRoaXMucmVzZXQoKSkpKX1yZWdpc3RlckRlY29yYXRpb24oZSl7aWYoZS5tYXJrZXIuaXNEaXNwb3NlZClyZXR1cm47Y29uc3Qg"
    "dD1uZXcgbChlKTtpZih0KXtjb25zdCBlPXQubWFya2VyLm9uRGlzcG9zZSgoKCk9PnQuZGlzcG9zZSgpKSk7dC5vbkRpc3Bvc2UoKCgpPT57dCYmKHRoaXMu"
    "X2RlY29yYXRpb25zLmRlbGV0ZSh0KSYmdGhpcy5fb25EZWNvcmF0aW9uUmVtb3ZlZC5maXJlKHQpLGUuZGlzcG9zZSgpKX0pKSx0aGlzLl9kZWNvcmF0aW9u"
    "cy5pbnNlcnQodCksdGhpcy5fb25EZWNvcmF0aW9uUmVnaXN0ZXJlZC5maXJlKHQpfXJldHVybiB0fXJlc2V0KCl7Zm9yKGNvbnN0IGUgb2YgdGhpcy5fZGVj"
    "b3JhdGlvbnMudmFsdWVzKCkpZS5kaXNwb3NlKCk7dGhpcy5fZGVjb3JhdGlvbnMuY2xlYXIoKX0qZ2V0RGVjb3JhdGlvbnNBdENlbGwoZSx0LGkpe3ZhciBz"
    "LHIsbjtsZXQgbz0wLGE9MDtmb3IoY29uc3QgaCBvZiB0aGlzLl9kZWNvcmF0aW9ucy5nZXRLZXlJdGVyYXRvcih0KSlvPW51bGwhPT0ocz1oLm9wdGlvbnMu"
    "eCkmJnZvaWQgMCE9PXM/czowLGE9bysobnVsbCE9PShyPWgub3B0aW9ucy53aWR0aCkmJnZvaWQgMCE9PXI/cjoxKSxlPj1vJiZlPGEmJighaXx8KG51bGwh"
    "PT0obj1oLm9wdGlvbnMubGF5ZXIpJiZ2b2lkIDAhPT1uP246ImJvdHRvbSIpPT09aSkmJih5aWVsZCBoKX1mb3JFYWNoRGVjb3JhdGlvbkF0Q2VsbChlLHQs"
    "aSxzKXt0aGlzLl9kZWNvcmF0aW9ucy5mb3JFYWNoQnlLZXkodCwodD0+e3ZhciByLG4sbzthPW51bGwhPT0ocj10Lm9wdGlvbnMueCkmJnZvaWQgMCE9PXI/"
    "cjowLGg9YSsobnVsbCE9PShuPXQub3B0aW9ucy53aWR0aCkmJnZvaWQgMCE9PW4/bjoxKSxlPj1hJiZlPGgmJighaXx8KG51bGwhPT0obz10Lm9wdGlvbnMu"
    "bGF5ZXIpJiZ2b2lkIDAhPT1vP286ImJvdHRvbSIpPT09aSkmJnModCl9KSl9fXQuRGVjb3JhdGlvblNlcnZpY2U9YztjbGFzcyBsIGV4dGVuZHMgbi5EaXNw"
    "b3NhYmxle2dldCBpc0Rpc3Bvc2VkKCl7cmV0dXJuIHRoaXMuX2lzRGlzcG9zZWR9Z2V0IGJhY2tncm91bmRDb2xvclJHQigpe3JldHVybiBudWxsPT09dGhp"
    "cy5fY2FjaGVkQmcmJih0aGlzLm9wdGlvbnMuYmFja2dyb3VuZENvbG9yP3RoaXMuX2NhY2hlZEJnPXMuY3NzLnRvQ29sb3IodGhpcy5vcHRpb25zLmJhY2tn"
    "cm91bmRDb2xvcik6dGhpcy5fY2FjaGVkQmc9dm9pZCAwKSx0aGlzLl9jYWNoZWRCZ31nZXQgZm9yZWdyb3VuZENvbG9yUkdCKCl7cmV0dXJuIG51bGw9PT10"
    "aGlzLl9jYWNoZWRGZyYmKHRoaXMub3B0aW9ucy5mb3JlZ3JvdW5kQ29sb3I/dGhpcy5fY2FjaGVkRmc9cy5jc3MudG9Db2xvcih0aGlzLm9wdGlvbnMuZm9y"
    "ZWdyb3VuZENvbG9yKTp0aGlzLl9jYWNoZWRGZz12b2lkIDApLHRoaXMuX2NhY2hlZEZnfWNvbnN0cnVjdG9yKGUpe3N1cGVyKCksdGhpcy5vcHRpb25zPWUs"
    "dGhpcy5vblJlbmRlckVtaXR0ZXI9dGhpcy5yZWdpc3RlcihuZXcgci5FdmVudEVtaXR0ZXIpLHRoaXMub25SZW5kZXI9dGhpcy5vblJlbmRlckVtaXR0ZXIu"
    "ZXZlbnQsdGhpcy5fb25EaXNwb3NlPXRoaXMucmVnaXN0ZXIobmV3IHIuRXZlbnRFbWl0dGVyKSx0aGlzLm9uRGlzcG9zZT10aGlzLl9vbkRpc3Bvc2UuZXZl"
    "bnQsdGhpcy5fY2FjaGVkQmc9bnVsbCx0aGlzLl9jYWNoZWRGZz1udWxsLHRoaXMubWFya2VyPWUubWFya2VyLHRoaXMub3B0aW9ucy5vdmVydmlld1J1bGVy"
    "T3B0aW9ucyYmIXRoaXMub3B0aW9ucy5vdmVydmlld1J1bGVyT3B0aW9ucy5wb3NpdGlvbiYmKHRoaXMub3B0aW9ucy5vdmVydmlld1J1bGVyT3B0aW9ucy5w"
    "b3NpdGlvbj0iZnVsbCIpfWRpc3Bvc2UoKXt0aGlzLl9vbkRpc3Bvc2UuZmlyZSgpLHN1cGVyLmRpc3Bvc2UoKX19fSw0MzQ4OihlLHQsaSk9PntPYmplY3Qu"
    "ZGVmaW5lUHJvcGVydHkodCwiX19lc01vZHVsZSIse3ZhbHVlOiEwfSksdC5JbnN0YW50aWF0aW9uU2VydmljZT10LlNlcnZpY2VDb2xsZWN0aW9uPXZvaWQg"
    "MDtjb25zdCBzPWkoMjU4NSkscj1pKDgzNDMpO2NsYXNzIG57Y29uc3RydWN0b3IoLi4uZSl7dGhpcy5fZW50cmllcz1uZXcgTWFwO2Zvcihjb25zdFt0LGld"
    "b2YgZSl0aGlzLnNldCh0LGkpfXNldChlLHQpe2NvbnN0IGk9dGhpcy5fZW50cmllcy5nZXQoZSk7cmV0dXJuIHRoaXMuX2VudHJpZXMuc2V0KGUsdCksaX1m"
    "b3JFYWNoKGUpe2Zvcihjb25zdFt0LGldb2YgdGhpcy5fZW50cmllcy5lbnRyaWVzKCkpZSh0LGkpfWhhcyhlKXtyZXR1cm4gdGhpcy5fZW50cmllcy5oYXMo"
    "ZSl9Z2V0KGUpe3JldHVybiB0aGlzLl9lbnRyaWVzLmdldChlKX19dC5TZXJ2aWNlQ29sbGVjdGlvbj1uLHQuSW5zdGFudGlhdGlvblNlcnZpY2U9Y2xhc3N7"
    "Y29uc3RydWN0b3IoKXt0aGlzLl9zZXJ2aWNlcz1uZXcgbix0aGlzLl9zZXJ2aWNlcy5zZXQocy5JSW5zdGFudGlhdGlvblNlcnZpY2UsdGhpcyl9c2V0U2Vy"
    "dmljZShlLHQpe3RoaXMuX3NlcnZpY2VzLnNldChlLHQpfWdldFNlcnZpY2UoZSl7cmV0dXJuIHRoaXMuX3NlcnZpY2VzLmdldChlKX1jcmVhdGVJbnN0YW5j"
    "ZShlLC4uLnQpe2NvbnN0IGk9KDAsci5nZXRTZXJ2aWNlRGVwZW5kZW5jaWVzKShlKS5zb3J0KCgoZSx0KT0+ZS5pbmRleC10LmluZGV4KSkscz1bXTtmb3Io"
    "Y29uc3QgdCBvZiBpKXtjb25zdCBpPXRoaXMuX3NlcnZpY2VzLmdldCh0LmlkKTtpZighaSl0aHJvdyBuZXcgRXJyb3IoYFtjcmVhdGVJbnN0YW5jZV0gJHtl"
    "Lm5hbWV9IGRlcGVuZHMgb24gVU5LTk9XTiBzZXJ2aWNlICR7dC5pZH0uYCk7cy5wdXNoKGkpfWNvbnN0IG49aS5sZW5ndGg+MD9pWzBdLmluZGV4OnQubGVu"
    "Z3RoO2lmKHQubGVuZ3RoIT09bil0aHJvdyBuZXcgRXJyb3IoYFtjcmVhdGVJbnN0YW5jZV0gRmlyc3Qgc2VydmljZSBkZXBlbmRlbmN5IG9mICR7ZS5uYW1l"
    "fSBhdCBwb3NpdGlvbiAke24rMX0gY29uZmxpY3RzIHdpdGggJHt0Lmxlbmd0aH0gc3RhdGljIGFyZ3VtZW50c2ApO3JldHVybiBuZXcgZSguLi5bLi4udCwu"
    "Li5zXSl9fX0sNzg2NjpmdW5jdGlvbihlLHQsaSl7dmFyIHM9dGhpcyYmdGhpcy5fX2RlY29yYXRlfHxmdW5jdGlvbihlLHQsaSxzKXt2YXIgcixuPWFyZ3Vt"
    "ZW50cy5sZW5ndGgsbz1uPDM/dDpudWxsPT09cz9zPU9iamVjdC5nZXRPd25Qcm9wZXJ0eURlc2NyaXB0b3IodCxpKTpzO2lmKCJvYmplY3QiPT10eXBlb2Yg"
    "UmVmbGVjdCYmImZ1bmN0aW9uIj09dHlwZW9mIFJlZmxlY3QuZGVjb3JhdGUpbz1SZWZsZWN0LmRlY29yYXRlKGUsdCxpLHMpO2Vsc2UgZm9yKHZhciBhPWUu"
    "bGVuZ3RoLTE7YT49MDthLS0pKHI9ZVthXSkmJihvPShuPDM/cihvKTpuPjM/cih0LGksbyk6cih0LGkpKXx8byk7cmV0dXJuIG4+MyYmbyYmT2JqZWN0LmRl"
    "ZmluZVByb3BlcnR5KHQsaSxvKSxvfSxyPXRoaXMmJnRoaXMuX19wYXJhbXx8ZnVuY3Rpb24oZSx0KXtyZXR1cm4gZnVuY3Rpb24oaSxzKXt0KGkscyxlKX19"
    "O09iamVjdC5kZWZpbmVQcm9wZXJ0eSh0LCJfX2VzTW9kdWxlIix7dmFsdWU6ITB9KSx0LnRyYWNlQ2FsbD10LnNldFRyYWNlTG9nZ2VyPXQuTG9nU2Vydmlj"
    "ZT12b2lkIDA7Y29uc3Qgbj1pKDg0NCksbz1pKDI1ODUpLGE9e3RyYWNlOm8uTG9nTGV2ZWxFbnVtLlRSQUNFLGRlYnVnOm8uTG9nTGV2ZWxFbnVtLkRFQlVH"
    "LGluZm86by5Mb2dMZXZlbEVudW0uSU5GTyx3YXJuOm8uTG9nTGV2ZWxFbnVtLldBUk4sZXJyb3I6by5Mb2dMZXZlbEVudW0uRVJST1Isb2ZmOm8uTG9nTGV2"
    "ZWxFbnVtLk9GRn07bGV0IGgsYz10LkxvZ1NlcnZpY2U9Y2xhc3MgZXh0ZW5kcyBuLkRpc3Bvc2FibGV7Z2V0IGxvZ0xldmVsKCl7cmV0dXJuIHRoaXMuX2xv"
    "Z0xldmVsfWNvbnN0cnVjdG9yKGUpe3N1cGVyKCksdGhpcy5fb3B0aW9uc1NlcnZpY2U9ZSx0aGlzLl9sb2dMZXZlbD1vLkxvZ0xldmVsRW51bS5PRkYsdGhp"
    "cy5fdXBkYXRlTG9nTGV2ZWwoKSx0aGlzLnJlZ2lzdGVyKHRoaXMuX29wdGlvbnNTZXJ2aWNlLm9uU3BlY2lmaWNPcHRpb25DaGFuZ2UoImxvZ0xldmVsIiwo"
    "KCk9PnRoaXMuX3VwZGF0ZUxvZ0xldmVsKCkpKSksaD10aGlzfV91cGRhdGVMb2dMZXZlbCgpe3RoaXMuX2xvZ0xldmVsPWFbdGhpcy5fb3B0aW9uc1NlcnZp"
    "Y2UucmF3T3B0aW9ucy5sb2dMZXZlbF19X2V2YWxMYXp5T3B0aW9uYWxQYXJhbXMoZSl7Zm9yKGxldCB0PTA7dDxlLmxlbmd0aDt0KyspImZ1bmN0aW9uIj09"
    "dHlwZW9mIGVbdF0mJihlW3RdPWVbdF0oKSl9X2xvZyhlLHQsaSl7dGhpcy5fZXZhbExhenlPcHRpb25hbFBhcmFtcyhpKSxlLmNhbGwoY29uc29sZSwodGhp"
    "cy5fb3B0aW9uc1NlcnZpY2Uub3B0aW9ucy5sb2dnZXI/IiI6Inh0ZXJtLmpzOiAiKSt0LC4uLmkpfXRyYWNlKGUsLi4udCl7dmFyIGksczt0aGlzLl9sb2dM"
    "ZXZlbDw9by5Mb2dMZXZlbEVudW0uVFJBQ0UmJnRoaXMuX2xvZyhudWxsIT09KHM9bnVsbD09PShpPXRoaXMuX29wdGlvbnNTZXJ2aWNlLm9wdGlvbnMubG9n"
    "Z2VyKXx8dm9pZCAwPT09aT92b2lkIDA6aS50cmFjZS5iaW5kKHRoaXMuX29wdGlvbnNTZXJ2aWNlLm9wdGlvbnMubG9nZ2VyKSkmJnZvaWQgMCE9PXM/czpj"
    "b25zb2xlLmxvZyxlLHQpfWRlYnVnKGUsLi4udCl7dmFyIGksczt0aGlzLl9sb2dMZXZlbDw9by5Mb2dMZXZlbEVudW0uREVCVUcmJnRoaXMuX2xvZyhudWxs"
    "IT09KHM9bnVsbD09PShpPXRoaXMuX29wdGlvbnNTZXJ2aWNlLm9wdGlvbnMubG9nZ2VyKXx8dm9pZCAwPT09aT92b2lkIDA6aS5kZWJ1Zy5iaW5kKHRoaXMu"
    "X29wdGlvbnNTZXJ2aWNlLm9wdGlvbnMubG9nZ2VyKSkmJnZvaWQgMCE9PXM/czpjb25zb2xlLmxvZyxlLHQpfWluZm8oZSwuLi50KXt2YXIgaSxzO3RoaXMu"
    "X2xvZ0xldmVsPD1vLkxvZ0xldmVsRW51bS5JTkZPJiZ0aGlzLl9sb2cobnVsbCE9PShzPW51bGw9PT0oaT10aGlzLl9vcHRpb25zU2VydmljZS5vcHRpb25z"
    "LmxvZ2dlcil8fHZvaWQgMD09PWk/dm9pZCAwOmkuaW5mby5iaW5kKHRoaXMuX29wdGlvbnNTZXJ2aWNlLm9wdGlvbnMubG9nZ2VyKSkmJnZvaWQgMCE9PXM/"
    "czpjb25zb2xlLmluZm8sZSx0KX13YXJuKGUsLi4udCl7dmFyIGksczt0aGlzLl9sb2dMZXZlbDw9by5Mb2dMZXZlbEVudW0uV0FSTiYmdGhpcy5fbG9nKG51"
    "bGwhPT0ocz1udWxsPT09KGk9dGhpcy5fb3B0aW9uc1NlcnZpY2Uub3B0aW9ucy5sb2dnZXIpfHx2b2lkIDA9PT1pP3ZvaWQgMDppLndhcm4uYmluZCh0aGlz"
    "Ll9vcHRpb25zU2VydmljZS5vcHRpb25zLmxvZ2dlcikpJiZ2b2lkIDAhPT1zP3M6Y29uc29sZS53YXJuLGUsdCl9ZXJyb3IoZSwuLi50KXt2YXIgaSxzO3Ro"
    "aXMuX2xvZ0xldmVsPD1vLkxvZ0xldmVsRW51bS5FUlJPUiYmdGhpcy5fbG9nKG51bGwhPT0ocz1udWxsPT09KGk9dGhpcy5fb3B0aW9uc1NlcnZpY2Uub3B0"
    "aW9ucy5sb2dnZXIpfHx2b2lkIDA9PT1pP3ZvaWQgMDppLmVycm9yLmJpbmQodGhpcy5fb3B0aW9uc1NlcnZpY2Uub3B0aW9ucy5sb2dnZXIpKSYmdm9pZCAw"
    "IT09cz9zOmNvbnNvbGUuZXJyb3IsZSx0KX19O3QuTG9nU2VydmljZT1jPXMoW3IoMCxvLklPcHRpb25zU2VydmljZSldLGMpLHQuc2V0VHJhY2VMb2dnZXI9"
    "ZnVuY3Rpb24oZSl7aD1lfSx0LnRyYWNlQ2FsbD1mdW5jdGlvbihlLHQsaSl7aWYoImZ1bmN0aW9uIiE9dHlwZW9mIGkudmFsdWUpdGhyb3cgbmV3IEVycm9y"
    "KCJub3Qgc3VwcG9ydGVkIik7Y29uc3Qgcz1pLnZhbHVlO2kudmFsdWU9ZnVuY3Rpb24oLi4uZSl7aWYoaC5sb2dMZXZlbCE9PW8uTG9nTGV2ZWxFbnVtLlRS"
    "QUNFKXJldHVybiBzLmFwcGx5KHRoaXMsZSk7aC50cmFjZShgR2x5cGhSZW5kZXJlciMke3MubmFtZX0oJHtlLm1hcCgoZT0+SlNPTi5zdHJpbmdpZnkoZSkp"
    "KS5qb2luKCIsICIpfSlgKTtjb25zdCB0PXMuYXBwbHkodGhpcyxlKTtyZXR1cm4gaC50cmFjZShgR2x5cGhSZW5kZXJlciMke3MubmFtZX0gcmV0dXJuYCx0"
    "KSx0fX19LDczMDI6KGUsdCxpKT0+e09iamVjdC5kZWZpbmVQcm9wZXJ0eSh0LCJfX2VzTW9kdWxlIix7dmFsdWU6ITB9KSx0Lk9wdGlvbnNTZXJ2aWNlPXQu"
    "REVGQVVMVF9PUFRJT05TPXZvaWQgMDtjb25zdCBzPWkoODQ2MCkscj1pKDg0NCksbj1pKDYxMTQpO3QuREVGQVVMVF9PUFRJT05TPXtjb2xzOjgwLHJvd3M6"
    "MjQsY3Vyc29yQmxpbms6ITEsY3Vyc29yU3R5bGU6ImJsb2NrIixjdXJzb3JXaWR0aDoxLGN1cnNvckluYWN0aXZlU3R5bGU6Im91dGxpbmUiLGN1c3RvbUds"
    "eXBoczohMCxkcmF3Qm9sZFRleHRJbkJyaWdodENvbG9yczohMCxmYXN0U2Nyb2xsTW9kaWZpZXI6ImFsdCIsZmFzdFNjcm9sbFNlbnNpdGl2aXR5OjUsZm9u"
    "dEZhbWlseToiY291cmllci1uZXcsIGNvdXJpZXIsIG1vbm9zcGFjZSIsZm9udFNpemU6MTUsZm9udFdlaWdodDoibm9ybWFsIixmb250V2VpZ2h0Qm9sZDoi"
    "Ym9sZCIsaWdub3JlQnJhY2tldGVkUGFzdGVNb2RlOiExLGxpbmVIZWlnaHQ6MSxsZXR0ZXJTcGFjaW5nOjAsbGlua0hhbmRsZXI6bnVsbCxsb2dMZXZlbDoi"
    "aW5mbyIsbG9nZ2VyOm51bGwsc2Nyb2xsYmFjazoxZTMsc2Nyb2xsT25Vc2VySW5wdXQ6ITAsc2Nyb2xsU2Vuc2l0aXZpdHk6MSxzY3JlZW5SZWFkZXJNb2Rl"
    "OiExLHNtb290aFNjcm9sbER1cmF0aW9uOjAsbWFjT3B0aW9uSXNNZXRhOiExLG1hY09wdGlvbkNsaWNrRm9yY2VzU2VsZWN0aW9uOiExLG1pbmltdW1Db250"
    "cmFzdFJhdGlvOjEsZGlzYWJsZVN0ZGluOiExLGFsbG93UHJvcG9zZWRBcGk6ITEsYWxsb3dUcmFuc3BhcmVuY3k6ITEsdGFiU3RvcFdpZHRoOjgsdGhlbWU6"
    "e30scmlnaHRDbGlja1NlbGVjdHNXb3JkOm4uaXNNYWMsd2luZG93T3B0aW9uczp7fSx3aW5kb3dzTW9kZTohMSx3aW5kb3dzUHR5Ont9LHdvcmRTZXBhcmF0"
    "b3I6IiAoKVtde30nLFwiYCIsYWx0Q2xpY2tNb3Zlc0N1cnNvcjohMCxjb252ZXJ0RW9sOiExLHRlcm1OYW1lOiJ4dGVybSIsY2FuY2VsRXZlbnRzOiExLG92"
    "ZXJ2aWV3UnVsZXJXaWR0aDowfTtjb25zdCBvPVsibm9ybWFsIiwiYm9sZCIsIjEwMCIsIjIwMCIsIjMwMCIsIjQwMCIsIjUwMCIsIjYwMCIsIjcwMCIsIjgw"
    "MCIsIjkwMCJdO2NsYXNzIGEgZXh0ZW5kcyByLkRpc3Bvc2FibGV7Y29uc3RydWN0b3IoZSl7c3VwZXIoKSx0aGlzLl9vbk9wdGlvbkNoYW5nZT10aGlzLnJl"
    "Z2lzdGVyKG5ldyBzLkV2ZW50RW1pdHRlciksdGhpcy5vbk9wdGlvbkNoYW5nZT10aGlzLl9vbk9wdGlvbkNoYW5nZS5ldmVudDtjb25zdCBpPU9iamVjdC5h"
    "c3NpZ24oe30sdC5ERUZBVUxUX09QVElPTlMpO2Zvcihjb25zdCB0IGluIGUpaWYodCBpbiBpKXRyeXtjb25zdCBzPWVbdF07aVt0XT10aGlzLl9zYW5pdGl6"
    "ZUFuZFZhbGlkYXRlT3B0aW9uKHQscyl9Y2F0Y2goZSl7Y29uc29sZS5lcnJvcihlKX10aGlzLnJhd09wdGlvbnM9aSx0aGlzLm9wdGlvbnM9T2JqZWN0LmFz"
    "c2lnbih7fSxpKSx0aGlzLl9zZXR1cE9wdGlvbnMoKX1vblNwZWNpZmljT3B0aW9uQ2hhbmdlKGUsdCl7cmV0dXJuIHRoaXMub25PcHRpb25DaGFuZ2UoKGk9"
    "PntpPT09ZSYmdCh0aGlzLnJhd09wdGlvbnNbZV0pfSkpfW9uTXVsdGlwbGVPcHRpb25DaGFuZ2UoZSx0KXtyZXR1cm4gdGhpcy5vbk9wdGlvbkNoYW5nZSgo"
    "aT0+ey0xIT09ZS5pbmRleE9mKGkpJiZ0KCl9KSl9X3NldHVwT3B0aW9ucygpe2NvbnN0IGU9ZT0+e2lmKCEoZSBpbiB0LkRFRkFVTFRfT1BUSU9OUykpdGhy"
    "b3cgbmV3IEVycm9yKGBObyBvcHRpb24gd2l0aCBrZXkgIiR7ZX0iYCk7cmV0dXJuIHRoaXMucmF3T3B0aW9uc1tlXX0saT0oZSxpKT0+e2lmKCEoZSBpbiB0"
    "LkRFRkFVTFRfT1BUSU9OUykpdGhyb3cgbmV3IEVycm9yKGBObyBvcHRpb24gd2l0aCBrZXkgIiR7ZX0iYCk7aT10aGlzLl9zYW5pdGl6ZUFuZFZhbGlkYXRl"
    "T3B0aW9uKGUsaSksdGhpcy5yYXdPcHRpb25zW2VdIT09aSYmKHRoaXMucmF3T3B0aW9uc1tlXT1pLHRoaXMuX29uT3B0aW9uQ2hhbmdlLmZpcmUoZSkpfTtm"
    "b3IoY29uc3QgdCBpbiB0aGlzLnJhd09wdGlvbnMpe2NvbnN0IHM9e2dldDplLmJpbmQodGhpcyx0KSxzZXQ6aS5iaW5kKHRoaXMsdCl9O09iamVjdC5kZWZp"
    "bmVQcm9wZXJ0eSh0aGlzLm9wdGlvbnMsdCxzKX19X3Nhbml0aXplQW5kVmFsaWRhdGVPcHRpb24oZSxpKXtzd2l0Y2goZSl7Y2FzZSJjdXJzb3JTdHlsZSI6"
    "aWYoaXx8KGk9dC5ERUZBVUxUX09QVElPTlNbZV0pLCFmdW5jdGlvbihlKXtyZXR1cm4iYmxvY2siPT09ZXx8InVuZGVybGluZSI9PT1lfHwiYmFyIj09PWV9"
    "KGkpKXRocm93IG5ldyBFcnJvcihgIiR7aX0iIGlzIG5vdCBhIHZhbGlkIHZhbHVlIGZvciAke2V9YCk7YnJlYWs7Y2FzZSJ3b3JkU2VwYXJhdG9yIjppfHwo"
    "aT10LkRFRkFVTFRfT1BUSU9OU1tlXSk7YnJlYWs7Y2FzZSJmb250V2VpZ2h0IjpjYXNlImZvbnRXZWlnaHRCb2xkIjppZigibnVtYmVyIj09dHlwZW9mIGkm"
    "JjE8PWkmJmk8PTFlMylicmVhaztpPW8uaW5jbHVkZXMoaSk/aTp0LkRFRkFVTFRfT1BUSU9OU1tlXTticmVhaztjYXNlImN1cnNvcldpZHRoIjppPU1hdGgu"
    "Zmxvb3IoaSk7Y2FzZSJsaW5lSGVpZ2h0IjpjYXNlInRhYlN0b3BXaWR0aCI6aWYoaTwxKXRocm93IG5ldyBFcnJvcihgJHtlfSBjYW5ub3QgYmUgbGVzcyB0"
    "aGFuIDEsIHZhbHVlOiAke2l9YCk7YnJlYWs7Y2FzZSJtaW5pbXVtQ29udHJhc3RSYXRpbyI6aT1NYXRoLm1heCgxLE1hdGgubWluKDIxLE1hdGgucm91bmQo"
    "MTAqaSkvMTApKTticmVhaztjYXNlInNjcm9sbGJhY2siOmlmKChpPU1hdGgubWluKGksNDI5NDk2NzI5NSkpPDApdGhyb3cgbmV3IEVycm9yKGAke2V9IGNh"
    "bm5vdCBiZSBsZXNzIHRoYW4gMCwgdmFsdWU6ICR7aX1gKTticmVhaztjYXNlImZhc3RTY3JvbGxTZW5zaXRpdml0eSI6Y2FzZSJzY3JvbGxTZW5zaXRpdml0"
    "eSI6aWYoaTw9MCl0aHJvdyBuZXcgRXJyb3IoYCR7ZX0gY2Fubm90IGJlIGxlc3MgdGhhbiBvciBlcXVhbCB0byAwLCB2YWx1ZTogJHtpfWApO2JyZWFrO2Nh"
    "c2Uicm93cyI6Y2FzZSJjb2xzIjppZighaSYmMCE9PWkpdGhyb3cgbmV3IEVycm9yKGAke2V9IG11c3QgYmUgbnVtZXJpYywgdmFsdWU6ICR7aX1gKTticmVh"
    "aztjYXNlIndpbmRvd3NQdHkiOmk9bnVsbCE9aT9pOnt9fXJldHVybiBpfX10Lk9wdGlvbnNTZXJ2aWNlPWF9LDI2NjA6ZnVuY3Rpb24oZSx0LGkpe3ZhciBz"
    "PXRoaXMmJnRoaXMuX19kZWNvcmF0ZXx8ZnVuY3Rpb24oZSx0LGkscyl7dmFyIHIsbj1hcmd1bWVudHMubGVuZ3RoLG89bjwzP3Q6bnVsbD09PXM/cz1PYmpl"
    "Y3QuZ2V0T3duUHJvcGVydHlEZXNjcmlwdG9yKHQsaSk6cztpZigib2JqZWN0Ij09dHlwZW9mIFJlZmxlY3QmJiJmdW5jdGlvbiI9PXR5cGVvZiBSZWZsZWN0"
    "LmRlY29yYXRlKW89UmVmbGVjdC5kZWNvcmF0ZShlLHQsaSxzKTtlbHNlIGZvcih2YXIgYT1lLmxlbmd0aC0xO2E+PTA7YS0tKShyPWVbYV0pJiYobz0objwz"
    "P3Iobyk6bj4zP3IodCxpLG8pOnIodCxpKSl8fG8pO3JldHVybiBuPjMmJm8mJk9iamVjdC5kZWZpbmVQcm9wZXJ0eSh0LGksbyksb30scj10aGlzJiZ0aGlz"
    "Ll9fcGFyYW18fGZ1bmN0aW9uKGUsdCl7cmV0dXJuIGZ1bmN0aW9uKGkscyl7dChpLHMsZSl9fTtPYmplY3QuZGVmaW5lUHJvcGVydHkodCwiX19lc01vZHVs"
    "ZSIse3ZhbHVlOiEwfSksdC5Pc2NMaW5rU2VydmljZT12b2lkIDA7Y29uc3Qgbj1pKDI1ODUpO2xldCBvPXQuT3NjTGlua1NlcnZpY2U9Y2xhc3N7Y29uc3Ry"
    "dWN0b3IoZSl7dGhpcy5fYnVmZmVyU2VydmljZT1lLHRoaXMuX25leHRJZD0xLHRoaXMuX2VudHJpZXNXaXRoSWQ9bmV3IE1hcCx0aGlzLl9kYXRhQnlMaW5r"
    "SWQ9bmV3IE1hcH1yZWdpc3RlckxpbmsoZSl7Y29uc3QgdD10aGlzLl9idWZmZXJTZXJ2aWNlLmJ1ZmZlcjtpZih2b2lkIDA9PT1lLmlkKXtjb25zdCBpPXQu"
    "YWRkTWFya2VyKHQueWJhc2UrdC55KSxzPXtkYXRhOmUsaWQ6dGhpcy5fbmV4dElkKyssbGluZXM6W2ldfTtyZXR1cm4gaS5vbkRpc3Bvc2UoKCgpPT50aGlz"
    "Ll9yZW1vdmVNYXJrZXJGcm9tTGluayhzLGkpKSksdGhpcy5fZGF0YUJ5TGlua0lkLnNldChzLmlkLHMpLHMuaWR9Y29uc3QgaT1lLHM9dGhpcy5fZ2V0RW50"
    "cnlJZEtleShpKSxyPXRoaXMuX2VudHJpZXNXaXRoSWQuZ2V0KHMpO2lmKHIpcmV0dXJuIHRoaXMuYWRkTGluZVRvTGluayhyLmlkLHQueWJhc2UrdC55KSxy"
    "LmlkO2NvbnN0IG49dC5hZGRNYXJrZXIodC55YmFzZSt0LnkpLG89e2lkOnRoaXMuX25leHRJZCsrLGtleTp0aGlzLl9nZXRFbnRyeUlkS2V5KGkpLGRhdGE6"
    "aSxsaW5lczpbbl19O3JldHVybiBuLm9uRGlzcG9zZSgoKCk9PnRoaXMuX3JlbW92ZU1hcmtlckZyb21MaW5rKG8sbikpKSx0aGlzLl9lbnRyaWVzV2l0aElk"
    "LnNldChvLmtleSxvKSx0aGlzLl9kYXRhQnlMaW5rSWQuc2V0KG8uaWQsbyksby5pZH1hZGRMaW5lVG9MaW5rKGUsdCl7Y29uc3QgaT10aGlzLl9kYXRhQnlM"
    "aW5rSWQuZ2V0KGUpO2lmKGkmJmkubGluZXMuZXZlcnkoKGU9PmUubGluZSE9PXQpKSl7Y29uc3QgZT10aGlzLl9idWZmZXJTZXJ2aWNlLmJ1ZmZlci5hZGRN"
    "YXJrZXIodCk7aS5saW5lcy5wdXNoKGUpLGUub25EaXNwb3NlKCgoKT0+dGhpcy5fcmVtb3ZlTWFya2VyRnJvbUxpbmsoaSxlKSkpfX1nZXRMaW5rRGF0YShl"
    "KXt2YXIgdDtyZXR1cm4gbnVsbD09PSh0PXRoaXMuX2RhdGFCeUxpbmtJZC5nZXQoZSkpfHx2b2lkIDA9PT10P3ZvaWQgMDp0LmRhdGF9X2dldEVudHJ5SWRL"
    "ZXkoZSl7cmV0dXJuYCR7ZS5pZH07OyR7ZS51cml9YH1fcmVtb3ZlTWFya2VyRnJvbUxpbmsoZSx0KXtjb25zdCBpPWUubGluZXMuaW5kZXhPZih0KTstMSE9"
    "PWkmJihlLmxpbmVzLnNwbGljZShpLDEpLDA9PT1lLmxpbmVzLmxlbmd0aCYmKHZvaWQgMCE9PWUuZGF0YS5pZCYmdGhpcy5fZW50cmllc1dpdGhJZC5kZWxl"
    "dGUoZS5rZXkpLHRoaXMuX2RhdGFCeUxpbmtJZC5kZWxldGUoZS5pZCkpKX19O3QuT3NjTGlua1NlcnZpY2U9bz1zKFtyKDAsbi5JQnVmZmVyU2VydmljZSld"
    "LG8pfSw4MzQzOihlLHQpPT57T2JqZWN0LmRlZmluZVByb3BlcnR5KHQsIl9fZXNNb2R1bGUiLHt2YWx1ZTohMH0pLHQuY3JlYXRlRGVjb3JhdG9yPXQuZ2V0"
    "U2VydmljZURlcGVuZGVuY2llcz10LnNlcnZpY2VSZWdpc3RyeT12b2lkIDA7Y29uc3QgaT0iZGkkdGFyZ2V0IixzPSJkaSRkZXBlbmRlbmNpZXMiO3Quc2Vy"
    "dmljZVJlZ2lzdHJ5PW5ldyBNYXAsdC5nZXRTZXJ2aWNlRGVwZW5kZW5jaWVzPWZ1bmN0aW9uKGUpe3JldHVybiBlW3NdfHxbXX0sdC5jcmVhdGVEZWNvcmF0"
    "b3I9ZnVuY3Rpb24oZSl7aWYodC5zZXJ2aWNlUmVnaXN0cnkuaGFzKGUpKXJldHVybiB0LnNlcnZpY2VSZWdpc3RyeS5nZXQoZSk7Y29uc3Qgcj1mdW5jdGlv"
    "bihlLHQsbil7aWYoMyE9PWFyZ3VtZW50cy5sZW5ndGgpdGhyb3cgbmV3IEVycm9yKCJASVNlcnZpY2VOYW1lLWRlY29yYXRvciBjYW4gb25seSBiZSB1c2Vk"
    "IHRvIGRlY29yYXRlIGEgcGFyYW1ldGVyIik7IWZ1bmN0aW9uKGUsdCxyKXt0W2ldPT09dD90W3NdLnB1c2goe2lkOmUsaW5kZXg6cn0pOih0W3NdPVt7aWQ6"
    "ZSxpbmRleDpyfV0sdFtpXT10KX0ocixlLG4pfTtyZXR1cm4gci50b1N0cmluZz0oKT0+ZSx0LnNlcnZpY2VSZWdpc3RyeS5zZXQoZSxyKSxyfX0sMjU4NToo"
    "ZSx0LGkpPT57T2JqZWN0LmRlZmluZVByb3BlcnR5KHQsIl9fZXNNb2R1bGUiLHt2YWx1ZTohMH0pLHQuSURlY29yYXRpb25TZXJ2aWNlPXQuSVVuaWNvZGVT"
    "ZXJ2aWNlPXQuSU9zY0xpbmtTZXJ2aWNlPXQuSU9wdGlvbnNTZXJ2aWNlPXQuSUxvZ1NlcnZpY2U9dC5Mb2dMZXZlbEVudW09dC5JSW5zdGFudGlhdGlvblNl"
    "cnZpY2U9dC5JQ2hhcnNldFNlcnZpY2U9dC5JQ29yZVNlcnZpY2U9dC5JQ29yZU1vdXNlU2VydmljZT10LklCdWZmZXJTZXJ2aWNlPXZvaWQgMDtjb25zdCBz"
    "PWkoODM0Myk7dmFyIHI7dC5JQnVmZmVyU2VydmljZT0oMCxzLmNyZWF0ZURlY29yYXRvcikoIkJ1ZmZlclNlcnZpY2UiKSx0LklDb3JlTW91c2VTZXJ2aWNl"
    "PSgwLHMuY3JlYXRlRGVjb3JhdG9yKSgiQ29yZU1vdXNlU2VydmljZSIpLHQuSUNvcmVTZXJ2aWNlPSgwLHMuY3JlYXRlRGVjb3JhdG9yKSgiQ29yZVNlcnZp"
    "Y2UiKSx0LklDaGFyc2V0U2VydmljZT0oMCxzLmNyZWF0ZURlY29yYXRvcikoIkNoYXJzZXRTZXJ2aWNlIiksdC5JSW5zdGFudGlhdGlvblNlcnZpY2U9KDAs"
    "cy5jcmVhdGVEZWNvcmF0b3IpKCJJbnN0YW50aWF0aW9uU2VydmljZSIpLGZ1bmN0aW9uKGUpe2VbZS5UUkFDRT0wXT0iVFJBQ0UiLGVbZS5ERUJVRz0xXT0i"
    "REVCVUciLGVbZS5JTkZPPTJdPSJJTkZPIixlW2UuV0FSTj0zXT0iV0FSTiIsZVtlLkVSUk9SPTRdPSJFUlJPUiIsZVtlLk9GRj01XT0iT0ZGIn0ocnx8KHQu"
    "TG9nTGV2ZWxFbnVtPXI9e30pKSx0LklMb2dTZXJ2aWNlPSgwLHMuY3JlYXRlRGVjb3JhdG9yKSgiTG9nU2VydmljZSIpLHQuSU9wdGlvbnNTZXJ2aWNlPSgw"
    "LHMuY3JlYXRlRGVjb3JhdG9yKSgiT3B0aW9uc1NlcnZpY2UiKSx0LklPc2NMaW5rU2VydmljZT0oMCxzLmNyZWF0ZURlY29yYXRvcikoIk9zY0xpbmtTZXJ2"
    "aWNlIiksdC5JVW5pY29kZVNlcnZpY2U9KDAscy5jcmVhdGVEZWNvcmF0b3IpKCJVbmljb2RlU2VydmljZSIpLHQuSURlY29yYXRpb25TZXJ2aWNlPSgwLHMu"
    "Y3JlYXRlRGVjb3JhdG9yKSgiRGVjb3JhdGlvblNlcnZpY2UiKX0sMTQ4MDooZSx0LGkpPT57T2JqZWN0LmRlZmluZVByb3BlcnR5KHQsIl9fZXNNb2R1bGUi"
    "LHt2YWx1ZTohMH0pLHQuVW5pY29kZVNlcnZpY2U9dm9pZCAwO2NvbnN0IHM9aSg4NDYwKSxyPWkoMjI1KTt0LlVuaWNvZGVTZXJ2aWNlPWNsYXNze2NvbnN0"
    "cnVjdG9yKCl7dGhpcy5fcHJvdmlkZXJzPU9iamVjdC5jcmVhdGUobnVsbCksdGhpcy5fYWN0aXZlPSIiLHRoaXMuX29uQ2hhbmdlPW5ldyBzLkV2ZW50RW1p"
    "dHRlcix0aGlzLm9uQ2hhbmdlPXRoaXMuX29uQ2hhbmdlLmV2ZW50O2NvbnN0IGU9bmV3IHIuVW5pY29kZVY2O3RoaXMucmVnaXN0ZXIoZSksdGhpcy5fYWN0"
    "aXZlPWUudmVyc2lvbix0aGlzLl9hY3RpdmVQcm92aWRlcj1lfWRpc3Bvc2UoKXt0aGlzLl9vbkNoYW5nZS5kaXNwb3NlKCl9Z2V0IHZlcnNpb25zKCl7cmV0"
    "dXJuIE9iamVjdC5rZXlzKHRoaXMuX3Byb3ZpZGVycyl9Z2V0IGFjdGl2ZVZlcnNpb24oKXtyZXR1cm4gdGhpcy5fYWN0aXZlfXNldCBhY3RpdmVWZXJzaW9u"
    "KGUpe2lmKCF0aGlzLl9wcm92aWRlcnNbZV0pdGhyb3cgbmV3IEVycm9yKGB1bmtub3duIFVuaWNvZGUgdmVyc2lvbiAiJHtlfSJgKTt0aGlzLl9hY3RpdmU9"
    "ZSx0aGlzLl9hY3RpdmVQcm92aWRlcj10aGlzLl9wcm92aWRlcnNbZV0sdGhpcy5fb25DaGFuZ2UuZmlyZShlKX1yZWdpc3RlcihlKXt0aGlzLl9wcm92aWRl"
    "cnNbZS52ZXJzaW9uXT1lfXdjd2lkdGgoZSl7cmV0dXJuIHRoaXMuX2FjdGl2ZVByb3ZpZGVyLndjd2lkdGgoZSl9Z2V0U3RyaW5nQ2VsbFdpZHRoKGUpe2xl"
    "dCB0PTA7Y29uc3QgaT1lLmxlbmd0aDtmb3IobGV0IHM9MDtzPGk7KytzKXtsZXQgcj1lLmNoYXJDb2RlQXQocyk7aWYoNTUyOTY8PXImJnI8PTU2MzE5KXtp"
    "ZigrK3M+PWkpcmV0dXJuIHQrdGhpcy53Y3dpZHRoKHIpO2NvbnN0IG49ZS5jaGFyQ29kZUF0KHMpOzU2MzIwPD1uJiZuPD01NzM0Mz9yPTEwMjQqKHItNTUy"
    "OTYpK24tNTYzMjArNjU1MzY6dCs9dGhpcy53Y3dpZHRoKG4pfXQrPXRoaXMud2N3aWR0aChyKX1yZXR1cm4gdH19fX0sdD17fTtmdW5jdGlvbiBpKHMpe3Zh"
    "ciByPXRbc107aWYodm9pZCAwIT09cilyZXR1cm4gci5leHBvcnRzO3ZhciBuPXRbc109e2V4cG9ydHM6e319O3JldHVybiBlW3NdLmNhbGwobi5leHBvcnRz"
    "LG4sbi5leHBvcnRzLGkpLG4uZXhwb3J0c312YXIgcz17fTtyZXR1cm4oKCk9Pnt2YXIgZT1zO09iamVjdC5kZWZpbmVQcm9wZXJ0eShlLCJfX2VzTW9kdWxl"
    "Iix7dmFsdWU6ITB9KSxlLlRlcm1pbmFsPXZvaWQgMDtjb25zdCB0PWkoOTA0Mikscj1pKDMyMzYpLG49aSg4NDQpLG89aSg1NzQxKSxhPWkoODI4NSksaD1p"
    "KDc5NzUpLGM9aSg3MDkwKSxsPVsiY29scyIsInJvd3MiXTtjbGFzcyBkIGV4dGVuZHMgbi5EaXNwb3NhYmxle2NvbnN0cnVjdG9yKGUpe3N1cGVyKCksdGhp"
    "cy5fY29yZT10aGlzLnJlZ2lzdGVyKG5ldyByLlRlcm1pbmFsKGUpKSx0aGlzLl9hZGRvbk1hbmFnZXI9dGhpcy5yZWdpc3RlcihuZXcgby5BZGRvbk1hbmFn"
    "ZXIpLHRoaXMuX3B1YmxpY09wdGlvbnM9T2JqZWN0LmFzc2lnbih7fSx0aGlzLl9jb3JlLm9wdGlvbnMpO2NvbnN0IHQ9ZT0+dGhpcy5fY29yZS5vcHRpb25z"
    "W2VdLGk9KGUsdCk9Pnt0aGlzLl9jaGVja1JlYWRvbmx5T3B0aW9ucyhlKSx0aGlzLl9jb3JlLm9wdGlvbnNbZV09dH07Zm9yKGNvbnN0IGUgaW4gdGhpcy5f"
    "Y29yZS5vcHRpb25zKXtjb25zdCBzPXtnZXQ6dC5iaW5kKHRoaXMsZSksc2V0OmkuYmluZCh0aGlzLGUpfTtPYmplY3QuZGVmaW5lUHJvcGVydHkodGhpcy5f"
    "cHVibGljT3B0aW9ucyxlLHMpfX1fY2hlY2tSZWFkb25seU9wdGlvbnMoZSl7aWYobC5pbmNsdWRlcyhlKSl0aHJvdyBuZXcgRXJyb3IoYE9wdGlvbiAiJHtl"
    "fSIgY2FuIG9ubHkgYmUgc2V0IGluIHRoZSBjb25zdHJ1Y3RvcmApfV9jaGVja1Byb3Bvc2VkQXBpKCl7aWYoIXRoaXMuX2NvcmUub3B0aW9uc1NlcnZpY2Uu"
    "cmF3T3B0aW9ucy5hbGxvd1Byb3Bvc2VkQXBpKXRocm93IG5ldyBFcnJvcigiWW91IG11c3Qgc2V0IHRoZSBhbGxvd1Byb3Bvc2VkQXBpIG9wdGlvbiB0byB0"
    "cnVlIHRvIHVzZSBwcm9wb3NlZCBBUEkiKX1nZXQgb25CZWxsKCl7cmV0dXJuIHRoaXMuX2NvcmUub25CZWxsfWdldCBvbkJpbmFyeSgpe3JldHVybiB0aGlz"
    "Ll9jb3JlLm9uQmluYXJ5fWdldCBvbkN1cnNvck1vdmUoKXtyZXR1cm4gdGhpcy5fY29yZS5vbkN1cnNvck1vdmV9Z2V0IG9uRGF0YSgpe3JldHVybiB0aGlz"
    "Ll9jb3JlLm9uRGF0YX1nZXQgb25LZXkoKXtyZXR1cm4gdGhpcy5fY29yZS5vbktleX1nZXQgb25MaW5lRmVlZCgpe3JldHVybiB0aGlzLl9jb3JlLm9uTGlu"
    "ZUZlZWR9Z2V0IG9uUmVuZGVyKCl7cmV0dXJuIHRoaXMuX2NvcmUub25SZW5kZXJ9Z2V0IG9uUmVzaXplKCl7cmV0dXJuIHRoaXMuX2NvcmUub25SZXNpemV9"
    "Z2V0IG9uU2Nyb2xsKCl7cmV0dXJuIHRoaXMuX2NvcmUub25TY3JvbGx9Z2V0IG9uU2VsZWN0aW9uQ2hhbmdlKCl7cmV0dXJuIHRoaXMuX2NvcmUub25TZWxl"
    "Y3Rpb25DaGFuZ2V9Z2V0IG9uVGl0bGVDaGFuZ2UoKXtyZXR1cm4gdGhpcy5fY29yZS5vblRpdGxlQ2hhbmdlfWdldCBvbldyaXRlUGFyc2VkKCl7cmV0dXJu"
    "IHRoaXMuX2NvcmUub25Xcml0ZVBhcnNlZH1nZXQgZWxlbWVudCgpe3JldHVybiB0aGlzLl9jb3JlLmVsZW1lbnR9Z2V0IHBhcnNlcigpe3JldHVybiB0aGlz"
    "Ll9wYXJzZXJ8fCh0aGlzLl9wYXJzZXI9bmV3IGguUGFyc2VyQXBpKHRoaXMuX2NvcmUpKSx0aGlzLl9wYXJzZXJ9Z2V0IHVuaWNvZGUoKXtyZXR1cm4gdGhp"
    "cy5fY2hlY2tQcm9wb3NlZEFwaSgpLG5ldyBjLlVuaWNvZGVBcGkodGhpcy5fY29yZSl9Z2V0IHRleHRhcmVhKCl7cmV0dXJuIHRoaXMuX2NvcmUudGV4dGFy"
    "ZWF9Z2V0IHJvd3MoKXtyZXR1cm4gdGhpcy5fY29yZS5yb3dzfWdldCBjb2xzKCl7cmV0dXJuIHRoaXMuX2NvcmUuY29sc31nZXQgYnVmZmVyKCl7cmV0dXJu"
    "IHRoaXMuX2J1ZmZlcnx8KHRoaXMuX2J1ZmZlcj10aGlzLnJlZ2lzdGVyKG5ldyBhLkJ1ZmZlck5hbWVzcGFjZUFwaSh0aGlzLl9jb3JlKSkpLHRoaXMuX2J1"
    "ZmZlcn1nZXQgbWFya2Vycygpe3JldHVybiB0aGlzLl9jaGVja1Byb3Bvc2VkQXBpKCksdGhpcy5fY29yZS5tYXJrZXJzfWdldCBtb2Rlcygpe2NvbnN0IGU9"
    "dGhpcy5fY29yZS5jb3JlU2VydmljZS5kZWNQcml2YXRlTW9kZXM7bGV0IHQ9Im5vbmUiO3N3aXRjaCh0aGlzLl9jb3JlLmNvcmVNb3VzZVNlcnZpY2UuYWN0"
    "aXZlUHJvdG9jb2wpe2Nhc2UiWDEwIjp0PSJ4MTAiO2JyZWFrO2Nhc2UiVlQyMDAiOnQ9InZ0MjAwIjticmVhaztjYXNlIkRSQUciOnQ9ImRyYWciO2JyZWFr"
    "O2Nhc2UiQU5ZIjp0PSJhbnkifXJldHVybnthcHBsaWNhdGlvbkN1cnNvcktleXNNb2RlOmUuYXBwbGljYXRpb25DdXJzb3JLZXlzLGFwcGxpY2F0aW9uS2V5"
    "cGFkTW9kZTplLmFwcGxpY2F0aW9uS2V5cGFkLGJyYWNrZXRlZFBhc3RlTW9kZTplLmJyYWNrZXRlZFBhc3RlTW9kZSxpbnNlcnRNb2RlOnRoaXMuX2NvcmUu"
    "Y29yZVNlcnZpY2UubW9kZXMuaW5zZXJ0TW9kZSxtb3VzZVRyYWNraW5nTW9kZTp0LG9yaWdpbk1vZGU6ZS5vcmlnaW4scmV2ZXJzZVdyYXBhcm91bmRNb2Rl"
    "OmUucmV2ZXJzZVdyYXBhcm91bmQsc2VuZEZvY3VzTW9kZTplLnNlbmRGb2N1cyx3cmFwYXJvdW5kTW9kZTplLndyYXBhcm91bmR9fWdldCBvcHRpb25zKCl7"
    "cmV0dXJuIHRoaXMuX3B1YmxpY09wdGlvbnN9c2V0IG9wdGlvbnMoZSl7Zm9yKGNvbnN0IHQgaW4gZSl0aGlzLl9wdWJsaWNPcHRpb25zW3RdPWVbdF19Ymx1"
    "cigpe3RoaXMuX2NvcmUuYmx1cigpfWZvY3VzKCl7dGhpcy5fY29yZS5mb2N1cygpfXJlc2l6ZShlLHQpe3RoaXMuX3ZlcmlmeUludGVnZXJzKGUsdCksdGhp"
    "cy5fY29yZS5yZXNpemUoZSx0KX1vcGVuKGUpe3RoaXMuX2NvcmUub3BlbihlKX1hdHRhY2hDdXN0b21LZXlFdmVudEhhbmRsZXIoZSl7dGhpcy5fY29yZS5h"
    "dHRhY2hDdXN0b21LZXlFdmVudEhhbmRsZXIoZSl9cmVnaXN0ZXJMaW5rUHJvdmlkZXIoZSl7cmV0dXJuIHRoaXMuX2NvcmUucmVnaXN0ZXJMaW5rUHJvdmlk"
    "ZXIoZSl9cmVnaXN0ZXJDaGFyYWN0ZXJKb2luZXIoZSl7cmV0dXJuIHRoaXMuX2NoZWNrUHJvcG9zZWRBcGkoKSx0aGlzLl9jb3JlLnJlZ2lzdGVyQ2hhcmFj"
    "dGVySm9pbmVyKGUpfWRlcmVnaXN0ZXJDaGFyYWN0ZXJKb2luZXIoZSl7dGhpcy5fY2hlY2tQcm9wb3NlZEFwaSgpLHRoaXMuX2NvcmUuZGVyZWdpc3RlckNo"
    "YXJhY3RlckpvaW5lcihlKX1yZWdpc3Rlck1hcmtlcihlPTApe3JldHVybiB0aGlzLl92ZXJpZnlJbnRlZ2VycyhlKSx0aGlzLl9jb3JlLnJlZ2lzdGVyTWFy"
    "a2VyKGUpfXJlZ2lzdGVyRGVjb3JhdGlvbihlKXt2YXIgdCxpLHM7cmV0dXJuIHRoaXMuX2NoZWNrUHJvcG9zZWRBcGkoKSx0aGlzLl92ZXJpZnlQb3NpdGl2"
    "ZUludGVnZXJzKG51bGwhPT0odD1lLngpJiZ2b2lkIDAhPT10P3Q6MCxudWxsIT09KGk9ZS53aWR0aCkmJnZvaWQgMCE9PWk/aTowLG51bGwhPT0ocz1lLmhl"
    "aWdodCkmJnZvaWQgMCE9PXM/czowKSx0aGlzLl9jb3JlLnJlZ2lzdGVyRGVjb3JhdGlvbihlKX1oYXNTZWxlY3Rpb24oKXtyZXR1cm4gdGhpcy5fY29yZS5o"
    "YXNTZWxlY3Rpb24oKX1zZWxlY3QoZSx0LGkpe3RoaXMuX3ZlcmlmeUludGVnZXJzKGUsdCxpKSx0aGlzLl9jb3JlLnNlbGVjdChlLHQsaSl9Z2V0U2VsZWN0"
    "aW9uKCl7cmV0dXJuIHRoaXMuX2NvcmUuZ2V0U2VsZWN0aW9uKCl9Z2V0U2VsZWN0aW9uUG9zaXRpb24oKXtyZXR1cm4gdGhpcy5fY29yZS5nZXRTZWxlY3Rp"
    "b25Qb3NpdGlvbigpfWNsZWFyU2VsZWN0aW9uKCl7dGhpcy5fY29yZS5jbGVhclNlbGVjdGlvbigpfXNlbGVjdEFsbCgpe3RoaXMuX2NvcmUuc2VsZWN0QWxs"
    "KCl9c2VsZWN0TGluZXMoZSx0KXt0aGlzLl92ZXJpZnlJbnRlZ2VycyhlLHQpLHRoaXMuX2NvcmUuc2VsZWN0TGluZXMoZSx0KX1kaXNwb3NlKCl7c3VwZXIu"
    "ZGlzcG9zZSgpfXNjcm9sbExpbmVzKGUpe3RoaXMuX3ZlcmlmeUludGVnZXJzKGUpLHRoaXMuX2NvcmUuc2Nyb2xsTGluZXMoZSl9c2Nyb2xsUGFnZXMoZSl7"
    "dGhpcy5fdmVyaWZ5SW50ZWdlcnMoZSksdGhpcy5fY29yZS5zY3JvbGxQYWdlcyhlKX1zY3JvbGxUb1RvcCgpe3RoaXMuX2NvcmUuc2Nyb2xsVG9Ub3AoKX1z"
    "Y3JvbGxUb0JvdHRvbSgpe3RoaXMuX2NvcmUuc2Nyb2xsVG9Cb3R0b20oKX1zY3JvbGxUb0xpbmUoZSl7dGhpcy5fdmVyaWZ5SW50ZWdlcnMoZSksdGhpcy5f"
    "Y29yZS5zY3JvbGxUb0xpbmUoZSl9Y2xlYXIoKXt0aGlzLl9jb3JlLmNsZWFyKCl9d3JpdGUoZSx0KXt0aGlzLl9jb3JlLndyaXRlKGUsdCl9d3JpdGVsbihl"
    "LHQpe3RoaXMuX2NvcmUud3JpdGUoZSksdGhpcy5fY29yZS53cml0ZSgiXHJcbiIsdCl9cGFzdGUoZSl7dGhpcy5fY29yZS5wYXN0ZShlKX1yZWZyZXNoKGUs"
    "dCl7dGhpcy5fdmVyaWZ5SW50ZWdlcnMoZSx0KSx0aGlzLl9jb3JlLnJlZnJlc2goZSx0KX1yZXNldCgpe3RoaXMuX2NvcmUucmVzZXQoKX1jbGVhclRleHR1"
    "cmVBdGxhcygpe3RoaXMuX2NvcmUuY2xlYXJUZXh0dXJlQXRsYXMoKX1sb2FkQWRkb24oZSl7dGhpcy5fYWRkb25NYW5hZ2VyLmxvYWRBZGRvbih0aGlzLGUp"
    "fXN0YXRpYyBnZXQgc3RyaW5ncygpe3JldHVybiB0fV92ZXJpZnlJbnRlZ2VycyguLi5lKXtmb3IoY29uc3QgdCBvZiBlKWlmKHQ9PT0xLzB8fGlzTmFOKHQp"
    "fHx0JTEhPTApdGhyb3cgbmV3IEVycm9yKCJUaGlzIEFQSSBvbmx5IGFjY2VwdHMgaW50ZWdlcnMiKX1fdmVyaWZ5UG9zaXRpdmVJbnRlZ2VycyguLi5lKXtm"
    "b3IoY29uc3QgdCBvZiBlKWlmKHQmJih0PT09MS8wfHxpc05hTih0KXx8dCUxIT0wfHx0PDApKXRocm93IG5ldyBFcnJvcigiVGhpcyBBUEkgb25seSBhY2Nl"
    "cHRzIHBvc2l0aXZlIGludGVnZXJzIil9fWUuVGVybWluYWw9ZH0pKCksc30pKCkpKTsKLy8jIHNvdXJjZU1hcHBpbmdVUkw9eHRlcm0uanMubWFw"
)

_XTERM_CSS_B64 = (
    "LyoqCiAqIENvcHlyaWdodCAoYykgMjAxNCBUaGUgeHRlcm0uanMgYXV0aG9ycy4gQWxsIHJpZ2h0cyByZXNlcnZlZC4KICogQ29weXJpZ2h0IChjKSAyMDEy"
    "LTIwMTMsIENocmlzdG9waGVyIEplZmZyZXkgKE1JVCBMaWNlbnNlKQogKiBodHRwczovL2dpdGh1Yi5jb20vY2hqai90ZXJtLmpzCiAqIEBsaWNlbnNlIE1J"
    "VAogKgogKiBQZXJtaXNzaW9uIGlzIGhlcmVieSBncmFudGVkLCBmcmVlIG9mIGNoYXJnZSwgdG8gYW55IHBlcnNvbiBvYnRhaW5pbmcgYSBjb3B5CiAqIG9m"
    "IHRoaXMgc29mdHdhcmUgYW5kIGFzc29jaWF0ZWQgZG9jdW1lbnRhdGlvbiBmaWxlcyAodGhlICJTb2Z0d2FyZSIpLCB0byBkZWFsCiAqIGluIHRoZSBTb2Z0"
    "d2FyZSB3aXRob3V0IHJlc3RyaWN0aW9uLCBpbmNsdWRpbmcgd2l0aG91dCBsaW1pdGF0aW9uIHRoZSByaWdodHMKICogdG8gdXNlLCBjb3B5LCBtb2RpZnks"
    "IG1lcmdlLCBwdWJsaXNoLCBkaXN0cmlidXRlLCBzdWJsaWNlbnNlLCBhbmQvb3Igc2VsbAogKiBjb3BpZXMgb2YgdGhlIFNvZnR3YXJlLCBhbmQgdG8gcGVy"
    "bWl0IHBlcnNvbnMgdG8gd2hvbSB0aGUgU29mdHdhcmUgaXMKICogZnVybmlzaGVkIHRvIGRvIHNvLCBzdWJqZWN0IHRvIHRoZSBmb2xsb3dpbmcgY29uZGl0"
    "aW9uczoKICoKICogVGhlIGFib3ZlIGNvcHlyaWdodCBub3RpY2UgYW5kIHRoaXMgcGVybWlzc2lvbiBub3RpY2Ugc2hhbGwgYmUgaW5jbHVkZWQgaW4KICog"
    "YWxsIGNvcGllcyBvciBzdWJzdGFudGlhbCBwb3J0aW9ucyBvZiB0aGUgU29mdHdhcmUuCiAqCiAqIFRIRSBTT0ZUV0FSRSBJUyBQUk9WSURFRCAiQVMgSVMi"
    "LCBXSVRIT1VUIFdBUlJBTlRZIE9GIEFOWSBLSU5ELCBFWFBSRVNTIE9SCiAqIElNUExJRUQsIElOQ0xVRElORyBCVVQgTk9UIExJTUlURUQgVE8gVEhFIFdB"
    "UlJBTlRJRVMgT0YgTUVSQ0hBTlRBQklMSVRZLAogKiBGSVRORVNTIEZPUiBBIFBBUlRJQ1VMQVIgUFVSUE9TRSBBTkQgTk9OSU5GUklOR0VNRU5ULiBJTiBO"
    "TyBFVkVOVCBTSEFMTCBUSEUKICogQVVUSE9SUyBPUiBDT1BZUklHSFQgSE9MREVSUyBCRSBMSUFCTEUgRk9SIEFOWSBDTEFJTSwgREFNQUdFUyBPUiBPVEhF"
    "UgogKiBMSUFCSUxJVFksIFdIRVRIRVIgSU4gQU4gQUNUSU9OIE9GIENPTlRSQUNULCBUT1JUIE9SIE9USEVSV0lTRSwgQVJJU0lORyBGUk9NLAogKiBPVVQg"
    "T0YgT1IgSU4gQ09OTkVDVElPTiBXSVRIIFRIRSBTT0ZUV0FSRSBPUiBUSEUgVVNFIE9SIE9USEVSIERFQUxJTkdTIElOCiAqIFRIRSBTT0ZUV0FSRS4KICoK"
    "ICogT3JpZ2luYWxseSBmb3JrZWQgZnJvbSAod2l0aCB0aGUgYXV0aG9yJ3MgcGVybWlzc2lvbik6CiAqICAgRmFicmljZSBCZWxsYXJkJ3MgamF2YXNjcmlw"
    "dCB2dDEwMCBmb3IganNsaW51eDoKICogICBodHRwOi8vYmVsbGFyZC5vcmcvanNsaW51eC8KICogICBDb3B5cmlnaHQgKGMpIDIwMTEgRmFicmljZSBCZWxs"
    "YXJkCiAqICAgVGhlIG9yaWdpbmFsIGRlc2lnbiByZW1haW5zLiBUaGUgdGVybWluYWwgaXRzZWxmCiAqICAgaGFzIGJlZW4gZXh0ZW5kZWQgdG8gaW5jbHVk"
    "ZSB4dGVybSBDU0kgY29kZXMsIGFtb25nCiAqICAgb3RoZXIgZmVhdHVyZXMuCiAqLwoKLyoqCiAqICBEZWZhdWx0IHN0eWxlcyBmb3IgeHRlcm0uanMKICov"
    "CgoueHRlcm0gewogICAgY3Vyc29yOiB0ZXh0OwogICAgcG9zaXRpb246IHJlbGF0aXZlOwogICAgdXNlci1zZWxlY3Q6IG5vbmU7CiAgICAtbXMtdXNlci1z"
    "ZWxlY3Q6IG5vbmU7CiAgICAtd2Via2l0LXVzZXItc2VsZWN0OiBub25lOwp9CgoueHRlcm0uZm9jdXMsCi54dGVybTpmb2N1cyB7CiAgICBvdXRsaW5lOiBu"
    "b25lOwp9CgoueHRlcm0gLnh0ZXJtLWhlbHBlcnMgewogICAgcG9zaXRpb246IGFic29sdXRlOwogICAgdG9wOiAwOwogICAgLyoqCiAgICAgKiBUaGUgei1p"
    "bmRleCBvZiB0aGUgaGVscGVycyBtdXN0IGJlIGhpZ2hlciB0aGFuIHRoZSBjYW52YXNlcyBpbiBvcmRlciBmb3IKICAgICAqIElNRXMgdG8gYXBwZWFyIG9u"
    "IHRvcC4KICAgICAqLwogICAgei1pbmRleDogNTsKfQoKLnh0ZXJtIC54dGVybS1oZWxwZXItdGV4dGFyZWEgewogICAgcGFkZGluZzogMDsKICAgIGJvcmRl"
    "cjogMDsKICAgIG1hcmdpbjogMDsKICAgIC8qIE1vdmUgdGV4dGFyZWEgb3V0IG9mIHRoZSBzY3JlZW4gdG8gdGhlIGZhciBsZWZ0LCBzbyB0aGF0IHRoZSBj"
    "dXJzb3IgaXMgbm90IHZpc2libGUgKi8KICAgIHBvc2l0aW9uOiBhYnNvbHV0ZTsKICAgIG9wYWNpdHk6IDA7CiAgICBsZWZ0OiAtOTk5OWVtOwogICAgdG9w"
    "OiAwOwogICAgd2lkdGg6IDA7CiAgICBoZWlnaHQ6IDA7CiAgICB6LWluZGV4OiAtNTsKICAgIC8qKiBQcmV2ZW50IHdyYXBwaW5nIHNvIHRoZSBJTUUgYXBw"
    "ZWFycyBhZ2FpbnN0IHRoZSB0ZXh0YXJlYSBhdCB0aGUgY29ycmVjdCBwb3NpdGlvbiAqLwogICAgd2hpdGUtc3BhY2U6IG5vd3JhcDsKICAgIG92ZXJmbG93"
    "OiBoaWRkZW47CiAgICByZXNpemU6IG5vbmU7Cn0KCi54dGVybSAuY29tcG9zaXRpb24tdmlldyB7CiAgICAvKiBUT0RPOiBDb21wb3NpdGlvbiBwb3NpdGlv"
    "biBnb3QgbWVzc2VkIHVwIHNvbWV3aGVyZSAqLwogICAgYmFja2dyb3VuZDogIzAwMDsKICAgIGNvbG9yOiAjRkZGOwogICAgZGlzcGxheTogbm9uZTsKICAg"
    "IHBvc2l0aW9uOiBhYnNvbHV0ZTsKICAgIHdoaXRlLXNwYWNlOiBub3dyYXA7CiAgICB6LWluZGV4OiAxOwp9CgoueHRlcm0gLmNvbXBvc2l0aW9uLXZpZXcu"
    "YWN0aXZlIHsKICAgIGRpc3BsYXk6IGJsb2NrOwp9CgoueHRlcm0gLnh0ZXJtLXZpZXdwb3J0IHsKICAgIC8qIE9uIE9TIFggdGhpcyBpcyByZXF1aXJlZCBp"
    "biBvcmRlciBmb3IgdGhlIHNjcm9sbCBiYXIgdG8gYXBwZWFyIGZ1bGx5IG9wYXF1ZSAqLwogICAgYmFja2dyb3VuZC1jb2xvcjogIzAwMDsKICAgIG92ZXJm"
    "bG93LXk6IHNjcm9sbDsKICAgIGN1cnNvcjogZGVmYXVsdDsKICAgIHBvc2l0aW9uOiBhYnNvbHV0ZTsKICAgIHJpZ2h0OiAwOwogICAgbGVmdDogMDsKICAg"
    "IHRvcDogMDsKICAgIGJvdHRvbTogMDsKfQoKLnh0ZXJtIC54dGVybS1zY3JlZW4gewogICAgcG9zaXRpb246IHJlbGF0aXZlOwp9CgoueHRlcm0gLnh0ZXJt"
    "LXNjcmVlbiBjYW52YXMgewogICAgcG9zaXRpb246IGFic29sdXRlOwogICAgbGVmdDogMDsKICAgIHRvcDogMDsKfQoKLnh0ZXJtIC54dGVybS1zY3JvbGwt"
    "YXJlYSB7CiAgICB2aXNpYmlsaXR5OiBoaWRkZW47Cn0KCi54dGVybS1jaGFyLW1lYXN1cmUtZWxlbWVudCB7CiAgICBkaXNwbGF5OiBpbmxpbmUtYmxvY2s7"
    "CiAgICB2aXNpYmlsaXR5OiBoaWRkZW47CiAgICBwb3NpdGlvbjogYWJzb2x1dGU7CiAgICB0b3A6IDA7CiAgICBsZWZ0OiAtOTk5OWVtOwogICAgbGluZS1o"
    "ZWlnaHQ6IG5vcm1hbDsKfQoKLnh0ZXJtLmVuYWJsZS1tb3VzZS1ldmVudHMgewogICAgLyogV2hlbiBtb3VzZSBldmVudHMgYXJlIGVuYWJsZWQgKGVnLiB0"
    "bXV4KSwgcmV2ZXJ0IHRvIHRoZSBzdGFuZGFyZCBwb2ludGVyIGN1cnNvciAqLwogICAgY3Vyc29yOiBkZWZhdWx0Owp9CgoueHRlcm0ueHRlcm0tY3Vyc29y"
    "LXBvaW50ZXIsCi54dGVybSAueHRlcm0tY3Vyc29yLXBvaW50ZXIgewogICAgY3Vyc29yOiBwb2ludGVyOwp9CgoueHRlcm0uY29sdW1uLXNlbGVjdC5mb2N1"
    "cyB7CiAgICAvKiBDb2x1bW4gc2VsZWN0aW9uIG1vZGUgKi8KICAgIGN1cnNvcjogY3Jvc3NoYWlyOwp9CgoueHRlcm0gLnh0ZXJtLWFjY2Vzc2liaWxpdHks"
    "Ci54dGVybSAueHRlcm0tbWVzc2FnZSB7CiAgICBwb3NpdGlvbjogYWJzb2x1dGU7CiAgICBsZWZ0OiAwOwogICAgdG9wOiAwOwogICAgYm90dG9tOiAwOwog"
    "ICAgcmlnaHQ6IDA7CiAgICB6LWluZGV4OiAxMDsKICAgIGNvbG9yOiB0cmFuc3BhcmVudDsKICAgIHBvaW50ZXItZXZlbnRzOiBub25lOwp9CgoueHRlcm0g"
    "LmxpdmUtcmVnaW9uIHsKICAgIHBvc2l0aW9uOiBhYnNvbHV0ZTsKICAgIGxlZnQ6IC05OTk5cHg7CiAgICB3aWR0aDogMXB4OwogICAgaGVpZ2h0OiAxcHg7"
    "CiAgICBvdmVyZmxvdzogaGlkZGVuOwp9CgoueHRlcm0tZGltIHsKICAgIC8qIERpbSBzaG91bGQgbm90IGFwcGx5IHRvIGJhY2tncm91bmQsIHNvIHRoZSBv"
    "cGFjaXR5IG9mIHRoZSBmb3JlZ3JvdW5kIGNvbG9yIGlzIGFwcGxpZWQKICAgICAqIGV4cGxpY2l0bHkgaW4gdGhlIGdlbmVyYXRlZCBjbGFzcyBhbmQgcmVz"
    "ZXQgdG8gMSBoZXJlICovCiAgICBvcGFjaXR5OiAxICFpbXBvcnRhbnQ7Cn0KCi54dGVybS11bmRlcmxpbmUtMSB7IHRleHQtZGVjb3JhdGlvbjogdW5kZXJs"
    "aW5lOyB9Ci54dGVybS11bmRlcmxpbmUtMiB7IHRleHQtZGVjb3JhdGlvbjogZG91YmxlIHVuZGVybGluZTsgfQoueHRlcm0tdW5kZXJsaW5lLTMgeyB0ZXh0"
    "LWRlY29yYXRpb246IHdhdnkgdW5kZXJsaW5lOyB9Ci54dGVybS11bmRlcmxpbmUtNCB7IHRleHQtZGVjb3JhdGlvbjogZG90dGVkIHVuZGVybGluZTsgfQou"
    "eHRlcm0tdW5kZXJsaW5lLTUgeyB0ZXh0LWRlY29yYXRpb246IGRhc2hlZCB1bmRlcmxpbmU7IH0KCi54dGVybS1vdmVybGluZSB7CiAgICB0ZXh0LWRlY29y"
    "YXRpb246IG92ZXJsaW5lOwp9CgoueHRlcm0tb3ZlcmxpbmUueHRlcm0tdW5kZXJsaW5lLTEgeyB0ZXh0LWRlY29yYXRpb246IG92ZXJsaW5lIHVuZGVybGlu"
    "ZTsgfQoueHRlcm0tb3ZlcmxpbmUueHRlcm0tdW5kZXJsaW5lLTIgeyB0ZXh0LWRlY29yYXRpb246IG92ZXJsaW5lIGRvdWJsZSB1bmRlcmxpbmU7IH0KLnh0"
    "ZXJtLW92ZXJsaW5lLnh0ZXJtLXVuZGVybGluZS0zIHsgdGV4dC1kZWNvcmF0aW9uOiBvdmVybGluZSB3YXZ5IHVuZGVybGluZTsgfQoueHRlcm0tb3Zlcmxp"
    "bmUueHRlcm0tdW5kZXJsaW5lLTQgeyB0ZXh0LWRlY29yYXRpb246IG92ZXJsaW5lIGRvdHRlZCB1bmRlcmxpbmU7IH0KLnh0ZXJtLW92ZXJsaW5lLnh0ZXJt"
    "LXVuZGVybGluZS01IHsgdGV4dC1kZWNvcmF0aW9uOiBvdmVybGluZSBkYXNoZWQgdW5kZXJsaW5lOyB9CgoueHRlcm0tc3RyaWtldGhyb3VnaCB7CiAgICB0"
    "ZXh0LWRlY29yYXRpb246IGxpbmUtdGhyb3VnaDsKfQoKLnh0ZXJtLXNjcmVlbiAueHRlcm0tZGVjb3JhdGlvbi1jb250YWluZXIgLnh0ZXJtLWRlY29yYXRp"
    "b24gewoJei1pbmRleDogNjsKCXBvc2l0aW9uOiBhYnNvbHV0ZTsKfQoKLnh0ZXJtLXNjcmVlbiAueHRlcm0tZGVjb3JhdGlvbi1jb250YWluZXIgLnh0ZXJt"
    "LWRlY29yYXRpb24ueHRlcm0tZGVjb3JhdGlvbi10b3AtbGF5ZXIgewoJei1pbmRleDogNzsKfQoKLnh0ZXJtLWRlY29yYXRpb24tb3ZlcnZpZXctcnVsZXIg"
    "ewogICAgei1pbmRleDogODsKICAgIHBvc2l0aW9uOiBhYnNvbHV0ZTsKICAgIHRvcDogMDsKICAgIHJpZ2h0OiAwOwogICAgcG9pbnRlci1ldmVudHM6IG5v"
    "bmU7Cn0KCi54dGVybS1kZWNvcmF0aW9uLXRvcCB7CiAgICB6LWluZGV4OiAyOwogICAgcG9zaXRpb246IHJlbGF0aXZlOwp9Cg=="
)

_ADDON_FIT_JS_B64 = (
    "IWZ1bmN0aW9uKGUsdCl7Im9iamVjdCI9PXR5cGVvZiBleHBvcnRzJiYib2JqZWN0Ij09dHlwZW9mIG1vZHVsZT9tb2R1bGUuZXhwb3J0cz10KCk6ImZ1bmN0"
    "aW9uIj09dHlwZW9mIGRlZmluZSYmZGVmaW5lLmFtZD9kZWZpbmUoW10sdCk6Im9iamVjdCI9PXR5cGVvZiBleHBvcnRzP2V4cG9ydHMuRml0QWRkb249dCgp"
    "OmUuRml0QWRkb249dCgpfShnbG9iYWxUaGlzLCgoKT0+KCgpPT57InVzZSBzdHJpY3QiO3ZhciBlPXt9O3JldHVybigoKT0+e3ZhciB0PWU7T2JqZWN0LmRl"
    "ZmluZVByb3BlcnR5KHQsIl9fZXNNb2R1bGUiLHt2YWx1ZTohMH0pLHQuRml0QWRkb249dm9pZCAwLHQuRml0QWRkb249Y2xhc3N7YWN0aXZhdGUoZSl7dGhp"
    "cy5fdGVybWluYWw9ZX1kaXNwb3NlKCl7fWZpdCgpe2NvbnN0IGU9dGhpcy5wcm9wb3NlRGltZW5zaW9ucygpO2lmKCFlfHwhdGhpcy5fdGVybWluYWx8fGlz"
    "TmFOKGUuY29scyl8fGlzTmFOKGUucm93cykpcmV0dXJuO2NvbnN0IHQ9dGhpcy5fdGVybWluYWwuX2NvcmU7dGhpcy5fdGVybWluYWwucm93cz09PWUucm93"
    "cyYmdGhpcy5fdGVybWluYWwuY29scz09PWUuY29sc3x8KHQuX3JlbmRlclNlcnZpY2UuY2xlYXIoKSx0aGlzLl90ZXJtaW5hbC5yZXNpemUoZS5jb2xzLGUu"
    "cm93cykpfXByb3Bvc2VEaW1lbnNpb25zKCl7aWYoIXRoaXMuX3Rlcm1pbmFsKXJldHVybjtpZighdGhpcy5fdGVybWluYWwuZWxlbWVudHx8IXRoaXMuX3Rl"
    "cm1pbmFsLmVsZW1lbnQucGFyZW50RWxlbWVudClyZXR1cm47Y29uc3QgZT10aGlzLl90ZXJtaW5hbC5fY29yZS5fcmVuZGVyU2VydmljZS5kaW1lbnNpb25z"
    "O2lmKDA9PT1lLmNzcy5jZWxsLndpZHRofHwwPT09ZS5jc3MuY2VsbC5oZWlnaHQpcmV0dXJuO2NvbnN0IHQ9MD09PXRoaXMuX3Rlcm1pbmFsLm9wdGlvbnMu"
    "c2Nyb2xsYmFjaz8wOnRoaXMuX3Rlcm1pbmFsLm9wdGlvbnMub3ZlcnZpZXdSdWxlcj8ud2lkdGh8fDE0LHI9d2luZG93LmdldENvbXB1dGVkU3R5bGUodGhp"
    "cy5fdGVybWluYWwuZWxlbWVudC5wYXJlbnRFbGVtZW50KSxpPXBhcnNlSW50KHIuZ2V0UHJvcGVydHlWYWx1ZSgiaGVpZ2h0IikpLG89TWF0aC5tYXgoMCxw"
    "YXJzZUludChyLmdldFByb3BlcnR5VmFsdWUoIndpZHRoIikpKSxzPXdpbmRvdy5nZXRDb21wdXRlZFN0eWxlKHRoaXMuX3Rlcm1pbmFsLmVsZW1lbnQpLG49"
    "aS0ocGFyc2VJbnQocy5nZXRQcm9wZXJ0eVZhbHVlKCJwYWRkaW5nLXRvcCIpKStwYXJzZUludChzLmdldFByb3BlcnR5VmFsdWUoInBhZGRpbmctYm90dG9t"
    "IikpKSxsPW8tKHBhcnNlSW50KHMuZ2V0UHJvcGVydHlWYWx1ZSgicGFkZGluZy1yaWdodCIpKStwYXJzZUludChzLmdldFByb3BlcnR5VmFsdWUoInBhZGRp"
    "bmctbGVmdCIpKSktdDtyZXR1cm57Y29sczpNYXRoLm1heCgyLE1hdGguZmxvb3IobC9lLmNzcy5jZWxsLndpZHRoKSkscm93czpNYXRoLm1heCgxLE1hdGgu"
    "Zmxvb3Iobi9lLmNzcy5jZWxsLmhlaWdodCkpfX19fSkoKSxlfSkoKSkpOwovLyMgc291cmNlTWFwcGluZ1VSTD1hZGRvbi1maXQuanMubWFw"
)

# ---------------------------------------------------------------------------
# HTML / CSS / JS – embedded so the server is a single file with no assets
# ---------------------------------------------------------------------------
_HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ModernJVS WebUI</title>
<link rel="icon" type="image/png" href="__STICKS__">
<link rel="stylesheet" href="/xterm.css"/>
<script src="/xterm.js"></script>
<script src="/addon-fit.js"></script>
<style>
  :root {
    --bg:      #0d0d14;
    --surface: #16161f;
    --card:    #1e1e2e;
    --border:  #2e2e42;
    --accent:  #970011;
    --accent2: #970011;
    --text:    #e2e2f0;
    --muted:   #7878a0;
    --green:   #50fa7b;
    --yellow:  #f1fa8c;
    --red:     #ff5555;
    --radius:  8px;
    --font:    'Segoe UI', system-ui, sans-serif;
  }
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: var(--font); min-height: 100vh; }

  /* --- header --- */
  header {
    background: var(--surface);
    border-bottom: 2px solid var(--accent);
    padding: 0.75rem 2rem;
    display: flex;
    align-items: center;
    gap: 1.5rem;
    position: sticky;
    top: 0;
    z-index: 100;
  }
  /* Logo: fluid height, never shrinks below clamped minimum */
  header img { height: clamp(26px, 5vw, 42px); flex-shrink: 0; }
  /* h1: stretches to fill available space, then shrinks and truncates before
     pushing the status badge off-screen */
  header h1 {
    font-size: clamp(0.95rem, 3.5vw, 1.4rem);
    color: var(--muted);
    font-weight: 400;
    letter-spacing: 0.05em;
    flex: 1 1 0;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .status-badge {
    flex-shrink: 0;        /* always fully visible */
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.85rem;
    color: var(--muted);
  }
  .dot {
    width: 10px; height: 10px;
    border-radius: 50%;
    background: var(--muted);
    display: inline-block;
  }
  .dot.running { background: var(--green); box-shadow: 0 0 6px var(--green); }
  .dot.stopped { background: var(--red); }

  /* --- layout --- */
  .container { max-width: 1100px; margin: 0 auto; padding: 1.5rem; position: relative; z-index: 2; }
  footer {
    text-align: center;
    color: var(--muted);
    font-size: 0.78rem;
    padding: 1.5rem;
    position: relative;
    z-index: 2;
  }
  /* Version in footer: only shown on mobile (see ≤640px breakpoint) */
  .footer-ver { display: none; }

  /* --- tabs --- */
  .tabs { display: flex; gap: 0.25rem; margin-bottom: 1.5rem; border-bottom: 2px solid var(--border); }
  .tab {
    padding: 0.6rem 1.25rem;
    background: none;
    border: none;
    color: var(--muted);
    cursor: pointer;
    font-size: 0.95rem;
    font-family: var(--font);
    border-bottom: 2px solid transparent;
    margin-bottom: -2px;
    transition: color 0.15s, border-color 0.15s;
  }
  .tab:hover { color: var(--text); }
  .tab.active { color: var(--accent); border-bottom-color: var(--accent); }

  .panel { display: none; }
  .panel.active { display: block; }

  /* --- card --- */
  .card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 1.25rem;
    margin-bottom: 1.25rem;
  }
  .card h2 { font-size: 1rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 1rem; }

  /* --- control row --- */
  .control-row { display: flex; gap: 0.75rem; flex-wrap: wrap; align-items: center; }
  .btn {
    padding: 0.55rem 1.25rem;
    border-radius: var(--radius);
    border: none;
    cursor: pointer;
    font-family: var(--font);
    font-size: 0.9rem;
    font-weight: 600;
    transition: opacity 0.15s, transform 0.1s;
  }
  .btn:active { transform: scale(0.97); }
  .btn:disabled { opacity: 0.45; cursor: not-allowed; }
  .btn-start  { background: var(--green);  color: #0d0d14; }
  .btn-stop   { background: var(--red);    color: #fff; }
  .btn-restart{ background: var(--yellow); color: #0d0d14; }
  .btn-save   { background: var(--accent); color: #fff; }
  .btn-refresh{ background: var(--border); color: var(--text); }

  /* --- form --- */
  .form-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 1rem; }
  .field { display: flex; flex-direction: column; gap: 0.35rem; }
  .field label { font-size: 0.82rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.06em; }
  .field select, .field input[type="text"], .field input[type="number"] {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    color: var(--text);
    padding: 0.5rem 0.75rem;
    font-family: var(--font);
    font-size: 0.9rem;
    width: 100%;
    transition: border-color 0.15s;
  }
  .field select:focus, .field input:focus { outline: none; border-color: var(--accent); }
  .field select option { background: var(--surface); }

  /* --- log terminal --- */
  .log-wrap {
    background: #0a0a10;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    height: 420px;
    overflow-y: auto;
    padding: 0.75rem 1rem;
    font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
    font-size: 0.8rem;
    line-height: 1.55;
  }
  .log-wrap .log-line { white-space: pre-wrap; word-break: break-all; }
  .log-wrap .log-err  { color: var(--red); }
  .log-wrap .log-warn { color: var(--yellow); }
  .log-wrap .log-info { color: var(--text); }
  .log-controls { display: flex; gap: 0.75rem; align-items: center; margin-bottom: 0.75rem; flex-wrap: wrap; }
  .log-controls label { color: var(--muted); font-size: 0.85rem; display: flex; align-items: center; gap: 0.4rem; }

  /* --- status grid --- */
  .stat-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 1rem; }
  .stat-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 1rem;
    text-align: center;
  }
  .stat-card .val { font-size: 1.4rem; font-weight: 700; color: var(--accent2); }
  .stat-card .lbl { font-size: 0.78rem; color: var(--muted); margin-top: 0.3rem; text-transform: uppercase; letter-spacing: 0.06em; }

  /* --- version badge in header --- */
  .ver-badge {
    display: none;
    font-size: 0.72rem;
    color: var(--muted);
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 0.2rem 0.5rem;
    margin-left: 0.5rem;
    vertical-align: middle;
    white-space: nowrap;
  }
  .ver-badge.visible { display: inline-block; }

  /* --- device table --- */
  .device-table { width: 100%; border-collapse: collapse; font-size: 0.88rem; }
  .device-table th { text-align: left; color: var(--muted); font-weight: 600; padding: 0.4rem 0.6rem; border-bottom: 1px solid var(--border); font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.06em; }
  .device-table td { padding: 0.4rem 0.6rem; border-bottom: 1px solid rgba(46,46,66,0.5); color: var(--text); }
  .device-table tr:last-child td { border-bottom: none; }
  .device-table tr:hover td { background: rgba(255,255,255,0.03); }
  .device-table td code { color: var(--accent2); font-family: monospace; font-size: 0.82rem; }

  /* --- usage / progress bars --- */
  .usage-row { margin-bottom: 0.9rem; }
  .usage-header { display: flex; justify-content: space-between; margin-bottom: 0.3rem; }
  .usage-label { font-size: 0.82rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.06em; }
  .usage-value { font-size: 0.82rem; color: var(--text); font-weight: 600; }
  .progress { width: 100%; height: 6px; background: var(--border); border-radius: 3px; overflow: hidden; }
  .progress-bar { height: 100%; border-radius: 3px; background: var(--green); transition: width 0.5s ease, background 0.5s ease; }
  .progress-bar.warm { background: var(--yellow); }
  .progress-bar.hot  { background: var(--red); }
  .sysinfo-footer { font-size: 0.78rem; color: var(--muted); margin-top: 0.25rem; }
  .ip-info { font-size: 0.82rem; color: var(--muted); margin-top: 0.75rem; padding-top: 0.75rem; border-top: 1px solid var(--border); }
  .ip-info span { color: var(--accent2); font-weight: 600; }

  /* --- log filter bar --- */
  .log-filter-bar { display: flex; gap: 0.5rem; align-items: center; flex-wrap: wrap; }
  .log-filter-bar select, .log-filter-bar input[type="text"] {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 4px;
    color: var(--text);
    padding: 0.25rem 0.5rem;
    font-family: var(--font);
    font-size: 0.85rem;
  }
  .log-filter-bar input[type="text"] { width: 160px; }
  .log-filter-bar input[type="text"]::placeholder { color: var(--muted); }
  .btn-xs { padding: 0.25rem 0.6rem; font-size: 0.8rem; }

  /* --- alert --- */
  .alert {
    padding: 0.7rem 1rem;
    border-radius: var(--radius);
    font-size: 0.88rem;
    margin-bottom: 1rem;
    display: none;
  }
  .alert.ok  { background: rgba(80,250,123,0.12); border: 1px solid var(--green); color: var(--green); display: block; }
  .alert.err { background: rgba(255,85,85,0.12);  border: 1px solid var(--red);   color: var(--red);   display: block; }

  /* --- footer --- */
  footer a { color: var(--accent); text-decoration: none; }

  /* ================================================================
     THEMES – variable overrides applied via data-theme on <html>
     ================================================================ */
  /* dark is the default; defined explicitly so the selector pattern is consistent */
  [data-theme="dark"] {
    --bg:      #0d0d14;
    --surface: #16161f;
    --card:    #1e1e2e;
    --border:  #2e2e42;
    --accent:  #970011;
    --accent2: #970011;
    --text:    #e2e2f0;
    --muted:   #7878a0;
  }
  [data-theme="light"] {
    --bg:      #f0f0f5;
    --surface: #e0e0ea;
    --card:    #ffffff;
    --border:  #c4c4d4;
    --accent:  #000000;
    --accent2: #000000;
    --text:    #1a1a2e;
    --muted:   #55558a;
  }
  [data-theme="midnight"] {
    --bg:      #080c18;
    --surface: #0d1528;
    --card:    #111c38;
    --border:  #1a2d54;
    --accent:  #3b82f6;
    --accent2: #60a5fa;
    --text:    #c5d8f5;
    --muted:   #4d6a9a;
  }
  [data-theme="dracula"] {
    --bg:      #1e1f29;
    --surface: #282a36;
    --card:    #313442;
    --border:  #44475a;
    --text:    #f8f8f2;
    --muted:   #6272a4;
    --accent:  #bd93f9;
    --accent2: #ff79c6;
  }
  [data-theme="terminal"] {
    --bg:      #0a0f0a;
    --surface: #0d150d;
    --card:    #111c11;
    --border:  #1a2e1a;
    --text:    #a0f0a0;
    --muted:   #4a8a4a;
    --accent:  #50fa7b;
    --accent2: #69ff47;
  }
  [data-theme="black"] {
    --bg:      #000000;
    --surface: #0a0a0a;
    --card:    #111111;
    --border:  #1f1f1f;
    --text:    #e2e2f0;
    --muted:   #888888;
  }
  /* ---- Additional colour themes ---- */
  [data-theme="ocean"] {
    --bg:      #020c18;
    --surface: #051422;
    --card:    #071c30;
    --border:  #0c2e4a;
    --accent:  #0ea5e9;
    --accent2: #38bdf8;
    --text:    #e0f4ff;
    --muted:   #4a7e99;
  }
  [data-theme="sunset"] {
    --bg:      #1a0800;
    --surface: #261000;
    --card:    #2d1400;
    --border:  #4a2000;
    --accent:  #f97316;
    --accent2: #fb923c;
    --text:    #fde8cc;
    --muted:   #8a5a2a;
  }
  [data-theme="forest"] {
    --bg:      #030d03;
    --surface: #071507;
    --card:    #091a09;
    --border:  #0f2a10;
    --accent:  #22c55e;
    --accent2: #4ade80;
    --text:    #d0f0d0;
    --muted:   #3a7a45;
  }
  [data-theme="purple"] {
    --bg:      #0d0018;
    --surface: #130025;
    --card:    #1a0030;
    --border:  #2c004d;
    --accent:  #a855f7;
    --accent2: #c084fc;
    --text:    #f0e0ff;
    --muted:   #6e3f99;
  }
  [data-theme="neon"] {
    --bg:      #00080d;
    --surface: #001018;
    --card:    #001820;
    --border:  #002a38;
    --accent:  #06b6d4;
    --accent2: #22d3ee;
    --text:    #cffafe;
    --muted:   #2e7a8a;
  }
  [data-theme="rose"] {
    --bg:      #1a0010;
    --surface: #240018;
    --card:    #2e0020;
    --border:  #480038;
    --accent:  #f43f5e;
    --accent2: #fb7185;
    --text:    #ffe0e8;
    --muted:   #883a5a;
  }
  [data-theme="amber"] {
    --bg:      #0d0600;
    --surface: #180e00;
    --card:    #1e1000;
    --border:  #321a00;
    --accent:  #f59e0b;
    --accent2: #fbbf24;
    --text:    #fef3c7;
    --muted:   #7a5820;
  }
  [data-theme="solarized"] {
    --bg:      #002b36;
    --surface: #04323f;
    --card:    #073642;
    --border:  #0d4f5e;
    --accent:  #2aa198;
    --accent2: #859900;
    --text:    #fdf6e3;
    --muted:   #657b83;
  }
  /* ---- Logo colour tinting per theme ----
     hue-rotate shifts all logo colours to complement each theme's accent.
     Pure Dark / Dark use the original logo colours (no rotation). */
  [data-theme="dark"]      #logo { filter: none; }
  [data-theme="black"]     #logo { filter: none; }
  [data-theme="light"]     #logo { filter: brightness(0) saturate(0); }
  [data-theme="midnight"]  #logo { filter: hue-rotate(212deg) saturate(1.1); }
  [data-theme="dracula"]   #logo { filter: hue-rotate(268deg) saturate(1.2); }
  [data-theme="terminal"]  #logo { filter: hue-rotate(148deg) saturate(1.2); }
  [data-theme="ocean"]     #logo { filter: hue-rotate(208deg) saturate(1.2); }
  [data-theme="sunset"]    #logo { filter: hue-rotate(36deg)  saturate(1.2); }
  [data-theme="forest"]    #logo { filter: hue-rotate(148deg) saturate(1.2); }
  [data-theme="purple"]    #logo { filter: hue-rotate(278deg) saturate(1.2); }
  [data-theme="neon"]      #logo { filter: hue-rotate(196deg) saturate(1.2); }
  [data-theme="rose"]      #logo { filter: hue-rotate(4deg)   saturate(1.1); }
  [data-theme="amber"]     #logo { filter: hue-rotate(50deg)  saturate(1.2); }
  [data-theme="solarized"] #logo { filter: hue-rotate(192deg) saturate(0.9); }

  /* ---- Sticks corner decoration ---- */
  .sticks-corner {
    position: fixed;
    bottom: 12px;
    right: 12px;
    width: 150px;
    opacity: 0.23;
    pointer-events: none;
    z-index: 0;
  }
  /* Sticks image: dominant hue ~20°, logo dominant hue ~350°, offset = +330°.
     sticks_rot = (logo_rot + 330) % 360  so both reach the same output hue. */
  [data-theme="dark"]      #sticks { filter: hue-rotate(330deg) saturate(1.1) brightness(0.75); }
  [data-theme="black"]     #sticks { filter: hue-rotate(330deg) saturate(1.1) brightness(0.75); }
  [data-theme="light"]     #sticks { filter: grayscale(1) brightness(0.5); }
  [data-theme="midnight"]  #sticks { filter: hue-rotate(182deg) saturate(1.1); }
  [data-theme="dracula"]   #sticks { filter: hue-rotate(238deg) saturate(1.2); }
  [data-theme="terminal"]  #sticks { filter: hue-rotate(118deg) saturate(1.2); }
  [data-theme="ocean"]     #sticks { filter: hue-rotate(178deg) saturate(1.2); }
  [data-theme="sunset"]    #sticks { filter: hue-rotate(6deg)   saturate(1.2); }
  [data-theme="forest"]    #sticks { filter: hue-rotate(118deg) saturate(1.2); }
  [data-theme="purple"]    #sticks { filter: hue-rotate(248deg) saturate(1.2); }
  [data-theme="neon"]      #sticks { filter: hue-rotate(166deg) saturate(1.2); }
  [data-theme="rose"]      #sticks { filter: hue-rotate(334deg) saturate(1.1); }
  [data-theme="amber"]     #sticks { filter: hue-rotate(20deg)  saturate(1.2); }
  [data-theme="solarized"] #sticks { filter: hue-rotate(162deg) saturate(0.9); }

  /* ---- compact mode ---- */
  body.compact .card { padding: 0.85rem 1rem; }
  body.compact .card h2 { font-size: 1rem; margin-bottom: 0.6rem; }
  body.compact .stat-card { padding: 0.65rem 0.85rem; }
  body.compact .stat-card .val { font-size: 1.3rem; }
  body.compact .tabs { gap: 0.15rem; }
  body.compact .tab { padding: 0.5rem 1rem; font-size: 0.82rem; }

  /* ---- no-animations ---- */
  body.no-anim *, body.no-anim *::before, body.no-anim *::after {
    transition: none !important;
    animation: none !important;
  }

  /* ---- settings panel ---- */
  .settings-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
    gap: 1.25rem;
    margin-bottom: 1.5rem;
  }
  .settings-field { display: flex; flex-direction: column; gap: 0.35rem; }
  .settings-field label { font-size: 0.82rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.06em; }
  .settings-field select,
  .settings-field input[type="text"],
  .settings-field input[type="password"] {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 4px;
    color: var(--text);
    padding: 0.4rem 0.6rem;
    font-family: var(--font);
    font-size: 0.88rem;
  }
  .settings-field input[type="color"] {
    width: 100%;
    height: 36px;
    border: 1px solid var(--border);
    border-radius: 4px;
    background: var(--surface);
    cursor: pointer;
    padding: 2px 4px;
  }
  .settings-toggle { display: flex; align-items: center; gap: 0.6rem; margin-top: 0.15rem; }
  .settings-toggle input[type="checkbox"] { width: 16px; height: 16px; accent-color: var(--accent); cursor: pointer; }
  .settings-toggle span { font-size: 0.88rem; color: var(--text); }
  .settings-preview {
    font-size: 0.78rem;
    color: var(--muted);
    margin-top: 0.5rem;
    font-style: italic;
  }

  /* ================================================================
     RESPONSIVE – tablets and mobile phones
     ================================================================ */

  /* ---- Tablet (≤ 768 px) ---- */
  @media (max-width: 768px) {
    header { padding: 0.65rem 1.25rem; gap: 1rem; }
    .container { padding: 1rem; }
    .log-wrap { height: 320px; }
    .sticks-corner { width: 105px; }
  }

  /* ---- Mobile (≤ 640 px) ---- */
  @media (max-width: 640px) {
    /* Header: tighter padding */
    header { padding: 0.55rem 0.85rem; gap: 0.65rem; }
    .status-badge { font-size: 0.78rem; }

    /* Container: less horizontal padding */
    .container { padding: 0.75rem 0.65rem; }

    /* Tabs: single scrollable row, no wrapping */
    .tabs {
      overflow-x: auto;
      -webkit-overflow-scrolling: touch;
      flex-wrap: nowrap;
      scrollbar-width: none;       /* Firefox */
    }
    .tabs::-webkit-scrollbar { display: none; }
    .tab {
      padding: 0.5rem 0.85rem;
      font-size: 0.82rem;
      flex-shrink: 0;
      white-space: nowrap;
    }

    /* Cards: tighter padding */
    .card { padding: 0.9rem 0.75rem; }
    .card h2 { font-size: 0.95rem; margin-bottom: 0.75rem; }

    /* Buttons: slightly narrower */
    .btn { padding: 0.55rem 0.9rem; font-size: 0.85rem; }

    /* Stat grid: 2 columns */
    .stat-grid { grid-template-columns: repeat(2, 1fr); gap: 0.65rem; }
    .stat-card { padding: 0.7rem 0.5rem; }
    .stat-card .val { font-size: 1.1rem; }

    /* Form / settings grids: single column */
    .form-grid    { grid-template-columns: 1fr; }
    .settings-grid { grid-template-columns: 1fr; }

    /* Log terminal: shorter, smaller text */
    .log-wrap { height: 260px; font-size: 0.75rem; padding: 0.5rem 0.65rem; }

    /* Device tables: horizontal scroll */
    .table-wrap { overflow-x: auto; -webkit-overflow-scrolling: touch; }
    .device-table { min-width: 420px; }

    /* Log filter bar: narrower search input */
    .log-filter-bar input[type="text"] { width: 110px; }

    /* Sticks: leave fixed position but shrink further */
    .sticks-corner { width: 80px; opacity: 0.23; }
    /* Version badge: hidden on mobile — version shown in footer text instead */
    .ver-badge { display: none !important; }
    /* Footer: stack as column so sticks appears below the text line */
    footer {
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 0.6rem;
      padding: 1rem 0.75rem;
    }
    /* Show version in footer */
    .footer-ver { display: inline; }
    /* Sticks: switch from fixed corner to static, centred below footer text */
    .sticks-corner {
      position: static;
      display: block;
      width: clamp(80px, 30vw, 130px);
      opacity: 0.23;
      margin: 0 auto;
      pointer-events: none;
    }
  }

  /* ---- Small phones (≤ 400 px) ---- */
  @media (max-width: 400px) {
    /* Single column stat grid */
    .stat-grid { grid-template-columns: 1fr; }
  }
</style>
</head>
<body>
<header>
  <img id="logo" src="__LOGO__" alt="ModernJVS">
  <h1>WebUI<span class="ver-badge" id="verBadge"></span></h1>
  <div class="status-badge">
    <span class="dot" id="statusDot"></span>
    <span id="statusText">Loading…</span>
  </div>
</header>

<div class="container">
  <div class="tabs">
    <button class="tab active" onclick="showTab('dashboard', this)">Dashboard</button>
    <button class="tab" onclick="showTab('config', this)">Configuration</button>
    <button class="tab" onclick="showTab('monitor', this)">Monitor &amp; Logs</button>
    <button class="tab" onclick="showTab('profiles', this)">Profiles</button>
    <button class="tab" onclick="showTab('devices', this)">Devices</button>
    <button class="tab" onclick="showTab('diagnostics', this)">&#x26A0; Diagnostics</button>
    <button class="tab" onclick="showTab('webui-settings', this)">&#9881; WebUI Settings</button>
    <button class="tab" onclick="showTab('terminal', this)">&#128279; Terminal</button>
  </div>

  <!-- ====== DASHBOARD ====== -->
  <div id="panel-dashboard" class="panel active">
    <div id="dashAlert" class="alert"></div>

    <div class="card">
      <h2>Service Control</h2>
      <div class="control-row">
        <button class="btn btn-start"   onclick="serviceAction('start')">▶ Start</button>
        <button class="btn btn-stop"    onclick="serviceAction('stop')">■ Stop</button>
        <button class="btn btn-restart" onclick="serviceAction('restart')">↺ Restart</button>
        <button class="btn btn-refresh" onclick="refreshDashboard()">⟳ Refresh Status</button>
      </div>
    </div>

    <div class="card">
      <h2>System Overview</h2>
      <div class="stat-grid" id="statGrid">
        <div class="stat-card"><div class="val" id="svcState">—</div><div class="lbl">Service State</div></div>
        <div class="stat-card"><div class="val" id="svcPid">—</div><div class="lbl">PID</div></div>
        <div class="stat-card"><div class="val" id="svcUptime">—</div><div class="lbl">Active Since</div></div>
        <div class="stat-card"><div class="val" id="currentIO">—</div><div class="lbl">Emulated I/O</div></div>
        <div class="stat-card"><div class="val" id="currentIO2">—</div><div class="lbl">Secondary I/O</div></div>
        <div class="stat-card"><div class="val" id="currentGame">—</div><div class="lbl">Current Game</div></div>
        <div class="stat-card"><div class="val" id="currentDevice">—</div><div class="lbl">Device Path</div></div>
        <div class="stat-card"><div class="val" id="jvsConnection">—</div><div class="lbl">JVS Connection</div></div>
      </div>
    </div>

    <div class="card">
      <h2>Player Assignments</h2>
      <div class="stat-grid" id="playerSlots">
        <div class="stat-card"><div class="val" style="font-size:0.85rem;word-break:break-all;">—</div><div class="lbl">Player 1</div></div>
        <div class="stat-card"><div class="val" style="font-size:0.85rem;word-break:break-all;">—</div><div class="lbl">Player 2</div></div>
        <div class="stat-card"><div class="val" style="font-size:0.85rem;word-break:break-all;">—</div><div class="lbl">Player 3</div></div>
        <div class="stat-card"><div class="val" style="font-size:0.85rem;word-break:break-all;">—</div><div class="lbl">Player 4</div></div>
      </div>
    </div>

    <div class="card">
      <h2>Pi System Usage <button class="btn btn-refresh btn-xs" onclick="refreshSysinfo()" style="margin-left:0.5rem;vertical-align:middle;">⟳</button></h2>
      <div class="usage-row">
        <div class="usage-header">
          <span class="usage-label">CPU Usage</span>
          <span class="usage-value" id="siCpu">—</span>
        </div>
        <div class="progress"><div class="progress-bar" id="siCpuBar" style="width:0%"></div></div>
      </div>
      <div class="usage-row">
        <div class="usage-header">
          <span class="usage-label">Memory</span>
          <span class="usage-value" id="siMem">—</span>
        </div>
        <div class="progress"><div class="progress-bar" id="siMemBar" style="width:0%"></div></div>
      </div>
      <div class="usage-row">
        <div class="usage-header">
          <span class="usage-label">CPU Temperature</span>
          <span class="usage-value" id="siTemp">—</span>
        </div>
        <div class="progress"><div class="progress-bar" id="siTempBar" style="width:0%"></div></div>
      </div>
      <div class="usage-row">
        <div class="usage-header">
          <span class="usage-label">Disk Usage (/)</span>
          <span class="usage-value" id="siDisk">—</span>
        </div>
        <div class="progress"><div class="progress-bar" id="siDiskBar" style="width:0%"></div></div>
      </div>
      <div class="sysinfo-footer">Load Average: <span id="siLoad">—</span></div>
      <div class="ip-info">Access WebUI from other devices: <span id="siIP">—</span></div>
    </div>
  </div>

  <!-- ====== CONFIG ====== -->
  <div id="panel-config" class="panel">
    <div id="cfgAlert" class="alert"></div>
    <div class="card">
      <h2>Game &amp; I/O Configuration</h2>
      <div class="form-grid">
        <div class="field">
          <label>Emulated I/O Board</label>
          <select id="cfgEmulate"></select>
        </div>
        <div class="field">
          <label>Default Game</label>
          <select id="cfgGame"></select>
        </div>
        <div class="field">
          <label>Device Path</label>
          <input type="text" id="cfgDevice" placeholder="/dev/ttyUSB0">
        </div>
        <div class="field">
          <label>Sense Line Type (0/1)</label>
          <select id="cfgSense">
            <option value="0">0 – USB RS485, no sense line</option>
            <option value="1">1 – USB RS485, with sense line</option>
          </select>
        </div>
        <div class="field">
          <label>Sense Line GPIO Pin</label>
          <input type="number" id="cfgPin" min="1" max="40" placeholder="26">
        </div>
        <div class="field">
          <label>Debug Mode (0/1/2)</label>
          <select id="cfgDebug">
            <option value="0">0 – Off</option>
            <option value="1">1 – JVS outputs</option>
            <option value="2">2 – Raw packets</option>
          </select>
        </div>
        <div class="field">
          <label>Auto Controller Detection</label>
          <select id="cfgAutoCtrl">
            <option value="1">Enabled</option>
            <option value="0">Disabled</option>
          </select>
        </div>
        <div class="field">
          <label>Analog Deadzone – Player 1</label>
          <input type="number" id="cfgDz1" step="0.01" min="0" max="0.5" placeholder="0.2">
        </div>
        <div class="field">
          <label>Analog Deadzone – Player 2</label>
          <input type="number" id="cfgDz2" step="0.01" min="0" max="0.5" placeholder="0.2">
        </div>
        <div class="field">
          <label>Analog Deadzone – Player 3</label>
          <input type="number" id="cfgDz3" step="0.01" min="0" max="0.5" placeholder="0.2">
        </div>
        <div class="field">
          <label>Analog Deadzone – Player 4</label>
          <input type="number" id="cfgDz4" step="0.01" min="0" max="0.5" placeholder="0.2">
        </div>
        <div class="field">
          <label>Secondary I/O Board (EMULATE_SECOND)</label>
          <select id="cfgEmulate2"></select>
        </div>
      </div>
      <br>
      <div class="control-row">
        <button class="btn btn-save" onclick="saveConfig()">💾 Save Configuration</button>
        <button class="btn btn-restart" onclick="saveConfigAndRestart()">💾↺ Save &amp; Restart Service</button>
        <button class="btn btn-refresh" onclick="loadConfig()">⟳ Reload from Disk</button>
        <button class="btn btn-danger" onclick="resetConfig()">↩ Reset to Defaults</button>
      </div>
    </div>
  </div>

  <!-- ====== MONITOR ====== -->
  <div id="panel-monitor" class="panel">
    <div class="card">
      <h2>Live Log Monitor</h2>
      <div class="log-controls">
        <button class="btn btn-refresh" onclick="fetchLogs()">⟳ Refresh</button>
        <button class="btn btn-refresh btn-xs" onclick="downloadLogs()" style="background:var(--border);">⬇ Download</button>
        <label>
          <input type="checkbox" id="autoRefresh" onchange="toggleAutoRefresh()"> Auto-refresh (5s)
        </label>
        <label>
          Lines:
          <select id="logLines" style="background:var(--surface);border:1px solid var(--border);border-radius:4px;color:var(--text);padding:0.25rem 0.5rem;">
            <option value="50">50</option>
            <option value="100" selected>100</option>
            <option value="200">200</option>
            <option value="500">500</option>
          </select>
        </label>
        <label>
          <input type="checkbox" id="scrollBottom" checked> Scroll to bottom
        </label>
      </div>
      <div class="log-wrap" id="logBox"></div>
    </div>

    <div class="card">
      <h2>Log Filter</h2>
      <div class="log-filter-bar" style="margin-bottom:0.75rem;">
        <span style="font-size:0.82rem;color:var(--muted);">Filter:</span>
        <select id="logFilter" onchange="applyJvsFilter()">
          <option value="all">All Messages</option>
          <option value="errors">Errors &amp; Critical</option>
          <option value="warnings">Warnings</option>
          <option value="jvs" selected>JVS Activity</option>
          <option value="controllers">Controllers</option>
        </select>
        <input type="text" id="logSearch" placeholder="Search…" oninput="applyJvsFilter()">
        <button class="btn btn-refresh btn-xs" onclick="clearLogFilter()">✕ Clear</button>
      </div>
      <div id="logFilterHint" style="display:none;font-size:0.8rem;color:var(--yellow);margin-bottom:0.5rem;padding:0.35rem 0.5rem;border-left:3px solid var(--yellow);background:rgba(255,200,0,0.06);">
        ⚠ <strong>JVS Activity</strong> shows <code style="color:var(--accent2)">CMD_</code> debug messages —
        these are only logged when <strong>Debug Mode</strong> is set to <strong>1</strong> or <strong>2</strong>
        in the <a href="#" onclick="showTab('config',document.querySelector('[onclick*=showTab].tab'));return false;"
          style="color:var(--accent)">Configuration</a> tab.
      </div>
      <div class="log-wrap" id="jvsBox" style="height:340px;"></div>
    </div>

    <div class="card">
      <h2>Audit Log <button class="btn btn-refresh btn-xs" onclick="loadAuditLog()" style="margin-left:0.5rem;vertical-align:middle;">⟳ Refresh</button></h2>
      <p style="font-size:0.82rem;color:var(--muted);margin-bottom:0.75rem;">WebUI actions: config changes, service restarts, logins, Bluetooth pairings, profile edits.</p>
      <div class="log-wrap" id="auditLogBox" style="height:300px;"></div>
    </div>
  </div>

  <!-- ====== PROFILES ====== -->
  <div id="panel-profiles" class="panel">
    <div class="card">
      <h2>Profile Editor</h2>
      <div id="profilesAlert" class="alert"></div>
      <div style="display:flex;gap:0.5rem;margin-bottom:1rem;flex-wrap:wrap;align-items:center;">
        <button class="btn btn-xs" id="profTabGames"   onclick="setProfileTab('games')"   style="background:var(--accent);color:#000;">Games</button>
        <button class="btn btn-xs" id="profTabDevices" onclick="setProfileTab('devices')" style="">Devices</button>
        <button class="btn btn-xs" id="profTabIos"     onclick="setProfileTab('ios')"     style="">I/O Boards</button>
        <span style="flex:1"></span>
        <button class="btn btn-xs btn-refresh" onclick="newProfileFile()">+ New File</button>
        <label class="btn btn-xs" style="cursor:pointer;margin:0;">
          ⬆ Upload
          <input type="file" id="profileUploadInputTop" style="display:none;" onchange="uploadProfile(this)">
        </label>
      </div>
      <div class="table-wrap">
      <table class="device-table" id="profilesTable">
        <thead><tr><th>Name</th><th>Actions</th></tr></thead>
        <tbody id="profilesTableBody"><tr><td colspan="2" style="color:var(--muted)">Loading…</td></tr></tbody>
      </table>
      </div>
      <div id="profileEditorWrap" style="display:none;margin-top:1.25rem;padding-top:1rem;border-top:1px solid var(--border);">
        <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:0.5rem;flex-wrap:wrap;">
          <span style="font-size:0.82rem;color:var(--muted);">Editing:</span>
          <code id="profileEditName" style="color:var(--accent2);font-family:monospace;font-size:0.9rem;"></code>
          <input type="text" id="profileNewName" placeholder="new-filename" style="display:none;background:var(--surface);border:1px solid var(--border);border-radius:4px;color:var(--text);padding:0.25rem 0.5rem;font-family:monospace;font-size:0.85rem;">
        </div>
        <textarea id="profileEditContent" style="width:100%;box-sizing:border-box;min-height:300px;background:var(--surface);border:1px solid var(--border);border-radius:4px;color:var(--text);font-family:monospace;font-size:0.85rem;padding:0.5rem;resize:vertical;"></textarea>
        <div style="display:flex;gap:0.5rem;margin-top:0.75rem;flex-wrap:wrap;">
          <button class="btn btn-save" onclick="saveProfile()">💾 Save</button>
          <button class="btn btn-refresh" onclick="newProfileFile()">+ New File</button>
          <label class="btn" style="cursor:pointer;">
            ⬆ Upload File
            <input type="file" id="profileUploadInput" style="display:none;" onchange="uploadProfile(this)">
          </label>
          <button class="btn btn-danger" onclick="closeProfileEditor()">✕ Close</button>
        </div>
      </div>
    </div>
  </div>

  <!-- ====== DEVICES ====== -->
  <div id="panel-devices" class="panel">
    <div style="margin-bottom:0.75rem;text-align:right;">
      <button class="btn btn-refresh" onclick="loadDevices();loadBluetoothSection();populateInputTesterDevices();">⟳ Refresh All</button>
    </div>
    <div class="card">
      <h2>Connected Input Devices</h2>
      <p style="font-size:0.83rem;color:var(--muted);margin-bottom:1rem;">Shows all <code style="color:var(--accent2);font-family:monospace">/dev/input/event*</code> nodes currently present on the system.</p>
      <div class="table-wrap">
      <table class="device-table">
        <thead><tr><th>Event Node</th><th>Device Name</th><th>Status</th></tr></thead>
        <tbody id="deviceTableBody"><tr><td colspan="3" style="color:var(--muted)">Loading…</td></tr></tbody>
      </table>
      </div>
    </div>

    <div class="card" style="margin-top:1rem;">
      <h2>Bluetooth Controllers</h2>
      <p style="font-size:0.83rem;color:var(--muted);margin-bottom:1rem;">Add and remove Bluetooth controllers such as Wii Remotes.</p>
      <div id="btAlert" class="alert"></div>
      <div id="btStatusBanner" class="alert" style="display:none;"></div>

      <div id="btPairedSection">
        <h3 style="font-size:0.85rem;color:var(--muted);font-weight:600;text-transform:uppercase;letter-spacing:0.06em;margin-bottom:0.5rem;">Paired Devices</h3>
        <div class="table-wrap">
        <table class="device-table">
          <thead><tr><th>Device Name</th><th>MAC Address</th><th>Status</th><th></th></tr></thead>
          <tbody id="btPairedBody"><tr><td colspan="4" style="color:var(--muted)">Loading…</td></tr></tbody>
        </table>
        </div>
      </div>

      <div id="btScanSection" style="margin-top:1.25rem;padding-top:1rem;border-top:1px solid var(--border);">
        <h3 style="font-size:0.85rem;color:var(--muted);font-weight:600;text-transform:uppercase;letter-spacing:0.06em;margin-bottom:0.5rem;">Add Bluetooth Controller</h3>
        <p style="font-size:0.82rem;color:var(--muted);margin-bottom:0.75rem;">
          For Wii Remotes: press the red <strong>SYNC</strong> button inside the battery compartment, or hold <strong>1+2</strong> until the lights flash, then click Scan.
        </p>
        <div style="display:flex;gap:0.5rem;align-items:center;flex-wrap:wrap;margin-bottom:0.75rem;">
          <button class="btn btn-refresh" id="btScanBtn" onclick="btScan()">&#x1F50D; Scan for Devices (8s)</button>
          <span id="btScanStatus" style="font-size:0.82rem;color:var(--muted);"></span>
        </div>
        <div class="table-wrap">
        <table class="device-table" id="btScanTable" style="display:none;">
          <thead><tr><th>Device Name</th><th>MAC Address</th><th></th></tr></thead>
          <tbody id="btScanBody"></tbody>
        </table>
        </div>
      </div>
    </div>

    <div class="card" id="inputTesterCard" style="margin-top:1rem;">
      <h2>Live Input Tester</h2>
      <p style="font-size:0.83rem;color:var(--muted);margin-bottom:1rem;">
        Select a controller to monitor its button presses and axis values in real time.
      </p>
      <div style="display:flex;gap:0.75rem;align-items:center;flex-wrap:wrap;margin-bottom:1rem;">
        <select id="inputTesterDevice" style="background:var(--surface);border:1px solid var(--border);border-radius:4px;color:var(--text);padding:0.35rem 0.6rem;"></select>
        <button class="btn btn-start" onclick="startInputTest()">&#9654; Start</button>
        <button class="btn btn-stop"  onclick="stopInputTest()" disabled id="inputTesterStopBtn">&#9632; Stop</button>
      </div>
      <div id="inputTesterStatus" style="font-size:0.82rem;color:var(--muted);margin-bottom:0.75rem;"></div>
      <div id="inputTesterDisplay" style="font-family:monospace;font-size:0.82rem;min-height:60px;"></div>
    </div>
  </div>

  <!-- ====== DIAGNOSTICS ====== -->
  <div id="panel-diagnostics" class="panel">

    <!-- Serial Port Test -->
    <div class="card">
      <h2>Serial Port Test</h2>
      <p style="font-size:0.83rem;color:var(--muted);margin-bottom:1rem;">
        Try to open the JVS serial port at 115200 8N1 and report the result. Useful when the device is
        not responding and you want to confirm the path is correct and accessible.
      </p>
      <div id="diagSerialAlert" class="alert"></div>
      <div style="display:flex;gap:0.6rem;align-items:center;flex-wrap:wrap;margin-bottom:0.75rem;">
        <select id="diagSerialPort" style="background:var(--surface);border:1px solid var(--border);border-radius:4px;color:var(--text);padding:0.35rem 0.6rem;min-width:180px;">
          <option value="">— loading ports… —</option>
        </select>
        <input type="text" id="diagSerialCustom" placeholder="or type a path, e.g. /dev/ttyUSB0"
               style="flex:1;min-width:200px;background:var(--surface);border:1px solid var(--border);border-radius:4px;color:var(--text);padding:0.35rem 0.6rem;">
        <button class="btn btn-start" onclick="runSerialTest()">&#9654; Test Port</button>
      </div>
      <div id="diagSerialResult" style="font-family:monospace;font-size:0.84rem;min-height:2rem;"></div>
    </div>

    <!-- JVS Bus -->
    <div class="card" style="margin-top:1rem;">
      <h2>JVS Bus</h2>
      <p style="font-size:0.83rem;color:var(--muted);margin-bottom:1rem;">
        Two tools for inspecting the JVS bus.
        <strong>Probe Bus</strong> sends a
        <code style="color:var(--accent2);font-family:monospace">RESET</code> +
        <code style="color:var(--accent2);font-family:monospace">ASSIGN_ADDR</code>
        broadcast and listens for 2&nbsp;s — any response bytes confirm a connected,
        powered-on board.
        <strong>Monitor Bus</strong> listens passively for 5&nbsp;seconds without sending
        anything, showing whatever packets the arcade board is already transmitting.
        Both tools auto-detect a running service and report bus status without touching
        the port. When the service is stopped, the sense line is floated before listening.
      </p>
      <div id="diagJvsAlert" class="alert"></div>
      <div style="display:flex;gap:0.6rem;align-items:center;flex-wrap:wrap;margin-bottom:0.75rem;">
        <select id="diagJvsPort" style="background:var(--surface);border:1px solid var(--border);border-radius:4px;color:var(--text);padding:0.35rem 0.6rem;min-width:180px;">
          <option value="">— loading ports… —</option>
        </select>
        <input type="text" id="diagJvsCustom" placeholder="or type a path, e.g. /dev/ttyUSB0"
               style="flex:1;min-width:200px;background:var(--surface);border:1px solid var(--border);border-radius:4px;color:var(--text);padding:0.35rem 0.6rem;">
        <button class="btn btn-restart" onclick="runJvsBusProbe()">&#9654; Probe Bus</button>
        <button class="btn btn-restart" onclick="runJvsBusMonitor()">&#128065; Monitor Bus</button>
        <button class="btn btn-stop"  onclick="jvsServiceAction('stop')">&#9632; Stop Service</button>
        <button class="btn btn-start" onclick="jvsServiceAction('start')">&#9654; Start Service</button>
      </div>
      <div id="diagJvsResult" style="font-family:monospace;font-size:0.84rem;min-height:2rem;"></div>
    </div>

    <!-- GPIO Sense Line Test -->
    <div class="card" style="margin-top:1rem;">
      <h2>GPIO Sense Line Test</h2>
      <p style="font-size:0.83rem;color:var(--muted);margin-bottom:1rem;">
        Read the current logic level of the configured sense-line GPIO pin via the Linux GPIO character device.
        Useful when first wiring the sense line — confirms the pin is reachable and reports HIGH or LOW.
        <strong>Note:</strong> if the ModernJVS service is currently <strong>running</strong> it holds the GPIO
        line exclusively; the read will return <em>IN USE</em> rather than a logic level.
        Stop the service first to read or manually drive the pin.
        <br><br>
        Use <strong>Set HIGH</strong> / <strong>Set LOW</strong> to manually drive the pin to a known state
        for the chosen duration (e.g. to verify wiring with a multimeter), then the line is released automatically.
      </p>
      <div id="diagGpioAlert" class="alert"></div>
      <div style="display:flex;gap:0.6rem;align-items:center;flex-wrap:wrap;margin-bottom:0.75rem;">
        <label style="font-size:0.85rem;color:var(--muted);">Pin (header #):</label>
        <input type="number" id="diagGpioPin" min="1" max="40" placeholder="26"
               style="width:80px;background:var(--surface);border:1px solid var(--border);border-radius:4px;color:var(--text);padding:0.35rem 0.6rem;">
        <label style="font-size:0.85rem;color:var(--muted);">Duration (s):</label>
        <input type="number" id="diagGpioDuration" min="1" max="60" value="3"
               style="width:70px;background:var(--surface);border:1px solid var(--border);border-radius:4px;color:var(--text);padding:0.35rem 0.6rem;">
        <button class="btn btn-start"   onclick="runGpioTest()">&#9654; Read Pin</button>
        <button class="btn btn-restart" onclick="setGpioPin('high')">&#9650; Set HIGH</button>
        <button class="btn btn-stop"    onclick="setGpioPin('low')">&#9660; Set LOW</button>
      </div>
      <div id="diagGpioResult" style="font-family:monospace;font-size:0.84rem;min-height:2rem;"></div>
    </div>

    <!-- Available Serial Devices -->
    <div class="card" style="margin-top:1rem;">
      <h2>Available Serial Devices</h2>
      <p style="font-size:0.83rem;color:var(--muted);margin-bottom:1rem;">
        All <code style="color:var(--accent2);font-family:monospace">/dev/ttyUSB*</code>,
        <code style="color:var(--accent2);font-family:monospace">/dev/ttyAMA*</code>, and
        <code style="color:var(--accent2);font-family:monospace">/dev/ttyS*</code> nodes currently
        present on the system.
      </p>
      <div id="diagPortListWrap" style="font-family:monospace;font-size:0.84rem;"></div>
    </div>

    <!-- USB Device Inspector -->
    <div class="card" style="margin-top:1rem;">
      <h2>USB Device Inspector <button class="btn btn-refresh btn-xs" onclick="loadUsbDevices()" style="margin-left:0.5rem;vertical-align:middle;">⟳</button></h2>
      <p style="font-size:0.83rem;color:var(--muted);margin-bottom:1rem;">
        All connected USB devices read from
        <code style="color:var(--accent2);font-family:monospace">/sys/bus/usb/devices/</code>.
        Known RS-485/serial adapters are highlighted. Shows the currently bound kernel driver —
        useful when a <code style="color:var(--accent2);font-family:monospace">/dev/ttyUSB*</code>
        node is not appearing.
      </p>
      <div id="diagUsbWrap" style="font-size:0.84rem;"></div>
    </div>

  </div>

  <!-- ====== APPEARANCE ====== -->
  <div id="panel-webui-settings" class="panel">
    <div class="card">
      <h2>Theme</h2>
      <div class="settings-grid">
        <div class="settings-field">
          <label>Colour Theme</label>
          <select id="stTheme">
            <option value="black">Pure Dark (default)</option>
            <option value="dark">Dark</option>
            <option value="light">Light</option>
            <option value="midnight">Midnight Blue</option>
            <option value="dracula">Dracula</option>
            <option value="terminal">Green Terminal</option>
            <option value="ocean">Ocean Deep</option>
            <option value="sunset">Sunset</option>
            <option value="forest">Forest</option>
            <option value="purple">Purple Night</option>
            <option value="neon">Neon Cyan</option>
            <option value="rose">Rose</option>
            <option value="amber">Amber</option>
            <option value="solarized">Solarized Dark</option>
          </select>
          <div class="settings-preview">Base colour theme</div>
        </div>
      </div>
    </div>

    <div class="card">
      <h2>Layout &amp; Behaviour</h2>
      <div class="settings-grid">
        <div class="settings-field">
          <label>Display Density</label>
          <div class="settings-toggle">
            <input type="checkbox" id="stCompact">
            <span>Compact mode (reduce card padding and spacing)</span>
          </div>
        </div>
        <div class="settings-field">
          <label>Animations</label>
          <div class="settings-toggle">
            <input type="checkbox" id="stNoAnim">
            <span>Disable all CSS transitions and animations</span>
          </div>
        </div>
      </div>
    </div>

    <div class="card">
      <h2>&#128274; Password Protection</h2>
      <p id="pwStatus" style="margin-bottom:1rem;font-size:0.88rem;"></p>
      <div class="settings-grid">
        <div class="settings-field">
          <label>New Password</label>
          <input type="password" id="pwNew" autocomplete="new-password" maxlength="128"
                 placeholder="Enter new password">
        </div>
        <div class="settings-field">
          <label>Confirm Password</label>
          <input type="password" id="pwConfirm" autocomplete="new-password" maxlength="128"
                 placeholder="Re-enter new password">
        </div>
      </div>
      <div id="pwMsg" style="font-size:0.85rem;min-height:1.2em;margin-bottom:0.75rem;"></div>
      <div class="control-row">
        <button class="btn btn-save" onclick="setPassword()">&#128190; Set Password</button>
        <button class="btn btn-stop" id="pwClearBtn" onclick="clearPassword()" style="display:none">&#128275; Clear Password</button>
      </div>
      <div class="settings-preview" style="margin-top:0.75rem;">
        If you forget the password, remove <code style="color:var(--muted)">/etc/modernjvs/webui-password</code> via SSH to reset it.
      </div>
    </div>

    <div class="card">
      <h2>WebUI Process</h2>
      <div class="control-row">
        <button class="btn btn-restart" onclick="restartWebUI()">↺ Restart WebUI</button>
      </div>
      <div id="webuiRestartMsg" style="display:none;margin-top:0.75rem;font-size:0.88rem;color:var(--muted)"></div>
    </div>

    <div class="card">
      <h2>&#x23FB; System Power</h2>
      <p style="font-size:0.82rem;color:var(--muted);margin-bottom:0.75rem;">Restart or shut down the Raspberry Pi. The WebUI will become unreachable until the Pi boots again.</p>
      <div class="control-row">
        <button class="btn btn-restart" onclick="systemReboot()">&#x21BA; Restart Pi</button>
        <button class="btn btn-stop" onclick="systemShutdown()">&#x23FB; Shutdown Pi</button>
      </div>
      <div id="systemPowerMsg" style="font-size:0.85rem;min-height:1.2em;margin-top:0.5rem;"></div>
    </div>

    <div class="card">
      <h2>&#128274; Active Sessions</h2>
      <p style="font-size:0.82rem;color:var(--muted);margin-bottom:0.75rem;">Each entry is a logged-in browser. Token shown as first 8 characters only.</p>
      <div id="sessionsList" style="margin-bottom:0.75rem;"></div>
      <div class="control-row">
        <button class="btn btn-refresh btn-xs" onclick="loadSessions()">⟳ Refresh</button>
        <button class="btn btn-stop" onclick="invalidateOtherSessions()">&#128274; Log Out All Other Devices</button>
      </div>
      <div id="sessionsMsg" style="font-size:0.85rem;min-height:1.2em;margin-top:0.5rem;"></div>
    </div>

    <div class="control-row">
      <button class="btn btn-save" onclick="saveAppearanceSettings()">&#128190; Save &amp; Apply</button>
      <button class="btn btn-refresh" onclick="resetAppearanceSettings()">&#8635; Reset to Defaults</button>
    </div>
  </div>

  <!-- ====== TERMINAL ====== -->
  <div id="panel-terminal" class="panel" style="padding:0 1rem 1rem;">
    <div class="card">
      <h2>&#128279; SSH Terminal</h2>
      <div class="settings-grid" style="grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:0.75rem;margin-bottom:1rem;">
        <div class="settings-field">
          <label>Host</label>
          <input type="text" id="termHost" value="localhost" maxlength="253" style="width:100%;padding:0.4rem 0.6rem;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);color:var(--text);">
        </div>
        <div class="settings-field">
          <label>Port</label>
          <input type="number" id="termPort" value="22" min="1" max="65535" style="width:100%;padding:0.4rem 0.6rem;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);color:var(--text);">
        </div>
        <div class="settings-field">
          <label>Username</label>
          <input type="text" id="termUser" value="pi" maxlength="64" style="width:100%;padding:0.4rem 0.6rem;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);color:var(--text);">
        </div>
      </div>
      <div class="control-row" style="margin-bottom:0.75rem;">
        <button class="btn btn-start" id="termConnectBtn" onclick="termConnect()">&#9654; Connect</button>
        <button class="btn btn-stop"  id="termDisconnectBtn" onclick="termDisconnect()" style="display:none;">&#9632; Disconnect</button>
      </div>
      <div id="termMsg" style="font-size:0.85rem;min-height:1.2em;margin-bottom:0.5rem;color:var(--muted);"></div>
    </div>
    <div class="card" style="padding:0;">
      <div id="terminal-container" style="width:100%;height:420px;background:#000;border-radius:var(--radius);overflow:hidden;"></div>
    </div>
  </div>
</div>
<footer><span>ModernJVS <span id="footerVer" class="footer-ver"></span>WebUI &mdash; <a href="https://github.com/dazzaXx/ModernJVS" target="_blank">github.com/dazzaXx/ModernJVS</a></span>
<div id="footerSysInfo" style="display:none;font-size:0.75rem;color:var(--muted);"></div>
<div id="footerPiModel" style="display:none;font-size:0.75rem;color:var(--muted);"></div>
<img id="sticks" src="__STICKS__" alt="" class="sticks-corner">
</footer>

<script>
// ---- Constants ----
// Temperature scale reference: Pi throttles at ~80 °C, absolute hardware max ~85 °C
const MAX_TEMP_C = 85;

// ---- Tab navigation ----
function showTab(name, btn) {
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.getElementById('panel-' + name).classList.add('active');
  btn.classList.add('active');
  if (name === 'monitor') { fetchLogs(); loadAuditLog(); }
  if (name === 'config') loadConfig();
  if (name === 'profiles') loadProfiles();
  if (name === 'devices') { loadDevices(); loadBluetoothSection(); populateInputTesterDevices(); }
  if (name !== 'devices') stopInputTest(); // stop streaming when leaving the Devices tab
  if (name !== 'diagnostics') cancelDiagTests(); // abort any in-flight diag tests when leaving
  if (name === 'diagnostics') loadDiagnostics();
  if (name === 'webui-settings') { initAppearancePanel(); loadSessions(); }
}

// ---- API helpers ----
async function api(path, opts) {
  try {
    const r = await fetch(path, opts);
    return await r.json();
  } catch(e) { return { error: String(e) }; }
}

function showAlert(id, msg, isErr) {
  const el = document.getElementById(id);
  el.textContent = msg;
  el.className = 'alert ' + (isErr ? 'err' : 'ok');
  setTimeout(() => { el.className = 'alert'; }, 4000);
}

// ---- Dashboard ----
async function refreshDashboard() {
  const d = await api('/api/status');
  if (d.error) { showAlert('dashAlert', 'Error: ' + d.error, true); return; }

  const dot  = document.getElementById('statusDot');
  const txt  = document.getElementById('statusText');
  const running = d.active_state === 'active';

  dot.className = 'dot ' + (running ? 'running' : 'stopped');
  txt.textContent = d.active_state || 'unknown';

  document.getElementById('svcState').textContent    = d.active_state  || '—';
  document.getElementById('svcPid').textContent      = d.main_pid      || '—';
  document.getElementById('svcUptime').textContent   = d.active_since  || '—';
  document.getElementById('currentIO').textContent     = d.config?.emulate         || '—';
  document.getElementById('currentIO2').textContent    = d.config?.emulate_second   || '—';
  document.getElementById('currentGame').textContent   = d.config?.game             || '—';
  document.getElementById('currentDevice').textContent = d.config?.device           || '—';

  const jvsEl = document.getElementById('jvsConnection');
  if (d.jvs_connected === true) {
    jvsEl.textContent = 'Connected';
    jvsEl.style.color = 'var(--green)';
  } else if (d.active_state === 'active') {
    jvsEl.textContent = 'Not connected';
    jvsEl.style.color = 'var(--red)';
  } else {
    jvsEl.textContent = '—';
    jvsEl.style.color = '';
  }

  const players = d.players || [];
  const psEl = document.getElementById('playerSlots');
  const playerMap = {};
  players.forEach(p => { playerMap[p.player] = p.profile; });
  psEl.innerHTML = [1, 2, 3, 4].map(n =>
    `<div class="stat-card"><div class="val" style="font-size:0.85rem;word-break:break-all;">${_escHtml(playerMap[n] || 'Not assigned')}</div><div class="lbl">Player ${n}</div></div>`
  ).join('');
}

async function refreshSysinfo() {
  const d = await api('/api/sysinfo');
  if (d.error) return;

  // CPU
  const cpuPct = d.cpu_pct ?? 0;
  document.getElementById('siCpu').textContent = cpuPct.toFixed(1) + '%';
  const cpuBar = document.getElementById('siCpuBar');
  cpuBar.style.width = Math.min(100, cpuPct) + '%';
  cpuBar.className = 'progress-bar' + (cpuPct > 80 ? ' hot' : cpuPct > 50 ? ' warm' : '');

  // Memory
  const memPct = d.mem_pct ?? 0;
  document.getElementById('siMem').textContent =
    (d.mem_used_mb ?? 0) + ' / ' + (d.mem_total_mb ?? 0) + ' MB (' + memPct.toFixed(0) + '%)';
  const memBar = document.getElementById('siMemBar');
  memBar.style.width = Math.min(100, memPct) + '%';
  memBar.className = 'progress-bar' + (memPct > 80 ? ' hot' : memPct > 60 ? ' warm' : '');

  // Temperature
  const tempEl   = document.getElementById('siTemp');
  const tempBar  = document.getElementById('siTempBar');
  if (d.temp_c !== null && d.temp_c !== undefined) {
    const t = d.temp_c;
    tempEl.textContent = t.toFixed(1) + '\u00b0C';
    const tempPct = Math.min(100, (t / MAX_TEMP_C) * 100);
    tempBar.style.width = tempPct + '%';
    tempBar.className = 'progress-bar' + (t > 70 ? ' hot' : t > 55 ? ' warm' : '');
  } else {
    tempEl.textContent = 'N/A';
    tempBar.style.width = '0%';
    tempBar.className = 'progress-bar';
  }

  // Disk
  const diskPct = d.disk_pct ?? 0;
  document.getElementById('siDisk').textContent =
    (d.disk_used_gb ?? 0).toFixed(1) + ' / ' + (d.disk_total_gb ?? 0).toFixed(1) + ' GB (' + diskPct.toFixed(0) + '%)';
  const diskBar = document.getElementById('siDiskBar');
  diskBar.style.width = Math.min(100, diskPct) + '%';
  diskBar.className = 'progress-bar' + (diskPct > 80 ? ' hot' : diskPct > 60 ? ' warm' : '');

  // Load average & IP
  document.getElementById('siLoad').textContent = d.load_avg || '—';
  if (d.ip_addresses && d.ip_addresses.length) {
    document.getElementById('siIP').textContent =
      d.ip_addresses.map(ip => 'http://' + ip + ':8080').join('  |  ');
  }

  // Footer: libgpiod + kernel on one line, Pi model on the next
  const sysInfoEl  = document.getElementById('footerSysInfo');
  const piModelEl  = document.getElementById('footerPiModel');
  const parts = [];
  if (d.libgpiod_version) parts.push('libgpiod v' + d.libgpiod_version);
  if (d.kernel_version)   parts.push('Kernel ' + d.kernel_version);
  if (parts.length) {
    sysInfoEl.textContent = parts.join('  |  ');
    sysInfoEl.style.display = 'block';
  }
  if (d.pi_model) {
    piModelEl.textContent = d.pi_model;
    piModelEl.style.display = 'block';
  }
}

async function serviceAction(action) {
  const d = await api('/api/control', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({action})
  });
  if (d.error) { showAlert('dashAlert', 'Error: ' + d.error, true); }
  else { showAlert('dashAlert', 'Service ' + action + ' successful.', false); }
  setTimeout(refreshDashboard, 1200);
}

// ---- Config ----
async function loadConfig() {
  const [cfgData, iosData, gamesData] = await Promise.all([
    api('/api/config'),
    api('/api/ios'),
    api('/api/games')
  ]);

  const ioSel = document.getElementById('cfgEmulate');
  ioSel.innerHTML = '';
  (iosData.ios || []).forEach(io => {
    const o = document.createElement('option');
    o.value = io; o.textContent = io;
    if (cfgData.emulate === io) o.selected = true;
    ioSel.appendChild(o);
  });

  const gameSel = document.getElementById('cfgGame');
  gameSel.innerHTML = '';
  (gamesData.games || []).forEach(g => {
    const o = document.createElement('option');
    o.value = g; o.textContent = g;
    if (cfgData.game === g) o.selected = true;
    gameSel.appendChild(o);
  });

  document.getElementById('cfgDevice').value    = cfgData.device  || '/dev/ttyUSB0';
  document.getElementById('cfgSense').value     = cfgData.sense_line_type  ?? '1';
  document.getElementById('cfgPin').value       = cfgData.sense_line_pin   ?? '26';
  document.getElementById('cfgDebug').value     = cfgData.debug_mode  ?? '0';
  document.getElementById('cfgAutoCtrl').value  = cfgData.auto_controller_detection ?? '1';
  document.getElementById('cfgDz1').value = cfgData.deadzone_p1 ?? '0.2';
  document.getElementById('cfgDz2').value = cfgData.deadzone_p2 ?? '0.2';
  document.getElementById('cfgDz3').value = cfgData.deadzone_p3 ?? '0.2';
  document.getElementById('cfgDz4').value = cfgData.deadzone_p4 ?? '0.2';

  const io2Sel = document.getElementById('cfgEmulate2');
  io2Sel.innerHTML = '<option value="">— None —</option>';
  (iosData.ios || []).forEach(io => {
    const o = document.createElement('option');
    o.value = io; o.textContent = io;
    if (cfgData.emulate_second === io) o.selected = true;
    io2Sel.appendChild(o);
  });
}

function validateConfigInputs() {
  const warnings = [];
  const device = document.getElementById('cfgDevice').value.trim();
  if (device && !/^\/dev\/(ttyUSB|ttyAMA)/.test(device))
    warnings.push('DEVICE_PATH "' + device + '" does not look like a serial port (/dev/ttyUSB* or /dev/ttyAMA*).');
  const pin = parseInt(document.getElementById('cfgPin').value, 10);
  if (!isNaN(pin) && (pin < 1 || pin > 40))
    warnings.push('SENSE_LINE_PIN (' + pin + ') is outside the valid Raspberry Pi GPIO range (1–40).');
  [['cfgDz1', 1], ['cfgDz2', 2], ['cfgDz3', 3], ['cfgDz4', 4]].forEach(([id, n]) => {
    if (parseFloat(document.getElementById(id).value) >= 0.5)
      warnings.push('ANALOG_DEADZONE for Player ' + n + ' is at or above the maximum (0.5), which will make the analog stick non-functional.');
  });
  return warnings;
}

async function saveConfig() {
  const warnings = validateConfigInputs();
  if (warnings.length > 0) {
    const msg = 'Configuration warnings:\n\n' + warnings.join('\n') + '\n\nSave anyway?';
    if (!confirm(msg)) return;
  }
  const payload = {
    emulate:                    document.getElementById('cfgEmulate').value,
    game:                       document.getElementById('cfgGame').value,
    device:                     document.getElementById('cfgDevice').value,
    sense_line_type:            document.getElementById('cfgSense').value,
    sense_line_pin:             document.getElementById('cfgPin').value,
    debug_mode:                 document.getElementById('cfgDebug').value,
    auto_controller_detection:  document.getElementById('cfgAutoCtrl').value,
    deadzone_p1:                document.getElementById('cfgDz1').value,
    deadzone_p2:                document.getElementById('cfgDz2').value,
    deadzone_p3:                document.getElementById('cfgDz3').value,
    deadzone_p4:                document.getElementById('cfgDz4').value,
    emulate_second:             document.getElementById('cfgEmulate2').value,
  };
  const d = await api('/api/config', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify(payload)
  });
  if (d.error) showAlert('cfgAlert', 'Error: ' + d.error, true);
  else showAlert('cfgAlert', 'Configuration saved. Restart the service to apply changes.', false);
  return !d.error;
}

async function saveConfigAndRestart() {
  const saved = await saveConfig();
  if (saved) {
    showAlert('cfgAlert', 'Configuration saved. Restarting service\u2026', false);
    await serviceAction('restart');
  }
}

function resetConfig() {
  if (!confirm('Reset configuration fields to factory defaults?\n\nClick Save to write the changes to disk.')) return;
  document.getElementById('cfgDevice').value   = '/dev/ttyUSB0';
  document.getElementById('cfgSense').value    = '1';
  document.getElementById('cfgPin').value      = '26';
  document.getElementById('cfgDebug').value    = '0';
  document.getElementById('cfgAutoCtrl').value = '1';
  document.getElementById('cfgDz1').value = '0.2';
  document.getElementById('cfgDz2').value = '0.2';
  document.getElementById('cfgDz3').value = '0.2';
  document.getElementById('cfgDz4').value = '0.2';
  document.getElementById('cfgEmulate2').value   = '';
  showAlert('cfgAlert', 'Fields reset to defaults. Click Save to write the configuration.', false);
}

// ---- Profiles ----
let _profilesCurrentTab = 'games';
let _profileEditingName = null;
let _profileEditingIsNew = false;

async function loadProfiles() {
  const d = await api('/api/profiles/list');
  if (d.error) { showAlert('profilesAlert', 'Error: ' + d.error, true); return; }
  renderProfilesTable(d);
}

function setProfileTab(tab) {
  _profilesCurrentTab = tab;
  ['games','devices','ios'].forEach(t => {
    const btn = document.getElementById('profTab' + t.charAt(0).toUpperCase() + t.slice(1));
    if (btn) btn.style.background = (t === tab) ? 'var(--accent)' : '';
    if (btn) btn.style.color      = (t === tab) ? '#000' : '';
  });
  // Re-render with current data
  api('/api/profiles/list').then(d => { if (!d.error) renderProfilesTable(d); });
}

function renderProfilesTable(data) {
  const files = data[_profilesCurrentTab] || [];
  const tbody = document.getElementById('profilesTableBody');
  if (files.length === 0) {
    tbody.innerHTML = '<tr><td colspan="2" style="color:var(--muted)">No files found.</td></tr>';
    return;
  }
  tbody.innerHTML = files.map(name => `
    <tr>
      <td><code style="color:var(--accent2);font-family:monospace;">${_escHtml(name)}</code></td>
      <td style="white-space:nowrap;">
        <button class="btn btn-xs btn-refresh" data-name="${_escHtml(name)}" onclick="editProfile(this.dataset.name)" style="margin-right:0.25rem;">Edit</button>
        <a href="/api/profiles/download?type=${encodeURIComponent(_profilesCurrentTab)}&name=${encodeURIComponent(name)}" class="btn btn-xs" style="margin-right:0.25rem;text-decoration:none;">Download</a>
        <button class="btn btn-xs" data-name="${_escHtml(name)}" onclick="renameProfile(this.dataset.name)" style="margin-right:0.25rem;">Rename</button>
        <button class="btn btn-xs btn-danger" data-name="${_escHtml(name)}" onclick="deleteProfile(this.dataset.name)">Delete</button>
      </td>
    </tr>`).join('');
}

async function editProfile(name) {
  const d = await api('/api/profiles/read?type=' + encodeURIComponent(_profilesCurrentTab) + '&name=' + encodeURIComponent(name));
  if (d.error) { showAlert('profilesAlert', 'Error: ' + d.error, true); return; }
  _profileEditingName  = name;
  _profileEditingIsNew = false;
  document.getElementById('profileEditName').textContent = name;
  document.getElementById('profileEditName').style.display = '';
  document.getElementById('profileNewName').style.display  = 'none';
  document.getElementById('profileEditContent').value = d.content;
  document.getElementById('profileEditorWrap').style.display = '';
  document.getElementById('profileEditContent').focus();
}

function newProfileFile() {
  _profileEditingName  = null;
  _profileEditingIsNew = true;
  document.getElementById('profileEditName').style.display = 'none';
  document.getElementById('profileNewName').style.display  = '';
  document.getElementById('profileNewName').value = '';
  document.getElementById('profileEditContent').value = '';
  document.getElementById('profileEditorWrap').style.display = '';
  document.getElementById('profileNewName').focus();
}

function closeProfileEditor() {
  document.getElementById('profileEditorWrap').style.display = 'none';
  _profileEditingName  = null;
  _profileEditingIsNew = false;
}

async function saveProfile() {
  const name = _profileEditingIsNew
    ? document.getElementById('profileNewName').value.trim()
    : _profileEditingName;
  if (!name) { showAlert('profilesAlert', 'Please enter a filename.', true); return; }
  const content = document.getElementById('profileEditContent').value;
  const d = await api('/api/profiles/write', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ type: _profilesCurrentTab, name, content })
  });
  if (d.error) { showAlert('profilesAlert', 'Error: ' + d.error, true); return; }
  showAlert('profilesAlert', 'Saved ' + name + ' successfully.', false);
  if (_profileEditingIsNew) {
    _profileEditingName  = name;
    _profileEditingIsNew = false;
    document.getElementById('profileEditName').textContent = name;
    document.getElementById('profileEditName').style.display = '';
    document.getElementById('profileNewName').style.display  = 'none';
  }
  loadProfiles();
}

async function deleteProfile(name) {
  if (!confirm('Delete profile "' + name + '"? This cannot be undone.')) return;
  const d = await api('/api/profiles/delete', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ type: _profilesCurrentTab, name })
  });
  if (d.error) { showAlert('profilesAlert', 'Error: ' + d.error, true); return; }
  showAlert('profilesAlert', 'Deleted ' + name + '.', false);
  if (_profileEditingName === name) closeProfileEditor();
  loadProfiles();
}

async function renameProfile(name) {
  const newName = prompt('Rename "' + name + '" to:', name);
  if (!newName || newName === name) return;
  const d = await api('/api/profiles/rename', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ type: _profilesCurrentTab, name, new_name: newName })
  });
  if (d.error) { showAlert('profilesAlert', 'Error: ' + d.error, true); return; }
  showAlert('profilesAlert', 'Renamed "' + name + '" to "' + newName + '".', false);
  if (_profileEditingName === name) {
    _profileEditingName = newName;
    document.getElementById('profileEditName').textContent = newName;
  }
  loadProfiles();
}

async function uploadProfile(input) {
  const file = input.files[0];
  if (!file) return;
  const name = _profileEditingIsNew
    ? (document.getElementById('profileNewName').value.trim() || file.name)
    : (_profileEditingName || file.name);
  const r = await fetch('/api/profiles/upload', {
    method: 'POST',
    headers: {
      'X-Profile-Type': _profilesCurrentTab,
      'X-Profile-Name': name,
      'Content-Length': file.size,
    },
    body: file,
  });
  const d = await r.json().catch(() => ({error: 'Parse error'}));
  if (d.error) { showAlert('profilesAlert', 'Upload error: ' + d.error, true); return; }
  showAlert('profilesAlert', 'Uploaded ' + name + ' (' + d.size + ' bytes).', false);
  editProfile(name);
  loadProfiles();
  input.value = '';
}

// ---- Live Input Tester ----

// Linux input event code → name lookup tables (auto-generated from input-event-codes.h)
// Complete table: all 616 EV_KEY and 42 EV_ABS codes so any device works automatically.
const _EV_KEY_NAMES = {
  0:'KEY_RESERVED',1:'KEY_ESC',2:'KEY_1',3:'KEY_2',4:'KEY_3',5:'KEY_4',
  6:'KEY_5',7:'KEY_6',8:'KEY_7',9:'KEY_8',10:'KEY_9',11:'KEY_0',
  12:'KEY_MINUS',13:'KEY_EQUAL',14:'KEY_BACKSPACE',15:'KEY_TAB',16:'KEY_Q',17:'KEY_W',
  18:'KEY_E',19:'KEY_R',20:'KEY_T',21:'KEY_Y',22:'KEY_U',23:'KEY_I',
  24:'KEY_O',25:'KEY_P',26:'KEY_LEFTBRACE',27:'KEY_RIGHTBRACE',28:'KEY_ENTER',29:'KEY_LEFTCTRL',
  30:'KEY_A',31:'KEY_S',32:'KEY_D',33:'KEY_F',34:'KEY_G',35:'KEY_H',
  36:'KEY_J',37:'KEY_K',38:'KEY_L',39:'KEY_SEMICOLON',40:'KEY_APOSTROPHE',41:'KEY_GRAVE',
  42:'KEY_LEFTSHIFT',43:'KEY_BACKSLASH',44:'KEY_Z',45:'KEY_X',46:'KEY_C',47:'KEY_V',
  48:'KEY_B',49:'KEY_N',50:'KEY_M',51:'KEY_COMMA',52:'KEY_DOT',53:'KEY_SLASH',
  54:'KEY_RIGHTSHIFT',55:'KEY_KPASTERISK',56:'KEY_LEFTALT',57:'KEY_SPACE',58:'KEY_CAPSLOCK',59:'KEY_F1',
  60:'KEY_F2',61:'KEY_F3',62:'KEY_F4',63:'KEY_F5',64:'KEY_F6',65:'KEY_F7',
  66:'KEY_F8',67:'KEY_F9',68:'KEY_F10',69:'KEY_NUMLOCK',70:'KEY_SCROLLLOCK',71:'KEY_KP7',
  72:'KEY_KP8',73:'KEY_KP9',74:'KEY_KPMINUS',75:'KEY_KP4',76:'KEY_KP5',77:'KEY_KP6',
  78:'KEY_KPPLUS',79:'KEY_KP1',80:'KEY_KP2',81:'KEY_KP3',82:'KEY_KP0',83:'KEY_KPDOT',
  85:'KEY_ZENKAKUHANKAKU',86:'KEY_102ND',87:'KEY_F11',88:'KEY_F12',89:'KEY_RO',90:'KEY_KATAKANA',
  91:'KEY_HIRAGANA',92:'KEY_HENKAN',93:'KEY_KATAKANAHIRAGANA',94:'KEY_MUHENKAN',95:'KEY_KPJPCOMMA',96:'KEY_KPENTER',
  97:'KEY_RIGHTCTRL',98:'KEY_KPSLASH',99:'KEY_SYSRQ',100:'KEY_RIGHTALT',101:'KEY_LINEFEED',102:'KEY_HOME',
  103:'KEY_UP',104:'KEY_PAGEUP',105:'KEY_LEFT',106:'KEY_RIGHT',107:'KEY_END',108:'KEY_DOWN',
  109:'KEY_PAGEDOWN',110:'KEY_INSERT',111:'KEY_DELETE',112:'KEY_MACRO',113:'KEY_MUTE',114:'KEY_VOLUMEDOWN',
  115:'KEY_VOLUMEUP',116:'KEY_POWER',117:'KEY_KPEQUAL',118:'KEY_KPPLUSMINUS',119:'KEY_PAUSE',120:'KEY_SCALE',
  121:'KEY_KPCOMMA',122:'KEY_HANGEUL',123:'KEY_HANJA',124:'KEY_YEN',125:'KEY_LEFTMETA',126:'KEY_RIGHTMETA',
  127:'KEY_COMPOSE',128:'KEY_STOP',129:'KEY_AGAIN',130:'KEY_PROPS',131:'KEY_UNDO',132:'KEY_FRONT',
  133:'KEY_COPY',134:'KEY_OPEN',135:'KEY_PASTE',136:'KEY_FIND',137:'KEY_CUT',138:'KEY_HELP',
  139:'KEY_MENU',140:'KEY_CALC',141:'KEY_SETUP',142:'KEY_SLEEP',143:'KEY_WAKEUP',144:'KEY_FILE',
  145:'KEY_SENDFILE',146:'KEY_DELETEFILE',147:'KEY_XFER',148:'KEY_PROG1',149:'KEY_PROG2',150:'KEY_WWW',
  151:'KEY_MSDOS',152:'KEY_COFFEE',153:'KEY_ROTATE_DISPLAY',154:'KEY_CYCLEWINDOWS',155:'KEY_MAIL',156:'KEY_BOOKMARKS',
  157:'KEY_COMPUTER',158:'KEY_BACK',159:'KEY_FORWARD',160:'KEY_CLOSECD',161:'KEY_EJECTCD',162:'KEY_EJECTCLOSECD',
  163:'KEY_NEXTSONG',164:'KEY_PLAYPAUSE',165:'KEY_PREVIOUSSONG',166:'KEY_STOPCD',167:'KEY_RECORD',168:'KEY_REWIND',
  169:'KEY_PHONE',170:'KEY_ISO',171:'KEY_CONFIG',172:'KEY_HOMEPAGE',173:'KEY_REFRESH',174:'KEY_EXIT',
  175:'KEY_MOVE',176:'KEY_EDIT',177:'KEY_SCROLLUP',178:'KEY_SCROLLDOWN',179:'KEY_KPLEFTPAREN',180:'KEY_KPRIGHTPAREN',
  181:'KEY_NEW',182:'KEY_REDO',183:'KEY_F13',184:'KEY_F14',185:'KEY_F15',186:'KEY_F16',
  187:'KEY_F17',188:'KEY_F18',189:'KEY_F19',190:'KEY_F20',191:'KEY_F21',192:'KEY_F22',
  193:'KEY_F23',194:'KEY_F24',200:'KEY_PLAYCD',201:'KEY_PAUSECD',202:'KEY_PROG3',203:'KEY_PROG4',
  204:'KEY_ALL_APPLICATIONS',205:'KEY_SUSPEND',206:'KEY_CLOSE',207:'KEY_PLAY',208:'KEY_FASTFORWARD',209:'KEY_BASSBOOST',
  210:'KEY_PRINT',211:'KEY_HP',212:'KEY_CAMERA',213:'KEY_SOUND',214:'KEY_QUESTION',215:'KEY_EMAIL',
  216:'KEY_CHAT',217:'KEY_SEARCH',218:'KEY_CONNECT',219:'KEY_FINANCE',220:'KEY_SPORT',221:'KEY_SHOP',
  222:'KEY_ALTERASE',223:'KEY_CANCEL',224:'KEY_BRIGHTNESSDOWN',225:'KEY_BRIGHTNESSUP',226:'KEY_MEDIA',227:'KEY_SWITCHVIDEOMODE',
  228:'KEY_KBDILLUMTOGGLE',229:'KEY_KBDILLUMDOWN',230:'KEY_KBDILLUMUP',231:'KEY_SEND',232:'KEY_REPLY',233:'KEY_FORWARDMAIL',
  234:'KEY_SAVE',235:'KEY_DOCUMENTS',236:'KEY_BATTERY',237:'KEY_BLUETOOTH',238:'KEY_WLAN',239:'KEY_UWB',
  240:'KEY_UNKNOWN',241:'KEY_VIDEO_NEXT',242:'KEY_VIDEO_PREV',243:'KEY_BRIGHTNESS_CYCLE',244:'KEY_BRIGHTNESS_AUTO',245:'KEY_DISPLAY_OFF',
  246:'KEY_WWAN',247:'KEY_RFKILL',248:'KEY_MICMUTE',
  256:'BTN_0',257:'BTN_1',258:'BTN_2',259:'BTN_3',260:'BTN_4',261:'BTN_5',
  262:'BTN_6',263:'BTN_7',264:'BTN_8',265:'BTN_9',
  272:'BTN_LEFT',273:'BTN_RIGHT',274:'BTN_MIDDLE',275:'BTN_SIDE',276:'BTN_EXTRA',277:'BTN_FORWARD',
  278:'BTN_BACK',279:'BTN_TASK',
  288:'BTN_TRIGGER',289:'BTN_THUMB',290:'BTN_THUMB2',291:'BTN_TOP',292:'BTN_TOP2',293:'BTN_PINKIE',
  294:'BTN_BASE',295:'BTN_BASE2',296:'BTN_BASE3',297:'BTN_BASE4',298:'BTN_BASE5',299:'BTN_BASE6',
  303:'BTN_DEAD',
  304:'BTN_SOUTH',305:'BTN_EAST',306:'BTN_C',307:'BTN_NORTH',308:'BTN_WEST',309:'BTN_Z',
  310:'BTN_TL',311:'BTN_TR',312:'BTN_TL2',313:'BTN_TR2',314:'BTN_SELECT',315:'BTN_START',
  316:'BTN_MODE',317:'BTN_THUMBL',318:'BTN_THUMBR',
  320:'BTN_TOOL_PEN',321:'BTN_TOOL_RUBBER',322:'BTN_TOOL_BRUSH',323:'BTN_TOOL_PENCIL',324:'BTN_TOOL_AIRBRUSH',325:'BTN_TOOL_FINGER',
  326:'BTN_TOOL_MOUSE',327:'BTN_TOOL_LENS',328:'BTN_TOOL_QUINTTAP',329:'BTN_STYLUS3',330:'BTN_TOUCH',331:'BTN_STYLUS',
  332:'BTN_STYLUS2',333:'BTN_TOOL_DOUBLETAP',334:'BTN_TOOL_TRIPLETAP',335:'BTN_TOOL_QUADTAP',336:'BTN_GEAR_DOWN',337:'BTN_GEAR_UP',
  352:'KEY_OK',353:'KEY_SELECT',354:'KEY_GOTO',355:'KEY_CLEAR',356:'KEY_POWER2',357:'KEY_OPTION',
  358:'KEY_INFO',359:'KEY_TIME',360:'KEY_VENDOR',361:'KEY_ARCHIVE',362:'KEY_PROGRAM',363:'KEY_CHANNEL',
  364:'KEY_FAVORITES',365:'KEY_EPG',366:'KEY_PVR',367:'KEY_MHP',368:'KEY_LANGUAGE',369:'KEY_TITLE',
  370:'KEY_SUBTITLE',371:'KEY_ANGLE',372:'KEY_FULL_SCREEN',373:'KEY_MODE',374:'KEY_KEYBOARD',375:'KEY_ASPECT_RATIO',
  376:'KEY_PC',377:'KEY_TV',378:'KEY_TV2',379:'KEY_VCR',380:'KEY_VCR2',381:'KEY_SAT',
  382:'KEY_SAT2',383:'KEY_CD',384:'KEY_TAPE',385:'KEY_RADIO',386:'KEY_TUNER',387:'KEY_PLAYER',
  388:'KEY_TEXT',389:'KEY_DVD',390:'KEY_AUX',391:'KEY_MP3',392:'KEY_AUDIO',393:'KEY_VIDEO',
  394:'KEY_DIRECTORY',395:'KEY_LIST',396:'KEY_MEMO',397:'KEY_CALENDAR',398:'KEY_RED',399:'KEY_GREEN',
  400:'KEY_YELLOW',401:'KEY_BLUE',402:'KEY_CHANNELUP',403:'KEY_CHANNELDOWN',404:'KEY_FIRST',405:'KEY_LAST',
  406:'KEY_AB',407:'KEY_NEXT',408:'KEY_RESTART',409:'KEY_SLOW',410:'KEY_SHUFFLE',411:'KEY_BREAK',
  412:'KEY_PREVIOUS',413:'KEY_DIGITS',414:'KEY_TEEN',415:'KEY_TWEN',416:'KEY_VIDEOPHONE',417:'KEY_GAMES',
  418:'KEY_ZOOMIN',419:'KEY_ZOOMOUT',420:'KEY_ZOOMRESET',421:'KEY_WORDPROCESSOR',422:'KEY_EDITOR',423:'KEY_SPREADSHEET',
  424:'KEY_GRAPHICSEDITOR',425:'KEY_PRESENTATION',426:'KEY_DATABASE',427:'KEY_NEWS',428:'KEY_VOICEMAIL',429:'KEY_ADDRESSBOOK',
  430:'KEY_MESSENGER',431:'KEY_DISPLAYTOGGLE',432:'KEY_SPELLCHECK',433:'KEY_LOGOFF',434:'KEY_DOLLAR',435:'KEY_EURO',
  436:'KEY_FRAMEBACK',437:'KEY_FRAMEFORWARD',438:'KEY_CONTEXT_MENU',439:'KEY_MEDIA_REPEAT',440:'KEY_10CHANNELSUP',441:'KEY_10CHANNELSDOWN',
  442:'KEY_IMAGES',444:'KEY_NOTIFICATION_CENTER',445:'KEY_PICKUP_PHONE',446:'KEY_HANGUP_PHONE',447:'KEY_LINK_PHONE',
  448:'KEY_DEL_EOL',449:'KEY_DEL_EOS',450:'KEY_INS_LINE',451:'KEY_DEL_LINE',
  464:'KEY_FN',465:'KEY_FN_ESC',466:'KEY_FN_F1',467:'KEY_FN_F2',468:'KEY_FN_F3',469:'KEY_FN_F4',
  470:'KEY_FN_F5',471:'KEY_FN_F6',472:'KEY_FN_F7',473:'KEY_FN_F8',474:'KEY_FN_F9',475:'KEY_FN_F10',
  476:'KEY_FN_F11',477:'KEY_FN_F12',478:'KEY_FN_1',479:'KEY_FN_2',480:'KEY_FN_D',481:'KEY_FN_E',
  482:'KEY_FN_F',483:'KEY_FN_S',484:'KEY_FN_B',485:'KEY_FN_RIGHT_SHIFT',
  497:'KEY_BRL_DOT1',498:'KEY_BRL_DOT2',499:'KEY_BRL_DOT3',500:'KEY_BRL_DOT4',501:'KEY_BRL_DOT5',502:'KEY_BRL_DOT6',
  503:'KEY_BRL_DOT7',504:'KEY_BRL_DOT8',505:'KEY_BRL_DOT9',506:'KEY_BRL_DOT10',
  512:'KEY_NUMERIC_0',513:'KEY_NUMERIC_1',514:'KEY_NUMERIC_2',515:'KEY_NUMERIC_3',516:'KEY_NUMERIC_4',517:'KEY_NUMERIC_5',
  518:'KEY_NUMERIC_6',519:'KEY_NUMERIC_7',520:'KEY_NUMERIC_8',521:'KEY_NUMERIC_9',522:'KEY_NUMERIC_STAR',523:'KEY_NUMERIC_POUND',
  524:'KEY_NUMERIC_A',525:'KEY_NUMERIC_B',526:'KEY_NUMERIC_C',527:'KEY_NUMERIC_D',
  528:'KEY_CAMERA_FOCUS',529:'KEY_WPS_BUTTON',530:'KEY_TOUCHPAD_TOGGLE',531:'KEY_TOUCHPAD_ON',532:'KEY_TOUCHPAD_OFF',
  533:'KEY_CAMERA_ZOOMIN',534:'KEY_CAMERA_ZOOMOUT',535:'KEY_CAMERA_UP',536:'KEY_CAMERA_DOWN',537:'KEY_CAMERA_LEFT',538:'KEY_CAMERA_RIGHT',
  539:'KEY_ATTENDANT_ON',540:'KEY_ATTENDANT_OFF',541:'KEY_ATTENDANT_TOGGLE',542:'KEY_LIGHTS_TOGGLE',
  544:'BTN_DPAD_UP',545:'BTN_DPAD_DOWN',546:'BTN_DPAD_LEFT',547:'BTN_DPAD_RIGHT',
  560:'KEY_ALS_TOGGLE',561:'KEY_ROTATE_LOCK_TOGGLE',562:'KEY_REFRESH_RATE_TOGGLE',
  576:'KEY_BUTTONCONFIG',577:'KEY_TASKMANAGER',578:'KEY_JOURNAL',579:'KEY_CONTROLPANEL',580:'KEY_APPSELECT',581:'KEY_SCREENSAVER',
  582:'KEY_VOICECOMMAND',583:'KEY_ASSISTANT',584:'KEY_KBD_LAYOUT_NEXT',585:'KEY_EMOJI_PICKER',586:'KEY_DICTATE',
  587:'KEY_CAMERA_ACCESS_ENABLE',588:'KEY_CAMERA_ACCESS_DISABLE',589:'KEY_CAMERA_ACCESS_TOGGLE',590:'KEY_ACCESSIBILITY',591:'KEY_DO_NOT_DISTURB',
  592:'KEY_BRIGHTNESS_MIN',
  608:'KEY_KBDINPUTASSIST_PREV',609:'KEY_KBDINPUTASSIST_NEXT',610:'KEY_KBDINPUTASSIST_PREVGROUP',611:'KEY_KBDINPUTASSIST_NEXTGROUP',
  612:'KEY_KBDINPUTASSIST_ACCEPT',613:'KEY_KBDINPUTASSIST_CANCEL',614:'KEY_RIGHT_UP',615:'KEY_RIGHT_DOWN',616:'KEY_LEFT_UP',617:'KEY_LEFT_DOWN',
  618:'KEY_ROOT_MENU',619:'KEY_MEDIA_TOP_MENU',620:'KEY_NUMERIC_11',621:'KEY_NUMERIC_12',622:'KEY_AUDIO_DESC',623:'KEY_3D_MODE',
  624:'KEY_NEXT_FAVORITE',625:'KEY_STOP_RECORD',626:'KEY_PAUSE_RECORD',627:'KEY_VOD',628:'KEY_UNMUTE',629:'KEY_FASTREVERSE',
  630:'KEY_SLOWREVERSE',631:'KEY_DATA',632:'KEY_ONSCREEN_KEYBOARD',633:'KEY_PRIVACY_SCREEN_TOGGLE',634:'KEY_SELECTIVE_SCREENSHOT',
  635:'KEY_NEXT_ELEMENT',636:'KEY_PREVIOUS_ELEMENT',637:'KEY_AUTOPILOT_ENGAGE_TOGGLE',638:'KEY_MARK_WAYPOINT',639:'KEY_SOS',
  640:'KEY_NAV_CHART',641:'KEY_FISHING_CHART',642:'KEY_SINGLE_RANGE_RADAR',643:'KEY_DUAL_RANGE_RADAR',644:'KEY_RADAR_OVERLAY',
  645:'KEY_TRADITIONAL_SONAR',646:'KEY_CLEARVU_SONAR',647:'KEY_SIDEVU_SONAR',648:'KEY_NAV_INFO',649:'KEY_BRIGHTNESS_MENU',
  656:'KEY_MACRO1',657:'KEY_MACRO2',658:'KEY_MACRO3',659:'KEY_MACRO4',660:'KEY_MACRO5',661:'KEY_MACRO6',
  662:'KEY_MACRO7',663:'KEY_MACRO8',664:'KEY_MACRO9',665:'KEY_MACRO10',666:'KEY_MACRO11',667:'KEY_MACRO12',
  668:'KEY_MACRO13',669:'KEY_MACRO14',670:'KEY_MACRO15',671:'KEY_MACRO16',672:'KEY_MACRO17',673:'KEY_MACRO18',
  674:'KEY_MACRO19',675:'KEY_MACRO20',676:'KEY_MACRO21',677:'KEY_MACRO22',678:'KEY_MACRO23',679:'KEY_MACRO24',
  680:'KEY_MACRO25',681:'KEY_MACRO26',682:'KEY_MACRO27',683:'KEY_MACRO28',684:'KEY_MACRO29',685:'KEY_MACRO30',
  688:'KEY_MACRO_RECORD_START',689:'KEY_MACRO_RECORD_STOP',690:'KEY_MACRO_PRESET_CYCLE',691:'KEY_MACRO_PRESET1',692:'KEY_MACRO_PRESET2',693:'KEY_MACRO_PRESET3',
  696:'KEY_KBD_LCD_MENU1',697:'KEY_KBD_LCD_MENU2',698:'KEY_KBD_LCD_MENU3',699:'KEY_KBD_LCD_MENU4',700:'KEY_KBD_LCD_MENU5',
  704:'BTN_TRIGGER_HAPPY1',705:'BTN_TRIGGER_HAPPY2',706:'BTN_TRIGGER_HAPPY3',707:'BTN_TRIGGER_HAPPY4',708:'BTN_TRIGGER_HAPPY5',709:'BTN_TRIGGER_HAPPY6',
  710:'BTN_TRIGGER_HAPPY7',711:'BTN_TRIGGER_HAPPY8',712:'BTN_TRIGGER_HAPPY9',713:'BTN_TRIGGER_HAPPY10',714:'BTN_TRIGGER_HAPPY11',715:'BTN_TRIGGER_HAPPY12',
  716:'BTN_TRIGGER_HAPPY13',717:'BTN_TRIGGER_HAPPY14',718:'BTN_TRIGGER_HAPPY15',719:'BTN_TRIGGER_HAPPY16',720:'BTN_TRIGGER_HAPPY17',721:'BTN_TRIGGER_HAPPY18',
  722:'BTN_TRIGGER_HAPPY19',723:'BTN_TRIGGER_HAPPY20',724:'BTN_TRIGGER_HAPPY21',725:'BTN_TRIGGER_HAPPY22',726:'BTN_TRIGGER_HAPPY23',727:'BTN_TRIGGER_HAPPY24',
  728:'BTN_TRIGGER_HAPPY25',729:'BTN_TRIGGER_HAPPY26',730:'BTN_TRIGGER_HAPPY27',731:'BTN_TRIGGER_HAPPY28',732:'BTN_TRIGGER_HAPPY29',733:'BTN_TRIGGER_HAPPY30',
  734:'BTN_TRIGGER_HAPPY31',735:'BTN_TRIGGER_HAPPY32',736:'BTN_TRIGGER_HAPPY33',737:'BTN_TRIGGER_HAPPY34',738:'BTN_TRIGGER_HAPPY35',739:'BTN_TRIGGER_HAPPY36',
  740:'BTN_TRIGGER_HAPPY37',741:'BTN_TRIGGER_HAPPY38',742:'BTN_TRIGGER_HAPPY39',743:'BTN_TRIGGER_HAPPY40',
};
const _EV_ABS_NAMES = {
  0:'ABS_X',1:'ABS_Y',2:'ABS_Z',3:'ABS_RX',4:'ABS_RY',5:'ABS_RZ',
  6:'ABS_THROTTLE',7:'ABS_RUDDER',8:'ABS_WHEEL',9:'ABS_GAS',10:'ABS_BRAKE',
  16:'ABS_HAT0X',17:'ABS_HAT0Y',18:'ABS_HAT1X',19:'ABS_HAT1Y',20:'ABS_HAT2X',21:'ABS_HAT2Y',
  22:'ABS_HAT3X',23:'ABS_HAT3Y',24:'ABS_PRESSURE',25:'ABS_DISTANCE',26:'ABS_TILT_X',27:'ABS_TILT_Y',
  28:'ABS_TOOL_WIDTH',32:'ABS_VOLUME',33:'ABS_PROFILE',46:'ABS_RESERVED',
  47:'ABS_MT_SLOT',48:'ABS_MT_TOUCH_MAJOR',49:'ABS_MT_TOUCH_MINOR',50:'ABS_MT_WIDTH_MAJOR',51:'ABS_MT_WIDTH_MINOR',52:'ABS_MT_ORIENTATION',
  53:'ABS_MT_POSITION_X',54:'ABS_MT_POSITION_Y',55:'ABS_MT_TOOL_TYPE',56:'ABS_MT_BLOB_ID',57:'ABS_MT_TRACKING_ID',58:'ABS_MT_PRESSURE',
  59:'ABS_MT_DISTANCE',60:'ABS_MT_TOOL_X',61:'ABS_MT_TOOL_Y',
};
let _inputTestSource = null;
let _inputTestState  = {};

async function populateInputTesterDevices() {
  const d = await api('/api/input_devices');
  const sel = document.getElementById('inputTesterDevice');
  if (!sel) return;
  sel.innerHTML = '';
  (d.devices || []).filter(dev => !dev.ignored).forEach(dev => {
    const o = document.createElement('option');
    o.value = dev.event;
    o.textContent = dev.event + (dev.name !== dev.event ? ' – ' + dev.name : '');
    sel.appendChild(o);
  });
  if (!sel.options.length) {
    const o = document.createElement('option');
    o.value = ''; o.textContent = '— No devices found —';
    sel.appendChild(o);
  }
}

function startInputTest() {
  const sel = document.getElementById('inputTesterDevice');
  const device = sel ? sel.value : '';
  if (!device) return;
  stopInputTest();
  _inputTestState = {};
  document.getElementById('inputTesterStatus').textContent = 'Connecting to ' + device + '…';
  document.getElementById('inputTesterDisplay').innerHTML = '';
  document.querySelector('[onclick="startInputTest()"]').disabled = true;
  document.getElementById('inputTesterStopBtn').disabled = false;
  _inputTestSource = new EventSource('/api/input/test?device=' + encodeURIComponent(device));
  _inputTestSource.onmessage = function(ev) {
    let data;
    try { data = JSON.parse(ev.data); } catch(e) { return; }
    // Update status to "Connected" on first message of any kind
    document.getElementById('inputTesterStatus').textContent = 'Connected – ' + device;
    if (data.keepalive) return;
    if (data.error) {
      document.getElementById('inputTesterStatus').textContent = 'Error: ' + data.error;
      stopInputTest();
      return;
    }
    const { type, code, value } = data;
    if (type === 0) return; // EV_SYN – skip
    const key = type + '_' + code;
    _inputTestState[key] = { type, code, value };
    renderInputTestDisplay();
  };
  _inputTestSource.onerror = function() {
    document.getElementById('inputTesterStatus').textContent = 'Connection lost.';
    stopInputTest();
  };
}

function stopInputTest() {
  if (_inputTestSource) { _inputTestSource.close(); _inputTestSource = null; }
  _inputTestState = {};
  const startBtn = document.querySelector('[onclick="startInputTest()"]');
  if (startBtn) startBtn.disabled = false;
  const stopBtn = document.getElementById('inputTesterStopBtn');
  if (stopBtn) stopBtn.disabled = true;
  document.getElementById('inputTesterStatus').textContent = '';
  document.getElementById('inputTesterDisplay').innerHTML = '';
}

function renderInputTestDisplay() {
  const keys  = Object.values(_inputTestState).filter(s => s.type === 1);
  const axes  = Object.values(_inputTestState).filter(s => s.type === 3);
  let html = '';
  if (keys.length) {
    html += '<div style="margin-bottom:0.5rem;"><strong style="font-size:0.78rem;color:var(--muted);text-transform:uppercase;letter-spacing:0.05em;">Buttons</strong><div style="display:flex;flex-wrap:wrap;gap:0.35rem;margin-top:0.35rem;">';
    keys.forEach(s => {
      const on   = s.value === 1;
      const name = _EV_KEY_NAMES[s.code] || ('CODE_' + s.code);
      html += `<span style="padding:0.2rem 0.5rem;border-radius:4px;font-size:0.82rem;background:${on?'var(--green,#22c55e)':'var(--surface)'};color:${on?'#000':'var(--muted)'};border:1px solid ${on?'transparent':'var(--border)'};" title="code ${s.code}">${name}</span>`;
    });
    html += '</div></div>';
  }
  if (axes.length) {
    html += '<div><strong style="font-size:0.78rem;color:var(--muted);text-transform:uppercase;letter-spacing:0.05em;">Axes</strong>';
    axes.forEach(s => {
      // Track min/max per axis code
      const stateKey = 'axisRange_' + s.code;
      if (!_inputTestState[stateKey]) _inputTestState[stateKey] = {min: s.value, max: s.value};
      const range = _inputTestState[stateKey];
      range.min = Math.min(range.min, s.value);
      range.max = Math.max(range.max, s.value);
      const span = range.max - range.min || 1;
      const pct  = Math.round(((s.value - range.min) / span) * 100);
      const name = _EV_ABS_NAMES[s.code] || ('ABS_' + s.code);
      html += `<div style="margin-top:0.35rem;"><span style="font-size:0.78rem;color:var(--muted);" title="code ${s.code}">${name}</span><div style="background:var(--surface);border:1px solid var(--border);border-radius:4px;height:8px;margin-top:2px;"><div style="background:var(--accent);height:100%;border-radius:4px;width:${pct}%;"></div></div></div>`;
    });
    html += '</div>';
  }
  if (!html) html = '<span style="color:var(--muted)">Waiting for events…</span>';
  document.getElementById('inputTesterDisplay').innerHTML = html;
}

// ---- Monitor ----
let autoRefreshTimer = null;
let rawLogLines = [];   // cached raw lines for client-side filtering

function toggleAutoRefresh() {
  if (document.getElementById('autoRefresh').checked) {
    autoRefreshTimer = setInterval(fetchLogs, 5000);
  } else {
    clearInterval(autoRefreshTimer);
    autoRefreshTimer = null;
  }
}

async function fetchLogs() {
  const lines = document.getElementById('logLines').value;
  const d = await api('/api/logs?lines=' + lines);
  const box = document.getElementById('logBox');
  if (d.error) { box.textContent = 'Error: ' + d.error; return; }

  rawLogLines = d.lines || [];

  // Live log shows ALL lines unfiltered
  renderLines(box, rawLogLines, 'No log entries.');

  // Apply current filter to the Log Filter / JVS Activity pane
  applyJvsFilter();
}

function applyJvsFilter() {
  const filter = document.getElementById('logFilter').value;
  const search = document.getElementById('logSearch').value.toLowerCase();

  // Show the debug-level hint only when the JVS Activity filter is active
  const hint = document.getElementById('logFilterHint');
  if (hint) hint.style.display = (filter === 'jvs') ? 'block' : 'none';

  let lines = rawLogLines;
  let emptyMsg = 'No matching log entries.';
  switch (filter) {
    case 'errors':
      lines = lines.filter(l => /error|critical|fail/i.test(l));
      break;
    case 'warnings':
      lines = lines.filter(l => /warning|warn/i.test(l));
      break;
    case 'jvs':
      // Only show CMD_ debug output — these are the actual JVS packet commands
      lines = lines.filter(l => /CMD_/.test(l));
      emptyMsg = 'No JVS activity found. CMD_ messages are only logged when Debug Mode is set to 1 or 2 in Configuration.';
      break;
    case 'controllers':
      lines = lines.filter(l => /controller|input|device|player|joystick|gamepad|wiimote/i.test(l));
      break;
  }
  if (search) {
    lines = lines.filter(l => l.toLowerCase().includes(search));
  }
  renderLines(document.getElementById('jvsBox'), lines, emptyMsg);
}

function renderLines(box, lines, emptyMsg, alwaysScroll) {
  box.innerHTML = '';
  if (lines.length === 0) {
    const div = document.createElement('div');
    div.className = 'log-line log-info';
    div.textContent = emptyMsg || 'No entries.';
    box.appendChild(div);
    return;
  }
  lines.forEach(line => {
    const div = document.createElement('div');
    div.className = 'log-line';
    if (/error|critical|fail/i.test(line))   div.classList.add('log-err');
    else if (/warning|warn/i.test(line))     div.classList.add('log-warn');
    else                                      div.classList.add('log-info');
    div.textContent = line;
    box.appendChild(div);
  });
  if (alwaysScroll || document.getElementById('scrollBottom').checked) {
    box.scrollTop = box.scrollHeight;
  }
}

function clearLogFilter() {
  document.getElementById('logSearch').value = '';
  // 'jvs' is the default — mirrors the `selected` attribute on the HTML option
  document.getElementById('logFilter').value = 'jvs';
  applyJvsFilter();
}

// ---- Devices ----
async function loadDevices() {
  const d = await api('/api/input_devices');
  const tbody = document.getElementById('deviceTableBody');
  if (d.error) {
    tbody.innerHTML = `<tr><td colspan="3" style="color:var(--red)">Error: ${d.error}</td></tr>`;
    return;
  }
  const devs = d.devices || [];
  if (devs.length === 0) {
    tbody.innerHTML = '<tr><td colspan="3" style="color:var(--muted)">No input devices found.</td></tr>';
    return;
  }
  tbody.innerHTML = devs.map(dev => {
    const statusHtml = dev.ignored
      ? '<span style="color:var(--yellow);font-size:0.8rem;">⚠ Ignored by ModernJVS</span>'
      : '<span style="color:var(--green);font-size:0.8rem;">✓ Active</span>';
    return `<tr><td><code>${dev.event}</code></td><td>${dev.name}</td><td>${statusHtml}</td></tr>`;
  }).join('');
}

// ---- Bluetooth Controllers ----
function _escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

async function loadBluetoothSection() {
  const banner    = document.getElementById('btStatusBanner');
  const paired    = document.getElementById('btPairedSection');
  const scanSect  = document.getElementById('btScanSection');

  // Reset banner and show normal sections initially
  banner.style.display = 'none';
  banner.innerHTML = '';
  paired.style.display = '';
  scanSect.style.display = '';

  const s = await api('/api/bluetooth/status');

  // If the status API itself errored (server-side exception), show raw error
  if (s.error) {
    banner.innerHTML = '&#x26A0; Bluetooth status check failed: ' + _escHtml(s.error);
    banner.className = 'alert err';
    banner.style.display = 'block';
    paired.style.display = 'none';
    scanSect.style.display = 'none';
    return;
  }

  const usable = s.hci_present && s.bluez_available && s.bt_service_running && !s.rfkill_soft_blocked;

  if (usable) {
    await loadBluetoothPaired();
    return;
  }

  // Build an appropriate diagnostic banner
  let html = '';
  let isErr = true;
  const setupBtn = '<button class="btn btn-xs" style="margin-left:0.5rem;vertical-align:middle;" onclick="btSetupUsb()">&#x1F527; Setup USB Bluetooth</button>';

  if (!s.bluez_available) {
    html = 'Bluetooth tools (BlueZ) are not installed. ' + setupBtn;
  } else if (s.rfkill_soft_blocked) {
    const cfgTool = s.is_dietpi
      ? '<code>sudo dietpi-config</code> (Advanced Options → Bluetooth)'
      : '<code>sudo raspi-config</code>';
    html = 'Bluetooth is disabled (rfkill). To enable it, run: '
      + '<code>sudo rfkill unblock bluetooth</code> or use ' + cfgTool + '.';
  } else if (s.hci_present && !s.bt_service_running) {
    html = 'A Bluetooth adapter is present but the Bluetooth service is not running. '
      + 'Start it with: <code>sudo systemctl enable --now bluetooth</code>';
  } else if (!s.hci_present) {
    if (s.is_pi5_or_later) {
      const cfgTool5 = s.is_dietpi
        ? '<code>sudo dietpi-config</code> (Advanced Options → Bluetooth)'
        : '<code>sudo raspi-config</code>';
      html = 'No Bluetooth adapter detected on your Raspberry Pi 5. '
        + 'Enable Bluetooth via ' + cfgTool5 + ' or confirm the '
        + '<code>bluetooth</code> service is running.';
    } else if (s.has_internal_bt && s.internal_bt_disabled) {
      html = 'Internal Bluetooth is disabled. Plug in a USB Bluetooth dongle to continue.';
      isErr = false;
    } else if (s.has_internal_bt) {
      // Pi 3/4 — internal BT present but not yet disabled; recommend USB dongle
      const model = s.pi_model ? ' (' + _escHtml(s.pi_model) + ')' : '';
      html = 'Your Raspberry Pi' + model + '\'s internal Bluetooth shares a UART with '
        + 'the JVS serial port, which can cause conflicts. For best results, disable the '
        + 'internal adapter and use a USB Bluetooth dongle instead. ' + setupBtn;
    } else if (s.pi_model) {
      // Pi 1/2/Zero — no internal BT
      html = 'This Raspberry Pi model has no built-in Bluetooth. '
        + 'Connect a USB Bluetooth dongle. ' + setupBtn;
    } else {
      html = 'No Bluetooth adapter detected. Connect a Bluetooth adapter.';
    }
  } else {
    html = 'Bluetooth is not available. Check that an adapter is connected and the '
      + '<code>bluetooth</code> service is running.';
  }

  banner.innerHTML = html;
  banner.className = 'alert ' + (isErr ? 'err' : 'ok');
  banner.style.display = 'block';
  paired.style.display = 'none';
  scanSect.style.display = 'none';
}

async function btSetupUsb() {
  const btAlert = document.getElementById('btAlert');
  btAlert.innerText = '⏳ Setting up Bluetooth… this may take a minute or two.';
  btAlert.className = 'alert ok';

  // Disable all setup buttons while running
  document.querySelectorAll('[onclick="btSetupUsb()"]').forEach(b => { b.disabled = true; });

  const d = await api('/api/bluetooth/setup_usb', {method: 'POST'});

  document.querySelectorAll('[onclick="btSetupUsb()"]').forEach(b => { b.disabled = false; });

  if (d.error) {
    btAlert.innerText = '✗ Setup failed: ' + d.error;
    btAlert.className = 'alert err';
    return;
  }

  const lines = (d.output || []).join('\n');
  if (d.reboot_needed) {
    btAlert.innerText = '✓ Setup complete. A reboot is required for the changes to take effect.\n'
      + 'Run: sudo reboot\n\n' + lines;
  } else {
    btAlert.innerText = '✓ Setup complete.\n\n' + lines;
    // Re-check status now that packages are installed
    setTimeout(() => loadBluetoothSection(), 1500);
  }
  btAlert.style.whiteSpace = 'pre-wrap';
}

async function loadBluetoothPaired() {
  const d = await api('/api/bluetooth/paired');
  const tbody = document.getElementById('btPairedBody');
  if (d.error) {
    tbody.innerHTML = `<tr><td colspan="4" style="color:var(--red)">Error: ${d.error}</td></tr>`;
    return;
  }
  const devs = d.devices || [];
  if (devs.length === 0) {
    tbody.innerHTML = '<tr><td colspan="4" style="color:var(--muted)">No paired Bluetooth controllers found.</td></tr>';
    return;
  }
  tbody.innerHTML = devs.map(dev => {
    const statusHtml = dev.connected
      ? '<span style="color:var(--green);font-size:0.8rem;">✓ Connected</span>'
      : '<span style="color:var(--muted);font-size:0.8rem;">● Paired</span>';
    const connectBtn = dev.connected
      ? ''
      : `<button class="btn btn-xs" style="margin-right:0.25rem;background:var(--green);border-color:var(--green);color:#000;" data-mac="${_escHtml(dev.mac)}" onclick="btConnect(this.dataset.mac, this)">&#x1F517; Connect</button>`;
    return `<tr>
      <td>${_escHtml(dev.name)}</td>
      <td><code>${_escHtml(dev.mac)}</code></td>
      <td>${statusHtml}</td>
      <td style="white-space:nowrap;">${connectBtn}<button class="btn btn-xs" style="background:var(--red);border-color:var(--red);" data-mac="${_escHtml(dev.mac)}" onclick="btRemove(this.dataset.mac, this)">✕ Remove</button></td>
    </tr>`;
  }).join('');
}

async function btScan() {
  const btn = document.getElementById('btScanBtn');
  const status = document.getElementById('btScanStatus');
  const table = document.getElementById('btScanTable');
  const tbody = document.getElementById('btScanBody');

  btn.disabled = true;
  status.textContent = 'Scanning… (8 seconds)';
  table.style.display = 'none';

  const d = await api('/api/bluetooth/scan', {method: 'POST'});
  btn.disabled = false;

  if (d.error) {
    status.textContent = 'Error: ' + d.error;
    return;
  }

  const devs = d.devices || [];
  status.textContent = devs.length
    ? `Found ${devs.length} device(s).`
    : 'No devices found. For Wii Remotes: press and hold the SYNC button (inside battery cover) or 1+2 until the LEDs flash rapidly, then scan again.';

  if (devs.length === 0) { table.style.display = 'none'; return; }

  tbody.innerHTML = devs.map(dev => {
    const wiimoteTag = dev.wiimote ? ' <span style="color:var(--accent2);font-size:0.78rem;">(Wii Remote)</span>' : '';
    if (dev.paired) {
      return `<tr>
        <td>${_escHtml(dev.name)}${wiimoteTag}</td>
        <td><code>${_escHtml(dev.mac)}</code></td>
        <td><span style="color:var(--muted);font-size:0.8rem;">Already paired</span></td>
      </tr>`;
    }
    return `<tr>
      <td>${_escHtml(dev.name)}${wiimoteTag}</td>
      <td><code>${_escHtml(dev.mac)}</code></td>
      <td><button class="btn btn-xs" style="background:var(--green);border-color:var(--green);color:#000;" data-mac="${_escHtml(dev.mac)}" data-name="${_escHtml(dev.name)}" onclick="btPair(this.dataset.mac, this.dataset.name, this)">&#x1F517; Pair</button></td>
    </tr>`;
  }).join('');
  table.style.display = '';
}

async function btPair(mac, name, btn) {
  btn.disabled = true;
  btn.textContent = 'Pairing…';

  const d = await api('/api/bluetooth/pair', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({mac}),
  });

  if (d.error) {
    showAlert('btAlert', 'Error pairing ' + name + ': ' + d.error, true);
    btn.disabled = false;
    btn.textContent = '🔗 Pair';
    return;
  }
  if (d.warning) {
    showAlert('btAlert', d.warning, true);
  } else {
    showAlert('btAlert', '✓ ' + (d.name || name) + ' paired and connected successfully.', false);
  }
  // Clear the scan results so the list doesn't linger after a successful pair
  const scanTable = document.getElementById('btScanTable');
  const scanBody  = document.getElementById('btScanBody');
  const scanStatus = document.getElementById('btScanStatus');
  if (scanTable)  { scanTable.style.display = 'none'; }
  if (scanBody)   { scanBody.innerHTML = ''; }
  if (scanStatus) { scanStatus.textContent = ''; }
  await loadBluetoothPaired();
}

async function btRemove(mac, btn) {
  if (!confirm('Remove this Bluetooth device?')) return;
  btn.disabled = true;

  const d = await api('/api/bluetooth/remove', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({mac}),
  });

  if (d.error) {
    showAlert('btAlert', 'Error removing device: ' + d.error, true);
    btn.disabled = false;
    return;
  }
  showAlert('btAlert', '✓ Device removed successfully.', false);
  await loadBluetoothPaired();
}
async function btConnect(mac, btn) {
  btn.disabled = true;
  btn.textContent = 'Connecting…';

  const d = await api('/api/bluetooth/connect', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({mac}),
  });

  if (d.error) {
    showAlert('btAlert', 'Error connecting: ' + d.error, true);
    btn.disabled = false;
    btn.textContent = '🔗 Connect';
    return;
  }
  if (d.warning) {
    showAlert('btAlert', d.warning, true);
  } else {
    showAlert('btAlert', '✓ Connected successfully.', false);
  }
  await loadBluetoothPaired();
}

function downloadLogs() {
  const lines = document.getElementById('logLines').value;
  const a = document.createElement('a');
  a.href = '/api/logs/download?lines=' + lines;
  a.download = 'modernjvs.log';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}

// ---- Appearance / Settings ----

const THEME_NAMES = {
  black:     'Pure Dark (default)',
  dark:      'Dark',
  light:     'Light',
  midnight:  'Midnight Blue',
  dracula:   'Dracula',
  terminal:  'Green Terminal',
  ocean:     'Ocean Deep',
  sunset:    'Sunset',
  forest:    'Forest',
  purple:    'Purple Night',
  neon:      'Neon Cyan',
  rose:      'Rose',
  amber:     'Amber',
  solarized: 'Solarized Dark',
};

// Seconds to wait for the WebUI service to come back up after a restart
const WEBUI_RESTART_WAIT_SECS = 8;

function updateFavicon(theme) {
  const filters = {
    dark:      'hue-rotate(330deg) saturate(1.1) brightness(0.75)',
    black:     'hue-rotate(330deg) saturate(1.1) brightness(0.75)',
    light:     'grayscale(1) brightness(0.5)',
    midnight:  'hue-rotate(182deg) saturate(1.1)',
    dracula:   'hue-rotate(238deg) saturate(1.2)',
    terminal:  'hue-rotate(118deg) saturate(1.2)',
    ocean:     'hue-rotate(178deg) saturate(1.2)',
    sunset:    'hue-rotate(6deg) saturate(1.2)',
    forest:    'hue-rotate(118deg) saturate(1.2)',
    purple:    'hue-rotate(248deg) saturate(1.2)',
    neon:      'hue-rotate(166deg) saturate(1.2)',
    rose:      'hue-rotate(334deg) saturate(1.1)',
    amber:     'hue-rotate(20deg) saturate(1.2)',
    solarized: 'hue-rotate(162deg) saturate(0.9)',
  };
  const src  = document.getElementById('sticks');
  const link = document.querySelector("link[rel='icon']");
  if (!src || !link) return;
  const c = document.createElement('canvas');
  c.width = c.height = 32;
  const ctx = c.getContext('2d');
  ctx.filter = filters[theme] || filters.black;
  ctx.drawImage(src, 0, 0, 32, 32);
  link.href = c.toDataURL();
}

function applyAppearanceSettings(s) {
  const root = document.documentElement;

  // Theme – always set an explicit data-theme value so selectors are consistent
  root.setAttribute('data-theme', s.theme || 'black');

  // Compact mode
  document.body.classList.toggle('compact', !!s.compact);

  // No animations
  document.body.classList.toggle('no-anim', !!s.noAnim);

  updateFavicon(s.theme || 'black');
}

async function initAppearancePanel() {
  const d = await api('/api/webui/settings');
  if (d.error) return;

  // Populate theme selector
  document.getElementById('stTheme').value      = d.theme     || 'black';
  document.getElementById('stCompact').checked  = !!d.compact;
  document.getElementById('stNoAnim').checked   = !!d.noAnim;

  initPasswordSection();
}

async function saveAppearanceSettings() {
  const s = {
    theme:          document.getElementById('stTheme').value,
    compact:        document.getElementById('stCompact').checked,
    noAnim:         document.getElementById('stNoAnim').checked,
  };
  const d = await api('/api/webui/settings', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(s),
  });
  if (d.error) {
    alert('Failed to save settings: ' + d.error);
    return;
  }
  applyAppearanceSettings(s);
}

async function resetAppearanceSettings() {
  const defaults = {theme:'black', compact:false, noAnim:false};
  await api('/api/webui/settings', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(defaults),
  });
  applyAppearanceSettings(defaults);
  initAppearancePanel();
}

// ---- Password protection ----
async function initPasswordSection() {
  const d = await api('/api/webui/password/status');
  if (d.error) return;
  const set = d.passwordSet;
  const statusEl = document.getElementById('pwStatus');
  statusEl.textContent = set
    ? '\uD83D\uDD10 Password protection is enabled.'
    : '\uD83D\uDD13 Password protection is disabled.';
  statusEl.style.color = set ? 'var(--green)' : 'var(--muted)';
  document.getElementById('pwClearBtn').style.display = set ? '' : 'none';
  document.getElementById('pwMsg').textContent = '';
}

async function setPassword() {
  const pw1 = document.getElementById('pwNew').value;
  const pw2 = document.getElementById('pwConfirm').value;
  const msg = document.getElementById('pwMsg');
  msg.style.color = 'var(--red)';
  if (!pw1) { msg.textContent = 'Please enter a new password.'; return; }
  if (pw1.length < 8) { msg.textContent = 'Password must be at least 8 characters.'; return; }
  if (pw1 !== pw2) { msg.textContent = 'Passwords do not match.'; return; }
  const d = await api('/api/webui/password', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({password: pw1}),
  });
  if (d.ok) {
    msg.style.color = 'var(--green)';
    msg.textContent = 'Password set successfully.';
    document.getElementById('pwNew').value = '';
    document.getElementById('pwConfirm').value = '';
    initPasswordSection();
  } else {
    msg.textContent = d.error || 'Failed to set password.';
  }
}

async function clearPassword() {
  if (!confirm('Remove password protection? Anyone on the local network will be able to access the WebUI.')) return;
  const d = await api('/api/webui/password/clear', {method: 'POST'});
  const msg = document.getElementById('pwMsg');
  if (d.ok) {
    msg.style.color = 'var(--muted)';
    msg.textContent = 'Password protection removed.';
    initPasswordSection();
  } else {
    msg.style.color = 'var(--red)';
    msg.textContent = d.error || 'Failed to clear password.';
  }
}

// ---- Restart WebUI ----
function restartWebUI() {
  const msg = document.getElementById('webuiRestartMsg');
  msg.style.display = 'block';
  // Fire-and-forget: the server schedules the restart after flushing the
  // response, but it may still die before we receive it.  Either way, start
  // the countdown immediately so the page reloads once the service is back up.
  fetch('/api/webui/restart', {method: 'POST'}).catch(() => {});
  let secs = WEBUI_RESTART_WAIT_SECS;
  const tick = () => {
    msg.textContent = 'WebUI restarting — reconnecting in ' + secs + 's…';
    if (secs-- > 0) { setTimeout(tick, 1000); }
    else { window.location.reload(); }
  };
  tick();
}

// ---- Active Sessions ----
async function loadSessions() {
  const d = await api('/api/sessions/list');
  const el = document.getElementById('sessionsList');
  if (!el) return;
  if (!d.password_set) {
    el.innerHTML = '<span style="font-size:0.85rem;color:var(--muted);">Sessions are only tracked when a WebUI password is set. Set a password in the Security section above to enable session management.</span>';
    return;
  }
  if (!d.sessions || d.sessions.length === 0) {
    el.innerHTML = '<span style="font-size:0.85rem;color:var(--muted);">No active sessions.</span>';
    return;
  }
  let html = '<table style="width:100%;border-collapse:collapse;font-size:0.82rem;">'
    + '<tr style="color:var(--muted);border-bottom:1px solid var(--border);">'
    + '<th style="text-align:left;padding:0.3rem 0.5rem;">Token</th>'
    + '<th style="text-align:left;padding:0.3rem 0.5rem;">IP</th>'
    + '<th style="text-align:left;padding:0.3rem 0.5rem;">Created</th>'
    + '<th style="text-align:left;padding:0.3rem 0.5rem;">Expires</th>'
    + '</tr>';
  d.sessions.forEach(s => {
    html += `<tr style="border-bottom:1px solid var(--border);">`
      + `<td style="padding:0.3rem 0.5rem;font-family:monospace;">${_escHtml(s.token_hint)}</td>`
      + `<td style="padding:0.3rem 0.5rem;">${_escHtml(s.ip || '—')}</td>`
      + `<td style="padding:0.3rem 0.5rem;">${_escHtml(s.created)}</td>`
      + `<td style="padding:0.3rem 0.5rem;">${_escHtml(s.expires)}</td>`
      + `</tr>`;
  });
  html += '</table>';
  el.innerHTML = html;
}

async function invalidateOtherSessions() {
  const d = await api('/api/sessions/invalidate_all', {method:'POST'});
  const msg = document.getElementById('sessionsMsg');
  if (d.ok) {
    msg.style.color = 'var(--green,#22c55e)';
    msg.textContent = 'All other sessions invalidated.';
    loadSessions();
  } else {
    msg.style.color = 'var(--red,#ef4444)';
    msg.textContent = d.error || 'Failed.';
  }
}

// ---- Audit Log ----
async function loadAuditLog() {
  const d = await api('/api/audit/log?lines=200');
  const el = document.getElementById('auditLogBox');
  if (!el) return;
  if (d.error) { el.textContent = 'Error: ' + d.error; return; }
  const lines = d.lines || [];
  if (lines.length === 0) {
    el.innerHTML = '<span style="color:var(--muted);font-size:0.82rem;">No audit log entries yet.</span>';
    return;
  }
  el.innerHTML = lines.map(l => {
    const div = document.createElement('div');
    div.className = 'log-line log-info';
    div.textContent = l.replace(/\n$/, '');
    return div.outerHTML;
  }).join('');
  el.scrollTop = el.scrollHeight;
}

// ---- System Power ----
async function systemReboot() {
  if (!confirm('Restart the Raspberry Pi now?\n\nThe WebUI will be unreachable for ~30 seconds.')) return;
  const msg = document.getElementById('systemPowerMsg');
  msg.style.color = 'var(--muted)';
  msg.textContent = 'Rebooting…';
  fetch('/api/system/reboot', {method: 'POST'}).catch(() => {});
}

async function systemShutdown() {
  if (!confirm('Shut down the Raspberry Pi now?\n\nYou will need physical access to turn it back on.')) return;
  const msg = document.getElementById('systemPowerMsg');
  msg.style.color = 'var(--muted)';
  msg.textContent = 'Shutting down…';
  fetch('/api/system/shutdown', {method: 'POST'}).catch(() => {});
}

// ---- Diagnostics ----
async function loadDiagnostics() {
  // Populate GPIO pin from config
  const cfg = await api('/api/config');
  if (!cfg.error) {
    const pin = cfg.sense_line_pin || '26';
    document.getElementById('diagGpioPin').value = pin;
  }

  // Load available serial ports
  const pd = await api('/api/diag/serial/ports');
  const sel = document.getElementById('diagSerialPort');
  sel.innerHTML = '';
  const ports = pd.ports || [];
  if (ports.length === 0) {
    sel.innerHTML = '<option value="">— no serial ports found —</option>';
  } else {
    sel.innerHTML = '<option value="">— select a port —</option>';
    ports.forEach(p => {
      const o = document.createElement('option');
      o.value = p;
      o.textContent = p;
      // Pre-select the configured device path if present
      if (!cfg.error && cfg.device && cfg.device === p) o.selected = true;
      sel.appendChild(o);
    });
  }

  // Mirror the same port list into the JVS probe dropdown
  const jvsSel = document.getElementById('diagJvsPort');
  jvsSel.innerHTML = '';
  if (ports.length === 0) {
    jvsSel.innerHTML = '<option value="">— no serial ports found —</option>';
  } else {
    jvsSel.innerHTML = '<option value="">— select a port —</option>';
    ports.forEach(p => {
      const o = document.createElement('option');
      o.value = p;
      o.textContent = p;
      if (!cfg.error && cfg.device && cfg.device === p) o.selected = true;
      jvsSel.appendChild(o);
    });
  }

  // Also fill the custom input with configured device if not in the dropdown
  if (!cfg.error && cfg.device) {
    document.getElementById('diagSerialCustom').placeholder = cfg.device;
    document.getElementById('diagJvsCustom').placeholder = cfg.device;
  }

  // Render port list card
  const wrap = document.getElementById('diagPortListWrap');
  if (ports.length === 0) {
    wrap.textContent = 'No serial devices found under /dev/tty{USB,AMA,S}*.';
    wrap.style.color = 'var(--muted)';
  } else {
    wrap.innerHTML = ports.map(p => `<div style="padding:0.15rem 0;color:var(--accent2);">${_escHtml(p)}</div>`).join('');
  }

  loadUsbDevices();
}

// ---- Diagnostics abort / cleanup ----
let _diagAbortCtrl = null;

function _diagAbortCurrent() {
  if (_diagAbortCtrl) { try { _diagAbortCtrl.abort(); } catch(_) {} }
  _diagAbortCtrl = new AbortController();
  return _diagAbortCtrl;
}

function cancelDiagTests() {
  if (_diagAbortCtrl) { try { _diagAbortCtrl.abort(); } catch(_) {} _diagAbortCtrl = null; }
  // Release any GPIO line held by a Set HIGH / Set LOW operation on the server.
  fetch('/api/diag/gpio/cancel', {method:'POST'}).catch(() => {});
  ['diagSerialResult', 'diagGpioResult', 'diagJvsResult'].forEach(id => {
    const el = document.getElementById(id);
    if (el) { el.textContent = ''; el.style.color = ''; }
  });
}

async function runSerialTest() {
  const custom = document.getElementById('diagSerialCustom').value.trim();
  const sel    = document.getElementById('diagSerialPort').value;
  const device = custom || sel;
  if (!device) {
    showAlert('diagSerialAlert', 'No device selected or typed.', true);
    return;
  }
  const ac = _diagAbortCurrent();
  const resultEl = document.getElementById('diagSerialResult');
  resultEl.textContent = '⏳ Testing…';
  resultEl.style.color = 'var(--muted)';
  const d = await api('/api/diag/serial', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({device}),
    signal: ac.signal
  });
  if (ac.signal.aborted) return;
  if (d.error) {
    resultEl.textContent = '✗ ' + d.error;
    resultEl.style.color = 'var(--red, #e06c75)';
  } else if (d.ok) {
    resultEl.textContent = '✓ ' + d.message;
    resultEl.style.color = 'var(--green, #98c379)';
  } else {
    resultEl.textContent = '✗ ' + d.message;
    resultEl.style.color = 'var(--red, #e06c75)';
  }
}

async function runGpioTest() {
  const pin = document.getElementById('diagGpioPin').value.trim();
  if (!pin) {
    showAlert('diagGpioAlert', 'Enter a pin number.', true);
    return;
  }
  const ac = _diagAbortCurrent();
  const resultEl = document.getElementById('diagGpioResult');
  resultEl.textContent = '⏳ Reading…';
  resultEl.style.color = 'var(--muted)';
  const d = await api('/api/diag/gpio', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({pin}),
    signal: ac.signal
  });
  if (ac.signal.aborted) return;
  if (d.error) {
    resultEl.textContent = '✗ ' + d.error;
    resultEl.style.color = 'var(--red, #e06c75)';
  } else if (d.ok) {
    const stateColor = d.state === 'HIGH' ? 'var(--accent2, #61afef)' : (d.state === 'LOW' ? 'var(--yellow, #e5c07b)' : 'var(--text)');
    resultEl.innerHTML = `✓ <span style="color:${stateColor};font-weight:bold;">${_escHtml(d.state || '')}</span> — ${_escHtml(d.message)}`;
    resultEl.style.color = 'var(--text)';
  } else {
    resultEl.textContent = '✗ ' + d.message;
    resultEl.style.color = 'var(--red, #e06c75)';
  }
}

async function setGpioPin(level) {
  const pin = document.getElementById('diagGpioPin').value.trim();
  if (!pin) {
    showAlert('diagGpioAlert', 'Enter a pin number.', true);
    return;
  }
  const durRaw = parseInt(document.getElementById('diagGpioDuration').value, 10);
  const duration = (!isNaN(durRaw) && durRaw >= 1) ? Math.min(durRaw, 60) : 3;
  const ac = _diagAbortCurrent();
  const resultEl = document.getElementById('diagGpioResult');
  resultEl.textContent = `⏳ Driving pin ${level.toUpperCase()} for ${duration} s…`;
  resultEl.style.color = 'var(--muted)';
  const d = await api('/api/diag/gpio/set', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({pin, level, duration}),
    signal: ac.signal
  });
  if (ac.signal.aborted) return;
  if (d.error) {
    resultEl.textContent = '✗ ' + d.error;
    resultEl.style.color = 'var(--red, #e06c75)';
  } else if (d.ok) {
    const lvlColor = level === 'high' ? 'var(--accent2, #61afef)' : 'var(--yellow, #e5c07b)';
    resultEl.innerHTML = `✓ <span style="color:${lvlColor};font-weight:bold;">${_escHtml(d.state || level.toUpperCase())}</span> — ${_escHtml(d.message)}`;
    resultEl.style.color = 'var(--text)';
  } else {
    resultEl.textContent = '✗ ' + d.message;
    resultEl.style.color = 'var(--red, #e06c75)';
  }
}

async function runJvsBusProbe() {
  const custom = document.getElementById('diagJvsCustom').value.trim();
  const sel    = document.getElementById('diagJvsPort').value;
  const device = custom || sel;
  if (!device) {
    showAlert('diagJvsAlert', 'No device selected or typed.', true);
    return;
  }
  const ac = _diagAbortCurrent();
  const resultEl = document.getElementById('diagJvsResult');
  resultEl.innerHTML = '⏳ Checking service state and probing bus…';
  resultEl.style.color = 'var(--muted)';
  const d = await api('/api/diag/jvs/probe', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({device}),
    signal: ac.signal
  });
  if (ac.signal.aborted) return;
  if (d.error) {
    resultEl.textContent = '✗ ' + d.error;
    resultEl.style.color = 'var(--red, #e06c75)';
    return;
  }
  if (!d.ok) {
    resultEl.textContent = '✗ ' + d.message;
    resultEl.style.color = 'var(--red, #e06c75)';
    return;
  }
  if (d.mode === 'service_running') {
    resultEl.style.color = 'var(--text)';
    resultEl.innerHTML =
      `<div style="color:var(--accent2,#61afef);font-weight:bold;">ℹ ${_escHtml(d.message)}</div>`
      + `<div style="margin-top:0.4rem;font-size:0.82rem;color:var(--muted);">`
      + `Stop the ModernJVS service and probe again to send a RESET broadcast and inspect raw bus traffic.`
      + `</div>`;
    return;
  }
  if (d.activity) {
    resultEl.style.color = 'var(--text)';
    let html = `<div style="color:var(--green,#98c379);font-weight:bold;">✓ ${_escHtml(d.message)}</div>`;
    if (d.raw_hex) {
      html += `<div style="margin-top:0.4rem;color:var(--muted);">Raw bytes: <code style="color:var(--accent2);word-break:break-all;">${_escHtml(d.raw_hex)}${d.truncated ? '…' : ''}</code></div>`;
    }
    if (d.packets && d.packets.length > 0) {
      html += '<div style="margin-top:0.5rem;">Parsed JVS packets:</div>'
            + '<ul style="margin:0.25rem 0 0 1rem;padding:0;">'
            + d.packets.map(p =>
                `<li><code style="color:var(--accent2);">${_escHtml(p.name)}</code>`
                + ` <span style="color:var(--muted);">→ ${_escHtml(p.dest)}</span></li>`
              ).join('')
            + '</ul>';
    }
    resultEl.innerHTML = html;
  } else {
    resultEl.textContent = '✗ ' + d.message;
    resultEl.style.color = 'var(--red, #e06c75)';
  }
}

async function runJvsBusMonitor() {
  const custom = document.getElementById('diagJvsCustom').value.trim();
  const sel    = document.getElementById('diagJvsPort').value;
  const device = custom || sel;
  if (!device) {
    showAlert('diagJvsAlert', 'No device selected or typed.', true);
    return;
  }
  const ac = _diagAbortCurrent();
  const resultEl = document.getElementById('diagJvsResult');
  resultEl.innerHTML = '⏳ Listening on bus for 5 seconds…';
  resultEl.style.color = 'var(--muted)';
  const d = await api('/api/diag/jvs/monitor', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({device}),
    signal: ac.signal
  });
  if (ac.signal.aborted) return;
  if (d.error) {
    resultEl.textContent = '✗ ' + d.error;
    resultEl.style.color = 'var(--red, #e06c75)';
    return;
  }
  if (!d.ok) {
    resultEl.textContent = '✗ ' + d.message;
    resultEl.style.color = 'var(--red, #e06c75)';
    return;
  }
  // Service-running mode: bus is actively in use by the daemon
  if (d.mode === 'service_running') {
    resultEl.style.color = 'var(--text)';
    resultEl.innerHTML =
      `<div style="color:var(--accent2,#61afef);font-weight:bold;">ℹ ${_escHtml(d.message)}</div>`
      + `<div style="margin-top:0.4rem;font-size:0.82rem;color:var(--muted);">`
      + `Stop the ModernJVS service and monitor again to inspect raw bus traffic.`
      + `</div>`;
    return;
  }
  // Passive-monitor mode
  if (d.activity) {
    resultEl.style.color = 'var(--text)';
    let html = `<div style="color:var(--green,#98c379);font-weight:bold;">✓ ${_escHtml(d.message)}</div>`;
    if (d.raw_hex) {
      html += `<div style="margin-top:0.4rem;color:var(--muted);">Raw bytes: <code style="color:var(--accent2);word-break:break-all;">${_escHtml(d.raw_hex)}${d.truncated ? '…' : ''}</code></div>`;
    }
    if (d.packets && d.packets.length > 0) {
      html += '<div style="margin-top:0.5rem;">Parsed JVS packets:</div>'
            + '<ul style="margin:0.25rem 0 0 1rem;padding:0;">'
            + d.packets.map(p =>
                `<li><code style="color:var(--accent2);">${_escHtml(p.name)}</code>`
                + ` <span style="color:var(--muted);">→ ${_escHtml(p.dest)}</span></li>`
              ).join('')
            + '</ul>';
    }
    resultEl.innerHTML = html;
  } else {
    resultEl.textContent = '✗ ' + d.message;
    resultEl.style.color = 'var(--red, #e06c75)';
  }
}

async function jvsServiceAction(action) {
  const d = await api('/api/control', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({action})
  });
  if (d.error) {
    showAlert('diagJvsAlert', 'Error: ' + d.error, true);
  } else {
    showAlert('diagJvsAlert', 'Service ' + action + ' successful.', false);
  }
}

async function loadUsbDevices() {
  const wrap = document.getElementById('diagUsbWrap');
  wrap.textContent = '⏳ Scanning…';
  wrap.style.color = 'var(--muted)';
  const d = await api('/api/diag/usb/devices');
  if (d.error) {
    wrap.textContent = '✗ ' + d.error;
    wrap.style.color = 'var(--red, #e06c75)';
    return;
  }
  const devices = d.devices || [];
  if (devices.length === 0) {
    wrap.textContent = 'No USB devices found.';
    wrap.style.color = 'var(--muted)';
    return;
  }
  wrap.style.color = '';
  wrap.innerHTML = devices.map(dev => {
    const vidpid = dev.vid + ':' + dev.pid;
    const label  = dev.product || dev.manufacturer || vidpid;
    const mfgStr = dev.manufacturer ? `<span style="color:var(--muted);margin-right:0.25rem;">${_escHtml(dev.manufacturer)}</span>` : '';
    let driverBadge;
    if (dev.driver) {
      const dc = dev.is_serial_driver ? 'var(--accent2, #61afef)' : 'var(--muted)';
      driverBadge = `<span style="font-size:0.75rem;padding:0.1rem 0.4rem;background:var(--surface2,#2c313a);border-radius:3px;color:${dc};">${_escHtml(dev.driver)}</span>`;
    } else {
      driverBadge = `<span style="font-size:0.75rem;padding:0.1rem 0.4rem;background:var(--surface2,#2c313a);border-radius:3px;color:var(--red,#e06c75);">unbound</span>`;
    }
    const rs485Badge = dev.is_rs485
      ? `<span style="font-size:0.75rem;padding:0.1rem 0.4rem;background:var(--yellow,#e5c07b);color:#1a1a1a;border-radius:3px;">RS-485/Serial: ${_escHtml(dev.rs485_chip)}</span>`
      : '';
    return `<div style="padding:0.35rem 0;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:0.4rem;flex-wrap:wrap;">`
      + `<code style="color:var(--accent2);font-family:monospace;">${_escHtml(vidpid)}</code>`
      + mfgStr
      + `<strong>${_escHtml(label)}</strong>`
      + (rs485Badge ? ' ' + rs485Badge : '')
      + ' ' + driverBadge
      + `</div>`;
  }).join('');
}

// ---- Init ----
// Fetch appearance settings from the server and apply them before first render.
// Falls back to sensible defaults if the server hasn't stored any yet.
api('/api/webui/settings').then(s => {
  applyAppearanceSettings(s.error ? {} : s);
});
refreshDashboard();
refreshSysinfo();
setInterval(refreshDashboard, 10000);
setInterval(refreshSysinfo, 5000);

// Fetch version once and show in header badge (desktop) and footer (mobile)
api('/api/version').then(d => {
  if (d.version && d.version !== 'unknown') {
    const badge = document.getElementById('verBadge');
    badge.textContent = 'v' + d.version;
    badge.classList.add('visible');
    const footerVer = document.getElementById('footerVer');
    if (footerVer) footerVer.textContent = 'v' + d.version + ' ';
  }
});

// ---- SSH Terminal ----
let _term = null;
let _termWs = null;
let _termFit = null;

function _termEnsureInit() {
  if (_term) return;
  const container = document.getElementById('terminal-container');
  if (typeof Terminal === 'undefined' || !container) return;
  _term = new Terminal({ cursorBlink: true, fontSize: 14, fontFamily: 'monospace' });
  if (typeof FitAddon !== 'undefined') {
    _termFit = new FitAddon();
    _term.loadAddon(_termFit);
  }
  _term.open(container);
  if (_termFit) _termFit.fit();
  window.addEventListener('resize', () => { if (_termFit) _termFit.fit(); });
}

function termConnect() {
  _termEnsureInit();
  if (!_term) { document.getElementById('termMsg').textContent = 'xterm.js not available — try reloading the page.'; return; }
  const host = document.getElementById('termHost').value.trim() || 'localhost';
  const port = parseInt(document.getElementById('termPort').value) || 22;
  const user = document.getElementById('termUser').value.trim() || 'pi';
  const wsUrl = `ws://${location.hostname}:${location.port || 8080}/terminal/ws?host=${encodeURIComponent(host)}&port=${port}&user=${encodeURIComponent(user)}`;
  document.getElementById('termMsg').textContent = 'Connecting…';
  _termWs = new WebSocket(wsUrl);
  _termWs.binaryType = 'arraybuffer';
  _termWs.onopen = () => {
    document.getElementById('termMsg').textContent = '';
    document.getElementById('termConnectBtn').style.display = 'none';
    document.getElementById('termDisconnectBtn').style.display = '';
    _term.focus();
    if (_termFit) _termFit.fit();
  };
  _termWs.onmessage = (ev) => {
    if (ev.data instanceof ArrayBuffer) {
      _term.write(new Uint8Array(ev.data));
    } else {
      _term.write(ev.data);
    }
  };
  _termWs.onclose = (ev) => {
    document.getElementById('termMsg').textContent = 'Disconnected' + (ev.reason ? ': ' + ev.reason : '.');
    document.getElementById('termConnectBtn').style.display = '';
    document.getElementById('termDisconnectBtn').style.display = 'none';
    _termWs = null;
  };
  _termWs.onerror = () => {
    document.getElementById('termMsg').textContent = 'WebSocket error — see browser console.';
  };
  _term.onData(data => {
    if (_termWs && _termWs.readyState === WebSocket.OPEN) _termWs.send(data);
  });
}

function termDisconnect() {
  if (_termWs) { _termWs.close(); _termWs = null; }
  document.getElementById('termConnectBtn').style.display = '';
  document.getElementById('termDisconnectBtn').style.display = 'none';
}
</script>
</body>
</html>
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
    """Build the final HTML page, embedding the logo as a base64 data URI."""
    return (
        _HTML_TEMPLATE
        .replace("__LOGO__",           _logo_data_uri())
        .replace("__STICKS__",         _sticks_data_uri())
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
            if directive in _optional_directives and not str(val).strip():
                _remove_directives.add(directive)
            else:
                updates[directive] = val

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
        with open(CONFIG_PATH, "w") as f:
            f.writelines(new_lines)
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


def get_player_slots():
    """Parse player slot assignments from the most recent service run's logs.

    Scans the service log for ``Player N:`` lines emitted by initInputs()
    and returns them as a list sorted by player number.  Only the most recent
    service start (identified by the last 'ModernJVS Version' banner) is used
    so that stale entries from a previous run are not shown.

    Returns a list of dicts: [{"player": int, "profile": str}, ...]
    """
    logs = get_logs(200)
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
    players = {}
    for line in logs[start_idx:]:
        m = _player_re.search(line)
        if m:
            num = int(m.group(1))
            players[num] = m.group(2).strip()
    return [{"player": k, "profile": v} for k, v in sorted(players.items())]


def get_jvs_connection_status():
    """Determine JVS connection status from the most recent service run's logs.

    Scans the service log for ``JVS: Connection established``,
    ``JVS: Connection reset``, and ``JVS: Connection lost`` lines emitted by
    jvs.c and returns the state based on which event appeared last.  Only the
    most recent service start (identified by the last 'ModernJVS Version'
    banner) is used so that stale entries from a previous run are not shown.

    ``JVS: Connection reset`` is logged when the arcade machine sends CMD_RESET.
    ``JVS: Connection lost`` is logged after 5 s of inactivity on an established
    connection (e.g. arcade machine powered off without sending a reset).

    Returns True if the JVS connection is currently established, False otherwise.
    """
    # 200 lines is enough to cover startup messages plus any connection events
    # since the last 'ModernJVS Version' banner in a typical run.
    logs = get_logs(200)
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

    cfg = config_to_api(read_config())
    return {
        "active_state":  props.get("ActiveState", "unknown"),
        "main_pid":      props.get("MainPID", ""),
        "active_since":  props.get("ActiveEnterTimestamp", ""),
        "config":        cfg,
        "players":       get_player_slots(),
        "jvs_connected": get_jvs_connection_status(),
    }


def get_logs(lines=100):
    """Return recent log lines for the modernjvs service.

    Tries journalctl first (works on Raspberry Pi OS and DietPi with journald).
    Falls back to grepping syslog files on systems without a persistent journal
    (e.g. DietPi configured with volatile-only journald or syslog-only logging).
    """
    lines_count = int(lines)
    lines_str = str(lines_count)

    # Primary: journalctl (systemd journal – works on RPiOS and most DietPi setups)
    try:
        result = subprocess.run(
            ["journalctl", "-u", SERVICE_NAME, "-n", lines_str,
             "--no-pager", "--output=short-iso"],
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

            # Collect bytes for up to 500 ms
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


# Build HTML_PAGE now that get_logo_bytes() / get_sticks_bytes() are defined.
def _build_login_page():
    """Build the login page, embedding static sysinfo (kernel, libgpiod, Pi model)."""
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
    return _LOGIN_TEMPLATE.format(
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
        ver = (result.stdout + result.stderr).strip()
        if ver:
            return ver
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
      pi_gen          — integer Pi generation (0 = unknown/non-Pi or Pi Zero/1)
      has_internal_bt — True if this Pi model ships with an internal BT chip
      is_pi5_or_later — True for Pi 5+; these don't need the USB-dongle workaround
      is_dietpi       — True when running on DietPi (uses dietpi-config, not raspi-config)
      hci_present     — True if at least one HCI Bluetooth adapter is visible
      bluez_available — True if bluetoothctl is on PATH
      bt_service_running — True if systemd bluetooth.service is active
      rfkill_soft_blocked — True if BT is soft-blocked by rfkill
      internal_bt_disabled — True if dtoverlay=disable-bt is in the boot config
    """
    # ---- Raspberry Pi model detection ----
    pi_model = ""
    try:
        with open("/proc/device-tree/model", "r", encoding="utf-8", errors="replace") as f:
            pi_model = f.read().strip().rstrip("\x00")
    except OSError:
        pass

    pi_gen = 0
    has_internal_bt = False
    is_pi5_or_later = False

    if pi_model:
        m_gen = re.search(r"raspberry pi (\d+)", pi_model, re.IGNORECASE)
        if m_gen:
            pi_gen = int(m_gen.group(1))
            has_internal_bt = pi_gen >= 3
            is_pi5_or_later = pi_gen >= 5
        elif re.search(r"raspberry pi zero.*w", pi_model, re.IGNORECASE):
            # Zero W and Zero 2 W have internal BT
            has_internal_bt = True

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

    # ---- dtoverlay=disable-bt in boot config (uncommented lines only) ----
    internal_bt_disabled = False
    _disable_bt_re = re.compile(r'^\s*dtoverlay\s*=\s*disable-bt')
    for boot_cfg in ("/boot/firmware/config.txt", "/boot/config.txt"):
        try:
            with open(boot_cfg) as f:
                for line in f:
                    if _disable_bt_re.match(line):
                        internal_bt_disabled = True
                        break
            if internal_bt_disabled:
                break
        except OSError:
            continue

    # ---- DietPi detection ----
    is_dietpi = os.path.isfile("/etc/dietpi/.version")

    return {
        "pi_model":             pi_model,
        "pi_gen":               pi_gen,
        "has_internal_bt":      has_internal_bt,
        "is_pi5_or_later":      is_pi5_or_later,
        "is_dietpi":            is_dietpi,
        "hci_present":          hci_present,
        "bluez_available":      bluez_available,
        "bt_service_running":   bt_service_running,
        "rfkill_soft_blocked":  rfkill_soft_blocked,
        "internal_bt_disabled": internal_bt_disabled,
    }


def setup_usb_bluetooth():
    """Install BlueZ packages and disable internal Bluetooth for USB-dongle use.

    - Installs bluetooth, bluez, and bluez-tools via apt-get.
    - On Pi 3/4 (models with internal BT that conflicts with JVS serial),
      appends dtoverlay=disable-bt to the boot config so the internal adapter
      is suppressed and only the USB dongle is used.
    - Enables the bluetooth systemd service.
    - Returns {"ok": True, "reboot_needed": bool, "output": [lines]}.
    """
    output_lines = []
    reboot_needed = False

    s = get_bluetooth_status()

    # ---- Disable internal Bluetooth in boot config if applicable ----
    if s["has_internal_bt"] and not s["is_pi5_or_later"] and not s["internal_bt_disabled"]:
        boot_cfg = None
        for path in ("/boot/firmware/config.txt", "/boot/config.txt"):
            if os.path.isfile(path):
                boot_cfg = path
                break
        if boot_cfg:
            try:
                with open(boot_cfg, "a") as f:
                    f.write(
                        "\n# Disable internal Bluetooth to use USB Bluetooth adapter\n"
                        "dtoverlay=disable-bt\n"
                    )
                output_lines.append(
                    f"✓ Internal Bluetooth disabled in {boot_cfg} (reboot required)."
                )
                reboot_needed = True
            except OSError as e:
                return {"error": f"Could not modify boot config: {e}"}
        else:
            output_lines.append("⚠ Boot config file not found; skipped disabling internal Bluetooth.")
    elif s["internal_bt_disabled"]:
        output_lines.append("✓ Internal Bluetooth already disabled in boot config.")

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

    return {"ok": True, "reboot_needed": reboot_needed, "output": output_lines}


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

        if not self._check_auth():
            return

        if path == "/" or path == "/index.html":
            self._send_html(HTML_PAGE)
        elif path == "/logo":
            self._serve_logo()
        elif path == "/sticks":
            self._serve_sticks()
        elif path == "/xterm.js":
            self._serve_xterm_js()
        elif path == "/xterm.css":
            self._serve_xterm_css()
        elif path == "/addon-fit.js":
            self._serve_addon_fit_js()
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
        elif path == "/api/version":
            self._json({"version": get_version()})
        elif path == "/api/webui/settings":
            self._json(read_webui_settings())
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
                    err_msg = f'data: {{"error":"{str(e)}"}}\n\n'.encode("utf-8")
                    try:
                        self.wfile.write(err_msg)
                        self.wfile.flush()
                    except OSError:
                        pass
                finally:
                    os.close(fd)
            except OSError as e:
                err_msg = f'data: {{"error":"{str(e)}"}}\n\n'.encode("utf-8")
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
        elif path == "/terminal/ws":
            self._handle_terminal_ws(query)
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
                self._json({"ok": True})
            else:
                self._json({"error": msg}, HTTPStatus.INTERNAL_SERVER_ERROR)

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
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length).decode("utf-8") if length else ""

    def _read_raw_body(self):
        """Read the raw request body as bytes (for binary uploads)."""
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length else b""

    def _handle_profile_upload(self):
        """Accept a profile file upload via binary POST with X-Profile-Type/Name headers."""
        type_ = self.headers.get("X-Profile-Type", "")
        name  = os.path.basename(self.headers.get("X-Profile-Name", ""))
        fpath = _resolve_profile_path(type_, name)
        if fpath is None:
            self._json({"error": "Invalid type or name."}, HTTPStatus.BAD_REQUEST)
            return
        content_length = int(self.headers.get("Content-Length", 0))
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

    def _handle_terminal_ws(self, query):
        """Upgrade the connection to a WebSocket and proxy an SSH session."""
        # ---- Validate SSH target host ----
        host = query.get("host", ["localhost"])[0]
        try:
            port = int(query.get("port", ["22"])[0])
            if port < 1 or port > 65535:
                raise ValueError
        except ValueError:
            port = 22
        user = query.get("user", [os.environ.get("USER", "pi")])[0]
        # Strip characters unsafe for shell args
        if not re.fullmatch(r"[A-Za-z0-9._@-]{1,253}", host):
            self._access_denied(self.client_address[0])
            return
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", user):
            self._access_denied(self.client_address[0])
            return
        # Only allow private/local SSH targets
        if not is_private_ip(host) and host != "localhost":
            self._access_denied(self.client_address[0])
            return

        # ---- WebSocket handshake (RFC 6455) ----
        key = self.headers.get("Sec-WebSocket-Key", "")
        if not key:
            self.send_response(HTTPStatus.BAD_REQUEST)
            self.send_header("Content-Length", 0)
            self.end_headers()
            return
        magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
        accept = base64.b64encode(
            hashlib.sha1((key + magic).encode()).digest()
        ).decode()
        self.send_response(101, "Switching Protocols")
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()
        self.wfile.flush()

        audit_log("SSH terminal connect", f"{user}@{host}:{port}", ip=self.client_address[0])

        # ---- Spawn SSH via PTY ----
        master_fd, slave_fd = pty.openpty()
        try:
            proc = subprocess.Popen(
                ["ssh", "-tt", "-o", "StrictHostKeyChecking=accept-new",
                 "-p", str(port), f"{user}@{host}"],
                stdin=slave_fd, stdout=slave_fd, stderr=slave_fd,
                close_fds=True,
            )
        except OSError:
            os.close(master_fd)
            os.close(slave_fd)
            return
        os.close(slave_fd)

        sock = self.request
        sock.setblocking(False)

        def _ws_send(data: bytes):
            """Frame *data* as a binary WebSocket frame and write it."""
            hdr = bytearray()
            hdr.append(0x82)  # FIN + opcode=binary
            length = len(data)
            if length < 126:
                hdr.append(length)
            elif length < 65536:
                hdr.append(126)
                hdr += struct.pack(">H", length)
            else:
                hdr.append(127)
                hdr += struct.pack(">Q", length)
            try:
                sock.sendall(bytes(hdr) + data)
            except OSError:
                pass

        def _ws_recv_frame(buf: bytearray):
            """Parse the first complete WebSocket frame from *buf*.

            Returns (opcode, payload_bytes, remaining_buf) or None if incomplete.
            """
            if len(buf) < 2:
                return None
            b0, b1 = buf[0], buf[1]
            masked = bool(b1 & 0x80)
            length = b1 & 0x7F
            offset = 2
            if length == 126:
                if len(buf) < 4:
                    return None
                length = struct.unpack_from(">H", buf, 2)[0]
                offset = 4
            elif length == 127:
                if len(buf) < 10:
                    return None
                length = struct.unpack_from(">Q", buf, 2)[0]
                offset = 10
            mask_len = 4 if masked else 0
            if len(buf) < offset + mask_len + length:
                return None
            mask = buf[offset:offset + mask_len]
            offset += mask_len
            payload = bytearray(buf[offset:offset + length])
            if masked:
                for i in range(len(payload)):
                    payload[i] ^= mask[i % 4]
            remaining = buf[offset + length:]
            opcode = b0 & 0x0F
            return opcode, bytes(payload), bytearray(remaining)

        recv_buf = bytearray()
        done = False
        try:
            while not done:
                rlist = [master_fd, sock]
                try:
                    readable, _, _ = select.select(rlist, [], [], 0.05)
                except (ValueError, OSError):
                    break

                # PTY → WebSocket
                if master_fd in readable:
                    try:
                        data = os.read(master_fd, 4096)
                    except OSError:
                        break
                    if data:
                        _ws_send(data)

                # WebSocket → PTY
                if sock in readable:
                    try:
                        chunk = sock.recv(4096)
                    except BlockingIOError:
                        chunk = b""
                    except OSError:
                        break
                    if not chunk:
                        break
                    recv_buf += chunk
                    while True:
                        result = _ws_recv_frame(recv_buf)
                        if result is None:
                            break
                        opcode, payload, recv_buf = result
                        if opcode == 0x8:   # close
                            done = True
                            break
                        if opcode in (0x1, 0x2) and payload:
                            try:
                                os.write(master_fd, payload)
                            except OSError:
                                done = True
                                break

                if proc.poll() is not None:
                    break
        finally:
            try:
                proc.terminate()
            except OSError:
                pass
            try:
                os.close(master_fd)
            except OSError:
                pass

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

    def _serve_xterm_js(self):
        data = base64.b64decode(_XTERM_JS_B64)
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/javascript")
        self.send_header("Content-Length", len(data))
        self.send_header("Cache-Control", "max-age=604800")
        self.end_headers()
        self.wfile.write(data)

    def _serve_xterm_css(self):
        data = base64.b64decode(_XTERM_CSS_B64)
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/css")
        self.send_header("Content-Length", len(data))
        self.send_header("Cache-Control", "max-age=604800")
        self.end_headers()
        self.wfile.write(data)

    def _serve_addon_fit_js(self):
        data = base64.b64decode(_ADDON_FIT_JS_B64)
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/javascript")
        self.send_header("Content-Length", len(data))
        self.send_header("Cache-Control", "max-age=604800")
        self.end_headers()
        self.wfile.write(data)

    def _not_found(self):
        self._json({"error": "Not found"}, HTTPStatus.NOT_FOUND)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    server = http.server.ThreadingHTTPServer(("0.0.0.0", WEBUI_PORT), WebUIHandler)
    print(f"ModernJVS WebUI running on http://0.0.0.0:{WEBUI_PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()


if __name__ == "__main__":
    main()
