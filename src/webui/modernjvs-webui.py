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
# HTML / CSS / JS – embedded so the server is a single file with no assets
# ---------------------------------------------------------------------------
_HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ModernJVS WebUI</title>
<link rel="icon" type="image/png" href="__STICKS__">
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
setInterval(refreshDashboard, 2000);
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


def get_player_slots(logs=None):
    """Parse player slot assignments from the most recent service run's logs.

    Scans the service log for ``Player N:`` lines emitted by initInputs()
    and returns them as a list sorted by player number.  Only the most recent
    service start (identified by the last 'ModernJVS Version' banner) is used
    so that stale entries from a previous run are not shown.

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
    players = {}
    last_player_idx = -1
    last_no_controllers_idx = -1
    for idx, line in enumerate(logs[start_idx:], start=start_idx):
        m = _player_re.search(line)
        if m:
            num = int(m.group(1))
            players[num] = m.group(2).strip()
            last_player_idx = idx
        if "Controllers:     None" in line or "No controllers detected" in line:
            last_no_controllers_idx = idx

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
    return {
        "active_state":  props.get("ActiveState", "unknown"),
        "main_pid":      props.get("MainPID", ""),
        "active_since":  props.get("ActiveEnterTimestamp", ""),
        "config":        cfg,
        "players":       get_player_slots(logs=logs),
        "jvs_connected": get_jvs_connection_status(logs=logs),
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


def set_bluetooth_supervision_timeout():
    """Apply a 3-second link supervision timeout to all active Bluetooth connections.

    BR/EDR (ACL) connections use ``hcitool lst <address> 4800``
    (4800 × 0.625 ms = 3 s).
    LE connections use ``hcitool lecup <handle> 6 12 0 300``
    (300 × 10 ms = 3 s, with low-latency 7.5–15 ms connection intervals).

    Returns {"ok": True, "output": [...lines], "count": N} on success, or
    {"ok": True, "partial": True, "output": [...lines]} if some connections
    could not be updated, or {"error": ...} on a hard failure.
    """
    supervision_timeout_bredr = 4800  # 3 s in 0.625 ms BR/EDR slots
    supervision_timeout_le    = 300   # 3 s in 10 ms LE units
    le_interval_min = 6
    le_interval_max = 12
    le_latency      = 0

    if not shutil.which("hcitool"):
        return {"error": "hcitool not found. Please install bluez: sudo apt install bluez"}

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
                    ["hcitool", "lst", address, str(supervision_timeout_bredr)],
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
                     str(le_interval_min), str(le_interval_max),
                     str(le_latency), str(supervision_timeout_le)],
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
            return ""
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

    def _not_found(self):
        self._json({"error": "Not found"}, HTTPStatus.NOT_FOUND)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _supervision_timeout_loop():
    """Background thread: apply BT supervision timeout every 30 s automatically."""
    while True:
        try:
            set_bluetooth_supervision_timeout()
        except Exception as e:
            print(f"[webui] WARNING: supervision timeout apply failed: {e}", flush=True)
        time.sleep(30)


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
