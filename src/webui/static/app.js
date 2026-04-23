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
  if (name !== 'devices') {
    stopInputTest(); // stop streaming when leaving the Devices tab
    clearBluetoothScanResults(); // discard stale scan list when leaving the Devices tab
  }
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

  updateTestButtonUI(!!d.test_button_active, d.jvs_connected === true);
}

function updateTestButtonUI(active, jvsConnected) {
  const card = document.getElementById('testBtnToggle');
  const val  = document.getElementById('testModeVal');
  if (!card) return;
  const canUse = !!jvsConnected;
  const isActive = canUse && !!active;
  card.classList.toggle('stat-card-disabled', !canUse);
  card.title = canUse ? (isActive ? 'Click to deactivate test mode' : 'Click to activate test mode') : 'No active JVS connection';
  if (val) {
    val.textContent = isActive ? 'Active' : 'Inactive';
    val.style.color = isActive ? 'var(--green)' : 'var(--muted)';
  }
}

async function toggleTestButton() {
  const card = document.getElementById('testBtnToggle');
  if (card && card.classList.contains('stat-card-disabled')) return;
  const d = await api('/api/control/test_button', {method: 'POST'});
  if (d.error) { showAlert('dashAlert', 'Error: ' + d.error, true); return; }
  updateTestButtonUI(!!d.test_button_active, d.jvs_connected === true);
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

async function serviceAction(action, alertId, successMsg) {
  const targetAlert = alertId || 'dashAlert';
  const d = await api('/api/control', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({action})
  });
  if (d.error) { showAlert(targetAlert, 'Error: ' + d.error, true); }
  else {
    showAlert(targetAlert, successMsg || ('Service ' + action + ' successful.'), false);
    // Daemon resets test mode to inactive on start/restart; disable the button
    // immediately — refreshDashboard() fires 1.2s later and will re-enable it
    // once a JVS connection is confirmed.
    if (action === 'start' || action === 'restart') updateTestButtonUI(false, false);
  }
  setTimeout(refreshDashboard, 1200);
}

// ---- Config ----
function _profileOptionText(entry) {
  const name = entry.name ?? entry;
  const friendly = entry.friendly_name;
  return friendly && friendly !== name ? `${friendly} (${name})` : (friendly || name);
}

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
    const ioName = io.name ?? io;
    o.value = ioName; o.textContent = _profileOptionText(io);
    if (cfgData.emulate === ioName) o.selected = true;
    ioSel.appendChild(o);
  });

  const gameSel = document.getElementById('cfgGame');
  gameSel.innerHTML = '';
  (gamesData.games || []).forEach(g => {
    const o = document.createElement('option');
    const gName = g.name ?? g;
    o.value = gName; o.textContent = _profileOptionText(g);
    if (cfgData.game === gName) o.selected = true;
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
  document.getElementById('cfgWiiIRScale').value  = cfgData.wii_ir_scale  ?? '1.0';

  const io2Sel = document.getElementById('cfgEmulate2');
  io2Sel.innerHTML = '<option value="">— None —</option>';
  (iosData.ios || []).forEach(io => {
    const o = document.createElement('option');
    const ioName = io.name ?? io;
    o.value = ioName; o.textContent = _profileOptionText(io);
    if (cfgData.emulate_second === ioName) o.selected = true;
    io2Sel.appendChild(o);
  });
}

function validateConfigInputs() {
  const warnings = [];
  const device = document.getElementById('cfgDevice').value.trim();
  if (device && !/^\/dev\/(ttyUSB|ttyAMA|ttyS|ttyACM|serial)/.test(device))
    warnings.push('DEVICE_PATH "' + device + '" does not look like a serial port (/dev/ttyUSB*, /dev/ttyAMA*, /dev/ttyS*, /dev/ttyACM*, /dev/serial*).');
  const pin = parseInt(document.getElementById('cfgPin').value, 10);
  if (!isNaN(pin) && (pin < 1 || pin > 40))
    warnings.push('SENSE_LINE_PIN (' + pin + ') is outside the valid Raspberry Pi GPIO range (1–40).');
  [['cfgDz1', 1], ['cfgDz2', 2], ['cfgDz3', 3], ['cfgDz4', 4]].forEach(([id, n]) => {
    if (parseFloat(document.getElementById(id).value) >= 0.5)
      warnings.push('ANALOG_DEADZONE for Player ' + n + ' is at or above the maximum (0.5), which will make the analog stick non-functional.');
  });
  const irScale = parseFloat(document.getElementById('cfgWiiIRScale').value);
  if (!isNaN(irScale) && (irScale < 0.1 || irScale > 5.0))
    warnings.push('WII_IR_SCALE (' + irScale + ') is outside the valid range (0.1–5.0).');
  return warnings;
}

async function saveConfig(silent = false) {
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
    wii_ir_scale:               document.getElementById('cfgWiiIRScale').value,
    emulate_second:             document.getElementById('cfgEmulate2').value,
  };
  const d = await api('/api/config', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify(payload)
  });
  if (d.error) { showAlert('cfgAlert', 'Error: ' + d.error, true); return false; }
  if (!silent) showAlert('cfgAlert', 'Configuration saved. Restart the service to apply changes.', false);
  return true;
}

async function saveConfigAndRestart() {
  const saved = await saveConfig(true);
  if (saved) await serviceAction('restart', 'cfgAlert', 'Configuration saved. Service restarted successfully.');
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
  document.getElementById('cfgWiiIRScale').value  = '1.0';
  document.getElementById('cfgEmulate').value = 'namco-FCA1';
  document.getElementById('cfgGame').value    = 'generic-driving';
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
    if (btn) btn.style.color      = (t === tab) ? '#fff' : '';
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
  tbody.innerHTML = files.map(entry => {
    const name = typeof entry === 'object' ? entry.name : entry;
    let displayCell;
    if (typeof entry === 'object' && entry.friendly_name) {
      displayCell = entry.friendly_name !== name
        ? `${_escHtml(entry.friendly_name)} <span style="color:var(--muted);font-size:0.8rem;">(${_escHtml(name)})</span>`
        : _escHtml(entry.friendly_name);
    } else {
      displayCell = `<code style="color:var(--accent2);font-family:var(--font-mono);">${_escHtml(name)}</code>`;
    }
    return `
    <tr>
      <td>${displayCell}</td>
      <td style="white-space:nowrap;">
        <button class="btn btn-xs btn-refresh" data-name="${_escHtml(name)}" onclick="editProfile(this.dataset.name)" style="margin-right:0.25rem;">Edit</button>
        <a href="/api/profiles/download?type=${encodeURIComponent(_profilesCurrentTab)}&name=${encodeURIComponent(name)}" class="btn btn-xs" style="margin-right:0.25rem;text-decoration:none;">Download</a>
        <button class="btn btn-xs" data-name="${_escHtml(name)}" onclick="renameProfile(this.dataset.name)" style="margin-right:0.25rem;">Rename</button>
        <button class="btn btn-xs btn-danger" data-name="${_escHtml(name)}" onclick="deleteProfile(this.dataset.name)">Delete</button>
      </td>
    </tr>`;
  }).join('');
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
    const displayName = dev.friendly_name && dev.friendly_name !== dev.name
        ? `${_escHtml(dev.friendly_name)} <span style="color:var(--muted);font-size:0.8rem;">(${_escHtml(dev.name)})</span>`
        : _escHtml(dev.friendly_name || dev.name);
    return `<tr><td><code>${_escHtml(dev.event)}</code></td><td>${displayName}</td><td>${statusHtml}</td></tr>`;
  }).join('');
}

// ---- Bluetooth Controllers ----
function _escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

function clearBluetoothScanResults() {
  document.getElementById('btScanTable').style.display = 'none';
  document.getElementById('btScanBody').innerHTML = '';
  document.getElementById('btScanStatus').textContent = '';
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
  // Always reset scan results when (re-)entering the section
  clearBluetoothScanResults();

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
    html = 'No Bluetooth adapter detected. Connect a USB Bluetooth dongle.';
    if (!s.bluez_available) {
      html += ' ' + setupBtn;
    }
    isErr = false;
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
  btAlert.innerText = '✓ Setup complete.\n\n' + lines;
  // Re-check status now that packages are installed
  setTimeout(() => loadBluetoothSection(), 1500);
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
  clearBluetoothScanResults();
  await loadBluetoothPaired();
  // BlueZ may not update its paired-device list immediately after BLE bonding;
  // schedule a second refresh so the device appears even if the first query
  // ran before BlueZ committed the pairing to its device database.
  setTimeout(loadBluetoothPaired, 2000);
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
async function btRemoveAll(btn) {
  if (!confirm('Remove ALL paired Bluetooth devices? This cannot be undone.')) return;
  btn.disabled = true;
  btn.textContent = 'Removing…';

  const d = await api('/api/bluetooth/remove_all', {method: 'POST'});

  btn.disabled = false;
  btn.textContent = '✕ Clear All Paired Devices';
  if (d.error) {
    showAlert('btAlert', 'Error clearing paired devices: ' + d.error, true);
    return;
  }
  const removed = d.removed || 0;
  const failed  = d.failed  || [];
  if (failed.length > 0) {
    showAlert('btAlert', `✓ Removed ${removed} device${removed === 1 ? '' : 's'}; could not remove: ${failed.join(', ')}`, true);
  } else {
    showAlert('btAlert', removed > 0
      ? `✓ Removed ${removed} paired device${removed === 1 ? '' : 's'}.`
      : '✓ No paired devices to remove.', false);
  }
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
      + `<td style="padding:0.3rem 0.5rem;font-family:var(--font-mono);">${_escHtml(s.token_hint)}</td>`
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
      + `<code style="color:var(--accent2);font-family:var(--font-mono);">${_escHtml(vidpid)}</code>`
      + mfgStr
      + `<strong>${_escHtml(label)}</strong>`
      + (rs485Badge ? ' ' + rs485Badge : '')
      + ' ' + driverBadge
      + `</div>`;
  }).join('');
}

// ---- Connected input device poller ----
// Tracks a fingerprint of the /dev/input/event* list so the Devices tab
// refreshes automatically when controllers are plugged in or removed.
let _inputDeviceKey = null;

async function pollInputDevices() {
  const d = await api('/api/input_devices');
  if (d.error) return;
  const key = (d.devices || []).map(x => x.event).join(',');
  if (_inputDeviceKey === null) {
    _inputDeviceKey = key; // initialise without triggering a refresh
    return;
  }
  if (key !== _inputDeviceKey) {
    _inputDeviceKey = key;
    if (document.getElementById('panel-devices').classList.contains('active')) {
      loadDevices();
      populateInputTesterDevices();
    }
  }
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
setInterval(pollInputDevices, 3000);

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
