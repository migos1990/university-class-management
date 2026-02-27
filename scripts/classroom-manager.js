#!/usr/bin/env node
/**
 * classroom-manager.js
 * Launches one app instance per team and serves an instructor dashboard.
 *
 * Usage:
 *   npm start                  (reads classroom.config.json)
 *   TEAM_COUNT=4 npm start     (override number of teams)
 *
 * Dashboard:  http://localhost:<dashboardPort>
 * Team URLs:  http://<hostAddress>:<basePort + i>
 */
'use strict';

const { spawn }  = require('child_process');
const http       = require('http');
const fs         = require('fs');
const path       = require('path');

const APP_ROOT    = path.join(__dirname, '..');
const CONFIG_PATH = path.join(APP_ROOT, 'classroom.config.json');
const INSTANCES   = path.join(APP_ROOT, 'instances');
const PID_FILE    = path.join(INSTANCES, '.pids.json');
const SERVER_JS   = path.join(APP_ROOT, 'server.js');

// ─── Load config ────────────────────────────────────────────────────────────
if (!fs.existsSync(CONFIG_PATH)) {
  console.error('classroom.config.json not found. Run from the project root.');
  process.exit(1);
}
const config = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
const { basePort, dashboardPort, hostAddress, autoResetOnStart } = config;

// ─── Configurable team count (TEAM_COUNT env var) ───────────────────────────
const teamCount = Math.min(
  parseInt(process.env.TEAM_COUNT, 10) || config.teams.length,
  config.teams.length
);
const teams = config.teams.slice(0, teamCount);

// ─── Codespaces URL detection ───────────────────────────────────────────────
const CODESPACE_NAME = process.env.CODESPACE_NAME;
const CS_DOMAIN      = process.env.GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN;
const IS_CODESPACES  = !!CODESPACE_NAME;

function getExternalUrl(port) {
  if (IS_CODESPACES && CS_DOMAIN) {
    return `https://${CODESPACE_NAME}-${port}.${CS_DOMAIN}`;
  }
  return `http://${hostAddress === '0.0.0.0' ? 'localhost' : hostAddress}:${port}`;
}

// ─── Instance state ─────────────────────────────────────────────────────────
const instances = teams.map((team, i) => ({
  index:  i,
  team,
  port:   basePort + i,
  url:    getExternalUrl(basePort + i),
  slot:   `team-${i + 1}`,
  pid:    null,
  proc:   null,
  status: 'stopped',   // stopped | starting | online | offline
  startedAt: null,
  lastCheck:  null,
  lastStatus: null
}));

// ─── Summary cache (per-instance, updated every 60s) ────────────────────────
const summaryCache = new Array(teams.length).fill(null);

// ─── Broadcast message store (ephemeral) ────────────────────────────────────
let broadcastMessage = null;

// ─── Spawn / respawn a single instance ──────────────────────────────────────
function spawnInstance(inst) {
  const slotDir = path.join(INSTANCES, inst.slot);
  const dataDir = path.join(slotDir, 'database');
  const bkDir   = path.join(slotDir, 'backups');
  const sslDir  = path.join(slotDir, 'ssl');

  // Ensure directories exist
  [slotDir, dataDir, bkDir, sslDir].forEach(d => {
    if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
  });

  inst.status = 'starting';
  inst.startedAt = new Date().toISOString();

  const child = spawn(process.execPath, [SERVER_JS], {
    cwd: APP_ROOT,
    env: {
      ...process.env,
      PORT:      String(inst.port),
      DATA_DIR:  dataDir,
      BACKUP_DIR: bkDir,
      SSL_DIR:   sslDir,
      TEAM_NAME: inst.team,
      NODE_ENV:  process.env.NODE_ENV || 'development'
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });

  inst.proc = child;
  inst.pid  = child.pid;

  child.stdout.on('data', d => {
    const line = d.toString().trim();
    if (line) console.log(`[${inst.team}] ${line}`);
  });
  child.stderr.on('data', d => {
    const line = d.toString().trim();
    if (line) console.error(`[${inst.team}] ERR: ${line}`);
  });
  child.on('exit', (code, signal) => {
    inst.status = 'stopped';
    inst.proc   = null;
    inst.pid    = null;
    console.log(`[${inst.team}] Exited (code=${code}, signal=${signal})`);
  });

  return child;
}

// ─── Health-check a single instance ─────────────────────────────────────────
function healthCheck(inst) {
  return new Promise(resolve => {
    const opts = {
      hostname: 'localhost',
      port: inst.port,
      path: '/health',
      method: 'GET',
      timeout: 2000
    };
    const req = http.request(opts, res => {
      let body = '';
      res.on('data', d => { body += d; });
      res.on('end', () => {
        try {
          const data = JSON.parse(body);
          inst.status = 'online';
          inst.lastCheck = new Date().toISOString();
          inst.lastStatus = data;
          resolve(true);
        } catch(e) {
          inst.status = 'offline';
          resolve(false);
        }
      });
    });
    req.on('error', () => { inst.status = 'offline'; resolve(false); });
    req.on('timeout', () => { req.destroy(); inst.status = 'offline'; resolve(false); });
    req.end();
  });
}

// ─── Fetch /api/summary from a single instance ───────────────────────────────
function fetchSummary(inst) {
  return new Promise(resolve => {
    const opts = {
      hostname: 'localhost',
      port: inst.port,
      path: '/api/summary',
      method: 'GET',
      timeout: 4000
    };
    const req = http.request(opts, res => {
      let body = '';
      res.on('data', d => { body += d; });
      res.on('end', () => {
        try {
          summaryCache[inst.index] = JSON.parse(body);
          resolve(true);
        } catch(e) {
          resolve(false);
        }
      });
    });
    req.on('error',   () => resolve(false));
    req.on('timeout', () => { req.destroy(); resolve(false); });
    req.end();
  });
}

// ─── Push broadcast message to one instance ──────────────────────────────────
function broadcastToInstance(inst, message) {
  return new Promise(resolve => {
    const body = JSON.stringify({ message });
    const opts = {
      hostname: 'localhost',
      port: inst.port,
      path: '/api/instructor-message',
      method: 'POST',
      timeout: 3000,
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body)
      }
    };
    const req = http.request(opts, res => {
      res.resume();
      res.on('end', () => resolve(true));
    });
    req.on('error',   () => resolve(false));
    req.on('timeout', () => { req.destroy(); resolve(false); });
    req.write(body);
    req.end();
  });
}

// ─── Reset an instance (wipe data, restart) ─────────────────────────────────
async function resetInstance(inst) {
  if (inst.proc) {
    inst.proc.kill('SIGTERM');
    await new Promise(r => setTimeout(r, 2000));
  }

  const dbFile = path.join(INSTANCES, inst.slot, 'database', 'data.json');
  if (fs.existsSync(dbFile)) {
    fs.unlinkSync(dbFile);
    console.log(`[${inst.team}] Database wiped`);
  }

  spawnInstance(inst);
  console.log(`[${inst.team}] Restarted on port ${inst.port}`);

  for (let i = 0; i < 30; i++) {
    await new Promise(r => setTimeout(r, 1000));
    const ok = await healthCheck(inst);
    if (ok) return { success: true, pid: inst.pid, startedAt: inst.startedAt };
  }
  return { success: false, error: 'Timeout waiting for instance to come up' };
}

// ─── Persist PIDs so classroom-stop.js can read them ────────────────────────
function savePIDs() {
  if (!fs.existsSync(INSTANCES)) fs.mkdirSync(INSTANCES, { recursive: true });
  const data = instances.map(i => ({ team: i.team, port: i.port, pid: i.pid }));
  fs.writeFileSync(PID_FILE, JSON.stringify(data, null, 2));
}

// ─── Dashboard section helpers ───────────────────────────────────────────────

const SECURITY_FEATURES = [
  ['mfa_enabled',        'MFA'],
  ['rbac_enabled',       'RBAC'],
  ['encryption_at_rest', 'Pwd Encryption'],
  ['field_encryption',   'Field Encryption'],
  ['https_enabled',      'HTTPS'],
  ['audit_logging',      'Audit Logging'],
  ['rate_limiting',      'Rate Limiting']
];

const PENTEST_PHASES = [
  ['recon',        'Recon'],
  ['enumeration',  'Enumeration'],
  ['vuln_id',      'Vuln ID'],
  ['exploitation', 'Exploitation'],
  ['reporting',    'Reporting']
];

function fmtUptime(seconds) {
  if (!seconds) return '';
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

function renderHealthGrid() {
  const cards = instances.map(inst => {
    const s     = summaryCache[inst.index];
    const uptime = s ? fmtUptime(s.uptime) : '';
    const users  = s ? `${s.users.students} student${s.users.students !== 1 ? 's' : ''}` : '';
    return `<div class="health-card ${inst.status}">
      <div class="hcard-name"><a href="${inst.url}" target="_blank">${inst.team}</a></div>
      <div class="hcard-status"><span class="dot dot-${inst.status}"></span>${inst.status}</div>
      <div class="hcard-meta">${uptime}${uptime && users ? ' · ' : ''}${users}</div>
      <div class="hcard-actions">
        <a href="${inst.url}" target="_blank" class="btn-sm">Open</a>
        <button class="btn-sm danger" onclick="resetOne(${inst.index})">Reset</button>
      </div>
    </div>`;
  }).join('');
  return `<section class="dash-section">
    <h2>Health Grid</h2>
    <div class="health-grid" id="health-grid">${cards}</div>
  </section>`;
}

function renderSecurityMatrix() {
  const teamHeaders = instances.map(inst =>
    `<th title="${inst.team}">T${inst.index + 1}</th>`).join('');

  const rows = SECURITY_FEATURES.map(([key, label]) => {
    const cells = instances.map(inst => {
      const s = summaryCache[inst.index];
      if (!s) return '<td class="mat-unknown">?</td>';
      const on = s.security && s.security[key];
      return `<td><span class="${on ? 'check-on' : 'check-off'}">${on ? '✓' : '✗'}</span></td>`;
    }).join('');
    const onCount = summaryCache.filter(s => s && s.security && s.security[key]).length;
    const total   = summaryCache.filter(Boolean).length;
    return `<tr><td class="mat-label">${label}</td>${cells}<td class="mat-total">${onCount}/${total}</td></tr>`;
  }).join('');

  return `<section class="dash-section">
    <h2>Security Config Matrix</h2>
    <div class="card scroll-x">
      <table class="matrix-table" id="security-matrix">
        <thead><tr><th>Feature</th>${teamHeaders}<th>On/Live</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
  </section>`;
}

function renderLabProgress() {
  const teamHeaders = instances.map(inst =>
    `<th title="${inst.team}">T${inst.index + 1}</th>`).join('');

  function pctBar(pct) {
    const cls = pct >= 80 ? 'good' : pct >= 40 ? '' : 'warn';
    return `<div class="pb-wrap" title="${pct}%"><div class="pb-fill ${cls}" style="width:${pct}%"></div></div><div class="pb-label">${pct}%</div>`;
  }

  const modules = [
    {
      label: 'SCA',
      pct: s => s && s.sca ? s.sca.avg_completion_pct : 0
    },
    {
      label: 'DAST',
      pct: s => s && s.dast ? s.dast.avg_completion_pct : 0
    },
    {
      label: 'VM',
      pct: s => {
        if (!s || !s.vm || !s.vm.total) return 0;
        return Math.round(((s.vm.resolved + s.vm.wont_fix) / s.vm.total) * 100);
      }
    },
    {
      label: 'Pentest',
      pct: s => {
        if (!s || !s.pentest || !s.pentest.total_students) return 0;
        return Math.round(((s.pentest.submitted + s.pentest.graded) / s.pentest.total_students) * 100);
      }
    }
  ];

  const rows = modules.map(mod => {
    const cells = instances.map(inst => {
      const pct = mod.pct(summaryCache[inst.index]);
      return `<td>${pctBar(pct)}</td>`;
    }).join('');
    return `<tr><td class="mat-label"><strong>${mod.label}</strong></td>${cells}</tr>`;
  }).join('');

  return `<section class="dash-section">
    <h2>Lab Progress Tracker</h2>
    <div class="card scroll-x">
      <table class="matrix-table" id="lab-progress">
        <thead><tr><th>Module</th>${teamHeaders}</tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
  </section>`;
}

function renderVMHeatmap() {
  const teamHeaders = instances.map(inst =>
    `<th title="${inst.team}">T${inst.index + 1}</th>`).join('');

  function heatCls(val, r, o, y) {
    if (val > r) return 'heat-red';
    if (val > o) return 'heat-orange';
    if (val > y) return 'heat-yellow';
    return 'heat-green';
  }

  const openRow = instances.map(inst => {
    const s = summaryCache[inst.index];
    const v = s && s.vm != null ? s.vm.open : null;
    const cls = v !== null ? heatCls(v, 10, 5, 2) : '';
    return `<td><span class="heatmap-cell ${cls}">${v !== null ? v : '?'}</span></td>`;
  }).join('');

  const critRow = instances.map(inst => {
    const s = summaryCache[inst.index];
    const v = s && s.vm != null ? s.vm.critical : null;
    const cls = v !== null ? heatCls(v, 3, 1, 0) : '';
    return `<td><span class="heatmap-cell ${cls}">${v !== null ? v : '?'}</span></td>`;
  }).join('');

  return `<section class="dash-section">
    <h2>VM Vulnerability Heatmap</h2>
    <div class="card scroll-x">
      <table class="matrix-table" id="vm-heatmap">
        <thead><tr><th>Metric</th>${teamHeaders}</tr></thead>
        <tbody>
          <tr><td class="mat-label">Open</td>${openRow}</tr>
          <tr><td class="mat-label">Critical</td>${critRow}</tr>
        </tbody>
      </table>
    </div>
  </section>`;
}

function renderPentestBoard() {
  const cols = PENTEST_PHASES.map(([key, label]) => {
    const count = summaryCache.reduce((acc, s) => {
      return acc + (s && s.pentest && s.pentest.phase_distribution ? (s.pentest.phase_distribution[key] || 0) : 0);
    }, 0);
    return `<div class="kanban-col">
      <div class="kanban-label">${label}</div>
      <div class="kanban-count" id="phase-${key}">${count}</div>
      <div class="kanban-sub">team(s)</div>
    </div>`;
  }).join('');

  return `<section class="dash-section">
    <h2>Pentest Phase Board</h2>
    <div class="card">
      <div class="kanban-board" id="pentest-board">${cols}</div>
    </div>
  </section>`;
}

function renderBroadcastBar() {
  const current = broadcastMessage
    ? `<span id="current-msg" style="font-size:0.82rem;color:#555">Active: "${broadcastMessage}"</span>`
    : `<span id="current-msg" style="font-size:0.82rem;color:#aaa">No active message</span>`;
  return `<section class="dash-section">
    <h2>Instructor Broadcast</h2>
    <div class="card">
      <div class="broadcast-bar">
        <input type="text" id="broadcast-input" placeholder="Type a message to all student instances…" maxlength="300">
        <button onclick="sendBroadcast()">Send to All</button>
        <button class="danger" onclick="clearBroadcast()">Clear</button>
      </div>
      <div style="margin-top:0.5rem;display:flex;gap:1rem;align-items:center">
        ${current}
        <span id="broadcast-status" style="font-size:0.82rem;color:#27ae60"></span>
      </div>
    </div>
  </section>`;
}

// ─── Full dashboard HTML ─────────────────────────────────────────────────────
function dashboardHTML() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Instructor Dashboard</title>
  <style>
    * { box-sizing:border-box; margin:0; padding:0; }
    body { font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif; background:#f0f2f5; color:#333; }
    header { background:#002855; color:#fff; padding:1rem 2rem; display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:0.5rem; }
    header h1 { font-size:1.3rem; }
    header small { font-size:0.85rem; opacity:0.7; }
    .container { padding:1.5rem 2rem; max-width:1600px; margin:0 auto; }
    .card { background:#fff; border-radius:8px; box-shadow:0 1px 4px rgba(0,0,0,0.08); padding:1.25rem; margin-bottom:0; }
    .scroll-x { overflow-x:auto; }
    table { width:100%; border-collapse:collapse; }
    th, td { padding:0.5rem 0.6rem; text-align:left; border-bottom:1px solid #f0f0f0; font-size:0.85rem; }
    th { font-weight:600; color:#555; background:#fafafa; }
    a { color:#002855; }
    button { background:#002855; color:#fff; border:none; border-radius:4px; padding:5px 12px; cursor:pointer; font-size:0.85rem; }
    button:hover { background:#003a80; }
    button.danger { background:#c0392b; }
    button.danger:hover { background:#a93226; }
    .btn-sm { display:inline-block; background:#002855; color:#fff; border:none; border-radius:3px;
              padding:3px 8px; cursor:pointer; font-size:0.75rem; text-decoration:none; }
    .btn-sm.danger { background:#c0392b; }
    .dot { display:inline-block; width:10px; height:10px; border-radius:50%; margin-right:4px; vertical-align:middle; }
    .dot-online   { background:#27ae60; }
    .dot-offline  { background:#e74c3c; }
    .dot-starting { background:#f39c12; }
    .dot-stopped  { background:#bdc3c7; }
    .footer-bar { display:flex; gap:0.75rem; align-items:center; flex-wrap:wrap; }
    #msg { font-size:0.9rem; color:#1e8449; }

    /* ── Dash sections ── */
    .dash-section { margin-bottom:1.75rem; }
    .dash-section h2 { font-size:0.95rem; font-weight:700; color:#002855; text-transform:uppercase;
                        letter-spacing:0.05em; margin-bottom:0.75rem;
                        border-bottom:2px solid #002855; padding-bottom:0.3rem; }

    /* ── Health grid ── */
    .health-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(150px,1fr)); gap:0.65rem; }
    .health-card { border-radius:6px; padding:0.75rem; border-left:4px solid #bdc3c7; background:#fff;
                   box-shadow:0 1px 3px rgba(0,0,0,0.07); }
    .health-card.online  { border-color:#27ae60; }
    .health-card.offline { border-color:#e74c3c; background:#fff9f9; }
    .health-card.starting{ border-color:#f39c12; }
    .health-card.stopped { border-color:#bdc3c7; }
    .hcard-name { font-size:0.82rem; font-weight:600; color:#002855; margin-bottom:0.25rem; }
    .hcard-name a { text-decoration:none; }
    .hcard-status { font-size:0.78rem; margin-bottom:0.25rem; }
    .hcard-meta { font-size:0.72rem; color:#888; margin-bottom:0.4rem; min-height:1em; }
    .hcard-actions { display:flex; gap:4px; }

    /* ── Matrix tables (security, progress, heatmap) ── */
    .matrix-table th, .matrix-table td { text-align:center; font-size:0.78rem; padding:0.35rem 0.45rem; }
    .matrix-table th:first-child, .matrix-table td:first-child { text-align:left; }
    .mat-label { font-weight:600; color:#444; white-space:nowrap; }
    .mat-total { font-weight:700; color:#002855; }
    .mat-unknown { color:#bbb; }
    .check-on  { color:#27ae60; font-weight:bold; }
    .check-off { color:#e74c3c; }

    /* ── Progress bars ── */
    .pb-wrap { background:#eee; border-radius:3px; height:10px; width:100%; min-width:40px; }
    .pb-fill { height:10px; border-radius:3px; background:#002855; transition:width 0.3s; }
    .pb-fill.warn { background:#e67e22; }
    .pb-fill.good { background:#27ae60; }
    .pb-label { font-size:0.7rem; text-align:center; color:#666; margin-top:1px; }

    /* ── VM heatmap ── */
    .heatmap-cell { display:inline-block; border-radius:3px; padding:2px 6px;
                    font-size:0.8rem; font-weight:700; min-width:28px; text-align:center; }
    .heat-red    { background:#fad7d2; color:#c0392b; }
    .heat-orange { background:#fde8d0; color:#d35400; }
    .heat-yellow { background:#fef5d4; color:#b7950b; }
    .heat-green  { background:#d5f5e3; color:#1e8449; }

    /* ── Pentest Kanban ── */
    .kanban-board { display:flex; gap:0.75rem; }
    .kanban-col { flex:1; background:#f8f9fa; border-radius:6px; padding:0.75rem; text-align:center; }
    .kanban-label { font-size:0.75rem; color:#555; text-transform:uppercase; letter-spacing:0.04em; margin-bottom:0.4rem; }
    .kanban-count { font-size:2rem; font-weight:800; color:#002855; line-height:1; }
    .kanban-sub { font-size:0.7rem; color:#888; margin-top:0.2rem; }

    /* ── Broadcast ── */
    .broadcast-bar { display:flex; gap:0.5rem; align-items:center; flex-wrap:wrap; }
    .broadcast-bar input[type=text] { flex:1; padding:6px 10px; border:1px solid #ccc; border-radius:4px;
                                       font-size:0.88rem; min-width:220px; }
  </style>
</head>
<body>
<header>
  <div>
    <h1>Instructor Dashboard</h1>
    <small>${teams.length} team${teams.length !== 1 ? 's' : ''} &nbsp;·&nbsp; Port ${dashboardPort}</small>
  </div>
  <div style="font-size:0.82rem;opacity:0.75">Health: 30s &nbsp;|&nbsp; Summary: 60s</div>
</header>
<div class="container">

  ${renderHealthGrid()}
  ${renderSecurityMatrix()}
  ${renderLabProgress()}
  ${renderVMHeatmap()}
  ${renderPentestBoard()}
  ${renderBroadcastBar()}

  <section class="dash-section">
    <h2>Instance Control</h2>
    <div class="card">
      <table>
        <thead>
          <tr>
            <th>Team</th><th>Port</th><th>URL</th><th>Status</th>
            <th>PID</th><th>Last Check</th><th>Actions</th>
          </tr>
        </thead>
        <tbody id="instance-tbody">
          ${instances.map(inst => `
          <tr id="row-${inst.index}">
            <td>${inst.team}</td>
            <td>${inst.port}</td>
            <td><a href="${inst.url}" target="_blank">${inst.url}</a></td>
            <td id="status-${inst.index}"><span class="dot dot-${inst.status}"></span> ${inst.status}</td>
            <td id="pid-${inst.index}">${inst.pid || '—'}</td>
            <td id="check-${inst.index}">${inst.lastCheck ? new Date(inst.lastCheck).toLocaleTimeString() : '—'}</td>
            <td><button onclick="resetOne(${inst.index})">Reset</button></td>
          </tr>`).join('')}
        </tbody>
      </table>
    </div>
    <div class="card" style="margin-top:0.75rem">
      <div class="footer-bar">
        <button onclick="resetAll()">Reset All Instances</button>
        <button class="danger" onclick="stopAll()">Stop All</button>
        <span id="msg"></span>
      </div>
    </div>
  </section>

</div>
<script>
const TEAM_URLS = ${JSON.stringify(instances.map(inst => inst.url))};
const FEATURES = [
  ['mfa_enabled','MFA'],['rbac_enabled','RBAC'],
  ['encryption_at_rest','Pwd Encryption'],['field_encryption','Field Encryption'],
  ['https_enabled','HTTPS'],['audit_logging','Audit Logging'],['rate_limiting','Rate Limiting']
];
const PT_PHASES = [
  ['recon','Recon'],['enumeration','Enumeration'],['vuln_id','Vuln ID'],
  ['exploitation','Exploitation'],['reporting','Reporting']
];

// ── Health polling (30s) ──────────────────────────────────────────────────────
async function fetchStatus() {
  try {
    const res  = await fetch('/api/instances');
    const data = await res.json();
    data.forEach(inst => {
      const sEl = document.getElementById('status-' + inst.index);
      const pEl = document.getElementById('pid-'    + inst.index);
      const cEl = document.getElementById('check-'  + inst.index);
      if (sEl) sEl.innerHTML = \`<span class="dot dot-\${inst.status}"></span> \${inst.status}\`;
      if (pEl) pEl.textContent = inst.pid || '—';
      if (cEl) cEl.textContent = inst.lastCheck ? new Date(inst.lastCheck).toLocaleTimeString() : '—';
    });
  } catch(e) { console.warn('fetchStatus failed', e); }
}

// ── Summary polling (60s) ─────────────────────────────────────────────────────
async function fetchOverview() {
  try {
    const res  = await fetch('/api/class-overview');
    const data = await res.json();
    renderAllSections(data);
  } catch(e) { console.warn('fetchOverview failed', e); }
}

function renderAllSections(data) {
  renderHealthGridDOM(data);
  renderSecurityMatrixDOM(data);
  renderLabProgressDOM(data);
  renderVMHeatmapDOM(data);
  renderPentestBoardDOM(data);
}

// ── Health grid update ────────────────────────────────────────────────────────
function fmtUptime(s) {
  if (!s) return '';
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60);
  return h > 0 ? \`\${h}h \${m}m\` : \`\${m}m\`;
}
function renderHealthGridDOM(data) {
  const grid = document.getElementById('health-grid');
  if (!grid || !data.per_team) return;
  grid.innerHTML = data.per_team.map(t => {
    const s = t.summary;
    const uptime = s ? fmtUptime(s.uptime) : '';
    const users  = s ? \`\${s.users.students} student\${s.users.students !== 1 ? 's' : ''}\` : '';
    const meta   = [uptime, users].filter(Boolean).join(' · ');
    const teamUrl = TEAM_URLS[t.index] || \`http://localhost:\${t.port}\`;
    return \`<div class="health-card \${t.status}">
      <div class="hcard-name"><a href="\${teamUrl}" target="_blank">\${t.team}</a></div>
      <div class="hcard-status"><span class="dot dot-\${t.status}"></span>\${t.status}</div>
      <div class="hcard-meta">\${meta}</div>
      <div class="hcard-actions">
        <a href="\${teamUrl}" target="_blank" class="btn-sm">Open</a>
        <button class="btn-sm danger" onclick="resetOne(\${t.index})">Reset</button>
      </div>
    </div>\`;
  }).join('');
}

// ── Security matrix update ────────────────────────────────────────────────────
function renderSecurityMatrixDOM(data) {
  const tbl = document.getElementById('security-matrix');
  if (!tbl || !data.per_team) return;
  const heads = \`<th>Feature</th>\${data.per_team.map(t => \`<th title="\${t.team}">T\${t.index+1}</th>\`).join('')}<th>On/Live</th>\`;
  const tbody = FEATURES.map(([key, label]) => {
    const cells = data.per_team.map(t => {
      const s = t.summary;
      if (!s) return '<td class="mat-unknown">?</td>';
      const on = s.security && s.security[key];
      return \`<td><span class="\${on ? 'check-on' : 'check-off'}">\${on ? '✓' : '✗'}</span></td>\`;
    }).join('');
    const onCount = data.per_team.filter(t => t.summary && t.summary.security && t.summary.security[key]).length;
    const total   = data.per_team.filter(t => t.summary).length;
    return \`<tr><td class="mat-label">\${label}</td>\${cells}<td class="mat-total">\${onCount}/\${total}</td></tr>\`;
  }).join('');
  tbl.innerHTML = \`<thead><tr>\${heads}</tr></thead><tbody>\${tbody}</tbody>\`;
}

// ── Lab progress update ───────────────────────────────────────────────────────
function pctBar(pct) {
  const cls = pct >= 80 ? 'good' : pct >= 40 ? '' : 'warn';
  return \`<div class="pb-wrap" title="\${pct}%"><div class="pb-fill \${cls}" style="width:\${pct}%"></div></div><div class="pb-label">\${pct}%</div>\`;
}
const MODS = [
  { label:'SCA',     pct: t => t.summary?.sca?.avg_completion_pct  || 0 },
  { label:'DAST',    pct: t => t.summary?.dast?.avg_completion_pct || 0 },
  { label:'VM',      pct: t => {
    const vm = t.summary?.vm;
    if (!vm || !vm.total) return 0;
    return Math.round(((vm.resolved + vm.wont_fix) / vm.total) * 100);
  }},
  { label:'Pentest', pct: t => {
    const p = t.summary?.pentest;
    if (!p || !p.total_students) return 0;
    return Math.round(((p.submitted + p.graded) / p.total_students) * 100);
  }}
];
function renderLabProgressDOM(data) {
  const tbl = document.getElementById('lab-progress');
  if (!tbl || !data.per_team) return;
  const heads = \`<th>Module</th>\${data.per_team.map(t => \`<th title="\${t.team}">T\${t.index+1}</th>\`).join('')}\`;
  const tbody = MODS.map(mod => {
    const cells = data.per_team.map(t => \`<td>\${pctBar(mod.pct(t))}</td>\`).join('');
    return \`<tr><td class="mat-label"><strong>\${mod.label}</strong></td>\${cells}</tr>\`;
  }).join('');
  tbl.innerHTML = \`<thead><tr>\${heads}</tr></thead><tbody>\${tbody}</tbody>\`;
}

// ── VM heatmap update ─────────────────────────────────────────────────────────
function heatCls(v, r, o, y) {
  if (v > r) return 'heat-red';
  if (v > o) return 'heat-orange';
  if (v > y) return 'heat-yellow';
  return 'heat-green';
}
function renderVMHeatmapDOM(data) {
  const tbl = document.getElementById('vm-heatmap');
  if (!tbl || !data.per_team) return;
  const heads = \`<th>Metric</th>\${data.per_team.map(t => \`<th title="\${t.team}">T\${t.index+1}</th>\`).join('')}\`;
  function vmRow(metricKey, thresholds) {
    const cells = data.per_team.map(t => {
      const v = t.summary?.vm?.[metricKey];
      if (v == null) return '<td><span class="heatmap-cell">?</span></td>';
      const cls = heatCls(v, ...thresholds);
      return \`<td><span class="heatmap-cell \${cls}">\${v}</span></td>\`;
    }).join('');
    return cells;
  }
  tbl.innerHTML = \`<thead><tr>\${heads}</tr></thead><tbody>
    <tr><td class="mat-label">Open</td>\${vmRow('open',[10,5,2])}</tr>
    <tr><td class="mat-label">Critical</td>\${vmRow('critical',[3,1,0])}</tr>
  </tbody>\`;
}

// ── Pentest board update ──────────────────────────────────────────────────────
function renderPentestBoardDOM(data) {
  const board = document.getElementById('pentest-board');
  if (!board || !data.pentest_phases) return;
  board.innerHTML = PT_PHASES.map(([key, label]) => \`
    <div class="kanban-col">
      <div class="kanban-label">\${label}</div>
      <div class="kanban-count">\${data.pentest_phases[key] || 0}</div>
      <div class="kanban-sub">team(s)</div>
    </div>\`).join('');
}

// ── Broadcast ─────────────────────────────────────────────────────────────────
async function sendBroadcast() {
  const msg = document.getElementById('broadcast-input').value.trim();
  if (!msg) return;
  const r = await fetch('/api/broadcast', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message: msg })
  });
  const d = await r.json();
  document.getElementById('broadcast-status').textContent = \`Delivered to \${d.delivered} instance(s)\`;
  document.getElementById('current-msg').textContent = \`Active: "\${msg}"\`;
  document.getElementById('current-msg').style.color = '#555';
}
async function clearBroadcast() {
  await fetch('/api/broadcast', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message: null })
  });
  document.getElementById('broadcast-input').value = '';
  document.getElementById('broadcast-status').textContent = 'Cleared';
  document.getElementById('current-msg').textContent = 'No active message';
  document.getElementById('current-msg').style.color = '#aaa';
}

// ── Instance control ──────────────────────────────────────────────────────────
async function resetOne(index) {
  if (!confirm('Reset this instance? All its data will be wiped.')) return;
  setMsg('Resetting…');
  await fetch('/api/instances/' + index + '/reset', {method:'POST'});
  setMsg('Reset complete. Refreshing…');
  setTimeout(fetchStatus, 2000);
}
async function resetAll() {
  if (!confirm('Reset ALL instances? This will wipe all team data.')) return;
  if (!confirm('Are you sure? This cannot be undone.')) return;
  setMsg('Resetting all…');
  await fetch('/api/reset-all', {method:'POST'});
  setMsg('All reset. Refreshing…');
  setTimeout(fetchStatus, 3000);
}
async function stopAll() {
  if (!confirm('Stop all classroom instances?')) return;
  await fetch('/api/stop-all', {method:'POST'});
  setMsg('All instances stopped.');
}
function setMsg(txt) { document.getElementById('msg').textContent = txt; }

// ── Boot ──────────────────────────────────────────────────────────────────────
fetchStatus();
fetchOverview();
setInterval(fetchStatus,   30000);
setInterval(fetchOverview, 60000);
</script>
</body>
</html>`;
}

// ─── Dashboard HTTP server ───────────────────────────────────────────────────
const dashboard = http.createServer(async (req, res) => {
  const url = req.url.replace(/\?.*/, '');

  if (req.method === 'GET' && url === '/') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(dashboardHTML());
  }

  if (req.method === 'GET' && url === '/api/instances') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify(instances.map(i => ({
      index:     i.index,
      team:      i.team,
      port:      i.port,
      url:       i.url,
      pid:       i.pid,
      status:    i.status,
      startedAt: i.startedAt,
      lastCheck: i.lastCheck
    }))));
  }

  if (req.method === 'GET' && url === '/api/class-overview') {
    const live = summaryCache.filter(Boolean);
    const total = instances.length;

    const secAdoption = {};
    SECURITY_FEATURES.forEach(([key]) => {
      secAdoption[key] = live.filter(s => s.security && s.security[key]).length;
    });

    const phaseDist = {};
    PENTEST_PHASES.forEach(([key]) => { phaseDist[key] = 0; });
    live.forEach(s => {
      if (s.pentest && s.pentest.phase_distribution) {
        PENTEST_PHASES.forEach(([key]) => { phaseDist[key] += s.pentest.phase_distribution[key] || 0; });
      }
    });

    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({
      teams_online:  instances.filter(i => i.status === 'online').length,
      teams_total:   total,
      security:      secAdoption,
      sca_avg_pct:   live.length === 0 ? 0 : Math.round(live.reduce((a, s) => a + (s.sca ? s.sca.avg_completion_pct : 0), 0) / live.length),
      dast_avg_pct:  live.length === 0 ? 0 : Math.round(live.reduce((a, s) => a + (s.dast ? s.dast.avg_completion_pct : 0), 0) / live.length),
      pentest_phases: phaseDist,
      per_team:      instances.map((inst, i) => ({
        index:   inst.index,
        team:    inst.team,
        port:    inst.port,
        status:  inst.status,
        summary: summaryCache[i]
      })),
      timestamp: new Date().toISOString()
    }));
  }

  if (req.method === 'POST' && url === '/api/broadcast') {
    let body = '';
    req.on('data', d => { body += d; });
    req.on('end', async () => {
      try {
        const parsed = JSON.parse(body);
        broadcastMessage = parsed.message || null;
        const results = await Promise.allSettled(
          instances
            .filter(inst => inst.status === 'online')
            .map(inst => broadcastToInstance(inst, broadcastMessage))
        );
        const delivered = results.filter(r => r.status === 'fulfilled' && r.value === true).length;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, message: broadcastMessage, delivered }));
      } catch(e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, error: 'Invalid JSON' }));
      }
    });
    return;
  }

  const resetOneMatch = url.match(/^\/api\/instances\/(\d+)\/reset$/);
  if (req.method === 'POST' && resetOneMatch) {
    const idx  = parseInt(resetOneMatch[1]);
    const inst = instances[idx];
    if (!inst) { res.writeHead(404); return res.end('Not found'); }
    const result = await resetInstance(inst);
    savePIDs();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify(result));
  }

  if (req.method === 'POST' && url === '/api/reset-all') {
    for (const inst of instances) {
      await resetInstance(inst);
      savePIDs();
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ success: true }));
  }

  if (req.method === 'POST' && url === '/api/stop-all') {
    instances.forEach(inst => { if (inst.proc) inst.proc.kill('SIGTERM'); });
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ success: true }));
  }

  res.writeHead(404);
  res.end('Not found');
});

// ─── Main ────────────────────────────────────────────────────────────────────
async function main() {
  console.log('');
  console.log('='.repeat(60));
  console.log(' University Class Management System');
  console.log('='.repeat(60));
  console.log(`  Teams:     ${teams.length}${teamCount < config.teams.length ? ` (of ${config.teams.length}, set via TEAM_COUNT)` : ''}`);
  console.log(`  Ports:     ${basePort} – ${basePort + teams.length - 1}`);
  console.log(`  Dashboard: ${getExternalUrl(dashboardPort)}`);
  if (IS_CODESPACES) console.log(`  Mode:      GitHub Codespaces`);
  console.log('');

  if (autoResetOnStart) {
    console.log('  autoResetOnStart=true: wiping all instance data…');
    instances.forEach(inst => {
      const dbFile = path.join(INSTANCES, inst.slot, 'database', 'data.json');
      if (fs.existsSync(dbFile)) fs.unlinkSync(dbFile);
    });
  }

  // Spawn all instances
  instances.forEach(inst => spawnInstance(inst));
  savePIDs();

  // Start dashboard
  dashboard.listen(dashboardPort, () => {
    console.log(`  Dashboard listening on ${getExternalUrl(dashboardPort)}`);
    console.log('');
  });

  // Periodic health checks (every 30s)
  setInterval(async () => {
    for (const inst of instances) {
      if (inst.proc) await healthCheck(inst);
    }
  }, 30000);

  // Periodic summary fetch (every 60s — staggered 100ms per instance)
  setInterval(() => {
    instances.forEach((inst, i) => {
      if (inst.status === 'online') {
        setTimeout(() => fetchSummary(inst), i * 100);
      }
    });
  }, 60000);

  // Graceful shutdown
  function shutdown() {
    console.log('\nShutting down classroom…');
    instances.forEach(inst => { if (inst.proc) inst.proc.kill('SIGTERM'); });
    dashboard.close();
    if (fs.existsSync(PID_FILE)) fs.unlinkSync(PID_FILE);
    setTimeout(() => process.exit(0), 2000);
  }

  process.on('SIGINT',  shutdown);
  process.on('SIGTERM', shutdown);
}

main().catch(err => { console.error(err); process.exit(1); });
