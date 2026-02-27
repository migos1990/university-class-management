#!/usr/bin/env node
/**
 * classroom-manager.js
 * Launches one app instance per team and serves a management dashboard.
 *
 * Usage:
 *   npm run classroom          (reads classroom.config.json)
 *   node scripts/classroom-manager.js
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
const { teams, basePort, dashboardPort, hostAddress, autoResetOnStart } = config;

// ─── Instance state ─────────────────────────────────────────────────────────
const instances = teams.map((team, i) => ({
  index:  i,
  team,
  port:   basePort + i,
  url:    `http://${hostAddress}:${basePort + i}`,
  slot:   `team-${i + 1}`,
  pid:    null,
  proc:   null,
  status: 'stopped',   // stopped | starting | online | offline
  startedAt: null,
  lastCheck:  null,
  lastStatus: null
}));

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

// ─── Reset an instance (wipe data, restart) ─────────────────────────────────
async function resetInstance(inst) {
  // Kill existing process
  if (inst.proc) {
    inst.proc.kill('SIGTERM');
    await new Promise(r => setTimeout(r, 2000));
  }

  // Wipe database
  const dbFile = path.join(INSTANCES, inst.slot, 'database', 'data.json');
  if (fs.existsSync(dbFile)) {
    fs.unlinkSync(dbFile);
    console.log(`[${inst.team}] Database wiped`);
  }

  // Respawn
  spawnInstance(inst);
  console.log(`[${inst.team}] Restarted on port ${inst.port}`);

  // Wait until healthy (up to 30s)
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

// ─── Simple inline HTML dashboard ───────────────────────────────────────────
function dashboardHTML() {
  const rows = instances.map(inst => `
    <tr id="row-${inst.index}">
      <td>${inst.team}</td>
      <td>${inst.port}</td>
      <td><a href="${inst.url}" target="_blank">${inst.url}</a></td>
      <td id="status-${inst.index}">
        <span class="dot dot-${inst.status}"></span> ${inst.status}
      </td>
      <td id="pid-${inst.index}">${inst.pid || '—'}</td>
      <td id="check-${inst.index}">${inst.lastCheck ? new Date(inst.lastCheck).toLocaleTimeString() : '—'}</td>
      <td>
        <button onclick="resetOne(${inst.index})">Reset</button>
      </td>
    </tr>`).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Classroom Manager</title>
  <style>
    * { box-sizing:border-box; margin:0; padding:0; }
    body { font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif; background:#f0f2f5; color:#333; }
    header { background:#002855; color:#fff; padding:1rem 2rem; display:flex; align-items:center; justify-content:space-between; }
    header h1 { font-size:1.3rem; }
    header small { font-size:0.85rem; opacity:0.7; }
    .container { padding:1.5rem 2rem; }
    .card { background:#fff; border-radius:8px; box-shadow:0 1px 4px rgba(0,0,0,0.08); padding:1.25rem; margin-bottom:1.25rem; }
    table { width:100%; border-collapse:collapse; }
    th, td { padding:0.6rem 0.75rem; text-align:left; border-bottom:1px solid #f0f0f0; font-size:0.9rem; }
    th { font-weight:600; color:#555; }
    a { color:#002855; }
    button { background:#002855; color:#fff; border:none; border-radius:4px; padding:5px 12px; cursor:pointer; font-size:0.85rem; }
    button:hover { background:#003a80; }
    button.danger { background:#c0392b; }
    button.danger:hover { background:#a93226; }
    .dot { display:inline-block; width:10px; height:10px; border-radius:50%; margin-right:4px; vertical-align:middle; }
    .dot-online   { background:#27ae60; }
    .dot-offline  { background:#e74c3c; }
    .dot-starting { background:#f39c12; }
    .dot-stopped  { background:#bdc3c7; }
    .footer-bar { display:flex; gap:0.75rem; align-items:center; flex-wrap:wrap; }
    #msg { font-size:0.9rem; color:#1e8449; }
  </style>
</head>
<body>
<header>
  <div>
    <h1>Classroom Manager</h1>
    <small>${teams.length} instances &nbsp;·&nbsp; Dashboard port ${dashboardPort}</small>
  </div>
  <div id="refresh-status" style="font-size:0.85rem; opacity:0.7;">Auto-refresh every 30s</div>
</header>
<div class="container">
  <div class="card">
    <table>
      <thead>
        <tr>
          <th>Team</th><th>Port</th><th>URL</th><th>Status</th><th>PID</th><th>Last Check</th><th>Actions</th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>
  </div>

  <div class="card footer-bar">
    <button onclick="resetAll()">Reset All Instances</button>
    <button class="danger" onclick="stopAll()">Stop All</button>
    <span id="msg"></span>
  </div>
</div>

<script>
const HOST = location.hostname;

async function fetchStatus() {
  const res = await fetch('/api/instances');
  const data = await res.json();
  data.forEach(inst => {
    const statusEl = document.getElementById('status-' + inst.index);
    const pidEl    = document.getElementById('pid-'    + inst.index);
    const checkEl  = document.getElementById('check-'  + inst.index);
    if (statusEl) statusEl.innerHTML = \`<span class="dot dot-\${inst.status}"></span> \${inst.status}\`;
    if (pidEl)    pidEl.textContent  = inst.pid || '—';
    if (checkEl)  checkEl.textContent = inst.lastCheck ? new Date(inst.lastCheck).toLocaleTimeString() : '—';
  });
}

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

fetchStatus();
setInterval(fetchStatus, 30000);
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
  console.log(' Classroom Manager');
  console.log('='.repeat(60));
  console.log(`  Teams:     ${teams.length}`);
  console.log(`  Ports:     ${basePort} – ${basePort + teams.length - 1}`);
  console.log(`  Dashboard: http://${hostAddress}:${dashboardPort}`);
  console.log('');

  // Optionally wipe all data before starting
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
    console.log(`  Dashboard listening on http://${hostAddress}:${dashboardPort}`);
    console.log('');
  });

  // Periodic health checks (every 30s)
  setInterval(async () => {
    for (const inst of instances) {
      if (inst.proc) await healthCheck(inst);
    }
  }, 30000);

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
