#!/usr/bin/env node
/**
 * classroom-stop.js
 * Gracefully stop all classroom instances.
 * Usage: npm run classroom:stop
 *        node scripts/classroom-stop.js
 * Optionally reads instances from the manager's PID file.
 */
'use strict';

const fs   = require('fs');
const path = require('path');

const APP_ROOT  = path.join(__dirname, '..');
const PID_FILE  = path.join(APP_ROOT, 'instances', '.pids.json');

if (!fs.existsSync(PID_FILE)) {
  console.log('No running classroom session found (no .pids.json).');
  process.exit(0);
}

let pids;
try {
  pids = JSON.parse(fs.readFileSync(PID_FILE, 'utf8'));
} catch (e) {
  console.error('Could not read .pids.json:', e.message);
  process.exit(1);
}

console.log('');
console.log('Stopping classroom instances…');
let stopped = 0;

pids.forEach(({ team, port, pid }) => {
  try {
    process.kill(pid, 'SIGTERM');
    console.log(`  ✓ Stopped ${team} (port ${port}, PID ${pid})`);
    stopped++;
  } catch (e) {
    if (e.code === 'ESRCH') {
      console.log(`  — ${team} (port ${port}) was already stopped`);
    } else {
      console.error(`  ✗ ${team}: ${e.message}`);
    }
  }
});

// Remove PID file
fs.unlinkSync(PID_FILE);

console.log('');
console.log(`Done. Stopped ${stopped} instance(s).`);
console.log('');
