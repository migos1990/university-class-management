#!/usr/bin/env node
/**
 * classroom-setup.js
 * Run once before class to prepare isolated instance directories.
 * Usage: npm run classroom:setup
 *        node scripts/classroom-setup.js
 */
'use strict';

const fs   = require('fs');
const path = require('path');

const APP_ROOT    = path.join(__dirname, '..');
const CONFIG_PATH = path.join(APP_ROOT, 'classroom.config.json');
const INSTANCES   = path.join(APP_ROOT, 'instances');

// ─── Load config ────────────────────────────────────────────────────────────
if (!fs.existsSync(CONFIG_PATH)) {
  console.error('classroom.config.json not found. Run from the project root.');
  process.exit(1);
}
const config = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
const { teams, basePort, hostAddress, dashboardPort } = config;

console.log('');
console.log('='.repeat(60));
console.log(' Classroom Setup');
console.log('='.repeat(60));
console.log(`  Teams:     ${teams.length}`);
console.log(`  Base port: ${basePort}`);
console.log(`  Host:      ${hostAddress}`);
console.log(`  Dashboard: http://${hostAddress}:${dashboardPort}`);
console.log('');

// ─── Create instance directories ────────────────────────────────────────────
teams.forEach((team, i) => {
  const slot     = `team-${i + 1}`;
  const slotDir  = path.join(INSTANCES, slot);
  const dbDir    = path.join(slotDir, 'database');
  const bkDir    = path.join(slotDir, 'backups');
  const sslDir   = path.join(slotDir, 'ssl');
  const port     = basePort + i;

  [slotDir, dbDir, bkDir, sslDir].forEach(d => {
    if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
  });

  console.log(`  ${String(port).padEnd(5)} ${team.padEnd(16)} → instances/${slot}/`);
});

console.log('');
console.log('✓ Setup complete. Start class with: npm run classroom');
console.log('');
