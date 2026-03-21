/**
 * Comprehensive Smoke Test for University Class Management System
 *
 * Pre-class verification command: npm test
 * Tests all 13 ports (dashboard + 12 team instances) for:
 *   - Health check responsiveness
 *   - French login page rendering ("Connexion")
 *   - Deep authenticated student journey on one instance
 *   - Instructor dashboard French content and stats endpoint
 *
 * Output: Emoji pass/fail per port with X/13 summary
 * Exit code: 0 if all pass, 1 if any fail
 */

const http = require('http');
const fs = require('fs');
const path = require('path');

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const configPath = path.join(__dirname, '..', 'classroom.config.json');
let config;
try {
  config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
} catch (e) {
  console.error('Could not read classroom.config.json:', e.message);
  process.exit(1);
}

const DASHBOARD_PORT = config.dashboardPort || 3000;
const BASE_PORT = config.basePort || 3001;
const INSTANCE_COUNT = config.instanceCount || 12;
const TEAMS = config.teams || [];

const REQUEST_TIMEOUT = 5000;   // ms per request
const HEALTH_RETRIES = 3;       // retry attempts for health check
const HEALTH_DELAY = 2000;      // ms between retries

// Build port list: dashboard + team instances
const ALL_PORTS = [DASHBOARD_PORT];
for (let i = 0; i < INSTANCE_COUNT; i++) {
  ALL_PORTS.push(BASE_PORT + i);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Make an HTTP request with timeout support.
 */
function request(options) {
  return new Promise((resolve, reject) => {
    const url = new URL(options.url);

    const reqOptions = {
      hostname: url.hostname,
      port: url.port || 80,
      path: url.pathname + url.search,
      method: options.method || 'GET',
      headers: options.headers || {}
    };

    const timeout = options.timeout || REQUEST_TIMEOUT;

    const req = http.request(reqOptions, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          body: data
        });
      });
    });

    req.setTimeout(timeout, () => {
      req.destroy();
      reject(new Error(`Timeout after ${timeout}ms`));
    });

    req.on('error', reject);

    if (options.body) {
      req.write(options.body);
    }

    req.end();
  });
}

/**
 * Extract session cookie from response.
 */
function getSessionCookie(response) {
  const setCookie = response.headers['set-cookie'];
  if (!setCookie) return null;

  for (const cookie of setCookie) {
    if (cookie.includes('connect.sid')) {
      return cookie.split(';')[0];
    }
  }
  return null;
}

/**
 * Wait for an instance to become healthy with retry logic.
 */
async function waitForInstance(port, maxRetries, delayMs) {
  maxRetries = maxRetries || HEALTH_RETRIES;
  delayMs = delayMs || HEALTH_DELAY;

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const res = await request({
        url: `http://localhost:${port}/health`,
        timeout: REQUEST_TIMEOUT
      });
      if (res.statusCode === 200) return true;
    } catch (_e) {
      // Retry on error
    }
    if (attempt < maxRetries) {
      await new Promise(r => setTimeout(r, delayMs));
    }
  }
  return false;
}

/**
 * Get display name for a port.
 */
function portLabel(port) {
  if (port === DASHBOARD_PORT) {
    return `Instructor Dashboard (${port})`;
  }
  const teamIndex = port - BASE_PORT;
  const teamName = TEAMS[teamIndex] || `Instance ${teamIndex + 1}`;
  return `${teamName} (${port})`;
}

// ---------------------------------------------------------------------------
// Test phases
// ---------------------------------------------------------------------------

async function runTests() {
  console.log('');
  console.log('==========================================================');
  console.log('  HEC Montreal - Pre-Class Smoke Test');
  console.log('==========================================================');
  console.log(`  Ports: ${DASHBOARD_PORT}, ${BASE_PORT}-${BASE_PORT + INSTANCE_COUNT - 1}`);
  console.log(`  Teams: ${INSTANCE_COUNT}`);
  console.log('');

  const healthyPorts = new Set();
  const frenchPorts = new Set();
  const failedPorts = [];
  let allPassed = true;
  let studentCookie = null;
  let profCookie = null;

  // -----------------------------------------------------------------------
  // Phase A: Health checks (all 13 ports)
  // -----------------------------------------------------------------------
  console.log('--- Phase A: Health Checks ---');
  console.log('');

  for (const port of ALL_PORTS) {
    const label = portLabel(port);
    const healthy = await waitForInstance(port);
    if (healthy) {
      healthyPorts.add(port);
      console.log(`  \u2705 ${label} -- healthy`);
    } else {
      console.log(`  \u274C ${label} -- not responding`);
      failedPorts.push(port);
      allPassed = false;
    }
  }

  console.log('');

  // -----------------------------------------------------------------------
  // Phase B: French login page (all healthy ports)
  // -----------------------------------------------------------------------
  console.log('--- Phase B: French Login Page ---');
  console.log('');

  for (const port of ALL_PORTS) {
    if (!healthyPorts.has(port)) continue;

    const label = portLabel(port);
    try {
      const res = await request({ url: `http://localhost:${port}/` });
      if (res.statusCode === 200 && res.body.includes('Connexion')) {
        frenchPorts.add(port);
        console.log(`  \u2705 French login -- ${label}`);
      } else {
        console.log(`  \u274C French login -- ${label} (missing "Connexion")`);
        if (!failedPorts.includes(port)) failedPorts.push(port);
        allPassed = false;
      }
    } catch (e) {
      console.log(`  \u274C French login -- ${label} (${e.message})`);
      if (!failedPorts.includes(port)) failedPorts.push(port);
      allPassed = false;
    }
  }

  console.log('');

  // -----------------------------------------------------------------------
  // Phase C: Deep authenticated test (port 3001 -- Team Alpha)
  // -----------------------------------------------------------------------
  console.log('--- Phase C: Student Journey (port 3001) ---');
  console.log('');

  const DEEP_PORT = BASE_PORT; // 3001

  if (!healthyPorts.has(DEEP_PORT)) {
    console.log(`  \u274C Skipped -- port ${DEEP_PORT} not healthy`);
    allPassed = false;
  } else {
    // Step 1: Login as student
    try {
      const loginData = 'username=alice_student&password=student123';
      const loginRes = await request({
        url: `http://localhost:${DEEP_PORT}/auth/login`,
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Content-Length': Buffer.byteLength(loginData).toString()
        },
        body: loginData
      });

      studentCookie = getSessionCookie(loginRes);
      if (studentCookie && (loginRes.statusCode === 302 || loginRes.statusCode === 303)) {
        console.log('  \u2705 Student login (alice_student)');
      } else {
        console.log(`  \u274C Student login -- status ${loginRes.statusCode}, no session cookie`);
        allPassed = false;
      }
    } catch (e) {
      console.log(`  \u274C Student login -- ${e.message}`);
      allPassed = false;
    }

    // Step 2: GET /sca -- French SCA lab
    if (studentCookie) {
      try {
        const scaRes = await request({
          url: `http://localhost:${DEEP_PORT}/sca`,
          headers: { 'Cookie': studentCookie }
        });
        if (scaRes.statusCode === 200 && scaRes.body.includes('Analyse statique')) {
          console.log('  \u2705 SCA lab page -- "Analyse statique" found');
        } else {
          console.log(`  \u274C SCA lab page -- status ${scaRes.statusCode}, missing French content`);
          allPassed = false;
        }
      } catch (e) {
        console.log(`  \u274C SCA lab page -- ${e.message}`);
        allPassed = false;
      }

      // Step 3: GET /sca/findings/1 -- Finding detail
      try {
        const findingRes = await request({
          url: `http://localhost:${DEEP_PORT}/sca/findings/1`,
          headers: { 'Cookie': studentCookie }
        });
        if (findingRes.statusCode === 200 && findingRes.body.includes('Classification')) {
          console.log('  \u2705 Finding detail -- "Classification" found');
        } else {
          console.log(`  \u274C Finding detail -- status ${findingRes.statusCode}, missing French content`);
          allPassed = false;
        }
      } catch (e) {
        console.log(`  \u274C Finding detail -- ${e.message}`);
        allPassed = false;
      }
    }
  }

  console.log('');

  // -----------------------------------------------------------------------
  // Phase D: Instructor dashboard (port 3000)
  // -----------------------------------------------------------------------
  console.log('--- Phase D: Instructor Dashboard (port 3000) ---');
  console.log('');

  if (!healthyPorts.has(DASHBOARD_PORT)) {
    console.log(`  \u274C Skipped -- port ${DASHBOARD_PORT} not healthy`);
    allPassed = false;
  } else {
    // Step 1: Login as professor
    try {
      const loginData = 'username=prof_jones&password=prof123';
      const loginRes = await request({
        url: `http://localhost:${DASHBOARD_PORT}/auth/login`,
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Content-Length': Buffer.byteLength(loginData).toString()
        },
        body: loginData
      });

      profCookie = getSessionCookie(loginRes);
      if (profCookie && (loginRes.statusCode === 302 || loginRes.statusCode === 303)) {
        console.log('  \u2705 Professor login (prof_jones)');
      } else {
        console.log(`  \u274C Professor login -- status ${loginRes.statusCode}, no session cookie`);
        allPassed = false;
      }
    } catch (e) {
      console.log(`  \u274C Professor login -- ${e.message}`);
      allPassed = false;
    }

    // Step 2: GET /sca -- Instructor dashboard French content
    if (profCookie) {
      try {
        const dashRes = await request({
          url: `http://localhost:${DASHBOARD_PORT}/sca`,
          headers: { 'Cookie': profCookie }
        });
        if (dashRes.statusCode === 200 && dashRes.body.includes('\u00C9tudiants')) {
          console.log('  \u2705 Instructor dashboard -- "\u00C9tudiants" found');
        } else {
          console.log(`  \u274C Instructor dashboard -- status ${dashRes.statusCode}, missing French content`);
          allPassed = false;
        }
      } catch (e) {
        console.log(`  \u274C Instructor dashboard -- ${e.message}`);
        allPassed = false;
      }

      // Step 3: GET /sca/stats -- Stats endpoint JSON shape
      try {
        const statsRes = await request({
          url: `http://localhost:${DASHBOARD_PORT}/sca/stats`,
          headers: { 'Cookie': profCookie }
        });
        if (statsRes.statusCode === 200) {
          const data = JSON.parse(statsRes.body);
          const hasFields = 'studentsStarted' in data
            && 'totalStudents' in data
            && 'avgCompletion' in data
            && 'pace' in data;
          if (hasFields) {
            console.log('  \u2705 Stats endpoint -- valid JSON with required fields');
          } else {
            console.log('  \u274C Stats endpoint -- missing required fields');
            allPassed = false;
          }
        } else {
          console.log(`  \u274C Stats endpoint -- status ${statsRes.statusCode}`);
          allPassed = false;
        }
      } catch (e) {
        console.log(`  \u274C Stats endpoint -- ${e.message}`);
        allPassed = false;
      }
    }
  }

  console.log('');

  // -----------------------------------------------------------------------
  // Phase E: Answer Key Role-Gating (AKEY-01, AKEY-04)
  // -----------------------------------------------------------------------
  console.log('--- Phase E: Answer Key Role-Gating ---');
  console.log('');

  // Test 1: Professor can access answer key
  if (profCookie) {
    try {
      const akRes = await request({
        url: `http://localhost:${DASHBOARD_PORT}/sca/answer-key`,
        headers: { 'Cookie': profCookie }
      });
      if (akRes.statusCode === 200 && akRes.body.includes('Corrig')) {
        console.log('  \u2713 Answer key -- professor access OK');
      } else {
        console.log(`  \u2717 Answer key -- professor got status ${akRes.statusCode}, missing French content`);
        allPassed = false;
      }
    } catch (e) {
      console.log(`  \u2717 Answer key -- professor access error: ${e.message}`);
      allPassed = false;
    }
  }

  // Test 2: Student is denied answer key access
  if (studentCookie) {
    try {
      const akStudentRes = await request({
        url: `http://localhost:${DEEP_PORT}/sca/answer-key`,
        headers: { 'Cookie': studentCookie }
      });
      if (akStudentRes.statusCode === 403) {
        console.log('  \u2713 Answer key -- student denied (403)');
      } else {
        console.log(`  \u2717 Answer key -- student got status ${akStudentRes.statusCode} (expected 403)`);
        allPassed = false;
      }
    } catch (e) {
      console.log(`  \u2717 Answer key -- student denial check error: ${e.message}`);
      allPassed = false;
    }
  }

  // Test 3: Student page source does NOT contain answer key data
  if (studentCookie) {
    try {
      const findingRes = await request({
        url: `http://localhost:${DEEP_PORT}/sca/findings/1`,
        headers: { 'Cookie': studentCookie }
      });
      if (findingRes.statusCode === 200 && !findingRes.body.includes('answerKey') && !findingRes.body.includes('sca.answerKey.inlineTitle')) {
        console.log('  \u2713 Finding detail -- no answer key in student page source');
      } else {
        console.log('  \u2717 Finding detail -- answer key content leaked to student page source!');
        allPassed = false;
      }
    } catch (e) {
      console.log(`  \u2717 Finding detail -- student source check error: ${e.message}`);
      allPassed = false;
    }
  }

  console.log('');

  // -----------------------------------------------------------------------
  // Summary
  // -----------------------------------------------------------------------
  console.log('==========================================================');

  // Count ports that passed all tests (health + French login)
  const passedCount = ALL_PORTS.filter(p =>
    healthyPorts.has(p) && frenchPorts.has(p)
  ).length;

  const total = ALL_PORTS.length;

  if (passedCount === total && allPassed) {
    console.log(`  \u2705 ${passedCount}/${total} instances passed -- ready for class!`);
  } else {
    console.log(`  \u26A0\uFE0F  ${passedCount}/${total} instances passed`);
    if (failedPorts.length > 0) {
      console.log(`  Failed ports: ${failedPorts.join(', ')} -- reduce TEAM_COUNT or check logs`);
    }
  }

  console.log('==========================================================');
  console.log('');

  process.exit(allPassed && passedCount === total ? 0 : 1);
}

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------

runTests().catch(error => {
  console.error('Smoke test error:', error.message);
  process.exit(1);
});
