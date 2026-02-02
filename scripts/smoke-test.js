/**
 * Smoke Test Script for University Class Management System
 *
 * This script runs basic tests to verify the application is working correctly.
 * Run before class to ensure all key functions work.
 *
 * Usage: npm run test
 * Output: Opens an HTML report in the browser
 */

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');

// Configuration
const BASE_URL = process.env.TEST_URL || 'http://localhost:3000';
const REPORT_PATH = path.join(__dirname, '..', 'test-report.html');

// Test accounts
const TEST_ACCOUNTS = [
  { username: 'admin', password: 'admin123', role: 'admin', expectedPages: ['/dashboard', '/admin/security', '/admin/audit-logs'] },
  { username: 'prof_jones', password: 'prof123', role: 'professor', expectedPages: ['/dashboard'] },
  { username: 'alice_student', password: 'student123', role: 'student', expectedPages: ['/dashboard'] }
];

// Public pages to test
const PUBLIC_PAGES = [
  { path: '/', name: 'Login Page' }
];

// Test results storage
const results = {
  startTime: new Date(),
  endTime: null,
  passed: 0,
  failed: 0,
  tests: []
};

/**
 * Make an HTTP request
 */
function request(options) {
  return new Promise((resolve, reject) => {
    const url = new URL(options.url);
    const protocol = url.protocol === 'https:' ? https : http;

    const reqOptions = {
      hostname: url.hostname,
      port: url.port || (url.protocol === 'https:' ? 443 : 80),
      path: url.pathname + url.search,
      method: options.method || 'GET',
      headers: options.headers || {},
      rejectUnauthorized: false // Allow self-signed certs
    };

    const req = protocol.request(reqOptions, (res) => {
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

    req.on('error', reject);

    if (options.body) {
      req.write(options.body);
    }

    req.end();
  });
}

/**
 * Extract session cookie from response
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
 * Add test result
 */
function addResult(category, name, passed, details = '') {
  results.tests.push({
    category,
    name,
    passed,
    details,
    timestamp: new Date().toISOString()
  });

  if (passed) {
    results.passed++;
    console.log(`  ✓ ${name}`);
  } else {
    results.failed++;
    console.log(`  ✗ ${name} - ${details}`);
  }
}

/**
 * Test login for a user account
 */
async function testLogin(account) {
  console.log(`\nTesting ${account.role} login (${account.username})...`);

  try {
    // Step 1: Get login page (and any initial cookies)
    const loginPage = await request({ url: `${BASE_URL}/` });

    if (loginPage.statusCode !== 200) {
      addResult('Login', `${account.role}: Access login page`, false, `Status ${loginPage.statusCode}`);
      return null;
    }
    addResult('Login', `${account.role}: Access login page`, true);

    // Step 2: Submit login form
    const loginData = `username=${encodeURIComponent(account.username)}&password=${encodeURIComponent(account.password)}`;

    const loginResponse = await request({
      url: `${BASE_URL}/auth/login`,
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(loginData)
      },
      body: loginData
    });

    // Check for redirect (successful login redirects to dashboard)
    if (loginResponse.statusCode === 302 || loginResponse.statusCode === 303) {
      const sessionCookie = getSessionCookie(loginResponse);
      if (sessionCookie) {
        addResult('Login', `${account.role}: Login successful`, true);
        return sessionCookie;
      }
    }

    // Check if we got an error page
    if (loginResponse.body.includes('Invalid') || loginResponse.body.includes('error')) {
      addResult('Login', `${account.role}: Login successful`, false, 'Invalid credentials');
      return null;
    }

    addResult('Login', `${account.role}: Login successful`, false, `Unexpected response: ${loginResponse.statusCode}`);
    return null;

  } catch (error) {
    addResult('Login', `${account.role}: Login attempt`, false, error.message);
    return null;
  }
}

/**
 * Test page access with session
 */
async function testPageAccess(pagePath, pageName, sessionCookie, role) {
  try {
    const response = await request({
      url: `${BASE_URL}${pagePath}`,
      headers: {
        'Cookie': sessionCookie
      }
    });

    // Follow redirect if needed
    if (response.statusCode === 302 || response.statusCode === 303) {
      const location = response.headers.location;
      if (location && !location.includes('/auth/login')) {
        // Redirect to another page (not login) is OK
        addResult('Page Access', `${role}: ${pageName} (${pagePath})`, true, 'Redirected');
        return true;
      }
      addResult('Page Access', `${role}: ${pageName} (${pagePath})`, false, 'Redirected to login');
      return false;
    }

    if (response.statusCode === 200) {
      // Check for error indicators in the page
      if (response.body.includes('Error') && response.body.includes('error-code')) {
        addResult('Page Access', `${role}: ${pageName} (${pagePath})`, false, 'Error page returned');
        return false;
      }
      addResult('Page Access', `${role}: ${pageName} (${pagePath})`, true);
      return true;
    }

    addResult('Page Access', `${role}: ${pageName} (${pagePath})`, false, `Status ${response.statusCode}`);
    return false;

  } catch (error) {
    addResult('Page Access', `${role}: ${pageName} (${pagePath})`, false, error.message);
    return false;
  }
}

/**
 * Test public pages
 */
async function testPublicPages() {
  console.log('\nTesting public pages...');

  for (const page of PUBLIC_PAGES) {
    try {
      const response = await request({ url: `${BASE_URL}${page.path}` });

      if (response.statusCode === 200) {
        addResult('Public Pages', page.name, true);
      } else {
        addResult('Public Pages', page.name, false, `Status ${response.statusCode}`);
      }
    } catch (error) {
      addResult('Public Pages', page.name, false, error.message);
    }
  }
}

/**
 * Test static assets
 */
async function testStaticAssets() {
  console.log('\nTesting static assets...');

  const assets = [
    { path: '/images/hec-logo.svg', name: 'HEC Logo' }
  ];

  for (const asset of assets) {
    try {
      const response = await request({ url: `${BASE_URL}${asset.path}` });

      if (response.statusCode === 200) {
        addResult('Static Assets', asset.name, true);
      } else {
        addResult('Static Assets', asset.name, false, `Status ${response.statusCode}`);
      }
    } catch (error) {
      addResult('Static Assets', asset.name, false, error.message);
    }
  }
}

/**
 * Generate HTML report
 */
function generateReport() {
  results.endTime = new Date();
  const duration = ((results.endTime - results.startTime) / 1000).toFixed(2);

  const passRate = results.tests.length > 0
    ? ((results.passed / results.tests.length) * 100).toFixed(1)
    : 0;

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Smoke Test Report - HEC Montréal</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #f0f2f5;
      padding: 2rem;
      color: #333;
    }
    .container { max-width: 900px; margin: 0 auto; }
    .header {
      background: #002855;
      color: white;
      padding: 2rem;
      border-radius: 12px 12px 0 0;
      text-align: center;
    }
    .header h1 { font-size: 1.5rem; margin-bottom: 0.5rem; }
    .header p { opacity: 0.8; font-size: 0.9rem; }
    .summary {
      background: white;
      padding: 2rem;
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 1rem;
      border-bottom: 1px solid #e0e0e0;
    }
    .stat {
      text-align: center;
      padding: 1rem;
    }
    .stat-value {
      font-size: 2rem;
      font-weight: 700;
    }
    .stat-label { color: #666; font-size: 0.85rem; }
    .stat-passed .stat-value { color: #27ae60; }
    .stat-failed .stat-value { color: #e74c3c; }
    .stat-rate .stat-value { color: #002855; }
    .results {
      background: white;
      padding: 2rem;
      border-radius: 0 0 12px 12px;
    }
    .category {
      margin-bottom: 2rem;
    }
    .category:last-child { margin-bottom: 0; }
    .category h3 {
      font-size: 1rem;
      color: #002855;
      margin-bottom: 1rem;
      padding-bottom: 0.5rem;
      border-bottom: 2px solid #002855;
    }
    .test-item {
      display: flex;
      align-items: center;
      padding: 0.75rem 1rem;
      border-radius: 6px;
      margin-bottom: 0.5rem;
    }
    .test-item:last-child { margin-bottom: 0; }
    .test-passed { background: #d4edda; }
    .test-failed { background: #f8d7da; }
    .test-icon {
      width: 24px;
      height: 24px;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      margin-right: 1rem;
      font-size: 0.8rem;
    }
    .test-passed .test-icon { background: #27ae60; color: white; }
    .test-failed .test-icon { background: #e74c3c; color: white; }
    .test-name { flex: 1; font-weight: 500; }
    .test-details {
      font-size: 0.85rem;
      color: #666;
      margin-left: 1rem;
    }
    .test-failed .test-details { color: #721c24; }
    .footer {
      text-align: center;
      padding: 1.5rem;
      color: #666;
      font-size: 0.85rem;
    }
    .all-passed {
      background: #d4edda;
      color: #155724;
      padding: 1rem;
      border-radius: 8px;
      text-align: center;
      margin-bottom: 1.5rem;
      font-weight: 600;
    }
    .has-failures {
      background: #f8d7da;
      color: #721c24;
      padding: 1rem;
      border-radius: 8px;
      text-align: center;
      margin-bottom: 1.5rem;
      font-weight: 600;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>Smoke Test Report</h1>
      <p>HEC Montréal - Application Security Platform</p>
    </div>

    <div class="summary">
      <div class="stat">
        <div class="stat-value">${results.tests.length}</div>
        <div class="stat-label">Total Tests</div>
      </div>
      <div class="stat stat-passed">
        <div class="stat-value">${results.passed}</div>
        <div class="stat-label">Passed</div>
      </div>
      <div class="stat stat-failed">
        <div class="stat-value">${results.failed}</div>
        <div class="stat-label">Failed</div>
      </div>
      <div class="stat stat-rate">
        <div class="stat-value">${passRate}%</div>
        <div class="stat-label">Pass Rate</div>
      </div>
    </div>

    <div class="results">
      ${results.failed === 0
        ? '<div class="all-passed">✓ All tests passed! The application is ready for class.</div>'
        : `<div class="has-failures">⚠ ${results.failed} test(s) failed. Please review the issues below.</div>`
      }

      ${generateTestCategories()}
    </div>

    <div class="footer">
      <p>Test completed in ${duration} seconds</p>
      <p>Generated: ${results.endTime.toLocaleString()}</p>
    </div>
  </div>
</body>
</html>`;

  fs.writeFileSync(REPORT_PATH, html);
  console.log(`\n📄 Report saved to: ${REPORT_PATH}`);
  return REPORT_PATH;
}

/**
 * Generate test categories HTML
 */
function generateTestCategories() {
  const categories = {};

  for (const test of results.tests) {
    if (!categories[test.category]) {
      categories[test.category] = [];
    }
    categories[test.category].push(test);
  }

  let html = '';
  for (const [category, tests] of Object.entries(categories)) {
    html += `
      <div class="category">
        <h3>${category}</h3>
        ${tests.map(test => `
          <div class="test-item ${test.passed ? 'test-passed' : 'test-failed'}">
            <div class="test-icon">${test.passed ? '✓' : '✗'}</div>
            <div class="test-name">${test.name}</div>
            ${test.details ? `<div class="test-details">${test.details}</div>` : ''}
          </div>
        `).join('')}
      </div>
    `;
  }

  return html;
}

/**
 * Open report in browser
 */
function openReport(reportPath) {
  const { exec } = require('child_process');
  const platform = process.platform;

  let command;
  if (platform === 'darwin') {
    command = `open "${reportPath}"`;
  } else if (platform === 'win32') {
    command = `start "" "${reportPath}"`;
  } else {
    command = `xdg-open "${reportPath}" 2>/dev/null || echo "Report saved to: ${reportPath}"`;
  }

  exec(command, (error) => {
    if (error) {
      console.log(`Open the report manually: ${reportPath}`);
    }
  });
}

/**
 * Main test runner
 */
async function runTests() {
  console.log('╔══════════════════════════════════════════════════════════╗');
  console.log('║     HEC Montréal - Application Security Smoke Tests      ║');
  console.log('╚══════════════════════════════════════════════════════════╝');
  console.log(`\nTarget: ${BASE_URL}`);
  console.log('Starting tests...\n');

  // Test 1: Public pages
  await testPublicPages();

  // Test 2: Static assets
  await testStaticAssets();

  // Test 3: Login and page access for each role
  for (const account of TEST_ACCOUNTS) {
    const sessionCookie = await testLogin(account);

    if (sessionCookie) {
      // Test expected pages for this role
      for (const pagePath of account.expectedPages) {
        const pageName = pagePath === '/dashboard' ? 'Dashboard' : pagePath.split('/').pop();
        await testPageAccess(pagePath, pageName, sessionCookie, account.role);
      }
    }
  }

  // Generate report
  console.log('\n' + '═'.repeat(60));
  console.log(`Results: ${results.passed} passed, ${results.failed} failed`);

  const reportPath = generateReport();

  // Try to open report
  if (process.argv.includes('--open')) {
    openReport(reportPath);
  }

  // Exit with error code if any tests failed
  process.exit(results.failed > 0 ? 1 : 0);
}

// Run tests
runTests().catch(error => {
  console.error('Test runner error:', error);
  process.exit(1);
});
