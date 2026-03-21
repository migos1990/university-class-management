/**
 * Shared HTTP helpers for integration tests.
 *
 * Uses node:http directly (no fetch) so that redirects are NOT followed --
 * this is critical for testing 302 responses from requireAuth.
 */

const http = require('node:http');

const BASE_URL = process.env.TEST_URL || 'http://localhost:3001';
const REQUEST_TIMEOUT = 5000;

const CREDENTIALS = {
  student: { username: 'alice_student', password: 'student123' },
  professor: { username: 'prof_jones', password: 'prof123' },
  admin: { username: 'admin', password: 'admin123' }
};

/**
 * Promise-based HTTP client using node:http.
 * Does NOT follow redirects.
 *
 * @param {object} options - { url, method, headers, body, timeout }
 * @returns {Promise<{ statusCode: number, headers: object, body: string }>}
 */
function request(options) {
  return new Promise((resolve, reject) => {
    const url = new URL(options.url);
    const timeout = options.timeout || REQUEST_TIMEOUT;

    const reqOptions = {
      hostname: url.hostname,
      port: url.port || 80,
      path: url.pathname + url.search,
      method: options.method || 'GET',
      headers: options.headers || {}
    };

    const req = http.request(reqOptions, (res) => {
      let data = '';
      res.on('data', (chunk) => {
        data += chunk;
      });
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
      reject(new Error(`Request timeout after ${timeout}ms`));
    });

    req.on('error', reject);

    if (options.body) {
      req.write(options.body);
    }

    req.end();
  });
}

/**
 * Extract connect.sid cookie from set-cookie header array.
 *
 * @param {object} response - { headers }
 * @returns {string|null} e.g. "connect.sid=s%3A..."
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
 * Log in as a given role and return the session cookie string.
 *
 * @param {string} role - 'student' | 'professor' | 'admin'
 * @returns {Promise<string>} session cookie
 */
async function loginAs(role) {
  const creds = CREDENTIALS[role];
  if (!creds) {
    throw new Error(`Unknown role "${role}". Valid roles: ${Object.keys(CREDENTIALS).join(', ')}`);
  }

  const body = `username=${encodeURIComponent(creds.username)}&password=${encodeURIComponent(creds.password)}`;

  const res = await request({
    url: `${BASE_URL}/auth/login`,
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Content-Length': Buffer.byteLength(body).toString()
    },
    body
  });

  const cookie = getSessionCookie(res);
  if (!cookie) {
    throw new Error(
      `Login as "${role}" failed: status ${res.statusCode}, no connect.sid cookie returned`
    );
  }

  return cookie;
}

module.exports = { request, getSessionCookie, loginAs, BASE_URL, REQUEST_TIMEOUT, CREDENTIALS };
