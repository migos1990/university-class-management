/**
 * TEST-03: API Endpoints Require Auth
 *
 * Verifies that unauthenticated requests to API endpoints
 * get redirected (302) by requireAuth middleware.
 */

const { describe, it, before } = require('node:test');
const assert = require('node:assert');
const { request, BASE_URL } = require('./helpers');

describe('TEST-03: API Endpoints Require Auth', () => {
  before(async () => {
    // Health check -- ensure server is reachable
    const health = await request({ url: `${BASE_URL}/health` });
    assert.ok(
      health.statusCode === 200,
      'Server not running. Start it first: npm start'
    );
  });

  it('GET /api/instructor-message returns 302 without auth', async () => {
    const res = await request({
      url: `${BASE_URL}/api/instructor-message`
    });

    assert.strictEqual(
      res.statusCode, 302,
      `Expected 302 redirect, got ${res.statusCode}`
    );
  });

  it('POST /api/instructor-message returns 302 without auth', async () => {
    const body = JSON.stringify({ message: 'test' });

    const res = await request({
      url: `${BASE_URL}/api/instructor-message`,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body).toString()
      },
      body
    });

    assert.strictEqual(
      res.statusCode, 302,
      `Expected 302 redirect, got ${res.statusCode}`
    );
  });

  it('GET /api/summary returns 302 without auth', async () => {
    const res = await request({
      url: `${BASE_URL}/api/summary`
    });

    assert.strictEqual(
      res.statusCode, 302,
      `Expected 302 redirect, got ${res.statusCode}`
    );
  });
});
