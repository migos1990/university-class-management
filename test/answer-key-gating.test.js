/**
 * TEST-02: Answer Key Role-Gating
 *
 * Verifies that GET /sca/answer-key enforces role-based access:
 * - Students get 403 (Access Denied)
 * - Professors get 200 with placeholder JSON
 * - Admins get 200 with placeholder JSON
 * - Unauthenticated users get 302 redirect
 */

const { describe, it, before } = require('node:test');
const assert = require('node:assert');
const { request, loginAs, BASE_URL } = require('./helpers');

describe('TEST-02: Answer Key Role-Gating', () => {
  let studentCookie;
  let professorCookie;
  let adminCookie;

  before(async () => {
    // Health check -- ensure server is reachable
    const health = await request({ url: `${BASE_URL}/health` });
    assert.ok(
      health.statusCode === 200,
      'Server not running. Start it first: npm start'
    );

    studentCookie = await loginAs('student');
    professorCookie = await loginAs('professor');
    adminCookie = await loginAs('admin');
  });

  it('should deny student access with 403', async () => {
    const res = await request({
      url: `${BASE_URL}/sca/answer-key`,
      headers: { 'Cookie': studentCookie }
    });

    assert.strictEqual(res.statusCode, 403);
    assert.ok(
      res.body.includes('refus'),
      'Response body should contain access denied text (French: "Accès refusé")'
    );
  });

  it('should allow professor access with 200', async () => {
    const res = await request({
      url: `${BASE_URL}/sca/answer-key`,
      headers: { 'Cookie': professorCookie }
    });

    assert.strictEqual(res.statusCode, 200);
    assert.ok(
      res.body.includes('placeholder'),
      'Response body should contain "placeholder"'
    );
  });

  it('should allow admin access with 200', async () => {
    const res = await request({
      url: `${BASE_URL}/sca/answer-key`,
      headers: { 'Cookie': adminCookie }
    });

    assert.strictEqual(res.statusCode, 200);
    assert.ok(
      res.body.includes('placeholder'),
      'Response body should contain "placeholder"'
    );
  });

  it('should redirect unauthenticated request', async () => {
    const res = await request({
      url: `${BASE_URL}/sca/answer-key`
    });

    assert.strictEqual(
      res.statusCode, 302,
      `Expected 302 redirect for unauthenticated request, got ${res.statusCode}`
    );
  });
});
