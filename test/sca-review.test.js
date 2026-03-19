/**
 * TEST-01: SCA Review Submission
 *
 * Verifies that a student can submit a review classification
 * and that the classification persists on the finding detail page.
 * Also verifies unauthenticated users are redirected.
 */

const { describe, it, before } = require('node:test');
const assert = require('node:assert');
const { request, loginAs, BASE_URL } = require('./helpers');

describe('TEST-01: SCA Review Submission', () => {
  let studentCookie;

  before(async () => {
    // Health check -- ensure server is reachable
    const health = await request({ url: `${BASE_URL}/health` });
    assert.ok(
      health.statusCode === 200,
      'Server not running. Start it first: npm start'
    );

    studentCookie = await loginAs('student');
  });

  it('should submit a review classification and persist it', async () => {
    const body = 'classification=confirmed&action=submit&student_notes=integration+test';

    // Submit review
    const submitRes = await request({
      url: `${BASE_URL}/sca/findings/1/review`,
      method: 'POST',
      headers: {
        'Cookie': studentCookie,
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(body).toString()
      },
      body
    });

    assert.ok(
      submitRes.statusCode === 302 || submitRes.statusCode === 303,
      `Expected redirect (302/303), got ${submitRes.statusCode}`
    );

    // Verify persistence -- GET the finding detail page
    const detailRes = await request({
      url: `${BASE_URL}/sca/findings/1`,
      headers: { 'Cookie': studentCookie }
    });

    assert.strictEqual(detailRes.statusCode, 200);
    assert.ok(
      detailRes.body.includes('confirmed'),
      'Finding detail page should contain "confirmed" classification'
    );
  });

  it('should reject unauthenticated review submission', async () => {
    const body = 'classification=confirmed&action=submit&student_notes=no+auth';

    const res = await request({
      url: `${BASE_URL}/sca/findings/1/review`,
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(body).toString()
      },
      body
    });

    assert.strictEqual(
      res.statusCode, 302,
      `Expected 302 redirect for unauthenticated request, got ${res.statusCode}`
    );
  });
});
