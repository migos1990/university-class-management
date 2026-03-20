/**
 * INST-01 / INST-02: Instructor Tools - Student Activity Tracking
 *
 * Verifies:
 * - /sca/stats returns students array and totalFindings
 * - Activity tracking on finding view, lab page, review submission
 * - Per-student submitted count
 * - Students sorted by submitted count descending
 * - Unauthenticated /sca/stats returns 302 (regression)
 */

const { describe, it, before } = require('node:test');
const assert = require('node:assert');
const { request, loginAs, BASE_URL } = require('./helpers');

describe('INST-01 / INST-02: Instructor Student Activity Tracking', () => {
  let profCookie;
  let studentCookie;

  before(async () => {
    // Health check
    const health = await request({ url: `${BASE_URL}/health` });
    assert.ok(
      health.statusCode === 200,
      'Server not running. Start it first: npm start'
    );

    profCookie = await loginAs('professor');
    studentCookie = await loginAs('student');
  });

  it('INST-01: /sca/stats returns students array and totalFindings', async () => {
    const res = await request({
      url: `${BASE_URL}/sca/stats`,
      headers: { 'Cookie': profCookie }
    });

    assert.strictEqual(res.statusCode, 200);
    const data = JSON.parse(res.body);
    assert.ok(Array.isArray(data.students), 'Response should have a students array');
    assert.strictEqual(typeof data.totalFindings, 'number', 'Response should have totalFindings as a number');
  });

  it('INST-01: Activity tracked on finding view', async () => {
    // Student visits finding 1 (triggers tracking)
    const findingRes = await request({
      url: `${BASE_URL}/sca/findings/1`,
      headers: { 'Cookie': studentCookie }
    });
    assert.strictEqual(findingRes.statusCode, 200);

    // Professor checks stats
    const statsRes = await request({
      url: `${BASE_URL}/sca/stats`,
      headers: { 'Cookie': profCookie }
    });
    assert.strictEqual(statsRes.statusCode, 200);
    const data = JSON.parse(statsRes.body);

    // Find alice_student in the array
    const alice = data.students.find(s => s.username === 'alice_student');
    assert.ok(alice, 'alice_student should be in students array');
    assert.ok(alice.lastActiveAt !== null, 'lastActiveAt should be non-null after finding view');
    assert.strictEqual(alice.currentFindingId, 1, 'currentFindingId should be 1 after viewing finding 1');
  });

  it('INST-01: Lab page tracks activity without setting currentFindingId', async () => {
    // Student visits the SCA lab page (not a specific finding)
    const labRes = await request({
      url: `${BASE_URL}/sca/`,
      headers: { 'Cookie': studentCookie }
    });
    assert.strictEqual(labRes.statusCode, 200);

    // Professor checks stats
    const statsRes = await request({
      url: `${BASE_URL}/sca/stats`,
      headers: { 'Cookie': profCookie }
    });
    assert.strictEqual(statsRes.statusCode, 200);
    const data = JSON.parse(statsRes.body);

    const alice = data.students.find(s => s.username === 'alice_student');
    assert.ok(alice, 'alice_student should be in students array');
    assert.ok(alice.lastActiveAt !== null, 'lastActiveAt should be non-null after lab page visit');
    // currentFindingId should still be 1 from the previous test (lab page does not change it)
    assert.strictEqual(alice.currentFindingId, 1, 'currentFindingId should remain 1 (lab page does not set it)');
  });

  it('INST-02: Per-student submitted count', async () => {
    // Submit a review as alice_student to ensure at least 1 submitted review exists
    const body = 'classification=confirmed&action=submit&student_notes=inst-test';
    await request({
      url: `${BASE_URL}/sca/findings/2/review`,
      method: 'POST',
      headers: {
        'Cookie': studentCookie,
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(body).toString()
      },
      body
    });

    const statsRes = await request({
      url: `${BASE_URL}/sca/stats`,
      headers: { 'Cookie': profCookie }
    });
    assert.strictEqual(statsRes.statusCode, 200);
    const data = JSON.parse(statsRes.body);

    const alice = data.students.find(s => s.username === 'alice_student');
    assert.ok(alice, 'alice_student should be in students array');
    assert.strictEqual(typeof alice.submitted, 'number', 'submitted should be a number');
    assert.ok(alice.submitted >= 1, `alice_student should have >= 1 submitted review, got ${alice.submitted}`);
  });

  it('INST-02: Students sorted by completion descending', async () => {
    const statsRes = await request({
      url: `${BASE_URL}/sca/stats`,
      headers: { 'Cookie': profCookie }
    });
    assert.strictEqual(statsRes.statusCode, 200);
    const data = JSON.parse(statsRes.body);

    // Verify sort order: each student's submitted >= next student's submitted
    for (let i = 0; i < data.students.length - 1; i++) {
      assert.ok(
        data.students[i].submitted >= data.students[i + 1].submitted,
        `Students should be sorted descending by submitted: students[${i}].submitted (${data.students[i].submitted}) >= students[${i + 1}].submitted (${data.students[i + 1].submitted})`
      );
    }
  });

  it('Regression: Unauthenticated /sca/stats returns 302', async () => {
    const res = await request({
      url: `${BASE_URL}/sca/stats`
    });
    assert.strictEqual(
      res.statusCode, 302,
      `Expected 302 for unauthenticated request, got ${res.statusCode}`
    );
  });
});
