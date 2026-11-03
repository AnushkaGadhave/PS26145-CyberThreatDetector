/**
 * ThreatTrack Client Resilience Verification Test Suite
 * Tests:
 * 1. Retry-After header parsing (numeric seconds, HTTP-date, boundaries, clamping).
 * 2. Exponential backoff delay calculation with random jitter.
 * 3. In-flight request deduplication for concurrent GET calls.
 * 4. Automatic retry loop with backoff on 429 and 503 for idempotent GET requests.
 * 5. Strict rejection of retries for non-idempotent POST/auth operations.
 */

import assert from 'node:assert/strict';

// Import compiled functions and api client from frontend/src/services/api.ts logic
import { parseRetryAfter, computeBackoffDelay, api } from './src/services/api.ts';

async function runTests() {
  console.log('--- Starting ThreatTrack Client Resilience Tests ---\n');

  // Test 1: parseRetryAfter
  console.log('Test 1: parseRetryAfter header parsing');
  assert.equal(parseRetryAfter(null), null, 'null header should return null');
  assert.equal(parseRetryAfter(''), null, 'empty header should return null');
  assert.equal(parseRetryAfter('invalid-header'), null, 'malformed string should return null');
  assert.equal(parseRetryAfter('5'), 5000, '5 seconds should parse to 5000ms');
  assert.equal(parseRetryAfter(' 12 '), 12000, 'padded 12 seconds should parse to 12000ms');
  assert.equal(parseRetryAfter('60'), 30000, 'values > 30s should be clamped to 30000ms ceiling');

  // Test HTTP-date format
  const futureSeconds = 10;
  const httpDate = new Date(Date.now() + futureSeconds * 1000).toUTCString();
  const parsedDateMs = parseRetryAfter(httpDate);
  assert(parsedDateMs !== null, 'Valid HTTP-date should parse');
  assert(parsedDateMs >= 8000 && parsedDateMs <= 11000, `Parsed date ms (${parsedDateMs}) should be ~10000ms`);
  console.log('  ✓ parseRetryAfter passed all scenarios');

  // Test 2: computeBackoffDelay
  console.log('Test 2: computeBackoffDelay calculation and jitter');
  for (let i = 0; i < 20; i++) {
    const delay1 = computeBackoffDelay(1, null);
    assert(delay1 >= 1050 && delay1 <= 1250, `Attempt 1 delay (${delay1}) must be between 1050ms and 1250ms`);

    const delay2 = computeBackoffDelay(2, null);
    assert(delay2 >= 2050 && delay2 <= 2250, `Attempt 2 delay (${delay2}) must be between 2050ms and 2250ms`);

    const delay3 = computeBackoffDelay(3, null);
    assert(delay3 >= 4050 && delay3 <= 4250, `Attempt 3 delay (${delay3}) must be between 4050ms and 4250ms`);

    const retryAfterDelay = computeBackoffDelay(1, 2500);
    assert(retryAfterDelay >= 2550 && retryAfterDelay <= 2750, `Retry-After delay (${retryAfterDelay}) must honor 2500 + jitter`);
  }
  console.log('  ✓ computeBackoffDelay passed jitter and progression checks');

  // Test 3: In-flight request deduplication
  console.log('Test 3: In-flight request deduplication for concurrent GET calls');
  let fetchCallCount = 0;
  const originalFetch = globalThis.fetch;

  globalThis.fetch = async (_url, _opts) => {
    fetchCallCount++;
    // Simulate slight network latency
    await new Promise((r) => setTimeout(r, 50));
    return {
      ok: true,
      status: 200,
      statusText: 'OK',
      headers: new Headers(),
      json: async () => ({ status: 'ACTIVE', packets_captured: 100 })
    };
  };

  try {
    // Fire 3 simultaneous calls to getCaptureStatus
    const [res1, res2, res3] = await Promise.all([
      api.getCaptureStatus(),
      api.getCaptureStatus(),
      api.getCaptureStatus()
    ]);

    assert.equal(res1.status, 'ACTIVE');
    assert.equal(res2.status, 'ACTIVE');
    assert.equal(res3.status, 'ACTIVE');
    assert.equal(fetchCallCount, 1, `Expected exactly 1 network fetch dispatch, got ${fetchCallCount}`);
    console.log('  ✓ In-flight deduplication collapsed 3 parallel calls into 1 network fetch');
  } finally {
    globalThis.fetch = originalFetch;
  }

  // Test 4: Automatic retry on 429 then success
  console.log('Test 4: Idempotent GET retries on HTTP 429');
  let attemptCount = 0;
  globalThis.fetch = async (_url, _opts) => {
    attemptCount++;
    if (attemptCount === 1) {
      // First attempt returns 429 with Retry-After: 0.1s
      return {
        ok: false,
        status: 429,
        statusText: 'Too Many Requests',
        headers: new Headers({ 'Retry-After': '0' }),
        json: async () => ({ detail: 'Rate limit exceeded' })
      };
    }
    return {
      ok: true,
      status: 200,
      statusText: 'OK',
      headers: new Headers(),
      json: async () => ({ service: 'PS26145 API', status: 'ok' })
    };
  };

  try {
    const health = await api.checkHealth();
    assert.equal(health.status, 'ok');
    assert.equal(attemptCount, 2, `Expected 2 attempts (1 initial failure + 1 retry), got ${attemptCount}`);
    console.log('  ✓ Idempotent GET successfully recovered after HTTP 429 retry');
  } finally {
    globalThis.fetch = originalFetch;
  }

  // Test 5: Sensitive auth POST endpoints are never retried
  console.log('Test 5: Sensitive auth operations reject automatic retries');
  let authAttempts = 0;
  globalThis.fetch = async (_url, _opts) => {
    authAttempts++;
    return {
      ok: false,
      status: 429,
      statusText: 'Too Many Requests',
      headers: new Headers(),
      json: async () => ({ detail: 'Too many login attempts' })
    };
  };

  try {
    await api.login({ email: 'test@example.com', password: 'Password123!' });
    assert.fail('Login should have thrown on 429');
  } catch (err) {
    assert.equal(authAttempts, 1, `Login POST should never retry; expected 1 attempt, got ${authAttempts}`);
    assert.equal(err.status, 429);
    console.log('  ✓ Non-idempotent auth POST failed immediately without retrying');
  } finally {
    globalThis.fetch = originalFetch;
  }

  console.log('\n--- All Client Resilience Unit Tests Passed Successfully ---');
}

runTests().catch((err) => {
  console.error('Test failed:', err);
  process.exit(1);
});
