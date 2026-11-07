import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { request } from 'node:http';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { startReviewServer } from '../server.mjs';
import { scanDirectory } from '../src/scanner.mjs';

let session;
let directory;
const locations = new Map();
const sensitiveFilename = 'synthetic-student-private-name.js';
const secretMarker = 'sk-proj-SYNTHETIC_ONLY_NEVER_A_REAL_CREDENTIAL_12345678901234567890';

before(async () => {
  directory = await mkdtemp(join(tmpdir(), 'school-guard-http-'));
  await writeFile(join(directory, sensitiveFilename), `const apiKey = '${secretMarker}';\nconsole.log(req.body);\n`);
  const scan = await scanDirectory(directory, { onFile: ({ fileId, relativePath }) => locations.set(fileId, relativePath) });
  session = await startReviewServer(scan, locations);
});

after(async () => {
  if (session) {
    session.server.closeAllConnections();
    await new Promise(resolve => session.server.close(resolve));
  }
  if (directory) await rm(directory, { recursive: true, force: true });
});

function call(path = '/api/review', { method = 'GET', headers = {}, body, authenticated = true } = {}) {
  return new Promise((resolve, reject) => {
    const req = request(session.origin, {
      path, method,
      headers: { ...(authenticated ? { Authorization: `Bearer ${session.token}` } : {}), ...headers },
    }, res => {
      const chunks = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.setTimeout(3000, () => req.destroy(new Error('HTTP test timed out')));
    req.on('error', reject);
    req.end(body);
  });
}

const postHeaders = () => ({ Origin: session.origin, 'Content-Type': 'application/json' });

test('review server binds only IPv4 loopback and issues a strong fragment token', () => {
  assert.equal(session.server.address().address, '127.0.0.1');
  assert.match(session.token, /^[a-f0-9]{64}$/);
  assert.equal(new URL(session.url).hash, `#${session.token}`);
  assert.equal(new URL(session.url).search, '');
});

test('API requires the session bearer token; static assets expose no scan or token', async () => {
  assert.equal((await call('/api/review', { authenticated: false })).status, 403);
  assert.equal((await call('/api/review', { headers: { Authorization: 'Bearer invalid' } })).status, 403);
  const page = await call('/', { authenticated: false });
  assert.equal(page.status, 200);
  for (const value of [session.token, secretMarker, sensitiveFilename]) assert.ok(!page.body.includes(value));
  assert.equal(page.headers['cache-control'], 'no-store');
  assert.equal(page.headers['x-content-type-options'], 'nosniff');
  assert.match(page.headers['content-security-policy'], /frame-ancestors 'none'/);
  assert.equal(page.headers['access-control-allow-origin'], undefined);
});

test('host, origin and browser cross-site requests are rejected even with valid auth', async () => {
  for (const headers of [
    { Host: 'attacker.example' },
    { Origin: 'https://attacker.example' },
    { Origin: 'null' },
    { 'Sec-Fetch-Site': 'cross-site' },
    { 'Sec-Fetch-Site': 'same-site' },
  ]) assert.equal((await call('/api/review', { headers })).status, 403);
  assert.equal((await call('/api/review', { headers: { Origin: session.origin, 'Sec-Fetch-Site': 'same-origin' } })).status, 200);
});

test('scan API does not expose source, original filenames, target path or session token', async () => {
  const response = await call();
  assert.equal(response.status, 200);
  for (const value of [secretMarker, sensitiveFilename, directory, session.token, 'console.log(req.body)']) assert.ok(!response.body.includes(value), `Unexpected disclosure of synthetic test marker`);
  const result = JSON.parse(response.body);
  assert.ok(Array.isArray(result.scan.findings));
  assert.ok(result.scan.findings.length > 0);
  assert.ok(Array.isArray(result.questionnaire));
});

test('POST requires same-origin JSON and rejects malformed or unexpected values without echo', async () => {
  assert.equal((await call('/api/assess', { method: 'POST', body: '{}' })).status, 403);
  assert.equal((await call('/api/assess', { method: 'POST', headers: { Origin: session.origin, 'Content-Type': 'text/plain' }, body: '{}' })).status, 403);
  for (const body of ['{', 'null', '[]', 'true', '{"unexpected":"<script>private-input</script>"}', '{"realStudentData":{"yes":true}}', '{"realStudentData":"wrong"}']) {
    const response = await call('/api/assess', { method: 'POST', headers: postHeaders(), body });
    assert.equal(response.status, 400);
    assert.ok(!response.body.includes('private-input'));
    assert.ok(!response.body.includes(secretMarker));
  }
});

test('oversized questionnaire is rejected and server remains usable', async () => {
  const response = await call('/api/assess', { method: 'POST', headers: postHeaders(), body: JSON.stringify({ padding: 'x'.repeat(17000) }) });
  assert.equal(response.status, 413);
  assert.equal((await call()).status, 200);
});

test('incomplete questionnaire never produces approval and counseling AI is blocked', async () => {
  const missing = await call('/api/assess', { method: 'POST', headers: postHeaders(), body: '{}' });
  assert.equal(missing.status, 200);
  assert.ok(JSON.parse(missing.body).missingAnswers.length > 0);
  assert.notEqual(JSON.parse(missing.body).status, 'APPROVED');
  const counseling = await call('/api/assess', { method: 'POST', headers: postHeaders(), body: JSON.stringify({ sensitiveNarratives: 'yes', aiProcessing: 'yes' }) });
  assert.equal(counseling.status, 200);
  assert.equal(JSON.parse(counseling.body).status, 'BLOCKED');
});

test('malformed request target and non-ASCII bearer cannot crash the process', async () => {
  const badUrl = await call('//[', { authenticated: false });
  assert.equal(badUrl.status, 400);
  const badToken = await call('/api/review', { headers: { Authorization: `Bearer ${'a'.repeat(63)}é` } });
  assert.equal(badToken.status, 403);
  assert.equal((await call()).status, 200);
});

test('unknown routes and traversal never serve filesystem files', async () => {
  for (const path of ['/cli.mjs', '/src/scanner.mjs', '/%2e%2e/server.mjs', '/api/unknown']) assert.equal((await call(path)).status, 404);
});

test('local path reveal is separately authenticated and rejects unknown identifiers', async () => {
  const [id] = locations.keys();
  assert.ok(id);
  assert.equal((await call(`/api/location?id=${id}`, { authenticated: false })).status, 403);
  assert.equal((await call(`/api/location?id=${id}`, { headers: { Origin: 'https://attacker.example' } })).status, 403);
  const response = await call(`/api/location?id=${id}`);
  assert.equal(response.status, 200);
  assert.equal(JSON.parse(response.body).relativePath, sensitiveFilename);
  for (const query of ['../../etc/passwd', 'F99999', '<script>']) assert.equal((await call(`/api/location?id=${encodeURIComponent(query)}`)).status, 404);
  const report = await call('/api/assess', { method: 'POST', headers: postHeaders(), body: '{}' });
  assert.ok(!report.body.includes(sensitiveFilename));
});
