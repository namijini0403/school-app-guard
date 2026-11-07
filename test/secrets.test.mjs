import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { scanDirectory } from '../src/scanner.mjs';
import { secretRules } from '../src/secret-rules.mjs';

function ids(text) {
  return secretRules.filter(rule => { rule.pattern.lastIndex = 0; return rule.pattern.test(text); }).map(rule => rule.id);
}
test('secret assignment shapes cover JSON, provider env prefixes, and quoted literals', () => {
  for (const input of ['"api_key": "synthetic-value-only"', 'OPENAI_API_KEY=synthetic-value-only', 'AWS_SECRET_ACCESS_KEY=synthetic-value-only', 'SUPABASE_SERVICE_ROLE_KEY=synthetic-value-only', 'client_secret: "synthetic-value-only"', 'jwt_secret = "synthetic-value-only"', 'private_key = "synthetic-value-only"']) {
    assert.ok(ids(input).includes('ASSIGNED_SECRET'), input);
  }
  assert.ok(!ids('OPENAI_API_KEY=process.env.OPENAI_API_KEY').includes('ASSIGNED_SECRET'));
});
test('public secret references and credential URLs are signals without provider calls', () => {
  assert.ok(ids('NEXT_PUBLIC_OPENAI_API_KEY=process.env.KEY').includes('PUBLIC_EXPOSED_SECRET'));
  assert.ok(ids('VITE_SUPABASE_SERVICE_ROLE_KEY').includes('PUBLIC_EXPOSED_SECRET'));
  assert.ok(ids('postgresql://sample:synthetic-password@localhost/db').includes('CREDENTIAL_URL'));
});
test('public anon, publishable and Firebase config are not classified as secret assignments', () => {
  for (const input of ['VITE_SUPABASE_ANON_KEY=synthetic-value-only', 'STRIPE_PUBLISHABLE_KEY=synthetic-value-only', 'NEXT_PUBLIC_FIREBASE_API_KEY=synthetic-value-only']) {
    const found = ids(input);
    assert.ok(found.includes('PUBLIC_CLIENT_CONFIG'));
    assert.ok(!found.includes('ASSIGNED_SECRET'));
    assert.ok(!found.includes('PUBLIC_EXPOSED_SECRET'));
  }
});
test('provider token and private key shapes stay redacted in scanner reports', async t => {
  const root = await mkdtemp(path.join(tmpdir(), 'guard-secret-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const samples = ['sk-proj-' + 'a'.repeat(32), 'ghp_' + 'b'.repeat(36), 'AKIA' + 'C'.repeat(16), 'AIza' + 'd'.repeat(35), 'sk_test_' + 'e'.repeat(24), 'xoxb-' + '1'.repeat(24), '-----BEGIN ' + 'PRIVATE KEY-----'];
  for (const sample of samples) assert.ok(ids(sample).includes('SECRET_LITERAL'));
  await writeFile(path.join(root, 'synthetic.env'), 'SUPABASE_SERVICE_ROLE_KEY=synthetic-value-only\n' + samples.join('\n'));
  const report = await scanDirectory(root);
  assert.ok(report.findings.some(f => f.id === 'ASSIGNED_SECRET'));
  assert.ok(report.findings.some(f => f.id === 'SECRET_LITERAL'));
  const serialized = JSON.stringify(report);
  for (const sample of samples) assert.ok(!serialized.includes(sample));
  assert.ok(!serialized.includes('synthetic-value-only'));
});

test('split secret assignments, PEM files and source maps are inspected', async t => {
  const root = await mkdtemp(path.join(tmpdir(), 'guard-secret-boundary-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const value = 'synthetic-boundary-value';
  await writeFile(path.join(root, '.env'), ' '.repeat(65530) + 'OPENAI_API_KEY=' + value);
  await writeFile(path.join(root, 'private.pem'), '-----BEGIN ' + 'PRIVATE KEY-----');
  await writeFile(path.join(root, 'bundle.js.map'), JSON.stringify({ api_key: value }));
  const report = await scanDirectory(root);
  assert.equal(report.coverage.filesScanned, 3);
  assert.equal(report.findings.filter(f => f.id === 'ASSIGNED_SECRET').length, 2);
  assert.equal(report.findings.filter(f => f.id === 'SECRET_LITERAL').length, 1);
  assert.ok(!JSON.stringify(report).includes(value));
});
