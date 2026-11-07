import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { scanDirectory } from '../src/scanner.mjs';

async function rootFor(t) {
  const root = await mkdtemp(path.join(tmpdir(), 'guard-scale-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  return root;
}

test('reads beyond old file/total byte caps and reports every finding beyond 500', async t => {
  const root = await rootFor(t);
  const prefix = ' '.repeat(26 * 1024 * 1024);
  await writeFile(path.join(root, 'large.js'), prefix + '\n' + 'eval(input);\n'.repeat(601));
  const result = await scanDirectory(root);
  const hits = result.findings.filter(x => x.id === 'DYNAMIC_CODE');
  assert.equal(hits.length, 601);
  assert.equal(hits[0].line, 2);
  assert.equal(hits.at(-1).line, 602);
  assert.ok(result.coverage.bytesScanned > 25 * 1024 * 1024);
  assert.equal(result.coverage.complete, true);
  assert.equal(result.coverage.truncated, false);
});

test('visits more than 15000 entries and 5000 files without stopping', async t => {
  const root = await rootFor(t);
  for (let i = 0; i < 15001; i += 64) {
    await Promise.all(Array.from({ length: Math.min(64, 15001 - i) }, (_, j) => writeFile(path.join(root, `${i + j}.txt`), '')));
  }
  const result = await scanDirectory(root);
  assert.equal(result.coverage.filesScanned, 15001);
  assert.equal(result.coverage.entriesSeen, 15001);
  assert.equal(result.coverage.complete, true);
});

test('traverses deeper than 24 levels without retaining recursive directory handles', async t => {
  const root = await rootFor(t);
  const deep = path.join(root, ...Array(30).fill('d'));
  await mkdir(deep, { recursive: true });
  await writeFile(path.join(deep, 'app.js'), 'eval(input)');
  const result = await scanDirectory(root);
  assert.equal(result.coverage.filesScanned, 1);
  assert.ok(result.findings.some(x => x.id === 'DYNAMIC_CODE'));
  assert.equal(result.coverage.complete, true);
});

test('stream boundaries preserve UTF-8, line numbers and split matches without duplicates', async t => {
  const root = await rootFor(t);
  const prefix = '\n'.repeat(65532);
  await writeFile(path.join(root, 'split.js'), prefix + 'eval(input);\n' + '가'.repeat(30000) + '\neval(other);');
  const result = await scanDirectory(root);
  const hits = result.findings.filter(x => x.id === 'DYNAMIC_CODE');
  assert.deepEqual(hits.map(x => x.line), [65533, 65535]);
  assert.equal(result.coverage.complete, true);
});

test('invalid encoding after valid prefix discards partial findings and reports incomplete', async t => {
  const root = await rootFor(t);
  await writeFile(path.join(root, 'invalid.js'), Buffer.concat([Buffer.from('eval(input);' + ' '.repeat(70000)), Buffer.from([255])]));
  const result = await scanDirectory(root);
  assert.equal(result.coverage.filesScanned, 0);
  assert.equal(result.coverage.skippedFiles, 1);
  assert.ok(!result.findings.some(x => x.id === 'DYNAMIC_CODE'));
  assert.equal(result.coverage.complete, false);
});
