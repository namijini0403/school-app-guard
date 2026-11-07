import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, mkdir, rm, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { scanDirectory } from '../src/scanner.mjs';
import { evaluatePolicy, questionnaire, combineAssessment } from '../src/policy.mjs';

async function fixture(t, files) {
  const root = await mkdtemp(path.join(tmpdir(), 'school-guard-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  for (const [name, text] of Object.entries(files)) {
    await mkdir(path.dirname(path.join(root, name)), { recursive: true });
    await writeFile(path.join(root, name), text);
  }
  return root;
}
const answers = () => Object.fromEntries(questionnaire.map(q => [q.id, 'no']));

test('raw counseling analyzed by AI blocks even with all controls and anonymization claimed', () => {
  const input = Object.fromEntries(questionnaire.map(q => [q.id, 'yes']));
  input.publicAccess = 'no';
  const report = evaluatePolicy(input);
  assert.equal(report.status, 'BLOCKED');
  assert.ok(report.findings.some(x => x.id === 'SENSITIVE_AI_ARCHITECTURE'));
  assert.match(report.findings[0].remediation, /합성 사례/);
});
test('synthetic/no personal data never receives automatic approval', () => {
  assert.equal(evaluatePolicy(answers()).status, 'REVIEW_REQUIRED');
});
test('unknown and malformed questionnaire values cannot certify safety or leak input', () => {
  for (const input of [null, [], 'PRIVATE_SENTINEL', { realStudentData: 'PRIVATE_SENTINEL' }, { arbitrary: 'PRIVATE_SENTINEL' }]) {
    const report = evaluatePolicy(input);
    assert.equal(report.status, 'REVIEW_REQUIRED');
    assert.ok(report.missingAnswers.length);
    assert.ok(!JSON.stringify(report).includes('PRIVATE_SENTINEL'));
  }
});
test('actual student exposure blocks; missing controls require remediation', () => {
  const input = answers();
  input.realStudentData = 'yes';
  assert.equal(evaluatePolicy(input).status, 'REMEDIATE');
  input.publicAccess = 'yes';
  assert.equal(evaluatePolicy(input).status, 'BLOCKED');
});
test('sensitive-data contradiction cannot bypass sensitive policy', () => {
  const input = { ...answers(), sensitiveNarratives: 'yes', aiProcessing: 'yes' };
  const report = evaluatePolicy(input);
  assert.equal(report.status, 'BLOCKED');
  assert.ok(report.findings.some(x => x.id === 'ANSWERS_CONFLICT'));
});
test('scan produces signals with remediation and no raw secrets, paths, names or snippets', async t => {
  const secret = `sk-proj-${'a'.repeat(32)}`;
  const root = await fixture(t, {
    'PRIVATE_STUDENT_NAME.js': `const key = '${secret}';\nexec(req.body.command);\nconsole.log(req.body);`,
  });
  const report = await scanDirectory(root);
  const serialized = JSON.stringify(report);
  assert.equal(report.status, 'REMEDIATE');
  for (const forbidden of [secret, root, 'PRIVATE_STUDENT_NAME', 'exec(req.body.command)']) assert.ok(!serialized.includes(forbidden));
  assert.ok(report.findings.some(x => x.id === 'SHELL_EXECUTION' && x.line === 2 && x.fileId === 'F00001'));
  assert.ok(report.findings.some(x => x.id === 'RAW_LOGGING'));
  assert.ok(report.findings.every(x => x.confidence === 'pattern_signal'));
});
test('no target code is executed', async t => {
  const root = await fixture(t, { 'attack.js': `throw new Error('TARGET_WAS_EXECUTED');` });
  const report = await scanDirectory(root);
  assert.equal(report.coverage.filesScanned, 1);
  assert.equal(report.status, 'REVIEW_REQUIRED');
});
test('cross-file sensitive and AI terms request flow review without asserting proven transfer', async t => {
  const root = await fixture(t, { 'records.txt': '상담 기록', 'client.js': 'const provider = "openai";' });
  const report = await scanDirectory(root);
  assert.ok(report.findings.some(x => x.id === 'SENSITIVE_AI_SIGNALS' && x.confidence === 'pattern_signal'));
  assert.notEqual(report.status, 'BLOCKED');
});
test('resource limits, unsupported binaries, and invalid encoding declare incomplete coverage', async t => {
  const root = await fixture(t, { 'huge.txt': 'a'.repeat(100), 'binary.txt': Buffer.from([0, 255]), 'invalid.txt': Buffer.from([255, 254]), 'archive.zip': 'binary' });
  const report = await scanDirectory(root, { maxFileBytes: 20 });
  assert.equal(report.coverage.complete, false);
  assert.equal(report.coverage.skippedFiles, 4);
  assert.ok(report.findings.some(x => x.id === 'COVERAGE_INCOMPLETE'));
});
test('directory entries bounded; dependency folders are excluded explicitly', async t => {
  const root = await fixture(t, { 'node_modules/module/index.js': 'eval(input)', 'one.js': 'const x = 1;', 'two.js': 'const y = 2;' });
  const report = await scanDirectory(root);
  assert.equal(report.coverage.excludedDirectories, 1);
  assert.ok(!report.findings.some(x => x.id === 'DYNAMIC_CODE'));
  const bounded = await scanDirectory(root, { maxEntries: 1 });
  assert.equal(bounded.coverage.complete, false);
  assert.equal(bounded.coverage.truncated, true);
});
test('missing/empty roots are reportable, without path disclosure', async t => {
  const root = await fixture(t, {});
  for (const target of [root, path.join(root, 'PRIVATE_MISSING_PATH'), null]) {
    const report = await scanDirectory(target);
    assert.equal(report.coverage.complete, false);
    assert.equal(report.status, 'REVIEW_REQUIRED');
    assert.ok(!JSON.stringify(report).includes('PRIVATE_MISSING_PATH'));
  }
});
test('linked directories are skipped and never followed', async t => {
  const root = await fixture(t, { 'safe.txt': 'safe' });
  const outside = await fixture(t, { 'private.txt': 'const password = "PRIVATE_OUTSIDE_VALUE";' });
  await symlink(outside, path.join(root, 'link'), process.platform === 'win32' ? 'junction' : 'dir');
  const report = await scanDirectory(root);
  assert.equal(report.coverage.linkedEntries, 1);
  assert.equal(report.coverage.complete, false);
  assert.ok(!report.findings.some(x => x.id === 'ASSIGNED_SECRET'));
});
test('combination preserves blockers and coverage', async t => {
  const root = await fixture(t, { 'app.js': 'const ok = true;' });
  const result = combineAssessment(await scanDirectory(root), evaluatePolicy({ ...answers(), sensitiveNarratives: 'yes', aiProcessing: 'yes' }));
  assert.equal(result.status, 'BLOCKED');
  assert.equal(result.version, 1);
});
test('optional local path callback is separate from redacted report; callback failures stay redacted', async t => {
  const root = await fixture(t, { 'PRIVATE_FILE.js': 'exec(command)', 'unsupported.bin': 'binary' });
  const locations = [];
  const report = await scanDirectory(root, { onFile: item => locations.push(item) });
  assert.deepEqual(locations, [{ fileId: 'F00001', relativePath: 'PRIVATE_FILE.js' }]);
  assert.ok(!JSON.stringify(report).includes('PRIVATE_FILE'));
  const failed = await scanDirectory(root, { onFile() { throw new Error('PRIVATE_FILE_CALLBACK'); } });
  assert.equal(failed.coverage.complete, false);
  assert.equal(failed.coverage.unreadableEntries, 1);
  assert.ok(!JSON.stringify(failed).includes('PRIVATE_FILE_CALLBACK'));
  await assert.rejects(scanDirectory(root, { onFile: 'bad' }), /Invalid scanner callback/);
});
