import assert from 'node:assert/strict';
import { chmod, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { analyzeIntegrity, auditExtension } from '../src/analyzer.js';
import { parseCsv, stringifyCsv } from '../src/csv.js';
import { parse, runLabContainer } from '../scripts/run-lab.mjs';
import { writeExtension } from '../support/helpers.js';

test('Phase 2.1 exports analyzeIntegrity without altering behavior or auditExtension provenance', async (t) => {
  const cleanFindings = analyzeIntegrity(
    {
      manifest_version: 3,
      name: 'Complete fixture',
      version: '1.0.0',
      background: { service_worker: 'worker.js' },
      content_scripts: [{ matches: ['https://example.invalid/*'], js: ['content.js'] }]
    },
    ['manifest.json', 'worker.js', 'content.js']
  );
  assert.deepEqual(cleanFindings, []);

  const missingFindings = analyzeIntegrity(
    {
      manifest_version: 3,
      name: 'Broken fixture',
      version: '1.0.0',
      background: { service_worker: 'missing.js' },
      options_page: '../escape.html'
    },
    ['manifest.json']
  );
  assert.equal(missingFindings.length, 1);
  assert.equal(missingFindings[0].id, 'MVX002');
  assert.equal(missingFindings[0].severity, 'high');
  assert.deepEqual(
    missingFindings[0].evidence.map((item) => item.field),
    ['background.service_worker', 'options_page']
  );

  const cookieMv3 = await auditExtension(path.resolve('corpus/fixtures/cookie-access/mv3'));
  assert.equal(cookieMv3.analysis.sha256, 'b57ae698199aabddb9d1280d47bc1953df5ce6a6fe687537eff40c40cc0fe427');
  assert.deepEqual(Object.keys(cookieMv3.summary), ['total', 'counts', 'riskScore', 'rating']);

  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-phase21-integrity-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  await writeExtension(temp, {
    manifest_version: 3,
    name: 'Missing worker audit',
    version: '1.0.0',
    background: { service_worker: 'absent.js' }
  });
  const audit = await auditExtension(temp);
  assert.equal(audit.findings[0].id, 'MVX002');
});

test('Phase 2.1 importing scripts/run-lab.mjs does not execute CLI and exposes parse + runLabContainer', async () => {
  assert.equal(typeof parse, 'function');
  assert.equal(typeof runLabContainer, 'function');

  assert.deepEqual(
    parse(['--extension', '/ext', '--scenario', '/sc.json', '--output', '/out', '--acknowledge-risk']),
    { extension: '/ext', scenario: '/sc.json', output: '/out', acknowledgeRisk: true }
  );
  assert.throws(() => parse(['--extension', '/ext']), /Refusing live extension execution/);
  await assert.rejects(() => runLabContainer({}), /Refusing live extension execution/);
  await assert.rejects(
    () => runLabContainer({ acknowledgeRisk: true, extension: '/ext' }),
    /--scenario is required/
  );
});

test('Phase 2.1 runLabContainer works programmatically with a mocked docker binary and preserves report schema', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-phase21-lab-'));
  t.after(() => rm(temp, { recursive: true, force: true }));

  const extension = path.join(temp, 'extension');
  await writeExtension(extension, {
    manifest_version: 3,
    name: 'Programmatic lab fixture',
    version: '1.0.0'
  });
  const scenario = path.join(temp, 'scenario.json');
  await writeFile(scenario, `${JSON.stringify({
    schemaVersion: 1,
    id: 'programmatic-check',
    targetUrl: 'https://example.test/',
    canaries: { sessionToken: 'mvx-canary-1234567890' },
    durationMs: 1_000
  })}\n`, 'utf8');

  const fakeBin = path.join(temp, 'bin');
  await writeExtension(fakeBin, { manifest_version: 3, name: 'bin', version: '1.0.0' });
  await rm(path.join(fakeBin, 'manifest.json'));
  const fakeDocker = path.join(fakeBin, 'docker');
  const imageId = `sha256:${'9'.repeat(64)}`;
  await writeFile(fakeDocker, `#!/usr/bin/env node
const { writeFileSync } = require('node:fs');
const args = process.argv.slice(2);
if (args[0] === 'image') {
  process.stdout.write('${imageId}\\n');
} else if (args[0] === 'run') {
  const env = {};
  for (let i = 0; i < args.length; i += 1) {
    if (args[i] === '--cidfile') writeFileSync(args[i + 1], '${'4'.repeat(64)}\\n');
    if (args[i] === '--env') {
      const pair = args[i + 1];
      const eq = pair.indexOf('=');
      env[pair.slice(0, eq)] = pair.slice(eq + 1);
    }
  }
  const started = {
    schemaVersion: 1,
    timestamp: '2026-11-25T10:00:00.000Z',
    type: 'lab.started',
    data: {
      profile: env.MVX_LAB_PROFILE,
      browser: 'Chromium 150.0.0.0',
      imageId: env.MVX_LAB_IMAGE_ID,
      imageReference: env.MVX_LAB_IMAGE_REFERENCE,
      network: 'none',
      durationMs: 1000,
      packageSha256: env.MVX_LAB_PACKAGE_SHA256,
      analysisSha256: env.MVX_LAB_ANALYSIS_SHA256,
      scenarioSha256: env.MVX_LAB_SCENARIO_SHA256,
      seccompSha256: env.MVX_LAB_SECCOMP_SHA256,
      toolVersion: env.MVX_LAB_TOOL_VERSION
    }
  };
  const completed = {
    schemaVersion: 1,
    timestamp: '2026-11-25T10:00:01.000Z',
    type: 'lab.completed',
    data: { sessionsObserved: 1, extensionTargetsObserved: 0, extensionIds: [] }
  };
  process.stdout.write(JSON.stringify(started) + '\\n' + JSON.stringify(completed) + '\\n');
}
`, 'utf8');
  await chmod(fakeDocker, 0o700);

  const originalPath = process.env.PATH;
  process.env.PATH = `${fakeBin}${path.delimiter}${originalPath}`;
  t.after(() => { process.env.PATH = originalPath; });

  const output = path.join(temp, 'out');
  const result = await runLabContainer({
    extension,
    scenario,
    output,
    image: 'mvx-lab:mock',
    acknowledgeRisk: true
  });

  assert.equal(result.imageId, imageId);
  assert.equal(result.report.verdict, 'no_trigger_observed');
  assert.equal(result.report.contained, true);
  assert.equal(result.report.execution.container.imageId, imageId);
  const savedReport = JSON.parse(await readFile(result.reportPath, 'utf8'));
  assert.deepEqual(savedReport, result.report);
});

test('Phase 2.1 stringifyCsv produces deterministic headers-only output for empty rows', () => {
  const csv = stringifyCsv(['a', 'b,c'], []);
  assert.equal(csv, 'a,"b,c"\n');
  assert.deepEqual(parseCsv(csv), []);
});
