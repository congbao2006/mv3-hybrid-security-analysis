import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { runCli } from '../src/cli.js';
import { runExperimentBatch } from '../src/research/experiment-runner.js';
import {
  collectExtendedEnvironmentMetadata,
  computeRecordBreakdown,
  createProgressEvent,
  formatProgressEventText,
  normalizeStructuredFailure,
  probeGitStatus,
  redactSensitiveObject,
  redactSensitiveText
} from '../src/research/logging.js';
import { runM1PermissionOnly } from '../src/research/modes.js';
import { captureStreams } from '../support/helpers.js';

const COOKIE_MV3 = path.resolve('corpus/fixtures/cookie-access/mv3');
const CLIPBOARD_MV3 = path.resolve('corpus/fixtures/clipboard-read/mv3');
const SCENARIO = path.resolve('lab/scenarios/credential-exfiltration.json');

test('Sensitive data redaction strips tokens, cookies, passwords, and URL credentials while preserving error diagnostics', () => {
  const raw = [
    'Request failed for https://alice:s3cr3tPass@api.example.test/v1?token=tok_abc123&password=myPassword99',
    'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig',
    'Cookie: session_id=xyz987; theme=dark',
    '{"api_key":"sk-live-99999","normal":"safe-value"}'
  ].join('\n');

  const redacted = redactSensitiveText(raw);
  assert.doesNotMatch(redacted, /s3cr3tPass/);
  assert.doesNotMatch(redacted, /tok_abc123/);
  assert.doesNotMatch(redacted, /myPassword99/);
  assert.doesNotMatch(redacted, /eyJhbGciOiJIUzI1NiJ9/);
  assert.doesNotMatch(redacted, /xyz987/);
  assert.doesNotMatch(redacted, /sk-live-99999/);
  assert.match(redacted, /\[REDACTED\]/);
  assert.match(redacted, /api\.example\.test/);
  assert.match(redacted, /safe-value/);

  const obj = redactSensitiveObject({
    sampleId: 'S1',
    sessionToken: 'top-secret-token',
    nested: { cookie: 'sid=12345', status: 'failed' }
  });
  assert.equal(obj.sampleId, 'S1');
  assert.equal(obj.sessionToken, '[REDACTED]');
  assert.equal(obj.nested.cookie, '[REDACTED]');
  assert.equal(obj.nested.status, 'failed');

  const failure = normalizeStructuredFailure(
    { code: 'LAB_TIMEOUT', message: 'Timed out with Authorization: Bearer secret12345678' },
    { stage: 'm3_dynamic' }
  );
  assert.equal(failure.code, 'LAB_TIMEOUT');
  assert.equal(failure.stage, 'm3_dynamic');
  assert.equal(failure.retryable, true);
  assert.match(failure.timestamp, /^\d{4}-\d{2}-\d{2}T/);
  assert.doesNotMatch(failure.message, /secret12345678/);
  assert.match(failure.message, /\[REDACTED\]/);

  const nonRetryable = normalizeStructuredFailure(
    { code: 'LAB_CONTAINMENT_VIOLATION', message: 'Uncontained request' },
    { stage: 'm3_dynamic' }
  );
  assert.equal(nonRetryable.retryable, false);
});

test('Extended environment provenance distinguishes optional unavailable metadata from missing required Docker dependency', () => {
  const staticOnlyEnv = collectExtendedEnvironmentMetadata(
    { docker: { status: 'unavailable', version: null, imageReference: null, imageId: null, imageDigest: null, reason: 'docker_not_found' } },
    { requiresDocker: false, skipExternalProbes: true }
  );
  assert.equal(staticOnlyEnv.dependencyStatus.dockerRequired, false);
  assert.equal(staticOnlyEnv.dependencyStatus.dockerSatisfied, true);
  assert.match(staticOnlyEnv.dependencyStatus.note, /OPTIONAL_METADATA_UNAVAILABLE/);
  assert.match(staticOnlyEnv.startedAtUtc, /^\d{4}-\d{2}-\d{2}T/);

  const liveM3MissingDocker = collectExtendedEnvironmentMetadata(
    { docker: { status: 'unavailable', version: null, imageReference: 'mvx-lab:local', imageId: null, imageDigest: null, reason: 'docker_not_found' } },
    { requiresDocker: true, customLabRunner: false, skipExternalProbes: true }
  );
  assert.equal(liveM3MissingDocker.dependencyStatus.dockerRequired, true);
  assert.equal(liveM3MissingDocker.dependencyStatus.dockerSatisfied, false);
  assert.match(liveM3MissingDocker.dependencyStatus.note, /REQUIRED_DEPENDENCY_MISSING/);

  const ev = createProgressEvent('sample.started', {
    experimentId: 'exp-1',
    sampleIndex: 1,
    totalSamples: 2,
    sampleId: 'S1',
    extensionId: 'ext-1',
    statusCounts: { completed: 0, completed_with_static_fallback: 0, inconclusive: 0, failed: 0, skipped: 0 }
  });
  assert.match(formatProgressEventText(ev), /SAMPLE \[1\/2\] START sample=S1/);
});

test('Real-time progress events stream to stdout in text mode, persist to progress.jsonl, preserve final summary, and do not alter runs.jsonl or scores', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-log-progress-'));
  t.after(() => rm(temp, { recursive: true, force: true }));

  const manifestPath = path.join(temp, 'manifest.json');
  await writeFile(manifestPath, JSON.stringify({
    schemaVersion: 1,
    datasetVersion: 'ds-prog-1',
    samples: [
      { sampleId: 'S1', extensionId: 'ext-cookie', artifactPath: COOKIE_MV3 },
      { sampleId: 'S2', extensionId: 'ext-clip', artifactPath: CLIPBOARD_MV3 }
    ]
  }));

  const expRoot = path.join(temp, 'exps');
  const textCap = captureStreams();
  const exitCode = await runCli([
    'research', 'experiment',
    '--manifest', manifestPath,
    '--output', expRoot,
    '--experiment-id', 'exp-text',
    '--methods', 'M1,M2',
    '--weights', 'W1',
    '--format', 'text'
  ], textCap.streams, { skipExternalProbes: true });
  assert.equal(exitCode, 0);

  const stdout = textCap.output().stdout;
  assert.match(stdout, /START experiment=exp-text/);
  assert.match(stdout, /SAMPLE \[1\/2\] START sample=S1/);
  assert.match(stdout, /METHOD \[1\/2\] sample=S1 M1\/W1 status=completed/);
  assert.match(stdout, /SAMPLE \[2\/2\] DONE sample=S2/);
  assert.match(stdout, /DONE experiment=exp-text lifecycle=completed/);
  // Preserved legacy summary lines
  assert.match(stdout, /Experiment completed: exp-text/);
  assert.match(stdout, /Config SHA-256:/);
  assert.match(stdout, /Records: 4 \(completed=4,/);

  // progress.jsonl is separate from runs.jsonl
  const expDir = path.join(expRoot, 'exp-text');
  const progressLines = (await readFile(path.join(expDir, 'progress.jsonl'), 'utf8'))
    .trim().split('\n').map((l) => JSON.parse(l));
  assert.equal(progressLines[0].event, 'experiment.started');
  assert.equal(progressLines.at(-1).event, 'experiment.completed');

  // runs.jsonl stays pure append-only run records with enriched artifact provenance & identical M1 scores
  const runLines = (await readFile(path.join(expDir, 'runs.jsonl'), 'utf8'))
    .trim().split('\n').map((l) => JSON.parse(l));
  assert.equal(runLines.length, 4);
  const directM1 = await runM1PermissionOnly(COOKIE_MV3, { sampleId: 'S1', weightProfile: 'W1' });
  const loggedM1 = runLines.find((r) => r.sampleId === 'S1' && r.method === 'M1');
  assert.equal(loggedM1.riskScore, directM1.summary.riskScore);
  assert.equal(loggedM1.artifact.sampleId, 'S1');
  assert.equal(loggedM1.artifact.method, 'M1');
  assert.equal(loggedM1.artifact.packageSha256, directM1.provenance.packageSha256);
  assert.equal(loggedM1.artifact.configSha256, loggedM1.experimentConfigSha256);
  assert.match(loggedM1.artifact.createdAtUtc, /^\d{4}-\d{2}-\d{2}T/);
});

test('Experiment lifecycle handles interruption, preserves partial evidence, resumes cleanly, records runtime provenance, and detects artifact metadata tampering', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-log-lifecycle-'));
  t.after(() => rm(temp, { recursive: true, force: true }));

  const cookieM1 = await runM1PermissionOnly(COOKIE_MV3, { sampleId: 'S1' });
  const clipM1 = await runM1PermissionOnly(CLIPBOARD_MV3, { sampleId: 'S2' });
  const manifestPath = path.join(temp, 'manifest.json');
  await writeFile(manifestPath, JSON.stringify({
    schemaVersion: 1,
    datasetVersion: 'ds-life-1',
    samples: [
      { sampleId: 'S1', extensionId: 'ext-cookie', artifactPath: COOKIE_MV3 },
      { sampleId: 'S2', extensionId: 'ext-clip', artifactPath: CLIPBOARD_MV3 }
    ]
  }));

  const expRoot = path.join(temp, 'exps');
  const controller = new AbortController();
  let labCalls = 0;
  const mockLab = async ({ extension, scenario, output }) => {
    labCalls += 1;
    const isFirst = path.resolve(extension) === COOKIE_MV3;
    if (isFirst) {
      // Trigger graceful interruption after S1 completes M3 so S2 is never started
      controller.abort();
    }
    return {
      output,
      eventsPath: path.join(output, 'events.jsonl'),
      reportPath: path.join(output, 'report.json'),
      scenarioPath: scenario,
      imageId: 'sha256:' + '9'.repeat(64),
      report: {
        schemaVersion: 1,
        verdict: 'no_trigger_observed',
        contained: true,
        summary: { uncontainedExternalRequests: 0, blockedExternalRequests: 0 },
        objectives: {},
        suspicious: [],
        execution: {
          extension: { packageSha256: isFirst ? cookieM1.provenance.packageSha256 : clipM1.provenance.packageSha256 },
          browser: { name: 'chromium', version: '150.0.7871.181' },
          durationMs: 1000,
          isolation: { seccompSha256: 'c'.repeat(64) },
          container: { imageId: 'sha256:' + '9'.repeat(64) }
        },
        evidenceProvenance: {
          scenario: { sha256: 'd'.repeat(64) },
          events: { sha256: 'e'.repeat(64) },
          evaluation: { sha256: 'a'.repeat(64) }
        },
        caveats: []
      }
    };
  };

  // Run 1: interrupted after S1
  const intCap = captureStreams();
  const intCode = await runCli([
    'research', 'experiment',
    '--manifest', manifestPath,
    '--output', expRoot,
    '--experiment-id', 'exp-life',
    '--methods', 'M1,M3',
    '--weights', 'W1',
    '--scenario', SCENARIO,
    '--acknowledge-risk',
    '--format', 'json'
  ], intCap.streams, { labRunner: mockLab, signal: controller.signal, skipExternalProbes: true });
  assert.equal(intCode, 1);
  const intOut = JSON.parse(intCap.output().stdout);
  assert.equal(intOut.lifecycleState, 'interrupted');
  assert.equal(intOut.processedSamples, 1);
  assert.equal(labCalls, 1);

  const expDir = path.join(expRoot, 'exp-life');
  const runsPath = path.join(expDir, 'runs.jsonl');
  const runsAfterInterrupt = await readFile(runsPath, 'utf8');
  const manifestAfterInterrupt = JSON.parse(await readFile(path.join(expDir, 'run_manifest.json'), 'utf8'));
  assert.equal(manifestAfterInterrupt.lifecycleState, 'interrupted');
  assert.equal(manifestAfterInterrupt.environment.docker.imageId, 'sha256:' + '9'.repeat(64));
  assert.equal(manifestAfterInterrupt.environment.chromium.version, '150.0.7871.181');
  const originalCreatedAt = manifestAfterInterrupt.createdAtUtc;

  // Run 2: resume completes S2 without modifying existing runs.jsonl lines
  const resCap = captureStreams();
  const resCode = await runCli([
    'research', 'resume', expDir,
    '--acknowledge-risk',
    '--format', 'json'
  ], resCap.streams, { labRunner: mockLab, skipExternalProbes: true });
  assert.equal(resCode, 0);
  const resOut = JSON.parse(resCap.output().stdout);
  assert.equal(resOut.lifecycleState, 'completed');
  assert.equal(resOut.wasResumed, true);
  assert.equal(resOut.resumeCount, 1);
  assert.equal(resOut.priorRecordCount, 2);
  assert.equal(resOut.newRecordCount, 2);
  assert.equal(labCalls, 2);

  // Append-only guarantee: runs.jsonl starts byte-for-byte with prior lines
  const runsAfterResume = await readFile(runsPath, 'utf8');
  assert.ok(runsAfterResume.startsWith(runsAfterInterrupt));

  // Inspect shows complete lifecycle history and original createdAtUtc
  const inspCap = captureStreams();
  assert.equal(await runCli(['research', 'inspect', expDir, '--format', 'json'], inspCap.streams), 0);
  const insp = JSON.parse(inspCap.output().stdout);
  assert.equal(insp.experiment.createdAtUtc, originalCreatedAt);
  assert.equal(insp.experiment.lifecycleState, 'completed');
  assert.equal(insp.experiment.wasResumed, true);
  assert.equal(insp.experiment.resumeCount, 1);
  assert.deepEqual(
    insp.experiment.lifecycleHistory.map((h) => h.state),
    ['running', 'interrupted', 'resumed', 'completed']
  );
  assert.equal(insp.provenanceValidation.valid, true);
  assert.equal(insp.provenanceValidation.artifactMetadataMismatches, 0);

  // Tamper artifact provenance metadata in runs.jsonl -> detected by both inspect and resume
  const parsedRuns = runsAfterResume.trim().split('\n').map((l) => JSON.parse(l));
  parsedRuns[0].artifact.method = 'M2';
  await writeFile(runsPath, `${parsedRuns.map((r) => JSON.stringify(r)).join('\n')}\n`, 'utf8');

  const badInsp = captureStreams();
  assert.equal(await runCli(['research', 'inspect', expDir, '--format', 'json'], badInsp.streams), 0);
  const badInspJson = JSON.parse(badInsp.output().stdout);
  assert.equal(badInspJson.provenanceValidation.valid, false);
  assert.equal(badInspJson.provenanceValidation.artifactMetadataMismatches, 1);

  const badResume = captureStreams();
  assert.equal(await runCli(['research', 'resume', expDir, '--acknowledge-risk'], badResume.streams), 2);
  assert.match(badResume.output().stderr, /ARTIFACT_HASH_MISMATCH/);

  // Verify failed lifecycle state when all samples fail intake (and failure carries structured fields)
  const failDir = path.join(temp, 'fail-exp');
  const failedBatch = await runExperimentBatch({
    experimentId: 'exp-all-fail',
    outputDir: failDir,
    manifest: {
      schemaVersion: 1,
      datasetVersion: 'ds-fail',
      samples: [{ sampleId: 'F1', extensionId: 'ext-missing', artifactPath: path.join(temp, 'does-not-exist.crx') }]
    },
    methods: ['M1'],
    weightProfiles: ['W1'],
    skipExternalProbes: true
  });
  assert.equal(failedBatch.summary.lifecycleState, 'failed');
  assert.equal(failedBatch.records[0].status, 'failed');
  assert.equal(failedBatch.records[0].riskScore, null);
  assert.equal(failedBatch.records[0].failure.stage, 'intake');
  assert.equal(typeof failedBatch.records[0].failure.retryable, 'boolean');
  assert.match(failedBatch.records[0].failure.timestamp, /^\d{4}-\d{2}-\d{2}T/);
});

test('Audit P1-P5 fixes: repo-root git provenance, explicit timing breakdown, recordBreakdown, missing vs tampered artifacts, M3 runtime env, auxiliaryDependency, and 1-sample containment interrupt', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-audit-p1p5-'));
  t.after(() => rm(temp, { recursive: true, force: true }));

  // P1 (F4.2): probeGitStatus defaults to mvx-audit repo root regardless of caller cwd
  const gitStatus = probeGitStatus();
  assert.match(gitStatus.commit, /^[a-f0-9]{40}$/);
  assert.ok(['clean', 'dirty'].includes(gitStatus.workingTreeStatus));

  const cookieM1 = await runM1PermissionOnly(COOKIE_MV3, { sampleId: 'S1' });
  const fusionConfig = {
    schemaVersion: 1, configVersion: '2026.1-p1p5', formula: 'C-2', scoreCap: 100,
    staticBlendAlpha: 0.5, confidenceMultipliers: { high: 1.0, medium: 0.7, low: 0.4 },
    deduplicateMvx103Chain: true, tierABehavioralFloor: 85, tierBDynamicElevation: 35,
    tierBEscalatesWithExternalNetwork: true, suspiciousDynamicElevation: 20,
    requireExtensionInitiatorForSuspicious: true,
    corroboration: { primaryCategoryBonus: 12, t04ConditionalBonus: 5, maxBonus: 20 },
    allowStaticFallbackOnExecutionFailure: true,
    riskTierThresholds: { critical: 80, high: 55, medium: 25 }
  };
  const makeLab = (contained) => async ({ scenario, output }) => ({
    output, eventsPath: path.join(output, 'events.jsonl'), reportPath: path.join(output, 'report.json'),
    scenarioPath: scenario, imageId: 'sha256:' + '8'.repeat(64),
    report: {
      schemaVersion: 1, verdict: contained ? 'no_trigger_observed' : 'confirmed_attack', contained,
      summary: { uncontainedExternalRequests: contained ? 0 : 1, blockedExternalRequests: 0 },
      objectives: {}, suspicious: [],
      execution: {
        extension: { packageSha256: cookieM1.provenance.packageSha256 },
        browser: { name: 'chromium', version: '150.0.7871.181' },
        durationMs: 900, isolation: { seccompSha256: 'c'.repeat(64) },
        container: { imageId: 'sha256:' + '8'.repeat(64) }
      },
      evidenceProvenance: { scenario: { sha256: 'd'.repeat(64) }, events: { sha256: 'e'.repeat(64) }, evaluation: { sha256: 'a'.repeat(64) } },
      caveats: []
    }
  });

  // P2 (F1.2) + P3 (F3.2) + P5 (F4.4 & F2.2): multi-weight timing + recordBreakdown + M3 runtime env + auxiliaryDependency
  const batch = await runExperimentBatch({
    experimentId: 'exp-p1p5',
    outputDir: temp,
    manifest: {
      schemaVersion: 1, datasetVersion: 'ds-p1p5',
      samples: [
        { sampleId: 'S1', extensionId: 'ext-1', artifactPath: COOKIE_MV3 },
        { sampleId: 'S2', extensionId: 'ext-2', skip: true, skipReason: 'skip_test' }
      ]
    },
    methods: ['M1', 'M2', 'M4'], // M3 omitted -> persisted with auxiliaryDependency: true
    weightProfiles: ['W1', 'W2'],
    scenarioPath: SCENARIO,
    fusionConfig,
    m3Options: { repeatCount: 1, labRunner: makeLab(true) },
    acknowledgeRisk: true,
    skipExternalProbes: true
  });

  const m1W1 = batch.records.find((r) => r.sampleId === 'S1' && r.method === 'M1' && r.weightProfile === 'W1');
  const m1W2 = batch.records.find((r) => r.sampleId === 'S1' && r.method === 'M1' && r.weightProfile === 'W2');
  assert.equal(m1W1.sharedAnalysisPass, true);
  assert.equal(m1W1.primaryWeightPass, true);
  assert.equal(m1W2.sharedAnalysisPass, true);
  assert.equal(m1W2.primaryWeightPass, false);
  assert.equal(typeof m1W1.analysisDurationMs, 'number');
  assert.equal(typeof m1W1.scoringDurationMs, 'number');
  assert.equal(m1W1.totalDurationMs, Number((m1W1.analysisDurationMs + m1W1.scoringDurationMs).toFixed(3)));
  assert.notEqual(m1W1.riskScore, m1W2.riskScore);

  const m3Rec = batch.records.find((r) => r.sampleId === 'S1' && r.method === 'M3');
  assert.equal(m3Rec.auxiliaryDependency, true);
  assert.equal(m3Rec.environment.docker.imageId, 'sha256:' + '8'.repeat(64));
  assert.equal(m3Rec.environment.chromium.version, '150.0.7871.181');

  const rb = batch.summary.recordBreakdown;
  assert.deepEqual(rb, computeRecordBreakdown(batch.records, 2));
  assert.equal(rb.independentSamplesInManifest, 2);
  assert.equal(rb.uniqueStaticAnalysisPasses.M1, 1);
  assert.equal(rb.weightProfileEvaluations.M1, 2);
  assert.equal(rb.dynamicM3Executions.primary, 1);
  assert.equal(rb.dynamicM3Executions.auxiliaryDependency, 1);
  assert.equal(rb.nonExecutedPlaceholderRecords.skipped, 3);

  // P4 (F4.3): inspect separates missingArtifacts from artifactHashMismatches
  const artPath = path.join(batch.experimentRoot, m1W1.artifact.path);
  await rm(artPath);
  const missCap = captureStreams();
  assert.equal(await runCli(['research', 'inspect', batch.experimentRoot, '--format', 'json'], missCap.streams), 0);
  const missJson = JSON.parse(missCap.output().stdout);
  assert.equal(missJson.provenanceValidation.valid, false);
  assert.equal(missJson.provenanceValidation.missingArtifacts, 1);
  assert.equal(missJson.provenanceValidation.artifactHashMismatches, 0);
  assert.equal(missJson.runs.recordBreakdown.uniqueStaticAnalysisPasses.M1, 1);

  await writeFile(artPath, '{"corrupted":true}\n', 'utf8');
  const hashCap = captureStreams();
  assert.equal(await runCli(['research', 'inspect', batch.experimentRoot, '--format', 'json'], hashCap.streams), 0);
  const hashJson = JSON.parse(hashCap.output().stdout);
  assert.equal(hashJson.provenanceValidation.missingArtifacts, 0);
  assert.equal(hashJson.provenanceValidation.artifactHashMismatches, 1);

  // P5 (F2.3): 1-sample containment violation emits experiment.interrupted consistently
  const events = [];
  const containBatch = await runExperimentBatch({
    experimentId: 'exp-1sample-contain',
    outputDir: temp,
    manifest: {
      schemaVersion: 1, datasetVersion: 'ds-c',
      samples: [{ sampleId: 'S1', extensionId: 'ext-1', artifactPath: COOKIE_MV3 }]
    },
    methods: ['M3'],
    weightProfiles: ['W1'],
    scenarioPath: SCENARIO,
    m3Options: { repeatCount: 1, labRunner: makeLab(false) },
    acknowledgeRisk: true,
    skipExternalProbes: true,
    onProgress: (ev) => events.push(ev)
  });
  assert.equal(containBatch.summary.lifecycleState, 'failed');
  assert.equal(events.at(-1).event, 'experiment.interrupted');
  assert.equal(events.at(-1).reason, 'LAB_CONTAINMENT_VIOLATION');
});
