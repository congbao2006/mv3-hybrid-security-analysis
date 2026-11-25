import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { auditExtension } from '../src/analyzer.js';
import { MvxError } from '../src/errors.js';
import { createFusionConfig } from '../src/research/hybrid-fusion.js';
import {
  runExperimentBatch,
  validateDatasetManifest,
  verifyExperimentProvenance
} from '../src/research/experiment-runner.js';
import {
  computeMultiSampleStabilitySummary,
  selectRepeatedRunSubset,
  summarizeRepeatedDynamicRuns
} from '../src/research/stability.js';
import { VERSION } from '../src/version.js';

const MOCK_HASH = 'c'.repeat(64);

function makeFusionConfig() {
  return createFusionConfig({
    schemaVersion: 1,
    configVersion: '2026.1-phase4-test',
    formula: 'C-2',
    scoreCap: 100,
    staticBlendAlpha: 0.4,
    confidenceMultipliers: { high: 1.0, medium: 0.7, low: 0.4 },
    deduplicateMvx103Chain: true,
    tierABehavioralFloor: 85,
    tierBDynamicElevation: 20,
    tierBEscalatesWithExternalNetwork: true,
    suspiciousDynamicElevation: 15,
    requireExtensionInitiatorForSuspicious: true,
    corroboration: {
      primaryCategoryBonus: 12,
      t04ConditionalBonus: 5,
      maxBonus: 20
    },
    allowStaticFallbackOnExecutionFailure: false,
    riskTierThresholds: { critical: 70, high: 40, medium: 20 }
  });
}

function makeMockLabRunner(behaviorByExtensionPath) {
  const callCounts = new Map();
  return async ({ extension, output, scenario }) => {
    const count = (callCounts.get(extension) ?? 0) + 1;
    callCounts.set(extension, count);
    const audit = await auditExtension(extension);
    const spec = behaviorByExtensionPath(extension, count);
    if (spec.throwError) throw spec.throwError;
    const verdict = spec.verdict ?? 'no_trigger_observed';
    const contained = spec.contained ?? true;
    const imageId = `sha256:${MOCK_HASH}`;
    return {
      imageId,
      output,
      eventsPath: path.join(output, 'events.jsonl'),
      reportPath: path.join(output, 'report.json'),
      scenarioPath: scenario,
      report: {
        schemaVersion: 1,
        scenarioId: 'mock-scenario',
        verdict,
        contained,
        summary: {
          eventsAnalyzed: 4,
          confirmedObjectives: verdict === 'confirmed_attack' ? 1 : 0,
          suspiciousEvents: spec.suspicious?.length ?? 0,
          errors: spec.errors?.length ?? 0,
          blockedExternalRequests: verdict === 'no_trigger_observed' ? 0 : 1,
          uncontainedExternalRequests: contained ? 0 : 1,
          completed: verdict !== 'inconclusive'
        },
        objectives: spec.objectives ?? {},
        suspicious: spec.suspicious ?? [],
        errors: spec.errors ?? [],
        caveats: [],
        execution: {
          profile: 'mvx-lab-execution-v1',
          startedAt: '2026-11-25T10:00:00.000Z',
          tool: { version: VERSION },
          extension: {
            packageSha256: spec.overridePackageSha256 ?? audit.package.sha256,
            analysisSha256: audit.analysis.sha256
          },
          scenarioSha256: MOCK_HASH,
          browser: 'Chromium 150.0.0.0',
          container: { imageReference: 'mvx-lab:mock', imageId, network: 'none' },
          isolation: { seccompSha256: MOCK_HASH },
          durationMs: 8_000
        },
        evidenceProvenance: {
          scenario: { sha256: MOCK_HASH },
          events: { sha256: MOCK_HASH },
          evaluation: { sha256: MOCK_HASH }
        }
      }
    };
  };
}

test('Batch runner processes multiple fixtures across M1-M4 and W1-W5 with deterministic provenance and non-destructive storage', async (t) => {
  const outDir = await mkdtemp(path.join(os.tmpdir(), 'mvx-phase4-batch-'));
  t.after(() => rm(outDir, { recursive: true, force: true }));

  const benignDir = path.resolve('lab/fixtures/benign');
  const cookieDir = path.resolve('corpus/fixtures/cookie-access/mv3');
  const manifest = {
    schemaVersion: 1,
    datasetVersion: '2026.1-unit',
    samples: [
      { sampleId: 'CB-001', extensionId: 'local:benign', cohort: 'controlled_benign', artifactPath: benignDir },
      { sampleId: 'CST-002', extensionId: 'local:cookie', cohort: 'controlled_security', artifactPath: cookieDir },
      { sampleId: 'SKIP-001', extensionId: 'local:skip', cohort: 'skipped', skip: true, skipReason: 'uncollected_artifact' },
      { sampleId: 'MISSING-001', extensionId: 'local:missing', cohort: 'missing', artifactPath: path.join(outDir, 'does-not-exist') }
    ]
  };

  const fusionConfig = makeFusionConfig();
  const result = await runExperimentBatch({
    experimentId: 'exp-001',
    manifest,
    outputDir: outDir,
    methods: ['M1', 'M2', 'M3', 'M4'],
    weightProfiles: ['W1', 'W2', 'W5'],
    fusionConfig,
    scenarioPath: path.resolve('lab/scenarios/credential-exfiltration.json'),
    acknowledgeRisk: true,
    baseCommit: 'e4ee18b8f3f1bd34ef7744015d8c58b5fb930a1d',
    m3Options: {
      labRunner: makeMockLabRunner((extPath) => {
        if (extPath.includes('cookie-access')) {
          return {
            verdict: 'confirmed_attack',
            objectives: {
              sessionCookie: {
                status: 'confirmed',
                evidence: [{ event: 2, type: 'network.request', url: 'https://evil.invalid/cookie' }]
              }
            }
          };
        }
        return { verdict: 'no_trigger_observed' };
      })
    }
  });

  assert.equal(result.summary.haltedEarly, false);
  assert.equal(result.summary.containmentViolationObserved, false);
  assert.equal(result.summary.provenanceCheck.valid, true);
  assert.equal(result.summary.fusionConfigSha256, fusionConfig.sha256);
  // CB-001 & CST-002 each produce: 3 M1 + 3 M2 + 1 M3 + 3 M4 = 10 records -> 20
  // SKIP-001 produces 4 skipped records (1 per method)
  // MISSING-001 produces 3 M1 failed + 3 M2 failed + 1 M3 failed + 3 M4 failed = 10 failed records
  assert.equal(result.summary.statusCounts.skipped, 4);
  assert.equal(result.summary.statusCounts.failed > 0, true);
  assert.equal(result.summary.statusCounts.completed, 20);

  // Verify W1, W2, W5 M1 scores for CST-002
  const m1W1 = result.records.find((r) => r.runId === 'exp-001:CST-002:M1:W1');
  const m1W2 = result.records.find((r) => r.runId === 'exp-001:CST-002:M1:W2');
  const m1W5 = result.records.find((r) => r.runId === 'exp-001:CST-002:M1:W5');
  assert.equal(m1W1.riskScore, 49);
  assert.equal(m1W2.riskScore, 59);
  assert.equal(m1W5.riskScore, 61);
  assert.equal(m1W1.packageSha256, m1W2.packageSha256);

  // Verify M4 CST-002 got Tier-A floor (85) and preserved fusionConfig provenance
  const m4W1 = result.records.find((r) => r.runId === 'exp-001:CST-002:M4:W1');
  assert.equal(m4W1.riskScore, 85);
  assert.equal(m4W1.fusionConfigSha256, fusionConfig.sha256);
  assert.equal(m4W1.packageSha256, m1W1.packageSha256);

  // Non-destructive overwrite guard
  await assert.rejects(
    () => runExperimentBatch({
      experimentId: 'exp-001',
      manifest,
      outputDir: outDir,
      methods: ['M1'],
      weightProfiles: ['W1']
    }),
    (err) => err instanceof MvxError && err.code === 'EXPERIMENT_EXISTS'
  );

  // Verify runs.jsonl deterministic formatting and valid JSONL lines
  const rawJsonl = await readFile(path.join(result.experimentRoot, 'runs.jsonl'), 'utf8');
  const parsedLines = rawJsonl.trim().split('\n').map((line) => JSON.parse(line));
  assert.equal(parsedLines.length, result.records.length);
  assert.equal(verifyExperimentProvenance(parsedLines).valid, true);
});

test('Repeated-run stability computes stats over completed runs only, excludes inconclusive/failed from numeric average, and never treats repeats as independent samples', async (t) => {
  const outDir = await mkdtemp(path.join(os.tmpdir(), 'mvx-phase4-stability-'));
  t.after(() => rm(outDir, { recursive: true, force: true }));

  const cookieDir = path.resolve('corpus/fixtures/cookie-access/mv3');
  const benignDir = path.resolve('lab/fixtures/benign');
  const manifest = {
    schemaVersion: 1,
    datasetVersion: '2026.1-stability',
    samples: [
      { sampleId: 'CST-002', extensionId: 'local:cookie', cohort: 'controlled_security', artifactPath: cookieDir },
      { sampleId: 'CB-001', extensionId: 'local:benign', cohort: 'controlled_benign', artifactPath: benignDir }
    ]
  };

  // CST-002: run 1 confirmed_attack (100), run 2 suspicious_activity (50), run 3 inconclusive (null), run 4 LAB_TIMEOUT (null)
  // CB-001: all 4 runs no_trigger_observed (0)
  const result = await runExperimentBatch({
    experimentId: 'exp-stab',
    manifest,
    outputDir: outDir,
    methods: ['M1', 'M2', 'M3', 'M4'],
    weightProfiles: ['W1'],
    fusionConfig: makeFusionConfig(),
    scenarioPath: path.resolve('lab/scenarios/credential-exfiltration.json'),
    acknowledgeRisk: true,
    m3Options: {
      repeatCount: 4,
      labRunner: makeMockLabRunner((extPath, callIdx) => {
        if (extPath.includes('cookie-access')) {
          if (callIdx === 1) {
            return {
              verdict: 'confirmed_attack',
              objectives: {
                sessionCookie: { status: 'confirmed', evidence: [{ event: 2, type: 'network.request', url: 'https://evil.invalid/c' }] }
              }
            };
          }
          if (callIdx === 2) {
            return {
              verdict: 'suspicious_activity',
              suspicious: [{ event: 2, type: 'network.request', reason: 'external-request', url: 'https://evil.invalid/ping', initiator: 'extension' }]
            };
          }
          if (callIdx === 3) return { verdict: 'inconclusive', errors: [{ message: 'CDP timeout' }] };
          return { throwError: new MvxError('Container timed out', { code: 'LAB_TIMEOUT' }) };
        }
        return { verdict: 'no_trigger_observed' };
      })
    }
  });

  // Only 1 M4 record per extension (NOT 4!) -> repeated runs never treated as independent extensions
  const m4Records = result.records.filter((r) => r.method === 'M4');
  assert.equal(m4Records.length, 2);

  assert.equal(result.stabilitySummaries.length, 2);
  const cookieStab = result.stabilitySummaries.find((s) => s.sampleId === 'CST-002');
  assert.equal(cookieStab.independentDatasetSampleCount, 1);
  assert.equal(cookieStab.counts.requestedRuns, 4);
  assert.equal(cookieStab.counts.completedRuns, 2);
  assert.equal(cookieStab.counts.inconclusiveRuns, 1);
  assert.equal(cookieStab.counts.failedRuns, 1);
  // Mean/min/max computed ONLY over [100, 50] -> mean=75, min=50, max=100 (NOT averaging inconclusive/failed as 0!)
  assert.equal(cookieStab.riskScoreStats.sampleCount, 2);
  assert.equal(cookieStab.riskScoreStats.mean, 75);
  assert.equal(cookieStab.riskScoreStats.min, 50);
  assert.equal(cookieStab.riskScoreStats.max, 100);
  assert.equal(cookieStab.riskScoreStats.excludedIncompatibleRunCount, 2);
  assert.equal(cookieStab.verdictConsistencyAllRuns.exactAgreement, false);
  assert.equal(cookieStab.objectiveDetectionFrequency.sessionCookie.confirmedCount, 1);
  assert.equal(cookieStab.objectiveDetectionFrequency.sessionCookie.frequencyOverCompleted, 0.5);
  assert.equal(cookieStab.rates.failureRate, 0.25);

  const benignStab = result.stabilitySummaries.find((s) => s.sampleId === 'CB-001');
  assert.equal(benignStab.verdictConsistencyAllRuns.exactAgreement, true);
  assert.equal(benignStab.riskScoreStats.mean, 0);
  assert.equal(benignStab.riskScoreStats.populationStdDev, 0);

  const multi = computeMultiSampleStabilitySummary(result.stabilitySummaries);
  assert.equal(multi.extensionsEvaluated, 2);
  assert.equal(multi.overallExactAgreementRate, 0.5);
  assert.equal(typeof multi.fleissKappa, 'number');

  // Seeded subset selection is deterministic
  const subsetA = selectRepeatedRunSubset(manifest.samples, { ratio: 0.5, minSamples: 1, seed: 42 });
  const subsetB = selectRepeatedRunSubset(manifest.samples, { ratio: 0.5, minSamples: 1, seed: 42 });
  assert.deepEqual(subsetA.selectedSampleIds, subsetB.selectedSampleIds);
});

test('Containment violation halts batch immediately without retrying and fails M4 hard', async (t) => {
  const outDir = await mkdtemp(path.join(os.tmpdir(), 'mvx-phase4-containment-'));
  t.after(() => rm(outDir, { recursive: true, force: true }));

  const manifest = {
    schemaVersion: 1,
    datasetVersion: '2026.1-containment',
    samples: [
      { sampleId: 'S1', extensionId: 'ext-1', cohort: 'test', artifactPath: path.resolve('lab/fixtures/benign') },
      { sampleId: 'S2', extensionId: 'ext-2', cohort: 'test', artifactPath: path.resolve('corpus/fixtures/cookie-access/mv3') }
    ]
  };

  let runnerCalls = 0;
  const result = await runExperimentBatch({
    experimentId: 'exp-halt',
    manifest,
    outputDir: outDir,
    methods: ['M1', 'M2', 'M3', 'M4'],
    weightProfiles: ['W1'],
    fusionConfig: makeFusionConfig(),
    scenarioPath: path.resolve('lab/scenarios/credential-exfiltration.json'),
    acknowledgeRisk: true,
    m3Options: {
      repeatCount: 3,
      labRunner: makeMockLabRunner(() => {
        runnerCalls += 1;
        return { verdict: 'confirmed_attack', contained: false };
      })
    }
  });

  // Never retried repeat 2 or 3, and never proceeded to S2!
  assert.equal(runnerCalls, 1);
  assert.equal(result.summary.haltedEarly, true);
  assert.equal(result.summary.haltReason, 'LAB_CONTAINMENT_VIOLATION');
  assert.equal(result.summary.containmentViolationObserved, true);
  assert.equal(result.records.some((r) => r.sampleId === 'S2'), false);
  const s1M4 = result.records.find((r) => r.sampleId === 'S1' && r.method === 'M4');
  assert.equal(s1M4.status, 'failed');
  assert.equal(s1M4.riskScore, null);
  assert.equal(s1M4.failure.code, 'LAB_CONTAINMENT_VIOLATION');
});

test('Interrupted batch recovery resumes cleanly without duplicating completed records and rejects config drift', async (t) => {
  const outDir = await mkdtemp(path.join(os.tmpdir(), 'mvx-phase4-resume-'));
  t.after(() => rm(outDir, { recursive: true, force: true }));

  const manifest = {
    schemaVersion: 1,
    datasetVersion: '2026.1-resume',
    samples: [
      { sampleId: 'S1', extensionId: 'ext-1', cohort: 'test', artifactPath: path.resolve('lab/fixtures/benign') },
      { sampleId: 'S2', extensionId: 'ext-2', cohort: 'test', artifactPath: path.resolve('corpus/fixtures/cookie-access/mv3') }
    ]
  };

  // Run only S1 first (simulating interruption before S2)
  const partial = await runExperimentBatch({
    experimentId: 'exp-resume',
    manifest: { ...manifest, samples: [manifest.samples[0]] },
    outputDir: outDir,
    methods: ['M1', 'M2'],
    weightProfiles: ['W1']
  });
  assert.equal(partial.records.length, 2);

  // Resume with full manifest (S1 + S2) -> preserves S1 records and executes only S2
  const resumed = await runExperimentBatch({
    experimentId: 'exp-resume',
    manifest,
    outputDir: outDir,
    methods: ['M1', 'M2'],
    weightProfiles: ['W1'],
    resume: true
  });
  assert.equal(resumed.records.length, 4);
  assert.equal(resumed.summary.provenanceCheck.uniqueRunIds, 4);

  // Config mismatch on resume fails closed
  await assert.rejects(
    () => runExperimentBatch({
      experimentId: 'exp-resume',
      manifest,
      outputDir: outDir,
      methods: ['M1', 'M2'],
      weightProfiles: ['W1', 'W2'],
      resume: true
    }),
    (err) => err instanceof MvxError && err.code === 'CONFIG_MISMATCH'
  );

  // Corrupted JSONL line on resume fails closed
  const jsonlPath = path.join(outDir, 'exp-resume', 'runs.jsonl');
  await writeFile(jsonlPath, `${await readFile(jsonlPath, 'utf8')}{broken json\n`, 'utf8');
  await assert.rejects(
    () => runExperimentBatch({
      experimentId: 'exp-resume',
      manifest,
      outputDir: outDir,
      methods: ['M1', 'M2'],
      weightProfiles: ['W1'],
      resume: true
    }),
    (err) => err instanceof MvxError && err.code === 'CORRUPT_RUN_LOG'
  );
});

test('Reproducibility checks detect package SHA mismatch, config mismatch, duplicate runIds, and Ground Truth leakage', () => {
  // Ground Truth rejected in manifest and runner options
  assert.throws(
    () => validateDatasetManifest({
      schemaVersion: 1,
      datasetVersion: '1',
      samples: [{ sampleId: 'S1', extensionId: 'e1', artifactPath: '/x', groundTruth: 'Benign' }]
    }),
    (err) => err instanceof MvxError && err.code === 'GROUND_TRUTH_FORBIDDEN'
  );

  const baseRecord = {
    schemaVersion: 1,
    experimentId: 'exp-1',
    runId: 'exp-1:S1:M1:W1',
    sampleId: 'S1',
    extensionId: 'e1',
    packageSha256: '1'.repeat(64),
    method: 'M1',
    weightProfile: 'W1',
    experimentConfigSha256: '2'.repeat(64),
    mvxVersion: VERSION,
    mvxBaseCommit: 'a'.repeat(40),
    timestampUtc: '2026-11-25T10:00:00.000Z',
    durationMs: 12,
    environment: { nodeVersion: process.version },
    status: 'completed'
  };

  assert.throws(
    () => verifyExperimentProvenance([baseRecord, baseRecord]),
    (err) => err instanceof MvxError && err.code === 'DUPLICATE_RUN_ID'
  );
  assert.throws(
    () => verifyExperimentProvenance([
      baseRecord,
      { ...baseRecord, runId: 'exp-1:S1:M2:W1', method: 'M2', packageSha256: '9'.repeat(64) }
    ]),
    (err) => err instanceof MvxError && err.code === 'PACKAGE_SHA_MISMATCH'
  );
  assert.throws(
    () => verifyExperimentProvenance([
      baseRecord,
      { ...baseRecord, runId: 'exp-1:S2:M1:W1', sampleId: 'S2', experimentConfigSha256: '8'.repeat(64) }
    ]),
    (err) => err instanceof MvxError && err.code === 'CONFIG_MISMATCH'
  );
  assert.throws(
    () => summarizeRepeatedDynamicRuns([
      { runId: 'r1', status: 'completed', verdict: 'no_trigger_observed', riskScore: 0, packageSha256: '1'.repeat(64) },
      { runId: 'r2', status: 'completed', verdict: 'no_trigger_observed', riskScore: 0, packageSha256: '2'.repeat(64) }
    ]),
    (err) => err instanceof MvxError && err.code === 'PACKAGE_SHA_MISMATCH'
  );
});
