import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { lstat, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { runCli } from '../src/cli.js';
import { runM1PermissionOnly } from '../src/research/modes.js';
import { captureStreams } from '../support/helpers.js';

const COOKIE_MV3 = path.resolve('corpus/fixtures/cookie-access/mv3');
const COOKIE_MV2 = path.resolve('corpus/fixtures/cookie-access/mv2');
const CLIPBOARD_MV3 = path.resolve('corpus/fixtures/clipboard-read/mv3');
const SCENARIO = path.resolve('lab/scenarios/credential-exfiltration.json');

function sha256(text) {
  return createHash('sha256').update(text).digest('hex');
}

function makeMockLabRunner(pkgShaByPath, options = {}) {
  let calls = 0;
  const runner = async ({ extension, scenario, output }) => {
    calls += 1;
    const pkgSha = pkgShaByPath.get(path.resolve(extension));
    const uncontained = options.uncontained === true;
    const verdict = options.verdictByPath?.get(path.resolve(extension)) ?? 'no_trigger_observed';
    return {
      output,
      eventsPath: path.join(output, 'events.jsonl'),
      reportPath: path.join(output, 'report.json'),
      scenarioPath: scenario,
      imageId: 'sha256:' + 'f'.repeat(64),
      report: {
        schemaVersion: 1,
        verdict,
        contained: !uncontained,
        summary: {
          uncontainedExternalRequests: uncontained ? 1 : 0,
          blockedExternalRequests: 0
        },
        objectives: verdict === 'confirmed_attack'
          ? {
            credentialCanaryExfiltration: { status: 'confirmed', evidence: [] },
            contentManipulation: { status: 'not_observed', evidence: [] }
          }
          : {
            contentManipulation: { status: 'not_observed', evidence: [] }
          },
        suspicious: [],
        execution: {
          extension: { packageSha256: pkgSha },
          browser: { name: 'chromium', version: '138.0.0.0' },
          durationMs: 1200,
          isolation: { seccompSha256: 'c'.repeat(64) },
          container: { imageId: 'sha256:' + 'f'.repeat(64) }
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
  runner.getCalls = () => calls;
  return runner;
}

test('CLI help and command discovery document mvx research and preserve legacy CLI behavior', async () => {
  const topHelp = captureStreams();
  assert.equal(await runCli(['--help'], topHelp.streams), 0);
  assert.match(topHelp.output().stdout, /mvx research <validate\|experiment\|resume\|stability\|export\|evaluate\|inspect>/);
  assert.match(topHelp.output().stdout, /Exit codes:/);

  const researchHelp = captureStreams();
  assert.equal(await runCli(['research', '--help'], researchHelp.streams), 0);
  assert.match(researchHelp.output().stdout, /mvx research validate/);
  assert.match(researchHelp.output().stdout, /mvx research experiment/);
  assert.match(researchHelp.output().stdout, /mvx research resume/);
  assert.match(researchHelp.output().stdout, /mvx research stability/);
  assert.match(researchHelp.output().stdout, /mvx research export/);
  assert.match(researchHelp.output().stdout, /mvx research evaluate/);
  assert.match(researchHelp.output().stdout, /mvx research inspect/);

  const unknownSub = captureStreams();
  assert.equal(await runCli(['research', 'unknown-sub'], unknownSub.streams), 2);
  assert.match(unknownSub.output().stderr, /INVALID_CONFIG/);

  // Legacy CLI regressions remain intact
  const legacyAudit = captureStreams();
  assert.equal(await runCli(['audit', COOKIE_MV3, '--format', 'json'], legacyAudit.streams), 0);
  const auditJson = JSON.parse(legacyAudit.output().stdout);
  assert.equal(auditJson.analysis.sha256, 'b57ae698199aabddb9d1280d47bc1953df5ce6a6fe687537eff40c40cc0fe427');

  const legacyVersion = captureStreams();
  assert.equal(await runCli(['--version'], legacyVersion.streams), 0);
  assert.match(legacyVersion.output().stdout, /^3\.1\.0/);

  // Research-only flags are rejected by legacy commands
  const legacyBadFlag = captureStreams();
  assert.equal(await runCli(['audit', COOKIE_MV3, '--ground-truth', 'gt.csv'], legacyBadFlag.streams), 2);
  assert.match(legacyBadFlag.output().stderr, /INVALID_ARGUMENT/);
});

test('mvx research validate verifies manifest schema, hashes, MV3 compatibility, config, and Ground Truth separation', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-research-cli-val-'));
  t.after(() => rm(temp, { recursive: true, force: true }));

  const cookieM1 = await runM1PermissionOnly(COOKIE_MV3, { sampleId: 'S1' });
  const clipM1 = await runM1PermissionOnly(CLIPBOARD_MV3, { sampleId: 'S2' });

  const validManifestPath = path.join(temp, 'manifest.json');
  await writeFile(validManifestPath, JSON.stringify({
    schemaVersion: 1,
    datasetVersion: 'ds-val-1',
    samples: [
      {
        sampleId: 'S1',
        extensionId: 'ext-cookie',
        cohort: 'synthetic_positive',
        campaignId: 'camp-1',
        artifactPath: COOKIE_MV3,
        expectedPackageSha256: cookieM1.provenance.packageSha256
      },
      {
        sampleId: 'S2',
        extensionId: 'ext-clip',
        cohort: 'synthetic_negative',
        artifactPath: CLIPBOARD_MV3,
        expectedPackageSha256: clipM1.provenance.packageSha256
      }
    ]
  }, null, 2));

  const validConfigPath = path.join(temp, 'config.json');
  await writeFile(validConfigPath, JSON.stringify({
    schemaVersion: 1,
    methods: ['M1', 'M2', 'M3', 'M4'],
    weightProfiles: ['W1', 'W2'],
    m3Options: { repeatCount: 2, timeoutMs: 30000 }
  }, null, 2));

  const okJson = captureStreams();
  assert.equal(
    await runCli([
      'research', 'validate',
      '--manifest', validManifestPath,
      '--config', validConfigPath,
      '--require-manifest-v3',
      '--strict-hashes',
      '--format', 'json'
    ], okJson.streams),
    0
  );
  const valReport = JSON.parse(okJson.output().stdout);
  assert.equal(valReport.valid, true);
  assert.equal(valReport.groundTruthSeparated, true);
  assert.equal(valReport.summary.mv3CompatibleSamples, 2);
  assert.equal(valReport.summary.campaigns['camp-1'], 1);
  assert.equal(valReport.configValidation.valid, true);

  // Hash mismatch -> HASH_MISMATCH
  const badHashPath = path.join(temp, 'bad-hash.json');
  await writeFile(badHashPath, JSON.stringify({
    schemaVersion: 1,
    datasetVersion: 'ds-bad-hash',
    samples: [{
      sampleId: 'S1',
      extensionId: 'ext-cookie',
      artifactPath: COOKIE_MV3,
      expectedPackageSha256: '0'.repeat(64)
    }]
  }));
  const badHash = captureStreams();
  assert.equal(await runCli(['research', 'validate', '--manifest', badHashPath], badHash.streams), 2);
  assert.match(badHash.output().stderr, /HASH_MISMATCH/);

  // Missing hash with --strict-hashes -> HASH_MISSING
  const noHashPath = path.join(temp, 'no-hash.json');
  await writeFile(noHashPath, JSON.stringify({
    schemaVersion: 1,
    datasetVersion: 'ds-no-hash',
    samples: [{ sampleId: 'S1', extensionId: 'ext-cookie', artifactPath: COOKIE_MV3 }]
  }));
  const missingHash = captureStreams();
  assert.equal(
    await runCli(['research', 'validate', '--manifest', noHashPath, '--strict-hashes'], missingHash.streams),
    2
  );
  assert.match(missingHash.output().stderr, /HASH_MISSING/);

  // Non-MV3 rejected when --require-manifest-v3 is passed -> INVALID_DATASET
  const mv2ManifestPath = path.join(temp, 'mv2-manifest.json');
  await writeFile(mv2ManifestPath, JSON.stringify({
    schemaVersion: 1,
    datasetVersion: 'ds-mv2',
    samples: [{ sampleId: 'S1', extensionId: 'ext-mv2', artifactPath: COOKIE_MV2 }]
  }));
  const mv2Cap = captureStreams();
  assert.equal(
    await runCli(['research', 'validate', '--manifest', mv2ManifestPath, '--require-manifest-v3'], mv2Cap.streams),
    2
  );
  assert.match(mv2Cap.output().stderr, /INVALID_DATASET.*manifest_version=2/);

  // Ground Truth leakage in manifest -> GROUND_TRUTH_FORBIDDEN
  const gtLeakPath = path.join(temp, 'gt-leak.json');
  await writeFile(gtLeakPath, JSON.stringify({
    schemaVersion: 1,
    datasetVersion: 'ds-leak',
    samples: [{ sampleId: 'S1', extensionId: 'ext-1', artifactPath: COOKIE_MV3, groundTruthLabel: 'Malicious' }]
  }));
  const leakCap = captureStreams();
  assert.equal(await runCli(['research', 'validate', '--manifest', gtLeakPath], leakCap.streams), 2);
  assert.match(leakCap.output().stderr, /GROUND_TRUTH_FORBIDDEN/);
});

test('mvx research experiment, resume, stability, export, evaluate, and inspect work end-to-end with mocked M3 and synthetic Ground Truth', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-research-cli-e2e-'));
  t.after(() => rm(temp, { recursive: true, force: true }));

  const cookieM1 = await runM1PermissionOnly(COOKIE_MV3, { sampleId: 'S1' });
  const clipM1 = await runM1PermissionOnly(CLIPBOARD_MV3, { sampleId: 'S2' });
  const pkgByPath = new Map([
    [COOKIE_MV3, cookieM1.provenance.packageSha256],
    [CLIPBOARD_MV3, clipM1.provenance.packageSha256]
  ]);
  const verdictByPath = new Map([
    [COOKIE_MV3, 'confirmed_attack'],
    [CLIPBOARD_MV3, 'no_trigger_observed']
  ]);

  const manifestPath = path.join(temp, 'dataset.json');
  await writeFile(manifestPath, JSON.stringify({
    schemaVersion: 1,
    datasetVersion: 'ds-e2e-1',
    samples: [
      {
        sampleId: 'S1',
        extensionId: 'ext-cookie',
        cohort: 'cohort_a',
        artifactPath: COOKIE_MV3,
        expectedPackageSha256: cookieM1.provenance.packageSha256
      },
      {
        sampleId: 'S2',
        extensionId: 'ext-clip',
        cohort: 'cohort_b',
        artifactPath: CLIPBOARD_MV3,
        expectedPackageSha256: clipM1.provenance.packageSha256
      }
    ]
  }, null, 2));

  const experimentsRoot = path.join(temp, 'experiments');
  const fusionConfigPath = path.join(temp, 'fusion-config.json');
  await writeFile(fusionConfigPath, JSON.stringify({
    schemaVersion: 1,
    configVersion: '2026.1-cli-test',
    formula: 'C-2',
    scoreCap: 100,
    staticBlendAlpha: 0.5,
    confidenceMultipliers: { high: 1.0, medium: 0.7, low: 0.4 },
    deduplicateMvx103Chain: true,
    tierABehavioralFloor: 85,
    tierBDynamicElevation: 35,
    tierBEscalatesWithExternalNetwork: true,
    suspiciousDynamicElevation: 20,
    requireExtensionInitiatorForSuspicious: true,
    corroboration: { primaryCategoryBonus: 12, t04ConditionalBonus: 5, maxBonus: 20 },
    allowStaticFallbackOnExecutionFailure: true,
    riskTierThresholds: { critical: 80, high: 55, medium: 25 }
  }, null, 2));

  // Pre-validation failure must NOT create output directories
  const invalidExp = captureStreams();
  assert.equal(
    await runCli([
      'research', 'experiment',
      '--manifest', manifestPath,
      '--output', experimentsRoot,
      '--experiment-id', 'exp-bad',
      '--methods', 'M1,M9',
      '--weights', 'W1'
    ], invalidExp.streams),
    2
  );
  assert.match(invalidExp.output().stderr, /INVALID_CONFIG/);
  await assert.rejects(() => lstat(path.join(experimentsRoot, 'exp-bad')));

  // Run full M1-M4 experiment with 2 M3 repeats using mocked labRunner
  const mockLab = makeMockLabRunner(pkgByPath, { verdictByPath });
  const expCap = captureStreams();
  assert.equal(
    await runCli([
      'research', 'experiment',
      '--manifest', manifestPath,
      '--output', experimentsRoot,
      '--experiment-id', 'exp-01',
      '--methods', 'M1,M2,M3,M4',
      '--weights', 'W1,W2',
      '--scenario', SCENARIO,
      '--fusion-config', fusionConfigPath,
      '--m3-repeats', '2',
      '--m3-timeout', '15000',
      '--require-manifest-v3',
      '--acknowledge-risk',
      '--format', 'json'
    ], expCap.streams, { labRunner: mockLab }),
    0
  );
  const expResult = JSON.parse(expCap.output().stdout);
  assert.equal(expResult.experimentId, 'exp-01');
  assert.equal(expResult.totalSamples, 2);
  assert.equal(mockLab.getCalls(), 4); // 2 samples x 2 M3 repeats

  // Existing experiment protection without --resume -> EXPERIMENT_EXISTS
  const dupExp = captureStreams();
  assert.equal(
    await runCli([
      'research', 'experiment',
      '--manifest', manifestPath,
      '--output', experimentsRoot,
      '--experiment-id', 'exp-01',
      '--methods', 'M1,M2,M3,M4',
      '--weights', 'W1,W2',
      '--scenario', SCENARIO,
      '--fusion-config', fusionConfigPath,
      '--m3-repeats', '2',
      '--acknowledge-risk'
    ], dupExp.streams, { labRunner: mockLab }),
    2
  );
  assert.match(dupExp.output().stderr, /EXPERIMENT_EXISTS/);

  // Simulate interrupted experiment by dropping the last 2 lines from runs.jsonl, then resume
  const expDir = path.join(experimentsRoot, 'exp-01');
  const runsPath = path.join(expDir, 'runs.jsonl');
  const fullLines = (await readFile(runsPath, 'utf8')).trim().split('\n');
  const truncatedText = `${fullLines.slice(0, fullLines.length - 2).join('\n')}\n`;
  await writeFile(runsPath, truncatedText, 'utf8');

  const resumeLab = makeMockLabRunner(pkgByPath, { verdictByPath });
  const resumeCap = captureStreams();
  assert.equal(
    await runCli([
      'research', 'resume', expDir,
      '--acknowledge-risk',
      '--format', 'json'
    ], resumeCap.streams, { labRunner: resumeLab }),
    0
  );
  const resumeOut = JSON.parse(resumeCap.output().stdout);
  assert.equal(resumeOut.priorRecordCount, fullLines.length - 2);
  assert.equal(resumeOut.newRecordCount, 2);
  assert.equal(resumeOut.totalRunRecords, fullLines.length);
  assert.equal(resumeLab.getCalls(), 0); // M3 runs were already completed & cached!

  // Resume with drifted config -> CONFIG_MISMATCH
  const driftedCfg = path.join(temp, 'drifted-config.json');
  await writeFile(driftedCfg, JSON.stringify({
    schemaVersion: 1,
    methods: ['M1', 'M2'],
    weightProfiles: ['W1']
  }));
  const driftCap = captureStreams();
  assert.equal(
    await runCli(['research', 'resume', expDir, '--config', driftedCfg], driftCap.streams),
    2
  );
  assert.match(driftCap.output().stderr, /CONFIG_MISMATCH/);

  // Stability subcommand preserves independent sample count (2) vs total M3 runs (4)
  const stabDir = path.join(temp, 'stability-out');
  const stabCap = captureStreams();
  assert.equal(
    await runCli(['research', 'stability', expDir, '--output', stabDir, '--format', 'json'], stabCap.streams),
    0
  );
  const stabJson = JSON.parse(stabCap.output().stdout);
  assert.equal(stabJson.independentExtensionsEvaluated, 2);
  assert.equal(stabJson.overall.totalExecutedRuns, 4);
  assert.ok(stabJson.exportedFiles.csv.sha256);

  // Label-blind export
  const exportDir = path.join(temp, 'exp-01-export');
  const exportCap = captureStreams();
  assert.equal(
    await runCli(['research', 'export', expDir, '--output', exportDir, '--format', 'json'], exportCap.streams),
    0
  );
  const exportJson = JSON.parse(exportCap.output().stdout);
  assert.equal(exportJson.labelBlind, true);
  assert.ok(exportJson.files['raw/execution_log.csv']);
  assert.ok(exportJson.files['tables/per_extension_results.csv']);

  // Evaluation requires pre-registered thresholds for every evaluated method
  const gtCsvPath = path.join(temp, 'synthetic_gt.csv');
  await writeFile(gtCsvPath, [
    'Sample_ID,Final_Decision,Label_Level,Verification_Status,Reviewer_1_Decision,Reviewer_2_Decision,Disagreement,SHA256,Campaign_ID',
    `S1,Malicious,Extension-Level,Verified,Malicious,Malicious,No,${cookieM1.provenance.packageSha256},camp-1`,
    `S2,Benign,Extension-Level,Verified,Benign,Benign,No,${clipM1.provenance.packageSha256},camp-2`,
    'S3,Unverified,Extension-Level,Unverified,Pending,Pending,Pending,,camp-3'
  ].join('\n'));

  const incompleteEvalCfg = path.join(temp, 'eval-missing-threshold.json');
  await writeFile(incompleteEvalCfg, JSON.stringify({
    thresholds: { M1: 20, M2: 20, M4: 40 } // M3 missing!
  }));
  const evalDir = path.join(temp, 'exp-01-evaluation');
  const missingThr = captureStreams();
  assert.equal(
    await runCli([
      'research', 'evaluate', expDir,
      '--ground-truth', gtCsvPath,
      '--config', incompleteEvalCfg,
      '--output', evalDir
    ], missingThr.streams),
    2
  );
  assert.match(missingThr.output().stderr, /INVALID_CONFIG.*M3/);

  // Evaluation refuses overlapping output directory -> GROUND_TRUTH_FORBIDDEN
  const evalCfgPath = path.join(temp, 'eval-config.json');
  await writeFile(evalCfgPath, JSON.stringify({
    thresholds: { M1: 20, M2: 20, M3: 50, M4: 40 },
    alpha: 0.05,
    bootstrapResamples: 20,
    bootstrapSeed: 42
  }));
  const overlapEval = captureStreams();
  assert.equal(
    await runCli([
      'research', 'evaluate', expDir,
      '--ground-truth', gtCsvPath,
      '--config', evalCfgPath,
      '--output', path.join(expDir, 'eval-inside')
    ], overlapEval.streams),
    2
  );
  assert.match(overlapEval.output().stderr, /GROUND_TRUTH_FORBIDDEN/);

  // Valid evaluation writes separate directory & preserves original runs.jsonl byte-for-byte
  const runsBeforeEval = await readFile(runsPath, 'utf8');
  const evalCap = captureStreams();
  assert.equal(
    await runCli([
      'research', 'evaluate', expDir,
      '--ground-truth', gtCsvPath,
      '--config', evalCfgPath,
      '--output', evalDir,
      '--format', 'text'
    ], evalCap.streams),
    0
  );
  assert.equal(await readFile(runsPath, 'utf8'), runsBeforeEval);
  assert.match(evalCap.output().stdout, /Ground Truth SHA-256:/);
  assert.match(evalCap.output().stdout, /Cohort: 2\/3 eligible/);
  assert.match(evalCap.output().stdout, /Prec=/);

  // Export with existing evaluation report rejects overlapping --evaluation-output
  const overlapExport = captureStreams();
  assert.equal(
    await runCli([
      'research', 'export', expDir,
      '--output', path.join(temp, 'export-2'),
      '--evaluation', path.join(evalDir, 'evaluation_report.json'),
      '--evaluation-output', path.join(temp, 'export-2', 'tables')
    ], overlapExport.streams),
    2
  );
  assert.match(overlapExport.output().stderr, /GROUND_TRUTH_FORBIDDEN/);

  // Inspect shows provenance & locations without exposing Ground Truth labels
  const inspectCap = captureStreams();
  assert.equal(
    await runCli([
      'research', 'inspect', expDir,
      '--export-dir', exportDir,
      '--evaluation-dir', evalDir,
      '--format', 'json'
    ], inspectCap.streams),
    0
  );
  const inspectJson = JSON.parse(inspectCap.output().stdout);
  assert.equal(inspectJson.labelBlind, true);
  assert.equal(inspectJson.provenanceValidation.valid, true);
  assert.equal(inspectJson.stability.available, true);
  assert.equal(inspectJson.artifacts.exportLocation.exists, true);
  assert.equal(inspectJson.artifacts.evaluationLocation.exists, true);
  assert.doesNotMatch(inspectCap.output().stdout, /Malicious/);

  // Tampered cached artifact detected by resume -> ARTIFACT_HASH_MISMATCH
  const firstRecord = JSON.parse((await readFile(runsPath, 'utf8')).trim().split('\n')[0]);
  const artPath = path.join(expDir, firstRecord.artifact.path);
  await writeFile(artPath, '{"tampered":true}\n', 'utf8');
  const tamperCap = captureStreams();
  assert.equal(await runCli(['research', 'resume', expDir, '--acknowledge-risk'], tamperCap.streams), 2);
  assert.match(tamperCap.output().stderr, /ARTIFACT_HASH_MISMATCH/);

  // Corrupted runs.jsonl -> CORRUPT_RUN_LOG
  await writeFile(runsPath, '{bad json\n', 'utf8');
  const corruptCap = captureStreams();
  assert.equal(await runCli(['research', 'inspect', expDir], corruptCap.streams), 2);
  assert.match(corruptCap.output().stderr, /CORRUPT_RUN_LOG/);
});

test('mvx research experiment halts on LAB_CONTAINMENT_VIOLATION and evaluate rejects hash mismatch or zero eligible Ground Truth', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-research-cli-err-'));
  t.after(() => rm(temp, { recursive: true, force: true }));

  const cookieM1 = await runM1PermissionOnly(COOKIE_MV3, { sampleId: 'S1' });
  const manifestPath = path.join(temp, 'manifest.json');
  await writeFile(manifestPath, JSON.stringify({
    schemaVersion: 1,
    datasetVersion: 'ds-err-1',
    samples: [{ sampleId: 'S1', extensionId: 'ext-cookie', artifactPath: COOKIE_MV3 }]
  }));

  // Containment violation halts experiment with LAB_CONTAINMENT_VIOLATION
  const badLab = makeMockLabRunner(new Map([[COOKIE_MV3, cookieM1.provenance.packageSha256]]), { uncontained: true });
  const expRoot = path.join(temp, 'exps');
  const containCap = captureStreams();
  assert.equal(
    await runCli([
      'research', 'experiment',
      '--manifest', manifestPath,
      '--output', expRoot,
      '--experiment-id', 'exp-contain',
      '--methods', 'M1,M3',
      '--weights', 'W1',
      '--scenario', SCENARIO,
      '--m3-repeats', '2',
      '--acknowledge-risk'
    ], containCap.streams, { labRunner: badLab }),
    2
  );
  assert.match(containCap.output().stderr, /LAB_CONTAINMENT_VIOLATION/);
  assert.equal(badLab.getCalls(), 1); // Never retried after containment violation!

  // Clean M1-only experiment for Ground Truth failure tests
  const cleanExp = captureStreams();
  assert.equal(
    await runCli([
      'research', 'experiment',
      '--manifest', manifestPath,
      '--output', expRoot,
      '--experiment-id', 'exp-m1',
      '--methods', 'M1',
      '--weights', 'W1'
    ], cleanExp.streams),
    0
  );
  const m1ExpDir = path.join(expRoot, 'exp-m1');
  const evalCfgPath = path.join(temp, 'eval-m1.json');
  await writeFile(evalCfgPath, JSON.stringify({ thresholds: { M1: 20 } }));

  // Hash mismatch in Ground Truth -> HASH_MISMATCH
  const wrongShaGt = path.join(temp, 'gt-wrong-sha.csv');
  await writeFile(wrongShaGt, [
    'Sample_ID,Final_Decision,Label_Level,Verification_Status,Disagreement,SHA256',
    `S1,Malicious,Extension-Level,Verified,No,${sha256('wrong')}`
  ].join('\n'));
  const hashFail = captureStreams();
  assert.equal(
    await runCli([
      'research', 'evaluate', m1ExpDir,
      '--ground-truth', wrongShaGt,
      '--config', evalCfgPath,
      '--output', path.join(temp, 'eval-hash-fail')
    ], hashFail.streams),
    2
  );
  assert.match(hashFail.output().stderr, /HASH_MISMATCH/);

  // Zero eligible verified Ground Truth -> EVALUATION_FAILED
  const unverifiedGt = path.join(temp, 'gt-unverified.csv');
  await writeFile(unverifiedGt, [
    'Sample_ID,Final_Decision,Label_Level,Verification_Status,Disagreement',
    'S1,Unverified,Extension-Level,Unverified,Pending'
  ].join('\n'));
  const zeroEligible = captureStreams();
  assert.equal(
    await runCli([
      'research', 'evaluate', m1ExpDir,
      '--ground-truth', unverifiedGt,
      '--config', evalCfgPath,
      '--output', path.join(temp, 'eval-empty')
    ], zeroEligible.streams),
    2
  );
  assert.match(zeroEligible.output().stderr, /EVALUATION_FAILED/);
});
