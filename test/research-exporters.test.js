import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { parseCsv } from '../src/csv.js';
import { MvxError } from '../src/errors.js';
import {
  EXPORTER_SCHEMA_VERSION,
  exportExecutionLog,
  exportExperimentBundle,
  exportFailureAndInconclusiveTable,
  exportMethodSummaries,
  exportPerExtensionTable,
  exportStabilitySummaries,
  exportWeightProfileComparison
} from '../src/research/exporters.js';
import { summarizeRepeatedDynamicRuns } from '../src/research/stability.js';

const PKG_1 = '1'.repeat(64);
const PKG_2 = '2'.repeat(64);
const CFG_SHA = 'a'.repeat(64);
const FUS_SHA = 'b'.repeat(64);

function sampleRecords() {
  const base = {
    schemaVersion: 1,
    experimentId: 'exp-export-1',
    experimentConfigSha256: CFG_SHA,
    mvxVersion: '3.1.0',
    mvxBaseCommit: 'e4ee18b8f3f1bd34ef7744015d8c58b5fb930a1d',
    timestampUtc: '2026-11-25T10:00:00.000Z',
    environment: { nodeVersion: 'v25.1.0' }
  };
  return [
    {
      ...base,
      runId: 'exp-export-1:S1:M1:W1',
      sampleId: 'S1',
      extensionId: 'ext-1',
      packageSha256: PKG_1,
      archiveSha256: null,
      method: 'M1',
      weightProfile: 'W1',
      repeatIndex: null,
      fusionConfigVersion: null,
      fusionConfigSha256: null,
      durationMs: 12.5,
      status: 'completed',
      verdict: null,
      riskScore: 25,
      failure: null,
      artifact: { path: 'artifacts/S1/m1_w1.json', sha256: CFG_SHA }
    },
    {
      ...base,
      runId: 'exp-export-1:S1:M1:W2',
      sampleId: 'S1',
      extensionId: 'ext-1',
      packageSha256: PKG_1,
      archiveSha256: null,
      method: 'M1',
      weightProfile: 'W2',
      repeatIndex: null,
      fusionConfigVersion: null,
      fusionConfigSha256: null,
      durationMs: 12.5,
      status: 'completed',
      verdict: null,
      riskScore: 35,
      failure: null,
      artifact: { path: 'artifacts/S1/m1_w2.json', sha256: CFG_SHA }
    },
    {
      ...base,
      runId: 'exp-export-1:S1:M3:r1',
      sampleId: 'S1',
      extensionId: 'ext-1',
      packageSha256: PKG_1,
      archiveSha256: null,
      method: 'M3',
      weightProfile: null,
      repeatIndex: 1,
      fusionConfigVersion: null,
      fusionConfigSha256: null,
      durationMs: 8000,
      status: 'completed',
      verdict: 'confirmed_attack',
      riskScore: 100,
      failure: null,
      artifact: { path: 'artifacts/S1/m3_r1.json', sha256: CFG_SHA }
    },
    {
      ...base,
      runId: 'exp-export-1:S1:M3:r2',
      sampleId: 'S1',
      extensionId: 'ext-1',
      packageSha256: PKG_1,
      archiveSha256: null,
      method: 'M3',
      weightProfile: null,
      repeatIndex: 2,
      fusionConfigVersion: null,
      fusionConfigSha256: null,
      durationMs: 8100,
      status: 'inconclusive',
      verdict: 'inconclusive',
      riskScore: null,
      failure: { code: 'LAB_INCONCLUSIVE', message: 'Error, "quoted"\nTiếng Việt 🔒' },
      artifact: { path: 'artifacts/S1/m3_r2.json', sha256: CFG_SHA }
    },
    {
      ...base,
      runId: 'exp-export-1:S1:M4:W1',
      sampleId: 'S1',
      extensionId: 'ext-1',
      packageSha256: PKG_1,
      archiveSha256: null,
      method: 'M4',
      weightProfile: 'W1',
      repeatIndex: null,
      fusionConfigVersion: '2026.1-test',
      fusionConfigSha256: FUS_SHA,
      durationMs: 2.1,
      status: 'completed',
      verdict: 'confirmed_attack',
      riskScore: 85,
      failure: null,
      artifact: { path: 'artifacts/S1/m4_w1.json', sha256: CFG_SHA }
    },
    {
      ...base,
      runId: 'exp-export-1:S2:M2:W1',
      sampleId: 'S2',
      extensionId: 'ext-2',
      packageSha256: PKG_2,
      archiveSha256: null,
      method: 'M2',
      weightProfile: 'W1',
      repeatIndex: null,
      fusionConfigVersion: null,
      fusionConfigSha256: null,
      durationMs: 45,
      status: 'failed',
      verdict: null,
      riskScore: null,
      failure: { code: 'SCAN_LIMIT', message: 'File exceeds limit' },
      artifact: null
    }
  ];
}

test('Exporters produce RFC4180 CSV with Unicode/quotes/commas/newlines, deterministic ordering, and preserve failed/inconclusive records', () => {
  const records = sampleRecords();
  // Shuffled order must yield byte-identical deterministic CSV output
  const logA = exportExecutionLog(records);
  const logB = exportExecutionLog([...records].reverse());
  assert.equal(logA.csv, logB.csv);
  assert.equal(logA.jsonl, logB.jsonl);
  assert.equal(logA.json.schemaVersion, EXPORTER_SCHEMA_VERSION);
  assert.equal(logA.json.labelBlind, true);

  const parsedLog = parseCsv(logA.csv);
  assert.equal(parsedLog.length, 6);
  const incRow = parsedLog.find((row) => row.run_id === 'exp-export-1:S1:M3:r2');
  assert.equal(incRow.failure_message, 'Error, "quoted"\nTiếng Việt 🔒');
  assert.equal(incRow.risk_score, '');

  // Explicit nullToken handling
  const logWithNull = exportExecutionLog(records, { nullToken: 'NULL' });
  const parsedNull = parseCsv(logWithNull.csv);
  assert.equal(parsedNull.find((row) => row.run_id === 'exp-export-1:S1:M3:r2').risk_score, 'NULL');

  // Failed & inconclusive table retains both S1:M3:r2 (inconclusive) and S2:M2:W1 (failed)
  const failTable = exportFailureAndInconclusiveTable(records);
  const parsedFail = parseCsv(failTable.csv);
  assert.equal(parsedFail.length, 2);
  assert.deepEqual(parsedFail.map((row) => row.status).sort(), ['failed', 'inconclusive']);

  // Per-extension table joins primary M3 (r1) only and preserves W1/W2 separately
  const perExt = exportPerExtensionTable(records);
  const parsedPerExt = parseCsv(perExt.csv);
  assert.equal(parsedPerExt.length, 3); // S1:W1, S1:W2, S2:W1
  const s1W1 = parsedPerExt.find((r) => r.sample_id === 'S1' && r.weight_profile === 'W1');
  assert.equal(s1W1.m1_score, '25');
  assert.equal(s1W1.m3_verdict, 'confirmed_attack');
  assert.equal(s1W1.m4_score, '85');
  assert.equal(s1W1.fusion_config_sha256, FUS_SHA);

  // Weight comparison table preserves W1..W5 columns
  const weightComp = exportWeightProfileComparison(records);
  const parsedWeights = parseCsv(weightComp.csv);
  const s1M1 = parsedWeights.find((r) => r.sample_id === 'S1' && r.method === 'M1');
  assert.equal(s1M1.W1_score, '25');
  assert.equal(s1M1.W2_score, '35');
  assert.equal(s1M1.W3_score, '');

  // Method summary excludes repeated M3 (r2) from primary counts
  const methodSum = exportMethodSummaries(records);
  const m3Row = methodSum.json.rows.find((r) => r.method === 'M3');
  assert.equal(m3Row.total_records, 1);
  assert.equal(m3Row.completed, 1);
});

test('Label-blind exporters strictly reject Ground Truth leakage and exportExperimentBundle separates raw vs tables with SHA-256 manifest', async (t) => {
  const polluted = [{ ...sampleRecords()[0], groundTruth: 'Malicious' }];
  assert.throws(
    () => exportExecutionLog(polluted),
    (err) => err instanceof MvxError && err.code === 'GROUND_TRUTH_FORBIDDEN'
  );

  const stab = summarizeRepeatedDynamicRuns([
    { runId: 'r1', sampleId: 'S1', extensionId: 'ext-1', packageSha256: PKG_1, configSha256: CFG_SHA, status: 'completed', verdict: 'confirmed_attack', riskScore: 100, durationMs: 8000 },
    { runId: 'r2', sampleId: 'S1', extensionId: 'ext-1', packageSha256: PKG_1, configSha256: CFG_SHA, status: 'inconclusive', verdict: 'inconclusive', riskScore: null, durationMs: 8100 }
  ]);
  const stabExport = exportStabilitySummaries([stab]);
  assert.equal(parseCsv(stabExport.csv)[0].mean_score_completed, '100');

  const outDir = await mkdtemp(path.join(os.tmpdir(), 'mvx-phase5-export-'));
  t.after(() => rm(outDir, { recursive: true, force: true }));
  const bundle = await exportExperimentBundle({
    manifest: { experimentId: 'exp-export-1', experimentConfigSha256: CFG_SHA },
    records: sampleRecords(),
    stabilitySummaries: [stab]
  }, outDir);

  assert.equal(bundle.manifest.labelBlind, true);
  assert.match(bundle.manifestSha256, /^[a-f0-9]{64}$/);
  assert.ok(bundle.manifest.files['raw/execution_log.csv']);
  assert.ok(bundle.manifest.files['tables/per_extension_results.csv']);
  assert.ok(bundle.manifest.files['tables/stability_summary.csv']);
  const manifestText = await readFile(path.join(outDir, 'export_manifest.json'), 'utf8');
  assert.equal(JSON.parse(manifestText).experimentId, 'exp-export-1');
});
