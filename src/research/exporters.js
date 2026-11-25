import { createHash } from 'node:crypto';
import { mkdir, rename, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { stringifyCsv } from '../csv.js';
import { MvxError } from '../errors.js';
import { assertOptionsObject } from '../options.js';
import { VERSION } from '../version.js';

export const EXPORTER_SCHEMA_VERSION = 1;
export const EXPORTER_PROFILE = 'mvx-research-export-v1';

const FORBIDDEN_GROUND_TRUTH_KEYS = new Set([
  'groundTruth',
  'ground_truth',
  'groundTruthLabel',
  'ground_truth_label',
  'finalDecision',
  'final_decision',
  'label',
  'labels',
  'reviewer1Decision',
  'reviewer2Decision'
]);

const EXECUTION_LOG_HEADERS = Object.freeze([
  'experiment_id',
  'run_id',
  'sample_id',
  'extension_id',
  'package_sha256',
  'archive_sha256',
  'method',
  'weight_profile',
  'repeat_index',
  'fusion_config_version',
  'fusion_config_sha256',
  'experiment_config_sha256',
  'mvx_version',
  'mvx_base_commit',
  'timestamp_utc',
  'duration_ms',
  'status',
  'verdict',
  'risk_score',
  'failure_code',
  'failure_message',
  'artifact_path',
  'artifact_sha256'
]);

const FAILURE_INCONCLUSIVE_HEADERS = Object.freeze([
  'experiment_id',
  'run_id',
  'sample_id',
  'extension_id',
  'package_sha256',
  'method',
  'weight_profile',
  'repeat_index',
  'status',
  'verdict',
  'failure_code',
  'failure_message',
  'timestamp_utc',
  'experiment_config_sha256'
]);

const PER_EXTENSION_HEADERS = Object.freeze([
  'experiment_id',
  'sample_id',
  'extension_id',
  'package_sha256',
  'weight_profile',
  'm1_status',
  'm1_score',
  'm1_duration_ms',
  'm2_status',
  'm2_score',
  'm2_duration_ms',
  'm3_status',
  'm3_verdict',
  'm3_score',
  'm3_duration_ms',
  'm4_status',
  'm4_score',
  'm4_duration_ms',
  'fusion_config_version',
  'fusion_config_sha256',
  'experiment_config_sha256'
]);

const WEIGHT_COMPARISON_HEADERS = Object.freeze([
  'experiment_id',
  'sample_id',
  'extension_id',
  'package_sha256',
  'method',
  'W1_score',
  'W2_score',
  'W3_score',
  'W4_score',
  'W5_score',
  'W1_status',
  'W2_status',
  'W3_status',
  'W4_status',
  'W5_status',
  'experiment_config_sha256'
]);

const METHOD_SUMMARY_HEADERS = Object.freeze([
  'experiment_id',
  'method',
  'weight_profile',
  'total_records',
  'completed',
  'completed_with_static_fallback',
  'inconclusive',
  'failed',
  'skipped',
  'numeric_score_count',
  'mean_score',
  'min_score',
  'max_score',
  'mean_duration_ms',
  'median_duration_ms',
  'total_duration_ms',
  'experiment_config_sha256'
]);

const STABILITY_EXPORT_HEADERS = Object.freeze([
  'sample_id',
  'extension_id',
  'package_sha256',
  'config_sha256',
  'independent_sample_count',
  'requested_runs',
  'executed_runs',
  'completed_runs',
  'inconclusive_runs',
  'failed_runs',
  'containment_violations',
  'completion_rate',
  'inconclusive_rate',
  'failure_rate',
  'mean_score_completed',
  'population_stddev_completed',
  'min_score_completed',
  'max_score_completed',
  'exact_agreement_all_runs',
  'majority_verdict',
  'majority_agreement_rate',
  'pairwise_agreement_rate',
  'verdict_flip_count',
  'mean_duration_ms'
]);

const EVALUATION_METRICS_HEADERS = Object.freeze([
  'method',
  'weight_profile',
  'threshold',
  'eligible_samples',
  'evaluated_samples',
  'excluded_non_numeric',
  'tp',
  'fp',
  'tn',
  'fn',
  'accuracy',
  'balanced_accuracy',
  'precision',
  'recall',
  'specificity',
  'f1',
  'fpr',
  'fnr',
  'mcc',
  'roc_auc',
  'pr_auc',
  'mean_duration_ms',
  'median_duration_ms',
  'ground_truth_sha256',
  'experiment_manifest_sha256',
  'evaluation_config_sha256'
]);

const STATISTICAL_COMPARISON_HEADERS = Object.freeze([
  'weight_profile',
  'comparison',
  'method_a',
  'method_b',
  'paired_samples',
  'both_correct',
  'both_wrong',
  'a_correct_b_wrong',
  'a_wrong_b_correct',
  'discordant_pairs',
  'exact_mcnemar_p_value',
  'holm_adjusted_p_value',
  'significant_at_alpha',
  'underpowered',
  'note'
]);

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function roundNum(value) {
  return Math.round(value * 1_000_000) / 1_000_000;
}

function canonicalStringify(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalStringify).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalStringify(value[key])}`).join(',')}}`;
}

function assertLabelBlind(value, label, seen = new Set()) {
  if (!value || typeof value !== 'object' || seen.has(value)) return;
  seen.add(value);
  if (Array.isArray(value)) {
    for (const item of value) assertLabelBlind(item, label, seen);
    return;
  }
  for (const key of Object.getOwnPropertyNames(value)) {
    if (FORBIDDEN_GROUND_TRUTH_KEYS.has(key)) {
      throw new MvxError(`Ground Truth field '${key}' cannot enter label-blind export (${label})`, {
        code: 'GROUND_TRUTH_FORBIDDEN'
      });
    }
    assertLabelBlind(value[key], label, seen);
  }
}

function cellValue(value, nullToken) {
  if (value === null || value === undefined) return nullToken;
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  return value;
}

function normalizeNullToken(options = {}) {
  assertOptionsObject(options, 'Export');
  const nullToken = options.nullToken ?? '';
  if (typeof nullToken !== 'string') {
    throw new MvxError('nullToken must be a string', { code: 'INVALID_ARGUMENT' });
  }
  return nullToken;
}

function sortRecordsDeterministically(records) {
  return [...records].sort((left, right) =>
    String(left.sampleId ?? '').localeCompare(String(right.sampleId ?? ''))
    || String(left.method ?? '').localeCompare(String(right.method ?? ''))
    || String(left.weightProfile ?? '').localeCompare(String(right.weightProfile ?? ''))
    || ((left.repeatIndex ?? 0) - (right.repeatIndex ?? 0))
    || String(left.runId ?? '').localeCompare(String(right.runId ?? ''))
  );
}

function median(values) {
  if (values.length === 0) return null;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 1
    ? roundNum(sorted[mid])
    : roundNum((sorted[mid - 1] + sorted[mid]) / 2);
}

async function atomicWriteUtf8(filePath, text) {
  await mkdir(path.dirname(filePath), { recursive: true });
  const temp = `${filePath}.tmp-${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2, 10)}`;
  await writeFile(temp, text, { encoding: 'utf8', mode: 0o600 });
  await rename(temp, filePath);
  return {
    path: filePath,
    bytes: Buffer.byteLength(text, 'utf8'),
    sha256: sha256(text)
  };
}

export function exportExecutionLog(records, options = {}) {
  if (!Array.isArray(records)) {
    throw new MvxError('records must be an array', { code: 'INVALID_ARGUMENT' });
  }
  assertLabelBlind(records, 'execution_log');
  const nullToken = normalizeNullToken(options);
  const sorted = sortRecordsDeterministically(records);
  const rows = sorted.map((record) => ({
    experiment_id: cellValue(record.experimentId, nullToken),
    run_id: cellValue(record.runId, nullToken),
    sample_id: cellValue(record.sampleId, nullToken),
    extension_id: cellValue(record.extensionId, nullToken),
    package_sha256: cellValue(record.packageSha256, nullToken),
    archive_sha256: cellValue(record.archiveSha256, nullToken),
    method: cellValue(record.method, nullToken),
    weight_profile: cellValue(record.weightProfile, nullToken),
    repeat_index: cellValue(record.repeatIndex, nullToken),
    fusion_config_version: cellValue(record.fusionConfigVersion, nullToken),
    fusion_config_sha256: cellValue(record.fusionConfigSha256, nullToken),
    experiment_config_sha256: cellValue(record.experimentConfigSha256, nullToken),
    mvx_version: cellValue(record.mvxVersion, nullToken),
    mvx_base_commit: cellValue(record.mvxBaseCommit, nullToken),
    timestamp_utc: cellValue(record.timestampUtc, nullToken),
    duration_ms: cellValue(record.durationMs, nullToken),
    status: cellValue(record.status, nullToken),
    verdict: cellValue(record.verdict, nullToken),
    risk_score: cellValue(record.riskScore, nullToken),
    failure_code: cellValue(record.failure?.code, nullToken),
    failure_message: cellValue(record.failure?.message, nullToken),
    artifact_path: cellValue(record.artifact?.path, nullToken),
    artifact_sha256: cellValue(record.artifact?.sha256, nullToken)
  }));
  const csv = stringifyCsv([...EXECUTION_LOG_HEADERS], rows);
  const jsonl = `${sorted.map((record) => canonicalStringify(record)).join('\n')}${sorted.length > 0 ? '\n' : ''}`;
  const json = {
    schemaVersion: EXPORTER_SCHEMA_VERSION,
    profile: EXPORTER_PROFILE,
    table: 'execution_log',
    labelBlind: true,
    nullRepresentation: nullToken,
    headers: [...EXECUTION_LOG_HEADERS],
    rowCount: rows.length,
    rows: sorted
  };
  return { csv, jsonl, json };
}

export function exportFailureAndInconclusiveTable(records, options = {}) {
  if (!Array.isArray(records)) {
    throw new MvxError('records must be an array', { code: 'INVALID_ARGUMENT' });
  }
  assertLabelBlind(records, 'failure_and_inconclusive_cases');
  const nullToken = normalizeNullToken(options);
  const filtered = sortRecordsDeterministically(records).filter((record) =>
    record.status === 'failed'
    || record.status === 'inconclusive'
    || record.status === 'skipped'
    || record.status === 'completed_with_static_fallback'
  );
  const rows = filtered.map((record) => ({
    experiment_id: cellValue(record.experimentId, nullToken),
    run_id: cellValue(record.runId, nullToken),
    sample_id: cellValue(record.sampleId, nullToken),
    extension_id: cellValue(record.extensionId, nullToken),
    package_sha256: cellValue(record.packageSha256, nullToken),
    method: cellValue(record.method, nullToken),
    weight_profile: cellValue(record.weightProfile, nullToken),
    repeat_index: cellValue(record.repeatIndex, nullToken),
    status: cellValue(record.status, nullToken),
    verdict: cellValue(record.verdict, nullToken),
    failure_code: cellValue(record.failure?.code, nullToken),
    failure_message: cellValue(record.failure?.message, nullToken),
    timestamp_utc: cellValue(record.timestampUtc, nullToken),
    experiment_config_sha256: cellValue(record.experimentConfigSha256, nullToken)
  }));
  return {
    csv: stringifyCsv([...FAILURE_INCONCLUSIVE_HEADERS], rows),
    json: {
      schemaVersion: EXPORTER_SCHEMA_VERSION,
      profile: EXPORTER_PROFILE,
      table: 'failure_and_inconclusive_cases',
      labelBlind: true,
      nullRepresentation: nullToken,
      headers: [...FAILURE_INCONCLUSIVE_HEADERS],
      rowCount: rows.length,
      rows
    }
  };
}

export function exportPerExtensionTable(records, options = {}) {
  if (!Array.isArray(records)) {
    throw new MvxError('records must be an array', { code: 'INVALID_ARGUMENT' });
  }
  assertLabelBlind(records, 'per_extension_results');
  const nullToken = normalizeNullToken(options);
  const sorted = sortRecordsDeterministically(records);

  // Index primary M3 (repeatIndex === 1 only so repeated runs never duplicate extension rows)
  const primaryM3BySample = new Map();
  const sampleWeights = new Map();
  const byKey = new Map();

  for (const record of sorted) {
    if (record.method === 'M3') {
      if ((record.repeatIndex ?? 1) === 1 && !primaryM3BySample.has(record.sampleId)) {
        primaryM3BySample.set(record.sampleId, record);
      }
      if (!sampleWeights.has(record.sampleId)) sampleWeights.set(record.sampleId, new Set());
      continue;
    }
    const wp = record.weightProfile ?? 'W1';
    if (!sampleWeights.has(record.sampleId)) sampleWeights.set(record.sampleId, new Set());
    sampleWeights.get(record.sampleId).add(wp);
    byKey.set(`${record.sampleId}\0${wp}\0${record.method}`, record);
  }

  const sampleIds = [...sampleWeights.keys()].sort();
  const structuredRows = [];
  const csvRows = [];

  for (const sampleId of sampleIds) {
    const weights = [...sampleWeights.get(sampleId)].sort();
    const effectiveWeights = weights.length > 0 ? weights : [null];
    const m3 = primaryM3BySample.get(sampleId) ?? null;

    for (const wp of effectiveWeights) {
      const m1 = wp ? (byKey.get(`${sampleId}\0${wp}\0M1`) ?? null) : null;
      const m2 = wp ? (byKey.get(`${sampleId}\0${wp}\0M2`) ?? null) : null;
      const m4 = wp ? (byKey.get(`${sampleId}\0${wp}\0M4`) ?? null) : null;
      const anchor = m4 ?? m1 ?? m2 ?? m3;
      const rowObj = {
        experiment_id: anchor?.experimentId ?? null,
        sample_id: sampleId,
        extension_id: anchor?.extensionId ?? null,
        package_sha256: anchor?.packageSha256 ?? null,
        weight_profile: wp,
        m1_status: m1?.status ?? null,
        m1_score: m1?.riskScore ?? null,
        m1_duration_ms: m1?.durationMs ?? null,
        m2_status: m2?.status ?? null,
        m2_score: m2?.riskScore ?? null,
        m2_duration_ms: m2?.durationMs ?? null,
        m3_status: m3?.status ?? null,
        m3_verdict: m3?.verdict ?? null,
        m3_score: m3?.riskScore ?? null,
        m3_duration_ms: m3?.durationMs ?? null,
        m4_status: m4?.status ?? null,
        m4_score: m4?.riskScore ?? null,
        m4_duration_ms: m4?.durationMs ?? null,
        fusion_config_version: m4?.fusionConfigVersion ?? null,
        fusion_config_sha256: m4?.fusionConfigSha256 ?? null,
        experiment_config_sha256: anchor?.experimentConfigSha256 ?? null
      };
      structuredRows.push(rowObj);
      csvRows.push(Object.fromEntries(
        PER_EXTENSION_HEADERS.map((header) => [header, cellValue(rowObj[header], nullToken)])
      ));
    }
  }

  return {
    csv: stringifyCsv([...PER_EXTENSION_HEADERS], csvRows),
    json: {
      schemaVersion: EXPORTER_SCHEMA_VERSION,
      profile: EXPORTER_PROFILE,
      table: 'per_extension_results',
      labelBlind: true,
      nullRepresentation: nullToken,
      headers: [...PER_EXTENSION_HEADERS],
      rowCount: structuredRows.length,
      rows: structuredRows
    }
  };
}

export function exportWeightProfileComparison(records, options = {}) {
  if (!Array.isArray(records)) {
    throw new MvxError('records must be an array', { code: 'INVALID_ARGUMENT' });
  }
  assertLabelBlind(records, 'weight_profile_comparison');
  const nullToken = normalizeNullToken(options);
  const sorted = sortRecordsDeterministically(records).filter((record) => record.method !== 'M3');

  const grouped = new Map();
  for (const record of sorted) {
    const key = `${record.sampleId}\0${record.method}`;
    if (!grouped.has(key)) {
      grouped.set(key, {
        experiment_id: record.experimentId,
        sample_id: record.sampleId,
        extension_id: record.extensionId,
        package_sha256: record.packageSha256,
        method: record.method,
        experiment_config_sha256: record.experimentConfigSha256,
        profiles: {}
      });
    }
    const entry = grouped.get(key);
    if (record.weightProfile) {
      entry.profiles[record.weightProfile] = {
        score: record.riskScore,
        status: record.status
      };
    }
  }

  const structuredRows = [];
  const csvRows = [];
  for (const key of [...grouped.keys()].sort()) {
    const item = grouped.get(key);
    const rowObj = {
      experiment_id: item.experiment_id,
      sample_id: item.sample_id,
      extension_id: item.extension_id,
      package_sha256: item.package_sha256,
      method: item.method,
      W1_score: item.profiles.W1?.score ?? null,
      W2_score: item.profiles.W2?.score ?? null,
      W3_score: item.profiles.W3?.score ?? null,
      W4_score: item.profiles.W4?.score ?? null,
      W5_score: item.profiles.W5?.score ?? null,
      W1_status: item.profiles.W1?.status ?? null,
      W2_status: item.profiles.W2?.status ?? null,
      W3_status: item.profiles.W3?.status ?? null,
      W4_status: item.profiles.W4?.status ?? null,
      W5_status: item.profiles.W5?.status ?? null,
      experiment_config_sha256: item.experiment_config_sha256
    };
    structuredRows.push(rowObj);
    csvRows.push(Object.fromEntries(
      WEIGHT_COMPARISON_HEADERS.map((header) => [header, cellValue(rowObj[header], nullToken)])
    ));
  }

  return {
    csv: stringifyCsv([...WEIGHT_COMPARISON_HEADERS], csvRows),
    json: {
      schemaVersion: EXPORTER_SCHEMA_VERSION,
      profile: EXPORTER_PROFILE,
      table: 'weight_profile_comparison',
      labelBlind: true,
      nullRepresentation: nullToken,
      headers: [...WEIGHT_COMPARISON_HEADERS],
      rowCount: structuredRows.length,
      rows: structuredRows
    }
  };
}

export function exportMethodSummaries(records, options = {}) {
  if (!Array.isArray(records)) {
    throw new MvxError('records must be an array', { code: 'INVALID_ARGUMENT' });
  }
  assertLabelBlind(records, 'method_summary');
  const nullToken = normalizeNullToken(options);
  const sorted = sortRecordsDeterministically(records);

  const buckets = new Map();
  for (const record of sorted) {
    // For M3, aggregate primary runs only in dataset-level method summary to avoid double-counting repeats
    if (record.method === 'M3' && (record.repeatIndex ?? 1) > 1) continue;
    const key = `${record.method}\0${record.weightProfile ?? ''}`;
    if (!buckets.has(key)) buckets.set(key, []);
    buckets.get(key).push(record);
  }

  const structuredRows = [];
  const csvRows = [];
  for (const key of [...buckets.keys()].sort()) {
    const items = buckets.get(key);
    const first = items[0];
    const counts = {
      completed: 0,
      completed_with_static_fallback: 0,
      inconclusive: 0,
      failed: 0,
      skipped: 0
    };
    const scores = [];
    const durations = [];
    for (const item of items) {
      counts[item.status] = (counts[item.status] ?? 0) + 1;
      if (typeof item.riskScore === 'number' && Number.isFinite(item.riskScore)) {
        scores.push(item.riskScore);
      }
      if (typeof item.durationMs === 'number' && Number.isFinite(item.durationMs)) {
        durations.push(item.durationMs);
      }
    }
    const rowObj = {
      experiment_id: first.experimentId,
      method: first.method,
      weight_profile: first.weightProfile ?? null,
      total_records: items.length,
      completed: counts.completed,
      completed_with_static_fallback: counts.completed_with_static_fallback,
      inconclusive: counts.inconclusive,
      failed: counts.failed,
      skipped: counts.skipped,
      numeric_score_count: scores.length,
      mean_score: scores.length > 0 ? roundNum(scores.reduce((a, b) => a + b, 0) / scores.length) : null,
      min_score: scores.length > 0 ? Math.min(...scores) : null,
      max_score: scores.length > 0 ? Math.max(...scores) : null,
      mean_duration_ms: durations.length > 0 ? roundNum(durations.reduce((a, b) => a + b, 0) / durations.length) : null,
      median_duration_ms: median(durations),
      total_duration_ms: durations.length > 0 ? roundNum(durations.reduce((a, b) => a + b, 0)) : 0,
      experiment_config_sha256: first.experimentConfigSha256
    };
    structuredRows.push(rowObj);
    csvRows.push(Object.fromEntries(
      METHOD_SUMMARY_HEADERS.map((header) => [header, cellValue(rowObj[header], nullToken)])
    ));
  }

  return {
    csv: stringifyCsv([...METHOD_SUMMARY_HEADERS], csvRows),
    json: {
      schemaVersion: EXPORTER_SCHEMA_VERSION,
      profile: EXPORTER_PROFILE,
      table: 'method_summary',
      labelBlind: true,
      nullRepresentation: nullToken,
      headers: [...METHOD_SUMMARY_HEADERS],
      rowCount: structuredRows.length,
      rows: structuredRows
    }
  };
}

export function exportStabilitySummaries(sampleSummaries, multiSampleSummary = null, options = {}) {
  if (!Array.isArray(sampleSummaries)) {
    throw new MvxError('sampleSummaries must be an array', { code: 'INVALID_ARGUMENT' });
  }
  assertLabelBlind(sampleSummaries, 'stability_summary');
  const nullToken = normalizeNullToken(options);
  const sorted = [...sampleSummaries].sort((a, b) =>
    String(a.sampleId ?? '').localeCompare(String(b.sampleId ?? ''))
  );
  const structuredRows = [];
  const csvRows = [];
  for (const summary of sorted) {
    const rowObj = {
      sample_id: summary.sampleId,
      extension_id: summary.extensionId,
      package_sha256: summary.packageSha256,
      config_sha256: summary.configSha256,
      independent_sample_count: summary.independentDatasetSampleCount,
      requested_runs: summary.counts.requestedRuns,
      executed_runs: summary.counts.executedRuns,
      completed_runs: summary.counts.completedRuns,
      inconclusive_runs: summary.counts.inconclusiveRuns,
      failed_runs: summary.counts.failedRuns,
      containment_violations: summary.counts.containmentViolations,
      completion_rate: summary.rates.completionRate,
      inconclusive_rate: summary.rates.inconclusiveRate,
      failure_rate: summary.rates.failureRate,
      mean_score_completed: summary.riskScoreStats.mean,
      population_stddev_completed: summary.riskScoreStats.populationStdDev,
      min_score_completed: summary.riskScoreStats.min,
      max_score_completed: summary.riskScoreStats.max,
      exact_agreement_all_runs: summary.verdictConsistencyAllRuns.exactAgreement,
      majority_verdict: summary.verdictConsistencyAllRuns.majorityVerdict,
      majority_agreement_rate: summary.verdictConsistencyAllRuns.majorityAgreementRate,
      pairwise_agreement_rate: summary.verdictConsistencyAllRuns.pairwiseAgreementRate,
      verdict_flip_count: summary.verdictConsistencyAllRuns.verdictFlipCount,
      mean_duration_ms: summary.durationStats.meanDurationMs
    };
    structuredRows.push(rowObj);
    csvRows.push(Object.fromEntries(
      STABILITY_EXPORT_HEADERS.map((header) => [header, cellValue(rowObj[header], nullToken)])
    ));
  }

  return {
    csv: stringifyCsv([...STABILITY_EXPORT_HEADERS], csvRows),
    json: {
      schemaVersion: EXPORTER_SCHEMA_VERSION,
      profile: EXPORTER_PROFILE,
      table: 'stability_summary',
      labelBlind: true,
      nullRepresentation: nullToken,
      overall: multiSampleSummary,
      headers: [...STABILITY_EXPORT_HEADERS],
      rowCount: structuredRows.length,
      rows: structuredRows
    }
  };
}

export async function exportExperimentBundle(experimentData, outputDir, options = {}) {
  assertOptionsObject(experimentData, 'Experiment export data');
  assertLabelBlind(experimentData, 'experiment_bundle');
  if (typeof outputDir !== 'string' || outputDir.length === 0) {
    throw new MvxError('outputDir must be a non-empty string', { code: 'INVALID_ARGUMENT' });
  }
  const records = experimentData.records;
  if (!Array.isArray(records)) {
    throw new MvxError('experimentData.records must be an array', { code: 'INVALID_ARGUMENT' });
  }

  const root = path.resolve(outputDir);
  const rawDir = path.join(root, 'raw');
  const tablesDir = path.join(root, 'tables');
  await mkdir(rawDir, { recursive: true, mode: 0o700 });
  await mkdir(tablesDir, { recursive: true, mode: 0o700 });

  const execLog = exportExecutionLog(records, options);
  const failures = exportFailureAndInconclusiveTable(records, options);
  const perExt = exportPerExtensionTable(records, options);
  const weightComp = exportWeightProfileComparison(records, options);
  const methodSum = exportMethodSummaries(records, options);

  const files = {};
  files['raw/runs_export.jsonl'] = await atomicWriteUtf8(path.join(rawDir, 'runs_export.jsonl'), execLog.jsonl);
  files['raw/execution_log.csv'] = await atomicWriteUtf8(path.join(rawDir, 'execution_log.csv'), execLog.csv);
  files['raw/failure_and_inconclusive_cases.csv'] = await atomicWriteUtf8(
    path.join(rawDir, 'failure_and_inconclusive_cases.csv'),
    failures.csv
  );
  files['tables/per_extension_results.csv'] = await atomicWriteUtf8(
    path.join(tablesDir, 'per_extension_results.csv'),
    perExt.csv
  );
  files['tables/per_extension_results.json'] = await atomicWriteUtf8(
    path.join(tablesDir, 'per_extension_results.json'),
    `${JSON.stringify(perExt.json, null, 2)}\n`
  );
  files['tables/weight_profile_comparison.csv'] = await atomicWriteUtf8(
    path.join(tablesDir, 'weight_profile_comparison.csv'),
    weightComp.csv
  );
  files['tables/weight_profile_comparison.json'] = await atomicWriteUtf8(
    path.join(tablesDir, 'weight_profile_comparison.json'),
    `${JSON.stringify(weightComp.json, null, 2)}\n`
  );
  files['tables/method_summary.csv'] = await atomicWriteUtf8(
    path.join(tablesDir, 'method_summary.csv'),
    methodSum.csv
  );
  files['tables/method_summary.json'] = await atomicWriteUtf8(
    path.join(tablesDir, 'method_summary.json'),
    `${JSON.stringify(methodSum.json, null, 2)}\n`
  );

  if (Array.isArray(experimentData.stabilitySummaries) && experimentData.stabilitySummaries.length > 0) {
    const stab = exportStabilitySummaries(
      experimentData.stabilitySummaries,
      experimentData.summary?.stability ?? null,
      options
    );
    files['tables/stability_summary.csv'] = await atomicWriteUtf8(
      path.join(tablesDir, 'stability_summary.csv'),
      stab.csv
    );
    files['tables/stability_summary.json'] = await atomicWriteUtf8(
      path.join(tablesDir, 'stability_summary.json'),
      `${JSON.stringify(stab.json, null, 2)}\n`
    );
  }

  const manifest = {
    schemaVersion: EXPORTER_SCHEMA_VERSION,
    profile: EXPORTER_PROFILE,
    labelBlind: true,
    toolVersion: VERSION,
    exportedAtUtc: new Date().toISOString(),
    experimentId: experimentData.manifest?.experimentId ?? experimentData.summary?.experimentId ?? null,
    experimentConfigSha256: experimentData.manifest?.experimentConfigSha256
      ?? experimentData.summary?.experimentConfigSha256 ?? null,
    files: Object.fromEntries(
      Object.entries(files).map(([rel, info]) => [rel, { bytes: info.bytes, sha256: info.sha256 }])
    )
  };
  const manifestWrite = await atomicWriteUtf8(
    path.join(root, 'export_manifest.json'),
    `${JSON.stringify(manifest, null, 2)}\n`
  );
  return {
    outputDir: root,
    manifest,
    manifestSha256: manifestWrite.sha256,
    files
  };
}

export async function exportEvaluationTables(evaluationReport, outputDir, options = {}) {
  assertOptionsObject(evaluationReport, 'Evaluation report');
  if (typeof outputDir !== 'string' || outputDir.length === 0) {
    throw new MvxError('outputDir must be a non-empty string', { code: 'INVALID_ARGUMENT' });
  }
  const nullToken = normalizeNullToken(options);
  const root = path.resolve(outputDir);
  await mkdir(root, { recursive: true, mode: 0o700 });

  const metricRows = [];
  for (const entry of evaluationReport.methodEvaluations ?? []) {
    const b = entry.binaryMetrics;
    const r = entry.rankingMetrics;
    metricRows.push({
      method: cellValue(entry.method, nullToken),
      weight_profile: cellValue(entry.weightProfile, nullToken),
      threshold: cellValue(entry.threshold, nullToken),
      eligible_samples: cellValue(evaluationReport.cohortSummary?.eligibleExtensionLevelCount, nullToken),
      evaluated_samples: cellValue(b.confusionMatrix.total, nullToken),
      excluded_non_numeric: cellValue(entry.excludedNonNumericCount, nullToken),
      tp: cellValue(b.confusionMatrix.tp, nullToken),
      fp: cellValue(b.confusionMatrix.fp, nullToken),
      tn: cellValue(b.confusionMatrix.tn, nullToken),
      fn: cellValue(b.confusionMatrix.fn, nullToken),
      accuracy: cellValue(b.accuracy.value, nullToken),
      balanced_accuracy: cellValue(b.balancedAccuracy.value, nullToken),
      precision: cellValue(b.precision.value, nullToken),
      recall: cellValue(b.recall.value, nullToken),
      specificity: cellValue(b.specificity.value, nullToken),
      f1: cellValue(b.f1.value, nullToken),
      fpr: cellValue(b.fpr.value, nullToken),
      fnr: cellValue(b.fnr.value, nullToken),
      mcc: cellValue(b.mcc.value, nullToken),
      roc_auc: cellValue(r.rocAuc.value, nullToken),
      pr_auc: cellValue(r.prAuc.value, nullToken),
      mean_duration_ms: cellValue(entry.runtimeStats.meanDurationMs, nullToken),
      median_duration_ms: cellValue(entry.runtimeStats.medianDurationMs, nullToken),
      ground_truth_sha256: cellValue(evaluationReport.provenance?.groundTruthSha256, nullToken),
      experiment_manifest_sha256: cellValue(evaluationReport.provenance?.experimentManifestSha256, nullToken),
      evaluation_config_sha256: cellValue(evaluationReport.provenance?.evaluationConfigSha256, nullToken)
    });
  }

  const statRows = [];
  for (const comp of evaluationReport.statisticalComparisons ?? []) {
    statRows.push({
      weight_profile: cellValue(comp.weightProfile, nullToken),
      comparison: cellValue(comp.comparison, nullToken),
      method_a: cellValue(comp.methodA, nullToken),
      method_b: cellValue(comp.methodB, nullToken),
      paired_samples: cellValue(comp.mcnemar.pairedSamples, nullToken),
      both_correct: cellValue(comp.mcnemar.bothCorrect, nullToken),
      both_wrong: cellValue(comp.mcnemar.bothWrong, nullToken),
      a_correct_b_wrong: cellValue(comp.mcnemar.aCorrectBWrong, nullToken),
      a_wrong_b_correct: cellValue(comp.mcnemar.aWrongBCorrect, nullToken),
      discordant_pairs: cellValue(comp.mcnemar.discordantPairs, nullToken),
      exact_mcnemar_p_value: cellValue(comp.mcnemar.pValue, nullToken),
      holm_adjusted_p_value: cellValue(comp.adjustedPValue, nullToken),
      significant_at_alpha: cellValue(comp.significantAtAlpha, nullToken),
      underpowered: cellValue(comp.mcnemar.underpowered, nullToken),
      note: cellValue(comp.mcnemar.note, nullToken)
    });
  }

  const metricsCsv = stringifyCsv([...EVALUATION_METRICS_HEADERS], metricRows);
  const statsCsv = stringifyCsv([...STATISTICAL_COMPARISON_HEADERS], statRows);

  const files = {};
  files['evaluation_metrics.csv'] = await atomicWriteUtf8(path.join(root, 'evaluation_metrics.csv'), metricsCsv);
  files['statistical_comparisons.csv'] = await atomicWriteUtf8(path.join(root, 'statistical_comparisons.csv'), statsCsv);
  files['evaluation_report.json'] = await atomicWriteUtf8(
    path.join(root, 'evaluation_report.json'),
    `${JSON.stringify(evaluationReport, null, 2)}\n`
  );

  return {
    outputDir: root,
    files,
    metricsCsv,
    statsCsv
  };
}
