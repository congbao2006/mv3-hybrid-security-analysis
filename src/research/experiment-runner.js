import { createHash } from 'node:crypto';
import { appendFile, lstat, mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { unpackExtensionArchive } from '../archive.js';
import { MvxError } from '../errors.js';
import { WEIGHT_PROFILES } from '../model.js';
import { assertOptionsObject } from '../options.js';
import {
  createPrivateWorkspace,
  removePrivateWorkspace,
  resolvePrivateWorkspaceParent
} from '../private-workspace.js';
import { VERSION } from '../version.js';
import { RESEARCH_CONFIG_VERSION } from './config.js';
import { fuseHybridEvidence, validateFusionConfig } from './hybrid-fusion.js';
import {
  collectExtendedEnvironmentMetadata,
  createProgressEvent,
  normalizeStructuredFailure
} from './logging.js';
import { runM1PermissionOnly, runM2StaticOnly, runM3DynamicOnly } from './modes.js';
import {
  computeMultiSampleStabilitySummary,
  summarizeRepeatedDynamicRuns
} from './stability.js';

export const EXPERIMENT_SCHEMA_VERSION = 1;
export const EXPERIMENT_PROFILE = 'mvx-experiment-batch-v1';
export const RUN_RECORD_SCHEMA_VERSION = 1;

const EXPERIMENT_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const SAMPLE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const VALID_METHODS = new Set(['M1', 'M2', 'M3', 'M4']);
const VALID_WEIGHTS = new Set(Object.keys(WEIGHT_PROFILES));
const VALID_STATUSES = new Set([
  'completed',
  'completed_with_static_fallback',
  'inconclusive',
  'failed',
  'skipped'
]);

const FORBIDDEN_GROUND_TRUTH_KEYS = new Set([
  'groundTruth',
  'ground_truth',
  'groundTruthLabel',
  'ground_truth_label',
  'finalDecision',
  'final_decision',
  'label',
  'labels',
  'groundTruthPath',
  'ground_truth_path'
]);

const RUNNER_OPTIONS = new Set([
  'acknowledgeRisk',
  'baseCommit',
  'environment',
  'experimentId',
  'fusionConfig',
  'm2Options',
  'm3Options',
  'manifest',
  'methods',
  'onProgress',
  'outputDir',
  'requireManifestV3',
  'resume',
  'scenarioPath',
  'signal',
  'skipExternalProbes',
  'temporaryDirectory',
  'weightProfiles'
]);

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function canonicalStringify(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalStringify).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalStringify(value[key])}`).join(',')}}`;
}

function rejectGroundTruthKeys(object, label) {
  if (!object || typeof object !== 'object') return;
  for (const key of Object.getOwnPropertyNames(object)) {
    if (FORBIDDEN_GROUND_TRUTH_KEYS.has(key)) {
      throw new MvxError(`Ground Truth field '${key}' is strictly forbidden in ${label}`, {
        code: 'GROUND_TRUTH_FORBIDDEN'
      });
    }
  }
}

async function atomicWriteText(filePath, content) {
  const dir = path.dirname(filePath);
  await mkdir(dir, { recursive: true });
  const tempPath = `${filePath}.tmp-${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2, 10)}`;
  await writeFile(tempPath, content, { encoding: 'utf8', mode: 0o600 });
  await rename(tempPath, filePath);
}

async function atomicWriteJson(filePath, value) {
  const text = `${JSON.stringify(value, null, 2)}\n`;
  await atomicWriteText(filePath, text);
  return {
    path: filePath,
    bytes: Buffer.byteLength(text, 'utf8'),
    sha256: sha256(text)
  };
}

export function collectEnvironmentMetadata(overrides = {}, probeOptions = {}) {
  return collectExtendedEnvironmentMetadata(overrides, probeOptions);
}

export function validateDatasetManifest(manifest) {
  assertOptionsObject(manifest, 'Dataset manifest');
  rejectGroundTruthKeys(manifest, 'dataset manifest');
  if (manifest.schemaVersion !== 1) {
    throw new MvxError('Dataset manifest schemaVersion must equal 1', { code: 'INVALID_MANIFEST' });
  }
  if (typeof manifest.datasetVersion !== 'string' || manifest.datasetVersion.trim().length === 0) {
    throw new MvxError('Dataset manifest datasetVersion must be a non-empty string', { code: 'INVALID_MANIFEST' });
  }
  if (!Array.isArray(manifest.samples) || manifest.samples.length === 0) {
    throw new MvxError('Dataset manifest must contain a non-empty samples array', { code: 'INVALID_MANIFEST' });
  }

  const seenSampleIds = new Set();
  const normalized = [];
  for (let index = 0; index < manifest.samples.length; index += 1) {
    const sample = manifest.samples[index];
    assertOptionsObject(sample, `Dataset sample[${index}]`);
    rejectGroundTruthKeys(sample, `dataset sample[${index}]`);
    if (typeof sample.sampleId !== 'string' || !SAMPLE_ID_PATTERN.test(sample.sampleId)) {
      throw new MvxError(`Invalid sampleId at samples[${index}]`, { code: 'INVALID_MANIFEST' });
    }
    if (seenSampleIds.has(sample.sampleId)) {
      throw new MvxError(`Duplicate sampleId in dataset manifest: ${sample.sampleId}`, {
        code: 'DUPLICATE_SAMPLE_ID'
      });
    }
    seenSampleIds.add(sample.sampleId);
    if (typeof sample.extensionId !== 'string' || sample.extensionId.length === 0) {
      throw new MvxError(`Missing extensionId for sample ${sample.sampleId}`, { code: 'INVALID_MANIFEST' });
    }
    const skip = sample.skip === true;
    if (!skip && (typeof sample.artifactPath !== 'string' || sample.artifactPath.length === 0)) {
      throw new MvxError(`Missing artifactPath for sample ${sample.sampleId}`, { code: 'INVALID_MANIFEST' });
    }
    if (sample.expectedArchiveSha256 !== undefined && sample.expectedArchiveSha256 !== null
      && (typeof sample.expectedArchiveSha256 !== 'string' || !SHA256.test(sample.expectedArchiveSha256))) {
      throw new MvxError(`Invalid expectedArchiveSha256 for sample ${sample.sampleId}`, { code: 'INVALID_MANIFEST' });
    }
    if (sample.expectedPackageSha256 !== undefined && sample.expectedPackageSha256 !== null
      && (typeof sample.expectedPackageSha256 !== 'string' || !SHA256.test(sample.expectedPackageSha256))) {
      throw new MvxError(`Invalid expectedPackageSha256 for sample ${sample.sampleId}`, { code: 'INVALID_MANIFEST' });
    }
    normalized.push(Object.freeze({
      sampleId: sample.sampleId,
      extensionId: sample.extensionId,
      extensionName: typeof sample.extensionName === 'string' ? sample.extensionName : sample.sampleId,
      cohort: typeof sample.cohort === 'string' ? sample.cohort : 'unspecified',
      artifactPath: sample.artifactPath ?? null,
      expectedArchiveSha256: sample.expectedArchiveSha256 ?? null,
      expectedPackageSha256: sample.expectedPackageSha256 ?? null,
      skip,
      skipReason: typeof sample.skipReason === 'string' ? sample.skipReason : (skip ? 'manifest_marked_skip' : null)
    }));
  }

  return Object.freeze({
    schemaVersion: 1,
    datasetVersion: manifest.datasetVersion,
    samples: Object.freeze(normalized)
  });
}

export function validateRunRecord(record) {
  if (!record || typeof record !== 'object' || Array.isArray(record)) {
    throw new MvxError('Run record must be a plain object', { code: 'INVALID_RUN_RECORD' });
  }
  rejectGroundTruthKeys(record, 'run record');
  if (record.schemaVersion !== RUN_RECORD_SCHEMA_VERSION) {
    throw new MvxError(`Run record schemaVersion must equal ${RUN_RECORD_SCHEMA_VERSION}`, {
      code: 'INVALID_SCHEMA_VERSION'
    });
  }
  for (const field of ['experimentId', 'runId', 'sampleId', 'extensionId', 'method', 'status', 'timestampUtc', 'mvxVersion', 'mvxBaseCommit', 'experimentConfigSha256']) {
    if (typeof record[field] !== 'string' || record[field].length === 0) {
      throw new MvxError(`Run record is missing required field: ${field}`, { code: 'MISSING_METADATA' });
    }
  }
  if (!VALID_METHODS.has(record.method)) {
    throw new MvxError(`Invalid run record method: ${record.method}`, { code: 'INVALID_RUN_RECORD' });
  }
  if (!VALID_STATUSES.has(record.status)) {
    throw new MvxError(`Invalid run record status: ${record.status}`, { code: 'INVALID_RUN_RECORD' });
  }
  if (!SHA256.test(record.experimentConfigSha256)) {
    throw new MvxError(`Invalid experimentConfigSha256 in run ${record.runId}`, { code: 'INVALID_RUN_RECORD' });
  }
  if (record.packageSha256 !== null && !SHA256.test(record.packageSha256)) {
    throw new MvxError(`Invalid packageSha256 in run ${record.runId}`, { code: 'INVALID_RUN_RECORD' });
  }
  if (typeof record.durationMs !== 'number' || !Number.isFinite(record.durationMs) || record.durationMs < 0) {
    throw new MvxError(`Invalid durationMs in run ${record.runId}`, { code: 'INVALID_RUN_RECORD' });
  }
  if (!record.environment || typeof record.environment !== 'object') {
    throw new MvxError(`Run record ${record.runId} is missing environment metadata`, { code: 'MISSING_METADATA' });
  }
  if (record.method === 'M4') {
    if (typeof record.fusionConfigVersion !== 'string' || !SHA256.test(record.fusionConfigSha256 ?? '')) {
      throw new MvxError(`M4 run record ${record.runId} is missing fusionConfig provenance`, {
        code: 'MISSING_METADATA'
      });
    }
  }
  return record;
}

export function verifyExperimentProvenance(records, expected = {}) {
  if (!Array.isArray(records)) {
    throw new MvxError('records must be an array', { code: 'INVALID_ARGUMENT' });
  }
  const seenRunIds = new Set();
  const sampleHashes = new Map();
  let configSha = expected.experimentConfigSha256 ?? null;
  let fusionSha = expected.fusionConfigSha256 ?? null;

  for (const record of records) {
    validateRunRecord(record);
    if (seenRunIds.has(record.runId)) {
      throw new MvxError(`Duplicate runId detected: ${record.runId}`, { code: 'DUPLICATE_RUN_ID' });
    }
    seenRunIds.add(record.runId);

    if (configSha === null) configSha = record.experimentConfigSha256;
    else if (record.experimentConfigSha256 !== configSha) {
      throw new MvxError(
        `Configuration SHA mismatch on ${record.runId}: expected ${configSha}, observed ${record.experimentConfigSha256}`,
        { code: 'CONFIG_MISMATCH' }
      );
    }

    if (record.method === 'M4') {
      if (fusionSha === null) fusionSha = record.fusionConfigSha256;
      else if (record.fusionConfigSha256 !== fusionSha) {
        throw new MvxError(
          `Fusion config SHA mismatch on ${record.runId}: expected ${fusionSha}, observed ${record.fusionConfigSha256}`,
          { code: 'CONFIG_MISMATCH' }
        );
      }
    }

    if (record.packageSha256 !== null) {
      const prior = sampleHashes.get(record.sampleId);
      if (prior === undefined) sampleHashes.set(record.sampleId, record.packageSha256);
      else if (prior !== record.packageSha256) {
        throw new MvxError(
          `Package SHA mismatch for ${record.sampleId} on ${record.runId}: expected ${prior}, observed ${record.packageSha256}`,
          { code: 'PACKAGE_SHA_MISMATCH' }
        );
      }
    }
  }

  return Object.freeze({
    valid: true,
    recordCount: records.length,
    uniqueRunIds: seenRunIds.size,
    uniqueSamplesWithHash: sampleHashes.size,
    experimentConfigSha256: configSha,
    fusionConfigSha256: fusionSha
  });
}

async function isArchiveFile(artifactPath) {
  const ext = path.extname(artifactPath).toLowerCase();
  if (!['.crx', '.zip'].includes(ext)) return false;
  const stat = await lstat(path.resolve(artifactPath));
  return stat.isFile();
}

async function loadExistingRecords(jsonlPath, expectedConfigSha, expectedFusionSha) {
  let content;
  try {
    content = await readFile(jsonlPath, 'utf8');
  } catch (error) {
    if (error?.code === 'ENOENT') return [];
    throw error;
  }
  const lines = content.split(/\r?\n/).filter((line) => line.length > 0);
  const records = lines.map((line, index) => {
    try {
      return JSON.parse(line);
    } catch (error) {
      throw new MvxError(`Corrupted JSONL line ${index + 1} in ${jsonlPath}: ${error.message}`, {
        code: 'CORRUPT_RUN_LOG',
        cause: error
      });
    }
  });
  verifyExperimentProvenance(records, {
    experimentConfigSha256: expectedConfigSha,
    fusionConfigSha256: expectedFusionSha
  });
  return records;
}

export async function runExperimentBatch(options = {}) {
  assertOptionsObject(options, 'Experiment batch');
  rejectGroundTruthKeys(options, 'experiment batch options');
  const unknown = Object.getOwnPropertyNames(options).filter((key) => !RUNNER_OPTIONS.has(key)).sort();
  if (unknown.length > 0) {
    throw new MvxError(`Unknown experiment batch option(s): ${unknown.join(', ')}`, {
      code: 'INVALID_ARGUMENT'
    });
  }

  if (typeof options.experimentId !== 'string' || !EXPERIMENT_ID_PATTERN.test(options.experimentId)) {
    throw new MvxError('experimentId must match /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/', {
      code: 'INVALID_ARGUMENT'
    });
  }
  if (typeof options.outputDir !== 'string' || options.outputDir.length === 0) {
    throw new MvxError('outputDir must be a non-empty string', { code: 'INVALID_ARGUMENT' });
  }

  const manifest = validateDatasetManifest(options.manifest);
  const methods = options.methods ?? ['M1', 'M2', 'M3', 'M4'];
  if (!Array.isArray(methods) || methods.length === 0 || methods.some((method) => !VALID_METHODS.has(method))) {
    throw new MvxError('methods must be a non-empty array of M1, M2, M3, and/or M4', {
      code: 'INVALID_ARGUMENT'
    });
  }
  const methodSet = new Set(methods);
  const uniqueMethods = ['M1', 'M2', 'M3', 'M4'].filter((method) => methodSet.has(method));

  const weightProfiles = options.weightProfiles ?? ['W1'];
  if (!Array.isArray(weightProfiles) || weightProfiles.length === 0
    || weightProfiles.some((profile) => !VALID_WEIGHTS.has(profile))) {
    throw new MvxError('weightProfiles must be a non-empty array of W1-W5', {
      code: 'INVALID_ARGUMENT'
    });
  }
  const uniqueWeights = [...new Set(weightProfiles)];

  const needsM4 = methodSet.has('M4');
  const needsM3 = methodSet.has('M3') || needsM4;
  const needsM1 = methodSet.has('M1') || needsM4;
  const needsM2 = methodSet.has('M2') || needsM4;

  const fusionConfig = needsM4 ? validateFusionConfig(options.fusionConfig) : null;
  if (needsM3 && (typeof options.scenarioPath !== 'string' || options.scenarioPath.length === 0)) {
    throw new MvxError('scenarioPath is required when M3 or M4 is enabled', { code: 'INVALID_ARGUMENT' });
  }
  if (needsM3 && options.acknowledgeRisk !== true) {
    throw new MvxError('acknowledgeRisk: true is required when M3 or M4 is enabled', {
      code: 'RISK_ACK_REQUIRED'
    });
  }

  const m2Options = options.m2Options ?? {};
  assertOptionsObject(m2Options, 'm2Options');
  const m3Options = options.m3Options ?? {};
  assertOptionsObject(m3Options, 'm3Options');
  const repeatCount = m3Options.repeatCount ?? 1;
  if (!Number.isSafeInteger(repeatCount) || repeatCount < 1) {
    throw new MvxError('m3Options.repeatCount must be a positive safe integer', {
      code: 'INVALID_ARGUMENT'
    });
  }
  const repeatSampleIdSet = m3Options.repeatSampleIds !== undefined
    ? new Set(m3Options.repeatSampleIds)
    : null;
  const requireManifestV3 = options.requireManifestV3 === true;
  const resume = options.resume === true;
  if (options.onProgress !== undefined && typeof options.onProgress !== 'function') {
    throw new MvxError('onProgress must be a function', { code: 'INVALID_ARGUMENT' });
  }
  const onProgress = options.onProgress ?? null;
  const signal = options.signal ?? null;

  const startedAtUtc = new Date().toISOString();
  const envMetadata = collectEnvironmentMetadata(
    {
      startedAtUtc,
      ...(options.environment ?? {}),
      ...(options.baseCommit ? { mvxBaseCommit: options.baseCommit } : {})
    },
    {
      requiresDocker: needsM3,
      customLabRunner: typeof m3Options.labRunner === 'function',
      imageReference: m3Options.image ?? (needsM3 ? 'mvx-lab:local' : null),
      skipExternalProbes: options.skipExternalProbes === true
    }
  );

  const configIdentity = {
    profile: EXPERIMENT_PROFILE,
    schemaVersion: EXPERIMENT_SCHEMA_VERSION,
    researchConfigVersion: RESEARCH_CONFIG_VERSION,
    datasetVersion: manifest.datasetVersion,
    methods: uniqueMethods,
    weightProfiles: uniqueWeights,
    requireManifestV3,
    m2Switches: {
      includeManifestStructure: m2Options.includeManifestStructure === true,
      includeArchiveAuthenticity: m2Options.includeArchiveAuthenticity === true
    },
    m3RepeatCount: repeatCount,
    m3RepeatSampleIds: repeatSampleIdSet ? [...repeatSampleIdSet].sort() : null,
    fusionConfigVersion: fusionConfig?.configVersion ?? null,
    fusionConfigSha256: fusionConfig?.sha256 ?? null
  };
  const experimentConfigSha256 = sha256(canonicalStringify(configIdentity));

  const experimentRoot = path.resolve(options.outputDir, options.experimentId);
  const runManifestPath = path.join(experimentRoot, 'run_manifest.json');
  const runsJsonlPath = path.join(experimentRoot, 'runs.jsonl');
  const progressJsonlPath = path.join(experimentRoot, 'progress.jsonl');
  const artifactsRoot = path.join(experimentRoot, 'artifacts');
  const dynamicRunsRoot = path.join(experimentRoot, 'dynamic_runs');

  let existingDir = false;
  try {
    await lstat(experimentRoot);
    existingDir = true;
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }
  if (existingDir && !resume) {
    throw new MvxError(`Experiment output directory already exists (use resume: true to continue without overwriting): ${experimentRoot}`, {
      code: 'EXPERIMENT_EXISTS'
    });
  }

  await mkdir(artifactsRoot, { recursive: true, mode: 0o700 });
  if (needsM3) await mkdir(dynamicRunsRoot, { recursive: true, mode: 0o700 });

  let priorManifest = null;
  let existingRecords = [];
  if (resume) {
    try {
      priorManifest = JSON.parse(await readFile(runManifestPath, 'utf8'));
      if (priorManifest.experimentConfigSha256 !== experimentConfigSha256) {
        throw new MvxError(
          `Cannot resume experiment ${options.experimentId}: configuration SHA mismatch (${priorManifest.experimentConfigSha256} vs ${experimentConfigSha256})`,
          { code: 'CONFIG_MISMATCH' }
        );
      }
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
    }
    existingRecords = await loadExistingRecords(
      runsJsonlPath,
      experimentConfigSha256,
      fusionConfig?.sha256 ?? null
    );
  }

  const isResumingExisting = resume && (existingRecords.length > 0 || priorManifest !== null);
  const priorHistory = Array.isArray(priorManifest?.lifecycleHistory) ? priorManifest.lifecycleHistory : [];
  const priorResumeCount = Number.isSafeInteger(priorManifest?.resumeCount) ? priorManifest.resumeCount : 0;
  const resumeCount = isResumingExisting ? priorResumeCount + 1 : 0;
  const lifecycleHistory = [
    ...priorHistory,
    { state: isResumingExisting ? 'resumed' : 'running', timestampUtc: startedAtUtc }
  ];

  const runManifest = {
    schemaVersion: EXPERIMENT_SCHEMA_VERSION,
    profile: EXPERIMENT_PROFILE,
    experimentId: options.experimentId,
    experimentConfigSha256,
    createdAtUtc: priorManifest?.createdAtUtc ?? startedAtUtc,
    startedAtUtc,
    endedAtUtc: null,
    lastResumedAtUtc: isResumingExisting ? startedAtUtc : (priorManifest?.lastResumedAtUtc ?? null),
    resumed: isResumingExisting,
    wasResumed: isResumingExisting || priorManifest?.wasResumed === true,
    resumeCount,
    lifecycleState: isResumingExisting ? 'resumed' : 'running',
    lifecycleHistory,
    mvxVersion: VERSION,
    mvxBaseCommit: envMetadata.mvxBaseCommit,
    researchConfigVersion: RESEARCH_CONFIG_VERSION,
    fusionConfigVersion: fusionConfig?.configVersion ?? null,
    fusionConfigSha256: fusionConfig?.sha256 ?? null,
    datasetVersion: manifest.datasetVersion,
    sampleCount: manifest.samples.length,
    methods: uniqueMethods,
    weightProfiles: uniqueWeights,
    requireManifestV3,
    m3RepeatCount: repeatCount,
    environment: envMetadata
  };
  let manifestArtifact = await atomicWriteJson(runManifestPath, runManifest);

  const recordsByRunId = new Map(existingRecords.map((record) => [record.runId, record]));
  const allRecords = [...existingRecords];
  const liveStatusCounts = {
    completed: 0,
    completed_with_static_fallback: 0,
    inconclusive: 0,
    failed: 0,
    skipped: 0
  };
  for (const record of existingRecords) {
    liveStatusCounts[record.status] = (liveStatusCounts[record.status] ?? 0) + 1;
  }

  const emitProgress = async (type, payload) => {
    const event = createProgressEvent(type, {
      experimentId: options.experimentId,
      statusCounts: { ...liveStatusCounts },
      ...payload
    });
    await appendFile(progressJsonlPath, `${canonicalStringify(event)}\n`, { encoding: 'utf8', mode: 0o600 });
    if (onProgress) onProgress(event);
    return event;
  };

  await emitProgress('experiment.started', {
    resumed: isResumingExisting,
    resumeCount,
    totalSamples: manifest.samples.length,
    methods: uniqueMethods,
    weightProfiles: uniqueWeights,
    priorRecordCount: existingRecords.length
  });

  const stageForMethod = (method) => {
    if (method === 'M1') return 'm1_permission';
    if (method === 'M2') return 'm2_static';
    if (method === 'M3') return 'm3_dynamic';
    if (method === 'M4') return 'm4_fusion';
    return 'execution';
  };

  const writeRecordAndArtifact = async (recordDraft, artifactPayload, { stage } = {}) => {
    const normalizedFailure = recordDraft.failure
      ? normalizeStructuredFailure(recordDraft.failure, {
        stage: stage ?? stageForMethod(recordDraft.method),
        timestamp: recordDraft.timestampUtc
      })
      : null;
    let artifactInfo = null;
    if (artifactPayload !== undefined) {
      const safeName = recordDraft.runId.replace(/[^A-Za-z0-9._-]/g, '_');
      const artifactFile = path.join(artifactsRoot, recordDraft.sampleId, `${safeName}.json`);
      const saved = await atomicWriteJson(artifactFile, artifactPayload);
      artifactInfo = {
        path: path.relative(experimentRoot, saved.path).split(path.sep).join('/'),
        bytes: saved.bytes,
        sha256: saved.sha256,
        sampleId: recordDraft.sampleId,
        method: recordDraft.method,
        packageSha256: recordDraft.packageSha256,
        configSha256: recordDraft.method === 'M4'
          ? recordDraft.fusionConfigSha256
          : recordDraft.experimentConfigSha256,
        experimentConfigSha256: recordDraft.experimentConfigSha256,
        fusionConfigSha256: recordDraft.fusionConfigSha256,
        createdAtUtc: recordDraft.timestampUtc
      };
    }
    const record = validateRunRecord({
      schemaVersion: RUN_RECORD_SCHEMA_VERSION,
      ...recordDraft,
      failure: normalizedFailure,
      artifact: artifactInfo
    });
    if (recordsByRunId.has(record.runId)) {
      throw new MvxError(`Duplicate runId generated: ${record.runId}`, { code: 'DUPLICATE_RUN_ID' });
    }
    recordsByRunId.set(record.runId, record);
    allRecords.push(record);
    liveStatusCounts[record.status] = (liveStatusCounts[record.status] ?? 0) + 1;
    await appendFile(runsJsonlPath, `${canonicalStringify(record)}\n`, { encoding: 'utf8', mode: 0o600 });
    return record;
  };

  const loadExistingArtifact = async (runId) => {
    const existing = recordsByRunId.get(runId);
    if (!existing?.artifact?.path) return null;
    const fullPath = path.join(experimentRoot, existing.artifact.path);
    const text = await readFile(fullPath, 'utf8');
    if (sha256(text) !== existing.artifact.sha256) {
      throw new MvxError(`Saved artifact SHA-256 mismatch for resumed run ${runId}`, {
        code: 'ARTIFACT_HASH_MISMATCH'
      });
    }
    return JSON.parse(text);
  };

  let haltedEarly = false;
  let haltReason = null;
  let interruptedBySignal = false;
  let containmentViolationObserved = false;
  let processedSamples = 0;
  const observedImageIds = new Set();
  const observedChromiumVersions = new Set();
  const stabilitySummaries = [];

  for (let sampleIdx = 0; sampleIdx < manifest.samples.length; sampleIdx += 1) {
    const sample = manifest.samples[sampleIdx];
    const sampleIndex = sampleIdx + 1;
    const totalSamples = manifest.samples.length;
    if (haltedEarly) break;
    if (signal?.aborted) {
      haltedEarly = true;
      interruptedBySignal = true;
      haltReason = 'INTERRUPTED_BY_SIGNAL';
      break;
    }

    await emitProgress('sample.started', {
      sampleIndex,
      totalSamples,
      sampleId: sample.sampleId,
      extensionId: sample.extensionId
    });

    if (sample.skip) {
      for (const method of uniqueMethods) {
        const runId = `${options.experimentId}:${sample.sampleId}:${method}:skipped`;
        if (recordsByRunId.has(runId)) {
          await emitProgress('method.completed', {
            sampleIndex,
            totalSamples,
            sampleId: sample.sampleId,
            method,
            weightProfile: method === 'M3' ? null : uniqueWeights[0],
            repeatIndex: method === 'M3' ? 1 : null,
            status: 'skipped',
            verdict: null,
            durationMs: 0,
            resumedFromCache: true
          });
          continue;
        }
        await writeRecordAndArtifact({
          experimentId: options.experimentId,
          runId,
          sampleId: sample.sampleId,
          extensionId: sample.extensionId,
          packageSha256: null,
          archiveSha256: null,
          method,
          weightProfile: method === 'M3' ? null : uniqueWeights[0],
          repeatIndex: method === 'M3' ? 1 : null,
          fusionConfigVersion: method === 'M4' ? fusionConfig.configVersion : null,
          fusionConfigSha256: method === 'M4' ? fusionConfig.sha256 : null,
          experimentConfigSha256,
          mvxVersion: VERSION,
          mvxBaseCommit: envMetadata.mvxBaseCommit,
          timestampUtc: new Date().toISOString(),
          durationMs: 0,
          environment: envMetadata,
          status: 'skipped',
          verdict: null,
          riskScore: null,
          failure: { code: 'SAMPLE_SKIPPED', message: sample.skipReason, stage: 'intake', retryable: false }
        }, undefined, { stage: 'intake' });
        await emitProgress('method.completed', {
          sampleIndex,
          totalSamples,
          sampleId: sample.sampleId,
          method,
          weightProfile: method === 'M3' ? null : uniqueWeights[0],
          repeatIndex: method === 'M3' ? 1 : null,
          status: 'skipped',
          verdict: null,
          durationMs: 0,
          resumedFromCache: false
        });
      }
      processedSamples += 1;
      await emitProgress('sample.completed', { sampleIndex, totalSamples, sampleId: sample.sampleId });
      continue;
    }

    let workspaceRecord = null;
    let analysisPath = sample.artifactPath;
    let archiveMeta = null;
    let intakeError = null;

    try {
      const packed = await isArchiveFile(sample.artifactPath);
      if (packed) {
        if (options.acknowledgeRisk !== true) {
          throw new MvxError('acknowledgeRisk: true is required to unpack CRX/ZIP archive samples', {
            code: 'RISK_ACK_REQUIRED'
          });
        }
        const parent = await resolvePrivateWorkspaceParent(
          options.temporaryDirectory ?? os.tmpdir(),
          {
            missingMessage: 'Temporary directory does not exist',
            unsafeMessage: 'Temporary directory must be a real directory',
            changedMessage: 'Temporary directory changed during resolution'
          }
        );
        workspaceRecord = await createPrivateWorkspace(parent, 'mvx-exp-unpack-', {
          changedMessage: 'Temporary workspace changed during creation',
          cleanupMessage: 'Temporary workspace cleanup failed'
        });
        const extractedDir = path.join(workspaceRecord.path, 'extension');
        archiveMeta = await unpackExtensionArchive(sample.artifactPath, extractedDir, {
          expectedArchiveSha256: sample.expectedArchiveSha256 ?? undefined
        });
        analysisPath = extractedDir;
      }
    } catch (error) {
      intakeError = error;
    }

    try {
      if (intakeError) {
        for (const method of uniqueMethods) {
          const runId = `${options.experimentId}:${sample.sampleId}:${method}:intake-failed`;
          if (recordsByRunId.has(runId)) continue;
          await writeRecordAndArtifact({
            experimentId: options.experimentId,
            runId,
            sampleId: sample.sampleId,
            extensionId: sample.extensionId,
            packageSha256: null,
            archiveSha256: null,
            method,
            weightProfile: method === 'M3' ? null : uniqueWeights[0],
            repeatIndex: method === 'M3' ? 1 : null,
            fusionConfigVersion: method === 'M4' ? fusionConfig.configVersion : null,
            fusionConfigSha256: method === 'M4' ? fusionConfig.sha256 : null,
            experimentConfigSha256,
            mvxVersion: VERSION,
            mvxBaseCommit: envMetadata.mvxBaseCommit,
            timestampUtc: new Date().toISOString(),
            durationMs: 0,
            environment: envMetadata,
            status: 'failed',
            verdict: null,
            riskScore: null,
            failure: {
              code: typeof intakeError?.code === 'string' ? intakeError.code : 'INTAKE_FAILED',
              message: String(intakeError?.message ?? intakeError),
              stage: 'intake'
            }
          }, undefined, { stage: 'intake' });
          await emitProgress('method.completed', {
            sampleIndex,
            totalSamples,
            sampleId: sample.sampleId,
            method,
            weightProfile: method === 'M3' ? null : uniqueWeights[0],
            repeatIndex: method === 'M3' ? 1 : null,
            status: 'failed',
            verdict: null,
            durationMs: 0,
            resumedFromCache: false
          });
        }
        processedSamples += 1;
        await emitProgress('sample.completed', { sampleIndex, totalSamples, sampleId: sample.sampleId });
        continue;
      }

      // Execute M1 (once per sample; W1-W5 scores recorded in single M1 result & emitted per requested weight profile)
      let m1BaseResult = null;
      if (needsM1) {
        const primaryM1RunId = `${options.experimentId}:${sample.sampleId}:M1:${uniqueWeights[0]}`;
        if (recordsByRunId.has(primaryM1RunId)) {
          m1BaseResult = await loadExistingArtifact(primaryM1RunId);
        }
        if (!m1BaseResult) {
          const started = performance.now();
          m1BaseResult = await runM1PermissionOnly(analysisPath, {
            sampleId: sample.sampleId,
            weightProfile: uniqueWeights[0],
            limits: m2Options.limits,
            captureFailures: true
          });
          const elapsed = Number((performance.now() - started).toFixed(3));
          if (m1BaseResult.status === 'completed'
            && sample.expectedPackageSha256 !== null
            && m1BaseResult.provenance.packageSha256 !== sample.expectedPackageSha256) {
            throw new MvxError(
              `Package SHA-256 mismatch for ${sample.sampleId}: expected ${sample.expectedPackageSha256}, observed ${m1BaseResult.provenance.packageSha256}`,
              { code: 'PACKAGE_SHA_MISMATCH' }
            );
          }
          if (requireManifestV3 && m1BaseResult.status === 'completed' && m1BaseResult.target?.manifestVersion !== 3) {
            for (const method of uniqueMethods) {
              const skipRunId = `${options.experimentId}:${sample.sampleId}:${method}:non-mv3`;
              if (recordsByRunId.has(skipRunId)) continue;
              await writeRecordAndArtifact({
                experimentId: options.experimentId,
                runId: skipRunId,
                sampleId: sample.sampleId,
                extensionId: sample.extensionId,
                packageSha256: m1BaseResult.provenance.packageSha256,
                archiveSha256: archiveMeta?.archiveSha256 ?? null,
                method,
                weightProfile: method === 'M3' ? null : uniqueWeights[0],
                repeatIndex: method === 'M3' ? 1 : null,
                fusionConfigVersion: method === 'M4' ? fusionConfig.configVersion : null,
                fusionConfigSha256: method === 'M4' ? fusionConfig.sha256 : null,
                experimentConfigSha256,
                mvxVersion: VERSION,
                mvxBaseCommit: envMetadata.mvxBaseCommit,
                timestampUtc: new Date().toISOString(),
                durationMs: elapsed,
                environment: envMetadata,
                status: 'skipped',
                verdict: null,
                riskScore: null,
                failure: {
                  code: 'NON_MV3_MANIFEST',
                  message: `Observed manifest_version=${m1BaseResult.target?.manifestVersion}; primary cohort requires Manifest V3.`,
                  stage: 'validation',
                  retryable: false
                }
              }, undefined, { stage: 'validation' });
              await emitProgress('method.completed', {
                sampleIndex,
                totalSamples,
                sampleId: sample.sampleId,
                method,
                weightProfile: method === 'M3' ? null : uniqueWeights[0],
                repeatIndex: method === 'M3' ? 1 : null,
                status: 'skipped',
                verdict: null,
                durationMs: elapsed,
                resumedFromCache: false
              });
            }
            processedSamples += 1;
            await emitProgress('sample.completed', { sampleIndex, totalSamples, sampleId: sample.sampleId });
            continue;
          }
        }
        if (methodSet.has('M1')) {
          for (const weightProfile of uniqueWeights) {
            const runId = `${options.experimentId}:${sample.sampleId}:M1:${weightProfile}`;
            if (recordsByRunId.has(runId)) {
              const cachedRec = recordsByRunId.get(runId);
              await emitProgress('method.completed', {
                sampleIndex,
                totalSamples,
                sampleId: sample.sampleId,
                method: 'M1',
                weightProfile,
                repeatIndex: null,
                status: cachedRec.status,
                verdict: null,
                durationMs: cachedRec.durationMs,
                resumedFromCache: true
              });
              continue;
            }
            const summaryForWeight = m1BaseResult.status === 'completed'
              ? m1BaseResult.scoresByWeight[weightProfile]
              : null;
            const artifactPayload = m1BaseResult.status === 'completed'
              ? { ...m1BaseResult, summary: summaryForWeight, researchConfig: { ...m1BaseResult.researchConfig, weightProfile } }
              : m1BaseResult;
            await writeRecordAndArtifact({
              experimentId: options.experimentId,
              runId,
              sampleId: sample.sampleId,
              extensionId: sample.extensionId,
              packageSha256: m1BaseResult.provenance?.packageSha256 ?? null,
              archiveSha256: archiveMeta?.archiveSha256 ?? null,
              method: 'M1',
              weightProfile,
              repeatIndex: null,
              fusionConfigVersion: null,
              fusionConfigSha256: null,
              experimentConfigSha256,
              mvxVersion: VERSION,
              mvxBaseCommit: envMetadata.mvxBaseCommit,
              timestampUtc: new Date().toISOString(),
              durationMs: m1BaseResult.runtimeMs ?? 0,
              environment: envMetadata,
              status: m1BaseResult.status,
              verdict: null,
              riskScore: summaryForWeight?.riskScore ?? null,
              failure: m1BaseResult.failure ?? null
            }, artifactPayload, { stage: 'm1_permission' });
            await emitProgress('method.completed', {
              sampleIndex,
              totalSamples,
              sampleId: sample.sampleId,
              method: 'M1',
              weightProfile,
              repeatIndex: null,
              status: m1BaseResult.status,
              verdict: null,
              durationMs: m1BaseResult.runtimeMs ?? 0,
              resumedFromCache: false
            });
          }
        }
      }

      // Execute M2
      let m2BaseResult = null;
      if (needsM2) {
        const primaryM2RunId = `${options.experimentId}:${sample.sampleId}:M2:${uniqueWeights[0]}`;
        if (recordsByRunId.has(primaryM2RunId)) {
          m2BaseResult = await loadExistingArtifact(primaryM2RunId);
        }
        if (!m2BaseResult) {
          m2BaseResult = await runM2StaticOnly(analysisPath, {
            sampleId: sample.sampleId,
            weightProfile: uniqueWeights[0],
            limits: m2Options.limits,
            dnrRuleLimits: m2Options.dnrRuleLimits,
            includeManifestStructure: m2Options.includeManifestStructure === true,
            includeArchiveAuthenticity: m2Options.includeArchiveAuthenticity === true,
            ...(archiveMeta ? {
              archiveAuthenticity: {
                authenticity: archiveMeta.authenticity,
                format: archiveMeta.archiveFormat
              }
            } : {}),
            captureFailures: true
          });
          if (m2BaseResult.status === 'completed'
            && m1BaseResult?.status === 'completed'
            && m2BaseResult.provenance.packageSha256 !== m1BaseResult.provenance.packageSha256) {
            throw new MvxError(
              `Package SHA-256 mismatch between M1 and M2 for ${sample.sampleId}`,
              { code: 'PACKAGE_SHA_MISMATCH' }
            );
          }
        }
        if (methodSet.has('M2')) {
          for (const weightProfile of uniqueWeights) {
            const runId = `${options.experimentId}:${sample.sampleId}:M2:${weightProfile}`;
            if (recordsByRunId.has(runId)) {
              const cachedRec = recordsByRunId.get(runId);
              await emitProgress('method.completed', {
                sampleIndex,
                totalSamples,
                sampleId: sample.sampleId,
                method: 'M2',
                weightProfile,
                repeatIndex: null,
                status: cachedRec.status,
                verdict: null,
                durationMs: cachedRec.durationMs,
                resumedFromCache: true
              });
              continue;
            }
            const summaryForWeight = m2BaseResult.status === 'completed'
              ? m2BaseResult.scoresByWeight[weightProfile]
              : null;
            const artifactPayload = m2BaseResult.status === 'completed'
              ? { ...m2BaseResult, summary: summaryForWeight, researchConfig: { ...m2BaseResult.researchConfig, weightProfile } }
              : m2BaseResult;
            await writeRecordAndArtifact({
              experimentId: options.experimentId,
              runId,
              sampleId: sample.sampleId,
              extensionId: sample.extensionId,
              packageSha256: m2BaseResult.provenance?.packageSha256 ?? null,
              archiveSha256: archiveMeta?.archiveSha256 ?? null,
              method: 'M2',
              weightProfile,
              repeatIndex: null,
              fusionConfigVersion: null,
              fusionConfigSha256: null,
              experimentConfigSha256,
              mvxVersion: VERSION,
              mvxBaseCommit: envMetadata.mvxBaseCommit,
              timestampUtc: new Date().toISOString(),
              durationMs: m2BaseResult.runtimeMs ?? 0,
              environment: envMetadata,
              status: m2BaseResult.status,
              verdict: null,
              riskScore: summaryForWeight?.riskScore ?? null,
              failure: m2BaseResult.failure ?? null
            }, artifactPayload, { stage: 'm2_static' });
            await emitProgress('method.completed', {
              sampleIndex,
              totalSamples,
              sampleId: sample.sampleId,
              method: 'M2',
              weightProfile,
              repeatIndex: null,
              status: m2BaseResult.status,
              verdict: null,
              durationMs: m2BaseResult.runtimeMs ?? 0,
              resumedFromCache: false
            });
          }
        }
      }

      // Execute M3 (with optional repeated runs for stability)
      const sampleM3Results = [];
      const sampleM3StabilityInputs = [];
      const expectedPkgSha = m1BaseResult?.provenance?.packageSha256
        ?? m2BaseResult?.provenance?.packageSha256
        ?? sample.expectedPackageSha256
        ?? undefined;

      if (needsM3) {
        const runsForSample = (repeatSampleIdSet === null || repeatSampleIdSet.has(sample.sampleId))
          ? repeatCount
          : 1;
        for (let repeatIndex = 1; repeatIndex <= runsForSample; repeatIndex += 1) {
          if (signal?.aborted) {
            haltedEarly = true;
            interruptedBySignal = true;
            haltReason = 'INTERRUPTED_BY_SIGNAL';
            break;
          }
          const runId = `${options.experimentId}:${sample.sampleId}:M3:r${repeatIndex}`;
          let m3Result;
          let m3FromCache = false;
          if (recordsByRunId.has(runId)) {
            m3Result = await loadExistingArtifact(runId);
            m3FromCache = true;
          } else {
            const runOutDir = path.join(dynamicRunsRoot, sample.sampleId, `run_${repeatIndex}`);
            m3Result = await runM3DynamicOnly(analysisPath, options.scenarioPath, runOutDir, {
              acknowledgeRisk: true,
              sampleId: sample.sampleId,
              repeatIndex,
              expectedPackageSha256: expectedPkgSha,
              image: m3Options.image,
              labRunner: m3Options.labRunner,
              captureFailures: true
            });
            if (methodSet.has('M3') || repeatIndex === 1 || runsForSample > 1) {
              await writeRecordAndArtifact({
                experimentId: options.experimentId,
                runId,
                sampleId: sample.sampleId,
                extensionId: sample.extensionId,
                packageSha256: m3Result.provenance?.packageSha256 ?? expectedPkgSha ?? null,
                archiveSha256: archiveMeta?.archiveSha256 ?? null,
                method: 'M3',
                weightProfile: null,
                repeatIndex,
                fusionConfigVersion: null,
                fusionConfigSha256: null,
                experimentConfigSha256,
                mvxVersion: VERSION,
                mvxBaseCommit: envMetadata.mvxBaseCommit,
                timestampUtc: new Date().toISOString(),
                durationMs: m3Result.runtimeMs ?? 0,
                environment: envMetadata,
                status: m3Result.status,
                verdict: m3Result.verdict ?? null,
                riskScore: m3Result.riskScore ?? null,
                failure: m3Result.failure ?? null
              }, m3Result, { stage: 'm3_dynamic' });
            }
          }
          if (typeof m3Result?.provenance?.imageId === 'string' && m3Result.provenance.imageId.length > 0) {
            observedImageIds.add(m3Result.provenance.imageId);
          }
          const browserVersion = m3Result?.provenance?.browser?.version
            ?? (typeof m3Result?.provenance?.browser === 'string' ? m3Result.provenance.browser : null);
          if (typeof browserVersion === 'string' && browserVersion.length > 0) {
            observedChromiumVersions.add(browserVersion);
          }
          await emitProgress('method.completed', {
            sampleIndex,
            totalSamples,
            sampleId: sample.sampleId,
            method: 'M3',
            weightProfile: null,
            repeatIndex,
            status: m3Result.status,
            verdict: m3Result.verdict ?? null,
            durationMs: m3Result.runtimeMs ?? 0,
            resumedFromCache: m3FromCache
          });
          sampleM3Results.push(m3Result);
          sampleM3StabilityInputs.push({
            ...m3Result,
            runId,
            extensionId: sample.extensionId,
            packageSha256: m3Result.provenance?.packageSha256 ?? expectedPkgSha ?? null,
            configSha256: experimentConfigSha256
          });

          // Execution safety: containment violation stops experiment immediately, never retry
          const containmentBreached = m3Result.contained === false
            || m3Result.failure?.code === 'LAB_CONTAINMENT_VIOLATION';
          if (containmentBreached) {
            containmentViolationObserved = true;
            haltedEarly = true;
            haltReason = 'LAB_CONTAINMENT_VIOLATION';
            break;
          }
        }

        if (sampleM3StabilityInputs.length > 1 || (runsForSample > 1 && sampleM3StabilityInputs.length > 0)) {
          stabilitySummaries.push(summarizeRepeatedDynamicRuns(sampleM3StabilityInputs, {
            requestedRuns: runsForSample,
            sampleId: sample.sampleId,
            extensionId: sample.extensionId,
            expectedPackageSha256: expectedPkgSha,
            expectedConfigSha256: experimentConfigSha256
          }));
        }
      }

      // Execute M4 using ONLY the primary dynamic run (repeatIndex === 1) so repeated runs are never treated as independent samples
      if (needsM4 && sampleM3Results.length > 0 && !interruptedBySignal) {
        const primaryM3 = sampleM3Results[0];
        for (const weightProfile of uniqueWeights) {
          const runId = `${options.experimentId}:${sample.sampleId}:M4:${weightProfile}`;
          if (recordsByRunId.has(runId)) {
            const cachedRec = recordsByRunId.get(runId);
            await emitProgress('method.completed', {
              sampleIndex,
              totalSamples,
              sampleId: sample.sampleId,
              method: 'M4',
              weightProfile,
              repeatIndex: null,
              status: cachedRec.status,
              verdict: cachedRec.verdict ?? null,
              durationMs: cachedRec.durationMs,
              resumedFromCache: true
            });
            continue;
          }
          const started = performance.now();
          const m4Result = fuseHybridEvidence({
            m1: m1BaseResult,
            m2: m2BaseResult,
            m3: primaryM3,
            weightProfile,
            sampleId: sample.sampleId
          }, fusionConfig);
          const elapsed = Number((performance.now() - started).toFixed(3));
          await writeRecordAndArtifact({
            experimentId: options.experimentId,
            runId,
            sampleId: sample.sampleId,
            extensionId: sample.extensionId,
            packageSha256: m4Result.provenance?.packageSha256 ?? null,
            archiveSha256: archiveMeta?.archiveSha256 ?? null,
            method: 'M4',
            weightProfile,
            repeatIndex: null,
            fusionConfigVersion: fusionConfig.configVersion,
            fusionConfigSha256: fusionConfig.sha256,
            experimentConfigSha256,
            mvxVersion: VERSION,
            mvxBaseCommit: envMetadata.mvxBaseCommit,
            timestampUtc: new Date().toISOString(),
            durationMs: elapsed,
            environment: envMetadata,
            status: m4Result.status,
            verdict: m4Result.m3Verdict ?? null,
            riskScore: m4Result.hybridRiskScore,
            failure: m4Result.failure ?? null
          }, m4Result, { stage: 'm4_fusion' });
          await emitProgress('method.completed', {
            sampleIndex,
            totalSamples,
            sampleId: sample.sampleId,
            method: 'M4',
            weightProfile,
            repeatIndex: null,
            status: m4Result.status,
            verdict: m4Result.m3Verdict ?? null,
            durationMs: elapsed,
            resumedFromCache: false
          });
        }
      }
      processedSamples += 1;
      await emitProgress('sample.completed', { sampleIndex, totalSamples, sampleId: sample.sampleId });
    } finally {
      if (workspaceRecord) {
        await removePrivateWorkspace(workspaceRecord, {
          changedMessage: 'Temporary workspace changed before cleanup',
          cleanupMessage: 'Temporary workspace cleanup failed'
        });
      }
    }
  }

  const provenanceCheck = verifyExperimentProvenance(allRecords, {
    experimentConfigSha256,
    fusionConfigSha256: fusionConfig?.sha256 ?? null
  });

  let stabilityArtifact = null;
  let multiSampleStability = null;
  if (stabilitySummaries.length > 0) {
    multiSampleStability = computeMultiSampleStabilitySummary(stabilitySummaries);
    const stabilityPayload = {
      schemaVersion: EXPERIMENT_SCHEMA_VERSION,
      experimentId: options.experimentId,
      experimentConfigSha256,
      overall: multiSampleStability,
      perSample: stabilitySummaries
    };
    stabilityArtifact = await atomicWriteJson(
      path.join(experimentRoot, 'stability_summary.json'),
      stabilityPayload
    );
  }

  const statusCounts = {
    completed: 0,
    completed_with_static_fallback: 0,
    inconclusive: 0,
    failed: 0,
    skipped: 0
  };
  const methodCounts = { M1: 0, M2: 0, M3: 0, M4: 0 };
  for (const record of allRecords) {
    statusCounts[record.status] += 1;
    methodCounts[record.method] += 1;
  }

  const endedAtUtc = new Date().toISOString();
  const observedImageList = [...observedImageIds].sort();
  const observedChromiumList = [...observedChromiumVersions].sort();
  const finalEnvironment = {
    ...envMetadata,
    endedAtUtc,
    docker: {
      ...envMetadata.docker,
      imageId: envMetadata.docker?.imageId ?? observedImageList[0] ?? null,
      observedImageIds: observedImageList
    },
    chromium: observedChromiumList.length > 0
      ? {
        status: 'available',
        version: observedChromiumList[0],
        observedVersions: observedChromiumList,
        source: 'lab_runtime',
        reason: null
      }
      : envMetadata.chromium
  };

  let lifecycleState;
  if (interruptedBySignal || (haltedEarly && processedSamples < manifest.samples.length)) {
    lifecycleState = 'interrupted';
  } else if (containmentViolationObserved
    || (statusCounts.failed > 0 && statusCounts.completed === 0 && statusCounts.completed_with_static_fallback === 0)) {
    lifecycleState = 'failed';
  } else {
    lifecycleState = 'completed';
  }

  const finalLifecycleHistory = [
    ...lifecycleHistory,
    { state: lifecycleState, reason: haltReason, timestampUtc: endedAtUtc }
  ];

  const finalRunManifest = {
    ...runManifest,
    endedAtUtc,
    lifecycleState,
    lifecycleHistory: finalLifecycleHistory,
    haltedEarly,
    haltReason,
    environment: finalEnvironment
  };
  manifestArtifact = await atomicWriteJson(runManifestPath, finalRunManifest);

  if (lifecycleState === 'interrupted') {
    await emitProgress('experiment.interrupted', {
      reason: haltReason,
      processedSamples,
      totalSamples: manifest.samples.length,
      lifecycleState,
      totalRunRecords: allRecords.length
    });
  } else {
    await emitProgress('experiment.completed', {
      lifecycleState,
      totalRunRecords: allRecords.length,
      processedSamples,
      totalSamples: manifest.samples.length,
      startedAtUtc,
      endedAtUtc
    });
  }

  let runsJsonlSha256 = null;
  try {
    runsJsonlSha256 = sha256(await readFile(runsJsonlPath, 'utf8'));
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }

  let progressJsonlSha256 = null;
  try {
    progressJsonlSha256 = sha256(await readFile(progressJsonlPath, 'utf8'));
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }

  const summaryPayload = {
    schemaVersion: EXPERIMENT_SCHEMA_VERSION,
    profile: EXPERIMENT_PROFILE,
    experimentId: options.experimentId,
    experimentConfigSha256,
    startedAtUtc,
    completedAtUtc: endedAtUtc,
    endedAtUtc,
    lifecycleState,
    wasResumed: finalRunManifest.wasResumed,
    resumeCount: finalRunManifest.resumeCount,
    lifecycleHistory: finalLifecycleHistory,
    datasetVersion: manifest.datasetVersion,
    totalSamplesInManifest: manifest.samples.length,
    processedSamples,
    methods: uniqueMethods,
    weightProfiles: uniqueWeights,
    fusionConfigVersion: fusionConfig?.configVersion ?? null,
    fusionConfigSha256: fusionConfig?.sha256 ?? null,
    mvxVersion: VERSION,
    mvxBaseCommit: envMetadata.mvxBaseCommit,
    environment: finalEnvironment,
    haltedEarly,
    haltReason,
    containmentViolationObserved,
    totalRunRecords: allRecords.length,
    statusCounts,
    methodCounts,
    provenanceCheck,
    stability: multiSampleStability,
    outputs: {
      runManifest: { path: 'run_manifest.json', sha256: manifestArtifact.sha256 },
      runsJsonl: { path: 'runs.jsonl', sha256: runsJsonlSha256 },
      progressJsonl: { path: 'progress.jsonl', sha256: progressJsonlSha256 },
      stabilitySummary: stabilityArtifact
        ? { path: 'stability_summary.json', sha256: stabilityArtifact.sha256 }
        : null
    }
  };
  const summaryArtifact = await atomicWriteJson(
    path.join(experimentRoot, 'experiment_summary.json'),
    summaryPayload
  );

  return {
    experimentRoot,
    manifest: finalRunManifest,
    summary: summaryPayload,
    summaryArtifact,
    records: allRecords,
    stabilitySummaries
  };
}
