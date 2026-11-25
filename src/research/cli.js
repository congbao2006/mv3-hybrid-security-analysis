import { createHash } from 'node:crypto';
import { lstat, mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { runLabContainer } from '../../scripts/run-lab.mjs';
import { unpackExtensionArchive } from '../archive.js';
import { MvxError } from '../errors.js';
import { WEIGHT_PROFILES } from '../model.js';
import {
  createPrivateWorkspace,
  removePrivateWorkspace,
  resolvePrivateWorkspaceParent
} from '../private-workspace.js';
import { VERSION } from '../version.js';
import { RESEARCH_CONFIG_VERSION } from './config.js';
import {
  exportEvaluationTables,
  exportExperimentBundle,
  exportStabilitySummaries
} from './exporters.js';
import {
  EXPERIMENT_PROFILE,
  EXPERIMENT_SCHEMA_VERSION,
  runExperimentBatch,
  validateDatasetManifest,
  validateRunRecord,
  verifyExperimentProvenance
} from './experiment-runner.js';
import { validateFusionConfig } from './hybrid-fusion.js';
import { formatProgressEventText, redactSensitiveText } from './logging.js';
import {
  evaluateExperimentAgainstGroundTruth,
  loadGroundTruth
} from './metrics.js';
import { runM1PermissionOnly } from './modes.js';
import {
  computeMultiSampleStabilitySummary,
  summarizeRepeatedDynamicRuns
} from './stability.js';

export const RESEARCH_CLI_SCHEMA_VERSION = 1;

const SHA256 = /^[a-f0-9]{64}$/;
const VALID_METHODS = new Set(['M1', 'M2', 'M3', 'M4']);
const VALID_WEIGHTS = new Set(Object.keys(WEIGHT_PROFILES));
const EXPERIMENT_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

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
  'ground_truth_path',
  'reviewer1Decision',
  'reviewer2Decision'
]);

export const RESEARCH_HELP = `mvx-audit ${VERSION} — Research CLI

Usage:
  mvx research validate --manifest <manifest.json> [--config <config.json>]
                        [--require-manifest-v3] [--strict-hashes]
                        [--acknowledge-risk] [--format text|json] [--output <file>]
  mvx research experiment --manifest <manifest.json> --output <dir>
                          --experiment-id <id> [--config <config.json>]
                          [--methods M1,M2,M3,M4] [--weights W1,W2,W3,W4,W5]
                          [--scenario <scenario.json>] [--m3-repeats <n>]
                          [--m3-repeat-samples <id1,id2,...>] [--m3-timeout <ms>]
                          [--m3-image <image>] [--fusion-config <fusion.json>]
                          [--include-manifest-structure] [--include-archive-authenticity]
                          [--require-manifest-v3] [--acknowledge-risk] [--resume]
                          [--format text|json]
  mvx research resume <experiment-dir> [--manifest <manifest.json>]
                      [--config <config.json>] [--m3-timeout <ms>]
                      [--acknowledge-risk] [--format text|json]
  mvx research stability <experiment-dir> [--output <dir>]
                         [--null-token <str>] [--format text|json]
  mvx research export <experiment-dir> --output <export-dir>
                      [--evaluation <evaluation_report.json>]
                      [--evaluation-output <dir>] [--null-token <str>]
                      [--format text|json]
  mvx research evaluate <experiment-dir> --ground-truth <file.csv|file.json>
                        --config <eval-config.json> --output <eval-dir>
                        [--null-token <str>] [--format text|json]
  mvx research inspect <experiment-dir> [--export-dir <dir>]
                       [--evaluation-dir <dir>] [--format text|json]
  mvx research --help

Notes:
  - Research execution (validate, experiment, resume, stability, export, inspect) is strictly label-blind.
  - Ground Truth labels may only enter via 'mvx research evaluate' with an explicit config and separate output directory.
  - Failures and inconclusive runs are recorded explicitly and never converted to risk score 0.
`;

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function canonicalStringify(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalStringify).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalStringify(value[key])}`).join(',')}}`;
}

function json(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

async function emit(content, output, stdout) {
  if (!output) {
    stdout.write(content);
    return;
  }
  const absolute = path.resolve(output);
  await mkdir(path.dirname(absolute), { recursive: true });
  const tempPath = `${absolute}.tmp-${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2, 10)}`;
  await writeFile(tempPath, content, { encoding: 'utf8', mode: 0o600 });
  await rename(tempPath, absolute);
}

function pathsOverlap(left, right) {
  const a = path.resolve(left);
  const b = path.resolve(right);
  const relAB = path.relative(a, b);
  const relBA = path.relative(b, a);
  const inside = (rel) => rel === '' || (!rel.startsWith(`..${path.sep}`) && rel !== '..' && !path.isAbsolute(rel));
  return inside(relAB) || inside(relBA);
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
      throw new MvxError(`Ground Truth field '${key}' is forbidden in ${label}`, {
        code: 'GROUND_TRUTH_FORBIDDEN'
      });
    }
    assertLabelBlind(value[key], label, seen);
  }
}

async function readJsonFile(filePath, errorCode, label) {
  let text;
  try {
    text = await readFile(path.resolve(filePath), 'utf8');
  } catch (error) {
    throw new MvxError(`Unable to read ${label} (${filePath}): ${error.message}`, {
      code: errorCode,
      cause: error
    });
  }
  try {
    return { text, data: JSON.parse(text), resolvedPath: path.resolve(filePath) };
  } catch (error) {
    throw new MvxError(`Invalid JSON in ${label} (${filePath}): ${error.message}`, {
      code: errorCode,
      cause: error
    });
  }
}

function parseResearchArgs(argv) {
  const positionals = [];
  const options = Object.create(null);
  const flagOptions = new Set([
    '--help',
    '-h',
    '--acknowledge-risk',
    '--require-manifest-v3',
    '--strict-hashes',
    '--resume',
    '--include-manifest-structure',
    '--include-archive-authenticity'
  ]);
  const valueOptions = new Set([
    '--manifest',
    '--config',
    '--output',
    '--format',
    '--experiment-id',
    '--methods',
    '--weights',
    '--scenario',
    '--m3-repeats',
    '--m3-repeat-samples',
    '--m3-timeout',
    '--m3-image',
    '--fusion-config',
    '--null-token',
    '--ground-truth',
    '--evaluation',
    '--evaluation-output',
    '--export-dir',
    '--evaluation-dir'
  ]);
  const setSingleton = (key, value, token) => {
    if (Object.hasOwn(options, key)) {
      throw new MvxError(`Duplicate option: ${token}`, { code: 'INVALID_CONFIG' });
    }
    options[key] = value;
  };
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (token === '--help' || token === '-h') setSingleton('help', true, token);
    else if (flagOptions.has(token)) {
      const key = token.slice(2).replace(/-([a-z0-9])/g, (_, letter) => letter.toUpperCase());
      setSingleton(key, true, token);
    } else if (valueOptions.has(token)) {
      const value = argv[index + 1];
      if (value === undefined || value.startsWith('--')) {
        throw new MvxError(`${token} requires a value`, { code: 'INVALID_CONFIG' });
      }
      const key = token.slice(2).replace(/-([a-z0-9])/g, (_, letter) => letter.toUpperCase());
      setSingleton(key, value, token);
      index += 1;
    } else if (token.startsWith('--')) {
      throw new MvxError(`Unknown research option: ${token}`, { code: 'INVALID_CONFIG' });
    } else {
      positionals.push(token);
    }
  }
  return { positionals, options };
}

function rejectUnsupportedOptions(options, allowed, subcommand) {
  const unsupported = Object.keys(options)
    .filter((key) => !allowed.has(key))
    .sort();
  if (unsupported.length > 0) {
    throw new MvxError(`Unsupported research ${subcommand} option(s): ${unsupported.join(', ')}`, {
      code: 'INVALID_CONFIG'
    });
  }
}

function parsePositiveInt(value, flagName) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 1) {
      throw new MvxError(`${flagName} must be a positive integer`, { code: 'INVALID_CONFIG' });
    }
    return value;
  }
  const parsed = Number.parseInt(String(value), 10);
  if (!Number.isSafeInteger(parsed) || String(parsed) !== String(value) || parsed < 1) {
    throw new MvxError(`${flagName} must be a positive integer`, { code: 'INVALID_CONFIG' });
  }
  return parsed;
}

function parseCsvList(value, label) {
  if (Array.isArray(value)) return value.map((item) => String(item).trim()).filter(Boolean);
  if (typeof value !== 'string') {
    throw new MvxError(`${label} must be a comma-separated list`, { code: 'INVALID_CONFIG' });
  }
  const list = value.split(',').map((item) => item.trim()).filter(Boolean);
  if (list.length === 0) {
    throw new MvxError(`${label} cannot be empty`, { code: 'INVALID_CONFIG' });
  }
  return list;
}

function resolveDatasetManifestPaths(rawManifest, manifestFilePath) {
  if (!rawManifest || typeof rawManifest !== 'object' || Array.isArray(rawManifest)) {
    throw new MvxError('Dataset manifest must be a JSON object', { code: 'INVALID_DATASET' });
  }
  assertLabelBlind(rawManifest, 'dataset manifest');
  const baseDir = path.dirname(path.resolve(manifestFilePath));
  const normalizedInput = {
    ...rawManifest,
    samples: Array.isArray(rawManifest.samples)
      ? rawManifest.samples.map((sample) => {
        if (!sample || typeof sample !== 'object' || Array.isArray(sample)) return sample;
        if (typeof sample.artifactPath !== 'string' || sample.artifactPath.length === 0) return sample;
        const resolved = path.isAbsolute(sample.artifactPath)
          ? sample.artifactPath
          : path.resolve(baseDir, sample.artifactPath);
        return { ...sample, artifactPath: resolved };
      })
      : rawManifest.samples
  };
  let validated;
  try {
    validated = validateDatasetManifest(normalizedInput);
  } catch (error) {
    if (error instanceof MvxError && error.code === 'GROUND_TRUTH_FORBIDDEN') throw error;
    throw new MvxError(error.message, { code: 'INVALID_DATASET', cause: error });
  }
  // Preserve optional campaignId metadata for dataset validation inspection
  const campaignBySampleId = new Map();
  for (const sample of rawManifest.samples) {
    if (sample && typeof sample === 'object' && typeof sample.campaignId === 'string' && sample.campaignId.trim().length > 0) {
      campaignBySampleId.set(sample.sampleId, sample.campaignId.trim());
    }
  }
  return { validated, campaignBySampleId };
}

function validateExperimentConfigObject(rawConfig) {
  if (!rawConfig || typeof rawConfig !== 'object' || Array.isArray(rawConfig)) {
    throw new MvxError('Experiment config must be a JSON object', { code: 'INVALID_CONFIG' });
  }
  assertLabelBlind(rawConfig, 'experiment config');
  const allowedKeys = new Set([
    'schemaVersion',
    'experimentId',
    'methods',
    'weightProfiles',
    'scenarioPath',
    'requireManifestV3',
    'acknowledgeRisk',
    'fusionConfig',
    'm2Options',
    'm3Options'
  ]);
  const unknown = Object.getOwnPropertyNames(rawConfig).filter((key) => !allowedKeys.has(key)).sort();
  if (unknown.length > 0) {
    throw new MvxError(`Unknown experiment config key(s): ${unknown.join(', ')}`, { code: 'INVALID_CONFIG' });
  }
  if (rawConfig.schemaVersion !== undefined && rawConfig.schemaVersion !== 1) {
    throw new MvxError('Experiment config schemaVersion must equal 1', { code: 'INVALID_CONFIG' });
  }
  if (rawConfig.methods !== undefined) {
    if (!Array.isArray(rawConfig.methods) || rawConfig.methods.length === 0
      || rawConfig.methods.some((m) => !VALID_METHODS.has(m))) {
      throw new MvxError('Experiment config methods must be a non-empty subset of M1, M2, M3, M4', {
        code: 'INVALID_CONFIG'
      });
    }
  }
  if (rawConfig.weightProfiles !== undefined) {
    if (!Array.isArray(rawConfig.weightProfiles) || rawConfig.weightProfiles.length === 0
      || rawConfig.weightProfiles.some((w) => !VALID_WEIGHTS.has(w))) {
      throw new MvxError('Experiment config weightProfiles must be a non-empty subset of W1-W5', {
        code: 'INVALID_CONFIG'
      });
    }
  }
  if (rawConfig.m2Options !== undefined) {
    if (!rawConfig.m2Options || typeof rawConfig.m2Options !== 'object' || Array.isArray(rawConfig.m2Options)) {
      throw new MvxError('Experiment config m2Options must be an object', { code: 'INVALID_CONFIG' });
    }
  }
  if (rawConfig.m3Options !== undefined) {
    if (!rawConfig.m3Options || typeof rawConfig.m3Options !== 'object' || Array.isArray(rawConfig.m3Options)) {
      throw new MvxError('Experiment config m3Options must be an object', { code: 'INVALID_CONFIG' });
    }
    if (rawConfig.m3Options.repeatCount !== undefined) {
      parsePositiveInt(rawConfig.m3Options.repeatCount, 'm3Options.repeatCount');
    }
    if (rawConfig.m3Options.timeoutMs !== undefined) {
      parsePositiveInt(rawConfig.m3Options.timeoutMs, 'm3Options.timeoutMs');
    }
    if (rawConfig.m3Options.repeatSampleIds !== undefined
      && (!Array.isArray(rawConfig.m3Options.repeatSampleIds)
        || rawConfig.m3Options.repeatSampleIds.some((id) => typeof id !== 'string' || id.length === 0))) {
      throw new MvxError('m3Options.repeatSampleIds must be an array of non-empty strings', {
        code: 'INVALID_CONFIG'
      });
    }
  }
  let validatedFusion = null;
  if (rawConfig.fusionConfig !== undefined && rawConfig.fusionConfig !== null) {
    try {
      validatedFusion = validateFusionConfig(rawConfig.fusionConfig);
    } catch (error) {
      if (error instanceof MvxError && error.code === 'GROUND_TRUTH_FORBIDDEN') throw error;
      throw new MvxError(`Invalid fusionConfig: ${error.message}`, { code: 'INVALID_CONFIG', cause: error });
    }
  }
  return { rawConfig, validatedFusion };
}

function computeExpectedExperimentConfigSha256({
  datasetVersion,
  methods,
  weightProfiles,
  requireManifestV3,
  m2Options,
  m3RepeatCount,
  m3RepeatSampleIds,
  fusionConfig
}) {
  const methodSet = new Set(methods);
  const uniqueMethods = ['M1', 'M2', 'M3', 'M4'].filter((m) => methodSet.has(m));
  const uniqueWeights = [...new Set(weightProfiles)];
  const validatedFusion = methodSet.has('M4') ? validateFusionConfig(fusionConfig) : null;
  const repeatSampleIds = m3RepeatSampleIds ? [...new Set(m3RepeatSampleIds)].sort() : null;
  const identity = {
    profile: EXPERIMENT_PROFILE,
    schemaVersion: EXPERIMENT_SCHEMA_VERSION,
    researchConfigVersion: RESEARCH_CONFIG_VERSION,
    datasetVersion,
    methods: uniqueMethods,
    weightProfiles: uniqueWeights,
    requireManifestV3: requireManifestV3 === true,
    m2Switches: {
      includeManifestStructure: m2Options?.includeManifestStructure === true,
      includeArchiveAuthenticity: m2Options?.includeArchiveAuthenticity === true
    },
    m3RepeatCount: m3RepeatCount ?? 1,
    m3RepeatSampleIds: repeatSampleIds,
    fusionConfigVersion: validatedFusion?.configVersion ?? null,
    fusionConfigSha256: validatedFusion?.sha256 ?? null
  };
  return {
    experimentConfigSha256: sha256(canonicalStringify(identity)),
    fusionConfigSha256: validatedFusion?.sha256 ?? null
  };
}

function attachInterruptController(externalSignal) {
  const controller = new AbortController();
  const onExternalAbort = () => controller.abort();
  const onSigInt = () => controller.abort();
  const onSigTerm = () => controller.abort();
  if (externalSignal) {
    if (externalSignal.aborted) controller.abort();
    else externalSignal.addEventListener('abort', onExternalAbort, { once: true });
  }
  process.on('SIGINT', onSigInt);
  process.on('SIGTERM', onSigTerm);
  return {
    signal: controller.signal,
    cleanup: () => {
      process.off('SIGINT', onSigInt);
      process.off('SIGTERM', onSigTerm);
      if (externalSignal) externalSignal.removeEventListener('abort', onExternalAbort);
    }
  };
}

function verifyArtifactProvenanceMetadata(record) {
  const art = record.artifact;
  if (!art) return true;
  if (art.sampleId !== undefined && art.sampleId !== record.sampleId) return false;
  if (art.method !== undefined && art.method !== record.method) return false;
  if (art.packageSha256 !== undefined && art.packageSha256 !== record.packageSha256) return false;
  if (art.experimentConfigSha256 !== undefined && art.experimentConfigSha256 !== record.experimentConfigSha256) return false;
  if (art.fusionConfigSha256 !== undefined && art.fusionConfigSha256 !== record.fusionConfigSha256) return false;
  return true;
}

function wrapLabRunnerWithTimeout(baseRunner, timeoutMs) {
  if (timeoutMs === undefined || timeoutMs === null) return baseRunner;
  return async (params) => {
    let timer;
    try {
      return await Promise.race([
        Promise.resolve().then(() => baseRunner(params)),
        new Promise((_, reject) => {
          timer = setTimeout(() => {
            reject(new MvxError(`Dynamic M3 execution exceeded configured timeout (${timeoutMs} ms)`, {
              code: 'LAB_TIMEOUT'
            }));
          }, timeoutMs);
        })
      ]);
    } finally {
      clearTimeout(timer);
    }
  };
}

async function loadExperimentDirectory(experimentDir, { verifyArtifacts = true } = {}) {
  const root = path.resolve(experimentDir);
  let dirStat;
  try {
    dirStat = await lstat(root);
  } catch (error) {
    throw new MvxError(`Experiment directory does not exist: ${root}`, {
      code: 'INVALID_CONFIG',
      cause: error
    });
  }
  if (!dirStat.isDirectory()) {
    throw new MvxError(`Experiment path is not a directory: ${root}`, { code: 'INVALID_CONFIG' });
  }

  const manifestPath = path.join(root, 'run_manifest.json');
  const { data: runManifest } = await readJsonFile(manifestPath, 'INVALID_CONFIG', 'run_manifest.json');
  assertLabelBlind(runManifest, 'run_manifest.json');
  if (!runManifest || typeof runManifest !== 'object'
    || typeof runManifest.experimentId !== 'string'
    || !SHA256.test(runManifest.experimentConfigSha256 ?? '')) {
    throw new MvxError('run_manifest.json is missing required experimentId or experimentConfigSha256', {
      code: 'INVALID_CONFIG'
    });
  }

  const runsPath = path.join(root, 'runs.jsonl');
  let records = [];
  try {
    const content = await readFile(runsPath, 'utf8');
    const lines = content.split(/\r?\n/).filter((line) => line.length > 0);
    records = lines.map((line, index) => {
      let parsed;
      try {
        parsed = JSON.parse(line);
      } catch (error) {
        throw new MvxError(`Corrupted JSONL line ${index + 1} in ${runsPath}: ${error.message}`, {
          code: 'CORRUPT_RUN_LOG',
          cause: error
        });
      }
      try {
        validateRunRecord(parsed);
      } catch (error) {
        if (error instanceof MvxError && error.code === 'GROUND_TRUTH_FORBIDDEN') throw error;
        throw new MvxError(`Invalid run record at line ${index + 1}: ${error.message}`, {
          code: 'CORRUPT_RUN_LOG',
          cause: error
        });
      }
      return parsed;
    });
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }

  let provenance;
  try {
    provenance = verifyExperimentProvenance(records, {
      experimentConfigSha256: runManifest.experimentConfigSha256,
      fusionConfigSha256: runManifest.fusionConfigSha256 ?? null
    });
  } catch (error) {
    if (error instanceof MvxError) {
      if (error.code === 'PACKAGE_SHA_MISMATCH') {
        throw new MvxError(error.message, { code: 'HASH_MISMATCH', cause: error });
      }
      if (['DUPLICATE_RUN_ID', 'INVALID_RUN_RECORD', 'INVALID_SCHEMA_VERSION', 'MISSING_METADATA'].includes(error.code)) {
        throw new MvxError(error.message, { code: 'CORRUPT_RUN_LOG', cause: error });
      }
    }
    throw error;
  }

  const artifactPayloads = new Map();
  let artifactsVerified = 0;
  if (verifyArtifacts) {
    for (const record of records) {
      if (!record.artifact?.path) continue;
      const artifactPath = path.resolve(root, record.artifact.path);
      if (!pathsOverlap(root, artifactPath)) {
        throw new MvxError(`Artifact path escapes experiment directory for run ${record.runId}`, {
          code: 'ARTIFACT_HASH_MISMATCH'
        });
      }
      let text;
      try {
        text = await readFile(artifactPath, 'utf8');
      } catch (error) {
        throw new MvxError(`Missing cached artifact for run ${record.runId}: ${record.artifact.path}`, {
          code: 'ARTIFACT_HASH_MISMATCH',
          cause: error
        });
      }
      const actualSha = sha256(text);
      if (actualSha !== record.artifact.sha256) {
        throw new MvxError(
          `Artifact SHA-256 mismatch for run ${record.runId}: expected ${record.artifact.sha256}, observed ${actualSha}`,
          { code: 'ARTIFACT_HASH_MISMATCH' }
        );
      }
      if (!verifyArtifactProvenanceMetadata(record)) {
        throw new MvxError(
          `Artifact provenance metadata mismatch for run ${record.runId}`,
          { code: 'ARTIFACT_HASH_MISMATCH' }
        );
      }
      artifactsVerified += 1;
      try {
        artifactPayloads.set(record.runId, JSON.parse(text));
      } catch (error) {
        throw new MvxError(`Corrupted JSON artifact for run ${record.runId}: ${error.message}`, {
          code: 'ARTIFACT_HASH_MISMATCH',
          cause: error
        });
      }
    }
  }

  let summary = null;
  try {
    summary = JSON.parse(await readFile(path.join(root, 'experiment_summary.json'), 'utf8'));
    assertLabelBlind(summary, 'experiment_summary.json');
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }

  let stabilityFile = null;
  try {
    stabilityFile = JSON.parse(await readFile(path.join(root, 'stability_summary.json'), 'utf8'));
    assertLabelBlind(stabilityFile, 'stability_summary.json');
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }

  let resumeConfig = null;
  try {
    resumeConfig = JSON.parse(await readFile(path.join(root, 'resume_config.json'), 'utf8'));
    assertLabelBlind(resumeConfig, 'resume_config.json');
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }

  return {
    root,
    runManifest,
    records,
    provenance,
    artifactsVerified,
    artifactPayloads,
    summary,
    stabilityFile,
    resumeConfig
  };
}

async function handleValidate(args, options, streams) {
  rejectUnsupportedOptions(
    options,
    new Set(['manifest', 'config', 'requireManifestV3', 'strictHashes', 'acknowledgeRisk', 'format', 'output']),
    'validate'
  );
  if (args.length !== 0) {
    throw new MvxError('research validate accepts options (--manifest <file>) rather than positional arguments', {
      code: 'INVALID_CONFIG'
    });
  }
  if (!options.manifest) {
    throw new MvxError('research validate requires --manifest <file>', { code: 'INVALID_DATASET' });
  }
  const format = options.format ?? 'text';
  if (!['text', 'json'].includes(format)) {
    throw new MvxError(`Unsupported format: ${format}`, { code: 'INVALID_CONFIG' });
  }

  const { data: rawManifest, resolvedPath: manifestPath } = await readJsonFile(
    options.manifest,
    'INVALID_DATASET',
    'dataset manifest'
  );
  const { validated, campaignBySampleId } = resolveDatasetManifestPaths(rawManifest, manifestPath);

  let configSummary = null;
  if (options.config) {
    const { data: rawConfig, resolvedPath: configPath } = await readJsonFile(
      options.config,
      'INVALID_CONFIG',
      'experiment config'
    );
    const { validatedFusion } = validateExperimentConfigObject(rawConfig);
    configSummary = {
      path: configPath,
      valid: true,
      methods: rawConfig.methods ?? ['M1', 'M2', 'M3', 'M4'],
      weightProfiles: rawConfig.weightProfiles ?? ['W1'],
      fusionConfigSha256: validatedFusion?.sha256 ?? null
    };
  }

  const sampleResults = [];
  const cohortCounts = Object.create(null);
  const campaignCounts = Object.create(null);
  let activeCount = 0;
  let skippedCount = 0;
  let mv3CompatibleCount = 0;
  let nonMv3Count = 0;
  let archiveCount = 0;

  for (const sample of validated.samples) {
    cohortCounts[sample.cohort] = (cohortCounts[sample.cohort] ?? 0) + 1;
    const campaignId = campaignBySampleId.get(sample.sampleId) ?? null;
    if (campaignId) campaignCounts[campaignId] = (campaignCounts[campaignId] ?? 0) + 1;

    if (sample.skip) {
      skippedCount += 1;
      sampleResults.push({
        sampleId: sample.sampleId,
        extensionId: sample.extensionId,
        cohort: sample.cohort,
        campaignId,
        status: 'skipped',
        skipReason: sample.skipReason,
        mv3Compatible: null,
        packageSha256: null,
        archiveSha256: null
      });
      continue;
    }

    activeCount += 1;
    if (options.strictHashes && sample.expectedPackageSha256 === null && sample.expectedArchiveSha256 === null) {
      throw new MvxError(`Sample ${sample.sampleId} is missing expectedPackageSha256 and expectedArchiveSha256`, {
        code: 'HASH_MISSING'
      });
    }

    let stat;
    try {
      stat = await lstat(sample.artifactPath);
    } catch (error) {
      throw new MvxError(`Artifact does not exist for sample ${sample.sampleId}: ${sample.artifactPath}`, {
        code: 'INVALID_DATASET',
        cause: error
      });
    }
    if (stat.isSymbolicLink()) {
      throw new MvxError(`Artifact path must not be a symbolic link for sample ${sample.sampleId}`, {
        code: 'INVALID_DATASET'
      });
    }

    const ext = path.extname(sample.artifactPath).toLowerCase();
    const isArchive = stat.isFile() && ['.crx', '.zip'].includes(ext);
    let observedArchiveSha256 = null;
    let observedPackageSha256 = null;
    let manifestVersion = null;

    if (isArchive) {
      archiveCount += 1;
      const archiveBytes = await readFile(sample.artifactPath);
      observedArchiveSha256 = sha256(archiveBytes);
      if (sample.expectedArchiveSha256 !== null && observedArchiveSha256 !== sample.expectedArchiveSha256) {
        throw new MvxError(
          `Archive SHA-256 mismatch for ${sample.sampleId}: expected ${sample.expectedArchiveSha256}, observed ${observedArchiveSha256}`,
          { code: 'HASH_MISMATCH' }
        );
      }
      if (options.acknowledgeRisk) {
        const parent = await resolvePrivateWorkspaceParent(os.tmpdir(), {
          missingMessage: 'Temporary directory does not exist',
          unsafeMessage: 'Temporary directory must be a real directory',
          changedMessage: 'Temporary directory changed during resolution'
        });
        const workspace = await createPrivateWorkspace(parent, 'mvx-val-unpack-', {
          changedMessage: 'Temporary workspace changed during creation',
          cleanupMessage: 'Temporary workspace cleanup failed'
        });
        try {
          const extractedDir = path.join(workspace.path, 'extension');
          await unpackExtensionArchive(sample.artifactPath, extractedDir, {
            expectedArchiveSha256: sample.expectedArchiveSha256 ?? undefined
          });
          const m1 = await runM1PermissionOnly(extractedDir, { sampleId: sample.sampleId, captureFailures: false });
          observedPackageSha256 = m1.provenance.packageSha256;
          manifestVersion = m1.target.manifestVersion;
        } finally {
          await removePrivateWorkspace(workspace, {
            changedMessage: 'Temporary workspace changed before cleanup',
            cleanupMessage: 'Temporary workspace cleanup failed'
          });
        }
      } else if (sample.expectedPackageSha256 !== null) {
        throw new MvxError(
          `Validating expectedPackageSha256 inside packed archive ${sample.sampleId} requires --acknowledge-risk`,
          { code: 'RISK_ACK_REQUIRED' }
        );
      }
    } else if (stat.isDirectory()) {
      let m1;
      try {
        m1 = await runM1PermissionOnly(sample.artifactPath, { sampleId: sample.sampleId, captureFailures: false });
      } catch (error) {
        throw new MvxError(`Invalid extension package for sample ${sample.sampleId}: ${error.message}`, {
          code: 'INVALID_DATASET',
          cause: error
        });
      }
      observedPackageSha256 = m1.provenance.packageSha256;
      manifestVersion = m1.target.manifestVersion;
    } else {
      throw new MvxError(`Unsupported artifact type for sample ${sample.sampleId}: ${sample.artifactPath}`, {
        code: 'INVALID_DATASET'
      });
    }

    if (sample.expectedPackageSha256 !== null
      && observedPackageSha256 !== null
      && observedPackageSha256 !== sample.expectedPackageSha256) {
      throw new MvxError(
        `Package SHA-256 mismatch for ${sample.sampleId}: expected ${sample.expectedPackageSha256}, observed ${observedPackageSha256}`,
        { code: 'HASH_MISMATCH' }
      );
    }

    const mv3Compatible = manifestVersion === null ? null : manifestVersion === 3;
    if (mv3Compatible === true) mv3CompatibleCount += 1;
    if (mv3Compatible === false) {
      nonMv3Count += 1;
      if (options.requireManifestV3) {
        throw new MvxError(
          `Sample ${sample.sampleId} has manifest_version=${manifestVersion}, but --require-manifest-v3 was specified`,
          { code: 'INVALID_DATASET' }
        );
      }
    }

    sampleResults.push({
      sampleId: sample.sampleId,
      extensionId: sample.extensionId,
      cohort: sample.cohort,
      campaignId,
      status: 'valid',
      artifactType: isArchive ? 'archive' : 'directory',
      manifestVersion,
      mv3Compatible,
      packageSha256: observedPackageSha256,
      archiveSha256: observedArchiveSha256
    });
  }

  const report = {
    schemaVersion: RESEARCH_CLI_SCHEMA_VERSION,
    valid: true,
    groundTruthSeparated: true,
    datasetVersion: validated.datasetVersion,
    manifestPath,
    summary: {
      totalSamples: validated.samples.length,
      activeSamples: activeCount,
      skippedSamples: skippedCount,
      archiveSamples: archiveCount,
      mv3CompatibleSamples: mv3CompatibleCount,
      nonMv3Samples: nonMv3Count,
      cohorts: cohortCounts,
      campaigns: campaignCounts
    },
    configValidation: configSummary,
    samples: sampleResults
  };

  const text = [
    `Dataset valid: ${validated.datasetVersion}`,
    `Samples: ${validated.samples.length} total (${activeCount} active, ${skippedCount} skipped, ${mv3CompatibleCount} MV3-compatible, ${nonMv3Count} non-MV3)`,
    `Cohorts: ${Object.entries(cohortCounts).map(([k, v]) => `${k}=${v}`).join(', ') || 'none'}`,
    `Ground Truth separation: verified (no Ground Truth fields present)`,
    ...(configSummary ? [`Experiment config: valid (${configSummary.methods.join(',')} / ${configSummary.weightProfiles.join(',')})`] : [])
  ].join('\n') + '\n';

  await emit(format === 'json' ? json(report) : text, options.output, streams.stdout);
  return 0;
}

async function handleExperiment(args, options, streams, deps) {
  rejectUnsupportedOptions(
    options,
    new Set([
      'manifest', 'output', 'experimentId', 'config', 'methods', 'weights', 'scenario',
      'm3Repeats', 'm3RepeatSamples', 'm3Timeout', 'm3Image', 'fusionConfig',
      'includeManifestStructure', 'includeArchiveAuthenticity', 'requireManifestV3',
      'acknowledgeRisk', 'resume', 'format'
    ]),
    'experiment'
  );
  if (args.length !== 0) {
    throw new MvxError('research experiment uses named flags (--manifest, --output, --experiment-id)', {
      code: 'INVALID_CONFIG'
    });
  }
  const format = options.format ?? 'text';
  if (!['text', 'json'].includes(format)) {
    throw new MvxError(`Unsupported format: ${format}`, { code: 'INVALID_CONFIG' });
  }
  if (!options.manifest) {
    throw new MvxError('research experiment requires --manifest <file>', { code: 'INVALID_DATASET' });
  }
  if (!options.output) {
    throw new MvxError('research experiment requires --output <dir>', { code: 'INVALID_CONFIG' });
  }

  let fileConfig = {};
  let configDir = process.cwd();
  if (options.config) {
    const loaded = await readJsonFile(options.config, 'INVALID_CONFIG', 'experiment config');
    validateExperimentConfigObject(loaded.data);
    fileConfig = loaded.data;
    configDir = path.dirname(loaded.resolvedPath);
  }

  const experimentId = options.experimentId ?? fileConfig.experimentId;
  if (typeof experimentId !== 'string' || !EXPERIMENT_ID_PATTERN.test(experimentId)) {
    throw new MvxError('research experiment requires a valid --experiment-id', { code: 'INVALID_CONFIG' });
  }

  const { data: rawManifest, resolvedPath: manifestPath } = await readJsonFile(
    options.manifest,
    'INVALID_DATASET',
    'dataset manifest'
  );
  const { validated: manifest } = resolveDatasetManifestPaths(rawManifest, manifestPath);

  const methods = options.methods
    ? parseCsvList(options.methods, '--methods')
    : (fileConfig.methods ?? ['M1', 'M2', 'M3', 'M4']);
  if (methods.some((m) => !VALID_METHODS.has(m))) {
    throw new MvxError(`Invalid method in --methods: ${methods.join(',')}`, { code: 'INVALID_CONFIG' });
  }
  const weightProfiles = options.weights
    ? parseCsvList(options.weights, '--weights')
    : (fileConfig.weightProfiles ?? ['W1']);
  if (weightProfiles.some((w) => !VALID_WEIGHTS.has(w))) {
    throw new MvxError(`Invalid weight profile in --weights: ${weightProfiles.join(',')}`, {
      code: 'INVALID_CONFIG'
    });
  }

  const needsM3 = methods.includes('M3') || methods.includes('M4');
  const rawScenario = options.scenario
    ?? (fileConfig.scenarioPath ? path.resolve(configDir, fileConfig.scenarioPath) : undefined);
  const scenarioPath = rawScenario ? path.resolve(rawScenario) : undefined;
  if (needsM3) {
    if (!scenarioPath) {
      throw new MvxError('--scenario <file> is required when M3 or M4 is enabled', { code: 'INVALID_CONFIG' });
    }
    try {
      const scStat = await lstat(scenarioPath);
      if (!scStat.isFile()) {
        throw new MvxError(`Scenario path is not a file: ${scenarioPath}`, { code: 'INVALID_CONFIG' });
      }
    } catch (error) {
      if (error instanceof MvxError) throw error;
      throw new MvxError(`Scenario file not found: ${scenarioPath}`, { code: 'INVALID_CONFIG', cause: error });
    }
  }

  let fusionConfigInput = fileConfig.fusionConfig;
  if (options.fusionConfig) {
    const loadedFusion = await readJsonFile(options.fusionConfig, 'INVALID_CONFIG', 'fusion config');
    assertLabelBlind(loadedFusion.data, 'fusion config');
    fusionConfigInput = loadedFusion.data;
  }
  if (methods.includes('M4')) {
    if (fusionConfigInput === undefined || fusionConfigInput === null) {
      throw new MvxError('--fusion-config <file> (or fusionConfig in --config) is required when M4 is enabled', {
        code: 'INVALID_CONFIG'
      });
    }
    try {
      validateFusionConfig(fusionConfigInput);
    } catch (error) {
      if (error instanceof MvxError && error.code === 'GROUND_TRUTH_FORBIDDEN') throw error;
      throw new MvxError(`Invalid fusion config: ${error.message}`, { code: 'INVALID_CONFIG', cause: error });
    }
  }

  const repeatCount = options.m3Repeats !== undefined
    ? parsePositiveInt(options.m3Repeats, '--m3-repeats')
    : (fileConfig.m3Options?.repeatCount !== undefined
      ? parsePositiveInt(fileConfig.m3Options.repeatCount, 'm3Options.repeatCount')
      : 1);
  const repeatSampleIds = options.m3RepeatSamples !== undefined
    ? parseCsvList(options.m3RepeatSamples, '--m3-repeat-samples')
    : fileConfig.m3Options?.repeatSampleIds;
  const timeoutMs = options.m3Timeout !== undefined
    ? parsePositiveInt(options.m3Timeout, '--m3-timeout')
    : (fileConfig.m3Options?.timeoutMs !== undefined
      ? parsePositiveInt(fileConfig.m3Options.timeoutMs, 'm3Options.timeoutMs')
      : undefined);
  const image = options.m3Image ?? fileConfig.m3Options?.image;

  const requireManifestV3 = options.requireManifestV3 === true || fileConfig.requireManifestV3 === true;
  const acknowledgeRisk = options.acknowledgeRisk === true || fileConfig.acknowledgeRisk === true;
  const resume = options.resume === true;
  const m2Options = {
    ...(fileConfig.m2Options ?? {}),
    includeManifestStructure: options.includeManifestStructure === true
      || fileConfig.m2Options?.includeManifestStructure === true,
    includeArchiveAuthenticity: options.includeArchiveAuthenticity === true
      || fileConfig.m2Options?.includeArchiveAuthenticity === true
  };

  if (needsM3 && !acknowledgeRisk) {
    throw new MvxError('--acknowledge-risk is required when M3 or M4 dynamic analysis is enabled', {
      code: 'RISK_ACK_REQUIRED'
    });
  }

  // Validate pre-existing experiment directory BEFORE runExperimentBatch creates directories
  const experimentRoot = path.resolve(options.output, experimentId);
  if (!resume) {
    try {
      await lstat(experimentRoot);
      throw new MvxError(`Experiment directory already exists (use --resume or 'mvx research resume'): ${experimentRoot}`, {
        code: 'EXPERIMENT_EXISTS'
      });
    } catch (error) {
      if (error instanceof MvxError) throw error;
      if (error?.code !== 'ENOENT') throw error;
    }
  }

  const baseLabRunner = deps?.labRunner ?? runLabContainer;
  const effectiveLabRunner = wrapLabRunnerWithTimeout(baseLabRunner, timeoutMs);
  const m3Options = {
    repeatCount,
    ...(repeatSampleIds ? { repeatSampleIds } : {}),
    ...(image ? { image } : {}),
    ...(needsM3 ? { labRunner: effectiveLabRunner } : {})
  };

  const interrupt = attachInterruptController(deps?.signal);
  const progressEvents = [];
  const onProgress = (event) => {
    progressEvents.push(event);
    if (format === 'text') {
      streams.stdout.write(formatProgressEventText(event));
    }
  };

  let result;
  try {
    result = await runExperimentBatch({
      experimentId,
      outputDir: path.resolve(options.output),
      manifest,
      methods,
      weightProfiles,
      ...(scenarioPath ? { scenarioPath } : {}),
      ...(fusionConfigInput !== undefined ? { fusionConfig: fusionConfigInput } : {}),
      m2Options,
      m3Options,
      requireManifestV3,
      acknowledgeRisk,
      resume,
      onProgress,
      signal: interrupt.signal,
      ...(deps?.skipExternalProbes !== undefined ? { skipExternalProbes: deps.skipExternalProbes } : {})
    });
  } catch (error) {
    if (error instanceof MvxError && error.code === 'PACKAGE_SHA_MISMATCH') {
      throw new MvxError(error.message, { code: 'HASH_MISMATCH', cause: error });
    }
    throw error;
  } finally {
    interrupt.cleanup();
  }

  // Persist label-blind resume configuration snapshot atomically
  const resumeState = {
    schemaVersion: RESEARCH_CLI_SCHEMA_VERSION,
    experimentId,
    experimentConfigSha256: result.manifest.experimentConfigSha256,
    manifestPath,
    manifest,
    methods: result.manifest.methods,
    weightProfiles: result.manifest.weightProfiles,
    scenarioPath: scenarioPath ?? null,
    fusionConfig: fusionConfigInput ?? null,
    m2Options,
    m3Options: {
      repeatCount,
      repeatSampleIds: repeatSampleIds ?? null,
      timeoutMs: timeoutMs ?? null,
      image: image ?? null
    },
    requireManifestV3
  };
  await emit(json(resumeState), path.join(result.experimentRoot, 'resume_config.json'), streams.stdout);

  if (result.summary.containmentViolationObserved) {
    throw new MvxError(
      `Dynamic lab containment violation halted experiment '${experimentId}'; partial evidence persisted at ${result.experimentRoot}`,
      { code: 'LAB_CONTAINMENT_VIOLATION' }
    );
  }

  const outputPayload = {
    schemaVersion: RESEARCH_CLI_SCHEMA_VERSION,
    experimentId: result.manifest.experimentId,
    experimentRoot: result.experimentRoot,
    experimentConfigSha256: result.manifest.experimentConfigSha256,
    datasetVersion: result.manifest.datasetVersion,
    methods: result.manifest.methods,
    weightProfiles: result.manifest.weightProfiles,
    totalSamples: result.summary.totalSamplesInManifest,
    processedSamples: result.summary.processedSamples,
    totalRunRecords: result.summary.totalRunRecords,
    statusCounts: result.summary.statusCounts,
    lifecycleState: result.summary.lifecycleState,
    startedAtUtc: result.summary.startedAtUtc,
    endedAtUtc: result.summary.endedAtUtc,
    wasResumed: result.summary.wasResumed,
    resumeCount: result.summary.resumeCount,
    progressEventsCount: progressEvents.length,
    containmentViolationObserved: result.summary.containmentViolationObserved,
    resumed: result.manifest.resumed
  };

  const statusVerb = result.summary.lifecycleState === 'interrupted'
    ? 'interrupted'
    : (result.manifest.resumed ? 'resumed' : 'completed');
  const text = [
    `Experiment ${statusVerb}: ${result.manifest.experimentId}`,
    `Root: ${result.experimentRoot}`,
    `Config SHA-256: ${result.manifest.experimentConfigSha256}`,
    `Methods: ${result.manifest.methods.join(', ')} | Weights: ${result.manifest.weightProfiles.join(', ')}`,
    `Records: ${result.summary.totalRunRecords} (completed=${result.summary.statusCounts.completed}, fallback=${result.summary.statusCounts.completed_with_static_fallback}, inconclusive=${result.summary.statusCounts.inconclusive}, failed=${result.summary.statusCounts.failed}, skipped=${result.summary.statusCounts.skipped})`
  ].join('\n') + '\n';

  await emit(format === 'json' ? json(outputPayload) : text, undefined, streams.stdout);
  return result.summary.lifecycleState === 'interrupted' ? 1 : 0;
}

async function handleResume(args, options, streams, deps) {
  rejectUnsupportedOptions(
    options,
    new Set(['manifest', 'config', 'm3Timeout', 'acknowledgeRisk', 'format']),
    'resume'
  );
  if (args.length !== 1) {
    throw new MvxError('research resume requires <experiment-dir>', { code: 'INVALID_CONFIG' });
  }
  const format = options.format ?? 'text';
  if (!['text', 'json'].includes(format)) {
    throw new MvxError(`Unsupported format: ${format}`, { code: 'INVALID_CONFIG' });
  }

  // Strictly verify run_manifest.json, runs.jsonl, provenance, and every cached artifact SHA-256
  const loaded = await loadExperimentDirectory(args[0], { verifyArtifacts: true });
  const { root, runManifest, resumeConfig, records } = loaded;

  let manifest = resumeConfig?.manifest ?? null;
  if (options.manifest) {
    const { data: rawManifest, resolvedPath } = await readJsonFile(options.manifest, 'INVALID_DATASET', 'dataset manifest');
    manifest = resolveDatasetManifestPaths(rawManifest, resolvedPath).validated;
  }
  if (!manifest) {
    throw new MvxError('Resume requires resume_config.json inside the experiment directory or an explicit --manifest <file>', {
      code: 'INVALID_DATASET'
    });
  }

  let overrideConfig = {};
  let configDir = root;
  if (options.config) {
    const cfgLoaded = await readJsonFile(options.config, 'INVALID_CONFIG', 'experiment config');
    validateExperimentConfigObject(cfgLoaded.data);
    overrideConfig = cfgLoaded.data;
    configDir = path.dirname(cfgLoaded.resolvedPath);
  }

  const methods = overrideConfig.methods ?? resumeConfig?.methods ?? runManifest.methods;
  const weightProfiles = overrideConfig.weightProfiles ?? resumeConfig?.weightProfiles ?? runManifest.weightProfiles;
  const requireManifestV3 = overrideConfig.requireManifestV3 ?? resumeConfig?.requireManifestV3 ?? runManifest.requireManifestV3 === true;
  const m2Options = overrideConfig.m2Options ?? resumeConfig?.m2Options ?? {};
  const repeatCount = overrideConfig.m3Options?.repeatCount
    ?? resumeConfig?.m3Options?.repeatCount
    ?? runManifest.m3RepeatCount
    ?? 1;
  const repeatSampleIds = overrideConfig.m3Options?.repeatSampleIds
    ?? resumeConfig?.m3Options?.repeatSampleIds
    ?? undefined;
  const timeoutMs = options.m3Timeout !== undefined
    ? parsePositiveInt(options.m3Timeout, '--m3-timeout')
    : (overrideConfig.m3Options?.timeoutMs ?? resumeConfig?.m3Options?.timeoutMs ?? undefined);
  const image = overrideConfig.m3Options?.image ?? resumeConfig?.m3Options?.image ?? undefined;
  const fusionConfig = overrideConfig.fusionConfig !== undefined
    ? overrideConfig.fusionConfig
    : (resumeConfig?.fusionConfig ?? undefined);
  const scenarioPath = overrideConfig.scenarioPath
    ? path.resolve(configDir, overrideConfig.scenarioPath)
    : (resumeConfig?.scenarioPath ?? undefined);

  // Verify configuration SHA-256 BEFORE invoking batch runner
  const expectedSha = computeExpectedExperimentConfigSha256({
    datasetVersion: manifest.datasetVersion,
    methods,
    weightProfiles,
    requireManifestV3,
    m2Options,
    m3RepeatCount: repeatCount,
    m3RepeatSampleIds: repeatSampleIds,
    fusionConfig: fusionConfig ?? undefined
  });
  if (expectedSha.experimentConfigSha256 !== runManifest.experimentConfigSha256) {
    throw new MvxError(
      `Cannot resume '${runManifest.experimentId}': configuration SHA mismatch (${runManifest.experimentConfigSha256} vs ${expectedSha.experimentConfigSha256})`,
      { code: 'CONFIG_MISMATCH' }
    );
  }

  const needsM3 = methods.includes('M3') || methods.includes('M4');
  const acknowledgeRisk = options.acknowledgeRisk === true || overrideConfig.acknowledgeRisk === true;
  if (needsM3 && !acknowledgeRisk) {
    throw new MvxError('--acknowledge-risk is required to resume an experiment with M3 or M4 enabled', {
      code: 'RISK_ACK_REQUIRED'
    });
  }

  const baseLabRunner = deps?.labRunner ?? runLabContainer;
  const effectiveLabRunner = wrapLabRunnerWithTimeout(baseLabRunner, timeoutMs);

  const interrupt = attachInterruptController(deps?.signal);
  const progressEvents = [];
  const onProgress = (event) => {
    progressEvents.push(event);
    if (format === 'text') {
      streams.stdout.write(formatProgressEventText(event));
    }
  };

  let result;
  try {
    result = await runExperimentBatch({
      experimentId: runManifest.experimentId,
      outputDir: path.dirname(root),
      manifest,
      methods,
      weightProfiles,
      ...(scenarioPath ? { scenarioPath } : {}),
      ...(fusionConfig ? { fusionConfig } : {}),
      m2Options,
      m3Options: {
        repeatCount,
        ...(repeatSampleIds ? { repeatSampleIds } : {}),
        ...(image ? { image } : {}),
        ...(needsM3 ? { labRunner: effectiveLabRunner } : {})
      },
      requireManifestV3,
      acknowledgeRisk,
      resume: true,
      onProgress,
      signal: interrupt.signal,
      ...(deps?.skipExternalProbes !== undefined ? { skipExternalProbes: deps.skipExternalProbes } : {})
    });
  } catch (error) {
    if (error instanceof MvxError && error.code === 'PACKAGE_SHA_MISMATCH') {
      throw new MvxError(error.message, { code: 'HASH_MISMATCH', cause: error });
    }
    throw error;
  } finally {
    interrupt.cleanup();
  }

  if (result.summary.containmentViolationObserved) {
    throw new MvxError(
      `Dynamic lab containment violation halted resumed experiment '${runManifest.experimentId}'`,
      { code: 'LAB_CONTAINMENT_VIOLATION' }
    );
  }

  const newRecordsCount = result.records.length - records.length;
  const payload = {
    schemaVersion: RESEARCH_CLI_SCHEMA_VERSION,
    experimentId: runManifest.experimentId,
    experimentRoot: root,
    experimentConfigSha256: runManifest.experimentConfigSha256,
    lifecycleState: result.summary.lifecycleState,
    wasResumed: result.summary.wasResumed,
    resumeCount: result.summary.resumeCount,
    priorRecordCount: records.length,
    newRecordCount: newRecordsCount,
    totalRunRecords: result.records.length,
    artifactsVerifiedBeforeResume: loaded.artifactsVerified,
    progressEventsCount: progressEvents.length,
    statusCounts: result.summary.statusCounts
  };

  const text = [
    `Experiment resumed: ${runManifest.experimentId}`,
    `Config SHA-256: ${runManifest.experimentConfigSha256} (verified)`,
    `Prior records preserved: ${records.length} | New records added: ${newRecordsCount} | Total: ${result.records.length}`,
    `Cached artifacts verified: ${loaded.artifactsVerified}`
  ].join('\n') + '\n';

  await emit(format === 'json' ? json(payload) : text, undefined, streams.stdout);
  return result.summary.lifecycleState === 'interrupted' ? 1 : 0;
}

async function handleStability(args, options, streams) {
  rejectUnsupportedOptions(options, new Set(['output', 'nullToken', 'format']), 'stability');
  if (args.length !== 1) {
    throw new MvxError('research stability requires <experiment-dir>', { code: 'INVALID_CONFIG' });
  }
  const format = options.format ?? 'text';
  if (!['text', 'json'].includes(format)) {
    throw new MvxError(`Unsupported format: ${format}`, { code: 'INVALID_CONFIG' });
  }

  const loaded = await loadExperimentDirectory(args[0], { verifyArtifacts: true });
  const m3Records = loaded.records.filter((record) => record.method === 'M3');
  if (m3Records.length === 0) {
    throw new MvxError('No M3 dynamic run records found for stability analysis', { code: 'INVALID_DATASET' });
  }

  const grouped = new Map();
  for (const record of m3Records) {
    if (!grouped.has(record.sampleId)) grouped.set(record.sampleId, []);
    grouped.get(record.sampleId).push(record);
  }

  const perSample = [];
  for (const sampleId of [...grouped.keys()].sort()) {
    const sampleRuns = grouped.get(sampleId)
      .sort((a, b) => (a.repeatIndex ?? 0) - (b.repeatIndex ?? 0) || a.runId.localeCompare(b.runId))
      .map((record) => {
        const artifact = loaded.artifactPayloads.get(record.runId);
        return {
          ...record,
          contained: artifact?.contained ?? (record.failure?.code === 'LAB_CONTAINMENT_VIOLATION' ? false : true),
          labReport: artifact?.labReport ?? null,
          configSha256: record.experimentConfigSha256
        };
      });
    const requestedRuns = Math.max(loaded.runManifest.m3RepeatCount ?? 1, sampleRuns.length);
    perSample.push(summarizeRepeatedDynamicRuns(sampleRuns, {
      requestedRuns,
      sampleId,
      extensionId: sampleRuns[0].extensionId,
      ...(sampleRuns[0].packageSha256 ? { expectedPackageSha256: sampleRuns[0].packageSha256 } : {}),
      expectedConfigSha256: loaded.runManifest.experimentConfigSha256
    }));
  }

  const overall = computeMultiSampleStabilitySummary(perSample);
  let exportedFiles = null;
  if (options.output) {
    const outDir = path.resolve(options.output);
    await mkdir(outDir, { recursive: true, mode: 0o700 });
    const exported = exportStabilitySummaries(perSample, overall, {
      ...(options.nullToken !== undefined ? { nullToken: options.nullToken } : {})
    });
    const csvPath = path.join(outDir, 'stability_summary.csv');
    const jsonPath = path.join(outDir, 'stability_summary.json');
    await emit(exported.csv, csvPath, streams.stdout);
    await emit(json(exported.json), jsonPath, streams.stdout);
    exportedFiles = {
      csv: { path: csvPath, sha256: sha256(exported.csv) },
      json: { path: jsonPath, sha256: sha256(json(exported.json)) }
    };
  }

  const payload = {
    schemaVersion: RESEARCH_CLI_SCHEMA_VERSION,
    experimentId: loaded.runManifest.experimentId,
    experimentConfigSha256: loaded.runManifest.experimentConfigSha256,
    independentExtensionsEvaluated: overall.extensionsEvaluated,
    overall,
    perSample,
    exportedFiles
  };

  const text = [
    `Stability summary: ${loaded.runManifest.experimentId}`,
    `Independent extensions evaluated: ${overall.extensionsEvaluated} (repeated runs are never counted as independent samples)`,
    `Total M3 runs: ${overall.totalExecutedRuns}/${overall.totalRequestedRuns} executed (${overall.totalCompletedRuns} completed, ${overall.totalInconclusiveRuns} inconclusive, ${overall.totalFailedRuns} failed, ${overall.totalContainmentViolations} containment violations)`,
    `Exact agreement rate: ${overall.overallExactAgreementRate ?? 'null'} | Verdict flips: ${overall.totalVerdictFlips} | Fleiss' kappa: ${overall.fleissKappa ?? 'null'}`,
    ...(exportedFiles ? [`Exported: ${exportedFiles.csv.path}, ${exportedFiles.json.path}`] : [])
  ].join('\n') + '\n';

  await emit(format === 'json' ? json(payload) : text, undefined, streams.stdout);
  return 0;
}

async function handleExport(args, options, streams) {
  rejectUnsupportedOptions(
    options,
    new Set(['output', 'evaluation', 'evaluationOutput', 'nullToken', 'format']),
    'export'
  );
  if (args.length !== 1) {
    throw new MvxError('research export requires <experiment-dir>', { code: 'INVALID_CONFIG' });
  }
  if (!options.output) {
    throw new MvxError('research export requires --output <export-dir>', { code: 'INVALID_CONFIG' });
  }
  const format = options.format ?? 'text';
  if (!['text', 'json'].includes(format)) {
    throw new MvxError(`Unsupported format: ${format}`, { code: 'INVALID_CONFIG' });
  }

  const loaded = await loadExperimentDirectory(args[0], { verifyArtifacts: false });
  const exportDir = path.resolve(options.output);
  if (pathsOverlap(loaded.root, exportDir)) {
    throw new MvxError('Label-blind export directory must be separate from the raw experiment directory', {
      code: 'INVALID_CONFIG'
    });
  }

  const exportOpts = options.nullToken !== undefined ? { nullToken: options.nullToken } : {};
  const bundle = await exportExperimentBundle({
    manifest: loaded.runManifest,
    summary: loaded.summary,
    records: loaded.records,
    stabilitySummaries: loaded.stabilityFile?.perSample ?? []
  }, exportDir, exportOpts);

  let evaluationExport = null;
  if (options.evaluation) {
    const evalOutDir = options.evaluationOutput
      ? path.resolve(options.evaluationOutput)
      : path.resolve(`${exportDir}-evaluation`);
    if (pathsOverlap(evalOutDir, exportDir) || pathsOverlap(evalOutDir, loaded.root)) {
      throw new MvxError(
        'Ground Truth evaluation export directory must be strictly separate from label-blind export and experiment directories',
        { code: 'GROUND_TRUTH_FORBIDDEN' }
      );
    }
    const { data: evalReport } = await readJsonFile(
      options.evaluation,
      'EVALUATION_FAILED',
      'evaluation report'
    );
    const writtenEval = await exportEvaluationTables(evalReport, evalOutDir, exportOpts);
    evaluationExport = {
      outputDir: writtenEval.outputDir,
      files: Object.fromEntries(
        Object.entries(writtenEval.files).map(([name, info]) => [name, { bytes: info.bytes, sha256: info.sha256 }])
      )
    };
  }

  const payload = {
    schemaVersion: RESEARCH_CLI_SCHEMA_VERSION,
    experimentId: loaded.runManifest.experimentId,
    labelBlind: true,
    outputDir: bundle.outputDir,
    manifestSha256: bundle.manifestSha256,
    files: bundle.manifest.files,
    evaluationExport
  };

  const text = [
    `Exported label-blind experiment bundle: ${bundle.outputDir}`,
    `Manifest SHA-256: ${bundle.manifestSha256}`,
    `Files emitted: ${Object.keys(bundle.manifest.files).length}`,
    ...(evaluationExport ? [`Separate Ground Truth evaluation tables exported: ${evaluationExport.outputDir}`] : [])
  ].join('\n') + '\n';

  await emit(format === 'json' ? json(payload) : text, undefined, streams.stdout);
  return 0;
}

async function handleEvaluate(args, options, streams) {
  rejectUnsupportedOptions(
    options,
    new Set(['groundTruth', 'config', 'output', 'nullToken', 'format']),
    'evaluate'
  );
  if (args.length !== 1) {
    throw new MvxError('research evaluate requires <experiment-dir>', { code: 'INVALID_CONFIG' });
  }
  if (!options.groundTruth) {
    throw new MvxError('research evaluate requires an explicit --ground-truth <file>', {
      code: 'INVALID_GROUND_TRUTH'
    });
  }
  if (!options.config) {
    throw new MvxError('research evaluate requires an explicit --config <eval-config.json>', {
      code: 'INVALID_CONFIG'
    });
  }
  if (!options.output) {
    throw new MvxError('research evaluate requires a separate --output <eval-dir>', {
      code: 'INVALID_CONFIG'
    });
  }
  const format = options.format ?? 'text';
  if (!['text', 'json'].includes(format)) {
    throw new MvxError(`Unsupported format: ${format}`, { code: 'INVALID_CONFIG' });
  }

  const loaded = await loadExperimentDirectory(args[0], { verifyArtifacts: false });
  const evalOutDir = path.resolve(options.output);
  if (pathsOverlap(loaded.root, evalOutDir)) {
    throw new MvxError(
      'Evaluation output directory must be strictly separate from the label-blind experiment directory',
      { code: 'GROUND_TRUTH_FORBIDDEN' }
    );
  }

  if (loaded.records.length === 0) {
    throw new MvxError('Cannot evaluate experiment with zero run records', { code: 'EVALUATION_FAILED' });
  }

  const { data: evalConfig } = await readJsonFile(options.config, 'INVALID_CONFIG', 'evaluation config');
  if (!evalConfig || typeof evalConfig !== 'object' || Array.isArray(evalConfig)) {
    throw new MvxError('Evaluation config must be a JSON object', { code: 'INVALID_CONFIG' });
  }
  if (!evalConfig.thresholds || typeof evalConfig.thresholds !== 'object' || Array.isArray(evalConfig.thresholds)) {
    throw new MvxError('Evaluation config must specify pre-registered numeric thresholds for every evaluated method', {
      code: 'INVALID_CONFIG'
    });
  }
  const methodsInExperiment = [...new Set(loaded.records.map((r) => r.method))].sort();
  for (const method of methodsInExperiment) {
    const threshold = evalConfig.thresholds[method];
    if (typeof threshold !== 'number' || !Number.isFinite(threshold)) {
      throw new MvxError(
        `Evaluation config is missing a pre-registered finite threshold for method ${method} (automatic threshold tuning is forbidden)`,
        { code: 'INVALID_CONFIG' }
      );
    }
  }

  const gtPath = path.resolve(options.groundTruth);
  let gtInput;
  try {
    const rawText = await readFile(gtPath, 'utf8');
    gtInput = path.extname(gtPath).toLowerCase() === '.json' ? JSON.parse(rawText) : rawText;
  } catch (error) {
    throw new MvxError(`Unable to load Ground Truth file (${gtPath}): ${error.message}`, {
      code: 'INVALID_GROUND_TRUTH',
      cause: error
    });
  }

  let groundTruthBundle;
  try {
    groundTruthBundle = loadGroundTruth(gtInput);
  } catch (error) {
    throw new MvxError(error.message, { code: 'INVALID_GROUND_TRUTH', cause: error });
  }

  let report;
  try {
    report = evaluateExperimentAgainstGroundTruth({
      records: loaded.records,
      experimentManifest: loaded.runManifest,
      groundTruth: groundTruthBundle,
      evaluationConfig: evalConfig
    });
  } catch (error) {
    if (error instanceof MvxError) {
      if (error.code === 'PACKAGE_SHA_MISMATCH') {
        throw new MvxError(error.message, { code: 'HASH_MISMATCH', cause: error });
      }
      if (error.code === 'INVALID_GROUND_TRUTH') throw error;
      if (error.code === 'INVALID_ARGUMENT') {
        throw new MvxError(error.message, { code: 'INVALID_CONFIG', cause: error });
      }
    }
    throw new MvxError(`Evaluation failed: ${error.message}`, { code: 'EVALUATION_FAILED', cause: error });
  }

  if (report.cohortSummary.eligibleExtensionLevelCount === 0) {
    throw new MvxError(
      `Evaluation failed: 0 of ${report.cohortSummary.totalGroundTruthRecords} Ground Truth records were eligible verified extension-level labels (${report.cohortSummary.excludedCount} excluded)`,
      { code: 'EVALUATION_FAILED' }
    );
  }

  const written = await exportEvaluationTables(report, evalOutDir, {
    ...(options.nullToken !== undefined ? { nullToken: options.nullToken } : {})
  });

  const payload = {
    schemaVersion: RESEARCH_CLI_SCHEMA_VERSION,
    outputDir: written.outputDir,
    files: Object.fromEntries(
      Object.entries(written.files).map(([name, info]) => [name, { bytes: info.bytes, sha256: info.sha256 }])
    ),
    report
  };

  const lines = [
    `Evaluation completed: ${report.provenance.experimentId ?? loaded.runManifest.experimentId}`,
    `Output directory: ${written.outputDir}`,
    `Ground Truth SHA-256: ${report.provenance.groundTruthSha256}`,
    `Experiment Manifest SHA-256: ${report.provenance.experimentManifestSha256}`,
    `Evaluation Config SHA-256: ${report.provenance.evaluationConfigSha256}`,
    `Cohort: ${report.cohortSummary.eligibleExtensionLevelCount}/${report.cohortSummary.totalGroundTruthRecords} eligible (Malicious=${report.cohortSummary.eligiblePositives}, Benign=${report.cohortSummary.eligibleNegatives}, excluded=${report.cohortSummary.excludedCount}, findingLevelSeparated=${report.cohortSummary.findingLevelSeparatedCount})`
  ];
  for (const m of report.methodEvaluations) {
    const b = m.binaryMetrics;
    const r = m.rankingMetrics;
    const undef = [
      b.precision.undefinedReason ? `precision:${b.precision.undefinedReason}` : null,
      b.recall.undefinedReason ? `recall:${b.recall.undefinedReason}` : null,
      b.specificity.undefinedReason ? `specificity:${b.specificity.undefinedReason}` : null,
      b.f1.undefinedReason ? `f1:${b.f1.undefinedReason}` : null,
      b.mcc.undefinedReason ? `mcc:${b.mcc.undefinedReason}` : null,
      r.rocAuc.undefinedReason ? `roc_auc:${r.rocAuc.undefinedReason}` : null,
      r.prAuc.undefinedReason ? `pr_auc:${r.prAuc.undefinedReason}` : null
    ].filter(Boolean);
    lines.push(
      `  ${m.method}${m.weightProfile ? `/${m.weightProfile}` : ''} (thr>=${m.threshold}): n=${b.confusionMatrix.total} (exclNonNum=${m.excludedNonNumericCount}) TP=${b.confusionMatrix.tp} FP=${b.confusionMatrix.fp} TN=${b.confusionMatrix.tn} FN=${b.confusionMatrix.fn} | Prec=${b.precision.value ?? 'null'}(${b.precision.numerator}/${b.precision.denominator}) Rec=${b.recall.value ?? 'null'}(${b.recall.numerator}/${b.recall.denominator}) F1=${b.f1.value ?? 'null'} ROC-AUC=${r.rocAuc.value ?? 'null'} PR-AUC=${r.prAuc.value ?? 'null'}${undef.length ? ` [undefined: ${undef.join(', ')}]` : ''}`
    );
  }
  for (const cmp of report.statisticalComparisons) {
    lines.push(
      `  Stats ${cmp.weightProfile} ${cmp.comparison}: paired=${cmp.mcnemar.pairedSamples}, discordant=${cmp.mcnemar.discordantPairs}, p=${cmp.mcnemar.pValue ?? 'null'}, holm_p=${cmp.adjustedPValue ?? 'null'}, underpowered=${cmp.mcnemar.underpowered}`
    );
  }

  await emit(format === 'json' ? json(payload) : `${lines.join('\n')}\n`, undefined, streams.stdout);
  return 0;
}

async function probePathInfo(targetPath) {
  try {
    const resolved = path.resolve(targetPath);
    const stat = await lstat(resolved);
    return { path: resolved, exists: true, isDirectory: stat.isDirectory(), isFile: stat.isFile() };
  } catch {
    return { path: path.resolve(targetPath), exists: false, isDirectory: false, isFile: false };
  }
}

async function handleInspect(args, options, streams) {
  rejectUnsupportedOptions(options, new Set(['exportDir', 'evaluationDir', 'format']), 'inspect');
  if (args.length !== 1) {
    throw new MvxError('research inspect requires <experiment-dir>', { code: 'INVALID_CONFIG' });
  }
  const format = options.format ?? 'text';
  if (!['text', 'json'].includes(format)) {
    throw new MvxError(`Unsupported format: ${format}`, { code: 'INVALID_CONFIG' });
  }

  const loaded = await loadExperimentDirectory(args[0], { verifyArtifacts: false });
  const statusDistribution = {
    completed: 0,
    completed_with_static_fallback: 0,
    inconclusive: 0,
    failed: 0,
    skipped: 0
  };
  const failureCodes = Object.create(null);
  const sampleIds = new Set();
  let containmentViolations = 0;
  let artifactsChecked = 0;
  let artifactHashMismatches = 0;
  let artifactMetadataMismatches = 0;

  for (const record of loaded.records) {
    sampleIds.add(record.sampleId);
    statusDistribution[record.status] = (statusDistribution[record.status] ?? 0) + 1;
    if (record.failure?.code) {
      failureCodes[record.failure.code] = (failureCodes[record.failure.code] ?? 0) + 1;
    }
    if (record.failure?.code === 'LAB_CONTAINMENT_VIOLATION') {
      containmentViolations += 1;
    }
    if (record.artifact?.path) {
      artifactsChecked += 1;
      if (!verifyArtifactProvenanceMetadata(record)) artifactMetadataMismatches += 1;
      try {
        const text = await readFile(path.resolve(loaded.root, record.artifact.path), 'utf8');
        if (sha256(text) !== record.artifact.sha256) artifactHashMismatches += 1;
      } catch {
        artifactHashMismatches += 1;
      }
    }
  }

  const stabilityPath = path.join(loaded.root, 'stability_summary.json');
  const stabilityAvailable = loaded.stabilityFile !== null;
  const progressPath = path.join(loaded.root, 'progress.jsonl');
  const progressLog = await probePathInfo(progressPath);
  const exportLocation = options.exportDir
    ? await probePathInfo(options.exportDir)
    : await probePathInfo(path.join(path.dirname(loaded.root), `${loaded.runManifest.experimentId}-export`));
  const evaluationLocation = options.evaluationDir
    ? await probePathInfo(options.evaluationDir)
    : await probePathInfo(path.join(path.dirname(loaded.root), `${loaded.runManifest.experimentId}-evaluation`));

  const env = loaded.summary?.environment ?? loaded.runManifest.environment ?? null;
  const lifecycleState = loaded.summary?.lifecycleState ?? loaded.runManifest.lifecycleState ?? 'unknown';

  const inspection = {
    schemaVersion: RESEARCH_CLI_SCHEMA_VERSION,
    labelBlind: true,
    experiment: {
      experimentId: loaded.runManifest.experimentId,
      root: loaded.root,
      experimentConfigSha256: loaded.runManifest.experimentConfigSha256,
      createdAtUtc: loaded.runManifest.createdAtUtc ?? null,
      startedAtUtc: loaded.summary?.startedAtUtc ?? loaded.runManifest.startedAtUtc ?? null,
      endedAtUtc: loaded.summary?.endedAtUtc ?? loaded.runManifest.endedAtUtc ?? null,
      lifecycleState,
      resumed: loaded.runManifest.resumed === true,
      wasResumed: loaded.summary?.wasResumed ?? loaded.runManifest.wasResumed === true,
      resumeCount: loaded.summary?.resumeCount ?? loaded.runManifest.resumeCount ?? 0,
      lifecycleHistory: loaded.summary?.lifecycleHistory ?? loaded.runManifest.lifecycleHistory ?? [],
      mvxVersion: loaded.runManifest.mvxVersion,
      mvxBaseCommit: loaded.runManifest.mvxBaseCommit,
      fusionConfigVersion: loaded.runManifest.fusionConfigVersion ?? null,
      fusionConfigSha256: loaded.runManifest.fusionConfigSha256 ?? null
    },
    environment: env,
    dataset: {
      datasetVersion: loaded.runManifest.datasetVersion,
      manifestSampleCount: loaded.runManifest.sampleCount,
      observedSampleCount: sampleIds.size
    },
    configuration: {
      methods: loaded.runManifest.methods,
      weightProfiles: loaded.runManifest.weightProfiles,
      requireManifestV3: loaded.runManifest.requireManifestV3 === true,
      m3RepeatCount: loaded.runManifest.m3RepeatCount ?? 1
    },
    runs: {
      totalRecords: loaded.records.length,
      statusDistribution,
      failedCount: statusDistribution.failed,
      inconclusiveCount: statusDistribution.inconclusive,
      failureCodes,
      containmentViolations,
      haltedEarly: loaded.summary?.haltedEarly === true,
      haltReason: loaded.summary?.haltReason ?? loaded.runManifest.haltReason ?? null
    },
    provenanceValidation: {
      valid: loaded.provenance.valid && artifactHashMismatches === 0 && artifactMetadataMismatches === 0,
      recordCount: loaded.provenance.recordCount,
      uniqueRunIds: loaded.provenance.uniqueRunIds,
      uniqueSamplesWithHash: loaded.provenance.uniqueSamplesWithHash,
      artifactsChecked,
      artifactHashMismatches,
      artifactMetadataMismatches
    },
    stability: {
      available: stabilityAvailable,
      path: stabilityAvailable ? stabilityPath : null,
      extensionsEvaluated: loaded.stabilityFile?.overall?.extensionsEvaluated ?? null
    },
    artifacts: {
      runManifest: path.join(loaded.root, 'run_manifest.json'),
      runsJsonl: path.join(loaded.root, 'runs.jsonl'),
      progressJsonl: progressLog.exists ? progressPath : null,
      exportLocation,
      evaluationLocation
    }
  };

  const text = [
    `Experiment: ${inspection.experiment.experimentId} (label-blind inspection)`,
    `Root: ${inspection.experiment.root}`,
    `Lifecycle: ${lifecycleState} (wasResumed=${inspection.experiment.wasResumed}, resumeCount=${inspection.experiment.resumeCount})`,
    `Config SHA-256: ${inspection.experiment.experimentConfigSha256}`,
    `Dataset: ${inspection.dataset.datasetVersion} (${inspection.dataset.observedSampleCount}/${inspection.dataset.manifestSampleCount} samples observed)`,
    `Methods: ${inspection.configuration.methods.join(', ')} | Weights: ${inspection.configuration.weightProfiles.join(', ')}`,
    `Run statuses: completed=${statusDistribution.completed}, fallback=${statusDistribution.completed_with_static_fallback}, inconclusive=${statusDistribution.inconclusive}, failed=${statusDistribution.failed}, skipped=${statusDistribution.skipped}`,
    `Containment violations: ${containmentViolations}`,
    `Provenance: ${inspection.provenanceValidation.valid ? 'VALID' : 'INVALID'} (${artifactsChecked} artifacts checked, ${artifactHashMismatches} hash mismatches, ${artifactMetadataMismatches} metadata mismatches)`,
    `Stability summary: ${stabilityAvailable ? `available (${stabilityPath})` : 'not present'}`,
    `Export location: ${exportLocation.path} (${exportLocation.exists ? 'present' : 'not found'})`,
    `Evaluation location: ${evaluationLocation.path} (${evaluationLocation.exists ? 'present' : 'not found'}; Ground Truth labels not loaded)`
  ].join('\n') + '\n';

  await emit(format === 'json' ? json(inspection) : text, undefined, streams.stdout);
  return 0;
}

export async function runResearchCli(argv, streams = process, deps = {}) {
  try {
    const { positionals, options } = parseResearchArgs(argv);
    if (options.help || positionals.length === 0) {
      streams.stdout.write(RESEARCH_HELP);
      return 0;
    }
    const [subcommand, ...args] = positionals;
    if (subcommand === 'validate') return await handleValidate(args, options, streams);
    if (subcommand === 'experiment') return await handleExperiment(args, options, streams, deps);
    if (subcommand === 'resume') return await handleResume(args, options, streams, deps);
    if (subcommand === 'stability') return await handleStability(args, options, streams);
    if (subcommand === 'export') return await handleExport(args, options, streams);
    if (subcommand === 'evaluate') return await handleEvaluate(args, options, streams);
    if (subcommand === 'inspect') return await handleInspect(args, options, streams);

    throw new MvxError(
      `Unknown research subcommand: ${subcommand} (expected validate, experiment, resume, stability, export, evaluate, or inspect)`,
      { code: 'INVALID_CONFIG' }
    );
  } catch (error) {
    const raw = error instanceof MvxError
      ? `${error.code}: ${error.message}`
      : `UNEXPECTED_ERROR: ${error.message}`;
    streams.stderr.write(`${redactSensitiveText(raw)}\n`);
    return 2;
  }
}
