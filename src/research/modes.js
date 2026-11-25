import { createHash } from 'node:crypto';
import { lstat, readdir, readlink, realpath } from 'node:fs/promises';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { runLabContainer } from '../../scripts/run-lab.mjs';
import { analyzeIntegrity } from '../analyzer.js';
import { analyzeStaticDnrRules } from '../dnr-rules.js';
import { analyzeEncodedPayloads } from '../encoded-payloads.js';
import { MvxError } from '../errors.js';
import { loadExtension, normalizeScanLimits } from '../io.js';
import {
  DEFAULT_SCORE_CAP,
  DEFAULT_WEIGHT_PROFILE,
  WEIGHT_PROFILES,
  resolveWeightProfile,
  sortFindings,
  summarizeFindings
} from '../model.js';
import { assertOptionsObject } from '../options.js';
import { packageInventory } from '../package.js';
import { resolveRulePacks } from '../rule-packs.js';
import { analyzeArchiveAuthenticity } from '../rules/archive-rules.js';
import {
  NON_PERMISSION_MANIFEST_RULE_IDS,
  PERMISSION_RULE_IDS,
  analyzeNonPermissionManifestRules,
  analyzePermissionRules,
  hostPermissions
} from '../rules/manifest-rules.js';
import { analyzePackage } from '../rules/package-rules.js';
import { analyzeSources } from '../rules/source-rules.js';
import { analyzeCustomRules } from '../rules/custom-rules.js';
import { readBoundedRegularFile } from '../safe-file.js';
import { VERSION } from '../version.js';
import {
  DYNAMIC_VERDICT_SCORES,
  MANIFEST_STRUCTURE_RULE_IDS,
  RESEARCH_CONFIG_SCHEMA_VERSION,
  RESEARCH_CONFIG_VERSION,
  RESEARCH_MODES,
  SCORE_INTERPRETATION_NOTICE
} from './config.js';

const WEIGHT_PROFILE_IDS = Object.freeze(Object.keys(WEIGHT_PROFILES));
const PERMISSION_RULE_SET = new Set(PERMISSION_RULE_IDS);
const MANIFEST_STRUCTURE_RULE_SET = new Set(MANIFEST_STRUCTURE_RULE_IDS);
const SHA256 = /^[a-f0-9]{64}$/;

const M1_OPTIONS = new Set([
  'captureFailures',
  'limits',
  'sampleId',
  'scoreCap',
  'weightProfile',
  'weights'
]);

const M2_OPTIONS = new Set([
  '_preparedRulePacks',
  'archiveAuthenticity',
  'captureFailures',
  'dnrRuleLimits',
  'includeArchiveAuthenticity',
  'includeManifestStructure',
  'limits',
  'rulePackLimits',
  'rulePacks',
  'sampleId',
  'scoreCap',
  'weightProfile',
  'weights'
]);

const M3_OPTIONS = new Set([
  'acknowledgeRisk',
  'captureFailures',
  'expectedPackageSha256',
  'image',
  'labRunner',
  'repeatIndex',
  'sampleId'
]);

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function rejectUnknownOptions(options, allowed, label) {
  assertOptionsObject(options, label);
  const unknown = Object.getOwnPropertyNames(options)
    .filter((key) => !allowed.has(key))
    .sort(compareText);
  if (unknown.length > 0) {
    throw new MvxError(`Unknown ${label} option(s): ${unknown.join(', ')}`, {
      code: 'INVALID_ARGUMENT'
    });
  }
}

function assertOptionalBoolean(value, name) {
  if (value !== undefined && typeof value !== 'boolean') {
    throw new MvxError(`${name} must be boolean`, { code: 'INVALID_ARGUMENT' });
  }
}

function assertOptionalNonEmptyString(value, name) {
  if (value !== undefined && (typeof value !== 'string' || value.length === 0)) {
    throw new MvxError(`${name} must be a non-empty string`, { code: 'INVALID_ARGUMENT' });
  }
}

function validateScoringOptions(options) {
  if (options.weightProfile !== undefined && options.weights !== undefined) {
    throw new MvxError('Specify either weightProfile or weights, not both', {
      code: 'INVALID_ARGUMENT'
    });
  }
  const resolved = options.weights !== undefined
    ? resolveWeightProfile(options.weights)
    : resolveWeightProfile(options.weightProfile ?? DEFAULT_WEIGHT_PROFILE);
  const scoreCap = options.scoreCap ?? DEFAULT_SCORE_CAP;
  if (typeof scoreCap !== 'number' || !Number.isFinite(scoreCap) || scoreCap <= 0) {
    throw new MvxError('scoreCap must be a positive finite number', {
      code: 'INVALID_ARGUMENT'
    });
  }
  return {
    weightProfile: resolved.weightProfile,
    weights: resolved.weights,
    scoreCap,
    summaryOptions: options.weights !== undefined
      ? { weights: resolved.weights, scoreCap }
      : { weightProfile: resolved.weightProfile, scoreCap }
  };
}

function computeScoresByWeight(findings, scoreCap) {
  return Object.freeze(Object.fromEntries(
    WEIGHT_PROFILE_IDS.map((profileId) => [
      profileId,
      summarizeFindings(findings, { weightProfile: profileId, scoreCap })
    ])
  ));
}

function declaredApiPermissions(manifest) {
  return [
    ...(Array.isArray(manifest.permissions) ? manifest.permissions : []),
    ...(Array.isArray(manifest.optional_permissions) ? manifest.optional_permissions : [])
  ].filter((permission) => typeof permission === 'string' && permission !== '<all_urls>' && !permission.includes('://'));
}

async function resolveExtensionRoot(inputPath) {
  if (typeof inputPath !== 'string' || inputPath.length === 0) {
    throw new MvxError('Extension path must be a non-empty string', { code: 'INVALID_ARGUMENT' });
  }
  const absolute = path.resolve(inputPath);
  let stat;
  try {
    stat = await lstat(absolute);
  } catch (error) {
    throw new MvxError(`Input does not exist: ${absolute}`, { code: 'INPUT_NOT_FOUND', cause: error });
  }
  if (stat.isSymbolicLink()) {
    throw new MvxError('The extension root may not be a symbolic link', { code: 'UNSAFE_INPUT' });
  }
  if (stat.isFile()) {
    if (path.basename(absolute) !== 'manifest.json') {
      throw new MvxError('A file input must be named manifest.json', { code: 'INVALID_INPUT' });
    }
    const root = path.dirname(absolute);
    const rootStat = await lstat(root);
    if (rootStat.isSymbolicLink()) {
      throw new MvxError('The extension root may not be a symbolic link', { code: 'UNSAFE_INPUT' });
    }
    return { root, manifestPath: absolute };
  }
  if (!stat.isDirectory()) {
    throw new MvxError('Input must be an extension directory or manifest.json', { code: 'INVALID_INPUT' });
  }
  return { root: absolute, manifestPath: path.join(absolute, 'manifest.json') };
}

async function walkPackageInventoryOnly(root, current, state, limits, manifestBytes, depth = 0) {
  if (depth > limits.maxDepth) {
    throw new MvxError(`Extension directory depth exceeds ${limits.maxDepth}`, { code: 'SCAN_LIMIT' });
  }
  const entries = await readdir(current, { withFileTypes: true });
  entries.sort((left, right) => compareText(left.name, right.name));
  for (const entry of entries) {
    state.entryCount += 1;
    if (state.entryCount > limits.maxEntries) {
      throw new MvxError(`Extension contains more than ${limits.maxEntries} entries`, { code: 'SCAN_LIMIT' });
    }
    const absolute = path.join(current, entry.name);
    const relative = path.relative(root, absolute).split(path.sep).join('/');
    if (entry.isSymbolicLink()) {
      const target = await readlink(absolute, { encoding: 'buffer' });
      state.inventory.push({
        path: relative,
        type: 'symlink',
        targetBytes: target.length,
        targetSha256: sha256(target)
      });
      state.warnings.push(`Skipped symbolic link: ${relative}`);
      continue;
    }
    if (entry.isDirectory()) {
      state.inventory.push({ path: relative, type: 'directory' });
      await walkPackageInventoryOnly(root, absolute, state, limits, manifestBytes, depth + 1);
      continue;
    }
    if (!entry.isFile()) {
      state.inventory.push({ path: relative, type: 'other' });
      state.warnings.push(`Skipped non-regular filesystem entry: ${relative}`);
      continue;
    }
    if (state.fileCount >= limits.maxFiles) {
      throw new MvxError(`Extension contains more than ${limits.maxFiles} files`, { code: 'SCAN_LIMIT' });
    }
    state.fileCount += 1;
    const bytes = relative === 'manifest.json'
      ? manifestBytes
      : await readBoundedRegularFile(absolute, {
        maxBytes: limits.maxPackageFileBytes,
        label: `Package file ${relative}`,
        missingCode: 'INVALID_INPUT'
      });
    if (state.packageBytes + bytes.length > limits.maxPackageBytes) {
      throw new MvxError(`Package content exceeds ${limits.maxPackageBytes} bytes`, { code: 'SCAN_LIMIT' });
    }
    state.packageBytes += bytes.length;
    state.inventory.push({
      path: relative,
      type: 'file',
      bytes: bytes.length,
      sha256: sha256(bytes)
    });
  }
}

async function loadManifestAndPackageInventory(inputPath, limitOptions = {}) {
  const limits = normalizeScanLimits(limitOptions);
  const { root, manifestPath } = await resolveExtensionRoot(inputPath);
  let manifestStat;
  try {
    manifestStat = await lstat(manifestPath);
  } catch (error) {
    throw new MvxError(`Cannot read manifest: ${manifestPath}`, { code: 'MANIFEST_NOT_FOUND', cause: error });
  }
  if (manifestStat.isSymbolicLink()) {
    throw new MvxError('manifest.json may not be a symbolic link', { code: 'UNSAFE_INPUT' });
  }
  if (!manifestStat.isFile()) {
    throw new MvxError('manifest.json must be a regular file', { code: 'UNSAFE_INPUT' });
  }
  const manifestBytes = await readBoundedRegularFile(manifestPath, {
    maxBytes: Math.min(limits.maxFileBytes, limits.maxPackageFileBytes),
    label: 'manifest.json',
    missingCode: 'MANIFEST_NOT_FOUND'
  });
  let manifest;
  try {
    manifest = JSON.parse(manifestBytes.toString('utf8'));
  } catch (error) {
    throw new MvxError(`Invalid JSON in ${manifestPath}: ${error.message}`, { code: 'INVALID_MANIFEST', cause: error });
  }
  if (!manifest || Array.isArray(manifest) || typeof manifest !== 'object') {
    throw new MvxError('manifest.json must contain a JSON object', { code: 'INVALID_MANIFEST' });
  }
  const state = {
    entryCount: 0,
    fileCount: 0,
    packageBytes: 0,
    inventory: [],
    warnings: []
  };
  await walkPackageInventoryOnly(root, root, state, limits, manifestBytes);
  return {
    root: await realpath(root),
    manifest,
    manifestBytes: manifestBytes.length,
    manifestSha256: sha256(manifestBytes),
    inventory: packageInventory(state.inventory),
    warnings: state.warnings,
    limits
  };
}

function serializeFailure(error) {
  return {
    code: typeof error?.code === 'string' ? error.code : 'UNEXPECTED_ERROR',
    message: String(error?.message ?? error)
  };
}

function buildFailureEnvelope({ mode, sampleId, runtimeMs, error, extra = {} }) {
  return {
    schemaVersion: 1,
    mode,
    status: 'failed',
    sampleId: sampleId ?? null,
    tool: { name: 'mvx-audit', version: VERSION },
    researchConfig: {
      schemaVersion: RESEARCH_CONFIG_SCHEMA_VERSION,
      configVersion: RESEARCH_CONFIG_VERSION
    },
    summary: null,
    scoresByWeight: null,
    riskScore: null,
    failure: serializeFailure(error),
    runtimeMs,
    ...extra
  };
}

export async function runM1PermissionOnly(inputPath, options = {}) {
  rejectUnknownOptions(options, M1_OPTIONS, 'M1 permission-only');
  assertOptionalBoolean(options.captureFailures, 'captureFailures');
  assertOptionalNonEmptyString(options.sampleId, 'sampleId');
  const scoring = validateScoringOptions(options);
  const captureFailures = options.captureFailures === true;
  const started = performance.now();

  try {
    const loaded = await loadManifestAndPackageInventory(inputPath, options.limits ?? {});
    const findings = sortFindings(analyzePermissionRules(loaded.manifest));
    for (const finding of findings) {
      if (!PERMISSION_RULE_SET.has(finding.id)) {
        throw new MvxError(`M1 rule isolation violation: unexpected rule ${finding.id}`, {
          code: 'RULE_ISOLATION_VIOLATION'
        });
      }
    }
    const summary = summarizeFindings(findings, scoring.summaryOptions);
    const scoresByWeight = computeScoresByWeight(findings, scoring.scoreCap);
    const runtimeMs = Number((performance.now() - started).toFixed(3));
    return {
      schemaVersion: 1,
      mode: 'M1',
      status: 'completed',
      sampleId: options.sampleId ?? null,
      tool: { name: 'mvx-audit', version: VERSION },
      researchConfig: {
        schemaVersion: RESEARCH_CONFIG_SCHEMA_VERSION,
        configVersion: RESEARCH_CONFIG_VERSION,
        weightProfile: scoring.weightProfile,
        scoreCap: scoring.scoreCap
      },
      target: {
        root: loaded.root,
        name: loaded.manifest.name ?? null,
        version: loaded.manifest.version ?? null,
        manifestVersion: loaded.manifest.manifest_version ?? null
      },
      capabilities: {
        permissions: [...new Set(declaredApiPermissions(loaded.manifest))].sort(),
        hostPermissions: hostPermissions(loaded.manifest)
      },
      package: loaded.inventory,
      provenance: {
        packageSha256: loaded.inventory.sha256,
        packageProfile: loaded.inventory.profile,
        manifestSha256: loaded.manifestSha256,
        manifestBytes: loaded.manifestBytes,
        configVersion: RESEARCH_CONFIG_VERSION,
        toolVersion: VERSION,
        includedRuleIds: PERMISSION_RULE_IDS,
        excludedRuleIds: RESEARCH_MODES.M1.excludedRuleIds,
        sourceAnalysisExecuted: false,
        encodedPayloadAnalysisExecuted: false,
        dnrAnalysisExecuted: false
      },
      summary,
      scoresByWeight,
      findings,
      warnings: loaded.warnings,
      runtimeMs,
      assumptions: [
        SCORE_INTERPRETATION_NOTICE,
        'M1 inspects declared permissions and host permissions only; source code, Base64 payloads, DNR rulesets, and runtime behavior are not analyzed.'
      ]
    };
  } catch (error) {
    if (!captureFailures || error?.code === 'INVALID_ARGUMENT' || error?.code === 'RULE_ISOLATION_VIOLATION') {
      throw error;
    }
    const runtimeMs = Number((performance.now() - started).toFixed(3));
    return buildFailureEnvelope({
      mode: 'M1',
      sampleId: options.sampleId,
      runtimeMs,
      error,
      extra: {
        provenance: {
          packageSha256: null,
          configVersion: RESEARCH_CONFIG_VERSION,
          toolVersion: VERSION,
          sourceAnalysisExecuted: false,
          encodedPayloadAnalysisExecuted: false,
          dnrAnalysisExecuted: false
        }
      }
    });
  }
}

export async function runM2StaticOnly(inputPath, options = {}) {
  rejectUnknownOptions(options, M2_OPTIONS, 'M2 static-only');
  assertOptionalBoolean(options.captureFailures, 'captureFailures');
  assertOptionalBoolean(options.includeManifestStructure, 'includeManifestStructure');
  assertOptionalBoolean(options.includeArchiveAuthenticity, 'includeArchiveAuthenticity');
  assertOptionalNonEmptyString(options.sampleId, 'sampleId');
  const scoring = validateScoringOptions(options);
  const captureFailures = options.captureFailures === true;
  const includeManifestStructure = options.includeManifestStructure === true;
  const includeArchiveAuthenticity = options.includeArchiveAuthenticity === true;
  if (includeArchiveAuthenticity && options.archiveAuthenticity !== undefined) {
    assertOptionsObject(options.archiveAuthenticity, 'M2 archiveAuthenticity');
  }
  const started = performance.now();

  try {
    const preparedRulePacks = await resolveRulePacks(options);
    const snapshot = await loadExtension(inputPath, options.limits ?? {}, {
      rulePacks: preparedRulePacks.provenance,
      rulePackLimits: preparedRulePacks.limits,
      dnrRuleLimits: options.dnrRuleLimits ?? {}
    });

    const manifestStructureFindings = includeManifestStructure
      ? analyzeNonPermissionManifestRules(snapshot.manifest)
        .filter((finding) => MANIFEST_STRUCTURE_RULE_SET.has(finding.id))
      : [];
    const archiveAuthenticityFindings = includeArchiveAuthenticity && options.archiveAuthenticity
      ? analyzeArchiveAuthenticity(
        options.archiveAuthenticity.authenticity,
        options.archiveAuthenticity.format ?? 'crx'
      )
      : [];

    const findings = sortFindings([
      ...analyzeIntegrity(snapshot.manifest, snapshot.files),
      ...analyzePackage(snapshot.executableFiles),
      ...analyzeStaticDnrRules(snapshot.dnrRules),
      ...analyzeSources([...snapshot.sources, ...snapshot.decodedSources]),
      ...analyzeEncodedPayloads(snapshot.encodedPayloads),
      ...analyzeCustomRules(snapshot, preparedRulePacks),
      ...manifestStructureFindings,
      ...archiveAuthenticityFindings
    ]);

    for (const finding of findings) {
      if (PERMISSION_RULE_SET.has(finding.id)) {
        throw new MvxError(`M2 rule isolation violation: permission rule ${finding.id} emitted`, {
          code: 'RULE_ISOLATION_VIOLATION'
        });
      }
    }

    const summary = summarizeFindings(findings, scoring.summaryOptions);
    const scoresByWeight = computeScoresByWeight(findings, scoring.scoreCap);
    const runtimeMs = Number((performance.now() - started).toFixed(3));
    const includedRuleIds = Object.freeze([
      ...RESEARCH_MODES.M2.ruleIds.filter((id) => id !== 'MVX004' || includeArchiveAuthenticity),
      ...(includeManifestStructure ? MANIFEST_STRUCTURE_RULE_IDS : [])
    ]);
    const excludedRuleIds = Object.freeze([
      ...PERMISSION_RULE_IDS,
      ...NON_PERMISSION_MANIFEST_RULE_IDS.filter(
        (id) => !includeManifestStructure || !MANIFEST_STRUCTURE_RULE_SET.has(id)
      ),
      ...(!includeArchiveAuthenticity ? ['MVX004'] : [])
    ]);

    return {
      schemaVersion: 1,
      mode: 'M2',
      status: 'completed',
      sampleId: options.sampleId ?? null,
      tool: { name: 'mvx-audit', version: VERSION },
      researchConfig: {
        schemaVersion: RESEARCH_CONFIG_SCHEMA_VERSION,
        configVersion: RESEARCH_CONFIG_VERSION,
        weightProfile: scoring.weightProfile,
        scoreCap: scoring.scoreCap,
        switches: {
          includeManifestStructure,
          includeArchiveAuthenticity
        }
      },
      target: {
        root: snapshot.root,
        name: snapshot.manifest.name ?? null,
        version: snapshot.manifest.version ?? null,
        manifestVersion: snapshot.manifest.manifest_version ?? null
      },
      package: snapshot.inventory,
      analysis: snapshot.provenance,
      dnrRules: snapshot.dnrRules,
      encodedPayloads: {
        profile: snapshot.encodedPayloads.profile,
        decodedCount: snapshot.encodedPayloads.decodedCount,
        utf8Count: snapshot.encodedPayloads.utf8Count,
        totalDecodedBytes: snapshot.encodedPayloads.totalDecodedBytes,
        sha256: snapshot.encodedPayloads.sha256
      },
      provenance: {
        packageSha256: snapshot.inventory.sha256,
        packageProfile: snapshot.inventory.profile,
        analysisSha256: snapshot.provenance.sha256,
        analysisProfile: snapshot.provenance.profile,
        manifestSha256: snapshot.provenance.manifest.sha256,
        encodedPayloadsSha256: snapshot.encodedPayloads.sha256,
        dnrRulesSha256: snapshot.dnrRules.sha256,
        configVersion: RESEARCH_CONFIG_VERSION,
        toolVersion: VERSION,
        includedRuleIds,
        excludedRuleIds,
        permissionAnalysisExecuted: false,
        unresolvedDecisionSwitches: {
          OD1_includeManifestStructure: includeManifestStructure,
          OD2_includeArchiveAuthenticity: includeArchiveAuthenticity
        }
      },
      summary,
      scoresByWeight,
      findings,
      scan: snapshot.metadata,
      runtimeMs,
      assumptions: [
        SCORE_INTERPRETATION_NOTICE,
        'M2 evaluates static source, Base64 payload, package binary, integrity, and static DNR rules while excluding permission rules (MVX101, MVX102, MVX103, MVX110, MVX111).',
        'MVX104-MVX109 (OD-1) and MVX004 (OD-2) remain disabled unless explicitly enabled via configuration switches.'
      ]
    };
  } catch (error) {
    if (!captureFailures || error?.code === 'INVALID_ARGUMENT' || error?.code === 'RULE_ISOLATION_VIOLATION') {
      throw error;
    }
    const runtimeMs = Number((performance.now() - started).toFixed(3));
    return buildFailureEnvelope({
      mode: 'M2',
      sampleId: options.sampleId,
      runtimeMs,
      error,
      extra: {
        provenance: {
          packageSha256: null,
          analysisSha256: null,
          configVersion: RESEARCH_CONFIG_VERSION,
          toolVersion: VERSION,
          permissionAnalysisExecuted: false
        }
      }
    });
  }
}

export async function runM3DynamicOnly(extensionPath, scenarioPath, outputDir, options = {}) {
  for (const [label, value] of [
    ['extensionPath', extensionPath],
    ['scenarioPath', scenarioPath],
    ['outputDir', outputDir]
  ]) {
    if (typeof value !== 'string' || value.length === 0) {
      throw new MvxError(`${label} must be a non-empty string`, { code: 'INVALID_ARGUMENT' });
    }
  }
  rejectUnknownOptions(options, M3_OPTIONS, 'M3 dynamic-only');
  if (options.acknowledgeRisk !== true) {
    throw new MvxError('Refusing live extension execution without acknowledgeRisk: true', {
      code: 'RISK_ACK_REQUIRED'
    });
  }
  assertOptionalBoolean(options.captureFailures, 'captureFailures');
  assertOptionalNonEmptyString(options.image, 'image');
  assertOptionalNonEmptyString(options.sampleId, 'sampleId');
  if (options.expectedPackageSha256 !== undefined
    && (typeof options.expectedPackageSha256 !== 'string' || !SHA256.test(options.expectedPackageSha256))) {
    throw new MvxError('expectedPackageSha256 must be a lowercase SHA-256 digest', {
      code: 'INVALID_ARGUMENT'
    });
  }
  const repeatIndex = options.repeatIndex ?? 1;
  if (!Number.isSafeInteger(repeatIndex) || repeatIndex < 1) {
    throw new MvxError('repeatIndex must be a positive integer', { code: 'INVALID_ARGUMENT' });
  }
  const labRunner = options.labRunner ?? runLabContainer;
  if (typeof labRunner !== 'function') {
    throw new MvxError('labRunner must be a function', { code: 'INVALID_ARGUMENT' });
  }
  const captureFailures = options.captureFailures !== false;
  const image = options.image ?? 'mvx-lab:local';
  const started = performance.now();

  try {
    const execution = await labRunner({
      extension: extensionPath,
      scenario: scenarioPath,
      output: outputDir,
      image,
      acknowledgeRisk: true
    });
    const runtimeMs = Number((performance.now() - started).toFixed(3));
    const report = execution?.report;
    if (!report || typeof report !== 'object' || !Object.hasOwn(DYNAMIC_VERDICT_SCORES, report.verdict)) {
      throw new MvxError('Dynamic lab runner returned an invalid report', {
        code: 'INVALID_LAB_REPORT'
      });
    }

    const observedPackageSha256 = report.execution?.extension?.packageSha256 ?? null;
    if (options.expectedPackageSha256 !== undefined
      && observedPackageSha256 !== options.expectedPackageSha256) {
      throw new MvxError(
        `Dynamic package SHA-256 mismatch: expected ${options.expectedPackageSha256}, observed ${observedPackageSha256}`,
        { code: 'LAB_IDENTITY_MISMATCH' }
      );
    }

    const uncontained = report.contained !== true
      || (report.summary?.uncontainedExternalRequests ?? 0) > 0;
    if (uncontained) {
      return {
        schemaVersion: 1,
        mode: 'M3',
        status: 'failed',
        sampleId: options.sampleId ?? null,
        repeatIndex,
        tool: { name: 'mvx-audit', version: VERSION },
        researchConfig: {
          schemaVersion: RESEARCH_CONFIG_SCHEMA_VERSION,
          configVersion: RESEARCH_CONFIG_VERSION
        },
        verdict: report.verdict,
        contained: false,
        riskScore: null,
        benignInferenceAllowed: false,
        failure: {
          code: 'LAB_CONTAINMENT_VIOLATION',
          message: 'Dynamic execution observed uncontained external network activity; result is invalid for normal scoring.'
        },
        provenance: {
          packageSha256: observedPackageSha256,
          scenarioSha256: report.evidenceProvenance?.scenario?.sha256 ?? report.execution?.scenarioSha256 ?? null,
          eventsSha256: report.evidenceProvenance?.events?.sha256 ?? null,
          evaluationSha256: report.evidenceProvenance?.evaluation?.sha256 ?? null,
          seccompSha256: report.execution?.isolation?.seccompSha256 ?? null,
          imageId: execution.imageId ?? report.execution?.container?.imageId ?? null,
          browser: report.execution?.browser ?? null,
          durationMs: report.execution?.durationMs ?? null,
          configVersion: RESEARCH_CONFIG_VERSION,
          toolVersion: VERSION,
          staticFindingsConsumed: false
        },
        artifacts: {
          outputDir: execution.output ?? outputDir,
          eventsPath: execution.eventsPath ?? null,
          reportPath: execution.reportPath ?? null,
          scenarioPath: execution.scenarioPath ?? scenarioPath
        },
        labReport: report,
        runtimeMs,
        caveats: [
          ...(Array.isArray(report.caveats) ? report.caveats : []),
          'Containment violation occurred; errors are never converted into zero risk scores.'
        ]
      };
    }

    const inconclusive = report.verdict === 'inconclusive';
    const riskScore = DYNAMIC_VERDICT_SCORES[report.verdict];
    return {
      schemaVersion: 1,
      mode: 'M3',
      status: inconclusive ? 'inconclusive' : 'completed',
      sampleId: options.sampleId ?? null,
      repeatIndex,
      tool: { name: 'mvx-audit', version: VERSION },
      researchConfig: {
        schemaVersion: RESEARCH_CONFIG_SCHEMA_VERSION,
        configVersion: RESEARCH_CONFIG_VERSION
      },
      verdict: report.verdict,
      contained: true,
      riskScore,
      benignInferenceAllowed: false,
      failure: inconclusive
        ? {
          code: 'LAB_INCONCLUSIVE',
          message: 'Dynamic lab returned inconclusive due to collection or execution errors.'
        }
        : null,
      provenance: {
        packageSha256: observedPackageSha256,
        scenarioSha256: report.evidenceProvenance?.scenario?.sha256 ?? report.execution?.scenarioSha256 ?? null,
        eventsSha256: report.evidenceProvenance?.events?.sha256 ?? null,
        evaluationSha256: report.evidenceProvenance?.evaluation?.sha256 ?? null,
        seccompSha256: report.execution?.isolation?.seccompSha256 ?? null,
        imageId: execution.imageId ?? report.execution?.container?.imageId ?? null,
        browser: report.execution?.browser ?? null,
        durationMs: report.execution?.durationMs ?? null,
        configVersion: RESEARCH_CONFIG_VERSION,
        toolVersion: VERSION,
        staticFindingsConsumed: false
      },
      artifacts: {
        outputDir: execution.output ?? outputDir,
        eventsPath: execution.eventsPath ?? null,
        reportPath: execution.reportPath ?? null,
        scenarioPath: execution.scenarioPath ?? scenarioPath
      },
      labReport: report,
      runtimeMs,
      caveats: [
        ...(Array.isArray(report.caveats) ? report.caveats : []),
        'no_trigger_observed is NOT a Benign verdict; dormant, time-gated, or C2-dependent logic may not trigger during observation.',
        'M3 evaluates isolated dynamic behavioral evidence only and never reads M1 or M2 static findings.'
      ]
    };
  } catch (error) {
    if (!captureFailures
      || error?.code === 'INVALID_ARGUMENT'
      || error?.code === 'RISK_ACK_REQUIRED'
      || error?.code === 'LAB_IDENTITY_MISMATCH') {
      throw error;
    }
    const runtimeMs = Number((performance.now() - started).toFixed(3));
    return buildFailureEnvelope({
      mode: 'M3',
      sampleId: options.sampleId,
      runtimeMs,
      error,
      extra: {
        repeatIndex,
        verdict: null,
        contained: null,
        benignInferenceAllowed: false,
        provenance: {
          packageSha256: options.expectedPackageSha256 ?? null,
          scenarioSha256: null,
          eventsSha256: null,
          evaluationSha256: null,
          seccompSha256: null,
          imageId: null,
          browser: null,
          durationMs: null,
          configVersion: RESEARCH_CONFIG_VERSION,
          toolVersion: VERSION,
          staticFindingsConsumed: false
        },
        artifacts: {
          outputDir,
          eventsPath: null,
          reportPath: null,
          scenarioPath
        },
        labReport: null
      }
    });
  }
}
