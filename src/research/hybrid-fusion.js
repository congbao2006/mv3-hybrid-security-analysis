import { createHash } from 'node:crypto';
import { MvxError } from '../errors.js';
import { findingKey } from '../fingerprints.js';
import {
  DEFAULT_WEIGHT_PROFILE,
  WEIGHT_PROFILES,
  resolveWeightProfile
} from '../model.js';
import { assertOptionsObject } from '../options.js';
import { VERSION } from '../version.js';
import {
  RESEARCH_CONFIG_SCHEMA_VERSION,
  RESEARCH_CONFIG_VERSION,
  SCORE_INTERPRETATION_NOTICE
} from './config.js';

export const HYBRID_FUSION_PROFILE = 'mvx-hybrid-fusion-v1';
export const HYBRID_FUSION_SCHEMA_VERSION = 1;
export const HYBRID_FUSION_FORMULA = 'C-2';

const SHA256 = /^[a-f0-9]{64}$/;
const WEIGHT_PROFILE_IDS = Object.freeze(Object.keys(WEIGHT_PROFILES));
const CONFIDENCE_LEVELS = Object.freeze(['high', 'medium', 'low']);
const NON_CANARY_OBJECTIVES = new Set([
  'contentManipulation',
  'navigationHijack',
  'unauthorizedDownload'
]);
const CREDENTIAL_CANARY_PATTERN = /(?:credential|password|cookie|session|token.*auth)/i;

const FUSION_CONFIG_KEYS = new Set([
  'schemaVersion',
  'configVersion',
  'formula',
  'scoreCap',
  'staticBlendAlpha',
  'confidenceMultipliers',
  'deduplicateMvx103Chain',
  'tierABehavioralFloor',
  'tierBDynamicElevation',
  'tierBEscalatesWithExternalNetwork',
  'suspiciousDynamicElevation',
  'requireExtensionInitiatorForSuspicious',
  'corroboration',
  'allowStaticFallbackOnExecutionFailure',
  'riskTierThresholds',
  'researchNotice'
]);

const CORROBORATION_KEYS = new Set([
  'primaryCategoryBonus',
  't04ConditionalBonus',
  'maxBonus'
]);

const TIER_THRESHOLD_KEYS = new Set([
  'critical',
  'high',
  'medium'
]);

const FUSION_INPUT_KEYS = new Set([
  'm1',
  'm2',
  'm3',
  'weightProfile',
  'weights',
  'sampleId'
]);

const FORBIDDEN_GROUND_TRUTH_KEYS = new Set([
  'groundTruth',
  'ground_truth',
  'groundTruthLabel',
  'ground_truth_label',
  'label',
  'labels',
  'finalDecision',
  'final_decision'
]);

export const THREAT_CATEGORY_DEFINITIONS = Object.freeze({
  T01: Object.freeze({
    id: 'T01',
    name: 'Excessive Permissions',
    corroborationRole: 'unsupported',
    staticKeys: Object.freeze(['MVX101', 'MVX102', 'MVX103', 'MVX110', 'MVX111']),
    coverageNote: 'No dynamic unused-privilege API hook exists in mvx-audit v3.1.0; dynamic corroboration is not supported.'
  }),
  T02: Object.freeze({
    id: 'T02',
    name: 'Data Leakage',
    corroborationRole: 'primary',
    staticKeys: Object.freeze([
      'MVX101', 'MVX102:history', 'MVX102:clipboardRead', 'MVX102:tabs',
      'MVX102:webNavigation', 'MVX111', 'MVX206', 'MVX207', 'MVX209', 'MVX212'
    ]),
    coverageNote: 'Corroborated via non-credential canary exfiltration or extension-attributed external network requests.'
  }),
  T03: Object.freeze({
    id: 'T03',
    name: 'Credential Exposure',
    corroborationRole: 'primary',
    staticKeys: Object.freeze([
      'MVX103', 'MVX102:cookies', 'MVX102:debugger', 'MVX102:clipboardRead',
      'MVX205', 'MVX206', 'MVX209'
    ]),
    coverageNote: 'Corroborated via credential/session canary exfiltration or extension-attributed external POST on login canary.'
  }),
  T04: Object.freeze({
    id: 'T04',
    name: 'DOM Manipulation',
    corroborationRole: 'conditional',
    staticKeys: Object.freeze([
      'MVX203', 'MVX204', 'MVX211', 'MVX104', 'MVX105', 'MVX106', 'MVX109'
    ]),
    coverageNote: 'Conditional supporting signal only; cannot independently activate the Tier-A behavioral floor.'
  }),
  T05: Object.freeze({
    id: 'T05',
    name: 'Unauthorized Navigation',
    corroborationRole: 'primary',
    staticKeys: Object.freeze([
      'MVX110', 'MVX102:proxy', 'MVX102:downloads', 'MVX102:tabs',
      'MVX102:webNavigation', 'MVX113', 'MVX114', 'MVX208'
    ]),
    coverageNote: 'Corroborated via extension-initiated navigationHijack or unprompted unauthorizedDownload.'
  }),
  T06: Object.freeze({
    id: 'T06',
    name: 'Unsafe Code Execution',
    corroborationRole: 'unsupported',
    staticKeys: Object.freeze([
      'MVX003', 'MVX102:debugger', 'MVX102:nativeMessaging', 'MVX107',
      'MVX108', 'MVX201', 'MVX202', 'MVX210', 'MVX213'
    ]),
    coverageNote: 'No runtime eval/CSP/message-bridge execution hook exists in mvx-audit v3.1.0; dynamic corroboration is not supported.'
  }),
  T07: Object.freeze({
    id: 'T07',
    name: 'Resource Abuse',
    corroborationRole: 'unsupported',
    staticKeys: Object.freeze(['MVX003', 'MVX102:proxy', 'MVX102:tabs']),
    coverageNote: 'No CPU, memory, worker-count, or network-volume telemetry exists in mvx-audit v3.1.0; dynamic corroboration is not supported.'
  }),
  T08: Object.freeze({
    id: 'T08',
    name: 'Software Supply Chain Risk',
    corroborationRole: 'unsupported',
    staticKeys: Object.freeze(['MVX002', 'MVX004', 'MVX115']),
    coverageNote: 'No third-party JS SCA or single-snapshot longitudinal dynamic signal exists in mvx-audit v3.1.0; dynamic corroboration is not supported.'
  })
});

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function roundScore(value) {
  return Math.round(value * 10_000) / 10_000;
}

function deepFreeze(value, seen = new Set()) {
  if (!value || typeof value !== 'object' || seen.has(value)) return value;
  seen.add(value);
  for (const key of Reflect.ownKeys(value)) deepFreeze(value[key], seen);
  return Object.freeze(value);
}

function assertFiniteInRange(value, name, min, max, { minInclusive = true, maxInclusive = true } = {}) {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw new MvxError(`${name} must be a finite number`, { code: 'INVALID_ARGUMENT' });
  }
  const lowOk = minInclusive ? value >= min : value > min;
  const highOk = maxInclusive ? value <= max : value < max;
  if (!lowOk || !highOk) {
    throw new MvxError(`${name} must be within ${minInclusive ? '[' : '('}${min}, ${max}${maxInclusive ? ']' : ')'}`, {
      code: 'INVALID_ARGUMENT'
    });
  }
}

function assertBoolean(value, name) {
  if (typeof value !== 'boolean') {
    throw new MvxError(`${name} must be boolean`, { code: 'INVALID_ARGUMENT' });
  }
}

function assertExactAllowedKeys(obj, allowed, label) {
  assertOptionsObject(obj, label);
  const unknown = Object.getOwnPropertyNames(obj).filter((key) => !allowed.has(key)).sort();
  if (unknown.length > 0) {
    throw new MvxError(`Unknown ${label} field(s): ${unknown.join(', ')}`, {
      code: 'INVALID_ARGUMENT'
    });
  }
}

export function createFusionConfig(config) {
  assertExactAllowedKeys(config, FUSION_CONFIG_KEYS, 'Fusion config');

  if (config.schemaVersion !== HYBRID_FUSION_SCHEMA_VERSION) {
    throw new MvxError(`Fusion config schemaVersion must equal ${HYBRID_FUSION_SCHEMA_VERSION}`, {
      code: 'INVALID_ARGUMENT'
    });
  }
  if (typeof config.configVersion !== 'string' || config.configVersion.trim().length === 0) {
    throw new MvxError('Fusion config configVersion must be a non-empty string', {
      code: 'INVALID_ARGUMENT'
    });
  }
  if (config.formula !== HYBRID_FUSION_FORMULA) {
    throw new MvxError(`Fusion config formula must equal '${HYBRID_FUSION_FORMULA}'`, {
      code: 'INVALID_ARGUMENT'
    });
  }

  assertFiniteInRange(config.scoreCap, 'scoreCap', 0, 100, { minInclusive: false });
  const scoreCap = config.scoreCap;
  assertFiniteInRange(config.staticBlendAlpha, 'staticBlendAlpha', 0, 1);

  assertExactAllowedKeys(config.confidenceMultipliers, new Set(CONFIDENCE_LEVELS), 'confidenceMultipliers');
  const confidenceMultipliers = {};
  for (const level of CONFIDENCE_LEVELS) {
    assertFiniteInRange(config.confidenceMultipliers[level], `confidenceMultipliers.${level}`, 0, 1, {
      minInclusive: false
    });
    confidenceMultipliers[level] = config.confidenceMultipliers[level];
  }
  if (confidenceMultipliers.high < confidenceMultipliers.medium
    || confidenceMultipliers.medium < confidenceMultipliers.low) {
    throw new MvxError('confidenceMultipliers must be monotonically non-increasing (high >= medium >= low)', {
      code: 'INVALID_ARGUMENT'
    });
  }

  assertBoolean(config.deduplicateMvx103Chain, 'deduplicateMvx103Chain');
  assertFiniteInRange(config.tierABehavioralFloor, 'tierABehavioralFloor', 0, scoreCap);
  assertFiniteInRange(config.tierBDynamicElevation, 'tierBDynamicElevation', 0, scoreCap);
  if (config.tierBDynamicElevation >= config.tierABehavioralFloor && config.tierABehavioralFloor > 0) {
    throw new MvxError('tierBDynamicElevation must be strictly less than tierABehavioralFloor so Tier-B alone cannot activate the Tier-A floor', {
      code: 'INVALID_ARGUMENT'
    });
  }
  assertBoolean(config.tierBEscalatesWithExternalNetwork, 'tierBEscalatesWithExternalNetwork');
  assertFiniteInRange(config.suspiciousDynamicElevation, 'suspiciousDynamicElevation', 0, scoreCap);
  assertBoolean(config.requireExtensionInitiatorForSuspicious, 'requireExtensionInitiatorForSuspicious');

  assertExactAllowedKeys(config.corroboration, CORROBORATION_KEYS, 'corroboration');
  assertFiniteInRange(config.corroboration.primaryCategoryBonus, 'corroboration.primaryCategoryBonus', 0, scoreCap);
  assertFiniteInRange(config.corroboration.t04ConditionalBonus, 'corroboration.t04ConditionalBonus', 0, scoreCap);
  assertFiniteInRange(config.corroboration.maxBonus, 'corroboration.maxBonus', 0, scoreCap);

  assertBoolean(config.allowStaticFallbackOnExecutionFailure, 'allowStaticFallbackOnExecutionFailure');

  assertExactAllowedKeys(config.riskTierThresholds, TIER_THRESHOLD_KEYS, 'riskTierThresholds');
  assertFiniteInRange(config.riskTierThresholds.critical, 'riskTierThresholds.critical', 0, scoreCap, {
    minInclusive: false
  });
  assertFiniteInRange(config.riskTierThresholds.high, 'riskTierThresholds.high', 0, scoreCap, {
    minInclusive: false
  });
  assertFiniteInRange(config.riskTierThresholds.medium, 'riskTierThresholds.medium', 0, scoreCap, {
    minInclusive: false
  });
  if (!(config.riskTierThresholds.critical > config.riskTierThresholds.high
    && config.riskTierThresholds.high > config.riskTierThresholds.medium)) {
    throw new MvxError('riskTierThresholds must satisfy critical > high > medium > 0', {
      code: 'INVALID_ARGUMENT'
    });
  }

  const researchNotice = config.researchNotice ??
    'Fixed research configuration for bounded indicator prioritization; not a malware probability calibration.';
  if (typeof researchNotice !== 'string' || researchNotice.trim().length === 0) {
    throw new MvxError('researchNotice must be a non-empty string', { code: 'INVALID_ARGUMENT' });
  }

  const canonical = {
    profile: HYBRID_FUSION_PROFILE,
    schemaVersion: config.schemaVersion,
    configVersion: config.configVersion,
    formula: config.formula,
    scoreCap,
    staticBlendAlpha: config.staticBlendAlpha,
    confidenceMultipliers,
    deduplicateMvx103Chain: config.deduplicateMvx103Chain,
    tierABehavioralFloor: config.tierABehavioralFloor,
    tierBDynamicElevation: config.tierBDynamicElevation,
    tierBEscalatesWithExternalNetwork: config.tierBEscalatesWithExternalNetwork,
    suspiciousDynamicElevation: config.suspiciousDynamicElevation,
    requireExtensionInitiatorForSuspicious: config.requireExtensionInitiatorForSuspicious,
    corroboration: {
      primaryCategoryBonus: config.corroboration.primaryCategoryBonus,
      t04ConditionalBonus: config.corroboration.t04ConditionalBonus,
      maxBonus: config.corroboration.maxBonus
    },
    allowStaticFallbackOnExecutionFailure: config.allowStaticFallbackOnExecutionFailure,
    riskTierThresholds: {
      critical: config.riskTierThresholds.critical,
      high: config.riskTierThresholds.high,
      medium: config.riskTierThresholds.medium
    },
    researchNotice
  };

  return deepFreeze({
    ...canonical,
    sha256: sha256(JSON.stringify(canonical))
  });
}

export function validateFusionConfig(config) {
  if (config && typeof config === 'object' && Object.hasOwn(config, 'sha256') && Object.hasOwn(config, 'profile')) {
    const { profile, sha256: existingHash, ...rest } = config;
    if (profile !== HYBRID_FUSION_PROFILE) {
      throw new MvxError(`Unsupported fusion config profile: ${String(profile)}`, {
        code: 'INVALID_ARGUMENT'
      });
    }
    const rebuilt = createFusionConfig(rest);
    if (rebuilt.sha256 !== existingHash) {
      throw new MvxError('Fusion config SHA-256 does not match its canonical fields', {
        code: 'INVALID_ARGUMENT'
      });
    }
    return rebuilt;
  }
  return createFusionConfig(config);
}

function classifyRiskTier(score, thresholds) {
  if (score === null || score === undefined) return null;
  if (score >= thresholds.critical) return 'critical';
  if (score >= thresholds.high) return 'high';
  if (score >= thresholds.medium) return 'medium';
  if (score > 0) return 'low';
  return 'clean';
}

export function deduplicateStaticFindings(findings) {
  if (!Array.isArray(findings)) {
    throw new MvxError('Findings must be an array', { code: 'INVALID_ARGUMENT' });
  }
  const seen = new Set();
  const unique = [];
  let duplicateCount = 0;
  for (const finding of findings) {
    const key = findingKey(finding);
    if (seen.has(key)) {
      duplicateCount += 1;
      continue;
    }
    seen.add(key);
    unique.push(finding);
  }
  return { unique, duplicateCount };
}

function scoreStaticLayer(findings, weights, {
  scoreCap,
  confidenceMultipliers = null,
  deduplicateMvx103Chain = false
}) {
  const { unique, duplicateCount } = deduplicateStaticFindings(findings);
  const suppressedOverlapFingerprints = [];
  const hasMvx103 = deduplicateMvx103Chain && unique.some((finding) => finding.id === 'MVX103');

  let sum = 0;
  for (const finding of unique) {
    const key = findingKey(finding);
    if (hasMvx103 && (key === 'MVX101' || key === 'MVX102:cookies')) {
      suppressedOverlapFingerprints.push(key);
      continue;
    }
    const baseWeight = weights[finding.severity];
    if (typeof baseWeight !== 'number') {
      throw new MvxError(`Unsupported finding severity: ${String(finding.severity)}`, {
        code: 'INVALID_ARGUMENT'
      });
    }
    const mult = confidenceMultipliers
      ? (confidenceMultipliers[finding.confidence ?? 'high'] ?? confidenceMultipliers.high)
      : 1;
    sum += baseWeight * mult;
  }

  return {
    score: roundScore(Math.min(scoreCap, sum)),
    uniqueFindings: unique,
    duplicateCount,
    suppressedOverlapFingerprints: suppressedOverlapFingerprints.sort()
  };
}

function extractM1Hash(m1) {
  return m1?.provenance?.packageSha256 ?? m1?.package?.sha256 ?? null;
}

function extractM2Hash(m2) {
  return m2?.provenance?.packageSha256 ?? m2?.package?.sha256 ?? null;
}

function extractM3Hash(m3) {
  return m3?.provenance?.packageSha256
    ?? m3?.labReport?.execution?.extension?.packageSha256
    ?? null;
}

function isValidSha256(value) {
  return typeof value === 'string' && SHA256.test(value);
}

function dedupeDynamicObjectivesAndSuspicious(labReport, requireExtensionInitiatorForSuspicious) {
  const objectives = labReport?.objectives ?? {};
  const tierAConfirmed = [];
  const tierBConfirmed = [];
  const canaryExfiltrations = [];
  const credentialCanaryExfiltrations = [];
  const dataLeakageCanaryExfiltrations = [];
  const deduplicatedObjectiveEvidence = {};
  let duplicateDynamicEventsRemoved = 0;

  for (const [name, obj] of Object.entries(objectives)) {
    const rawEvidence = Array.isArray(obj?.evidence) ? obj.evidence : [];
    const seenKeys = new Set();
    const uniqueEvidence = [];
    for (const item of rawEvidence) {
      const targetKey = item?.url ?? item?.to ?? item?.target ?? item?.details?.url ?? 'default';
      const dedupeKey = `${name}\0${item?.type ?? ''}\0${targetKey}`;
      if (seenKeys.has(dedupeKey)) {
        duplicateDynamicEventsRemoved += 1;
        continue;
      }
      seenKeys.add(dedupeKey);
      uniqueEvidence.push(item);
    }
    deduplicatedObjectiveEvidence[name] = uniqueEvidence;

    if (obj?.status !== 'confirmed') continue;
    if (name === 'contentManipulation') {
      tierBConfirmed.push({ objective: name, evidence: uniqueEvidence });
    } else if (NON_CANARY_OBJECTIVES.has(name)) {
      tierAConfirmed.push({ objective: name, evidence: uniqueEvidence });
    } else {
      const entry = { objective: name, evidence: uniqueEvidence };
      tierAConfirmed.push(entry);
      canaryExfiltrations.push(entry);
      if (CREDENTIAL_CANARY_PATTERN.test(name)) {
        credentialCanaryExfiltrations.push(entry);
      } else {
        dataLeakageCanaryExfiltrations.push(entry);
      }
    }
  }

  const rawSuspicious = Array.isArray(labReport?.suspicious) ? labReport.suspicious : [];
  const seenSuspicious = new Set();
  const deduplicatedSuspicious = [];
  const qualifyingSuspicious = [];
  let unattributedSuspiciousSkipped = 0;

  for (const item of rawSuspicious) {
    const initiator = item?.initiator ?? 'unknown';
    const targetKey = item?.url ?? item?.target ?? 'default';
    const dedupeKey = `${item?.reason ?? ''}\0${targetKey}\0${initiator}`;
    if (seenSuspicious.has(dedupeKey)) {
      duplicateDynamicEventsRemoved += 1;
      continue;
    }
    seenSuspicious.add(dedupeKey);
    deduplicatedSuspicious.push(item);
    if (!requireExtensionInitiatorForSuspicious || initiator === 'extension') {
      qualifyingSuspicious.push(item);
    } else {
      unattributedSuspiciousSkipped += 1;
    }
  }

  const qualifyingExternalRequests = qualifyingSuspicious.filter(
    (item) => item?.reason === 'external-request'
  );
  const qualifyingExternalPosts = qualifyingExternalRequests.filter(
    (item) => String(item?.method ?? '').toUpperCase() === 'POST'
      || (item?.postData !== undefined && item?.postData !== null && item?.postData !== '')
  );
  const observedDownloadAttempts = qualifyingSuspicious.filter(
    (item) => item?.reason === 'download-attempt'
  );

  return {
    tierAConfirmed,
    tierBConfirmed,
    canaryExfiltrations,
    credentialCanaryExfiltrations,
    dataLeakageCanaryExfiltrations,
    deduplicatedObjectiveEvidence,
    deduplicatedSuspicious,
    qualifyingSuspicious,
    qualifyingExternalRequests,
    qualifyingExternalPosts,
    observedDownloadAttempts,
    unattributedSuspiciousSkipped,
    duplicateDynamicEventsRemoved
  };
}

function matchesStaticCategory(staticFindings, categoryDef) {
  const keySet = new Set(categoryDef.staticKeys);
  const matched = [];
  for (const finding of staticFindings) {
    const fp = findingKey(finding);
    if (keySet.has(fp) || keySet.has(finding.id)) {
      matched.push(fp);
    }
  }
  return [...new Set(matched)].sort();
}

function evaluateCorroboration(m1UniqueFindings, m2UniqueFindings, dynamicSummary, config) {
  const combinedStatic = [...m1UniqueFindings, ...m2UniqueFindings];
  const threatProfile = {};
  const corroboratedCategories = [];
  const evidenceLinks = [];
  let rawBonus = 0;

  for (const def of Object.values(THREAT_CATEGORY_DEFINITIONS)) {
    const staticMatched = def.id === 'T04'
      ? matchesStaticCategory(m2UniqueFindings, def)
      : matchesStaticCategory(combinedStatic, def);

    if (def.corroborationRole === 'unsupported') {
      threatProfile[def.id] = {
        id: def.id,
        name: def.name,
        corroborationSupported: false,
        staticIndicators: staticMatched,
        dynamicIndicators: [],
        corroborated: false,
        coverageNote: def.coverageNote
      };
      continue;
    }

    const dynamicIndicators = [];
    if (def.id === 'T02') {
      for (const hit of dynamicSummary.dataLeakageCanaryExfiltrations) {
        dynamicIndicators.push(`canary:${hit.objective}`);
      }
      if (dynamicSummary.qualifyingExternalRequests.length > 0) {
        dynamicIndicators.push(`external-request:${dynamicSummary.qualifyingExternalRequests.length}`);
      }
    } else if (def.id === 'T03') {
      for (const hit of dynamicSummary.credentialCanaryExfiltrations) {
        dynamicIndicators.push(`canary:${hit.objective}`);
      }
      if (dynamicSummary.qualifyingExternalPosts.length > 0) {
        dynamicIndicators.push(`external-post:${dynamicSummary.qualifyingExternalPosts.length}`);
      }
    } else if (def.id === 'T05') {
      for (const hit of dynamicSummary.tierAConfirmed) {
        if (hit.objective === 'navigationHijack' || hit.objective === 'unauthorizedDownload') {
          dynamicIndicators.push(`objective:${hit.objective}`);
        }
      }
      if (dynamicSummary.observedDownloadAttempts.length > 0) {
        dynamicIndicators.push(`download-attempt:${dynamicSummary.observedDownloadAttempts.length}`);
      }
    } else if (def.id === 'T04') {
      for (const hit of dynamicSummary.tierBConfirmed) {
        dynamicIndicators.push(`objective:${hit.objective}`);
      }
    }

    const corroborated = staticMatched.length > 0 && dynamicIndicators.length > 0;
    if (corroborated) {
      corroboratedCategories.push(def.id);
      rawBonus += def.corroborationRole === 'primary'
        ? config.corroboration.primaryCategoryBonus
        : config.corroboration.t04ConditionalBonus;
      evidenceLinks.push({
        threatCategory: def.id,
        role: def.corroborationRole,
        staticFingerprints: staticMatched,
        dynamicSignals: dynamicIndicators
      });
    }

    threatProfile[def.id] = {
      id: def.id,
      name: def.name,
      corroborationSupported: true,
      corroborationRole: def.corroborationRole,
      staticIndicators: staticMatched,
      dynamicIndicators,
      corroborated,
      coverageNote: def.coverageNote
    };
  }

  const corroborationBonus = roundScore(Math.min(config.corroboration.maxBonus, rawBonus));
  const corroboratedPrimaryCategories = corroboratedCategories.filter((id) => id !== 'T04');
  return {
    threatProfile,
    corroboratedCategories,
    corroboratedPrimaryCategories,
    evidenceLinks,
    rawBonus: roundScore(rawBonus),
    corroborationBonus
  };
}

function buildFailedM4Result({
  sampleId,
  config,
  weightProfile,
  failure,
  containmentVerified,
  provenance,
  m3Verdict = null,
  labReport = null
}) {
  return {
    schemaVersion: HYBRID_FUSION_SCHEMA_VERSION,
    mode: 'M4',
    status: 'failed',
    sampleId: sampleId ?? null,
    tool: { name: 'mvx-audit', version: VERSION },
    researchConfig: {
      schemaVersion: RESEARCH_CONFIG_SCHEMA_VERSION,
      configVersion: RESEARCH_CONFIG_VERSION,
      fusionProfile: HYBRID_FUSION_PROFILE,
      fusionConfigVersion: config.configVersion,
      fusionConfigSha256: config.sha256,
      formula: config.formula,
      weightProfile
    },
    contributingSources: [],
    staticFallback: false,
    containmentVerified,
    m3Verdict,
    behavioralAlertFlag: false,
    hybridRiskScore: null,
    riskTier: null,
    scoresByWeight: null,
    componentScores: null,
    corroboratedCategories: [],
    evidenceLinks: [],
    threatProfile: null,
    failure,
    provenance,
    m3Evidence: labReport ? {
      verdict: labReport.verdict ?? m3Verdict,
      contained: labReport.contained ?? null,
      objectives: labReport.objectives ?? null,
      suspicious: labReport.suspicious ?? null,
      errors: labReport.errors ?? null
    } : null,
    assumptions: [
      config.researchNotice,
      SCORE_INTERPRETATION_NOTICE,
      'Errors and containment violations are never converted into zero risk scores.'
    ]
  };
}

export function fuseHybridEvidence(inputs, rawFusionConfig) {
  assertOptionsObject(inputs, 'Hybrid fusion inputs');
  for (const key of Object.getOwnPropertyNames(inputs)) {
    if (FORBIDDEN_GROUND_TRUTH_KEYS.has(key)) {
      throw new MvxError(`Ground Truth input '${key}' is strictly forbidden in M4 hybrid fusion`, {
        code: 'GROUND_TRUTH_FORBIDDEN'
      });
    }
  }
  assertExactAllowedKeys(inputs, FUSION_INPUT_KEYS, 'Hybrid fusion inputs');

  const config = validateFusionConfig(rawFusionConfig);
  if (inputs.weightProfile !== undefined && inputs.weights !== undefined) {
    throw new MvxError('Specify either weightProfile or weights, not both', {
      code: 'INVALID_ARGUMENT'
    });
  }
  const resolvedWeights = inputs.weights !== undefined
    ? resolveWeightProfile(inputs.weights)
    : resolveWeightProfile(inputs.weightProfile ?? DEFAULT_WEIGHT_PROFILE);

  const { m1, m2, m3 } = inputs;
  if (!m1 || typeof m1 !== 'object' || m1.mode !== 'M1') {
    throw new MvxError('Hybrid fusion requires a valid M1 result object', { code: 'INVALID_ARGUMENT' });
  }
  if (!m2 || typeof m2 !== 'object' || m2.mode !== 'M2') {
    throw new MvxError('Hybrid fusion requires a valid M2 result object', { code: 'INVALID_ARGUMENT' });
  }
  if (!m3 || typeof m3 !== 'object' || m3.mode !== 'M3') {
    throw new MvxError('Hybrid fusion requires a valid M3 result object', { code: 'INVALID_ARGUMENT' });
  }

  const sampleId = inputs.sampleId ?? m1.sampleId ?? m2.sampleId ?? m3.sampleId ?? null;
  const m1Hash = extractM1Hash(m1);
  const m2Hash = extractM2Hash(m2);
  const m3Hash = extractM3Hash(m3);

  const baseProvenance = {
    packageSha256: m1Hash,
    analysisSha256: m2.provenance?.analysisSha256 ?? m2.analysis?.sha256 ?? null,
    manifestSha256: m1.provenance?.manifestSha256 ?? m2.provenance?.manifestSha256 ?? null,
    scenarioSha256: m3.provenance?.scenarioSha256 ?? null,
    eventsSha256: m3.provenance?.eventsSha256 ?? null,
    evaluationSha256: m3.provenance?.evaluationSha256 ?? null,
    seccompSha256: m3.provenance?.seccompSha256 ?? null,
    imageId: m3.provenance?.imageId ?? null,
    browser: m3.provenance?.browser ?? null,
    durationMs: m3.provenance?.durationMs ?? null,
    configVersion: RESEARCH_CONFIG_VERSION,
    fusionConfigVersion: config.configVersion,
    fusionConfigSha256: config.sha256,
    toolVersion: VERSION
  };

  // H4 State 6: Containment violation — hard fail, no fusion, no static fallback
  const isContainmentViolation = m3.contained === false
    || m3.failure?.code === 'LAB_CONTAINMENT_VIOLATION'
    || (m3.labReport?.summary?.uncontainedExternalRequests ?? 0) > 0;
  if (isContainmentViolation) {
    return buildFailedM4Result({
      sampleId,
      config,
      weightProfile: resolvedWeights.weightProfile,
      containmentVerified: false,
      m3Verdict: m3.verdict ?? null,
      labReport: m3.labReport ?? null,
      provenance: baseProvenance,
      failure: {
        code: 'LAB_CONTAINMENT_VIOLATION',
        message: 'Dynamic containment violation detected; M4 fusion halted without static fallback.'
      }
    });
  }

  // Verify M1 and M2 completion and SHA-256 identity
  if (m1.status !== 'completed' || m2.status !== 'completed') {
    const failedLayer = m1.status !== 'completed' ? 'M1' : 'M2';
    const layerFailure = m1.status !== 'completed' ? m1.failure : m2.failure;
    return buildFailedM4Result({
      sampleId,
      config,
      weightProfile: resolvedWeights.weightProfile,
      containmentVerified: m3.contained === true,
      m3Verdict: m3.verdict ?? null,
      labReport: m3.labReport ?? null,
      provenance: baseProvenance,
      failure: {
        code: layerFailure?.code ?? `${failedLayer}_FAILED`,
        message: `${failedLayer} failed (${layerFailure?.message ?? 'unknown error'}); static baseline unavailable for M4 fusion.`
      }
    });
  }

  if (!isValidSha256(m1Hash) || !isValidSha256(m2Hash)) {
    throw new MvxError('M1 and M2 must provide valid package SHA-256 digests before fusion', {
      code: 'HASH_MISSING'
    });
  }
  if (m1Hash !== m2Hash) {
    throw new MvxError(`Package SHA-256 mismatch between M1 (${m1Hash}) and M2 (${m2Hash})`, {
      code: 'HASH_MISMATCH'
    });
  }

  // Verify M3 SHA-256 identity (required for production fusion; fail closed on mismatch or missing)
  if (m3.status === 'completed' || m3.status === 'inconclusive') {
    if (!isValidSha256(m3Hash)) {
      throw new MvxError('M3 must provide a valid package SHA-256 digest for production fusion', {
        code: 'HASH_MISSING'
      });
    }
    if (m3Hash !== m1Hash) {
      throw new MvxError(`Package SHA-256 mismatch between static (${m1Hash}) and M3 (${m3Hash})`, {
        code: 'HASH_MISMATCH'
      });
    }
  } else if (m3Hash !== null) {
    if (!isValidSha256(m3Hash) || m3Hash !== m1Hash) {
      throw new MvxError(`Package SHA-256 mismatch between static (${m1Hash}) and failed M3 (${m3Hash})`, {
        code: 'HASH_MISMATCH'
      });
    }
  }

  // H4 State 5: Execution failure
  const isM3ExecutionFailure = m3.status === 'failed';
  if (isM3ExecutionFailure && !config.allowStaticFallbackOnExecutionFailure) {
    return buildFailedM4Result({
      sampleId,
      config,
      weightProfile: resolvedWeights.weightProfile,
      containmentVerified: m3.contained === true,
      m3Verdict: m3.verdict ?? null,
      labReport: m3.labReport ?? null,
      provenance: baseProvenance,
      failure: {
        code: m3.failure?.code ?? 'M3_EXECUTION_FAILED',
        message: m3.failure?.message ?? 'M3 dynamic execution failed and static fallback on execution failure is disabled.'
      }
    });
  }

  const isStaticFallback = m3.status === 'inconclusive'
    || m3.verdict === 'inconclusive'
    || isM3ExecutionFailure;

  // Evaluate deduplicated static layers across W1-W5 + selected weight profile
  const evaluateForWeights = (weightsObj, profileName) => {
    const m1Scored = scoreStaticLayer(m1.findings ?? [], weightsObj, {
      scoreCap: config.scoreCap,
      confidenceMultipliers: null,
      deduplicateMvx103Chain: config.deduplicateMvx103Chain
    });
    const m2Scored = scoreStaticLayer(m2.findings ?? [], weightsObj, {
      scoreCap: config.scoreCap,
      confidenceMultipliers: config.confidenceMultipliers,
      deduplicateMvx103Chain: false
    });
    const staticScore = roundScore(
      Math.min(
        config.scoreCap,
        config.staticBlendAlpha * m1Scored.score + (1 - config.staticBlendAlpha) * m2Scored.score
      )
    );
    return {
      profileName,
      m1Scored,
      m2Scored,
      staticScore
    };
  };

  const primaryStatic = evaluateForWeights(resolvedWeights.weights, resolvedWeights.weightProfile);

  // H4 State 4 (inconclusive) and permitted State 5 (execution failure with explicit fallback)
  if (isStaticFallback) {
    const scoresByWeight = {};
    for (const profileId of WEIGHT_PROFILE_IDS) {
      const s = evaluateForWeights(WEIGHT_PROFILES[profileId], profileId);
      scoresByWeight[profileId] = {
        weightProfile: profileId,
        m1Score: s.m1Scored.score,
        m2AdjustedScore: s.m2Scored.score,
        staticScore: s.staticScore,
        dynamicElevation: null,
        corroborationBonus: 0,
        tierAFloorApplied: false,
        hybridRiskScore: s.staticScore,
        riskTier: classifyRiskTier(s.staticScore, config.riskTierThresholds)
      };
    }

    const fallbackThreatProfile = {};
    const combinedStatic = [...primaryStatic.m1Scored.uniqueFindings, ...primaryStatic.m2Scored.uniqueFindings];
    for (const def of Object.values(THREAT_CATEGORY_DEFINITIONS)) {
      const staticMatched = def.id === 'T04'
        ? matchesStaticCategory(primaryStatic.m2Scored.uniqueFindings, def)
        : matchesStaticCategory(combinedStatic, def);
      fallbackThreatProfile[def.id] = {
        id: def.id,
        name: def.name,
        corroborationSupported: def.corroborationRole !== 'unsupported',
        staticIndicators: staticMatched,
        dynamicIndicators: [],
        corroborated: false,
        coverageNote: 'Dynamic evidence unavailable due to static fallback.'
      };
    }

    return {
      schemaVersion: HYBRID_FUSION_SCHEMA_VERSION,
      mode: 'M4',
      status: 'completed_with_static_fallback',
      sampleId,
      tool: { name: 'mvx-audit', version: VERSION },
      researchConfig: {
        schemaVersion: RESEARCH_CONFIG_SCHEMA_VERSION,
        configVersion: RESEARCH_CONFIG_VERSION,
        fusionProfile: HYBRID_FUSION_PROFILE,
        fusionConfigVersion: config.configVersion,
        fusionConfigSha256: config.sha256,
        formula: config.formula,
        weightProfile: resolvedWeights.weightProfile
      },
      contributingSources: ['M1', 'M2'],
      staticFallback: true,
      staticFallbackReason: isM3ExecutionFailure
        ? (m3.failure?.code ?? 'M3_EXECUTION_FAILED')
        : 'LAB_INCONCLUSIVE',
      containmentVerified: m3.contained === true,
      m3Verdict: m3.verdict ?? null,
      benignInferenceAllowed: false,
      behavioralAlertFlag: false,
      hybridRiskScore: primaryStatic.staticScore,
      riskTier: classifyRiskTier(primaryStatic.staticScore, config.riskTierThresholds),
      scoresByWeight,
      componentScores: {
        m1DeduplicatedScore: primaryStatic.m1Scored.score,
        m2ConfidenceAdjustedScore: primaryStatic.m2Scored.score,
        staticScore: primaryStatic.staticScore,
        dynamicElevation: null,
        corroborationBonus: 0,
        tierAFloor: 0,
        tierAFloorApplied: false
      },
      deduplication: {
        m1DuplicatesRemoved: primaryStatic.m1Scored.duplicateCount,
        m2DuplicatesRemoved: primaryStatic.m2Scored.duplicateCount,
        mvx103SuppressedOverlapFingerprints: primaryStatic.m1Scored.suppressedOverlapFingerprints,
        dynamicDuplicatesRemoved: 0
      },
      corroboratedCategories: [],
      evidenceLinks: [],
      threatProfile: fallbackThreatProfile,
      failure: isM3ExecutionFailure
        ? (m3.failure ?? { code: 'M3_EXECUTION_FAILED', message: 'M3 dynamic execution failed.' })
        : (m3.failure ?? { code: 'LAB_INCONCLUSIVE', message: 'Dynamic lab returned inconclusive.' }),
      provenance: baseProvenance,
      m3Evidence: m3.labReport ? {
        verdict: m3.labReport.verdict,
        contained: m3.labReport.contained,
        objectives: m3.labReport.objectives,
        suspicious: m3.labReport.suspicious,
        errors: m3.labReport.errors
      } : null,
      assumptions: [
        config.researchNotice,
        SCORE_INTERPRETATION_NOTICE,
        'M3 dynamic evidence was unavailable (inconclusive or execution failure); M4 fell back explicitly to normalized M1+M2 static evidence without assigning a zero dynamic score.'
      ]
    };
  }

  // Normal M3 completed states: confirmed_attack, suspicious_activity, no_trigger_observed
  const dynamicSummary = dedupeDynamicObjectivesAndSuspicious(
    m3.labReport,
    config.requireExtensionInitiatorForSuspicious
  );
  const corroboration = evaluateCorroboration(
    primaryStatic.m1Scored.uniqueFindings,
    primaryStatic.m2Scored.uniqueFindings,
    dynamicSummary,
    config
  );

  const hasTierA = dynamicSummary.tierAConfirmed.length > 0;
  const hasTierB = dynamicSummary.tierBConfirmed.length > 0;
  const hasIndependentTierBEscalation = hasTierB
    && config.tierBEscalatesWithExternalNetwork
    && (
      dynamicSummary.qualifyingExternalRequests.length > 0
      || corroboration.corroboratedPrimaryCategories.length > 0
    );

  // H1-Alt1: Tier-A floor activated ONLY by Tier-A confirmed objectives OR Tier-B escalated with qualifying independent evidence
  const tierAFloorApplied = hasTierA || hasIndependentTierBEscalation;
  const appliedTierAFloor = tierAFloorApplied ? config.tierABehavioralFloor : 0;

  // H3 Formula C-2: Non-diluting additive dynamic elevation
  let dynamicElevation = 0;
  if (m3.verdict === 'no_trigger_observed') {
    dynamicElevation = 0;
  } else if (m3.verdict === 'suspicious_activity') {
    dynamicElevation = dynamicSummary.qualifyingSuspicious.length > 0
      ? config.suspiciousDynamicElevation
      : 0;
  } else if (m3.verdict === 'confirmed_attack') {
    if (hasTierB && !hasTierA) {
      dynamicElevation = config.tierBDynamicElevation;
    } else if (dynamicSummary.qualifyingSuspicious.length > 0) {
      dynamicElevation = config.suspiciousDynamicElevation;
    } else {
      dynamicElevation = 0;
    }
  }

  const computeFinal = (staticScore) => {
    const additive = staticScore + dynamicElevation + corroboration.corroborationBonus;
    const bounded = Math.min(config.scoreCap, Math.max(appliedTierAFloor, additive));
    return roundScore(bounded);
  };

  const primaryHybridScore = computeFinal(primaryStatic.staticScore);
  const scoresByWeight = {};
  for (const profileId of WEIGHT_PROFILE_IDS) {
    const s = evaluateForWeights(WEIGHT_PROFILES[profileId], profileId);
    const finalScore = computeFinal(s.staticScore);
    scoresByWeight[profileId] = {
      weightProfile: profileId,
      m1Score: s.m1Scored.score,
      m2AdjustedScore: s.m2Scored.score,
      staticScore: s.staticScore,
      dynamicElevation,
      corroborationBonus: corroboration.corroborationBonus,
      tierAFloorApplied,
      hybridRiskScore: finalScore,
      riskTier: classifyRiskTier(finalScore, config.riskTierThresholds)
    };
  }

  return {
    schemaVersion: HYBRID_FUSION_SCHEMA_VERSION,
    mode: 'M4',
    status: 'completed',
    sampleId,
    tool: { name: 'mvx-audit', version: VERSION },
    researchConfig: {
      schemaVersion: RESEARCH_CONFIG_SCHEMA_VERSION,
      configVersion: RESEARCH_CONFIG_VERSION,
      fusionProfile: HYBRID_FUSION_PROFILE,
      fusionConfigVersion: config.configVersion,
      fusionConfigSha256: config.sha256,
      formula: config.formula,
      weightProfile: resolvedWeights.weightProfile
    },
    contributingSources: ['M1', 'M2', 'M3'],
    staticFallback: false,
    staticFallbackReason: null,
    containmentVerified: true,
    m3Verdict: m3.verdict,
    benignInferenceAllowed: false,
    behavioralAlertFlag: tierAFloorApplied,
    behavioralAlertTier: tierAFloorApplied ? 'Tier-A' : hasTierB ? 'Tier-B' : 'None',
    hybridRiskScore: primaryHybridScore,
    riskTier: classifyRiskTier(primaryHybridScore, config.riskTierThresholds),
    scoresByWeight,
    componentScores: {
      m1DeduplicatedScore: primaryStatic.m1Scored.score,
      m2ConfidenceAdjustedScore: primaryStatic.m2Scored.score,
      staticScore: primaryStatic.staticScore,
      dynamicElevation,
      corroborationBonus: corroboration.corroborationBonus,
      rawCorroborationBonus: corroboration.rawBonus,
      tierAFloor: appliedTierAFloor,
      tierAFloorApplied
    },
    deduplication: {
      m1DuplicatesRemoved: primaryStatic.m1Scored.duplicateCount,
      m2DuplicatesRemoved: primaryStatic.m2Scored.duplicateCount,
      mvx103SuppressedOverlapFingerprints: primaryStatic.m1Scored.suppressedOverlapFingerprints,
      dynamicDuplicatesRemoved: dynamicSummary.duplicateDynamicEventsRemoved,
      unattributedSuspiciousSkipped: dynamicSummary.unattributedSuspiciousSkipped
    },
    corroboratedCategories: corroboration.corroboratedCategories,
    evidenceLinks: corroboration.evidenceLinks,
    threatProfile: corroboration.threatProfile,
    failure: null,
    provenance: baseProvenance,
    m3Evidence: {
      verdict: m3.verdict,
      contained: m3.contained,
      tierAConfirmedObjectives: dynamicSummary.tierAConfirmed.map((entry) => entry.objective),
      tierBConfirmedObjectives: dynamicSummary.tierBConfirmed.map((entry) => entry.objective),
      qualifyingSuspiciousCount: dynamicSummary.qualifyingSuspicious.length,
      objectives: m3.labReport?.objectives ?? {},
      suspicious: dynamicSummary.deduplicatedSuspicious,
      errors: m3.labReport?.errors ?? []
    },
    assumptions: [
      config.researchNotice,
      SCORE_INTERPRETATION_NOTICE,
      'no_trigger_observed produces zero dynamic elevation and never reduces static risk or implies a Benign verdict.',
      'Tier-B content manipulation alone cannot activate the Tier-A behavioral floor.'
    ]
  };
}
