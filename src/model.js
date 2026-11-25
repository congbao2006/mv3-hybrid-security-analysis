import { MvxError } from './errors.js';
import { assertOptionsObject } from './options.js';

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

export const SEVERITY_WEIGHT = Object.freeze({
  critical: 25,
  high: 12,
  medium: 6,
  low: 2,
  info: 0
});

export const DEFAULT_WEIGHT_PROFILE = 'W1';
export const DEFAULT_SCORE_CAP = 100;

export const WEIGHT_PROFILES = Object.freeze({
  W1: SEVERITY_WEIGHT,
  W2: Object.freeze({ critical: 35, high: 12, medium: 6, low: 2, info: 0 }),
  W3: Object.freeze({ critical: 20, high: 15, medium: 10, low: 5, info: 0 }),
  W4: Object.freeze({ critical: 10, high: 10, medium: 10, low: 10, info: 0 }),
  W5: Object.freeze({ critical: 25, high: 18, medium: 6, low: 2, info: 0 })
});

const SUMMARY_OPTIONS = new Set(['weightProfile', 'weights', 'scoreCap']);
const WEIGHT_KEYS = new Set(SEVERITIES);
const REQUIRED_WEIGHT_KEYS = ['critical', 'high', 'medium', 'low'];

export function resolveWeightProfile(profileOrWeights) {
  if (profileOrWeights === undefined || profileOrWeights === null) {
    return Object.freeze({
      weightProfile: DEFAULT_WEIGHT_PROFILE,
      weights: WEIGHT_PROFILES[DEFAULT_WEIGHT_PROFILE]
    });
  }
  if (typeof profileOrWeights === 'string') {
    if (!Object.hasOwn(WEIGHT_PROFILES, profileOrWeights)) {
      throw new MvxError(`Unknown severity weight profile: ${profileOrWeights}`, {
        code: 'INVALID_ARGUMENT'
      });
    }
    return Object.freeze({
      weightProfile: profileOrWeights,
      weights: WEIGHT_PROFILES[profileOrWeights]
    });
  }
  assertOptionsObject(profileOrWeights, 'Severity weights');
  const unknown = Object.getOwnPropertyNames(profileOrWeights)
    .filter((key) => !WEIGHT_KEYS.has(key))
    .sort();
  if (unknown.length > 0) {
    throw new MvxError(`Unknown severity weight key(s): ${unknown.join(', ')}`, {
      code: 'INVALID_ARGUMENT'
    });
  }
  const normalized = {};
  for (const key of REQUIRED_WEIGHT_KEYS) {
    if (!Object.hasOwn(profileOrWeights, key)) {
      throw new MvxError(`Missing severity weight: ${key}`, {
        code: 'INVALID_ARGUMENT'
      });
    }
  }
  for (const key of SEVERITIES) {
    const value = Object.hasOwn(profileOrWeights, key) ? profileOrWeights[key] : 0;
    if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
      throw new MvxError(`Severity weight ${key} must be a non-negative finite number`, {
        code: 'INVALID_ARGUMENT'
      });
    }
    normalized[key] = value;
  }
  return Object.freeze({
    weightProfile: 'custom',
    weights: Object.freeze(normalized)
  });
}

export const CONFIDENCE = Object.freeze({ HIGH: 'high', MEDIUM: 'medium', LOW: 'low' });

export const REFERENCES = Object.freeze({
  mv3: 'https://developer.chrome.com/docs/extensions/develop/migrate/what-is-mv3',
  permissions: 'https://developer.chrome.com/docs/extensions/develop/concepts/declare-permissions',
  privacy: 'https://developer.chrome.com/docs/extensions/develop/security-privacy/user-privacy',
  security: 'https://developer.chrome.com/docs/extensions/develop/security-privacy/stay-secure',
  messaging: 'https://developer.chrome.com/docs/extensions/develop/concepts/messaging',
  csp: 'https://developer.chrome.com/docs/extensions/develop/migrate/improve-security',
  webRequest: 'https://developer.chrome.com/docs/extensions/reference/api/webRequest',
  dnr: 'https://developer.chrome.com/docs/extensions/reference/api/declarativeNetRequest',
  webResources: 'https://developer.chrome.com/docs/extensions/reference/manifest/web-accessible-resources',
  remoteCode: 'https://developer.chrome.com/docs/extensions/develop/migrate/remote-hosted-code',
  permissionsPolicy: 'https://www.w3.org/TR/permissions-policy-1/',
  mv2Timeline: 'https://developer.chrome.com/docs/extensions/develop/migrate/mv2-deprecation-timeline'
});

export function createFinding(rule, evidence, overrides = {}) {
  return Object.freeze({
    id: rule.id,
    title: rule.title,
    severity: rule.severity,
    confidence: rule.confidence ?? CONFIDENCE.HIGH,
    category: rule.category,
    description: rule.description,
    remediation: rule.remediation,
    references: rule.references ?? [],
    evidence: Array.isArray(evidence) ? evidence : [evidence],
    ...overrides,
    fingerprint: overrides.fingerprint ?? rule.id
  });
}

export function sortFindings(findings) {
  const order = new Map(SEVERITIES.map((severity, index) => [severity, index]));
  return [...findings].sort((left, right) => {
    const severity = order.get(left.severity) - order.get(right.severity);
    if (severity !== 0) return severity;
    const id = left.id.localeCompare(right.id);
    if (id !== 0) return id;
    const leftEvidence = left.evidence[0] ?? {};
    const rightEvidence = right.evidence[0] ?? {};
    return `${leftEvidence.file}:${leftEvidence.line ?? 0}`.localeCompare(
      `${rightEvidence.file}:${rightEvidence.line ?? 0}`
    );
  });
}

// Risk score is a bounded severity-weighted sum of detected capability/pattern
// indicators (0 to scoreCap); it is NOT a malware probability.
export function summarizeFindings(findings, options) {
  const counts = Object.fromEntries(SEVERITIES.map((severity) => [severity, 0]));
  let weightProfile = DEFAULT_WEIGHT_PROFILE;
  let weights = SEVERITY_WEIGHT;
  let scoreCap = DEFAULT_SCORE_CAP;
  const includeWeightMetadata = options !== undefined;

  if (includeWeightMetadata) {
    assertOptionsObject(options, 'Risk summary');
    const unknown = Object.getOwnPropertyNames(options)
      .filter((key) => !SUMMARY_OPTIONS.has(key))
      .sort();
    if (unknown.length > 0) {
      throw new MvxError(`Unknown risk summary option(s): ${unknown.join(', ')}`, {
        code: 'INVALID_ARGUMENT'
      });
    }
    if (options.weightProfile !== undefined && options.weights !== undefined) {
      throw new MvxError('Specify either weightProfile or weights, not both', {
        code: 'INVALID_ARGUMENT'
      });
    }
    const resolved = options.weights !== undefined
      ? resolveWeightProfile(options.weights)
      : resolveWeightProfile(options.weightProfile);
    weightProfile = resolved.weightProfile;
    weights = resolved.weights;
    if (options.scoreCap !== undefined) {
      if (typeof options.scoreCap !== 'number' || !Number.isFinite(options.scoreCap) || options.scoreCap <= 0) {
        throw new MvxError('scoreCap must be a positive finite number', {
          code: 'INVALID_ARGUMENT'
        });
      }
      scoreCap = options.scoreCap;
    }
  }

  let score = 0;
  for (const finding of findings) {
    counts[finding.severity] += 1;
    score += weights[finding.severity];
  }
  score = Math.min(scoreCap, score);
  const rating = score >= 70 ? 'critical' : score >= 40 ? 'high' : score >= 20 ? 'medium' : score > 0 ? 'low' : 'clean';
  if (!includeWeightMetadata) {
    return { total: findings.length, counts, riskScore: score, rating };
  }
  return { total: findings.length, counts, riskScore: score, rating, weightProfile, weights };
}
