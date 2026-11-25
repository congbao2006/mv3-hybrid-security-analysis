import { MvxError } from '../errors.js';
import {
  DEFAULT_SCORE_CAP,
  DEFAULT_WEIGHT_PROFILE,
  WEIGHT_PROFILES
} from '../model.js';
import {
  NON_PERMISSION_MANIFEST_RULE_IDS,
  PERMISSION_RULE_IDS
} from '../rules/manifest-rules.js';

export const RESEARCH_CONFIG_SCHEMA_VERSION = 1;
export const RESEARCH_CONFIG_VERSION = '2026.1-phase1';

export const STATIC_SOURCE_RULE_IDS = Object.freeze([
  'MVX002',
  'MVX003',
  'MVX004',
  'MVX113',
  'MVX114',
  'MVX115',
  'MVX201',
  'MVX202',
  'MVX203',
  'MVX204',
  'MVX205',
  'MVX206',
  'MVX207',
  'MVX208',
  'MVX209',
  'MVX210',
  'MVX211',
  'MVX212',
  'MVX213'
]);

export const MANIFEST_STRUCTURE_RULE_IDS = Object.freeze([
  'MVX104',
  'MVX105',
  'MVX106',
  'MVX107',
  'MVX108',
  'MVX109'
]);

export const MANIFEST_COMPATIBILITY_RULE_IDS = Object.freeze([
  'MVX001',
  'MVX112'
]);

export const DYNAMIC_VERDICT_SCORES = Object.freeze({
  confirmed_attack: 100,
  suspicious_activity: 50,
  no_trigger_observed: 0,
  inconclusive: null
});

export const HYBRID_CONFIDENCE_MULTIPLIERS = Object.freeze({
  high: 1.0,
  medium: 0.7,
  low: 0.4
});

export const RESEARCH_MODES = Object.freeze({
  M1: Object.freeze({
    id: 'M1',
    name: 'Permission-only analysis',
    permissionAnalysis: true,
    staticAnalysis: false,
    dynamicAnalysis: false,
    hybridIntegration: false,
    ruleIds: PERMISSION_RULE_IDS,
    excludedRuleIds: Object.freeze([
      ...NON_PERMISSION_MANIFEST_RULE_IDS,
      ...STATIC_SOURCE_RULE_IDS
    ])
  }),
  M2: Object.freeze({
    id: 'M2',
    name: 'Static source-code analysis',
    permissionAnalysis: false,
    staticAnalysis: true,
    dynamicAnalysis: false,
    hybridIntegration: false,
    ruleIds: STATIC_SOURCE_RULE_IDS,
    excludedRuleIds: PERMISSION_RULE_IDS,
    optionalManifestStructureRuleIds: MANIFEST_STRUCTURE_RULE_IDS
  }),
  M3: Object.freeze({
    id: 'M3',
    name: 'Dynamic behavioral analysis',
    permissionAnalysis: false,
    staticAnalysis: false,
    dynamicAnalysis: true,
    hybridIntegration: false,
    verdictScores: DYNAMIC_VERDICT_SCORES
  }),
  M4: Object.freeze({
    id: 'M4',
    name: 'Hybrid static and dynamic integration',
    permissionAnalysis: true,
    staticAnalysis: true,
    dynamicAnalysis: true,
    hybridIntegration: true,
    confidenceMultipliers: HYBRID_CONFIDENCE_MULTIPLIERS,
    hardBehavioralOverrideMinScore: 90
  })
});

export const SEVERITY_WEIGHT_PROFILES = WEIGHT_PROFILES;

export const SCORE_INTERPRETATION_NOTICE =
  'Risk score is a bounded severity-weighted sum of capability and behavioral indicators (0-100), not a malware probability.';

export const RESEARCH_CONFIG = Object.freeze({
  schemaVersion: RESEARCH_CONFIG_SCHEMA_VERSION,
  configVersion: RESEARCH_CONFIG_VERSION,
  defaultWeightProfile: DEFAULT_WEIGHT_PROFILE,
  scoreCap: DEFAULT_SCORE_CAP,
  scoreInterpretationNotice: SCORE_INTERPRETATION_NOTICE,
  modes: RESEARCH_MODES,
  weightProfiles: SEVERITY_WEIGHT_PROFILES,
  ruleClassifications: Object.freeze({
    permission: PERMISSION_RULE_IDS,
    nonPermissionManifest: NON_PERMISSION_MANIFEST_RULE_IDS,
    manifestStructure: MANIFEST_STRUCTURE_RULE_IDS,
    manifestCompatibility: MANIFEST_COMPATIBILITY_RULE_IDS,
    staticSource: STATIC_SOURCE_RULE_IDS
  })
});

export function getResearchMode(modeId) {
  if (typeof modeId !== 'string' || !Object.hasOwn(RESEARCH_MODES, modeId)) {
    throw new MvxError(`Unknown research mode: ${String(modeId)}`, {
      code: 'INVALID_ARGUMENT'
    });
  }
  return RESEARCH_MODES[modeId];
}

export function getWeightProfile(profileId = DEFAULT_WEIGHT_PROFILE) {
  if (typeof profileId !== 'string' || !Object.hasOwn(SEVERITY_WEIGHT_PROFILES, profileId)) {
    throw new MvxError(`Unknown severity weight profile: ${String(profileId)}`, {
      code: 'INVALID_ARGUMENT'
    });
  }
  return Object.freeze({
    id: profileId,
    weights: SEVERITY_WEIGHT_PROFILES[profileId]
  });
}
