export { analyzeIntegrity, auditExtension } from './analyzer.js';
export {
  AUDIT_VERIFICATION_PROFILE, DEFAULT_AUDIT_VERIFICATION_LIMITS,
  auditVerificationToText, verifyAuditReport
} from './audit-verification.js';
export { auditExtensionArchive } from './packed-audit.js';
export { unpackCrx, unpackExtensionArchive } from './archive.js';
export { runStaticBenchmark, staticBenchmarkToText } from './benchmark.js';
export {
  ARCHIVE_CONTINUITY_PROFILE, PACKAGE_DELTA_PROFILE,
  compareExtensionArchives, compareExtensions
} from './compare.js';
export {
  COMPARISON_VERIFICATION_PROFILE, DEFAULT_COMPARISON_VERIFICATION_LIMITS,
  comparisonVerificationToText, verifyComparisonReport
} from './comparison-verification.js';
export {
  DEFAULT_DISPOSITION_POLICY_LIMITS, applyDispositionPolicies, dispositionPoliciesToText,
  loadDispositionPolicies
} from './disposition-policy.js';
export { loadCatalog, validateCatalog } from './catalog.js';
export { loadIntelCatalog, lookupIntel, validateIntelCatalog } from './intelligence.js';
export {
  DEFAULT_LAB_EVIDENCE_LIMITS, LAB_EVALUATION_PROFILE, LAB_EVIDENCE_PROFILE,
  LAB_EXECUTION_PROFILE, LAB_VERIFICATION_PROFILE, evaluateLabFiles, evaluateLabRun,
  labReportToText, labVerificationToText, loadLabScenario, parseLabEvents,
  verifyLabReport, VERDICTS
} from './lab.js';
export {
  EVIDENCE_FINGERPRINT_PROFILE, FINDING_FINGERPRINT_PROFILE, FINGERPRINT_LIMITS,
  evidenceFingerprint, findingFingerprint, findingKey
} from './fingerprints.js';
export { fetchSample, fetchSampleBatch, planSample, planSampleBatch } from './quarantine.js';
export { loadRulePacks, rulePacksToText } from './rule-packs.js';
export { auditToSarif, auditToText, comparisonToMarkdown } from './reporters.js';
export { MvxError } from './errors.js';
export {
  ENCODED_PAYLOAD_LIMITS, ENCODED_PAYLOAD_PARSER_PROFILES,
  ENCODED_PAYLOAD_PROFILE
} from './encoded-payloads.js';
export { DNR_RULE_LIMITS, DNR_RULE_PROFILE } from './dnr-rules.js';
export {
  BROWSER_EVENT_HANDLER_PROFILE, BROWSER_EVENT_HANDLER_PROVENANCE,
  BODY_EVENT_HANDLER_ATTRIBUTES, FRAMESET_EVENT_HANDLER_ATTRIBUTES,
  HTML_EVENT_HANDLER_ATTRIBUTES, SVG_EVENT_HANDLER_ATTRIBUTES,
  SVG_SMIL_EVENT_HANDLER_ATTRIBUTES, SVG_SMIL_EVENT_HANDLER_ELEMENTS
} from './browser-event-handlers.js';
export {
  DEFAULT_SCORE_CAP, DEFAULT_WEIGHT_PROFILE, SEVERITIES, SEVERITY_WEIGHT,
  WEIGHT_PROFILES, resolveWeightProfile, summarizeFindings
} from './model.js';
export {
  NON_PERMISSION_MANIFEST_RULE_IDS, PERMISSION_RULE_IDS,
  analyzeManifest, analyzeNonPermissionManifestRules, analyzePermissionRules,
  hostPermissions
} from './rules/manifest-rules.js';
export {
  DYNAMIC_VERDICT_SCORES, HYBRID_CONFIDENCE_MULTIPLIERS,
  MANIFEST_COMPATIBILITY_RULE_IDS, MANIFEST_STRUCTURE_RULE_IDS,
  RESEARCH_CONFIG, RESEARCH_CONFIG_SCHEMA_VERSION, RESEARCH_CONFIG_VERSION,
  RESEARCH_MODES, SCORE_INTERPRETATION_NOTICE, SEVERITY_WEIGHT_PROFILES,
  STATIC_SOURCE_RULE_IDS, getResearchMode, getWeightProfile
} from './research/config.js';
export {
  runM1PermissionOnly, runM2StaticOnly, runM3DynamicOnly
} from './research/modes.js';
export {
  HYBRID_FUSION_FORMULA, HYBRID_FUSION_PROFILE, HYBRID_FUSION_SCHEMA_VERSION,
  THREAT_CATEGORY_DEFINITIONS, createFusionConfig, deduplicateStaticFindings,
  fuseHybridEvidence, validateFusionConfig
} from './research/hybrid-fusion.js';
export {
  STABILITY_PROFILE, STABILITY_SCHEMA_VERSION,
  computeMultiSampleStabilitySummary, selectRepeatedRunSubset,
  summarizeRepeatedDynamicRuns
} from './research/stability.js';
export {
  EXPERIMENT_PROFILE, EXPERIMENT_SCHEMA_VERSION, RUN_RECORD_SCHEMA_VERSION,
  collectEnvironmentMetadata, runExperimentBatch, validateDatasetManifest,
  validateRunRecord, verifyExperimentProvenance
} from './research/experiment-runner.js';
export {
  EXPORTER_PROFILE, EXPORTER_SCHEMA_VERSION, exportEvaluationTables,
  exportExecutionLog, exportExperimentBundle, exportFailureAndInconclusiveTable,
  exportMethodSummaries, exportPerExtensionTable, exportStabilitySummaries,
  exportWeightProfileComparison
} from './research/exporters.js';
export {
  ALLOWED_GROUND_TRUTH_LABELS, EVALUATION_PROFILE, EVALUATION_SCHEMA_VERSION,
  NEGATIVE_CLASS, POSITIVE_CLASS, SCORE_NOT_PROBABILITY_NOTICE,
  clopperPearsonCi, computeBinaryMetrics, computeRankingMetrics,
  evaluateExperimentAgainstGroundTruth, exactMcNemarTest,
  filterEligibleGroundTruth, groupAwareBootstrapCi, holmBonferroniCorrection,
  loadGroundTruth
} from './research/metrics.js';
export {
  LIFECYCLE_STATES, LOGGING_PROFILE, LOGGING_SCHEMA_VERSION,
  PROGRESS_EVENT_TYPES, collectExtendedEnvironmentMetadata,
  createProgressEvent, formatProgressEventText, isRetryableFailureCode,
  normalizeStructuredFailure, probeDockerEnvironment, probeGitStatus,
  probeNpmVersion, redactSensitiveObject, redactSensitiveText
} from './research/logging.js';
export {
  RESEARCH_CLI_SCHEMA_VERSION, RESEARCH_HELP, runResearchCli
} from './research/cli.js';
export { parseCsv, stringifyCsv } from './csv.js';
