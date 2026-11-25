import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { auditExtension } from '../src/analyzer.js';
import { MvxError } from '../src/errors.js';
import { createFinding } from '../src/model.js';
import {
  HYBRID_FUSION_FORMULA,
  HYBRID_FUSION_PROFILE,
  createFusionConfig,
  fuseHybridEvidence,
  validateFusionConfig
} from '../src/research/hybrid-fusion.js';
import {
  runM1PermissionOnly,
  runM2StaticOnly,
  runM3DynamicOnly
} from '../src/research/modes.js';
import { VERSION } from '../src/version.js';

const HASH_A = 'a'.repeat(64);
const HASH_B = 'b'.repeat(64);

function makeTestFusionConfig(overrides = {}) {
  return createFusionConfig({
    schemaVersion: 1,
    configVersion: '2026.1-test-fixed',
    formula: 'C-2',
    scoreCap: 100,
    staticBlendAlpha: 0.4,
    confidenceMultipliers: { high: 1.0, medium: 0.7, low: 0.4 },
    deduplicateMvx103Chain: true,
    tierABehavioralFloor: 85,
    tierBDynamicElevation: 20,
    tierBEscalatesWithExternalNetwork: true,
    suspiciousDynamicElevation: 15,
    requireExtensionInitiatorForSuspicious: true,
    corroboration: {
      primaryCategoryBonus: 12,
      t04ConditionalBonus: 5,
      maxBonus: 20
    },
    allowStaticFallbackOnExecutionFailure: false,
    riskTierThresholds: { critical: 70, high: 40, medium: 20 },
    ...overrides
  });
}

function makeFinding(id, severity, confidence = 'high', fingerprint = id) {
  return createFinding({
    id,
    title: id,
    severity,
    confidence,
    category: 'test',
    description: 'Test finding',
    remediation: 'None'
  }, { file: 'test.js', line: 1, snippet: id }, { fingerprint });
}

function makeM1(findings, packageSha256 = HASH_A, status = 'completed') {
  return {
    schemaVersion: 1,
    mode: 'M1',
    status,
    sampleId: 'TEST-001',
    package: { sha256: packageSha256 },
    provenance: { packageSha256, manifestSha256: HASH_A },
    findings,
    failure: status === 'failed' ? { code: 'INVALID_MANIFEST', message: 'broken manifest' } : null
  };
}

function makeM2(findings, packageSha256 = HASH_A, status = 'completed') {
  return {
    schemaVersion: 1,
    mode: 'M2',
    status,
    sampleId: 'TEST-001',
    package: { sha256: packageSha256 },
    provenance: { packageSha256, analysisSha256: HASH_A, manifestSha256: HASH_A },
    findings,
    failure: status === 'failed' ? { code: 'SCAN_LIMIT', message: 'scan limit exceeded' } : null
  };
}

function makeM3({
  status = 'completed',
  verdict = 'no_trigger_observed',
  contained = true,
  packageSha256 = HASH_A,
  objectives = {},
  suspicious = [],
  errors = [],
  uncontainedExternalRequests = 0,
  failure = null
} = {}) {
  return {
    schemaVersion: 1,
    mode: 'M3',
    status,
    sampleId: 'TEST-001',
    verdict,
    contained,
    riskScore: verdict === 'confirmed_attack' ? 100
      : verdict === 'suspicious_activity' ? 50
        : verdict === 'no_trigger_observed' ? 0 : null,
    failure,
    provenance: {
      packageSha256,
      scenarioSha256: HASH_A,
      eventsSha256: HASH_A,
      evaluationSha256: HASH_A,
      seccompSha256: HASH_A,
      imageId: `sha256:${HASH_A}`,
      browser: 'Chromium 150',
      durationMs: 8000,
      staticFindingsConsumed: false
    },
    labReport: status === 'failed' && !verdict ? null : {
      schemaVersion: 1,
      verdict,
      contained,
      summary: {
        eventsAnalyzed: 4,
        uncontainedExternalRequests,
        errors: errors.length
      },
      objectives,
      suspicious,
      errors,
      execution: {
        tool: { version: VERSION },
        extension: { packageSha256, analysisSha256: HASH_A }
      }
    }
  };
}

test('Fusion config requires explicit parameters, computes SHA-256, and rejects invalid ranges', () => {
  const config = makeTestFusionConfig();
  assert.equal(config.profile, HYBRID_FUSION_PROFILE);
  assert.equal(config.formula, HYBRID_FUSION_FORMULA);
  assert.match(config.sha256, /^[a-f0-9]{64}$/);
  assert.ok(Object.isFrozen(config));
  assert.equal(validateFusionConfig(config).sha256, config.sha256);

  // Missing required numeric parameter fails closed (no hidden defaults)
  assert.throws(() => createFusionConfig({ schemaVersion: 1 }), (err) => err instanceof MvxError && err.code === 'INVALID_ARGUMENT');
  // Tier-B elevation must remain strictly below Tier-A floor
  assert.throws(() => makeTestFusionConfig({ tierABehavioralFloor: 85, tierBDynamicElevation: 85 }), (err) => err.code === 'INVALID_ARGUMENT');
  // Tampered config SHA-256 rejected
  assert.throws(() => validateFusionConfig({ ...config, sha256: '0'.repeat(64) }), (err) => err.code === 'INVALID_ARGUMENT');
  // Non-monotonic confidence multipliers rejected
  assert.throws(() => makeTestFusionConfig({ confidenceMultipliers: { high: 0.5, medium: 0.8, low: 0.4 } }), (err) => err.code === 'INVALID_ARGUMENT');
});

test('H1-Alt1 separates Tier-A confirmed objectives from Tier-B contentManipulation alone', () => {
  const config = makeTestFusionConfig();
  const cleanM1 = makeM1([]);
  const cleanM2 = makeM2([]);

  // Tier-A: canary exfiltration activates Tier-A behavioral floor (85) even with zero static findings
  const m3Canary = makeM3({
    verdict: 'confirmed_attack',
    objectives: {
      credentialPassword: {
        status: 'confirmed',
        evidence: [{ event: 2, type: 'network.request', url: 'https://evil.invalid/steal' }]
      }
    }
  });
  const tierAResult = fuseHybridEvidence({ m1: cleanM1, m2: cleanM2, m3: m3Canary }, config);
  assert.equal(tierAResult.status, 'completed');
  assert.equal(tierAResult.hybridRiskScore, 85);
  assert.equal(tierAResult.behavioralAlertFlag, true);
  assert.equal(tierAResult.behavioralAlertTier, 'Tier-A');
  assert.equal(tierAResult.componentScores.tierAFloorApplied, true);

  // Tier-A: unauthorizedDownload and navigationHijack also activate Tier-A floor
  for (const objName of ['unauthorizedDownload', 'navigationHijack']) {
    const res = fuseHybridEvidence({
      m1: cleanM1,
      m2: cleanM2,
      m3: makeM3({
        verdict: 'confirmed_attack',
        objectives: { [objName]: { status: 'confirmed', evidence: [{ event: 3, type: 'test', target: 'https://evil.invalid/' }] } }
      })
    }, config);
    assert.equal(res.hybridRiskScore, 85, objName);
    assert.equal(res.behavioralAlertFlag, true, objName);
  }

  // Tier-B alone (contentManipulation on #mvx-protected): NEVER activates Tier-A floor!
  const m3DomOnly = makeM3({
    verdict: 'confirmed_attack',
    objectives: {
      contentManipulation: {
        status: 'confirmed',
        evidence: [{ event: 4, type: 'dom.mutation', target: 'https://accounts.example.test/login' }]
      }
    }
  });
  const tierBAlone = fuseHybridEvidence({
    m1: cleanM1,
    m2: makeM2([makeFinding('MVX203', 'high', 'medium')]), // 12 * 0.7 = 8.4 -> static = 0.6 * 8.4 = 5.04
    m3: m3DomOnly
  }, config);
  assert.equal(tierBAlone.behavioralAlertFlag, false);
  assert.equal(tierBAlone.behavioralAlertTier, 'Tier-B');
  assert.equal(tierBAlone.componentScores.tierAFloorApplied, false);
  assert.equal(tierBAlone.componentScores.dynamicElevation, 20);
  assert.deepEqual(tierBAlone.corroboratedCategories, ['T04']);
  assert.equal(tierBAlone.componentScores.corroborationBonus, 5);
  assert.equal(tierBAlone.hybridRiskScore, 30.04); // 5.04 + 20 + 5, well below Tier-A floor (85)!

  // Tier-B escalates to Tier-A floor ONLY when paired with qualifying extension-attributed external network request
  const m3DomPlusExfil = makeM3({
    verdict: 'confirmed_attack',
    objectives: {
      contentManipulation: {
        status: 'confirmed',
        evidence: [{ event: 4, type: 'dom.mutation', target: 'https://accounts.example.test/login' }]
      }
    },
    suspicious: [
      { event: 3, type: 'network.request', reason: 'external-request', url: 'https://evil.invalid/c2', initiator: 'extension' }
    ]
  });
  const tierBEscalated = fuseHybridEvidence({ m1: cleanM1, m2: cleanM2, m3: m3DomPlusExfil }, config);
  assert.equal(tierBEscalated.behavioralAlertFlag, true);
  assert.equal(tierBEscalated.componentScores.tierAFloorApplied, true);
  assert.equal(tierBEscalated.hybridRiskScore, 85);
});

test('H2 enforces Static+Dynamic corroboration, blocks M1-M2 static-only bonus, filters initiator, deduplicates events, and never fabricates T01/T06/T07/T08', () => {
  const config = makeTestFusionConfig();

  // M1 + M2 overlap ONLY (with no_trigger_observed) must NEVER yield corroboration bonus
  const staticOverlap = fuseHybridEvidence({
    m1: makeM1([makeFinding('MVX102', 'high', 'high', 'MVX102:cookies'), makeFinding('MVX101', 'high'), makeFinding('MVX103', 'critical')]),
    m2: makeM2([makeFinding('MVX206', 'high'), makeFinding('MVX205', 'high'), makeFinding('MVX201', 'critical')]),
    m3: makeM3({ verdict: 'no_trigger_observed' })
  }, config);
  assert.deepEqual(staticOverlap.corroboratedCategories, []);
  assert.equal(staticOverlap.componentScores.corroborationBonus, 0);
  // Also verifies MVX103 chain deduplication suppressed MVX101 and MVX102:cookies (score = 25, not 49)
  assert.equal(staticOverlap.componentScores.m1DeduplicatedScore, 25);
  assert.deepEqual(staticOverlap.deduplication.mvx103SuppressedOverlapFingerprints, ['MVX101', 'MVX102:cookies']);
  // T01, T06, T07, T08 explicitly marked unsupported
  for (const cat of ['T01', 'T06', 'T07', 'T08']) {
    assert.equal(staticOverlap.threatProfile[cat].corroborationSupported, false);
    assert.equal(staticOverlap.threatProfile[cat].corroborated, false);
  }

  // Unattributed suspicious external request (initiator !== 'extension') is filtered out
  const unattributed = fuseHybridEvidence({
    m1: makeM1([makeFinding('MVX101', 'high')]),
    m2: makeM2([makeFinding('MVX207', 'high')]),
    m3: makeM3({
      verdict: 'suspicious_activity',
      suspicious: [
        { event: 2, type: 'network.request', reason: 'external-request', url: 'https://update.chromium.invalid/', initiator: 'unknown' }
      ]
    })
  }, config);
  assert.deepEqual(unattributed.corroboratedCategories, []);
  assert.equal(unattributed.componentScores.corroborationBonus, 0);
  assert.equal(unattributed.componentScores.dynamicElevation, 0);
  assert.equal(unattributed.deduplication.unattributedSuspiciousSkipped, 1);

  // Verified canary hit qualifies for T03 corroboration even WITHOUT extension initiator attribution,
  // and 3 duplicate events to the same target are deduplicated to 1
  const canaryCorrob = fuseHybridEvidence({
    m1: makeM1([makeFinding('MVX103', 'critical'), makeFinding('MVX102', 'medium', 'high', 'MVX102:downloads')]),
    m2: makeM2([makeFinding('MVX205', 'high'), makeFinding('MVX208', 'medium')]),
    m3: makeM3({
      verdict: 'confirmed_attack',
      objectives: {
        credentialPassword: {
          status: 'confirmed',
          evidence: [
            { event: 2, type: 'network.request', url: 'https://evil.invalid/exfil' },
            { event: 3, type: 'network.request', url: 'https://evil.invalid/exfil' },
            { event: 4, type: 'network.request', url: 'https://evil.invalid/exfil' }
          ]
        },
        unauthorizedDownload: {
          status: 'confirmed',
          evidence: [{ event: 5, type: 'download.attempt', url: 'https://evil.invalid/drop.exe' }]
        }
      }
    })
  }, config);
  assert.deepEqual(canaryCorrob.corroboratedCategories, ['T03', 'T05']);
  assert.equal(canaryCorrob.componentScores.rawCorroborationBonus, 24); // 12 + 12
  assert.equal(canaryCorrob.componentScores.corroborationBonus, 20); // capped at maxBonus=20
  assert.equal(canaryCorrob.deduplication.dynamicDuplicatesRemoved, 2);
});

test('H3 Formula C-2 never dilutes static score on no_trigger_observed and supports W1-W5', () => {
  const config = makeTestFusionConfig();
  // M1: MVX102:debugger (critical), M2: MVX201 (critical, high conf) + MVX203 (high, med conf)
  const m1 = makeM1([makeFinding('MVX102', 'critical', 'high', 'MVX102:debugger')]);
  const m2 = makeM2([
    makeFinding('MVX201', 'critical', 'high'),
    makeFinding('MVX203', 'high', 'medium')
  ]);
  const m3 = makeM3({ verdict: 'no_trigger_observed' });

  const result = fuseHybridEvidence({ m1, m2, m3, weightProfile: 'W1' }, config);
  assert.equal(result.benignInferenceAllowed, false);
  assert.equal(result.componentScores.dynamicElevation, 0);
  // W1: M1=25, M2_adj = 25*1.0 + 12*0.7 = 33.4 -> S_static = 0.4*25 + 0.6*33.4 = 10 + 20.04 = 30.04
  assert.equal(result.componentScores.staticScore, 30.04);
  assert.equal(result.hybridRiskScore, 30.04);
  // Verify W2-W5 computed accurately:
  // W2: M1=35, M2_adj = 35 + 8.4 = 43.4 -> 0.4*35 + 0.6*43.4 = 14 + 26.04 = 40.04
  assert.equal(result.scoresByWeight.W2.hybridRiskScore, 40.04);
  // W4: M1=10, M2_adj = 10 + 7 = 17 -> 0.4*10 + 0.6*17 = 4 + 10.2 = 14.2
  assert.equal(result.scoresByWeight.W4.hybridRiskScore, 14.2);
  // W5: M1=25, M2_adj = 25 + 18*0.7 = 37.6 -> 0.4*25 + 0.6*37.6 = 10 + 22.56 = 32.56
  assert.equal(result.scoresByWeight.W5.hybridRiskScore, 32.56);
});

test('H4 handles all six M3 states: inconclusive fallback, execution failure, and containment violation hard fail', () => {
  const m1 = makeM1([makeFinding('MVX102', 'critical', 'high', 'MVX102:debugger')]);
  const m2 = makeM2([makeFinding('MVX201', 'critical', 'high')]);

  // State 4: inconclusive -> explicit static fallback (never 0 dynamic score)
  const configNoExecFallback = makeTestFusionConfig({ allowStaticFallbackOnExecutionFailure: false });
  const incResult = fuseHybridEvidence({
    m1,
    m2,
    m3: makeM3({ status: 'inconclusive', verdict: 'inconclusive', errors: [{ message: 'CDP error' }] })
  }, configNoExecFallback);
  assert.equal(incResult.status, 'completed_with_static_fallback');
  assert.equal(incResult.staticFallback, true);
  assert.deepEqual(incResult.contributingSources, ['M1', 'M2']);
  assert.equal(incResult.componentScores.dynamicElevation, null);
  assert.equal(incResult.hybridRiskScore, 25); // 0.4*25 + 0.6*25

  // State 5a: execution failure with allowStaticFallbackOnExecutionFailure = false -> failed, score null
  const execFailed = makeM3({
    status: 'failed',
    verdict: null,
    contained: null,
    failure: { code: 'LAB_TIMEOUT', message: 'Host timeout' }
  });
  const failStrict = fuseHybridEvidence({ m1, m2, m3: execFailed }, configNoExecFallback);
  assert.equal(failStrict.status, 'failed');
  assert.equal(failStrict.hybridRiskScore, null);
  assert.equal(failStrict.scoresByWeight, null);
  assert.deepEqual(failStrict.contributingSources, []);
  assert.equal(failStrict.failure.code, 'LAB_TIMEOUT');

  // State 5b: execution failure with allowStaticFallbackOnExecutionFailure = true -> explicit static fallback
  const configAllowExecFallback = makeTestFusionConfig({ allowStaticFallbackOnExecutionFailure: true });
  const failFallback = fuseHybridEvidence({ m1, m2, m3: execFailed }, configAllowExecFallback);
  assert.equal(failFallback.status, 'completed_with_static_fallback');
  assert.equal(failFallback.staticFallback, true);
  assert.equal(failFallback.staticFallbackReason, 'LAB_TIMEOUT');
  assert.deepEqual(failFallback.contributingSources, ['M1', 'M2']);
  assert.equal(failFallback.hybridRiskScore, 25);

  // State 6: containment violation -> HARD FAIL even when allowStaticFallbackOnExecutionFailure = true!
  const uncontained = makeM3({
    status: 'failed',
    verdict: 'confirmed_attack',
    contained: false,
    uncontainedExternalRequests: 1,
    failure: { code: 'LAB_CONTAINMENT_VIOLATION', message: 'Uncontained request' }
  });
  const containmentResult = fuseHybridEvidence({ m1, m2, m3: uncontained }, configAllowExecFallback);
  assert.equal(containmentResult.status, 'failed');
  assert.equal(containmentResult.containmentVerified, false);
  assert.equal(containmentResult.staticFallback, false);
  assert.equal(containmentResult.hybridRiskScore, null);
  assert.equal(containmentResult.scoresByWeight, null);
  assert.deepEqual(containmentResult.contributingSources, []);
  assert.equal(containmentResult.failure.code, 'LAB_CONTAINMENT_VIOLATION');
});

test('Evidence integrity rejects hash mismatches, missing hashes, and Ground Truth inputs', () => {
  const config = makeTestFusionConfig();

  // M1 vs M2 hash mismatch
  assert.throws(
    () => fuseHybridEvidence({ m1: makeM1([], HASH_A), m2: makeM2([], HASH_B), m3: makeM3({ packageSha256: HASH_A }) }, config),
    (err) => err instanceof MvxError && err.code === 'HASH_MISMATCH'
  );
  // Static vs M3 hash mismatch
  assert.throws(
    () => fuseHybridEvidence({ m1: makeM1([], HASH_A), m2: makeM2([], HASH_A), m3: makeM3({ packageSha256: HASH_B }) }, config),
    (err) => err instanceof MvxError && err.code === 'HASH_MISMATCH'
  );
  // Missing M3 hash for production fusion
  assert.throws(
    () => fuseHybridEvidence({ m1: makeM1([], HASH_A), m2: makeM2([], HASH_A), m3: makeM3({ packageSha256: null }) }, config),
    (err) => err instanceof MvxError && err.code === 'HASH_MISSING'
  );
  // Ground Truth input strictly forbidden
  assert.throws(
    () => fuseHybridEvidence({ m1: makeM1([]), m2: makeM2([]), m3: makeM3(), groundTruth: 'Malicious' }, config),
    (err) => err instanceof MvxError && err.code === 'GROUND_TRUTH_FORBIDDEN'
  );
});

test('End-to-end M1 + M2 + mocked M3 -> M4 fusion on cookie-access/mv3 preserves auditExtension provenance', async () => {
  const fixture = path.resolve('corpus/fixtures/cookie-access/mv3');
  const baseline = await auditExtension(fixture);
  assert.equal(baseline.analysis.sha256, 'b57ae698199aabddb9d1280d47bc1953df5ce6a6fe687537eff40c40cc0fe427');

  const m1 = await runM1PermissionOnly(fixture, { sampleId: 'CST-002' });
  const m2 = await runM2StaticOnly(fixture, { sampleId: 'CST-002' });
  const m3 = await runM3DynamicOnly(fixture, '/mock/scenario.json', '/mock/out', {
    acknowledgeRisk: true,
    sampleId: 'CST-002',
    expectedPackageSha256: m1.package.sha256,
    labRunner: async () => ({
      imageId: `sha256:${HASH_A}`,
      output: '/mock/out',
      eventsPath: '/mock/out/events.jsonl',
      reportPath: '/mock/out/report.json',
      scenarioPath: '/mock/scenario.json',
      report: {
        schemaVersion: 1,
        verdict: 'confirmed_attack',
        contained: true,
        summary: { eventsAnalyzed: 3, uncontainedExternalRequests: 0, errors: 0 },
        objectives: {
          sessionCookie: {
            status: 'confirmed',
            evidence: [{ event: 2, type: 'network.request', url: 'https://collector.evil.invalid/c' }]
          }
        },
        suspicious: [],
        errors: [],
        caveats: [],
        execution: {
          tool: { version: VERSION },
          extension: { packageSha256: m1.package.sha256, analysisSha256: m2.analysis.sha256 }
        },
        evidenceProvenance: {
          scenario: { sha256: HASH_A },
          events: { sha256: HASH_A },
          evaluation: { sha256: HASH_A }
        }
      }
    })
  });

  const config = makeTestFusionConfig();
  const m4 = fuseHybridEvidence({ m1, m2, m3, sampleId: 'CST-002' }, config);
  assert.equal(m4.status, 'completed');
  assert.equal(m4.provenance.packageSha256, baseline.package.sha256);
  assert.equal(m4.behavioralAlertFlag, true);
  assert.equal(m4.hybridRiskScore, 85);
  assert.deepEqual(m4.corroboratedCategories, ['T03']);
  assert.deepEqual(m4.deduplication.mvx103SuppressedOverlapFingerprints, ['MVX101', 'MVX102:cookies']);
});
