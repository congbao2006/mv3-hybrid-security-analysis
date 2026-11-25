import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { auditExtension } from '../src/analyzer.js';
import { loadCatalog } from '../src/catalog.js';
import { MvxError } from '../src/errors.js';
import {
  DEFAULT_SCORE_CAP,
  DEFAULT_WEIGHT_PROFILE,
  SEVERITY_WEIGHT,
  WEIGHT_PROFILES,
  createFinding,
  resolveWeightProfile,
  summarizeFindings
} from '../src/model.js';
import {
  RESEARCH_CONFIG,
  RESEARCH_CONFIG_SCHEMA_VERSION,
  RESEARCH_CONFIG_VERSION,
  RESEARCH_MODES,
  SCORE_INTERPRETATION_NOTICE,
  SEVERITY_WEIGHT_PROFILES,
  getResearchMode,
  getWeightProfile
} from '../src/research/config.js';
import {
  NON_PERMISSION_MANIFEST_RULE_IDS,
  PERMISSION_RULE_IDS,
  analyzeManifest,
  analyzeNonPermissionManifestRules,
  analyzePermissionRules
} from '../src/rules/manifest-rules.js';
import { writeExtension } from '../support/helpers.js';

function sampleFindings(severities) {
  return severities.map((severity, index) => createFinding({
    id: `TEST${String(index + 1).padStart(3, '0')}`,
    title: `Finding ${index + 1}`,
    severity,
    category: 'test',
    description: 'Synthetic test finding.',
    remediation: 'None.'
  }, { file: 'manifest.json', field: 'test', snippet: severity }));
}

test('Phase 0 research configuration defines frozen M1-M4 modes, W1-W5 profiles, and versions', () => {
  assert.equal(RESEARCH_CONFIG.schemaVersion, RESEARCH_CONFIG_SCHEMA_VERSION);
  assert.equal(RESEARCH_CONFIG.configVersion, RESEARCH_CONFIG_VERSION);
  assert.equal(RESEARCH_CONFIG.defaultWeightProfile, DEFAULT_WEIGHT_PROFILE);
  assert.equal(RESEARCH_CONFIG.scoreCap, DEFAULT_SCORE_CAP);
  assert.match(SCORE_INTERPRETATION_NOTICE, /not a malware probability/i);
  assert.ok(Object.isFrozen(RESEARCH_CONFIG));
  assert.ok(Object.isFrozen(RESEARCH_MODES));
  assert.ok(Object.isFrozen(SEVERITY_WEIGHT_PROFILES));

  assert.deepEqual(Object.keys(RESEARCH_MODES), ['M1', 'M2', 'M3', 'M4']);
  assert.deepEqual(
    [RESEARCH_MODES.M1.permissionAnalysis, RESEARCH_MODES.M1.staticAnalysis, RESEARCH_MODES.M1.dynamicAnalysis, RESEARCH_MODES.M1.hybridIntegration],
    [true, false, false, false]
  );
  assert.deepEqual(
    [RESEARCH_MODES.M2.permissionAnalysis, RESEARCH_MODES.M2.staticAnalysis, RESEARCH_MODES.M2.dynamicAnalysis, RESEARCH_MODES.M2.hybridIntegration],
    [false, true, false, false]
  );
  assert.deepEqual(
    [RESEARCH_MODES.M3.permissionAnalysis, RESEARCH_MODES.M3.staticAnalysis, RESEARCH_MODES.M3.dynamicAnalysis, RESEARCH_MODES.M3.hybridIntegration],
    [false, false, true, false]
  );
  assert.deepEqual(
    [RESEARCH_MODES.M4.permissionAnalysis, RESEARCH_MODES.M4.staticAnalysis, RESEARCH_MODES.M4.dynamicAnalysis, RESEARCH_MODES.M4.hybridIntegration],
    [true, true, true, true]
  );

  assert.equal(getResearchMode('M1'), RESEARCH_MODES.M1);
  assert.equal(getResearchMode('M4'), RESEARCH_MODES.M4);
  assert.throws(() => getResearchMode('M5'), (error) => error instanceof MvxError && error.code === 'INVALID_ARGUMENT');

  assert.deepEqual(Object.keys(SEVERITY_WEIGHT_PROFILES), ['W1', 'W2', 'W3', 'W4', 'W5']);
  assert.deepEqual(getWeightProfile().id, 'W1');
  assert.deepEqual(getWeightProfile('W3').weights, WEIGHT_PROFILES.W3);
  assert.throws(() => getWeightProfile('W9'), (error) => error instanceof MvxError && error.code === 'INVALID_ARGUMENT');
});

test('Phase 1A weight profiles W1-W5 match exact specifications and preserve default W1 compatibility', () => {
  const expected = {
    W1: { critical: 25, high: 12, medium: 6, low: 2, info: 0 },
    W2: { critical: 35, high: 12, medium: 6, low: 2, info: 0 },
    W3: { critical: 20, high: 15, medium: 10, low: 5, info: 0 },
    W4: { critical: 10, high: 10, medium: 10, low: 10, info: 0 },
    W5: { critical: 25, high: 18, medium: 6, low: 2, info: 0 }
  };

  assert.deepEqual(SEVERITY_WEIGHT, expected.W1);
  assert.equal(WEIGHT_PROFILES.W1, SEVERITY_WEIGHT);

  const oneOfEach = sampleFindings(['critical', 'high', 'medium', 'low', 'info']);
  const legacySummary = summarizeFindings(oneOfEach);
  assert.deepEqual(Object.keys(legacySummary), ['total', 'counts', 'riskScore', 'rating']);
  assert.equal(legacySummary.riskScore, 45);
  assert.equal(legacySummary.rating, 'high');

  const expectedTotals = { W1: 45, W2: 55, W3: 50, W4: 40, W5: 51 };
  for (const [profileId, weights] of Object.entries(expected)) {
    assert.deepEqual(WEIGHT_PROFILES[profileId], weights);
    const summary = summarizeFindings(oneOfEach, { weightProfile: profileId });
    assert.equal(summary.total, 5);
    assert.equal(summary.riskScore, expectedTotals[profileId]);
    assert.equal(summary.rating, 'high');
    assert.equal(summary.weightProfile, profileId);
    assert.deepEqual(summary.weights, weights);
  }
});

test('Phase 1A score cap saturation at 100 holds across all W1-W5 profiles and validates invalid inputs', () => {
  const heavyFindings = sampleFindings([
    'critical', 'critical', 'critical', 'high', 'high', 'high', 'medium', 'medium', 'low', 'low'
  ]);
  for (const profileId of ['W1', 'W2', 'W3', 'W4', 'W5']) {
    const summary = summarizeFindings(heavyFindings, { weightProfile: profileId });
    assert.equal(summary.riskScore, 100);
    assert.equal(summary.rating, 'critical');
    assert.equal(summary.weightProfile, profileId);
  }

  const w2ThreeCritical = summarizeFindings(sampleFindings(['critical', 'critical', 'critical']), { weightProfile: 'W2' });
  assert.equal(w2ThreeCritical.riskScore, 100);
  const w1ThreeCritical = summarizeFindings(sampleFindings(['critical', 'critical', 'critical']), { weightProfile: 'W1' });
  assert.equal(w1ThreeCritical.riskScore, 75);

  const w4TenLow = summarizeFindings(sampleFindings(Array(10).fill('low')), { weightProfile: 'W4' });
  assert.equal(w4TenLow.riskScore, 100);
  assert.equal(w4TenLow.rating, 'critical');

  const custom = summarizeFindings(sampleFindings(['high', 'low']), {
    weights: { critical: 50, high: 30, medium: 10, low: 5 },
    scoreCap: 100
  });
  assert.equal(custom.weightProfile, 'custom');
  assert.equal(custom.riskScore, 35);
  assert.equal(custom.weights.info, 0);

  assert.throws(() => resolveWeightProfile('W6'), (error) => error.code === 'INVALID_ARGUMENT');
  assert.throws(() => resolveWeightProfile({ critical: -1, high: 1, medium: 1, low: 1 }), (error) => error.code === 'INVALID_ARGUMENT');
  assert.throws(() => resolveWeightProfile({ critical: 10 }), (error) => error.code === 'INVALID_ARGUMENT');
  assert.throws(() => summarizeFindings([], { weightProfile: 'W1', weights: WEIGHT_PROFILES.W2 }), (error) => error.code === 'INVALID_ARGUMENT');
  assert.throws(() => summarizeFindings([], { unknownOption: true }), (error) => error.code === 'INVALID_ARGUMENT');
  assert.throws(() => summarizeFindings([], { scoreCap: 0 }), (error) => error.code === 'INVALID_ARGUMENT');
});

test('Phase 1B permission rule decomposition isolates permission rules from non-permission manifest rules', () => {
  const permissionSet = new Set(PERMISSION_RULE_IDS);
  const nonPermissionSet = new Set(NON_PERMISSION_MANIFEST_RULE_IDS);
  for (const id of permissionSet) {
    assert.equal(nonPermissionSet.has(id), false, `overlap on ${id}`);
  }
  assert.deepEqual([...permissionSet], ['MVX101', 'MVX102', 'MVX103', 'MVX110', 'MVX111']);
  assert.deepEqual([...nonPermissionSet], ['MVX001', 'MVX104', 'MVX105', 'MVX106', 'MVX107', 'MVX108', 'MVX109', 'MVX112']);

  const mixedManifest = {
    manifest_version: 3,
    name: 'Mixed manifest fixture',
    version: '1.0.0',
    permissions: ['cookies', 'tabs', 'webRequestBlocking'],
    host_permissions: ['<all_urls>', 'http://insecure.example.invalid/*'],
    background: { scripts: ['legacy.js'] },
    content_security_policy: { extension_pages: "script-src 'self' 'unsafe-eval'; object-src 'self'" },
    externally_connectable: { ids: ['*'] },
    content_scripts: [{ matches: ['<all_urls>'], js: ['content.js'], all_frames: true, world: 'MAIN' }],
    web_accessible_resources: [{ resources: ['*'], matches: ['<all_urls>'] }]
  };

  const permFindings = analyzePermissionRules(mixedManifest);
  const nonPermFindings = analyzeNonPermissionManifestRules(mixedManifest);
  const combinedFindings = analyzeManifest(mixedManifest);

  const permIds = permFindings.map((finding) => finding.id);
  const nonPermIds = nonPermFindings.map((finding) => finding.id);

  assert.ok(permIds.every((id) => permissionSet.has(id)));
  assert.ok(nonPermIds.every((id) => nonPermissionSet.has(id)));
  assert.deepEqual([...new Set(permIds)], ['MVX101', 'MVX102', 'MVX103', 'MVX110', 'MVX111']);
  assert.deepEqual([...new Set(nonPermIds)], ['MVX104', 'MVX105', 'MVX106', 'MVX107', 'MVX108', 'MVX109', 'MVX112']);

  assert.equal(combinedFindings.length, permFindings.length + nonPermFindings.length);
  assert.deepEqual(
    combinedFindings.map((finding) => finding.fingerprint),
    [
      'MVX101',
      'MVX102:cookies',
      'MVX102:tabs',
      'MVX103',
      'MVX104:0',
      'MVX105:0',
      'MVX106:0',
      'MVX107',
      'MVX108',
      'MVX109',
      'MVX110',
      'MVX111',
      'MVX112'
    ]
  );

  const invalidVersionManifest = { manifest_version: 4, name: 'Unsupported', version: '1.0.0' };
  assert.deepEqual(analyzePermissionRules(invalidVersionManifest), []);
  assert.deepEqual(analyzeNonPermissionManifestRules(invalidVersionManifest).map((f) => f.id), ['MVX001']);
  assert.deepEqual(analyzeManifest(invalidVersionManifest).map((f) => f.id), ['MVX001']);
});

test('Phase 1B preserves existing analyzer regression behavior and provenance hashes', async (t) => {
  const { catalog } = await loadCatalog();
  for (const scenario of catalog.scenarios) {
    for (const version of ['mv2', 'mv3']) {
      const fixtureDir = path.resolve('corpus', scenario.fixtures[version]);
      const result = await auditExtension(fixtureDir);
      const actualIds = new Set(result.findings.map((finding) => finding.id));
      for (const expectedId of scenario.expectedFindings[version]) {
        assert.ok(actualIds.has(expectedId), `${scenario.id}/${version} missing ${expectedId}`);
      }
      assert.deepEqual(Object.keys(result.summary), ['total', 'counts', 'riskScore', 'rating']);
    }
  }

  const cookieMv3 = await auditExtension(path.resolve('corpus/fixtures/cookie-access/mv3'));
  assert.equal(cookieMv3.analysis.sha256, 'b57ae698199aabddb9d1280d47bc1953df5ce6a6fe687537eff40c40cc0fe427');

  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-phase1-perm-only-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  await writeExtension(temp, {
    manifest_version: 3,
    name: 'Permission-only manifest',
    version: '1.0.0',
    permissions: ['debugger']
  });
  const audit = await auditExtension(temp);
  assert.equal(audit.summary.riskScore, 25);
  assert.equal(summarizeFindings(audit.findings, { weightProfile: 'W2' }).riskScore, 35);
});
