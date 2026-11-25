import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { auditExtension } from '../src/analyzer.js';
import { MvxError } from '../src/errors.js';
import { RESEARCH_CONFIG_VERSION } from '../src/research/config.js';
import {
  runM1PermissionOnly,
  runM2StaticOnly,
  runM3DynamicOnly
} from '../src/research/modes.js';
import { PERMISSION_RULE_IDS } from '../src/rules/manifest-rules.js';
import { VERSION } from '../src/version.js';
import { writeExtension } from '../support/helpers.js';

const PERMISSION_SET = new Set(PERMISSION_RULE_IDS);

function makeMockLabResult({
  verdict,
  contained = true,
  packageSha256,
  uncontainedExternalRequests = 0,
  errors = []
}) {
  const imageId = `sha256:${'a'.repeat(64)}`;
  return {
    imageId,
    output: '/mock/out',
    eventsPath: '/mock/out/events.jsonl',
    reportPath: '/mock/out/report.json',
    scenarioPath: '/mock/out/scenario.json',
    report: {
      schemaVersion: 1,
      scenarioId: 'credential-session-exfiltration',
      verdict,
      contained,
      summary: {
        eventsAnalyzed: 4,
        confirmedObjectives: verdict === 'confirmed_attack' ? 1 : 0,
        suspiciousEvents: verdict === 'suspicious_activity' ? 1 : 0,
        errors: errors.length,
        blockedExternalRequests: verdict === 'no_trigger_observed' ? 0 : 1,
        uncontainedExternalRequests,
        completed: verdict !== 'inconclusive'
      },
      objectives: {},
      suspicious: [],
      errors,
      caveats: [
        'no_trigger_observed is not a benign verdict.'
      ],
      execution: {
        profile: 'mvx-lab-execution-v1',
        startedAt: '2026-11-25T10:00:00.000Z',
        tool: { version: VERSION },
        extension: {
          packageSha256,
          analysisSha256: 'b'.repeat(64)
        },
        scenarioSha256: 'c'.repeat(64),
        browser: 'Chromium 150.0.0.0',
        container: {
          imageReference: 'mvx-lab:mock',
          imageId,
          network: 'none'
        },
        isolation: { seccompSha256: 'd'.repeat(64) },
        durationMs: 8_000
      },
      evidenceProvenance: {
        profile: 'mvx-lab-evidence-v1',
        scenario: { bytes: 200, sha256: 'c'.repeat(64) },
        events: { bytes: 500, sha256: 'e'.repeat(64), records: 4 },
        evaluation: { profile: 'mvx-lab-evaluation-v1', sha256: 'f'.repeat(64) }
      }
    }
  };
}

test('M1 and M2 enforce strict rule isolation and share identical packageSha256 with auditExtension', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-modes-iso-'));
  t.after(() => rm(temp, { recursive: true, force: true }));

  await writeExtension(temp, {
    manifest_version: 3,
    name: 'Mixed capability and source fixture',
    version: '1.2.3',
    permissions: ['cookies', 'tabs', 'declarativeNetRequest'],
    host_permissions: ['<all_urls>', 'http://insecure.example.invalid/*'],
    content_scripts: [{ matches: ['<all_urls>'], js: ['content.js'], world: 'MAIN' }],
    content_security_policy: { extension_pages: "script-src 'self' 'unsafe-eval'; object-src 'self'" },
    declarative_net_request: {
      rule_resources: [{ id: 'ruleset_1', enabled: true, path: 'rules.json' }]
    }
  }, {
    'content.js': "eval(payload);\nchrome.cookies.getAll({}, () => {});\n",
    'rules.json': JSON.stringify([{
      id: 1,
      priority: 1,
      action: { type: 'redirect', redirect: { url: 'https://redirect.example.invalid/' } },
      condition: { urlFilter: 'example.test' }
    }])
  });

  const baselineAudit = await auditExtension(temp);
  const m1 = await runM1PermissionOnly(temp, { sampleId: 'MIX-001' });
  const m2Default = await runM2StaticOnly(temp, { sampleId: 'MIX-001' });
  const m2WithStruct = await runM2StaticOnly(temp, {
    sampleId: 'MIX-001',
    includeManifestStructure: true
  });

  // Identical packageSha256 across baseline, M1, and M2
  assert.equal(m1.package.sha256, baselineAudit.package.sha256);
  assert.equal(m2Default.package.sha256, baselineAudit.package.sha256);
  assert.equal(m1.provenance.packageSha256, m2Default.provenance.packageSha256);
  assert.equal(m2Default.provenance.analysisSha256, baselineAudit.analysis.sha256);

  // Metadata and config version provenance
  assert.equal(m1.researchConfig.configVersion, RESEARCH_CONFIG_VERSION);
  assert.equal(m1.tool.version, VERSION);
  assert.equal(m2Default.researchConfig.configVersion, RESEARCH_CONFIG_VERSION);
  assert.equal(m2Default.tool.version, VERSION);

  // M1 emits ONLY permission rules (MVX101, MVX102, MVX103, MVX111)
  const m1Ids = m1.findings.map((finding) => finding.id);
  assert.ok(m1Ids.every((id) => PERMISSION_SET.has(id)));
  assert.deepEqual([...new Set(m1Ids)].sort(), ['MVX101', 'MVX102', 'MVX103', 'MVX111']);
  assert.equal(m1.provenance.sourceAnalysisExecuted, false);
  assert.equal(m1.provenance.encodedPayloadAnalysisExecuted, false);
  assert.equal(m1.provenance.dnrAnalysisExecuted, false);

  // M2 excludes ALL five permission rules and keeps OD-1 (MVX104-MVX109) off by default
  const m2DefaultIds = m2Default.findings.map((finding) => finding.id);
  assert.ok(m2DefaultIds.every((id) => !PERMISSION_SET.has(id)));
  assert.deepEqual([...new Set(m2DefaultIds)].sort(), ['MVX114', 'MVX201', 'MVX206']);
  assert.equal(m2Default.provenance.permissionAnalysisExecuted, false);
  assert.equal(m2Default.researchConfig.switches.includeManifestStructure, false);
  assert.equal(m2Default.researchConfig.switches.includeArchiveAuthenticity, false);

  // Explicit OD-1 switch includes MVX104/MVX106/MVX107 without leaking permission rules
  const m2StructIds = m2WithStruct.findings.map((finding) => finding.id);
  assert.ok(m2StructIds.every((id) => !PERMISSION_SET.has(id)));
  assert.ok(m2StructIds.includes('MVX104'));
  assert.ok(m2StructIds.includes('MVX106'));
  assert.ok(m2StructIds.includes('MVX107'));
});

test('M1 does not invoke source, Base64, or DNR analyzers even when source/DNR are malformed or exceed limits', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-m1-no-source-'));
  t.after(() => rm(temp, { recursive: true, force: true }));

  await writeExtension(temp, {
    manifest_version: 3,
    name: 'Broken DNR and large source',
    version: '1.0.0',
    permissions: ['debugger'],
    declarative_net_request: {
      rule_resources: [{ id: 'bad', enabled: true, path: 'broken-dnr.json' }]
    }
  }, {
    'broken-dnr.json': '{not valid json',
    'huge.js': `eval(atob('${Buffer.from('eval(innerPayload);').toString('base64')}'));\n${'a'.repeat(2_000)}`
  });

  // Restrict maxFileBytes to 500 so M2 fails with SCAN_LIMIT while M1 succeeds without reading source or DNR
  const m1 = await runM1PermissionOnly(temp, { limits: { maxFileBytes: 500, maxPackageFileBytes: 10_000 } });
  assert.equal(m1.status, 'completed');
  assert.deepEqual(m1.findings.map((finding) => finding.id), ['MVX102']);
  assert.equal(m1.summary.riskScore, 25);

  const m2Failure = await runM2StaticOnly(temp, {
    limits: { maxFileBytes: 500, maxPackageFileBytes: 10_000 },
    captureFailures: true
  });
  assert.equal(m2Failure.status, 'failed');
  assert.equal(m2Failure.failure.code, 'SCAN_LIMIT');
  assert.equal(m2Failure.summary, null);
  assert.equal(m2Failure.riskScore, null);
});

test('M2 controls MVX004 (OD-2) explicitly via includeArchiveAuthenticity switch', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-m2-od2-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  await writeExtension(temp, { manifest_version: 3, name: 'Clean MV3', version: '1.0.0' });

  const invalidAuth = {
    format: 'crx',
    authenticity: { status: 'invalid', error: 'Invalid signature' }
  };
  const m2Off = await runM2StaticOnly(temp, { archiveAuthenticity: invalidAuth });
  assert.deepEqual(m2Off.findings, []);

  const m2On = await runM2StaticOnly(temp, {
    includeArchiveAuthenticity: true,
    archiveAuthenticity: invalidAuth
  });
  assert.deepEqual(m2On.findings.map((finding) => finding.id), ['MVX004']);
});

test('M1 and M2 support W1-W5 weight profiles and preserve auditExtension analysis.sha256', async () => {
  const cookieFixture = path.resolve('corpus/fixtures/cookie-access/mv3');
  const audit = await auditExtension(cookieFixture);
  assert.equal(audit.analysis.sha256, 'b57ae698199aabddb9d1280d47bc1953df5ce6a6fe687537eff40c40cc0fe427');

  // cookie-access/mv3 permission findings: MVX103 (critical), MVX101 (high), MVX102:cookies (high)
  const m1 = await runM1PermissionOnly(cookieFixture, { weightProfile: 'W2' });
  assert.equal(m1.summary.weightProfile, 'W2');
  assert.equal(m1.summary.riskScore, 59); // 35 + 12 + 12
  assert.equal(m1.scoresByWeight.W1.riskScore, 49); // 25 + 12 + 12
  assert.equal(m1.scoresByWeight.W2.riskScore, 59); // 35 + 12 + 12
  assert.equal(m1.scoresByWeight.W3.riskScore, 50); // 20 + 15 + 15
  assert.equal(m1.scoresByWeight.W4.riskScore, 30); // 10 + 10 + 10
  assert.equal(m1.scoresByWeight.W5.riskScore, 61); // 25 + 18 + 18

  // cookie-access/mv3 static finding: MVX206 (high)
  const m2 = await runM2StaticOnly(cookieFixture, { weightProfile: 'W5' });
  assert.equal(m2.summary.weightProfile, 'W5');
  assert.equal(m2.summary.riskScore, 18);
  assert.equal(m2.scoresByWeight.W1.riskScore, 12);
  assert.equal(m2.scoresByWeight.W2.riskScore, 12);
  assert.equal(m2.scoresByWeight.W3.riskScore, 15);
  assert.equal(m2.scoresByWeight.W4.riskScore, 10);
  assert.equal(m2.scoresByWeight.W5.riskScore, 18);
});

test('M3 executes via mocked labRunner without Docker, verifies identity/containment, and never reads static findings', async () => {
  const expectedHash = '1'.repeat(64);
  let runnerCalls = 0;
  const mockRunner = async (params) => {
    runnerCalls += 1;
    assert.equal(params.acknowledgeRisk, true);
    return makeMockLabResult({ verdict: 'confirmed_attack', packageSha256: expectedHash });
  };

  // Requires explicit acknowledgeRisk
  await assert.rejects(
    () => runM3DynamicOnly('/ext', '/sc.json', '/out', { labRunner: mockRunner }),
    (error) => error instanceof MvxError && error.code === 'RISK_ACK_REQUIRED'
  );
  assert.equal(runnerCalls, 0);

  // Confirmed attack
  const confirmed = await runM3DynamicOnly('/ext', '/sc.json', '/out', {
    acknowledgeRisk: true,
    expectedPackageSha256: expectedHash,
    sampleId: 'CST-019',
    labRunner: mockRunner
  });
  assert.equal(confirmed.status, 'completed');
  assert.equal(confirmed.verdict, 'confirmed_attack');
  assert.equal(confirmed.riskScore, 100);
  assert.equal(confirmed.contained, true);
  assert.equal(confirmed.provenance.packageSha256, expectedHash);
  assert.equal(confirmed.provenance.staticFindingsConsumed, false);
  assert.equal(confirmed.benignInferenceAllowed, false);

  // no_trigger_observed is NOT treated as Benign
  const noTrigger = await runM3DynamicOnly('/ext', '/sc.json', '/out', {
    acknowledgeRisk: true,
    expectedPackageSha256: expectedHash,
    labRunner: async () => makeMockLabResult({ verdict: 'no_trigger_observed', packageSha256: expectedHash })
  });
  assert.equal(noTrigger.status, 'completed');
  assert.equal(noTrigger.verdict, 'no_trigger_observed');
  assert.equal(noTrigger.riskScore, 0);
  assert.equal(noTrigger.benignInferenceAllowed, false);
  assert.ok(noTrigger.caveats.some((caveat) => /NOT a Benign verdict/.test(caveat)));

  // suspicious_activity maps to 50
  const suspicious = await runM3DynamicOnly('/ext', '/sc.json', '/out', {
    acknowledgeRisk: true,
    labRunner: async () => makeMockLabResult({ verdict: 'suspicious_activity', packageSha256: expectedHash })
  });
  assert.equal(suspicious.status, 'completed');
  assert.equal(suspicious.riskScore, 50);

  // inconclusive never converts into zero risk score
  const inconclusive = await runM3DynamicOnly('/ext', '/sc.json', '/out', {
    acknowledgeRisk: true,
    labRunner: async () => makeMockLabResult({
      verdict: 'inconclusive',
      packageSha256: expectedHash,
      errors: [{ event: 2, type: 'lab.error', message: 'page target was not attached' }]
    })
  });
  assert.equal(inconclusive.status, 'inconclusive');
  assert.equal(inconclusive.verdict, 'inconclusive');
  assert.equal(inconclusive.riskScore, null);
  assert.equal(inconclusive.failure.code, 'LAB_INCONCLUSIVE');

  // Containment failure is recorded explicitly with riskScore: null
  const uncontained = await runM3DynamicOnly('/ext', '/sc.json', '/out', {
    acknowledgeRisk: true,
    labRunner: async () => makeMockLabResult({
      verdict: 'confirmed_attack',
      contained: false,
      uncontainedExternalRequests: 1,
      packageSha256: expectedHash
    })
  });
  assert.equal(uncontained.status, 'failed');
  assert.equal(uncontained.contained, false);
  assert.equal(uncontained.riskScore, null);
  assert.equal(uncontained.failure.code, 'LAB_CONTAINMENT_VIOLATION');

  // Package hash mismatch fails closed
  await assert.rejects(
    () => runM3DynamicOnly('/ext', '/sc.json', '/out', {
      acknowledgeRisk: true,
      expectedPackageSha256: '2'.repeat(64),
      labRunner: async () => makeMockLabResult({ verdict: 'no_trigger_observed', packageSha256: expectedHash })
    }),
    (error) => error instanceof MvxError && error.code === 'LAB_IDENTITY_MISMATCH'
  );

  // Runtime container error is recorded explicitly with riskScore: null (not 0)
  const runtimeFailure = await runM3DynamicOnly('/ext', '/sc.json', '/out', {
    acknowledgeRisk: true,
    sampleId: 'RWM-001',
    labRunner: async () => {
      throw new MvxError('Lab container exceeded the 60000-millisecond host runtime limit', {
        code: 'LAB_TIMEOUT'
      });
    }
  });
  assert.equal(runtimeFailure.status, 'failed');
  assert.equal(runtimeFailure.riskScore, null);
  assert.equal(runtimeFailure.verdict, null);
  assert.equal(runtimeFailure.failure.code, 'LAB_TIMEOUT');
  assert.equal(runtimeFailure.provenance.staticFindingsConsumed, false);
});

test('M1 failure capture records error explicitly without converting errors to zero risk scores', async () => {
  const result = await runM1PermissionOnly('/nonexistent/extension/path', {
    sampleId: 'BAD-001',
    captureFailures: true
  });
  assert.equal(result.status, 'failed');
  assert.equal(result.summary, null);
  assert.equal(result.scoresByWeight, null);
  assert.equal(result.riskScore, null);
  assert.equal(result.failure.code, 'INPUT_NOT_FOUND');
});
