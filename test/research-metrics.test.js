import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { MvxError } from '../src/errors.js';
import { exportEvaluationTables } from '../src/research/exporters.js';
import {
  NEGATIVE_CLASS,
  POSITIVE_CLASS,
  clopperPearsonCi,
  computeBinaryMetrics,
  computeRankingMetrics,
  evaluateExperimentAgainstGroundTruth,
  exactMcNemarTest,
  filterEligibleGroundTruth,
  groupAwareBootstrapCi,
  holmBonferroniCorrection,
  loadGroundTruth
} from '../src/research/metrics.js';

test('Binary metrics compute exact confusion matrix, Precision, Recall, Specificity, F1, MCC, Balanced Accuracy, Clopper-Pearson CIs, and safe null handling', () => {
  // Synthetic labels: 4 Malicious (3 TP, 1 FN), 6 Benign (5 TN, 1 FP)
  const yTrue = [
    'Malicious', 'Malicious', 'Malicious', 'Malicious',
    'Benign', 'Benign', 'Benign', 'Benign', 'Benign', 'Benign'
  ];
  const yPred = [true, true, true, false, true, false, false, false, false, false];
  const m = computeBinaryMetrics(yTrue, yPred);

  assert.equal(m.positiveClass, POSITIVE_CLASS);
  assert.equal(m.negativeClass, NEGATIVE_CLASS);
  assert.deepEqual(
    [m.confusionMatrix.tp, m.confusionMatrix.fp, m.confusionMatrix.tn, m.confusionMatrix.fn],
    [3, 1, 5, 1]
  );
  assert.equal(m.precision.value, 0.75); // 3/4
  assert.equal(m.recall.value, 0.75); // 3/4
  assert.equal(m.specificity.value, 0.833333); // 5/6
  assert.equal(m.f1.value, 0.75); // 6/8
  assert.equal(m.fpr.value, 0.166667); // 1/6
  assert.equal(m.fnr.value, 0.25); // 1/4
  assert.equal(m.accuracy.value, 0.8); // 8/10
  assert.equal(m.balancedAccuracy.value, 0.791667);
  // MCC = (3*5 - 1*1) / sqrt(4*4*6*6) = 14 / 24 = 0.583333
  assert.equal(m.mcc.value, 0.583333);
  assert.ok(m.confidenceIntervals.recall.low < 0.75 && m.confidenceIntervals.recall.high > 0.75);
  assert.equal(clopperPearsonCi(0, 0).low, null);

  // Zero predicted positives -> Precision and MCC return null with explicit reason (no NaN/Infinity)
  const allNegPred = computeBinaryMetrics(['Malicious', 'Benign'], [false, false]);
  assert.equal(allNegPred.precision.value, null);
  assert.equal(allNegPred.precision.undefinedReason, 'ZERO_PREDICTED_POSITIVES');
  assert.equal(allNegPred.mcc.value, null);
  assert.equal(allNegPred.mcc.undefinedReason, 'ZERO_MCC_DENOMINATOR');
  assert.equal(allNegPred.recall.value, 0);
});

test('Ranking metrics compute exact tie-aware ROC-AUC and PR-AUC and refuse single-operating-point or single-class inputs', () => {
  // Perfect separation
  const perfect = computeRankingMetrics(
    ['Malicious', 'Malicious', 'Benign', 'Benign'],
    [90, 80, 20, 10]
  );
  assert.equal(perfect.rocAuc.value, 1);
  assert.equal(perfect.prAuc.value, 1);

  // Tied score between 1 positive and 1 negative -> ROC-AUC = 0.75
  const tied = computeRankingMetrics(
    ['Malicious', 'Malicious', 'Benign', 'Benign'],
    [90, 50, 50, 10]
  );
  assert.equal(tied.rocAuc.value, 0.875);

  // Constant score (single operating point) -> explicitly null, NOT silently 0.5
  const constant = computeRankingMetrics(['Malicious', 'Benign'], [40, 40]);
  assert.equal(constant.rocAuc.value, null);
  assert.equal(constant.rocAuc.undefinedReason, 'SINGLE_OPERATING_POINT_OR_CONSTANT_SCORES');
  assert.equal(constant.prAuc.value, null);

  // Single class -> explicitly null
  const oneClass = computeRankingMetrics(['Benign', 'Benign'], [10, 40]);
  assert.equal(oneClass.rocAuc.value, null);
  assert.equal(oneClass.rocAuc.undefinedReason, 'ZERO_ACTUAL_POSITIVES');

  // Non-numeric null scores (inconclusive/failed) excluded explicitly
  const withNull = computeRankingMetrics(['Malicious', 'Malicious', 'Benign'], [90, null, 10]);
  assert.equal(withNull.excludedNonNumericCount, 1);
  assert.equal(withNull.rocAuc.value, 1);
});

test('Ground Truth filtering rejects Unknown/Unverified, unresolved disagreements, and separates finding-level tests from extension-level metrics', () => {
  const csv = [
    'Sample_ID,Final_Decision,Label_Level,Verification_Status,Reviewer_1_Decision,Reviewer_2_Decision,Disagreement,Campaign_ID',
    'RWM-001,Malicious,Extension-Level (Real-World),Verified,Malicious,Malicious,No,camp-a',
    'RWB-001,Benign,Extension-Level (Real-World),Verified,Benign,Benign,No,benign-1',
    'RWM-002,Unverified,Extension-Level (Real-World),Unverified,Pending,Pending,Pending,camp-b',
    'RWB-002,Unknown,Extension-Level (Real-World),Verified,Benign,Unknown,Yes,benign-2',
    'RWM-003,Malicious,Extension-Level (Real-World),Verified,Malicious,Benign,Yes,camp-c',
    'CST-001,Benign,Finding-Level (Controlled Security Test),Verified,Benign,Benign,No,ctrl'
  ].join('\n');

  const bundle = loadGroundTruth(csv);
  assert.match(bundle.groundTruthSha256, /^[a-f0-9]{64}$/);
  assert.equal(bundle.totalRecords, 6);

  const filtered = filterEligibleGroundTruth(bundle);
  assert.deepEqual(filtered.eligibleExtensionLevel.map((r) => r.sampleId), ['RWM-001', 'RWB-001']);
  assert.deepEqual(filtered.findingLevelSeparated.map((r) => r.sampleId), ['CST-001']);
  assert.equal(filtered.excluded.length, 4);
  assert.ok(filtered.excluded.some((e) => e.sampleId === 'RWM-002' && e.reason === 'UNVERIFIED_OR_UNKNOWN_LABEL'));
  assert.ok(filtered.excluded.some((e) => e.sampleId === 'RWM-003' && e.reason === 'UNRESOLVED_REVIEWER_DISAGREEMENT'));
  assert.ok(filtered.excluded.some((e) => e.sampleId === 'CST-001' && e.reason === 'FINDING_LEVEL_SEPARATED_FROM_EXTENSION_METRICS'));

  // Invalid label value throws
  assert.throws(
    () => loadGroundTruth([{ sampleId: 'X1', finalDecision: 'Suspicious' }]),
    (err) => err instanceof MvxError && err.code === 'INVALID_GROUND_TRUTH'
  );
});

test('Statistical comparisons implement exact McNemar, Holm-Bonferroni, and group-aware cluster bootstrap', () => {
  // 10 discordant pairs (b=9, c=1): exact two-sided binomial p = 2 * (1 + 10) / 1024 = 22/1024 = 0.021484
  const yTrue = Array(12).fill('Malicious');
  const predA = [true, true, true, true, true, true, true, true, true, true, false, true]; // 11/12 right
  const predB = [true, false, false, false, false, false, false, false, false, false, true, true]; // 3/12 right
  const mc = exactMcNemarTest(yTrue, predA, predB);
  assert.equal(mc.aCorrectBWrong, 9);
  assert.equal(mc.aWrongBCorrect, 1);
  assert.equal(mc.discordantPairs, 10);
  assert.equal(mc.pValue, 0.021484);
  assert.equal(mc.underpowered, false);

  // Holm-Bonferroni on [0.01, 0.04, 0.03] -> sorted [0.01 (x3=0.03), 0.03 (x2=0.06), 0.04 (x1=0.04 -> max=0.06)]
  const corrected = holmBonferroniCorrection([
    { name: 'c1', pValue: 0.01 },
    { name: 'c2', pValue: 0.04 },
    { name: 'c3', pValue: 0.03 }
  ], 0.05);
  assert.equal(corrected[0].adjustedPValue, 0.03);
  assert.equal(corrected[0].significantAtAlpha, true);
  assert.equal(corrected[1].adjustedPValue, 0.06);
  assert.equal(corrected[1].significantAtAlpha, false);
  assert.equal(corrected[2].adjustedPValue, 0.06);

  // Group-aware bootstrap resamples whole campaigns deterministically
  const items = [];
  for (let i = 0; i < 6; i += 1) {
    items.push({ groupId: `mal-camp-${i}`, truth: 'Malicious', pred: i < 5 });
    items.push({ groupId: `ben-camp-${i}`, truth: 'Benign', pred: i === 0 });
  }
  const bootA = groupAwareBootstrapCi(
    items,
    (sub) => computeBinaryMetrics(sub.map((x) => x.truth), sub.map((x) => x.pred)).f1.value,
    { resamples: 200, seed: 12345 }
  );
  const bootB = groupAwareBootstrapCi(
    items,
    (sub) => computeBinaryMetrics(sub.map((x) => x.truth), sub.map((x) => x.pred)).f1.value,
    { resamples: 200, seed: 12345 }
  );
  assert.deepEqual(bootA, bootB);
  assert.equal(bootA.clusterCount, 12);
  assert.ok(bootA.ciLow <= bootA.pointEstimate && bootA.pointEstimate <= bootA.ciHigh);
});

test('End-to-end synthetic Ground Truth evaluation preserves provenance, excludes repeats/unverified, never mutates input records, and exports evaluation tables', async (t) => {
  const pkg = '5'.repeat(64);
  const groundTruth = [
    { sampleId: 'M1', finalDecision: 'Malicious', labelLevel: 'Extension-Level', verificationStatus: 'Verified', disagreement: 'No', campaignId: 'c1', packageSha256: pkg },
    { sampleId: 'M2', finalDecision: 'Malicious', labelLevel: 'Extension-Level', verificationStatus: 'Verified', disagreement: 'No', campaignId: 'c2', packageSha256: pkg },
    { sampleId: 'B1', finalDecision: 'Benign', labelLevel: 'Extension-Level', verificationStatus: 'Verified', disagreement: 'No', campaignId: 'b1', packageSha256: pkg },
    { sampleId: 'B2', finalDecision: 'Benign', labelLevel: 'Extension-Level', verificationStatus: 'Verified', disagreement: 'No', campaignId: 'b2', packageSha256: pkg },
    { sampleId: 'U1', finalDecision: 'Unverified', labelLevel: 'Extension-Level', verificationStatus: 'Unverified', disagreement: 'Pending', campaignId: 'u1' }
  ];

  const makeRec = (sampleId, method, wp, riskScore, repeatIndex = null) => ({
    sampleId,
    extensionId: `ext-${sampleId}`,
    packageSha256: pkg,
    method,
    weightProfile: wp,
    repeatIndex,
    status: riskScore === null ? 'inconclusive' : 'completed',
    riskScore,
    durationMs: method === 'M3' ? 8000 : 15
  });

  const records = [
    // M1 scores
    makeRec('M1', 'M1', 'W1', 60), makeRec('M2', 'M1', 'W1', 10), makeRec('B1', 'M1', 'W1', 50), makeRec('B2', 'M1', 'W1', 0), makeRec('U1', 'M1', 'W1', 90),
    // M3 primary + repeated run r2 (r2 must NOT enter dataset count!)
    makeRec('M1', 'M3', null, 100, 1), makeRec('M1', 'M3', null, 100, 2),
    makeRec('M2', 'M3', null, 50, 1), makeRec('B1', 'M3', null, 0, 1), makeRec('B2', 'M3', null, null, 1),
    // M4 scores
    makeRec('M1', 'M4', 'W1', 90), makeRec('M2', 'M4', 'W1', 65), makeRec('B1', 'M4', 'W1', 20), makeRec('B2', 'M4', 'W1', 5)
  ];
  const snapshotBefore = JSON.stringify(records);

  const report = evaluateExperimentAgainstGroundTruth({
    records,
    experimentManifest: { experimentId: 'exp-syn', experimentConfigSha256: '7'.repeat(64) },
    groundTruth,
    evaluationConfig: {
      thresholds: { M1: 40, M2: 40, M3: 50, M4: 40 },
      alpha: 0.05,
      bootstrapResamples: 50,
      bootstrapSeed: 77
    }
  });

  // Zero mutation of original experiment records
  assert.equal(JSON.stringify(records), snapshotBefore);
  assert.match(report.provenance.groundTruthSha256, /^[a-f0-9]{64}$/);
  assert.match(report.provenance.experimentManifestSha256, /^[a-f0-9]{64}$/);
  assert.match(report.provenance.evaluationConfigSha256, /^[a-f0-9]{64}$/);

  assert.equal(report.cohortSummary.eligibleExtensionLevelCount, 4);
  assert.equal(report.cohortSummary.excludedCount, 1);

  const m3Eval = report.methodEvaluations.find((e) => e.method === 'M3');
  assert.equal(m3Eval.binaryMetrics.confusionMatrix.total, 3); // B2 inconclusive excluded from numeric evaluation, M1 r2 excluded
  assert.equal(m3Eval.excludedNonNumericCount, 1);

  const m4Eval = report.methodEvaluations.find((e) => e.method === 'M4' && e.weightProfile === 'W1');
  assert.equal(m4Eval.binaryMetrics.accuracy.value, 1);
  assert.equal(m4Eval.rankingMetrics.rocAuc.value, 1);
  assert.ok(report.statisticalComparisons.some((c) => c.comparison === 'M4_vs_M1'));

  const outDir = await mkdtemp(path.join(os.tmpdir(), 'mvx-phase5-eval-'));
  t.after(() => rm(outDir, { recursive: true, force: true }));
  const exported = await exportEvaluationTables(report, outDir);
  assert.ok(exported.files['evaluation_metrics.csv']);
  assert.ok(exported.files['statistical_comparisons.csv']);
  const savedReport = JSON.parse(await readFile(path.join(outDir, 'evaluation_report.json'), 'utf8'));
  assert.equal(savedReport.provenance.groundTruthSha256, report.provenance.groundTruthSha256);
});
