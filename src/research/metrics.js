import { createHash } from 'node:crypto';
import { parseCsv } from '../csv.js';
import { MvxError } from '../errors.js';
import { assertOptionsObject } from '../options.js';
import { VERSION } from '../version.js';

export const EVALUATION_SCHEMA_VERSION = 1;
export const EVALUATION_PROFILE = 'mvx-ground-truth-eval-v1';
export const POSITIVE_CLASS = 'Malicious';
export const NEGATIVE_CLASS = 'Benign';
export const ALLOWED_GROUND_TRUTH_LABELS = Object.freeze([
  'Benign',
  'Malicious',
  'Unknown',
  'Unverified'
]);
export const SCORE_NOT_PROBABILITY_NOTICE =
  'Heuristic risk scores (0-100) represent bounded indicator rankings, NOT calibrated malware probabilities.';

const ALLOWED_LABEL_SET = new Set(ALLOWED_GROUND_TRUTH_LABELS);
const SHA256 = /^[a-f0-9]{64}$/;

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function roundMetric(value) {
  return Math.round(value * 1_000_000) / 1_000_000;
}

function canonicalStringify(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalStringify).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalStringify(value[key])}`).join(',')}}`;
}

function mulberry32(seed) {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = Math.imul(state ^ (state >>> 15), 1 | state);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4_294_967_296;
  };
}

function safeMetric(numerator, denominator, undefinedReason) {
  if (denominator === 0 || !Number.isFinite(denominator) || !Number.isFinite(numerator)) {
    return Object.freeze({ value: null, numerator, denominator, undefinedReason });
  }
  return Object.freeze({
    value: roundMetric(numerator / denominator),
    numerator,
    denominator,
    undefinedReason: null
  });
}

function logFactorial(n) {
  let sum = 0;
  for (let i = 2; i <= n; i += 1) sum += Math.log(i);
  return sum;
}

function binomialPmf(k, n, p) {
  if (p === 0) return k === 0 ? 1 : 0;
  if (p === 1) return k === n ? 1 : 0;
  const logCoeff = logFactorial(n) - logFactorial(k) - logFactorial(n - k);
  return Math.exp(logCoeff + k * Math.log(p) + (n - k) * Math.log(1 - p));
}

function binomialCdfLower(k, n, p) {
  let sum = 0;
  for (let i = 0; i <= k; i += 1) sum += binomialPmf(i, n, p);
  return Math.min(1, Math.max(0, sum));
}

function binomialCdfUpper(k, n, p) {
  let sum = 0;
  for (let i = k; i <= n; i += 1) sum += binomialPmf(i, n, p);
  return Math.min(1, Math.max(0, sum));
}

export function clopperPearsonCi(successes, trials, alpha = 0.05) {
  if (!Number.isSafeInteger(trials) || trials <= 0 || !Number.isSafeInteger(successes) || successes < 0 || successes > trials) {
    return Object.freeze({ low: null, high: null, alpha, trials, successes, undefinedReason: 'ZERO_OR_INVALID_TRIALS' });
  }
  const halfAlpha = alpha / 2;
  let low = 0;
  if (successes > 0) {
    let lo = 0;
    let hi = 1;
    for (let iter = 0; iter < 60; iter += 1) {
      const mid = (lo + hi) / 2;
      if (binomialCdfUpper(successes, trials, mid) < halfAlpha) lo = mid;
      else hi = mid;
    }
    low = (lo + hi) / 2;
  }
  let high = 1;
  if (successes < trials) {
    let lo = 0;
    let hi = 1;
    for (let iter = 0; iter < 60; iter += 1) {
      const mid = (lo + hi) / 2;
      if (binomialCdfLower(successes, trials, mid) < halfAlpha) hi = mid;
      else lo = mid;
    }
    high = (lo + hi) / 2;
  }
  return Object.freeze({
    low: roundMetric(low),
    high: roundMetric(high),
    alpha,
    trials,
    successes,
    undefinedReason: null
  });
}

function normalizeGroundTruthRow(raw, index) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new MvxError(`Ground Truth row ${index} must be an object`, { code: 'INVALID_GROUND_TRUTH' });
  }
  const sampleId = raw.sampleId ?? raw.Sample_ID;
  if (typeof sampleId !== 'string' || sampleId.trim().length === 0) {
    throw new MvxError(`Ground Truth row ${index} is missing sampleId / Sample_ID`, { code: 'INVALID_GROUND_TRUTH' });
  }
  const finalDecision = raw.finalDecision ?? raw.Final_Decision ?? raw.groundTruthLabel ?? raw.Ground_Truth_Label;
  if (typeof finalDecision !== 'string' || !ALLOWED_LABEL_SET.has(finalDecision)) {
    throw new MvxError(`Invalid Ground Truth label '${String(finalDecision)}' for ${sampleId}`, {
      code: 'INVALID_GROUND_TRUTH'
    });
  }
  const labelLevel = raw.labelLevel ?? raw.Label_Level ?? 'Extension-Level';
  const verificationStatus = raw.verificationStatus ?? raw.Verification_Status ?? 'Unverified';
  const reviewer1Decision = raw.reviewer1Decision ?? raw.Reviewer_1_Decision ?? null;
  const reviewer2Decision = raw.reviewer2Decision ?? raw.Reviewer_2_Decision ?? null;
  const disagreement = raw.disagreement ?? raw.Disagreement
    ?? (reviewer1Decision && reviewer2Decision && reviewer1Decision !== 'Pending' && reviewer2Decision !== 'Pending'
      ? (reviewer1Decision === reviewer2Decision ? 'No' : 'Yes')
      : 'Pending');
  const expectedPackageSha256 = raw.packageSha256 ?? raw.SHA256 ?? null;
  if (expectedPackageSha256 !== null && expectedPackageSha256 !== '' && expectedPackageSha256 !== 'Not Collected'
    && !SHA256.test(expectedPackageSha256)) {
    throw new MvxError(`Invalid packageSha256 in Ground Truth for ${sampleId}`, {
      code: 'INVALID_GROUND_TRUTH'
    });
  }

  return Object.freeze({
    sampleId: sampleId.trim(),
    extensionName: raw.extensionName ?? raw.Extension_Name ?? null,
    extensionVersion: raw.extensionVersion ?? raw.Extension_Version ?? null,
    groundTruthLabel: raw.groundTruthLabel ?? raw.Ground_Truth_Label ?? finalDecision,
    finalDecision,
    labelLevel: String(labelLevel),
    verificationStatus: String(verificationStatus),
    reviewer1: raw.reviewer1 ?? raw.Reviewer_1 ?? null,
    reviewer1Decision,
    reviewer2: raw.reviewer2 ?? raw.Reviewer_2 ?? null,
    reviewer2Decision,
    disagreement: String(disagreement),
    campaignId: raw.campaignId ?? raw.Campaign_ID ?? raw.campaign ?? null,
    cohort: raw.cohort ?? raw.Cohort ?? null,
    packageSha256: expectedPackageSha256 && SHA256.test(expectedPackageSha256) ? expectedPackageSha256 : null
  });
}

export function loadGroundTruth(input) {
  let rawRows;
  let canonicalBytes;
  if (typeof input === 'string') {
    rawRows = parseCsv(input);
    canonicalBytes = input;
  } else if (Array.isArray(input)) {
    rawRows = input;
    canonicalBytes = canonicalStringify(input);
  } else {
    throw new MvxError('Ground Truth input must be CSV text or an array of records', {
      code: 'INVALID_GROUND_TRUTH'
    });
  }

  const seen = new Set();
  const records = [];
  for (let index = 0; index < rawRows.length; index += 1) {
    const normalized = normalizeGroundTruthRow(rawRows[index], index);
    if (seen.has(normalized.sampleId)) {
      throw new MvxError(`Duplicate sampleId in Ground Truth: ${normalized.sampleId}`, {
        code: 'DUPLICATE_GROUND_TRUTH'
      });
    }
    seen.add(normalized.sampleId);
    records.push(normalized);
  }

  return Object.freeze({
    schemaVersion: EVALUATION_SCHEMA_VERSION,
    groundTruthSha256: sha256(canonicalBytes),
    totalRecords: records.length,
    records: Object.freeze(records)
  });
}

export function filterEligibleGroundTruth(groundTruthBundle, options = {}) {
  assertOptionsObject(options, 'Ground Truth filter');
  const records = Array.isArray(groundTruthBundle) ? groundTruthBundle : groundTruthBundle?.records;
  if (!Array.isArray(records)) {
    throw new MvxError('Ground Truth bundle with records array is required', { code: 'INVALID_ARGUMENT' });
  }
  const allowedCohorts = Array.isArray(options.allowedCohorts) ? new Set(options.allowedCohorts) : null;

  const eligibleExtensionLevel = [];
  const findingLevelSeparated = [];
  const excluded = [];

  for (const record of records) {
    if (record.finalDecision === 'Unknown' || record.finalDecision === 'Unverified') {
      excluded.push({ sampleId: record.sampleId, reason: 'UNVERIFIED_OR_UNKNOWN_LABEL', finalDecision: record.finalDecision });
      continue;
    }
    if (record.verificationStatus !== 'Verified') {
      excluded.push({ sampleId: record.sampleId, reason: 'VERIFICATION_NOT_FINALIZED', verificationStatus: record.verificationStatus });
      continue;
    }
    if (record.disagreement === 'Yes') {
      excluded.push({ sampleId: record.sampleId, reason: 'UNRESOLVED_REVIEWER_DISAGREEMENT' });
      continue;
    }
    if (/finding-level|controlled security test/i.test(record.labelLevel)) {
      findingLevelSeparated.push(record);
      excluded.push({ sampleId: record.sampleId, reason: 'FINDING_LEVEL_SEPARATED_FROM_EXTENSION_METRICS', labelLevel: record.labelLevel });
      continue;
    }
    if (!/extension-level/i.test(record.labelLevel)) {
      excluded.push({ sampleId: record.sampleId, reason: 'NON_EXTENSION_LABEL_LEVEL', labelLevel: record.labelLevel });
      continue;
    }
    if (allowedCohorts !== null && !allowedCohorts.has(record.cohort)) {
      excluded.push({ sampleId: record.sampleId, reason: 'COHORT_EXCLUDED', cohort: record.cohort });
      continue;
    }
    eligibleExtensionLevel.push(record);
  }

  return Object.freeze({
    eligibleExtensionLevel: Object.freeze(eligibleExtensionLevel),
    findingLevelSeparated: Object.freeze(findingLevelSeparated),
    excluded: Object.freeze(excluded)
  });
}

export function computeBinaryMetrics(yTrue, yPred, options = {}) {
  if (!Array.isArray(yTrue) || !Array.isArray(yPred) || yTrue.length !== yPred.length) {
    throw new MvxError('yTrue and yPred must be arrays of equal length', { code: 'INVALID_ARGUMENT' });
  }
  assertOptionsObject(options, 'Binary metrics');
  const alpha = options.alpha ?? 0.05;

  let tp = 0;
  let fp = 0;
  let tn = 0;
  let fn = 0;
  for (let index = 0; index < yTrue.length; index += 1) {
    const truth = yTrue[index];
    const pred = yPred[index];
    if (truth !== POSITIVE_CLASS && truth !== NEGATIVE_CLASS) {
      throw new MvxError(`Invalid binary ground truth class at index ${index}: ${String(truth)}`, {
        code: 'INVALID_GROUND_TRUTH'
      });
    }
    const isPos = truth === POSITIVE_CLASS;
    const predPos = pred === true || pred === 1 || pred === POSITIVE_CLASS;
    if (isPos && predPos) tp += 1;
    else if (!isPos && predPos) fp += 1;
    else if (!isPos && !predPos) tn += 1;
    else fn += 1;
  }

  const total = tp + fp + tn + fn;
  const positives = tp + fn;
  const negatives = tn + fp;
  const predictedPositives = tp + fp;
  const predictedNegatives = tn + fn;

  const precision = safeMetric(tp, predictedPositives, 'ZERO_PREDICTED_POSITIVES');
  const recall = safeMetric(tp, positives, 'ZERO_ACTUAL_POSITIVES');
  const specificity = safeMetric(tn, negatives, 'ZERO_ACTUAL_NEGATIVES');
  const f1 = safeMetric(2 * tp, 2 * tp + fp + fn, 'ZERO_PRECISION_AND_RECALL_DENOMINATOR');
  const fpr = safeMetric(fp, negatives, 'ZERO_ACTUAL_NEGATIVES');
  const fnr = safeMetric(fn, positives, 'ZERO_ACTUAL_POSITIVES');
  const accuracy = safeMetric(tp + tn, total, 'EMPTY_DATASET');

  const balancedAccuracy = (recall.value !== null && specificity.value !== null)
    ? Object.freeze({
      value: roundMetric(0.5 * (recall.value + specificity.value)),
      undefinedReason: null
    })
    : Object.freeze({
      value: null,
      undefinedReason: recall.value === null ? 'ZERO_ACTUAL_POSITIVES' : 'ZERO_ACTUAL_NEGATIVES'
    });

  const mccDenomSq = predictedPositives * positives * negatives * predictedNegatives;
  const mcc = mccDenomSq > 0
    ? Object.freeze({
      value: roundMetric(((tp * tn) - (fp * fn)) / Math.sqrt(mccDenomSq)),
      undefinedReason: null
    })
    : Object.freeze({
      value: null,
      undefinedReason: 'ZERO_MCC_DENOMINATOR'
    });

  // Negative-class (Benign) precision/recall/F1 for explicit macro & weighted averaging
  const negPrecision = safeMetric(tn, predictedNegatives, 'ZERO_PREDICTED_NEGATIVES');
  const negRecall = specificity;
  const negF1 = safeMetric(2 * tn, 2 * tn + fp + fn, 'ZERO_NEGATIVE_F1_DENOMINATOR');

  const macroPrecision = (precision.value !== null && negPrecision.value !== null)
    ? roundMetric(0.5 * (precision.value + negPrecision.value)) : null;
  const macroRecall = balancedAccuracy.value;
  const macroF1 = (f1.value !== null && negF1.value !== null)
    ? roundMetric(0.5 * (f1.value + negF1.value)) : null;

  const weightedPrecision = (total > 0 && precision.value !== null && negPrecision.value !== null)
    ? roundMetric((positives * precision.value + negatives * negPrecision.value) / total) : null;
  const weightedRecall = accuracy.value;
  const weightedF1 = (total > 0 && f1.value !== null && negF1.value !== null)
    ? roundMetric((positives * f1.value + negatives * negF1.value) / total) : null;

  return {
    positiveClass: POSITIVE_CLASS,
    negativeClass: NEGATIVE_CLASS,
    confusionMatrix: {
      tp,
      fp,
      tn,
      fn,
      total,
      positives,
      negatives,
      predictedPositives,
      predictedNegatives
    },
    precision,
    recall,
    sensitivity: recall,
    specificity,
    f1,
    fpr,
    fnr,
    accuracy,
    balancedAccuracy,
    mcc,
    aggregations: {
      micro: { precision: accuracy.value, recall: accuracy.value, f1: accuracy.value },
      macro: { precision: macroPrecision, recall: macroRecall, f1: macroF1 },
      weighted: { precision: weightedPrecision, recall: weightedRecall, f1: weightedF1 }
    },
    confidenceIntervals: {
      method: 'clopper-pearson-exact',
      alpha,
      precision: clopperPearsonCi(tp, predictedPositives, alpha),
      recall: clopperPearsonCi(tp, positives, alpha),
      specificity: clopperPearsonCi(tn, negatives, alpha),
      fpr: clopperPearsonCi(fp, negatives, alpha),
      fnr: clopperPearsonCi(fn, positives, alpha),
      accuracy: clopperPearsonCi(tp + tn, total, alpha)
    }
  };
}

export function computeRankingMetrics(yTrue, scores) {
  if (!Array.isArray(yTrue) || !Array.isArray(scores) || yTrue.length !== scores.length) {
    throw new MvxError('yTrue and scores must be arrays of equal length', { code: 'INVALID_ARGUMENT' });
  }
  const pairs = [];
  let excludedNonNumeric = 0;
  for (let index = 0; index < yTrue.length; index += 1) {
    const truth = yTrue[index];
    if (truth !== POSITIVE_CLASS && truth !== NEGATIVE_CLASS) {
      throw new MvxError(`Invalid binary ground truth class at index ${index}: ${String(truth)}`, {
        code: 'INVALID_GROUND_TRUTH'
      });
    }
    const score = scores[index];
    if (typeof score !== 'number' || !Number.isFinite(score)) {
      excludedNonNumeric += 1;
      continue;
    }
    pairs.push({ positive: truth === POSITIVE_CLASS ? 1 : 0, score });
  }

  const totalPos = pairs.reduce((sum, item) => sum + item.positive, 0);
  const totalNeg = pairs.length - totalPos;
  const distinctScores = new Set(pairs.map((item) => item.score));

  if (totalPos === 0 || totalNeg === 0) {
    const reason = totalPos === 0 ? 'ZERO_ACTUAL_POSITIVES' : 'ZERO_ACTUAL_NEGATIVES';
    return {
      evaluatedCount: pairs.length,
      excludedNonNumericCount: excludedNonNumeric,
      positives: totalPos,
      negatives: totalNeg,
      distinctScoreCount: distinctScores.size,
      baselinePrevalence: pairs.length > 0 ? roundMetric(totalPos / pairs.length) : null,
      rocAuc: Object.freeze({ value: null, undefinedReason: reason }),
      prAuc: Object.freeze({ value: null, undefinedReason: reason }),
      notice: SCORE_NOT_PROBABILITY_NOTICE
    };
  }

  if (distinctScores.size < 2) {
    return {
      evaluatedCount: pairs.length,
      excludedNonNumericCount: excludedNonNumeric,
      positives: totalPos,
      negatives: totalNeg,
      distinctScoreCount: distinctScores.size,
      baselinePrevalence: roundMetric(totalPos / pairs.length),
      rocAuc: Object.freeze({ value: null, undefinedReason: 'SINGLE_OPERATING_POINT_OR_CONSTANT_SCORES' }),
      prAuc: Object.freeze({ value: null, undefinedReason: 'SINGLE_OPERATING_POINT_OR_CONSTANT_SCORES' }),
      notice: SCORE_NOT_PROBABILITY_NOTICE
    };
  }

  // Exact tie-aware ROC-AUC via Mann-Whitney U
  const posScores = pairs.filter((item) => item.positive === 1).map((item) => item.score);
  const negScores = pairs.filter((item) => item.positive === 0).map((item) => item.score);
  let concordance = 0;
  for (const ps of posScores) {
    for (const ns of negScores) {
      if (ps > ns) concordance += 1;
      else if (ps === ns) concordance += 0.5;
    }
  }
  const rocAuc = roundMetric(concordance / (totalPos * totalNeg));

  // Exact tie-aware stepwise PR-AUC (Average Precision across descending distinct thresholds)
  const sortedThresholds = [...distinctScores].sort((a, b) => b - a);
  const grouped = new Map(sortedThresholds.map((threshold) => [threshold, { pos: 0, neg: 0 }]));
  for (const item of pairs) {
    const bucket = grouped.get(item.score);
    if (item.positive === 1) bucket.pos += 1;
    else bucket.neg += 1;
  }

  let cumTp = 0;
  let cumFp = 0;
  let prevRecall = 0;
  let ap = 0;
  for (const threshold of sortedThresholds) {
    const bucket = grouped.get(threshold);
    cumTp += bucket.pos;
    cumFp += bucket.neg;
    const recall = cumTp / totalPos;
    const precision = cumTp / (cumTp + cumFp);
    ap += (recall - prevRecall) * precision;
    prevRecall = recall;
  }
  const prAuc = roundMetric(ap);

  return {
    evaluatedCount: pairs.length,
    excludedNonNumericCount: excludedNonNumeric,
    positives: totalPos,
    negatives: totalNeg,
    distinctScoreCount: distinctScores.size,
    baselinePrevalence: roundMetric(totalPos / pairs.length),
    rocAuc: Object.freeze({ value: rocAuc, undefinedReason: null }),
    prAuc: Object.freeze({ value: prAuc, undefinedReason: null }),
    notice: SCORE_NOT_PROBABILITY_NOTICE
  };
}

export function exactMcNemarTest(yTrue, predA, predB) {
  if (!Array.isArray(yTrue) || !Array.isArray(predA) || !Array.isArray(predB)
    || yTrue.length !== predA.length || yTrue.length !== predB.length) {
    throw new MvxError('yTrue, predA, and predB must be arrays of equal length', { code: 'INVALID_ARGUMENT' });
  }
  let bothCorrect = 0;
  let bothWrong = 0;
  let aCorrectBWrong = 0;
  let aWrongBCorrect = 0;

  for (let index = 0; index < yTrue.length; index += 1) {
    const truthPos = yTrue[index] === POSITIVE_CLASS;
    const aPos = predA[index] === true || predA[index] === 1 || predA[index] === POSITIVE_CLASS;
    const bPos = predB[index] === true || predB[index] === 1 || predB[index] === POSITIVE_CLASS;
    const aOk = aPos === truthPos;
    const bOk = bPos === truthPos;
    if (aOk && bOk) bothCorrect += 1;
    else if (!aOk && !bOk) bothWrong += 1;
    else if (aOk && !bOk) aCorrectBWrong += 1;
    else aWrongBCorrect += 1;
  }

  const discordantPairs = aCorrectBWrong + aWrongBCorrect;
  if (discordantPairs === 0) {
    return Object.freeze({
      pairedSamples: yTrue.length,
      bothCorrect,
      bothWrong,
      aCorrectBWrong,
      aWrongBCorrect,
      discordantPairs: 0,
      pValue: 1,
      underpowered: true,
      note: 'No discordant pairs observed; classifiers produced identical decisions.'
    });
  }

  const k = Math.min(aCorrectBWrong, aWrongBCorrect);
  const oneTail = binomialCdfLower(k, discordantPairs, 0.5);
  const pValue = roundMetric(Math.min(1, 2 * oneTail));
  const underpowered = discordantPairs < 10;

  return Object.freeze({
    pairedSamples: yTrue.length,
    bothCorrect,
    bothWrong,
    aCorrectBWrong,
    aWrongBCorrect,
    discordantPairs,
    pValue,
    underpowered,
    note: underpowered
      ? `Underpowered exact McNemar test (${discordantPairs} discordant pairs < 10); interpret p-value cautiously.`
      : 'Exact two-sided binomial McNemar test.'
  });
}

export function holmBonferroniCorrection(comparisons, alpha = 0.05) {
  if (!Array.isArray(comparisons)) {
    throw new MvxError('comparisons must be an array', { code: 'INVALID_ARGUMENT' });
  }
  const indexed = comparisons.map((item, originalIndex) => ({ item, originalIndex }));
  const valid = indexed
    .filter(({ item }) => typeof item.pValue === 'number' && Number.isFinite(item.pValue))
    .sort((left, right) => left.item.pValue - right.item.pValue || left.originalIndex - right.originalIndex);

  const m = valid.length;
  const adjustedByIndex = new Map();
  let runningMax = 0;
  for (let rank = 0; rank < m; rank += 1) {
    const rawP = valid[rank].item.pValue;
    const stepAdj = Math.min(1, (m - rank) * rawP);
    runningMax = Math.max(runningMax, stepAdj);
    adjustedByIndex.set(valid[rank].originalIndex, roundMetric(runningMax));
  }

  return comparisons.map((item, originalIndex) => {
    const adjustedPValue = adjustedByIndex.has(originalIndex) ? adjustedByIndex.get(originalIndex) : null;
    return {
      ...item,
      adjustedPValue,
      alpha,
      significantAtAlpha: adjustedPValue !== null ? adjustedPValue < alpha : null
    };
  });
}

export function groupAwareBootstrapCi(items, metricFn, options = {}) {
  if (!Array.isArray(items)) {
    throw new MvxError('items must be an array', { code: 'INVALID_ARGUMENT' });
  }
  if (typeof metricFn !== 'function') {
    throw new MvxError('metricFn must be a function', { code: 'INVALID_ARGUMENT' });
  }
  assertOptionsObject(options, 'Group-aware bootstrap');
  const resamples = options.resamples ?? 2_000;
  const seed = options.seed ?? 20260101;
  const alpha = options.alpha ?? 0.05;
  const groupKey = options.groupKey ?? 'groupId';

  if (!Number.isSafeInteger(resamples) || resamples < 10) {
    throw new MvxError('resamples must be an integer >= 10', { code: 'INVALID_ARGUMENT' });
  }

  const pointEstimate = metricFn(items);
  const clustersMap = new Map();
  for (let index = 0; index < items.length; index += 1) {
    const item = items[index];
    const key = String(item?.[groupKey] ?? item?.campaignId ?? item?.extensionId ?? item?.sampleId ?? index);
    if (!clustersMap.has(key)) clustersMap.set(key, []);
    clustersMap.get(key).push(item);
  }
  const clusterKeys = [...clustersMap.keys()].sort();
  const clusterCount = clusterKeys.length;
  if (clusterCount < 2 || pointEstimate === null || !Number.isFinite(pointEstimate)) {
    return Object.freeze({
      pointEstimate: pointEstimate !== null && Number.isFinite(pointEstimate) ? roundMetric(pointEstimate) : null,
      ciLow: null,
      ciHigh: null,
      alpha,
      resamples,
      validResamples: 0,
      skippedDegenerateResamples: resamples,
      clusterCount,
      underpowered: true,
      undefinedReason: clusterCount < 2 ? 'INSUFFICIENT_CLUSTERS' : 'UNDEFINED_POINT_ESTIMATE'
    });
  }

  const rng = mulberry32(seed);
  const distribution = [];
  let skipped = 0;
  for (let r = 0; r < resamples; r += 1) {
    const sample = [];
    for (let c = 0; c < clusterCount; c += 1) {
      const pickedKey = clusterKeys[Math.floor(rng() * clusterCount)];
      sample.push(...clustersMap.get(pickedKey));
    }
    const val = metricFn(sample);
    if (typeof val === 'number' && Number.isFinite(val)) distribution.push(val);
    else skipped += 1;
  }

  if (distribution.length === 0) {
    return Object.freeze({
      pointEstimate: roundMetric(pointEstimate),
      ciLow: null,
      ciHigh: null,
      alpha,
      resamples,
      validResamples: 0,
      skippedDegenerateResamples: skipped,
      clusterCount,
      underpowered: true,
      undefinedReason: 'ALL_RESAMPLES_DEGENERATE'
    });
  }

  distribution.sort((a, b) => a - b);
  const lowIdx = Math.max(0, Math.floor((alpha / 2) * (distribution.length - 1)));
  const highIdx = Math.min(distribution.length - 1, Math.ceil((1 - alpha / 2) * (distribution.length - 1)));
  const underpowered = clusterCount < 10 || (distribution.length / resamples) < 0.5;

  return Object.freeze({
    pointEstimate: roundMetric(pointEstimate),
    ciLow: roundMetric(distribution[lowIdx]),
    ciHigh: roundMetric(distribution[highIdx]),
    alpha,
    resamples,
    validResamples: distribution.length,
    skippedDegenerateResamples: skipped,
    clusterCount,
    underpowered,
    undefinedReason: null
  });
}

function median(values) {
  if (values.length === 0) return null;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 1
    ? roundMetric(sorted[mid])
    : roundMetric((sorted[mid - 1] + sorted[mid]) / 2);
}

export function evaluateExperimentAgainstGroundTruth({
  records,
  experimentManifest = null,
  groundTruth,
  evaluationConfig
}) {
  if (!Array.isArray(records)) {
    throw new MvxError('records must be an array', { code: 'INVALID_ARGUMENT' });
  }
  assertOptionsObject(evaluationConfig, 'Evaluation config');
  if (!evaluationConfig.thresholds || typeof evaluationConfig.thresholds !== 'object') {
    throw new MvxError('evaluationConfig.thresholds is required (pre-registered thresholds; never tuned on test labels)', {
      code: 'INVALID_ARGUMENT'
    });
  }

  // Deep-clone records immediately so evaluation can never mutate original experiment artifacts
  const immutableRecords = structuredClone(records);
  const gtBundle = (groundTruth && Array.isArray(groundTruth.records) && typeof groundTruth.groundTruthSha256 === 'string')
    ? groundTruth
    : loadGroundTruth(groundTruth);
  const filteredGt = filterEligibleGroundTruth(gtBundle, {
    allowedCohorts: evaluationConfig.allowedCohorts
  });
  const eligibleBySampleId = new Map(
    filteredGt.eligibleExtensionLevel.map((entry) => [entry.sampleId, entry])
  );

  const evaluationConfigSha256 = sha256(canonicalStringify(evaluationConfig));
  const experimentManifestSha256 = experimentManifest
    ? sha256(canonicalStringify(experimentManifest))
    : null;
  const alpha = evaluationConfig.alpha ?? 0.05;
  const bootstrapResamples = evaluationConfig.bootstrapResamples ?? 0;
  const bootstrapSeed = evaluationConfig.bootstrapSeed ?? 20260101;

  // Group primary records by (method, weightProfile); ignore repeated M3 runs (repeatIndex > 1)
  const slices = new Map();
  const weightProfilesSeen = new Set();
  for (const record of immutableRecords) {
    if (record.method === 'M3' && (record.repeatIndex ?? 1) > 1) continue;
    if (record.weightProfile) weightProfilesSeen.add(record.weightProfile);
    const key = `${record.method}\0${record.weightProfile ?? ''}`;
    if (!slices.has(key)) slices.set(key, new Map());
    slices.get(key).set(record.sampleId, record);
  }

  const methodEvaluations = [];
  const binaryPredictionsByKey = new Map();

  for (const key of [...slices.keys()].sort()) {
    const [method, rawWp] = key.split('\0');
    const weightProfile = rawWp.length > 0 ? rawWp : null;
    const threshold = evaluationConfig.thresholds[method];
    if (typeof threshold !== 'number' || !Number.isFinite(threshold)) {
      throw new MvxError(`Missing finite pre-registered threshold for method ${method}`, {
        code: 'INVALID_ARGUMENT'
      });
    }

    const sliceRecords = slices.get(key);
    const yTrue = [];
    const yPred = [];
    const scores = [];
    const durations = [];
    const bootstrapItems = [];
    const samplePredMap = new Map();
    let excludedNonNumericCount = 0;
    let missingFromExperimentCount = 0;

    for (const gtEntry of filteredGt.eligibleExtensionLevel) {
      const rec = sliceRecords.get(gtEntry.sampleId);
      if (!rec) {
        missingFromExperimentCount += 1;
        continue;
      }
      if (gtEntry.packageSha256 && rec.packageSha256 && gtEntry.packageSha256 !== rec.packageSha256) {
        throw new MvxError(
          `Ground Truth packageSha256 mismatch for ${gtEntry.sampleId}: GT=${gtEntry.packageSha256}, Run=${rec.packageSha256}`,
          { code: 'PACKAGE_SHA_MISMATCH' }
        );
      }
      if (typeof rec.durationMs === 'number' && Number.isFinite(rec.durationMs)) {
        durations.push(rec.durationMs);
      }
      if (typeof rec.riskScore !== 'number' || !Number.isFinite(rec.riskScore)) {
        excludedNonNumericCount += 1;
        continue;
      }
      const predPos = rec.riskScore >= threshold;
      yTrue.push(gtEntry.finalDecision);
      yPred.push(predPos);
      scores.push(rec.riskScore);
      samplePredMap.set(gtEntry.sampleId, { truth: gtEntry.finalDecision, pred: predPos });
      bootstrapItems.push({
        sampleId: gtEntry.sampleId,
        extensionId: rec.extensionId,
        campaignId: gtEntry.campaignId,
        groupId: gtEntry.campaignId ?? rec.extensionId ?? gtEntry.sampleId,
        truth: gtEntry.finalDecision,
        pred: predPos,
        score: rec.riskScore
      });
    }

    binaryPredictionsByKey.set(key, samplePredMap);
    const binaryMetrics = computeBinaryMetrics(yTrue, yPred, { alpha });
    const rankingMetrics = computeRankingMetrics(yTrue, scores);

    let groupBootstrap = null;
    if (bootstrapResamples >= 10) {
      groupBootstrap = {
        f1: groupAwareBootstrapCi(
          bootstrapItems,
          (subset) => computeBinaryMetrics(subset.map((x) => x.truth), subset.map((x) => x.pred)).f1.value,
          { resamples: bootstrapResamples, seed: bootstrapSeed, alpha }
        ),
        rocAuc: groupAwareBootstrapCi(
          bootstrapItems,
          (subset) => computeRankingMetrics(subset.map((x) => x.truth), subset.map((x) => x.score)).rocAuc.value,
          { resamples: bootstrapResamples, seed: bootstrapSeed + 1, alpha }
        )
      };
    }

    methodEvaluations.push({
      method,
      weightProfile,
      threshold,
      eligibleCount: filteredGt.eligibleExtensionLevel.length,
      missingFromExperimentCount,
      excludedNonNumericCount,
      binaryMetrics,
      rankingMetrics,
      groupBootstrap,
      runtimeStats: {
        sampleCount: durations.length,
        meanDurationMs: durations.length > 0 ? roundMetric(durations.reduce((a, b) => a + b, 0) / durations.length) : null,
        medianDurationMs: median(durations)
      }
    });
  }

  // Paired exact McNemar comparisons (M4 vs M1, M4 vs M2, M4 vs M3) per weight profile with Holm-Bonferroni
  const statisticalComparisons = [];
  const weightList = [...weightProfilesSeen].sort();
  for (const wp of weightList) {
    const m4Map = binaryPredictionsByKey.get(`M4\0${wp}`);
    if (!m4Map) continue;
    const rawGroup = [];
    for (const baseline of ['M1', 'M2', 'M3']) {
      const baseKey = baseline === 'M3' ? 'M3\0' : `${baseline}\0${wp}`;
      const baseMap = binaryPredictionsByKey.get(baseKey);
      if (!baseMap) continue;
      const pairedTruth = [];
      const pairedM4 = [];
      const pairedBase = [];
      for (const [sampleId, m4Entry] of m4Map.entries()) {
        if (!baseMap.has(sampleId)) continue;
        pairedTruth.push(m4Entry.truth);
        pairedM4.push(m4Entry.pred);
        pairedBase.push(baseMap.get(sampleId).pred);
      }
      const mcnemar = exactMcNemarTest(pairedTruth, pairedM4, pairedBase);
      rawGroup.push({
        weightProfile: wp,
        comparison: `M4_vs_${baseline}`,
        methodA: 'M4',
        methodB: baseline,
        pValue: mcnemar.pValue,
        mcnemar
      });
    }
    statisticalComparisons.push(...holmBonferroniCorrection(rawGroup, alpha));
  }

  return {
    schemaVersion: EVALUATION_SCHEMA_VERSION,
    profile: EVALUATION_PROFILE,
    toolVersion: VERSION,
    evaluatedAtUtc: new Date().toISOString(),
    positiveClass: POSITIVE_CLASS,
    negativeClass: NEGATIVE_CLASS,
    provenance: {
      groundTruthSha256: gtBundle.groundTruthSha256,
      experimentManifestSha256,
      evaluationConfigSha256,
      experimentId: experimentManifest?.experimentId ?? null,
      experimentConfigSha256: experimentManifest?.experimentConfigSha256 ?? null
    },
    cohortSummary: {
      totalGroundTruthRecords: gtBundle.totalRecords,
      eligibleExtensionLevelCount: filteredGt.eligibleExtensionLevel.length,
      eligiblePositives: filteredGt.eligibleExtensionLevel.filter((x) => x.finalDecision === POSITIVE_CLASS).length,
      eligibleNegatives: filteredGt.eligibleExtensionLevel.filter((x) => x.finalDecision === NEGATIVE_CLASS).length,
      findingLevelSeparatedCount: filteredGt.findingLevelSeparated.length,
      excludedCount: filteredGt.excluded.length,
      excludedRecords: filteredGt.excluded
    },
    methodEvaluations,
    statisticalComparisons,
    notices: [
      SCORE_NOT_PROBABILITY_NOTICE,
      'Evaluation is read-only and strictly decoupled from M1-M4 execution; Ground Truth labels never alter analysis scores or configurations.',
      'Repeated M3 dynamic runs (repeatIndex > 1) are excluded from primary binary metrics and evaluated only in stability summaries.'
    ]
  };
}
