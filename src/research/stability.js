import { MvxError } from '../errors.js';
import { assertOptionsObject } from '../options.js';

export const STABILITY_SCHEMA_VERSION = 1;
export const STABILITY_PROFILE = 'mvx-dynamic-stability-v1';

const SHA256 = /^[a-f0-9]{64}$/;
const VALID_VERDICTS = new Set([
  'confirmed_attack',
  'suspicious_activity',
  'no_trigger_observed',
  'inconclusive'
]);

function roundMetric(value) {
  return Math.round(value * 1_000_000) / 1_000_000;
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

function deterministicShuffle(items, rng) {
  const copy = [...items];
  for (let index = copy.length - 1; index > 0; index -= 1) {
    const swapIndex = Math.floor(rng() * (index + 1));
    [copy[index], copy[swapIndex]] = [copy[swapIndex], copy[index]];
  }
  return copy;
}

export function selectRepeatedRunSubset(samples, options = {}) {
  if (!Array.isArray(samples)) {
    throw new MvxError('Samples must be an array', { code: 'INVALID_ARGUMENT' });
  }
  assertOptionsObject(options, 'Repeated-run subset');
  const ratio = options.ratio ?? 0.15;
  const minSamples = options.minSamples ?? 15;
  const seed = options.seed ?? 20260101;
  const groupBy = options.groupBy ?? 'cohort';

  if (typeof ratio !== 'number' || !Number.isFinite(ratio) || ratio <= 0 || ratio > 1) {
    throw new MvxError('ratio must be a finite number in (0, 1]', { code: 'INVALID_ARGUMENT' });
  }
  if (!Number.isSafeInteger(minSamples) || minSamples < 1) {
    throw new MvxError('minSamples must be a positive safe integer', { code: 'INVALID_ARGUMENT' });
  }
  if (!Number.isSafeInteger(seed)) {
    throw new MvxError('seed must be a safe integer', { code: 'INVALID_ARGUMENT' });
  }
  if (typeof groupBy !== 'string' || groupBy.length === 0) {
    throw new MvxError('groupBy must be a non-empty string', { code: 'INVALID_ARGUMENT' });
  }

  const eligible = [...samples].sort((left, right) =>
    String(left.sampleId ?? '').localeCompare(String(right.sampleId ?? ''))
  );
  if (eligible.length === 0) {
    return Object.freeze({
      schemaVersion: STABILITY_SCHEMA_VERSION,
      seed,
      ratio,
      minSamples,
      targetCount: 0,
      selectedSampleIds: Object.freeze([])
    });
  }

  const targetCount = Math.min(eligible.length, Math.max(minSamples, Math.ceil(eligible.length * ratio)));
  const rng = mulberry32(seed);
  const groups = new Map();
  for (const sample of eligible) {
    const key = String(sample?.[groupBy] ?? 'default');
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(sample);
  }

  const sortedGroupKeys = [...groups.keys()].sort();
  const shuffledGroups = new Map(
    sortedGroupKeys.map((key) => [key, deterministicShuffle(groups.get(key), rng)])
  );

  const selected = [];
  const selectedIds = new Set();
  for (const key of sortedGroupKeys) {
    const bucket = shuffledGroups.get(key);
    const quota = Math.max(1, Math.round((bucket.length / eligible.length) * targetCount));
    for (const item of bucket.slice(0, quota)) {
      if (selected.length >= targetCount) break;
      if (!selectedIds.has(item.sampleId)) {
        selectedIds.add(item.sampleId);
        selected.push(item.sampleId);
      }
    }
  }
  if (selected.length < targetCount) {
    const remaining = deterministicShuffle(
      eligible.filter((item) => !selectedIds.has(item.sampleId)),
      rng
    );
    for (const item of remaining) {
      if (selected.length >= targetCount) break;
      selectedIds.add(item.sampleId);
      selected.push(item.sampleId);
    }
  }

  selected.sort();
  return Object.freeze({
    schemaVersion: STABILITY_SCHEMA_VERSION,
    seed,
    ratio,
    minSamples,
    targetCount,
    selectedSampleIds: Object.freeze(selected)
  });
}

function scoreStats(scores) {
  if (scores.length === 0) {
    return {
      sampleCount: 0,
      mean: null,
      populationStdDev: null,
      sampleStdDev: null,
      min: null,
      max: null
    };
  }
  const n = scores.length;
  const mean = scores.reduce((sum, value) => sum + value, 0) / n;
  const sumSq = scores.reduce((sum, value) => sum + ((value - mean) ** 2), 0);
  const populationStdDev = Math.sqrt(sumSq / n);
  const sampleStdDev = n > 1 ? Math.sqrt(sumSq / (n - 1)) : 0;
  return {
    sampleCount: n,
    mean: roundMetric(mean),
    populationStdDev: roundMetric(populationStdDev),
    sampleStdDev: roundMetric(sampleStdDev),
    min: Math.min(...scores),
    max: Math.max(...scores)
  };
}

function summarizeVerdictConsistency(categories) {
  const n = categories.length;
  if (n === 0) {
    return {
      evaluatedRuns: 0,
      exactAgreement: null,
      majorityVerdict: null,
      majorityAgreementRate: null,
      pairwiseAgreementRate: null,
      uniqueVerdictsObserved: 0,
      verdictFlipCount: 0
    };
  }
  const counts = new Map();
  for (const category of categories) {
    counts.set(category, (counts.get(category) ?? 0) + 1);
  }
  const sorted = [...counts.entries()].sort((left, right) =>
    right[1] - left[1] || left[0].localeCompare(right[0])
  );
  const [majorityVerdict, majorityCount] = sorted[0];
  let agreeingPairs = 0;
  for (const [, count] of sorted) {
    agreeingPairs += count * (count - 1);
  }
  const totalPairs = n * (n - 1);
  let flipCount = 0;
  for (let index = 1; index < categories.length; index += 1) {
    if (categories[index] !== categories[index - 1]) flipCount += 1;
  }
  return {
    evaluatedRuns: n,
    exactAgreement: sorted.length === 1,
    majorityVerdict,
    majorityAgreementRate: roundMetric(majorityCount / n),
    pairwiseAgreementRate: totalPairs > 0 ? roundMetric(agreeingPairs / totalPairs) : null,
    uniqueVerdictsObserved: sorted.length,
    verdictFlipCount: flipCount
  };
}

export function summarizeRepeatedDynamicRuns(runs, options = {}) {
  if (!Array.isArray(runs) || runs.length === 0) {
    throw new MvxError('Repeated-run stability requires a non-empty array of M3 runs', {
      code: 'INVALID_ARGUMENT'
    });
  }
  assertOptionsObject(options, 'Repeated-run stability');
  const requestedRuns = options.requestedRuns ?? runs.length;
  if (!Number.isSafeInteger(requestedRuns) || requestedRuns < runs.length) {
    throw new MvxError('requestedRuns must be an integer >= runs.length', { code: 'INVALID_ARGUMENT' });
  }
  if (options.expectedPackageSha256 !== undefined
    && (typeof options.expectedPackageSha256 !== 'string' || !SHA256.test(options.expectedPackageSha256))) {
    throw new MvxError('expectedPackageSha256 must be a lowercase SHA-256 digest', { code: 'INVALID_ARGUMENT' });
  }
  if (options.expectedConfigSha256 !== undefined
    && (typeof options.expectedConfigSha256 !== 'string' || !SHA256.test(options.expectedConfigSha256))) {
    throw new MvxError('expectedConfigSha256 must be a lowercase SHA-256 digest', { code: 'INVALID_ARGUMENT' });
  }

  const seenRunIds = new Set();
  let baselinePackageSha256 = options.expectedPackageSha256 ?? null;
  let baselineConfigSha256 = options.expectedConfigSha256 ?? null;

  const completedScores = [];
  const completedVerdicts = [];
  const allOutcomeCategories = [];
  const verdictDistribution = {
    confirmed_attack: 0,
    suspicious_activity: 0,
    no_trigger_observed: 0,
    inconclusive: 0,
    failed: 0
  };
  const objectiveCounts = new Map();
  const runDetails = [];

  let completedRuns = 0;
  let inconclusiveRuns = 0;
  let failedRuns = 0;
  let containmentViolations = 0;
  let totalDurationMs = 0;

  for (let index = 0; index < runs.length; index += 1) {
    const run = runs[index];
    if (!run || typeof run !== 'object') {
      throw new MvxError(`Repeated run entry at index ${index} must be an object`, {
        code: 'INVALID_RUN_RECORD'
      });
    }
    const runId = run.runId;
    if (typeof runId !== 'string' || runId.length === 0) {
      throw new MvxError(`Repeated run entry at index ${index} is missing runId`, {
        code: 'MISSING_METADATA'
      });
    }
    if (seenRunIds.has(runId)) {
      throw new MvxError(`Duplicate runId detected in repeated-run stability input: ${runId}`, {
        code: 'DUPLICATE_RUN_ID'
      });
    }
    seenRunIds.add(runId);

    const pkgHash = run.packageSha256 ?? run.provenance?.packageSha256 ?? null;
    if (pkgHash !== null) {
      if (!SHA256.test(pkgHash)) {
        throw new MvxError(`Invalid packageSha256 in run ${runId}`, { code: 'INVALID_RUN_RECORD' });
      }
      if (baselinePackageSha256 === null) baselinePackageSha256 = pkgHash;
      else if (pkgHash !== baselinePackageSha256) {
        throw new MvxError(
          `Package SHA-256 mismatch across repeated runs (${runId}): expected ${baselinePackageSha256}, observed ${pkgHash}`,
          { code: 'PACKAGE_SHA_MISMATCH' }
        );
      }
    }

    const cfgHash = run.configSha256 ?? run.experimentConfigSha256 ?? null;
    if (cfgHash !== null) {
      if (!SHA256.test(cfgHash)) {
        throw new MvxError(`Invalid configSha256 in run ${runId}`, { code: 'INVALID_RUN_RECORD' });
      }
      if (baselineConfigSha256 === null) baselineConfigSha256 = cfgHash;
      else if (cfgHash !== baselineConfigSha256) {
        throw new MvxError(
          `Configuration SHA-256 mismatch across repeated runs (${runId}): expected ${baselineConfigSha256}, observed ${cfgHash}`,
          { code: 'CONFIG_MISMATCH' }
        );
      }
    }

    const status = run.status;
    const verdict = run.verdict ?? run.labReport?.verdict ?? null;
    const durationMs = typeof run.durationMs === 'number' && Number.isFinite(run.durationMs)
      ? run.durationMs
      : (typeof run.runtimeMs === 'number' && Number.isFinite(run.runtimeMs) ? run.runtimeMs : 0);
    totalDurationMs += durationMs;

    const isContainmentViolation = run.contained === false
      || run.failure?.code === 'LAB_CONTAINMENT_VIOLATION';
    if (isContainmentViolation) containmentViolations += 1;

    const objectives = run.labReport?.objectives ?? run.objectives ?? {};
    const confirmedObjectives = [];
    for (const [objName, objState] of Object.entries(objectives)) {
      if (!objectiveCounts.has(objName)) {
        objectiveCounts.set(objName, { confirmedCount: 0, observedCount: 0 });
      }
      const counter = objectiveCounts.get(objName);
      if (objState?.status === 'confirmed') {
        counter.confirmedCount += 1;
        counter.observedCount += 1;
        confirmedObjectives.push(objName);
      } else if (objState?.status === 'observed') {
        counter.observedCount += 1;
      }
    }
    confirmedObjectives.sort();

    if (status === 'completed' && VALID_VERDICTS.has(verdict) && verdict !== 'inconclusive' && !isContainmentViolation) {
      if (typeof run.riskScore !== 'number' || !Number.isFinite(run.riskScore)) {
        throw new MvxError(`Completed M3 run ${runId} is missing a finite numeric riskScore`, {
          code: 'INVALID_RUN_RECORD'
        });
      }
      completedRuns += 1;
      completedScores.push(run.riskScore);
      completedVerdicts.push(verdict);
      allOutcomeCategories.push(verdict);
      verdictDistribution[verdict] += 1;
    } else if (status === 'inconclusive' || verdict === 'inconclusive') {
      inconclusiveRuns += 1;
      allOutcomeCategories.push('inconclusive');
      verdictDistribution.inconclusive += 1;
    } else {
      failedRuns += 1;
      allOutcomeCategories.push('failed');
      verdictDistribution.failed += 1;
    }

    runDetails.push({
      runId,
      repeatIndex: run.repeatIndex ?? index + 1,
      status,
      verdict,
      riskScore: status === 'completed' && verdict !== 'inconclusive' && !isContainmentViolation
        ? run.riskScore
        : null,
      contained: run.contained ?? null,
      durationMs: roundMetric(durationMs),
      failureCode: run.failure?.code ?? null,
      failureReason: run.failure?.message ?? null,
      packageSha256: pkgHash,
      confirmedObjectives,
      suspiciousEventCount: Array.isArray(run.labReport?.suspicious) ? run.labReport.suspicious.length : 0
    });
  }

  const objectiveDetectionFrequency = Object.fromEntries(
    [...objectiveCounts.entries()]
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([name, counter]) => [
        name,
        {
          confirmedCount: counter.confirmedCount,
          observedCount: counter.observedCount,
          frequencyOverCompleted: completedRuns > 0 ? roundMetric(counter.confirmedCount / completedRuns) : null,
          frequencyOverExecuted: roundMetric(counter.confirmedCount / runs.length)
        }
      ])
  );

  return {
    schemaVersion: STABILITY_SCHEMA_VERSION,
    profile: STABILITY_PROFILE,
    sampleId: options.sampleId ?? runs[0].sampleId ?? null,
    extensionId: options.extensionId ?? runs[0].extensionId ?? null,
    packageSha256: baselinePackageSha256,
    configSha256: baselineConfigSha256,
    independentDatasetSampleCount: 1,
    counts: {
      requestedRuns,
      executedRuns: runs.length,
      completedRuns,
      inconclusiveRuns,
      failedRuns,
      containmentViolations
    },
    rates: {
      completionRate: roundMetric(completedRuns / requestedRuns),
      inconclusiveRate: roundMetric(inconclusiveRuns / requestedRuns),
      failureRate: roundMetric(failedRuns / requestedRuns)
    },
    riskScoreStats: {
      ...scoreStats(completedScores),
      excludedIncompatibleRunCount: inconclusiveRuns + failedRuns,
      aggregationPolicy: 'completed_runs_only_never_averaging_inconclusive_or_failed_states'
    },
    verdictDistribution,
    verdictConsistencyAllRuns: summarizeVerdictConsistency(allOutcomeCategories),
    verdictConsistencyCompletedRuns: summarizeVerdictConsistency(completedVerdicts),
    objectiveDetectionFrequency,
    durationStats: {
      totalDurationMs: roundMetric(totalDurationMs),
      meanDurationMs: roundMetric(totalDurationMs / runs.length)
    },
    runs: runDetails,
    caveats: [
      'Repeated dynamic runs evaluate behavioral stability for a single extension and must not be treated as independent samples in primary evaluation metrics.',
      'Inconclusive and failed runs are never coerced to zero or averaged with completed numeric risk scores.'
    ]
  };
}

export function computeMultiSampleStabilitySummary(sampleSummaries) {
  if (!Array.isArray(sampleSummaries)) {
    throw new MvxError('sampleSummaries must be an array', { code: 'INVALID_ARGUMENT' });
  }
  const categories = ['confirmed_attack', 'suspicious_activity', 'no_trigger_observed', 'inconclusive', 'failed'];
  const totalExtensions = sampleSummaries.length;
  let totalRequested = 0;
  let totalExecuted = 0;
  let totalCompleted = 0;
  let totalInconclusive = 0;
  let totalFailed = 0;
  let totalContainmentViolations = 0;
  let exactAllAgreementCount = 0;
  let totalVerdictFlips = 0;

  for (const summary of sampleSummaries) {
    totalRequested += summary.counts.requestedRuns;
    totalExecuted += summary.counts.executedRuns;
    totalCompleted += summary.counts.completedRuns;
    totalInconclusive += summary.counts.inconclusiveRuns;
    totalFailed += summary.counts.failedRuns;
    totalContainmentViolations += summary.counts.containmentViolations;
    if (summary.verdictConsistencyAllRuns.exactAgreement === true) exactAllAgreementCount += 1;
    totalVerdictFlips += summary.verdictConsistencyAllRuns.verdictFlipCount;
  }

  // Fleiss' kappa requires equal number of ratings n >= 2 across subjects
  let fleissKappa = null;
  const ratersPerSubject = new Set(sampleSummaries.map((summary) => summary.counts.executedRuns));
  if (totalExtensions > 0 && ratersPerSubject.size === 1) {
    const n = [...ratersPerSubject][0];
    if (n >= 2) {
      const N = totalExtensions;
      const categoryTotals = Object.fromEntries(categories.map((category) => [category, 0]));
      let pBarSum = 0;
      for (const summary of sampleSummaries) {
        let subjectSum = 0;
        for (const category of categories) {
          const count = summary.verdictDistribution[category] ?? 0;
          categoryTotals[category] += count;
          subjectSum += count * count;
        }
        pBarSum += (subjectSum - n) / (n * (n - 1));
      }
      const pBar = pBarSum / N;
      let pe = 0;
      for (const category of categories) {
        const pj = categoryTotals[category] / (N * n);
        pe += pj * pj;
      }
      if (Math.abs(1 - pe) < 1e-12) {
        fleissKappa = pBar === 1 ? 1 : null;
      } else {
        fleissKappa = roundMetric((pBar - pe) / (1 - pe));
      }
    }
  }

  return {
    schemaVersion: STABILITY_SCHEMA_VERSION,
    profile: STABILITY_PROFILE,
    extensionsEvaluated: totalExtensions,
    totalRequestedRuns: totalRequested,
    totalExecutedRuns: totalExecuted,
    totalCompletedRuns: totalCompleted,
    totalInconclusiveRuns: totalInconclusive,
    totalFailedRuns: totalFailed,
    totalContainmentViolations,
    overallExactAgreementRate: totalExtensions > 0 ? roundMetric(exactAllAgreementCount / totalExtensions) : null,
    overallFailureRate: totalRequested > 0 ? roundMetric(totalFailed / totalRequested) : null,
    overallInconclusiveRate: totalRequested > 0 ? roundMetric(totalInconclusive / totalRequested) : null,
    totalVerdictFlips,
    fleissKappa
  };
}
