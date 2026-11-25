import { execFileSync } from 'node:child_process';
import os from 'node:os';
import process from 'node:process';
import { MvxError } from '../errors.js';
import { assertOptionsObject } from '../options.js';
import { VERSION } from '../version.js';

export const LOGGING_SCHEMA_VERSION = 1;
export const LOGGING_PROFILE = 'mvx-research-observability-v1';

export const PROGRESS_EVENT_TYPES = Object.freeze([
  'experiment.started',
  'sample.started',
  'method.completed',
  'sample.completed',
  'experiment.interrupted',
  'experiment.completed'
]);

export const LIFECYCLE_STATES = Object.freeze([
  'running',
  'resumed',
  'interrupted',
  'failed',
  'completed'
]);

const NON_RETRYABLE_CODES = new Set([
  'LAB_CONTAINMENT_VIOLATION',
  'HASH_MISMATCH',
  'PACKAGE_SHA_MISMATCH',
  'ARCHIVE_IDENTITY_MISMATCH',
  'LAB_IDENTITY_MISMATCH',
  'ARTIFACT_HASH_MISMATCH',
  'CONFIG_MISMATCH',
  'GROUND_TRUTH_FORBIDDEN',
  'INVALID_GROUND_TRUTH',
  'INVALID_DATASET',
  'INVALID_MANIFEST',
  'INVALID_CONFIG',
  'INVALID_ARGUMENT',
  'DUPLICATE_SAMPLE_ID',
  'DUPLICATE_RUN_ID',
  'CORRUPT_RUN_LOG',
  'EXPERIMENT_EXISTS',
  'RISK_ACK_REQUIRED',
  'NON_MV3_MANIFEST',
  'SAMPLE_SKIPPED',
  'SCAN_LIMIT',
  'DNR_RULE_LIMIT',
  'ENCODED_PAYLOAD_LIMIT'
]);

const RETRYABLE_CODES = new Set([
  'LAB_TIMEOUT',
  'LAB_INCONCLUSIVE',
  'ETIMEDOUT',
  'ECONNRESET',
  'EAGAIN',
  'EBUSY'
]);

const SENSITIVE_KEY_PATTERN = /(?:password|passwd|pwd|secret|token|api[-_]?key|auth(?:orization)?|cookie|session|credential)/i;

const REDACTION_PATTERNS = Object.freeze([
  // URL embedded credentials: scheme://user:pass@host
  [/(\b[a-z][a-z0-9+.-]*:\/\/)([^/\s:@]+):([^/\s@]+)@/gi, '$1[REDACTED]:[REDACTED]@'],
  // Authorization / Bearer / Basic headers
  [/(\bAuthorization\s*[:=]\s*)(?:Bearer|Basic|Token)\s+[^\s,;'"`]+/gi, '$1[REDACTED]'],
  [/(\b(?:Bearer|Basic)\s+)[A-Za-z0-9._~+/=-]{8,}/g, '$1[REDACTED]'],
  // Cookie / Set-Cookie header values
  [/(\b(?:Set-)?Cookie\s*[:=]\s*)([^\r\n;]+)/gi, '$1[REDACTED]'],
  // Query string sensitive params: ?token=..., &password=..., etc.
  [/([?&](?:token|access_token|refresh_token|auth|api_key|apikey|password|passwd|pwd|secret|session|session_id|cookie)=)([^&\s'"`]+)/gi, '$1[REDACTED]'],
  // JSON or key=value pairs with sensitive keys
  [/((?:["']?(?:password|passwd|pwd|secret|token|access_token|refresh_token|api_key|apikey|cookie|session_id|session|credential|authorization)["']?\s*[:=]\s*)(?:["']))([^"']+)(\2)?/gi, '$1[REDACTED]'],
  [/(\b(?:password|passwd|pwd|secret|token|access_token|refresh_token|api_key|apikey|cookie|session_id|credential)\s*[:=]\s*)([^\s,;'"`{}[\]]+)/gi, '$1[REDACTED]']
]);

export function redactSensitiveText(input) {
  if (typeof input !== 'string') return input;
  let output = input;
  for (const [pattern, replacement] of REDACTION_PATTERNS) {
    output = output.replace(pattern, replacement);
  }
  return output;
}

export function redactSensitiveObject(value, seen = new Set()) {
  if (value === null || value === undefined) return value;
  if (typeof value === 'string') return redactSensitiveText(value);
  if (typeof value !== 'object') return value;
  if (seen.has(value)) return '[CIRCULAR]';
  seen.add(value);
  if (Array.isArray(value)) {
    return value.map((item) => redactSensitiveObject(item, seen));
  }
  const result = {};
  for (const key of Object.getOwnPropertyNames(value)) {
    if (SENSITIVE_KEY_PATTERN.test(key) && typeof value[key] === 'string' && value[key].length > 0) {
      result[key] = '[REDACTED]';
    } else {
      result[key] = redactSensitiveObject(value[key], seen);
    }
  }
  return result;
}

export function isRetryableFailureCode(code) {
  if (typeof code !== 'string' || code.length === 0) return false;
  if (NON_RETRYABLE_CODES.has(code)) return false;
  if (RETRYABLE_CODES.has(code)) return true;
  return false;
}

export function normalizeStructuredFailure(input, defaults = {}) {
  if (input === null || input === undefined) return null;
  const code = typeof input.code === 'string' && input.code.length > 0
    ? input.code
    : (typeof defaults.code === 'string' && defaults.code.length > 0 ? defaults.code : 'UNEXPECTED_ERROR');
  const rawMessage = typeof input.message === 'string'
    ? input.message
    : String(input.message ?? defaults.message ?? 'Unknown failure');
  const stage = typeof input.stage === 'string' && input.stage.length > 0
    ? input.stage
    : (typeof defaults.stage === 'string' && defaults.stage.length > 0 ? defaults.stage : 'unknown');
  const retryable = typeof input.retryable === 'boolean'
    ? input.retryable
    : (typeof defaults.retryable === 'boolean' ? defaults.retryable : isRetryableFailureCode(code));
  const timestamp = typeof input.timestamp === 'string' && input.timestamp.length > 0
    ? input.timestamp
    : (typeof defaults.timestamp === 'string' && defaults.timestamp.length > 0
      ? defaults.timestamp
      : new Date().toISOString());

  return Object.freeze({
    code,
    message: redactSensitiveText(rawMessage),
    stage,
    retryable,
    timestamp
  });
}

function safeExec(command, args, { cwd = process.cwd(), timeout = 2_000 } = {}) {
  try {
    const out = execFileSync(command, args, {
      cwd,
      encoding: 'utf8',
      timeout,
      stdio: ['ignore', 'pipe', 'pipe']
    }).trim();
    return { ok: true, output: out, error: null };
  } catch (error) {
    return {
      ok: false,
      output: null,
      error: error?.code === 'ENOENT' ? `${command}_not_found` : redactSensitiveText(error?.message ?? 'probe_failed')
    };
  }
}

export function probeGitStatus(cwd = process.cwd()) {
  const commitProbe = safeExec('git', ['rev-parse', 'HEAD'], { cwd });
  const commit = commitProbe.ok && /^[a-f0-9]{40}$/.test(commitProbe.output)
    ? commitProbe.output
    : 'unknown';
  if (!commitProbe.ok) {
    return Object.freeze({
      commit,
      workingTreeStatus: 'unavailable',
      dirty: null,
      reason: commitProbe.error
    });
  }
  const statusProbe = safeExec('git', ['status', '--porcelain'], { cwd });
  if (!statusProbe.ok) {
    return Object.freeze({
      commit,
      workingTreeStatus: 'unavailable',
      dirty: null,
      reason: statusProbe.error
    });
  }
  const dirty = statusProbe.output.length > 0;
  return Object.freeze({
    commit,
    workingTreeStatus: dirty ? 'dirty' : 'clean',
    dirty,
    reason: null
  });
}

export function probeNpmVersion() {
  const ua = process.env.npm_config_user_agent;
  if (typeof ua === 'string') {
    const match = ua.match(/npm\/([0-9]+\.[0-9]+\.[0-9]+[^\s]*)/);
    if (match) return Object.freeze({ status: 'available', version: match[1], source: 'env', reason: null });
  }
  const probe = safeExec('npm', ['--version']);
  if (probe.ok && probe.output.length > 0) {
    return Object.freeze({ status: 'available', version: probe.output, source: 'cli', reason: null });
  }
  return Object.freeze({ status: 'unavailable', version: null, source: null, reason: probe.error });
}

export function probeDockerEnvironment({ imageReference = null, probeRuntime = true } = {}) {
  if (!probeRuntime) {
    return Object.freeze({
      status: 'unavailable',
      version: null,
      imageReference,
      imageId: null,
      imageDigest: null,
      reason: 'runtime_probe_skipped'
    });
  }
  const versionProbe = safeExec('docker', ['version', '--format', '{{.Server.Version}}']);
  if (!versionProbe.ok || !versionProbe.output) {
    return Object.freeze({
      status: 'unavailable',
      version: null,
      imageReference,
      imageId: null,
      imageDigest: null,
      reason: versionProbe.error ?? 'docker_daemon_unavailable'
    });
  }
  let imageId = null;
  let imageDigest = null;
  if (imageReference) {
    const idProbe = safeExec('docker', ['image', 'inspect', '--format', '{{.Id}}', imageReference]);
    if (idProbe.ok && idProbe.output) imageId = idProbe.output;
    const digestProbe = safeExec('docker', ['image', 'inspect', '--format', '{{index .RepoDigests 0}}', imageReference]);
    if (digestProbe.ok && digestProbe.output) imageDigest = digestProbe.output;
  }
  return Object.freeze({
    status: 'available',
    version: versionProbe.output,
    imageReference,
    imageId,
    imageDigest,
    reason: null
  });
}

export function collectExtendedEnvironmentMetadata(overrides = {}, options = {}) {
  assertOptionsObject(overrides, 'Environment metadata');
  assertOptionsObject(options, 'Environment probe options');
  const cwd = options.cwd ?? process.cwd();
  const skipExternalProbes = options.skipExternalProbes === true;
  const requiresDocker = options.requiresDocker === true;
  const imageReference = options.imageReference ?? null;

  const cpus = os.cpus();
  const gitInfo = overrides.git
    ? Object.freeze({ ...overrides.git })
    : (skipExternalProbes
      ? Object.freeze({
        commit: overrides.mvxBaseCommit ?? 'unknown',
        workingTreeStatus: 'unavailable',
        dirty: null,
        reason: 'probe_skipped'
      })
      : probeGitStatus(cwd));
  const npmInfo = overrides.npm
    ? Object.freeze({ ...overrides.npm })
    : (skipExternalProbes
      ? Object.freeze({ status: 'unavailable', version: null, source: null, reason: 'probe_skipped' })
      : probeNpmVersion());
  const dockerInfo = overrides.docker
    ? Object.freeze({ ...overrides.docker })
    : probeDockerEnvironment({ imageReference, probeRuntime: !skipExternalProbes });
  const chromiumInfo = overrides.chromium
    ? Object.freeze({ ...overrides.chromium })
    : Object.freeze({
      status: 'unavailable',
      version: null,
      source: null,
      reason: 'populated_from_m3_runtime_report_when_executed'
    });

  const dependencyStatus = Object.freeze({
    dockerRequired: requiresDocker,
    dockerSatisfied: !requiresDocker || dockerInfo.status === 'available' || options.customLabRunner === true,
    note: requiresDocker && dockerInfo.status !== 'available' && options.customLabRunner !== true
      ? 'REQUIRED_DEPENDENCY_MISSING: Docker daemon is required for live M3 dynamic execution'
      : (dockerInfo.status !== 'available'
        ? 'OPTIONAL_METADATA_UNAVAILABLE: Docker metadata unavailable (not required for static-only or mocked execution)'
        : 'All detected execution dependencies available')
  });

  return Object.freeze({
    startedAtUtc: overrides.startedAtUtc ?? new Date().toISOString(),
    osPlatform: overrides.osPlatform ?? process.platform,
    osRelease: overrides.osRelease ?? os.release(),
    osArch: overrides.osArch ?? process.arch,
    cpuModel: overrides.cpuModel ?? (cpus[0]?.model ?? 'unknown'),
    cpuCores: overrides.cpuCores ?? cpus.length,
    totalMemoryBytes: overrides.totalMemoryBytes ?? os.totalmem(),
    nodeVersion: overrides.nodeVersion ?? process.version,
    npmVersion: overrides.npmVersion ?? npmInfo.version,
    npm: npmInfo,
    mvxVersion: VERSION,
    mvxBaseCommit: overrides.mvxBaseCommit ?? gitInfo.commit,
    git: gitInfo,
    docker: dockerInfo,
    chromium: chromiumInfo,
    dependencyStatus
  });
}

export function createProgressEvent(type, payload = {}) {
  if (!PROGRESS_EVENT_TYPES.includes(type)) {
    throw new MvxError(`Unsupported progress event type: ${String(type)}`, { code: 'INVALID_ARGUMENT' });
  }
  return Object.freeze({
    schemaVersion: LOGGING_SCHEMA_VERSION,
    profile: LOGGING_PROFILE,
    event: type,
    timestampUtc: payload.timestampUtc ?? new Date().toISOString(),
    ...redactSensitiveObject(payload)
  });
}

export function formatProgressEventText(event) {
  const ts = event.timestampUtc ?? '';
  const counts = event.statusCounts
    ? ` [ok=${event.statusCounts.completed ?? 0} fb=${event.statusCounts.completed_with_static_fallback ?? 0} inc=${event.statusCounts.inconclusive ?? 0} fail=${event.statusCounts.failed ?? 0} skip=${event.statusCounts.skipped ?? 0}]`
    : '';
  if (event.event === 'experiment.started') {
    return `[${ts}] START experiment=${event.experimentId} samples=${event.totalSamples} methods=${(event.methods ?? []).join(',')} weights=${(event.weightProfiles ?? []).join(',')} resumed=${Boolean(event.resumed)}\n`;
  }
  if (event.event === 'sample.started') {
    return `[${ts}] SAMPLE [${event.sampleIndex}/${event.totalSamples}] START sample=${event.sampleId} ext=${event.extensionId}${counts}\n`;
  }
  if (event.event === 'method.completed') {
    const detail = [
      event.method,
      event.weightProfile ? `/${event.weightProfile}` : '',
      event.repeatIndex ? `#r${event.repeatIndex}` : ''
    ].join('');
    const cached = event.resumedFromCache ? ' (cached)' : '';
    const dur = typeof event.durationMs === 'number' ? ` ${event.durationMs}ms` : '';
    return `[${ts}]   METHOD [${event.sampleIndex}/${event.totalSamples}] sample=${event.sampleId} ${detail} status=${event.status}${cached}${dur}${counts}\n`;
  }
  if (event.event === 'sample.completed') {
    return `[${ts}] SAMPLE [${event.sampleIndex}/${event.totalSamples}] DONE sample=${event.sampleId}${counts}\n`;
  }
  if (event.event === 'experiment.interrupted') {
    return `[${ts}] INTERRUPTED experiment=${event.experimentId} reason=${event.reason ?? 'unknown'} processed=${event.processedSamples ?? 0}/${event.totalSamples ?? 0}${counts}\n`;
  }
  if (event.event === 'experiment.completed') {
    return `[${ts}] DONE experiment=${event.experimentId} lifecycle=${event.lifecycleState ?? 'completed'} records=${event.totalRunRecords ?? 0}${counts}\n`;
  }
  return `[${ts}] ${event.event}\n`;
}
