# Research CLI Guide (`mvx research`)

The `mvx research` command namespace integrates the MVX Audit empirical study modules (M1–M4 evaluation modes, W1–W5 severity weight profiles, batch execution, repeated-run stability, deterministic exporters, and isolated Ground Truth evaluation) without altering any legacy CLI command.

## Subcommands

### 1. Validate a Dataset Manifest and Optional Config

```bash
mvx research validate \
  --manifest dataset_manifest.json \
  --config experiment_config.json \
  --require-manifest-v3 \
  --strict-hashes \
  --format json
```

- Verifies dataset manifest schema, sample ID uniqueness, artifact existence, package/archive SHA-256 hashes, Manifest V3 compatibility, cohort/campaign metadata, and strict Ground Truth separation.
- Never assigns Ground Truth labels. Add `--acknowledge-risk` if packed `.crx`/`.zip` samples must be unpacked to verify inner `manifest.json` and `expectedPackageSha256`.

### 2. Run an Experiment Batch (`M1`–`M4`, `W1`–`W5`)

```bash
mvx research experiment \
  --manifest dataset_manifest.json \
  --output ./experiments \
  --experiment-id exp-2026-main \
  --methods M1,M2,M3,M4 \
  --weights W1,W2,W3,W4,W5 \
  --scenario ./lab/scenarios/credential-exfiltration.json \
  --m3-repeats 3 \
  --m3-timeout 60000 \
  --require-manifest-v3 \
  --acknowledge-risk \
  --format text
```

- Validates all inputs before creating output directories and delegates execution directly to `runExperimentBatch()`.
- Refuses to overwrite an existing experiment directory (`EXPERIMENT_EXISTS`) unless `--resume` is specified.
- Halts immediately with `LAB_CONTAINMENT_VIOLATION` if dynamic execution detects uncontained external activity, while retaining persisted evidence.

### 3. Resume an Interrupted Experiment

```bash
mvx research resume ./experiments/exp-2026-main --acknowledge-risk --format json
```

- Verifies `run_manifest.json`, `experimentConfigSha256`, every JSONL line in `runs.jsonl`, and the SHA-256 digest of every cached artifact on disk before executing only missing runs.
- Never overwrites completed records.

### 4. Compute Repeated-Run Dynamic Stability

```bash
mvx research stability ./experiments/exp-2026-main \
  --output ./exports/stability \
  --format json
```

- Delegates to `summarizeRepeatedDynamicRuns()` and `computeMultiSampleStabilitySummary()`.
- Preserves independent dataset sample counts (`independentExtensionsEvaluated`) and never treats repeated runs as independent extensions.

### 5. Export Label-Blind Research Tables

```bash
mvx research export ./experiments/exp-2026-main \
  --output ./exports/exp-2026-main \
  --format json
```

- Emits `raw/` (`runs_export.jsonl`, `execution_log.csv`, `failure_and_inconclusive_cases.csv`), `tables/` (`per_extension_results`, `weight_profile_comparison`, `method_summary`, optional `stability_summary`), and `export_manifest.json` with SHA-256 digests.
- Optionally pass `--evaluation <evaluation_report.json> --evaluation-output <separate-dir>` to emit Ground Truth evaluation tables to a physically separate directory.

### 6. Evaluate Against Finalized Ground Truth

```bash
mvx research evaluate ./experiments/exp-2026-main \
  --ground-truth ./ground_truth_final.csv \
  --config ./eval_config.json \
  --output ./evaluations/exp-2026-main \
  --format text
```

- Requires explicit `--ground-truth`, `--config` (with pre-registered finite numeric `thresholds` for every evaluated method), and a separate `--output` directory.
- Never tunes thresholds automatically, never mutates experiment artifacts, and never alters Ground Truth labels.
- Preserves `groundTruthSha256`, `experimentManifestSha256`, and `evaluationConfigSha256` across `evaluation_report.json`, `evaluation_metrics.csv`, and `statistical_comparisons.csv`.

### 7. Inspect an Experiment (Label-Blind)

```bash
mvx research inspect ./experiments/exp-2026-main --format json
```

- Reports experiment metadata, dataset/sample counts, methods and weights, run status distribution, failed/inconclusive counts, containment violations, provenance/artifact integrity checks, stability availability, and export/evaluation artifact paths without exposing Ground Truth labels.

## Stable Research CLI Error Codes

| Error Code | Meaning |
|---|---|
| `INVALID_DATASET` | Missing/malformed dataset manifest, duplicate sample ID, missing artifact, or non-MV3 failure when required |
| `INVALID_CONFIG` | Invalid research CLI option, experiment/evaluation config, or missing pre-registered method threshold |
| `HASH_MISMATCH` | Package or archive SHA-256 mismatch against expected manifest or Ground Truth hash |
| `HASH_MISSING` | Missing expected package/archive SHA-256 when `--strict-hashes` is enabled |
| `EXPERIMENT_EXISTS` | Target experiment output directory already exists without `--resume` |
| `CONFIG_MISMATCH` | Configuration or fusion config SHA-256 drift detected on resume or inspection |
| `CORRUPT_RUN_LOG` | Malformed JSONL line, duplicate `runId`, or invalid run record in `runs.jsonl` |
| `ARTIFACT_HASH_MISMATCH` | Missing or tampered cached artifact file referenced by `runs.jsonl` |
| `GROUND_TRUTH_FORBIDDEN` | Ground Truth field or output path leaked into label-blind workflow |
| `INVALID_GROUND_TRUTH` | Unreadable, malformed, or invalid-vocabulary Ground Truth file |
| `LAB_CONTAINMENT_VIOLATION` | Uncontained external network activity observed during M3 dynamic execution |
| `EVALUATION_FAILED` | Evaluation could not be completed (e.g., empty run log or zero eligible verified Ground Truth records) |
