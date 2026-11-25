# Research Datasets (`datasets/` — 150-Sample Target Structure)

Organized strictly by cohort into 4 dedicated folders to prevent mixing controlled synthetic specifications with real-world extensions:

| Folder | Cohort | Min Target | Goal Target | Manifest Entries | Local MV3 Ready | Pending Collection (`skip: true`) |
|---|---|---:|---:|---:|---:|---:|
| `real-world-benign/` | `real_world_benign` (`RWB-001`..`RWB-060`, 60/60 verified CWS IDs) | 40 | 60 | **60** | 0 | 60 |
| `controlled-benign/` | `controlled_benign` (`CB-001`..`CB-030`) | 20 | 30 | **30** | **30** | 0 |
| `controlled-security-test/` | `controlled_security_test` (`CST-001`..`CST-040`) | 30 | 40 | **40** | **40** | 0 |
| `real-world-malicious/` | `real_world_malicious` (`RWM-001`..`RWM-020`, 20/20 verified `GherardoFiori` IDs) | 10 | 20 | **20** | 0 | 20 |
| **TOTAL** | **4 cohorts** | **100** | **150** | **150** | **70** | **80** |

## Manifest Files

- `manifest-150.json`: Master 150-sample manifest (`70` active local MV3 extensions with `mvx-package-v1` `expectedPackageSha256` + `80` real-world entries explicitly marked `skip: true, skipReason: "pending_artifact_collection"` until downloaded and hash-verified).
- `manifest-controlled-70.json`: Immediately runnable 70-sample Controlled Benchmark manifest (`30 CB` + `40 CST`, zero skipped entries).

## Quick Validation & Execution Commands

```bash
# Validate all 150 entries (70 active MV3 + 80 explicitly skipped real-world slots)
node ./bin/mvx.js research validate \
  --manifest ./datasets/manifest-150.json \
  --require-manifest-v3 --strict-hashes

# Validate only the 70 locally ready controlled MV3 fixtures
node ./bin/mvx.js research validate \
  --manifest ./datasets/manifest-controlled-70.json \
  --require-manifest-v3 --strict-hashes

# Run M1 + M2 static benchmark on the 70 local controlled MV3 fixtures
node ./bin/mvx.js research experiment \
  --manifest ./datasets/manifest-controlled-70.json \
  --output ./results/local \
  --experiment-id controlled-70-static \
  --methods M1,M2 \
  --weights W1,W2,W3,W4,W5 \
  --require-manifest-v3
```

## Safety & Scientific Integrity Rules

1. Live real-world `.crx`/`.zip` files and `unpacked/` directories under `real-world-malicious/` and `real-world-benign/` are git-ignored and must **never** be committed.
2. No Ground Truth labels are stored in `manifest-150.json` or `manifest-controlled-70.json` (`mvx research validate` enforces `GROUND_TRUTH_FORBIDDEN`).
3. Controlled fixtures (`CB-*`, `CST-*`) must be evaluated separately from real-world extensions (`RWB-*`, `RWM-*`).
