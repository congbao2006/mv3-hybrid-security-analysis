# Research Artifacts — Empirical Evaluation of MV3 Chrome Extension Security Analysis

This directory archives all verifiable research data, dual-human ground truth audit logs, literature review records, independent Python verification scripts, figures, and manuscript materials for:

> **An Empirical Evaluation of Permission-Based, Static, Dynamic, and Hybrid Security Analysis for Manifest V3 Browser Extensions**  
> Quoc Hung Nguyen*, Xuan Ngoc Tran, Anh Truong Tai Nguyen, Cong Bao Le, The Luan Nguyen  
> University of Economics Ho Chi Minh City (UEH), Ho Chi Minh City, Vietnam (`hungngq@ueh.edu.vn`)

> **Safety & Ethics Notice:** No real-world malicious `.crx`/`.zip` extension binaries are redistributed in this repository. Only non-executable metadata, hashes (`mvx-package-v1` SHA-256), evaluation outputs, blinded human review sheets, and synthetic RFC-2606 `.test` controlled fixtures are archived.

## Directory Structure

| Path | Description |
|---|---|
| `ADVISOR_18POINT_RESPONSE_SUMMARY.md` | Point-by-point mapping of all 18 advisor revision items to sections, tables, figures, and files |
| `ground-truth/Dataset_Inventory.xlsx` | Complete 150-extension active inventory (+3 intake-replaced slots `RWM-004/015/019`) with package size, JS count, permissions, findings, and category |
| `ground-truth/Ground_Truth_Verified.xlsx` | Version-verified Ground Truth workbook (3 sheets: 150 active items, 10 excluded `Unknown_Unverified` items, agreement summary) |
| `ground-truth/Reviewer_1.csv`, `Reviewer_2.csv` | Independent blinded dual-human review sheets (`BLIND-001`–`BLIND-080`; 3-class $\kappa = 0.700$, 2-class $\kappa = 0.863$) |
| `ground-truth/Disagreement_Log.csv` | Resolution log for all 13 rater disagreements and version-drift exclusions |
| `literature/Literature_Review.xlsx` | Verified 24-entry literature review matrix (21 peer-reviewed papers with venues/DOIs, 1 MV3 spec, 2 open-source repos) |
| `results/results_per_extension.csv` | Consolidated per-extension outputs across all 150 active MV3 extensions |
| `results/results_per_finding.csv` | Consolidated per-finding static and dynamic rule outputs |
| `results/unified_runs_150.json` | Complete SHA-256-verified metadata across all 2,700 experiment artifacts |
| `verification/extension_scores_and_verdicts_150.csv` | Per-extension W1–W5 scores, M1–M5 values, M4 component breakdown, and dynamic verdicts |
| `verification/recompute_all_experiments.py` | Zero-dependency Python 3 stdlib script independently recomputing all tables, CIs, McNemar + Holm tests, EXP03–05, and 8-component M4 ablation |
| `verification/independent_recomputation_full.json` | Full JSON output of `recompute_all_experiments.py` (including discordant pair Sample IDs) |
| `figures/` | Publication-ready SVG and 1800 px PNG figures (`fig1`–`fig4`) |
| `manuscript/Paper_MV3_Revised_Official.docm` | Official Springer LNCS `.docm` manuscript |
| `manuscript/paper_v2_revised.md` | Source Markdown manuscript |

## Independent Reproduction

Using Python 3 (standard library only, no external packages required):

```bash
python3 research-artifacts/verification/recompute_all_experiments.py
```

This regenerates `extension_scores_and_verdicts_150.csv` and `independent_recomputation_full.json` directly from `results/` and `ground-truth/verified_gt_and_meta.json`.
