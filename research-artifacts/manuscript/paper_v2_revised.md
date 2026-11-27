# An Empirical Evaluation of Permission-Based, Static, Dynamic, and Hybrid Security Analysis for Manifest V3 Browser Extensions

**Authors:** Quoc Hung NGUYEN *[0000-0002-6363-0160], Xuan Ngoc TRAN [0009-0009-9947-8103], Anh Truong Tai NGUYEN [0009-0001-1866-031X], Cong Bao LE [0009-0001-0151-0120], The Luan NGUYEN [0009-0007-9242-3770]
**Affiliation:** University of Economics Ho Chi Minh City (UEH), Ho Chi Minh City, Vietnam
**Correspondence:** hungngq@ueh.edu.vn

**Abstract.** Checking Manifest V3 (MV3) Chrome extensions for security risk is still hard in practice. Permissions show only possible access, static rules over-alert on normal web libraries, and short-lived service workers make runtime tracing hard. Building on `mvx-audit` v3.1.0, we test five separate setups on 150 MV3 extensions: permission-only (M1), static source/package-only (M2), combined static scoring (M5), offline Docker/Chromium dynamic testing with an 8-second canary (M3), and hybrid scoring (M4, Formula C-2, $\alpha = 0.3$). Two reviewers checked all 80 real-world packages blindly by ID, version, and SHA-256 ($\kappa = 0.700$ 3-class; $\kappa = 0.863$ 2-class). Removing 10 version-drifted or unverified items leaves 70 verified real-world extensions (59B, 11M) plus 70 controlled fixtures (30 CB, 40 CST). On controlled common samples (n = 69), M4 ranks best (ROC-AUC = 0.962, FPR = 0%), while recall at T = 40 is 10.3% (4/39) because single-indicator fixtures score below 40. On verified real-world common samples (n = 61: 53B, 8M), M3 alert mode ($\ge 50$) gives the best triage separation (ROC-AUC = 0.790, Recall = 75.0%, F1 = 0.522, alert rate = 17.0%) but finds 0/8 strict confirmed attacks. Relative to M2, the hybrid framework reduces baseline alerts primarily through static score aggregation (52.5% to 30.5% on n = 69; Holm $p = 0.0073$), while the incremental contribution of dynamic evidence remains limited by runtime attribution constraints (0/18 suspicious runs with a CDP extension initiator, making real-world M4 equal M5). Static screening averages 0.23 s vs 11.02 s for end-to-end M4 (47.0×). Across W1–W5, ranks stay stable ($\rho \ge 0.971$) while risk tiers shift on up to 24.1% of extensions.

**Keywords:** Browser extension security, Manifest V3, empirical evaluation, static analysis, dynamic analysis, hybrid risk scoring, ground truth verification.

## 1 Introduction

### 1.1 Research Background and Motivation

Browser extensions run with broad access inside the browser, letting them read cookies, inspect forms, edit web pages, watch tabs, or send cross-origin requests across visited sites [1, 2, 4, 16]. Store studies show risky extensions stay on the Chrome Web Store (CWS) for months, and safe extensions can turn harmful after an update or ownership change [11, 16, 21]. Google introduced Manifest V3 (MV3) [22] to reduce this risk by replacing background pages with event-driven service workers, banning remote executable code, and replacing blocking `webRequest` with `declarativeNetRequest` (DNR). Recent work shows MV3 lowers some older attack paths but does not stop local malicious code, DOM injection, or broad host access, while short-lived service workers make runtime tracing harder [18, 19, 20].

### 1.2 Problem Statement and Research Gap

Each single analysis method has clear limits. Permission checks (M1) finish in milliseconds but show only possible access: password managers normally ask for broad hosts while hidden threats need few permissions [1, 17]. Static source scanning (M2) checks JavaScript, HTML, Base64 strings, and DNR rules without execution, yet fires frequent false alerts on UI libraries like React or Vue [13, 15, 21]. Dynamic testing (M3) runs extensions with fake bait data [3, 7] for concrete runtime evidence, but runs much slower and misses inactive code; `no_trigger_observed` never proves an extension is safe [3, 6]. Prior studies mostly tested static scanners (DoubleX [13], CoCo [15]), dynamic taint tools (Hulk [3], Mystique [7], JTaint [12]), or store ML models [21] on MV2 datasets in separate setups. Few compare M1–M5 on identical MV3 packages with common-sample fairness, version-level ground truth, weight sensitivity, and operational failures.

### 1.3 Research Objectives and Research Questions

We evaluate single and hybrid MV3 security analysis under strict label isolation and version-verified ground truth across four questions:
- **RQ1:** How well do M1, M2, and combined static analysis (M5) detect security indicators in controlled and real-world MV3 extensions? (EXP01, EXP03)
- **RQ2:** What extra evidence does isolated dynamic analysis (M3) add, and where does hybrid scoring (M4) improve on or match M5? (EXP02, Ablation)
- **RQ3:** How sensitive are scores, risk tiers, and alerts to weights (W1–W5), Formula C-2 settings, and structural traits? (EXP04, Sensitivity)
- **RQ4:** What trade-offs appear across detection quality, baseline alerts, coverage, and runtime cost? (EXP05, Error Analysis)

### 1.4 Research Contributions

We build on open-source `mvx-audit` v3.1.0 [23] and clearly separate inherited engine parts (CRX3/ZIP unpacker, default scan/XML/DTD caps in `src/crx.js` and `src/scan-limits.js`, `mvx-package-v1` hashing, base rules in `src/rules/`, and Docker lab in `lab/Dockerfile`, `src/lab-runner.js`) from our new work. Our four contributions are: (1) a **150-extension version-verified MV3 benchmark** separating 70 controlled fixtures (30 CB, 19 inherited, 21 authored) from 80 real-world packages audited blindly by two reviewers ($\kappa = 0.700$ 3-class; $\kappa = 0.863$ 2-class), excluding 10 drifted/unverified items; (2) an **isolated five-method pipeline** (`src/research/`, `configs/`, `datasets/`) enforcing `GROUND_TRUTH_FORBIDDEN` with 3-repeat checks and independent Python verification; (3) **frozen hybrid scoring (Formula C-2) and 8-part ablation** with post-hoc $\alpha$/threshold sweeps; and (4) **fair multi-view results** (Method-Specific, Common-Sample, End-to-End) explaining where dynamic triage helps and why real-world M4 matches M5 under CDP initiator limits.

## 2 Background and Related Work

### 2.1 Manifest V3 Architecture and Security Model

Chromium limits extensions using manifest permissions and isolated execution worlds [1, 2]. An MV3 CRX3 archive holds `manifest.json` and local scripts across three contexts [22]: manifest permissions (`cookies`, `tabs`, `scripting`, `downloads`, `debugger`, `host_permissions`, CSP); content scripts sharing the DOM unless `world: "MAIN"` disables heap isolation; and short-lived service workers paired with DNR rules. When a service worker stops while idle, Chromium DevTools Protocol (CDP) tracing can lose its target and end as `inconclusive`.

### 2.2 Security Threat Taxonomy

Table 1 maps static rules and dynamic hooks to eight threat categories (T01–T08) in `src/research/hybrid-fusion.js`; four categories (T01, T06, T07, T08) have no dynamic hook in `mvx-audit` v3.1.0 and are marked unsupported.

**Table 1.** Threat taxonomy (T01–T08), static indicators, methods, and dynamic hook support.

| ID & Category | Static Indicators | Methods | Dynamic Hook / M4 Scope |
|---|---|---|---|
| T01 Excess Perm. | Hosts (MVX101), APIs (102), chains (103), proxy/DNR (110–111) | M1 | Unsupported (N/A) |
| T02 Data Leakage | History/clipboard/tabs/nav + exfil (MVX206–207, 209, 212) | M1–M3 | Primary (canary/req) |
| T03 Cred. Exp. | Cookie/debugger/password form (MVX103, 205–206, 209) | M1–M3 | Primary (cred/cookie) |
| T04 DOM Manip. | `innerHTML`/`document.write`/`world:"MAIN"`/iframe (203–204, 211) | M2, M3 | Cond. (no Tier-A floor) |
| T05 Unauth. Nav. | Redirect/download/DNR rules (MVX110, 113–114, 208) | M1–M3 | Primary (hijack/dl) |
| T06 Unsafe Exec. | `eval`/`Function`/remote/WASM/bridge (003, 201–202, 210, 213) | M1, M2 | Unsupported (N/A) |
| T07 Resource Ab. | Opaque WASM (MVX003), proxy/tab amp. (MVX102) | M1, M2 | Unsupported (N/A) |
| T08 Supply Chain | Integrity, CRX auth., vendored anomalies (MVX002, 004, 115) | M2 | Unsupported (N/A) |

### 2.3 Permission-based and Static Security Analysis

Static tools check manifests, syntax trees, and data flows without execution: early audits studied permission isolation and Chrome bugs [1, 2], while DoubleX [13] (154,484 packages, Extension Dependence Graphs) and CoCo [15] (abstract interpretation) scaled flow checks. Static tools run in milliseconds but miss obfuscated sinks and over-alert on UI libraries [21].

### 2.4 Dynamic Behavioral Analysis

Dynamic tools run extensions in monitored browsers: Hulk [3] tested 48,332 extensions on honey-pages; ExtensionGuard [5], Ex-Ray [6], Mystique [7], and JTaint [12] tracked runtime privacy leaks; Starov and Nikiforakis [9], Carnus [10], and Solomos et al. [14] measured DOM/side-channel fingerprinting; and EmPoWeb [8] found message abuse. Offline synthetic canaries give clear triggers but depend on scenario design and runtime limits [3, 4].

### 2.5 Security Risk Scoring and Related Studies

WebEval [4] combined static, dynamic, and store signals in production, and Pantelaios et al. [11] tracked update changes over time. Recent MV2/MV3 work measured risky CWS extensions [16], sensitive DOM access [17], MV3 migration [18], developer security challenges [19, 20], and concept drift in supervised static ML [21]. Table 2 compares key studies (full 24-entry matrix in `Literature_Review.xlsx`). Unlike prior work, we test M1–M5 on identical MV3 packages with common-sample fairness, version-verified GT, parameter sensitivity, and 8-part ablation.

**Table 2.** Comparison of related extension security studies (full 24-entry review in `Literature_Review.xlsx`).

| Study (Year) | Dataset (Era) | Ground Truth | Method | Key Finding | Gap vs This Study |
|---|---|---|---|---|---|
| Carlini [2] (2012) | 100 Chrome (MV1/2) | Manual | Manual/static | 70 vulns in 40 ext | No sandbox/hybrid |
| Hulk [3] (2014) | 48k Chrome (MV2) | Manual+rem. | Dynamic fuzz | Triggers inactive code | Dynamic-only |
| WebEval [4] (2015) | 100k+ CWS (MV2) | Google logs | Hybrid+rep. | 9.4% mal.; hybrid helps | Private data; MV2 |
| Mystique [7] (2018) | 181k Chrome (MV2) | Leak logs | Dyn. taint | Wide privacy leaks | Custom browser; MV2 |
| Deltas [11] (2020) | 1.2M ver. (MV2) | Rem.+audit | Update delta | Safe ext turn mal. | Needs crawl; MV2 |
| DoubleX/CoCo [13, 15] | 154k+ CWS (MV2) | Exploits | Static flow | Fast flow/priv-esc | Static-only; UI FPs |
| MV3 Studies [16–18] | CWS (MV2/MV3) | Rem./DOM | Audit/MV3 | Threats stay in MV3 | No M1–M5 ablation |
| Rosenzweig [21] (26) | CWS ML (MV3) | Removals | Static ML | Drift & noisy labels | Static ML only |
| **This Study (2026)** | **150 MV3** | **Ver.-ver.+κ** | **M1–M5+C-2** | **Common-61, 8-abl.** | **1 scen.; 70 ver. RW** |

## 3 Research Methodology

### 3.1 Overall Research Framework

Figure 1 shows our eight-stage workflow. Every script follows `GROUND_TRUTH_FORBIDDEN`: no file passed to M1–M5 holds labels, and verified GT enters only at Stage 6. Stages 4–5 run M1–M5 separately, and Stages 6–7 verify all metrics independently in Python (`recompute_all_experiments.py`).

![Fig. 1. Proposed Empirical Research Framework](../deliverables_for_advisor/figures/fig1_research_framework.svg)
**Fig. 1.** Empirical research framework mapping isolated branches (M1–M5), Ground Truth isolation, EXP01–EXP05, and RQ1–RQ4.

### 3.2 Dataset Construction and Ground Truth Verification

Our 150-extension MV3 dataset (`Dataset_Inventory.xlsx`, `Ground_Truth_Verified.xlsx`) separates two tiers:
- **Controlled (n = 70, 100% MV3):** 30 benign controls (`CB-001`–`030`, zero risky permissions/sinks) and 40 Controlled Security Tests (`CST-001`–`040`): 19 inherited `mvx-audit` fixtures (`CST-001`–`019`) and 21 team-authored fixtures on `.test` domains (`CST-020`–`040`) designed around T01–T08 (so they are not fully independent of `mvx-audit`'s rule families). CST positives are *security indicators*, not real malware.
- **Real-World (n = 80 active, 100% MV3):** 60 live CWS CRX3 packages (`RWB-001`–`060`, fetched Nov 26, 2026 across 6 categories after 104 intake exclusions from 164 candidates: 60 HTTP errors, 29 `ENCODED_PAYLOAD_LIMIT`, 8 size/file caps, 7 XML/DTD rejections) and **exactly 20 active packages** from MIT-licensed `MaliciousBrowserExtensions` [24] pinned at commit `b346c095f8e33b9875da2bbede3854855b984bae`. Three candidates (`RWM-004, 015, 019`) exceeded 25 MB and were replaced 1-for-1 by `RWM-021, 022, 023` (IDs `RWM-001`–`023`, 3 retired slots, **20 active RWM**, 150 active total).

**Dual-Human Version Verification:** Two reviewers blindly audited all 80 shuffled real-world packages (`BLIND-001`–`080`) without seeing M1–M4 outputs or RWB/RWM IDs, checking Extension ID, version, SHA-256, CWS status, and public reports (Socket, Koi Security, Unit 42, Obsidian, Palant, THN). Agreement reached 70/80 (87.50%, $\kappa = 0.700$) across 3 classes and 68/71 (95.77%, $\kappa = 0.863$) on mutually decided items. Because $\kappa$ checks rater agreement rather than truth, version-level evidence rules (`Disagreement_Log.csv`) excluded **10 items** as `Unknown_Unverified`: 5 version-drifted RWM (`RWM-001` Cyberhaven `v25.10.5` vs `24.10.4`; `RWM-005` `v7.4.3` vs Koi `7.3.0`; `RWM-016/017/018` Socket drift), 4 grayware/unconfirmed RWM (`RWM-002/003` Palant *"no indication of malicious intent"*; `RWM-006` unverified `v11.0.35`; `RWM-009` mutual Unknown), and 1 ownership-change RWB (`RWB-033`). Three disagreed RWB items (`RWB-016` Raindrop.io, `RWB-044` Google Input Tools, `RWB-056` Awesome New Tab Page) were verified Benign via official store pages. Our **Primary Verified RW set** has **70 extensions (59B + 11M)**, with Strict Consensus (68: 56B+12M) and Provenance (80: 60B+20M) reported as extra checks.

### 3.3 Permission-based and Static Analysis

**M1** runs manifest permission rules (`MVX101–103, 110–111`, max 100); **M2** runs 19 source/Base64/binary/integrity/DNR rules (`MVX002–004, 113–115, 201–213`, excluding M1); and **M5 (Combined Static)** computes Formula C-2's static score ($S_{\text{static}}$, Eq. 1) with MVX103 deduplication and M2 confidence weights, isolating static gains from M4's dynamic terms.

### 3.4 Isolated Dynamic Behavioral Analysis

Figure 2 shows the dynamic sandbox (`lab/Dockerfile`, `src/lab-runner.js`). Fail-closed XML/DTD and token checks screen packages pre-launch (rejecting 5 RWM / 15 runs). Eligible packages run 3× (60 s timeout) in fresh Docker containers (`node:22-bookworm-slim`, Chromium `156.0.8078.108`, `--network none --read-only --cap-drop ALL --security-opt no-new-privileges`, seccomp, 1 GB RAM, 2 CPU). Scenario `credential-exfiltration.json` serves fake credentials/cookies over 8 s via CDP `Fetch.fulfillRequest` with zero real data and zero Internet access (0 `LAB_CONTAINMENT_VIOLATION` in 435 launches). Verdicts map to `confirmed_attack` (100), `suspicious_activity` (50), `no_trigger_observed` (0), and `inconclusive` (`null`).

![Fig. 2. Isolated Dynamic Behavioral Analysis Architecture](../deliverables_for_advisor/figures/fig2_dynamic_sandbox_architecture.svg)
**Fig. 2.** Isolated dynamic sandbox architecture (M3) from pre-checks through offline Docker containment to verdict mapping.

### 3.5 Hybrid Evidence Integration and Risk Scoring

M4 (`src/research/hybrid-fusion.js`, frozen `configs/fusion-config.json`, SHA-256 `b1c6e412…`) combines deduplicated $S_{M1}$ and confidence-adjusted $S_{M2}^{\text{adj}}$ ($c_{\text{high}}=1.0, c_{\text{med}}=0.7, c_{\text{low}}=0.4$) into $S_{\text{static}}$ (M5), then adds runtime evidence:
$$S_{\text{static}} = \min\!\big(100,\; \alpha \cdot S_{M1} + (1 - \alpha) \cdot S_{M2}^{\text{adj}}\big), \quad \alpha = 0.3 \quad (1)$$
$$S_{\text{hybrid}} = \min\!\Big(100,\; \max\!\big(F_{\text{TierA}},\; S_{\text{static}} + E_{\text{dyn}} + B_{\text{corr}}\big)\Big) \quad (2)$$
Here $E_{\text{dyn}}$ adds 0 (`no_trigger_observed`), +20 for extension-initiated `suspicious_activity` (`requireExtensionInitiatorForSuspicious = true`), or +35 for Tier-B `confirmed_attack` (`contentManipulation`). $B_{\text{corr}} \in [0, 20]$ adds +12 per matched category in {T02, T03, T05} and +5 for T04. $F_{\text{TierA}} = 90$ applies only when M3 confirms a Tier-A target (`credentialPassword`, `sessionCookie`, `navigationHijack`, `unauthorizedDownload`) or Tier-B with external network traffic. On `inconclusive` M3, M4 uses $S_{\text{static}}$ (`completed_with_static_fallback`). All constants ($\alpha=0.3$, +20/+35, 90, $T=40$) are design constants frozen before testing; Section 4.4 sweeps $\alpha \in \{0.1..0.9\}$ and $T \in \{20..70\}$ post-hoc.

### 3.6 Experimental Design and Evaluation Metrics

Five experiments cover **EXP01** (M1/M2/M5), **EXP02** (M1–M5), **EXP03** (*Threat Indicator Distribution Analysis*, T01–T08), **EXP04** (W1–W5 sensitivity and traits: W1 25/12/6/2/0, W2 35/12/6/2/0, W3 20/15/10/5/0, W4 10/10/10/10/0, W5 25/18/6/2/0), and **EXP05** (runtime, coverage, stability), plus an 8-part ablation. Pre-set cutoffs use M1/M2/M4/M5 $\ge 40$, M3 Alert $\ge 50$, and M3 Strict $= 100$. Results separate (1) *Method-Specific*, (2) *Common-Sample* (exact ID overlap: `69` Ctrl, `61` Verified RW, `66` Provenance RW), and (3) *End-to-End Coverage*. With one extension per unit ($n \le 150$), `recompute_all_experiments.py` computes tie-aware ROC-AUC (2,000-resample stratified bootstrap 95% CIs), PR-AUC, exact Clopper–Pearson 95% CIs, and exact two-sided McNemar tests with Holm–Bonferroni correction.

## 4 Experimental Results and Discussion

### 4.1 Experimental Environment and Dataset Eligibility

CB, CST, and RWB ran on macOS 26.6.2 (`arm64`, Node v25.1.0, Colima/Docker 29.5.2); RWM ran in an offline snapshot-reverted Ubuntu 26.04.1 LTS VM (`x86_64`, Node v22.22.1, Docker 29.10.0) using commit `ac3b584` and Chromium `156.0.8078.108`. Across 150 active packages, we logged 2,700 SHA-256-verified JSON artifacts (2,605 numeric, 30 M3 inconclusive, 65 fail-closed XML/DTD rejections on `RWM-003, 005, 006, 009, 012`) with 0 missing files and 0 containment violations (Table 3).

**Table 3.** Dataset composition, GT status, and eligibility (20 active RWM after 3 replacements, not 23; 10 RW excluded as `Unknown_Unverified`).

| Cohort / Tier | Active | Verified | Elig. M1 | Elig. M2/M5 | Elig. M3 (Det.) | Elig. M4 (fb) | Common |
|---|---:|---:|---:|---:|---:|---:|---:|
| Controlled Benign (CB) | 30 | 30 | 30 | 30 | 30 | 30 (0 fb) | 30 |
| Controlled Security Test (19 inh./21 auth.) | 40 | 40 | 40 | 40 | 39 | 40 (1 fb) | 39 |
| Real-World Benign (Ver./All RWB) | 60 | 59 (1 Unk) | 59/60 | 59/60 | 53/54 | 59/60 (6 fb) | 53/54 |
| Real-World Malicious (Ver./All RWM) | 20 | 11 (9 Unv) | 11/20 | 10/15 | 8/12 | 10/15 (2/3 fb) | 8/12 |
| **Total Verified Primary (Ctrl+Ver. RW)** | **140** | **140** | **140** | **139** | **130** | **139** | **130** |
| **Total Active Benchmark (Ctrl+All RW)** | **150** | **140 (+10)** | **150** | **145** | **135** | **145** | **135** |

### 4.2 Permission-based and Static Detection Performance (RQ1)

**EXP01 & 19-vs-21 Bias Check:** On Controlled Common-69 (Table 5), M1, M2, and M5 produce 0/30 FPs; M2 beats M1 in ranking (0.833 vs 0.782) because 12/40 CST fixtures use source-only sinks, and M5 raises ranking to 0.949 [0.897, 0.987]. At T = 40, M2 and M5 get TP = 0 while M1 gets TP = 2: single-indicator fixtures cap M2 at 31 (< 40), while `CST-002` and `CST-030` (`MVX101+102+103 = 49`) cross 40 in M1 before deduplication lowers them to 25 in M5. Splitting CST confirms ranking holds on both groups: paired with 30 CB, M5 reaches ROC-AUC 0.921 [0.842, 1.000] on the 19 inherited fixtures (M4 = 0.947) and 0.952 [0.881, 1.000] on the 21 authored fixtures (M4 = 0.952). Because CB controls omit complex UI bundles and CST fixtures follow T01–T08 (incorporation bias), controlled ROC-AUC checks indicator ranking rather than real-world malware detection.

On **Primary Verified RW** (Table 5, Method-Specific n = 69–70), M1 flags 0/11 malicious items (Recall 0.0% [0.0%, 28.5%], ROC-AUC 0.389, alert 15.3%); M2 reaches 60.0% recall (6/10) but alerts on 31/59 (52.5%) benign baselines at T = 40 and 14/59 (23.7%) at Critical $\ge 70$; M5 lowers benign alerts to 30.5% (18/59; exact McNemar vs M2: 13 vs 1 discordant pairs, raw $p = 0.001831$, Holm $p = 0.007324$) and raises F1 to 0.303 with Recall 50.0%.

**EXP03 (Threat Indicator Distribution Analysis):** Because real-world GT is per extension rather than per threat class, EXP03 reports indicator distribution across T01–T08 (Table 4; 458 unique findings, 590 primary hits, 1,079 multi-label tags). Verified RWB and RWM overlap closely in T01, T04, T03, and T06, explaining static alert noise. Dynamic matching fired only on 3 CST fixtures (`CST-030` T03, `CST-027` T04, `CST-036` T05; 0 on RWM), and T01/T06/T07/T08 stay N/A.

**Table 4.** EXP03 Threat Indicator Distribution Analysis and GT support across T01–T08 (RW category accuracy is N/A).

| Cat. | Hits | Ext. | CB (30) | CST (40) | Ver. RWB (59) | Ver. RWM (11) | All RWM (20) | Dynamic Hook & Category GT |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| T01 | 192 | 81 | 0 | 22 | 44 | 8 | 14 | Unsupported (N/A) |
| T02 | 17 | 17 | 0 | 6 | 10 | 0 | 0 | Primary; RW cat. GT N/A |
| T03 | 76 | 56 | 0 | 5 | 42 | 5 | 8 | Primary; 1 CST dyn. hit |
| T04 | 83 | 68 | 0 | 6 | 47 | 9 | 14 | Conditional; 1 CST dyn. hit |
| T05 | 25 | 21 | 0 | 7 | 10 | 3 | 4 | Primary; 1 CST dyn. hit |
| T06 | 88 | 51 | 0 | 7 | 35 | 7 | 8 | Unsupported (N/A) |
| T07 | 105 | 59 | 0 | 15 | 35 | 4 | 8 | Unsupported (N/A) |
| T08 | 4 | 4 | 0 | 1 | 3 | 0 | 0 | Unsupported (N/A) |

### 4.3 Complementary Dynamic Evidence and Hybrid Analysis (RQ2)

Table 5 and Figure 3 compare M1–M5 across Common-Sample and Method-Specific views. On Controlled-69, adding M3 lifts M4 above M5 in ranking (0.962 vs 0.949) and recall (4/39 vs 0/39, FPR 0%), catching hidden fixture `CST-019` (M1 = M2 = 0, M3 = 100, M4 = 90.0), while 35/39 fixtures remain below 40.

On **Verified RW Common-61 (53B + 8M)**, M3 Alert Mode ($\ge 50$) leads (ROC-AUC 0.790, Recall 75.0%, F1 0.522, alert 17.0%), beating M2 (exact McNemar: 25 vs 4 pairs, raw $p = 0.000104$, Holm $p = 0.000519$), yet Strict Mode (M3 = 100) logs **0/8 confirmed attacks** (all real-world M3 alerts are `suspicious_activity` triage signals). For **End-to-End Coverage**, across all **11 Verified RWM** inputs M3 records 6 `suspicious_activity`, 2 `no_trigger_observed`, 2 `inconclusive`, 1 XML rejection (`RWM-012`), and 0 `confirmed_attack`: determinate recall is **75.0% (6/8)**, end-to-end alert rate is **54.5% (6/11)**, unresolved rate is **27.3% (3/11)**, and confirmed rate is **0.0% (0/8)**; across all **20 Provenance RWM** inputs, these rates are **66.7% (8/12)**, **40.0% (8/20)**, **40.0% (8/20)**, and **0.0% (0/12)**.

On both Verified RW Method-Specific (n = 69) and Common-61, **M4 and M5 are identical** (0 vs 0 pairs, $p = 1.000$), cutting alerts vs M2 (Holm $p = 0.0073$) while trailing M3 (7 vs 16 pairs, raw $p = 0.0931$, Holm $p = 0.1863$; full discordant Sample IDs in `independent_recomputation_full.json`). The consensus-subset (n = 58) and provenance (n = 66: M3 ROC-AUC 0.750, F1 0.552; M4/M5 0.408, F1 0.258) checks preserve the main comparative trends, while several performance metrics change after excluding uncertain and version-drifted artifacts.

**Table 5.** EXP02 comparison (W1; M1/M2/M4/M5 $\ge 40$, M3 $\ge 50$, M3-S = 100) across Controlled Common-69, Primary Verified RW Common-61, and Primary Verified RW Method-Specific (n = 69).

| Evaluation Set | Method | N (Cov.) | TP | FP | TN | FN | Prec. | Rec. (95% CI) | F1 | Alert/FPR | ROC-AUC (95% CI) | PR-AUC |
|---|---|---:|---:|---:|---:|---:|---:|---|---:|---:|---|---:|
| **Controlled** | M1 | 69 (100%) | 2 | 0 | 30 | 37 | 1.000 | 0.051 [0.6–17.3%] | 0.098 | 0.000 | 0.782 [0.705–0.859] | 0.810 |
| **Common-Sample** | M2 | 69 (100%) | 0 | 0 | 30 | 39 | – | 0.000 [0.0–9.0%] | 0.000 | 0.000 | 0.833 [0.756–0.897] | 0.855 |
| (30 CB + 39 CST) | M5 | 69 (100%) | 0 | 0 | 30 | 39 | – | 0.000 [0.0–9.0%] | 0.000 | 0.000 | 0.949 [0.897–0.987] | 0.955 |
| | M3 | 69 (100%) | 5 | 0 | 30 | 34 | 1.000 | 0.128 [4.3–27.4%] | 0.227 | 0.000 | 0.564 [0.513–0.615] | 0.621 |
| | **M4** | **69 (100%)** | **4** | **0** | **30** | **35** | **1.000** | **0.103 [2.9–24.2%]** | **0.186** | **0.000** | **0.962 [0.910–1.000]** | **0.967** |
| **PRIMARY Ver. RW** | M1 | 61 (100%) | 0 | 8 | 45 | 8 | 0.000 | 0.000 [0.0–36.9%] | 0.000 | 0.151 | 0.367 [0.205–0.546] | 0.110 |
| **Common-Sample** | M2 | 61 (100%) | 4 | 28 | 25 | 4 | 0.125 | 0.500 [15.7–84.3%] | 0.200 | 0.528 | 0.496 [0.236–0.752] | 0.171 |
| (53B + 8M Exact) | M5 | 61 (100%) | 3 | 15 | 38 | 5 | 0.167 | 0.375 [8.5–75.5%] | 0.231 | 0.283 | 0.459 [0.208–0.723] | 0.166 |
| | **M3** | **61 (87.1%)** | **6** | **9** | **44** | **2** | **0.400** | **0.750 [34.9–96.8%]** | **0.522** | **0.170** | **0.790 [0.612–0.934]** | **0.333** |
| | M3-S | 61 (87.1%) | 0 | 0 | 53 | 8 | – | 0.000 [0.0–36.9%] | 0.000 | 0.000 | 0.790 [0.612–0.934] | 0.333 |
| | M4 | 61 (100%) | 3 | 15 | 38 | 5 | 0.167 | 0.375 [8.5–75.5%] | 0.231 | 0.283 | 0.459 [0.208–0.723] | 0.166 |
| **Ver. RW Method-** | M2 | 69 (98.6%) | 6 | 31 | 28 | 4 | 0.162 | 0.600 [26.2–87.8%] | 0.255 | 0.525 | 0.556 [0.330–0.773] | 0.209 |
| **Specific (59B+11M)** | M5/M4 | 69 (98.6%) | 5 | 18 | 41 | 5 | 0.217 | 0.500 [18.7–81.3%] | 0.303 | 0.305 | 0.521 [0.295–0.742] | 0.222 |

![Fig. 3. Common-Sample Comparative Performance Across M1–M5](../deliverables_for_advisor/figures/fig3_common_sample_m1_m5.svg)
**Fig. 3.** Common-sample performance of M1–M5 (W1) on (a) Controlled (n = 69) and (b) Primary Verified RW (n = 61).

### 4.4 Risk Score Sensitivity and Robustness (RQ3)

**EXP04 Four-Layer Stability (W1–W5, n = 145; Fig. 4a):** (1) *Ranks* stay stable: lowest pairwise Spearman $\rho = 0.9841$ (M1), $0.9750$ (M2), and $0.9709$ (M4, W2 vs W4). (2) *Absolute scores* shift across weights: mean M4 moves from 20.25 (W1) to 22.75 (W2, MAD 2.50), 22.33 (W3, 2.36), 15.53 (W4, 4.99), and 25.07 (W5, 4.82); M2 hits 100 on 8–14/145 items (0 under W4) while M4 hits 100 on 0/145. (3) *Risk tiers* shift vs W1 on 11.0% (W2), 7.6% (W3), 24.1% (W4), and 17.9% (W5). (4) *Alerts (T = 40)* flip on 2.8% (W2/W3), 13.1% (W4), and 5.5% (W5). Stable ranks therefore do not ensure stable tiers or alert decisions.

**Structural Trait Correlations (RW n = 75):** `Total_Static_Findings` drives M4 ($\rho = 0.8737$), M2 cap hits ($\rho = 0.4422$), and M4 tier shifts ($\rho = 0.4254$). `Permission_Count` tracks M1 ($\rho = 0.7248$) and M4 ($\rho = 0.5619$); `JS_File_Count` ($\rho = 0.4479$) and `Package_Bytes` ($\rho = 0.3143$) track M4 moderately, while `Host_Permission_Count` tracks M1 ($\rho = 0.3340$) but not M4 ($\rho = 0.0469$). `Utility_Accessibility_Shopping` (n = 32, M4 = 36.32) and `Security_Privacy_Auth` (n = 9, M4 = 32.43) score highest, while `Game_Entertainment` (n = 5, 16.4 MB, M4 = 9.24) scores lowest.

**Post-hoc Formula C-2 Sweep (Table 6, Fig. 4b):** On Verified RW (n = 69, T = 40), frozen $\alpha = 0.3$ gives the top F1 (0.303); $\alpha = 0.1$ raises alerts to 39.0%, while $\alpha \ge 0.5$ drops recall to 30.0% and 0.0% ($\alpha \ge 0.7$). Sweeping $T$ at $\alpha = 0.3$ shows a steep trade-off: $T = 20$ (Rec. 60%, Alert 76.3%), $T = 30$ (60%, 45.8%, F1 0.279), $T = 40$ (50%, 30.5%, F1 0.303), $T = 50$ (30%, 13.6%, F1 0.286), and $T = 70$ (0%, 1.7%).

**Table 6.** Post-hoc Formula C-2 $\alpha$-sensitivity on Verified RW (n = 69, T = 40) and Controlled (n = 70, T = 40).

| Weight $\alpha$ | Ver. RW TP | Ver. RW FP | Ver. RW Rec. | Ver. RW F1 | Ver. RW Alert | Ver. RW ROC | Ctrl TP | Ctrl ROC |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 0.1 | 5 | 23 | 0.500 | 0.263 | 0.390 | 0.533 | 4 | 0.950 |
| **0.3 (Frozen)** | **5** | **18** | **0.500** | **0.303** | **0.305** | **0.521** | **4** | **0.950** |
| 0.5 | 3 | 17 | 0.300 | 0.200 | 0.288 | 0.486 | 4 | 0.950 |
| 0.7 | 0 | 9 | 0.000 | 0.000 | 0.153 | 0.453 | 4 | 0.950 |
| 0.9 | 0 | 8 | 0.000 | 0.000 | 0.136 | 0.387 | 4 | 0.950 |

![Fig. 4. EXP04 Spearman Heatmap and Post-hoc Alpha Sensitivity](../deliverables_for_advisor/figures/fig4_heatmap_and_alpha_sensitivity.svg)
**Fig. 4.** (a) M4 Spearman rank heatmap across W1–W5 (n = 145) and (b) post-hoc $\alpha$-sensitivity on Verified RW (n = 69, T = 40).

### 4.5 Computational Efficiency, Coverage and Stability (RQ4)

Table 7 reports timing, failures, coverage, and stability. Static screening (M1+M2, n = 145) averages **234.35 ms** (median **13.04 ms**), and M4 fusion adds **0.33 ms**. Actual Docker M3 launches (n = 435, excluding 15 pre-launch rejections) average **10,784.43 ms**, giving **11.02 s** end-to-end M4 (1× M3, **47.0×** Static; **32.59 s** for 3× repeats). Separating actual launches fixes a prior reporting error: the 45 real RWM Docker runs on Ubuntu VM averaged **12,166.51 ms** (P95 12,792.10 ms), slower than RWB on macOS (`10,886.01 ms`), while mixing in 15 fast rejections pulled RWM down to 9.6 s. Cross-cohort times stay descriptive due to host differences. Across 435 runs, timeout rate was **0.0%**, XML rejection was **3.3%** (5/150), determinate coverage was **93.1%** of launched packages (135/145; 90.0% of 150), and 3-repeat verdict consistency was **100%** (145/145, 0 flips), checking repeatability rather than accuracy.

**Table 7.** EXP05 runtime (completed runs, ms), failure/timeout rates, coverage, and 3-repeat stability.

| Stage / Cohort | N Runs | Mean (ms) | Median (ms) | Std (ms) | P95 (ms) | Fail / TO | Coverage / Stability |
|---|---:|---:|---:|---:|---:|---|---|
| M1 / M2 (Completed) | 150/145 | 25.0 / 214.5 | 3.3 / 9.9 | 48.9 / 342.3 | 150 / 888 | 0% / 3.3% | 100% / 96.7% |
| Static Screen (M1 + M2) | 145 | 234.35 | 13.04 | 368.39 | 989.86 | 3.3% / 0% TO | 96.7% (145/150) |
| M4 Fusion Logic Only | 145 | 0.33 | 0.20 | 0.47 | 0.76 | 3.3% / 0% TO | 96.7% (145/150) |
| M3: CB / CST (macOS) | 90/120 | 10,406 / 10,398 | 10,406 / 10,394 | 50 / 40 | 10,480 / 10,456 | 0% / 0% TO | 100% / 97.5% det. |
| M3: RWB (macOS) | 180 | 10,886.01 | 10,813.00 | 323.48 | 11,446.15 | 0% / 0% TO | 90.0% det. / 100% 3/3 |
| M3: RWM (Ubuntu VM) | 45 | 12,166.51 | 12,075.99 | 809.61 | 12,792.10 | 25% / 0% TO | 60.0% det. / 100% 3/3 |
| **M3 All Launched (435)** | **435** | **10,784.43** | **10,505.40** | **619.64** | **12,076.23** | **3.3% / 0% TO** | **93.1% (135/145) / 100%** |
| **End-to-End M4 (1× M3)** | **145** | **11,019.11** | **10,531.84** | **953.49** | **13,001.93** | **3.3% / 0% TO** | **47.0× Static Screen** |

### 4.6 Ablation Study, Case Studies and Error Analysis

**Eight-Component M4 Breakdown (Table 8):** On **Controlled (n = 70)**, M5 raises ROC-AUC to 0.938; Dynamic Elevation adds `CST-027` (5.88 to 45.88); Corroboration Bonus fires on 3 fixtures; and Tier-A Floor lifts `CST-019, 030, 036` to 90.0 (TP = 4, ROC-AUC = 0.950). On **Primary Verified RW (n = 69)**, M2 Confidence Adjustment shifts 63 items ($\Delta = -11.22$, benign alerts 31 to 24) and M5 Static Aggregation ($\alpha = 0.3$) shifts 67 items ($\Delta = -6.13$, benign alerts 24 to 18, F1 0.303). After that, **Dynamic Elevation, Corroboration Bonus, and Tier-A Floor each affect 0/69 items ($\Delta = 0.00$)** because CDP reported `unknown` initiators on all 18 `suspicious_activity` runs. So the hybrid framework reduces real-world baseline alerts primarily through static score aggregation, while dynamic evidence stays limited by runtime attribution. Turning off the guard post-hoc keeps Controlled at 0.950 and lifts provenance M4 ROC-AUC (0.439 to 0.598) and Recall (40% to 60%), but raises RWB alerts (30.0% to 38.3%) and Critical alerts (1/60 to 5/60); fixing CDP attribution is safer.

**Table 8.** Eight-component incremental breakdown of Formula C-2 (W1, T = 40) on Controlled (n = 70) and Primary Verified RW (n = 69).

| Component Stage | Ctrl Aff. | Ctrl Mean | Ctrl TP/FP | Ctrl ROC | Ver. RW Aff. | Ver. RW Mean ($\Delta$) | Ver. RW TP/FP | Ver. RW F1 / Alert |
|---|---:|---:|---|---:|---:|---:|---|---|
| 1. M1 Permission-Only | 22 | 4.50 | 2 / 0 | 0.775 | 51 | 19.96 (–) | 0 / 9 | 0.000 / 15.3% |
| 2. M1 Deduplicated | 2 | 3.81 | 0 / 0 | 0.775 | 7 | 17.52 (-2.43) | 0 / 7 | 0.000 / 11.9% |
| 3. M2 Static Source Raw | 26 | 5.20 | 0 / 0 | 0.825 | 65 | 49.16 (–) | 6 / 31 | 0.255 / 52.5% |
| 4. M2 Confidence Adjusted | 7 | 4.70 | 0 / 0 | 0.825 | 63 | 37.94 (-11.22) | 5 / 24 | 0.256 / 40.7% |
| 5. M5 Static Agg. ($\alpha=0.3$) | 30 | 4.44 | 0 / 0 | 0.938 | 67 | 31.82 (-6.13) | 5 / 18 | 0.303 / 30.5% |
| 6. + Dynamic Elevation | 1 | 4.94 | 1 / 0 | 0.938 | **0** | 31.82 (0.00) | 5 / 18 | 0.303 / 30.5% |
| 7. + Corroboration Bonus | 3 | 5.35 | 1 / 0 | 0.938 | **0** | 31.82 (0.00) | 5 / 18 | 0.303 / 30.5% |
| 8. M4 Full (+ Tier-A Floor) | 3 | 8.61 | 4 / 0 | 0.950 | **0** | 31.82 (0.00) | 5 / 18 | 0.303 / 30.5% |

**Error Analysis & Case Studies (Table 9):** False positives come from large benign UI bundles (`RWB-003` M2 = 100, `RWB-023` M2 = 99), lowered below 70 by M5/M4. False negatives come from scenario mismatch (2/8 verified RWM missed `credential-exfiltration.json`), missing CDP initiators, and XML/DTD rejections (5/20 RWM). `RWM-001` (Cyberhaven `v25.10.5`, `6dba3420…`) came after the Dec 2024 `v24.10.4` breach and lacked a CDP initiator, so we excluded it from Primary Verified metrics. *(An extension named "Good Tab" discussed early on is not in commit `b346c09` and is omitted.)*

**Table 9.** Verified case studies showing tie splitting, version drift, attribution gaps, and MV3 limits (W1).

| Pattern | Sample ID | Pkg SHA-256 | M1 | M2 | M5 | M3 Verdict | M4 (Tier) | Lesson |
|---|---|---|---:|---:|---:|---|---|---|
| Tie Split | CST-002 / 030 | `3ae58ac8…`/`18ba936d…` | 49/49 | 12/12 | 15.9/15.9 | no_trg/conf | 15.9(L)/90(C) | Canary+Floor splits tie |
| Hidden Attack | CST-019 | `24b1e65e…` | 0 | 0 | 0.0 | conf (100) | 90.0 (Crit.) | M3 catches static-blind |
| Tier-B Only | CST-027 | `689b1845…` | 0 | 12 | 5.88 | conf (100) | 45.88 (High) | Tier-B w/o 90 floor |
| UI Static FP | RWB-003 / 023 | `b0f5ef43…`/`8f9c7851…` | 18/49 | 100/99 | 66.2/58.7 | no_trg (0) | 66.2/58.7 (H) | M5/M4 drop M2 < 70 |
| Drift & Attr. | RWM-001 / 013 | `6dba3420…`/`aec3c4e2…` | 79/0 | 49/12 | 48.3/5.9 | susp (50) | 48.3(H)/5.9(L) | Drifted; CDP muted |
| SW & XML | RWB-059 / RWM-012 | `48b24289…`/`f9f125b3…` | 36/18 | 100/fail | 80.8/fail | inc. / fail | 80.8(fb)/fail | SW fallback; XML cap |

### 4.7 Discussion, Practical Implications and Threats to Validity

**Practical Implications:** Teams managing company browsers can use a two-step review: Step 1 runs M5 screening (mean 0.23 s, median 13 ms) at intake and updates, cutting M2 alerts by 41.9% on verified baselines; Step 2 runs isolated M3 (~10.8 s) on high-risk items, sending `suspicious_activity`, `inconclusive`, and XML-rejected packages to manual review instead of auto-blocking.

**Threats to Validity:** (1) *Internal:* 5 RWM (`RWM-001, 005, 016–018`) had version drift and 5 items (`RWM-002, 003, 006, 009`, `RWB-033`) lacked version confirmation (excluded from primary binary metrics); clean `30 CB` controls and taxonomy-aligned CST fixtures introduce incorporation bias; runtimes mix macOS (`arm64`) and Ubuntu (`x86_64`) without cross-host calibration; and CDP `unknown` initiators muted M4 dynamic terms on real-world runs. (2) *External:* Results cover 150 Chrome MV3 packages within parser limits ($\le 1\text{M}$ tokens, $\le 50\text{ MB}$) under one 8 s scenario and may not generalize to search hijackers, adware, or Firefox/Safari. (3) *Construct:* Scores (0–100) are heuristic rankings, not malware probabilities; CST positives are indicators; `suspicious_activity` is not confirmed malware; `no_trigger_observed` never proves safety; and RWB alerts are baseline alert rates, not proven FPR. (4) *Conclusion:* Verified common-sample tests use 61 packages (53B + 8M), giving wide 95% CIs (M3 recall [34.9%, 96.8%]); post-hoc $\alpha$/threshold/guard sweeps are extra diagnostic checks.

## 5 Conclusion and Future Work

We evaluated five MV3 analysis setups (M1–M5) across 150 extensions (2,700 artifacts, 435 Docker runs, 0 containment violations) using version-verified dual-human GT (70 verified RW; 61 common-sample) and 70 controlled fixtures. For **RQ1**, M5 raises controlled ranking to 0.949 (vs M1 0.782, M2 0.833) despite 0% recall at T = 40 (`max M2 = 31`); on verified RW, M1 misses all malicious items (0/11), M2 alerts on 52.5% of benign baselines, and M5 cuts alerts to 30.5% (Holm $p = 0.0073$). For **RQ2**, M3 alert mode gives the best real-world triage separation on common samples (ROC-AUC 0.790, Recall 75.0%, F1 0.522, alert 17.0%) but logs 0/8 strict confirmed attacks and leaves 27.3% of verified RWM (40.0% of all 20 RWM) unresolved. Eight-part ablation confirms that the hybrid framework reduces real-world baseline alerts primarily through static score aggregation (identical to M5), while dynamic evidence stays limited by missing CDP initiators. For **RQ3**, W1–W5 keep ranks stable ($\rho \ge 0.971$) while shifting up to 24.1% of M4 risk tiers, driven by static finding counts ($\rho = 0.874$). For **RQ4**, static screening averages 0.23 s vs 11.02 s for end-to-end M4 (47.0×), with 0% timeouts and 100% 3-repeat consistency. Future work should fix offline CDP initiator tracking, add more dynamic scenarios, add complex benign controls and cross-host calibration, pin malware by compromised CRX version hash, and support streaming XML/AST parsing.

**Artifact Availability.** Code, `configs/fusion-config.json`, 70 controlled fixtures, `Dataset_Inventory.xlsx`, `Ground_Truth_Verified.xlsx`, `Literature_Review.xlsx`, and `recompute_all_experiments.py` are at `https://github.com/congbao2006/mv3-hybrid-security-analysis` (commit `ac3b584`). No malware binaries are shared.

## References

[1] Barth, A., Felt, A.P., Saxena, P., Boodman, A.: Protecting browsers from extension vulnerabilities. In: Proc. NDSS (2010)

[2] Carlini, N., Felt, A.P., Wagner, D.: An evaluation of the Google Chrome extension security architecture. In: Proc. USENIX Security, pp. 97–111 (2012)

[3] Kapravelos, A., et al.: Hulk: Eliciting malicious behavior in browser extensions. In: Proc. USENIX Security, pp. 641–654 (2014)

[4] Jagpal, N., et al.: Trends and lessons from three years fighting malicious extensions. In: Proc. USENIX Security, pp. 579–593 (2015)

[5] Chang, W., et al.: ExtensionGuard: Towards runtime browser extension information leakage detection. In: Proc. IEEE CNS (2016). doi:10.1109/CNS.2016.7860481

[6] Weissbacher, M., et al.: Ex-Ray: Detection of history-leaking browser extensions. In: Proc. ACSAC, pp. 130–144 (2017). doi:10.1145/3134600.3134632

[7] Chen, Q., Kapravelos, A.: Mystique: Uncovering information leakage from browser extensions. In: Proc. ACM CCS, pp. 1687–1700 (2018). doi:10.1145/3243734.3243823

[8] Somé, D.F.: EmPoWeb: Empowering web applications with browser extensions. In: Proc. IEEE S&P, pp. 227–245 (2019). doi:10.1109/SP.2019.00015

[9] Starov, O., Nikiforakis, N.: Unnecessarily identifiable: Quantifying extension fingerprintability due to bloat. In: Proc. WWW, pp. 3244–3250 (2019). doi:10.1145/3308558.3313685

[10] Karami, S., et al.: Carnus: Exploring the privacy threats of browser extension fingerprinting. In: Proc. NDSS (2020). doi:10.14722/ndss.2020.24383

[11] Pantelaios, N., Nikiforakis, N., Kapravelos, A.: You've changed: Detecting malicious browser extensions through update deltas. In: Proc. ACM CCS, pp. 477–491 (2020). doi:10.1145/3372297.3423343

[12] Xie, M., et al.: JTaint: Finding privacy-leakage in Chrome extensions. In: ACISP 2020, LNCS, pp. 566–585. Springer (2020). doi:10.1007/978-3-030-55304-3_29

[13] Fass, A., Somé, D.F., Backes, M., Stock, B.: DoubleX: Statically detecting vulnerable data flows in browser extensions. In: Proc. ACM CCS, pp. 1789–1804 (2021). doi:10.1145/3460120.3484745

[14] Solomos, K., et al.: Escaping the confines of time: Continuous extension fingerprinting via ephemeral modifications. In: Proc. ACM CCS, pp. 2691–2705 (2022). doi:10.1145/3548606.3560576

[15] Yu, J., Li, S., Zhu, J., Cao, Y.: CoCo: Efficient browser extension vulnerability detection via concurrent abstract interpretation. In: Proc. ACM CCS (2023). doi:10.1145/3576915.3623145

[16] Hsu, S., Tran, M., Fass, A.: What is in the Chrome Web Store? Investigating security-noteworthy browser extensions. In: Proc. ACM AsiaCCS (2024). doi:10.1145/3634737.3637636

[17] Nayak, A., et al.: Experimental security analysis of sensitive data access by browser extensions. In: Proc. ACM WWW (2024). doi:10.1145/3589334.3645683

[18] Pantelaios, N., Kapravelos, A.: Manifest V3 unveiled: Navigating the new era of browser extensions. In: Proc. MADWeb (2024). doi:10.14722/madweb.2024.23080

[19] Agarwal, S., et al.: 'I have no idea how to make it safer': Security and privacy mindsets of extension developers. In: Proc. USENIX Security (2025)

[20] Polčák, L., et al.: Developers' insight on Manifest v3 privacy and security WebExtensions. In: Proc. WEBIST (2025). doi:10.5220/0013669000003985

[21] Rosenzweig, B., Dalla Valle, V., Apruzzese, G., Fass, A.: It's not easy: Supervised machine learning for malicious CWS extensions. ACM TWEB (2026). doi:10.1145/3770852

[22] Chrome for Developers: Welcome to Manifest V3 & Migrate to Manifest V3. https://developer.chrome.com/docs/extensions/develop/migrate/what-is-mv3 (2024)

[23] Jia, H.: mvx-audit v3.1.0: Reproducible security auditing for Chrome extensions. https://github.com/hyj28/mvx-audit (2026)

[24] Fiori, G.: MaliciousBrowserExtensions (commit b346c095f8e33b9875da2bbede3854855b984bae). https://github.com/GherardoFiori/MaliciousBrowserExtensions (2026)
