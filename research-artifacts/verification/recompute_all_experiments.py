#!/usr/bin/env python3
"""
Phase 2: Independent Python 3 stdlib recomputation of ALL metrics, tables,
common-sample evaluations, 19-vs-21 controlled split, 8-component M4 breakdown,
EXP03 GT-support distribution, EXP04 6-feature correlations & 5x5 Spearman matrices,
Formula C-2 alpha/threshold post-hoc sensitivity, EXP05 full latency distributions,
and exact statistical tests (Clopper-Pearson 95% CI, Bootstrap ROC-AUC 95% CI,
Exact McNemar + Holm-Bonferroni + Discordant Pairs).
"""
import csv
import json
import math
import os
import random
import statistics
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
ARTIFACTS_ROOT = os.path.abspath(os.path.join(HERE, ".."))
OUT = HERE
GT_DIR = os.path.join(ARTIFACTS_ROOT, "ground-truth")
RES_DIR = os.path.join(ARTIFACTS_ROOT, "results")

with open(os.path.join(GT_DIR, "verified_gt_and_meta.json"), encoding="utf-8") as f:
    vmeta = json.load(f)
pkg_meta = vmeta["pkg_meta"]
gt_ver = vmeta["gt_verified"]

with open(f"{RES_DIR}/unified_runs_150.json") as f:
    uni = json.load(f)

with open(f"{RES_DIR}/results_per_extension.csv", encoding="utf-8-sig") as f:
    ext_rows = list(csv.DictReader(f))

with open(f"{RES_DIR}/results_per_finding.csv", encoding="utf-8-sig") as f:
    finding_rows = list(csv.DictReader(f))


# ---------- Exact Statistical Primitives (Pure Python 3 stdlib) ----------
def tie_aware_roc_auc(y_true, y_score):
    pos = [s for y, s in zip(y_true, y_score) if y == 1]
    neg = [s for y, s in zip(y_true, y_score) if y == 0]
    if not pos or not neg:
        return None
    wins = 0.0
    for p in pos:
        for n in neg:
            if p > n:
                wins += 1.0
            elif p == n:
                wins += 0.5
    return wins / (len(pos) * len(neg))


def average_precision_tie_aware(y_true, y_score):
    """Exact tie-aware Average Precision (matches scikit-learn step integration)."""
    total_pos = sum(y_true)
    if total_pos == 0:
        return None
    # Group by unique descending scores
    groups = defaultdict(lambda: [0, 0])  # score -> [pos, total]
    for y, s in zip(y_true, y_score):
        groups[s][0] += y
        groups[s][1] += 1
    tp = 0
    seen = 0
    ap = 0.0
    prev_rec = 0.0
    for s in sorted(groups.keys(), reverse=True):
        p_g, n_g = groups[s]
        tp += p_g
        seen += n_g
        rec = tp / total_pos
        prec = tp / seen
        ap += (rec - prev_rec) * prec
        prev_rec = rec
    return ap


def clopper_pearson_ci(k, n, alpha=0.05):
    """Exact Clopper-Pearson binomial CI via bisection on exact cumulative binomial."""
    if n == 0:
        return (None, None)

    def binom_tail_upper(p, k_min):
        # P(X >= k_min | n, p)
        if p <= 0.0:
            return 0.0 if k_min > 0 else 1.0
        if p >= 1.0:
            return 1.0
        s = 0.0
        for i in range(k_min, n + 1):
            s += math.comb(n, i) * (p ** i) * ((1.0 - p) ** (n - i))
        return s

    def binom_tail_lower(p, k_max):
        # P(X <= k_max | n, p)
        if p <= 0.0:
            return 1.0
        if p >= 1.0:
            return 1.0 if k_max == n else 0.0
        s = 0.0
        for i in range(0, k_max + 1):
            s += math.comb(n, i) * (p ** i) * ((1.0 - p) ** (n - i))
        return s

    if k == 0:
        lo = 0.0
    else:
        l, r = 0.0, 1.0
        for _ in range(60):
            mid = (l + r) / 2
            if binom_tail_upper(mid, k) < alpha / 2:
                l = mid
            else:
                r = mid
        lo = (l + r) / 2

    if k == n:
        hi = 1.0
    else:
        l, r = 0.0, 1.0
        for _ in range(60):
            mid = (l + r) / 2
            if binom_tail_lower(mid, k) < alpha / 2:
                r = mid
            else:
                l = mid
        hi = (l + r) / 2
    return (lo, hi)


def bootstrap_roc_auc_ci(y_true, y_score, n_boot=2000, seed=20261127):
    rng = random.Random(seed)
    pos_s = [s for y, s in zip(y_true, y_score) if y == 1]
    neg_s = [s for y, s in zip(y_true, y_score) if y == 0]
    if len(pos_s) < 2 or len(neg_s) < 2:
        return (None, None)
    aucs = []
    np_, nn_ = len(pos_s), len(neg_s)
    for _ in range(n_boot):
        sp = [pos_s[rng.randrange(np_)] for _ in range(np_)]
        sn = [neg_s[rng.randrange(nn_)] for _ in range(nn_)]
        wins = 0.0
        for p in sp:
            for n in sn:
                if p > n:
                    wins += 1.0
                elif p == n:
                    wins += 0.5
        aucs.append(wins / (np_ * nn_))
    aucs.sort()
    return (aucs[int(0.025 * n_boot)], aucs[int(0.975 * n_boot)])


def exact_mcnemar_p(b, c):
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    p = 2.0 * sum(math.comb(n, i) for i in range(k + 1)) / (2 ** n)
    return min(1.0, p)


def holm_bonferroni(pvals):
    """pvals: list of (key, p) -> dict key -> p_adj"""
    m = len(pvals)
    order = sorted(pvals, key=lambda x: x[1])
    adj = {}
    running_max = 0.0
    for idx, (k, p) in enumerate(order):
        val = min(1.0, p * (m - idx))
        running_max = max(running_max, val)
        adj[k] = running_max
    return adj


def avg_ranks(vals):
    indexed = sorted(enumerate(vals), key=lambda x: x[1])
    ranks = [0.0] * len(vals)
    i = 0
    while i < len(vals):
        j = i
        while j + 1 < len(vals) and indexed[j + 1][1] == indexed[i][1]:
            j += 1
        avg_r = (i + j) / 2.0 + 1.0
        for k in range(i, j + 1):
            ranks[indexed[k][0]] = avg_r
        i = j + 1
    return ranks


def spearman_rho(x, y):
    if len(x) < 3:
        return None
    rx, ry = avg_ranks(x), avg_ranks(y)
    mx, my = sum(rx) / len(rx), sum(ry) / len(ry)
    num = sum((a - mx) * (b - my) for a, b in zip(rx, ry))
    dx = math.sqrt(sum((a - mx) ** 2 for a in rx))
    dy = math.sqrt(sum((b - my) ** 2 for b in ry))
    if dx == 0 or dy == 0:
        return None
    return num / (dx * dy)


def percentile(vals, q):
    if not vals:
        return None
    s = sorted(vals)
    k = (len(s) - 1) * q
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return s[int(k)]
    return s[f] + (k - f) * (s[c] - s[f])


# ---------- Parse All W1-W5 Scores & Raw M4 Component Breakdowns ----------
by_wp_sid = defaultdict(dict)
for r in ext_rows:
    by_wp_sid[r["Weight_Profile"]][r["Sample_ID"]] = r

# Load exact componentScores from raw M4 W1 JSON artifacts for every numeric M4 extension
m4_comp_w1 = {}
for sid, r in by_wp_sid["W1"].items():
    p = r.get("M4_Raw_Artifact", "")
    if p and os.path.exists(p):
        j = json.load(open(p))
        if j.get("status") != "failed":
            m4_comp_w1[sid] = {
                "m1_dedup": float((j.get("componentScores") or {}).get("m1DeduplicatedScore", 0) or 0),
                "m2_conf_adj": float((j.get("componentScores") or {}).get("m2ConfidenceAdjustedScore", 0) or 0),
                "static_score": float((j.get("componentScores") or {}).get("staticScore", 0) or 0),
                "dyn_elev": float((j.get("componentScores") or {}).get("dynamicElevation", 0) or 0),
                "corr_bonus": float((j.get("componentScores") or {}).get("corroborationBonus", 0) or 0),
                "tierA_floor": float((j.get("componentScores") or {}).get("tierAFloor", 0) or 0),
                "tierA_applied": bool((j.get("componentScores") or {}).get("tierAFloorApplied", False)),
                "m1_dedup_removed": int((j.get("deduplication") or {}).get("m1DuplicatesRemoved", 0) or 0),
                "m2_dedup_removed": int((j.get("deduplication") or {}).get("m2DuplicatesRemoved", 0) or 0),
                "unattrib_skipped": int((j.get("deduplication") or {}).get("unattributedSuspiciousSkipped", 0) or 0),
            }

# Export full per-extension score & verdict table (Point 12: independent verification dataset)
exp_ext_path = os.path.join(OUT, "extension_scores_and_verdicts_150.csv")
exp_cols = [
    "Sample_ID", "Cohort", "CST_Origin", "Extension_Category", "Extension_Name", "Version",
    "Provenance_Label", "Primary_Verified_Label", "Include_In_Primary_Binary", "Strict_Consensus_68",
    "Package_Bytes", "JS_File_Count", "Permission_Count", "Host_Permission_Count", "Total_Static_Findings",
    "M1_W1", "M1_Dedup_W1", "M2_W1", "M2_ConfAdj_W1", "M5_CombinedStatic_W1",
    "M3_Verdict", "M3_Score", "M4_W1", "M4_DynElev", "M4_CorrBonus", "M4_TierA_Applied", "M4_Status",
    "M4_W2", "M4_W3", "M4_W4", "M4_W5"
]
with open(exp_ext_path, "w", newline="", encoding="utf-8-sig") as f:
    w = csv.writer(f)
    w.writerow(exp_cols)
    for sid in sorted(by_wp_sid["W1"].keys()):
        r1 = by_wp_sid["W1"][sid]
        pm = pkg_meta[sid]
        gv = gt_ver[sid]
        mc = m4_comp_w1.get(sid, {})
        w.writerow([
            sid, gv["cohort"], pm["CST_Origin"], pm["Extension_Category"], r1["Extension_Name"], gv["version"],
            gv["provenance_label"], gv["primary_verified_label"], "Yes" if gv["include_primary"] else "No",
            "Yes" if gv["strict_consensus_68"] else "No",
            pm["Package_Bytes"], pm["JS_File_Count"], pm["Permission_Count"], pm["Host_Permission_Count"], pm["Total_Static_Findings"],
            r1["M1_Score"], mc.get("m1_dedup", ""), r1["M2_Score"], mc.get("m2_conf_adj", ""), r1["M4_Static_Score"],
            r1["M3_Verdict"], r1["M3_Score"], r1["M4_Score"], mc.get("dyn_elev", ""), mc.get("corr_bonus", ""),
            mc.get("tierA_applied", ""), r1["M4_Status"],
            by_wp_sid["W2"][sid]["M4_Score"], by_wp_sid["W3"][sid]["M4_Score"],
            by_wp_sid["W4"][sid]["M4_Score"], by_wp_sid["W5"][sid]["M4_Score"]
        ])


# ---------- Core Evaluation Function (Supports M1, M2, M3, M3_Strict, M4, M5) ----------
def get_score(sid, method, wp="W1"):
    r = by_wp_sid[wp][sid]
    if method == "M1":
        return float(r["M1_Score"]) if r["M1_Score"] != "" else None
    if method == "M2":
        return float(r["M2_Score"]) if r["M2_Score"] != "" else None
    if method in ("M3", "M3_Strict"):
        return float(r["M3_Score"]) if r["M3_Score"] != "" else None
    if method == "M4":
        return float(r["M4_Score"]) if r["M4_Score"] != "" else None
    if method == "M5":  # Combined Static (Static-Only Fusion = S_static)
        return float(r["M4_Static_Score"]) if r["M4_Static_Score"] != "" else None
    raise ValueError(method)


def eval_subset(sample_ids, label_fn, method, thr, wp="W1", run_boot=True):
    yt, ys = [], []
    total_input = len(sample_ids)
    total_pos_in = sum(1 for s in sample_ids if label_fn(s) == 1)
    for sid in sample_ids:
        sc = get_score(sid, method, wp)
        if sc is not None:
            yt.append(label_fn(sid))
            ys.append(sc)
    tp = sum(1 for y, s in zip(yt, ys) if y == 1 and s >= thr)
    fp = sum(1 for y, s in zip(yt, ys) if y == 0 and s >= thr)
    tn = sum(1 for y, s in zip(yt, ys) if y == 0 and s < thr)
    fn = sum(1 for y, s in zip(yt, ys) if y == 1 and s < thr)
    prec = tp / (tp + fp) if (tp + fp) else None
    rec = tp / (tp + fn) if (tp + fn) else None
    f1 = (2 * prec * rec / (prec + rec)) if (prec and rec) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else None
    roc = tie_aware_roc_auc(yt, ys)
    pr = average_precision_tie_aware(yt, ys)
    rec_ci = clopper_pearson_ci(tp, tp + fn)
    fpr_ci = clopper_pearson_ci(fp, fp + tn)
    roc_ci = bootstrap_roc_auc_ci(yt, ys) if run_boot else (None, None)
    e2e_alert_pos = tp / total_pos_in if total_pos_in else None
    coverage = len(yt) / total_input if total_input else None
    return {
        "method": method, "input_n": total_input, "n": len(yt), "coverage": coverage,
        "pos": sum(yt), "neg": len(yt) - sum(yt),
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "prec": prec, "rec": rec, "rec_ci": rec_ci, "f1": f1,
        "fpr": fpr, "fpr_ci": fpr_ci, "roc": roc, "roc_ci": roc_ci, "pr": pr,
        "e2e_pos_alert_rate": e2e_alert_pos,
    }


def fmt(v, d=3):
    return "–" if v is None else f"{v:.{d}f}"


def fmt_pct(v):
    return "–" if v is None else f"{v*100:.1f}%"


def fmt_ci(ci, pct=False):
    if not ci or ci[0] is None:
        return "–"
    if pct:
        return f"[{ci[0]*100:.1f}%, {ci[1]*100:.1f}%]"
    return f"[{ci[0]:.3f}, {ci[1]:.3f}]"


# Define sample sets
ctrl_all = sorted(s for s, g in gt_ver.items() if g["cohort"].startswith("controlled_"))
ctrl_inh19 = sorted(s for s in ctrl_all if pkg_meta[s]["CST_Origin"] in ("Controlled_Benign_30", "Inherited_MVX_19"))
ctrl_auth21 = sorted(s for s in ctrl_all if pkg_meta[s]["CST_Origin"] in ("Controlled_Benign_30", "Authored_21"))

rw_ver70 = sorted(s for s, g in gt_ver.items() if g["cohort"].startswith("real_world_") and g["include_primary"])
rw_cons68 = sorted(s for s, g in gt_ver.items() if g["strict_consensus_68"])
rw_prov80 = sorted(s for s, g in gt_ver.items() if g["cohort"].startswith("real_world_"))
pooled_ver140 = ctrl_all + rw_ver70
pooled_prov150 = ctrl_all + rw_prov80

lbl_ver = lambda s: 1 if gt_ver[s]["primary_verified_label"] == "Malicious" else 0
lbl_prov = lambda s: 1 if gt_ver[s]["provenance_label"] == "Malicious" else 0

# Exact Common-Sample intersections (all of M1, M2, M3, M4, M5 numeric)
def common_ids(sids):
    return [s for s in sids if all(get_score(s, m) is not None for m in ("M1", "M2", "M3", "M4", "M5"))]

ctrl_common = common_ids(ctrl_all)        # 69
rw_ver_common = common_ids(rw_ver70)      # 61 (53B + 8M)
rw_cons_common = common_ids(rw_cons68)    # 58 (50B + 8M)
rw_prov_common = common_ids(rw_prov80)    # 66 (54B + 12M)
pool_ver_common = common_ids(pooled_ver140)
pool_prov_common = common_ids(pooled_prov150)

METHODS = [("M1", 40), ("M2", 40), ("M5", 40), ("M3", 50), ("M3_Strict", 100), ("M4", 40)]

results_json = {
    "sample_counts": {
        "ctrl_all": len(ctrl_all), "ctrl_common": len(ctrl_common),
        "ctrl_inh19_plus_30cb": len(ctrl_inh19), "ctrl_auth21_plus_30cb": len(ctrl_auth21),
        "rw_ver70": len(rw_ver70), "rw_ver_common": len(rw_ver_common),
        "rw_cons68": len(rw_cons68), "rw_cons_common": len(rw_cons_common),
        "rw_prov80": len(rw_prov80), "rw_prov_common": len(rw_prov_common),
        "pool_ver140": len(pooled_ver140), "pool_ver_common": len(pool_ver_common),
        "pool_prov150": len(pooled_prov150), "pool_prov_common": len(pool_prov_common),
    },
    "evaluations": {},
}

eval_sets = [
    ("Controlled_MethodSpecific", ctrl_all, lbl_ver),
    ("Controlled_CommonSample_69", ctrl_common, lbl_ver),
    ("Controlled_Inherited19_plus30CB", ctrl_inh19, lbl_ver),
    ("Controlled_Authored21_plus30CB", ctrl_auth21, lbl_ver),
    ("RealWorld_Verified70_PRIMARY_MethodSpecific", rw_ver70, lbl_ver),
    ("RealWorld_Verified_PRIMARY_CommonSample", rw_ver_common, lbl_ver),
    ("RealWorld_StrictConsensus68_MethodSpecific", rw_cons68, lbl_prov),
    ("RealWorld_StrictConsensus_CommonSample", rw_cons_common, lbl_prov),
    ("RealWorld_Provenance80_SUPP_MethodSpecific", rw_prov80, lbl_prov),
    ("RealWorld_Provenance_SUPP_CommonSample_66", rw_prov_common, lbl_prov),
    ("Pooled_Verified140_MethodSpecific", pooled_ver140, lbl_ver),
    ("Pooled_Verified_CommonSample", pool_ver_common, lbl_ver),
    ("Pooled_Provenance150_CommonSample_135", pool_prov_common, lbl_prov),
]

for name, sids, lfn in eval_sets:
    results_json["evaluations"][name] = [eval_subset(sids, lfn, m, t) for m, t in METHODS]


# ---------- Point 12: Exact McNemar + Holm-Bonferroni + Discordant Pairs ----------
def run_mcnemar_suite(sids, lfn, pairs_spec):
    raw = []
    details = {}
    for m_a, t_a, m_b, t_b in pairs_spec:
        a_only, b_only = [], []
        n_paired = 0
        for s in sids:
            sa, sb = get_score(s, m_a), get_score(s, m_b)
            if sa is None or sb is None:
                continue
            n_paired += 1
            y = lfn(s)
            oka = ((1 if sa >= t_a else 0) == y)
            okb = ((1 if sb >= t_b else 0) == y)
            if oka and not okb:
                a_only.append(s)
            elif okb and not oka:
                b_only.append(s)
        p = exact_mcnemar_p(len(a_only), len(b_only))
        key = f"{m_a}_vs_{m_b}"
        raw.append((key, p))
        details[key] = {
            "n_paired": n_paired, "a_right_b_wrong": len(a_only), "b_right_a_wrong": len(b_only),
            "p_raw": p, "a_only_ids": a_only, "b_only_ids": b_only
        }
    adj = holm_bonferroni(raw)
    for k in details:
        details[k]["p_holm"] = adj[k]
    return details


mc_pairs = [("M4", 40, "M2", 40), ("M4", 40, "M5", 40), ("M4", 40, "M3", 50), ("M5", 40, "M2", 40), ("M3", 50, "M2", 40)]
results_json["mcnemar"] = {
    "RealWorld_Verified70_MethodPaired": run_mcnemar_suite(rw_ver70, lbl_ver, mc_pairs),
    "RealWorld_Verified_CommonSample": run_mcnemar_suite(rw_ver_common, lbl_ver, mc_pairs),
    "RealWorld_Provenance80_MethodPaired": run_mcnemar_suite(rw_prov80, lbl_prov, mc_pairs),
    "RealWorld_Provenance_CommonSample66": run_mcnemar_suite(rw_prov_common, lbl_prov, mc_pairs),
    "Controlled_All70": run_mcnemar_suite(ctrl_all, lbl_ver, mc_pairs),
}


# ---------- Point 6: 8-Component Breakdown of M4 (Controlled vs Verified Real-World) ----------
def compute_component_breakdown(sids, lfn):
    valid = [s for s in sids if s in m4_comp_w1 and by_wp_sid["W1"][s]["M2_Score"] != ""]
    # Build score vector for each of the 8 stages
    stages = [
        ("1_M1_Permission_Only", lambda s: float(by_wp_sid["W1"][s]["M1_Score"])),
        ("2_M1_Deduplicated", lambda s: m4_comp_w1[s]["m1_dedup"]),
        ("3_M2_StaticSource_Raw", lambda s: float(by_wp_sid["W1"][s]["M2_Score"])),
        ("4_M2_Confidence_Adjusted", lambda s: m4_comp_w1[s]["m2_conf_adj"]),
        ("5_M5_Static_Aggregation_a03", lambda s: m4_comp_w1[s]["static_score"]),
        ("6_Plus_Dynamic_Elevation", lambda s: min(100.0, m4_comp_w1[s]["static_score"] + m4_comp_w1[s]["dyn_elev"])),
        ("7_Plus_Corroboration_Bonus", lambda s: min(100.0, m4_comp_w1[s]["static_score"] + m4_comp_w1[s]["dyn_elev"] + m4_comp_w1[s]["corr_bonus"])),
        ("8_M4_Full_Plus_TierA_Floor", lambda s: float(by_wp_sid["W1"][s]["M4_Score"])),
    ]
    out = []
    prev_scores = None
    for idx, (st_name, fn) in enumerate(stages):
        scores = [fn(s) for s in valid]
        yt = [lfn(s) for s in valid]
        tp = sum(1 for y, sc in zip(yt, scores) if y == 1 and sc >= 40)
        fp = sum(1 for y, sc in zip(yt, scores) if y == 0 and sc >= 40)
        tn = sum(1 for y, sc in zip(yt, scores) if y == 0 and sc < 40)
        fn_ = sum(1 for y, sc in zip(yt, scores) if y == 1 and sc < 40)
        prec = tp / (tp + fp) if (tp + fp) else None
        rec = tp / (tp + fn_) if (tp + fn_) else None
        f1 = (2 * prec * rec / (prec + rec)) if (prec and rec) else 0.0
        fpr = fp / (fp + tn) if (fp + tn) else None
        roc = tie_aware_roc_auc(yt, scores)
        # Delta vs logical predecessor
        if idx == 1:  # M1 dedup vs M1 raw
            base_sc = [float(by_wp_sid["W1"][s]["M1_Score"]) for s in valid]
        elif idx == 3:  # M2 conf adj vs M2 raw
            base_sc = [float(by_wp_sid["W1"][s]["M2_Score"]) for s in valid]
        elif idx >= 4:
            base_sc = prev_scores
        else:
            base_sc = None
        if base_sc is not None:
            diffs = [a - b for a, b in zip(scores, base_sc)]
            n_aff = sum(1 for d in diffs if abs(d) > 1e-6)
            mean_d = sum(diffs) / len(diffs)
        else:
            n_aff = sum(1 for sc in scores if sc > 0)
            mean_d = sum(scores) / len(scores)
        out.append({
            "stage": st_name, "n": len(valid), "mean_score": sum(scores) / len(scores),
            "affected_samples": n_aff, "mean_delta_vs_prev": mean_d,
            "tp": tp, "fp": fp, "rec": rec, "f1": f1, "fpr": fpr, "roc": roc
        })
        prev_scores = scores
    return out


results_json["m4_8component_breakdown"] = {
    "Controlled_70": compute_component_breakdown(ctrl_all, lbl_ver),
    "RealWorld_Verified_69": compute_component_breakdown(rw_ver70, lbl_ver),
    "RealWorld_Provenance_75": compute_component_breakdown(rw_prov80, lbl_prov),
}


# ---------- Point 7: M3 Full Operational Breakdown on RWM ----------
def m3_ops(sids):
    c = Counter()
    for s in sids:
        r = by_wp_sid["W1"][s]
        if r["M3_Status"] == "failed":
            c["parser_rejected"] += 1
        elif r["M3_Verdict"] == "inconclusive":
            c["inconclusive"] += 1
        else:
            c[r["M3_Verdict"]] += 1
    det = c["confirmed_attack"] + c["suspicious_activity"] + c["no_trigger_observed"]
    n = len(sids)
    return {
        "input_n": n, "determinate": det, "confirmed_attack": c["confirmed_attack"],
        "suspicious_activity": c["suspicious_activity"], "no_trigger_observed": c["no_trigger_observed"],
        "inconclusive": c["inconclusive"], "parser_rejected": c["parser_rejected"],
        "triage_recall_on_det": (c["confirmed_attack"] + c["suspicious_activity"]) / det if det else None,
        "e2e_alert_rate_on_input": (c["confirmed_attack"] + c["suspicious_activity"]) / n if n else None,
        "unresolvable_rate_inc_plus_rej": (c["inconclusive"] + c["parser_rejected"]) / n if n else None,
        "strict_confirmed_rate_on_det": c["confirmed_attack"] / det if det else None,
    }


results_json["m3_rwm_operational"] = {
    "RWM_All20_Provenance": m3_ops([s for s in rw_prov80 if s.startswith("RWM")]),
    "RWM_Verified11": m3_ops([s for s in rw_ver70 if s.startswith("RWM")]),
}


# ---------- Point 8: EXP03 Threat Indicator Distribution & GT Support ----------
rule_to_cats = {
    "MVX101": ["T01"], "MVX102": ["T01", "T07"], "MVX103": ["T01", "T03"],
    "MVX110": ["T01", "T05"], "MVX111": ["T01"], "MVX113": ["T05"], "MVX114": ["T05"],
    "MVX115": ["T08"], "MVX002": ["T08"], "MVX003": ["T06", "T07"], "MVX004": ["T08"],
    "MVX201": ["T06"], "MVX202": ["T06"], "MVX203": ["T04"], "MVX204": ["T04"],
    "MVX205": ["T03"], "MVX206": ["T02", "T03"], "MVX207": ["T02"], "MVX208": ["T05"],
    "MVX209": ["T02", "T03"], "MVX210": ["T06"], "MVX211": ["T04"], "MVX212": ["T02"], "MVX213": ["T06"],
}
dyn_hook_status = {
    "T01": "Unsupported (N/A)", "T02": "Primary (Canary/ExtReq)", "T03": "Primary (Credential/Cookie Canary)",
    "T04": "Conditional (DOM Manipulation)", "T05": "Primary (NavHijack/Download)",
    "T06": "Unsupported (N/A)", "T07": "Unsupported (N/A)", "T08": "Unsupported (N/A)"
}
cat_samples = defaultdict(set)
cat_assignments = Counter()
for fr in finding_rows:
    sid = fr.get("Sample_ID", "")
    rid = fr.get("Rule_ID", "")
    cats = [c.strip() for c in fr.get("Threat_Categories", "").split(";") if c.strip()] if "Threat_Categories" in fr else rule_to_cats.get(rid, [])
    for c in cats:
        cat_assignments[c] += 1
        cat_samples[c].add(sid)

exp03_rows = []
for c in [f"T0{i}" for i in range(1, 9)]:
    s_set = cat_samples[c]
    cb_n = sum(1 for s in s_set if s.startswith("CB-"))
    cst_n = sum(1 for s in s_set if s.startswith("CST-"))
    rwb_v = sum(1 for s in s_set if s in rw_ver70 and s.startswith("RWB-"))
    rwm_v = sum(1 for s in s_set if s in rw_ver70 and s.startswith("RWM-"))
    rwm_all = sum(1 for s in s_set if s.startswith("RWM-"))
    exp03_rows.append({
        "category": c, "assignments": cat_assignments[c], "unique_extensions": len(s_set),
        "cb_hits": cb_n, "cst_hits": cst_n, "rwb_ver59_hits": rwb_v, "rwm_ver11_hits": rwm_v,
        "rwm_all20_hits": rwm_all, "dynamic_hook": dyn_hook_status[c],
        "cat_level_gt_available": "Controlled fixtures only (Real-World GT is extension-level; category detection N/A)"
    })
results_json["exp03_threat_distribution"] = exp03_rows


# ---------- Point 9: EXP04 5x5 Spearman Matrices + 4 Stability Layers + 6 Extension Features ----------
WPS = ["W1", "W2", "W3", "W4", "W5"]
spearman_mats = {}
for m in ("M1", "M2", "M4"):
    sids_m = [s for s in sorted(by_wp_sid["W1"].keys()) if get_score(s, m, "W1") is not None]
    mat = {}
    for w1 in WPS:
        mat[w1] = {}
        v1 = [get_score(s, m, w1) for s in sids_m]
        for w2 in WPS:
            v2 = [get_score(s, m, w2) for s in sids_m]
            mat[w1][w2] = round(spearman_rho(v1, v2), 4)
    spearman_mats[m] = mat

# 4 Stability Layers for M4 across W1-W5 (n=145)
sids_m4 = [s for s in sorted(by_wp_sid["W1"].keys()) if get_score(s, "M4", "W1") is not None]
def tier_of(sc):
    return "Critical" if sc >= 70 else ("High" if sc >= 40 else ("Medium" if sc >= 20 else "Low"))

exp04_stability = {}
for w in WPS:
    sc_w1 = [get_score(s, "M4", "W1") for s in sids_m4]
    sc_w = [get_score(s, "M4", w) for s in sids_m4]
    mad = sum(abs(a - b) for a, b in zip(sc_w, sc_w1)) / len(sids_m4)
    tier_shifts = sum(1 for a, b in zip(sc_w, sc_w1) if tier_of(a) != tier_of(b))
    alert_flips = sum(1 for a, b in zip(sc_w, sc_w1) if (a >= 40) != (b >= 40))
    m2_sat = sum(1 for s in sids_m4 if get_score(s, "M2", w) == 100.0)
    m4_sat = sum(1 for sc in sc_w if sc == 100.0)
    exp04_stability[w] = {
        "mean_m4": sum(sc_w) / len(sc_w), "mad_vs_w1": mad,
        "spearman_vs_w1": spearman_mats["M4"]["W1"][w],
        "tier_shifts": tier_shifts, "tier_shift_pct": tier_shifts / len(sids_m4),
        "alert_flips_T40": alert_flips, "alert_flip_pct": alert_flips / len(sids_m4),
        "m2_sat_100": m2_sat, "m4_sat_100": m4_sat,
    }

# Correlations with 6 Extension Features (across all numeric Real-World n=75 and Pooled n=145)
feat_names = ["Package_Bytes", "JS_File_Count", "Permission_Count", "Host_Permission_Count", "Total_Static_Findings"]
feat_corrs = {}
for scope_name, s_list in [("All_Numeric_145", sids_m4), ("RealWorld_Numeric_75", [s for s in sids_m4 if s.startswith("RW")])]:
    feat_corrs[scope_name] = {}
    tier_changed = [1 if any(tier_of(get_score(s, "M4", w)) != tier_of(get_score(s, "M4", "W1")) for w in WPS[1:]) else 0 for s in s_list]
    m2_is_sat = [1 if get_score(s, "M2", "W1") == 100.0 else 0 for s in s_list]
    for fn in feat_names:
        fx = [float(pkg_meta[s][fn]) for s in s_list]
        feat_corrs[scope_name][fn] = {
            "rho_M1": round(spearman_rho(fx, [get_score(s, "M1", "W1") for s in s_list]) or 0, 4),
            "rho_M2": round(spearman_rho(fx, [get_score(s, "M2", "W1") for s in s_list]) or 0, 4),
            "rho_M4": round(spearman_rho(fx, [get_score(s, "M4", "W1") for s in s_list]) or 0, 4),
            "rho_M2_Sat100": round(spearman_rho(fx, m2_is_sat) or 0, 4),
            "rho_M4_TierShift": round(spearman_rho(fx, tier_changed) or 0, 4),
        }

# Per Extension_Category breakdown (6th feature!)
cat_groups = defaultdict(list)
for s in sids_m4:
    cat_groups[pkg_meta[s]["Extension_Category"]].append(s)
cat_summary = {}
for cat, sl in sorted(cat_groups.items()):
    cat_summary[cat] = {
        "n": len(sl),
        "mean_bytes": round(sum(pkg_meta[s]["Package_Bytes"] for s in sl) / len(sl)),
        "mean_js": round(sum(pkg_meta[s]["JS_File_Count"] for s in sl) / len(sl), 1),
        "mean_M1": round(sum(get_score(s, "M1") for s in sl) / len(sl), 2),
        "mean_M2": round(sum(get_score(s, "M2") for s in sl) / len(sl), 2),
        "mean_M4": round(sum(get_score(s, "M4") for s in sl) / len(sl), 2),
        "m2_alert_T40": sum(1 for s in sl if get_score(s, "M2") >= 40),
        "m4_alert_T40": sum(1 for s in sl if get_score(s, "M4") >= 40),
    }

results_json["exp04"] = {
    "spearman_5x5": spearman_mats,
    "stability_4layers": exp04_stability,
    "feature_correlations": feat_corrs,
    "category_breakdown": cat_summary,
}


# ---------- Point 10: Post-hoc Sensitivity Analysis for Formula C-2 (alpha & thresholds) ----------
def simulate_c2(s, alpha):
    mc = m4_comp_w1[s]
    s_stat = min(100.0, alpha * mc["m1_dedup"] + (1.0 - alpha) * mc["m2_conf_adj"])
    if by_wp_sid["W1"][s]["M4_Static_Fallback"] == "true":
        return s_stat
    floor = mc["tierA_floor"] if mc["tierA_applied"] else 0.0
    return min(100.0, max(floor, s_stat + mc["dyn_elev"] + mc["corr_bonus"]))


alpha_sens = {}
for scope_name, s_list, lfn in [
    ("Controlled_70", ctrl_all, lbl_ver),
    ("RealWorld_Verified_69", [s for s in rw_ver70 if s in m4_comp_w1], lbl_ver),
    ("RealWorld_Provenance_75", [s for s in rw_prov80 if s in m4_comp_w1], lbl_prov),
]:
    alpha_sens[scope_name] = []
    for alpha in [0.1, 0.3, 0.5, 0.7, 0.9]:
        yt = [lfn(s) for s in s_list]
        ys = [simulate_c2(s, alpha) for s in s_list]
        tp = sum(1 for y, sc in zip(yt, ys) if y == 1 and sc >= 40)
        fp = sum(1 for y, sc in zip(yt, ys) if y == 0 and sc >= 40)
        tn = sum(1 for y, sc in zip(yt, ys) if y == 0 and sc < 40)
        fn_ = sum(1 for y, sc in zip(yt, ys) if y == 1 and sc < 40)
        prec = tp / (tp + fp) if (tp + fp) else None
        rec = tp / (tp + fn_) if (tp + fn_) else None
        f1 = (2 * prec * rec / (prec + rec)) if (prec and rec) else 0.0
        fpr = fp / (fp + tn) if (fp + tn) else None
        alpha_sens[scope_name].append({
            "alpha": alpha, "n": len(s_list), "tp": tp, "fp": fp, "rec": rec, "f1": f1,
            "fpr": fpr, "roc": tie_aware_roc_auc(yt, ys), "pr": average_precision_tie_aware(yt, ys),
            "mean_score": sum(ys) / len(ys)
        })

thr_sens = {}
for scope_name, s_list, lfn in [
    ("Controlled_70", ctrl_all, lbl_ver),
    ("RealWorld_Verified_69", [s for s in rw_ver70 if s in m4_comp_w1], lbl_ver),
]:
    thr_sens[scope_name] = []
    yt = [lfn(s) for s in s_list]
    ys = [get_score(s, "M4") for s in s_list]
    for thr in [20, 30, 40, 50, 60, 70]:
        tp = sum(1 for y, sc in zip(yt, ys) if y == 1 and sc >= thr)
        fp = sum(1 for y, sc in zip(yt, ys) if y == 0 and sc >= thr)
        tn = sum(1 for y, sc in zip(yt, ys) if y == 0 and sc < thr)
        fn_ = sum(1 for y, sc in zip(yt, ys) if y == 1 and sc < thr)
        prec = tp / (tp + fp) if (tp + fp) else None
        rec = tp / (tp + fn_) if (tp + fn_) else None
        f1 = (2 * prec * rec / (prec + rec)) if (prec and rec) else 0.0
        fpr = fp / (fp + tn) if (fp + tn) else None
        thr_sens[scope_name].append({"threshold": thr, "tp": tp, "fp": fp, "rec": rec, "f1": f1, "fpr": fpr})

results_json["c2_posthoc_sensitivity"] = {"alpha_sweep": alpha_sens, "threshold_sweep": thr_sens}


# ---------- Point 11: EXP05 Full Latency & Operational Distributions ----------
# Extract exact W1 totalDurationMs for M1, M2, M4 and all 3 repeats for M3 from unified_runs_150.json
lat_by_cohort_meth = defaultdict(list)
m3_timeouts = Counter()
m3_failures = Counter()
for rec in uni["records"]:
    c = rec["cohort"]
    m = rec["method"]
    wp = rec.get("weightProfile")
    st = rec.get("status")
    dur = rec.get("totalDurationMs")
    if m in ("M1", "M2", "M4") and wp == "W1" and st != "failed" and dur is not None:
        lat_by_cohort_meth[(c, m)].append(float(dur))
        lat_by_cohort_meth[("ALL", m)].append(float(dur))
    elif m == "M3":
        if st == "failed":
            m3_failures[c] += 1
            m3_failures["ALL"] += 1
        else:
            if dur is not None:
                lat_by_cohort_meth[(c, "M3")].append(float(dur))
                lat_by_cohort_meth[("ALL", "M3")].append(float(dur))
            if "timeout" in str(rec.get("failure") or "").lower():
                m3_timeouts[c] += 1
                m3_timeouts["ALL"] += 1

# Also compute End-to-End M4 (1x M3 and 3x M3) and Static Screening (M1+M2) per extension
for s in sids_m4:
    r = by_wp_sid["W1"][s]
    c = gt_ver[s]["cohort"]
    d1 = float(r["M1_Duration_Ms"])
    d2 = float(r["M2_Duration_Ms"])
    d3 = float(r["M3_Mean_Duration_Ms"])
    d4 = float(r["M4_Duration_Ms"])
    for grp in (c, "ALL"):
        lat_by_cohort_meth[(grp, "Static_Screen")].append(d1 + d2)
        lat_by_cohort_meth[(grp, "E2E_M4_1x")].append(d1 + d2 + d3 + d4)
        lat_by_cohort_meth[(grp, "E2E_M4_3x")].append(d1 + d2 + 3 * d3 + d4)

exp05_stats = {}
for grp in ("controlled_benign", "controlled_security_test", "real_world_benign", "real_world_malicious", "ALL"):
    exp05_stats[grp] = {}
    for m in ("M1", "M2", "Static_Screen", "M3", "M4", "E2E_M4_1x", "E2E_M4_3x"):
        vals = lat_by_cohort_meth[(grp, m)]
        if vals:
            exp05_stats[grp][m] = {
                "n": len(vals),
                "mean_ms": round(statistics.mean(vals), 2),
                "median_ms": round(statistics.median(vals), 2),
                "std_ms": round(statistics.stdev(vals), 2) if len(vals) > 1 else 0.0,
                "p95_ms": round(percentile(vals, 0.95), 2),
            }
    exp05_stats[grp]["m3_prelaunch_reject_runs"] = m3_failures[grp]
    exp05_stats[grp]["m3_timeout_runs"] = m3_timeouts[grp]

results_json["exp05_full_stats"] = exp05_stats

# Save complete JSON report
out_json = os.path.join(OUT, "independent_recomputation_full.json")
with open(out_json, "w", encoding="utf-8") as f:
    json.dump(results_json, f, indent=2)

# Print clean concise summary to stdout for immediate verification
print("=== PHASE 2 INDEPENDENT RECOMPUTATION COMPLETE ===")
print("Sample counts:", results_json["sample_counts"])

for key in (
    "RealWorld_Verified70_PRIMARY_MethodSpecific",
    "RealWorld_Verified_PRIMARY_CommonSample",
    "Controlled_CommonSample_69",
    "Controlled_Inherited19_plus30CB",
    "Controlled_Authored21_plus30CB",
    "RealWorld_Provenance_SUPP_CommonSample_66",
):
    print(f"\n--- {key} ---")
    for row in results_json["evaluations"][key]:
        print(f"  {row['method']:9s} | N={row['n']:3d}/{row['input_n']:3d} ({fmt_pct(row['coverage'])}) | TP={row['tp']:2d} FP={row['fp']:2d} TN={row['tn']:2d} FN={row['fn']:2d} | Prec={fmt(row['prec'])} Rec={fmt(row['rec'])} {fmt_ci(row['rec_ci'],True)} F1={fmt(row['f1'])} FPR={fmt(row['fpr'])} ROC={fmt(row['roc'])} {fmt_ci(row['roc_ci'])} PR={fmt(row['pr'])}")

print("\n--- Exact McNemar (RealWorld Verified Common-Sample n=61 & Method-Paired) ---")
for scope in ("RealWorld_Verified70_MethodPaired", "RealWorld_Verified_CommonSample"):
    print(f"  [{scope}]")
    for k, d in results_json["mcnemar"][scope].items():
        print(f"    {k:12s}: n={d['n_paired']} | ({d['a_right_b_wrong']} vs {d['b_right_a_wrong']}) | p_raw={d['p_raw']:.6f}, p_holm={d['p_holm']:.6f}")

print("\n--- 8-Component M4 Breakdown (RealWorld Verified n=69) ---")
for st in results_json["m4_8component_breakdown"]["RealWorld_Verified_69"]:
    print(f"  {st['stage']:30s} | mean={st['mean_score']:5.2f} | aff={st['affected_samples']:2d} (Δ={st['mean_delta_vs_prev']:+6.2f}) | TP={st['tp']:2d} FP={st['fp']:2d} Rec={fmt(st['rec'])} F1={fmt(st['f1'])} FPR={fmt(st['fpr'])} ROC={fmt(st['roc'])}")

print("\n--- M3 RWM Operational Coverage ---")
for k, v in results_json["m3_rwm_operational"].items():
    print(f"  {k}: {v}")

print("\n--- Post-hoc Formula C-2 Alpha Sweep (RealWorld Verified n=69) ---")
for row in results_json["c2_posthoc_sensitivity"]["alpha_sweep"]["RealWorld_Verified_69"]:
    print(f"  alpha={row['alpha']:.1f} | TP={row['tp']} FP={row['fp']} | Rec={fmt(row['rec'])} F1={fmt(row['f1'])} FPR={fmt(row['fpr'])} ROC={fmt(row['roc'])} PR={fmt(row['pr'])}")

print("\n--- EXP04 Feature Correlations (RealWorld Numeric n=75) ---")
for fn, d in results_json["exp04"]["feature_correlations"]["RealWorld_Numeric_75"].items():
    print(f"  {fn:22s}: {d}")

print("\n--- EXP05 ALL-150 Latency Stats (ms) ---")
for m in ("M1", "M2", "Static_Screen", "M3", "M4", "E2E_M4_1x", "E2E_M4_3x"):
    print(f"  {m:14s}: {results_json['exp05_full_stats']['ALL'][m]}")
