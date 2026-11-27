# Bảng Đối Soát Trạng Thái Bản Thảo & Yêu Cầu Chuẩn Nghiên Cứu

**Tài liệu đối chiếu:** `paper_draft.md` / `paper_draft.docx` (bản nộp giảng viên nhận xét vòng 1)  
**Nguyên tắc đánh dấu:** **Chỉ xác nhận `[x] ĐẠT` khi đã kiểm chứng trực tiếp bằng file dữ liệu, log chạy (`runs.jsonl`), mã nguồn (`src/research/`), hoặc artifact trên đĩa.** Mọi mục chưa hoàn tất hoặc cần giảng viên quyết định được ghi thẳng ở Phần 2.

---

## Phần 1 — Những Hạng Mục ĐÃ CÓ & ĐÃ XÁC MINH ĐẠT

### 1.1. Dữ liệu, Tính Toàn Vẹn & Tính Tái Lập
- [x] **150 mẫu MV3 thực nghiệm + 3 mẫu fetch attrition có log minh bạch:** `30 CB + 40 CST + 60 RWB (CRX3 ký từ CWS, lọc từ 164 ứng viên) + 20 RWM (thay 3 mẫu >25 MB bằng RWM-021, RWM-022, RWM-023)`.
  - *Bằng chứng:* `01_data_validation/experiment_data_audit.csv`, `datasets/real-world-benign/attrition_log.json`, `results/local/rwm-20-tai/handoff-rwm-20-tai/dataset/plan_many_behavior_confirmed.json`.
- [x] **Nguồn 3 mẫu `RWM-021/022/023` khớp cùng repo & commit đã pin:** Xác minh trực tiếp từ `plan_many_behavior_confirmed.json` & `fetch_status.csv` đều thuộc `GherardoFiori/MaliciousBrowserExtensions@b346c095f8e33b9875da2bbede3854855b984bae` (thời điểm `2026-11-26T15:30:47–50Z`, hash khớp nguồn intel: `f1513783…`, `10d85f3b…`, `632ebc0a…`).
- [x] **2,700 JSON evaluation artifacts kiểm định toàn vẹn 100% và phân loại rõ ràng:** Xác minh trực tiếp trên `03_consolidated_results/unified_runs_150.json` gồm đúng **`2,605` numeric outputs** (`750 M1 + 725 M2 + 405 M3 + 675 M4 full + 50 M4 static-fallback`) + **`30` `M3` inconclusive outputs** (`10 × 3`) + **`65` fail-closed parser-failure/rejection records** (`25 M2 + 15 pre-M3 + 25 M4` trên 5 mẫu `RWM`); `0` file thiếu, `0` sai lệch SHA-256, `0` containment violation; cùng `fusionConfigSha256` (`b1c6e412…`), `Chromium 156.0.8078.108`, repo commit `ac3b584` (lưu ý tính toàn vẹn artifact không tự chứng minh tính đúng của nhãn Ground Truth).
  - *Bằng chứng:* `01_data_validation/missing_evidence.csv` (`0` dòng), `03_consolidated_results/unified_runs_150.json`, `01_data_validation/data_validation_report.md`.
- [x] **Không phát tán mã độc (`.crx`/`.zip`) trong Git:** Kiểm chứng `0` file nhị phân `.crx`/`.zip` trong repo công khai.

### 1.2. Thực Nghiệm, Số Liệu & Đối Chiếu Mã Nguồn
- [x] **Phân tách rõ 450 scheduled `M3` runs = `435` actual Docker launches + `15` pre-launch parser rejections:** Kiểm chứng trực tiếp từ `rwm-20-tai/experiment/runs.jsonl` (`RWM-003/005/006/009/012` fail sau `0.3–3.5 s` với mã `UNSAFE_LAB_INPUT` / `ENCODED_PAYLOAD_LIMIT` trước khi khởi chạy Chromium).
- [x] **Phân tách rõ 3 khái niệm thời gian chạy:** Static screening (`M1+M2` = `~0.28 s`), `M4` fusion computation overhead (`0.36 ms`), và end-to-end `M4` pipeline (`~10.77 s` cho 1 lượt `M3`, `~31.74 s` cho $3\times$ repeats); ghi nhận khác biệt host `macOS/Colima` vs `Ubuntu VM`.
- [x] **Phân tách rõ 3 chỉ số ổn định `M3` (đã xác minh từng repeat trong `unified_runs_150.json`):** `100%` 3-repeat run-outcome consistency trên `145` mẫu vào Docker (`435` container runs: `135/135` lặp 3/3 cùng determinate verdict + `10/10` lặp 3/3 cùng `inconclusive`, **`0` flips**), `93.1%` determinate verdict coverage trên mẫu đã chạy (`135/145`, tức `90.0%` trên `150` mẫu), `6.9%` `inconclusive` (`10/145`), và `5` mẫu bị chặn pre-`M3` (`5/5` lặp 3/3 pre-`M3` rejected).
- [x] **Đánh giá `M3` theo 2 chế độ riêng biệt:** Alert/Triage Mode (`score >= 50`: Real-World `Recall = 66.7% [8/12]`, `baseline alert rate = 16.7% [9/54]`, `F1 = 0.552`) và Strict Confirmation Mode (`score = 100`: Controlled `Recall = 10.3% [4/39]`, Real-World `Recall = 0.0% [0/12]`, `0/54` baseline).
- [x] **Ablation `M4` khớp 100% với 5 file JSON cấu hình, đủ 18/18 mẫu `suspicious_activity` và post-hoc diagnostic:** Bảng cấu hình `Enabled Terms` + bảng chuyển điểm thực tế từ `fuseHybridEvidence` cho `CST-019, CST-027, CST-030, CST-036` + ví dụ tính tay Formula `C-2` của `CST-030`; xác minh `experiment-runner.js` truyền `primaryM3` (`repeat 1`) vào `M4`; kiểm chứng cả `18/18` mẫu `suspicious_activity` (`1 CST`, `9 RWB`, `8 RWM`) đều có `unknown` initiator (`0/18` elevation applied); kèm 1 phân tích *post-hoc sensitivity* (`initiator = false`, tách riêng khỏi benchmark đóng băng `alpha03`: Real-World `ROC-AUC 0.439 → 0.598`, `Recall 40% → 60%`, `F1 0.308 → 0.383`, nhưng baseline alert rate tăng `30.0% → 38.3%`).
- [x] **Kiểm định thống kê & Khoảng tin cậy đối chiếu từ `eval_*_Primary_T40.json`:** Báo cáo rõ raw & Holm-adjusted exact McNemar $p$-values (`M4 vs M2`: Real-World raw `0.000977` / Holm `0.002931`; Pooled raw `0.000076` / Holm `0.000228`; `M4 vs M3`: Real-World raw `0.0639` / Holm `0.1278`) và Clopper–Pearson 95% CI cho `M3` Real-World Triage Recall (`8/12 = 66.7%`, 95% CI `[34.9%, 90.1%]`) và Baseline Alert Rate (`9/54 = 16.7%`, 95% CI `[7.9%, 29.3%]`).
- [x] **Khớp số liệu `EXP03` & `EXP04` giữa văn bản, CSV và biểu đồ:** `458` unique static findings → `1,079` multi-label category assignments; `EXP04` mean `M4` (`W1=20.25, W4=15.53, W5=25.07`), Spearman $\rho \ge 0.9709$, score saturation (`M2: 5.5%–9.7%` vs `M4: 0%`), risk-tier shifts (`7.6%–24.1%`).
- [x] **Thuật ngữ khoa học trung thực & nhất quán:** Tách `CST` (`Security-Risk Positive`) khỏi malware; gọi `RWB` là `Store-Sourced Benign Baseline` (estimated FPR / baseline alert rate) và `RWM` là `Source-Reported Malicious`; sửa đúng lập luận toán học về chiều dịch chuyển của `true FPR`; phân biệt `non-zero indicator coverage (36/40; 36/36 in enabled scope)` với `High-threshold recall (4/40)`; ghi `method-wise` FP/FN counts; không quy công Dynamic Fusion trên Real-World.
- [x] **Hoàn tất 100% Dual-Human Blind Ground Truth Review & Cohen's $\kappa$ thật (`Ground_Truth_Adjudicated_150.csv`):** Hai thành viên chấm mù hoàn toàn độc lập trên toàn bộ `80` mẫu Real-World (`BLIND-001`–`BLIND-080`, ẩn hoàn toàn điểm `M1–M4` và nhãn `RWB`/`RWM`):
  - **Đồng thuận 3 lớp (`Benign`/`Malicious`/`Unknown`, $n = 80$):** `70/80 (87.50%)`, **Cohen's $\kappa = 0.7001$** (*Substantial Agreement*).
  - **Đồng thuận 2 lớp trên các mẫu cả 2 người kết luận rõ ($n = 71$):** `68/71 (95.77%)`, **Cohen's $\kappa = 0.8632$** (*Almost Perfect Agreement*).
  - **Chốt nhãn & phát hiện Version Drift:** Cả `12` ca không đồng thuận/cùng `Unknown` (`10` lệch nhãn + `2` cùng `Unknown`) đã được ghi log & chốt nhãn minh bạch trong `02_ground_truth/disagreement_log.csv` và `Ground_Truth_Adjudicated_150.csv`; phát hiện 4 mẫu `RWM` (`RWM-001/016/017/018`) bị trôi phiên bản so với bản bị chiếm quyền gốc, và chạy kiểm tra độ nhạy trên tập đồng thuận nghiêm ngặt `n = 68` (`M3 ROC-AUC 0.750 → 0.795`, `Recall 66.7% → 75.0%`; `M4 ROC-AUC 0.439 → 0.521`, McNemar `M4 vs M2` $p = 0.001831$).
- [x] **Thông tin Tác giả, ORCID, Affiliation & Corresponding Author chuẩn UEH Springer LNCS:** Đã điền đủ 5 tác giả kèm mã ORCID dạng superscript đúng thứ tự (`Quoc Hung NGUYEN *[0000-0002-6363-0160]`, `Xuan Ngoc TRAN [0009-0009-9947-8103]`, `Anh Truong Tai NGUYEN [0009-0001-1866-031X]`, `Cong Bao LE [0009-0001-0151-0120]`, `The Luan NGUYEN [0009-0007-9242-3770]`), `University of Economics Ho Chi Minh City (UEH), Ho Chi Minh City, Vietnam`, và `Corresponding author: hungngq@ueh.edu.vn`.
- [x] **Khung trang chuẩn Springer LNCS (`12.2 × 19.3 cm`), font đồng nhất `Times New Roman`, & giải đáp đủ 5 góp ý phản biện:** Đã co gọn toàn bài về chuẩn **~12 trang LNCS** (Abstract `~210` từ, `7` bảng Booktabs, `4` biểu đồ sắc nét không trùng số liệu, bỏ font `Courier New` chênh nét), giải thích rõ trần điểm `M2` trên CST (`max=31 < 40` nên `TP=0` tại `T=40` dù `ROC-AUC=0.825`), chốt rõ `20` mẫu `RWM` hoạt động (không phải 23), cảnh báo chênh lệch host `macOS/Colima` vs `Ubuntu VM` ở Table 5, và làm rõ vai trò triage của `M3 >= 50` kèm CI rộng trên `n = 12–15`.

---

## Phần 2 — Việc còn lại trước khi nộp hội nghị chính thức (Không còn mục P0 nào thiếu!)

- [ ] **1. Danh sách Case Study (Table 7):** Hỏi thầy xác nhận giữ bộ 10 case thật trong 150 mẫu đã chạy (có **Cyberhaven `RWM-001`** cùng phân tích trôi phiên bản `v25.10.5`).
- [ ] **2. Dò lại DOI/số trang 24 tài liệu tham khảo & chuyển sang LaTeX (`llncs.cls` + `.bib`):** Làm sau khi thầy góp ý xong trên bản Word `.docx`.

---

## Phần 3 — Điểm Chốt Nhanh Để Bảo Vệ Trước Giảng Viên

1. **Tại sao `435` Docker launches chứ không phải `450`?** `450` là số lượt `M3` được lên lịch (`150 × 3`); `5` mẫu `RWM` chạm giới hạn XML/DTD mặc định trước khi mở Chromium (`15` lượt rejected), còn `145` mẫu (`435` lượt) chạy thực sự trong Docker với `100%` nhất quán và `0` vi phạm cách ly.
2. **Tại sao `M4` không thắng `M3` trên Real-World?** Do cờ đóng băng `requireExtensionInitiatorForSuspicious = true` chặn toàn bộ `+20` elevation trên `8/12` cảnh báo `suspicious_activity` có CDP initiator `unknown`; lợi ích hiện tại của `M4` trên Real-World là giảm mạnh báo động giả của `M2` (`53.3% → 30.0%` ở `T=40`, `23.3% → 1.7%` ở `Critical >= 70`, McNemar $p = 0.000977$).
3. **Nhóm tự làm gì vs kế thừa `mvx-audit`?** Kế thừa engine unpack/rule/Docker của `mvx-audit v3.1.0` (`[23]`); đóng góp của nhóm là benchmark 150 mẫu MV3 có đối chứng, bộ nghiên cứu `src/research/` (cô lập `M1–M3`, `W1–W5`, `M4` Formula `C-2`, 3-repeat stability, thống kê chính xác), và toàn bộ thực nghiệm `EXP01–EXP05` + Ablation.
