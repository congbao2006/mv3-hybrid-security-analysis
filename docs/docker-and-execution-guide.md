# Hướng dẫn Docker, Phiên bản Môi trường & Lưu ý Khi Chạy Thực nghiệm (`mvx-audit`)

Tài liệu này chốt chính xác phiên bản Docker, Node.js, Chromium lab image, cấu hình thực nghiệm và các lưu ý thực tế (đúc kết sau khi chạy kiểm chứng **130/150 mẫu**: 70 Controlled + 60 Real-World Benign) để cả nhóm (**Tài, Ngọc, Luân**) và người tái lập nghiên cứu chạy đồng bộ, không lệch kết quả.

---

## 1. Phiên bản môi trường đã kiểm chứng (Verified Baseline)

| Thành phần | Phiên bản yêu cầu / đã kiểm chứng | Ghi chú |
|---|---|---|
| **Git repo commit** | `9a43373` (hoặc mới hơn trên `main` / `research/mv3-hybrid`) | Cả nhóm dùng cùng 1 commit |
| **Node.js** | `>= 20` (khuyến nghị `22.x`; đã test ổn trên `v25.1.0`) | Cài dependency bằng `npm ci` theo `npm-shrinkwrap.json` |
| **Docker (macOS)** | **Colima `>= 0.10.3` + Docker CLI `>= 29.x`** *(khuyến nghị)* hoặc Docker Desktop / OrbStack | Đã kiểm chứng: `Docker CLI 29.10.1`, `Colima 0.10.3`, `Lima 2.3.0`, Docker Engine `29.5.2 (linux/aarch64)` |
| **Docker (Linux / VM)** | **Docker Engine `>= 24.x`** (khuyến nghị `28.x–29.x`) | Hỗ trợ `--network none`, `--read-only`, `--cap-drop ALL`, `seccomp`, `--pids-limit 256` |
| **Docker (Windows)** | **Docker Desktop + WSL2 (Ubuntu)** | Clone repo và chạy toàn bộ lệnh **bên trong WSL2** để tránh lỗi bind-mount & file mode |
| **Base image trong container** | `node:22-bookworm-slim@sha256:6c74791e...` | Đã pin cứng theo SHA-256 trong `lab/Dockerfile` |
| **Chromium trong container** | `156.0.8078.108-1~deb12u1` (`bookworm-security`) | Đã cập nhật sẵn trong `lab/Dockerfile` (bản `150.0.7871.181-1~deb12u1` cũ đã bị Debian gỡ) |
| **Tài nguyên máy tối thiểu** | RAM `>= 8 GB` (cấp cho VM Docker `>= 4 GB`), ổ trống `>= 10 GB` | Mỗi container lab giới hạn `1 GB` RAM, `2` vCPU |

> **Lưu ý về kiến trúc CPU:** `M1`, `M2` chạy thuần Node.js không cần Docker. `M3` và `M4` bắt buộc có Docker. Image `mvx-lab:local` build native được trên cả `linux/amd64` lẫn `linux/arm64` (Apple Silicon).

---

## 2. Cài đặt & Khởi động Docker chuẩn theo hệ điều hành

### 2.1. Trên macOS (Khuyến nghị dùng Colima — nhẹ, không cần GUI)
```bash
brew install docker colima
```

**BẮT BUỘC mount thêm `/private/var/folders:w` và `/private/tmp:w`** khi khởi động Colima (vì `mvx-audit` tạo private snapshot trong `os.tmpdir()` của macOS và bind-mount vào container):
```bash
colima start --cpus 4 --memory 4 --disk 25 \
  --mount "$HOME:w" \
  --mount "/private/var/folders:w" \
  --mount "/private/tmp:w"
```

Kiểm tra Docker daemon đã sẵn sàng:
```bash
docker info --format '{{.ServerVersion}} ({{.OSType}}/{{.Architecture}})'
```

*(Nếu dùng Docker Desktop hoặc OrbStack, đảm bảo thư mục dự án và thư mục tạm `/var/folders` / `/tmp` được phép file sharing.)*

### 2.2. Trên Linux / VM cách ly (Khuyến nghị cho 20 mẫu Malicious)
- Cài Docker Engine chính chủ (`docker-ce`, `docker-ce-cli`, `containerd.io`).
- Thêm user vào nhóm `docker` để chạy lệnh không cần `sudo`:
  ```bash
  sudo usermod -aG docker "$USER"
  # Đăng xuất/đăng nhập lại rồi kiểm tra:
  docker info --format '{{.ServerVersion}} ({{.OSType}}/{{.Architecture}})'
  ```

---

## 3. Build & Kiểm tra Lab Image trước khi chạy data (BẮT BUỘC)

Chạy đúng 4 lệnh sau trong thư mục `mvx-audit/`:

```bash
npm ci
npm test
npm run lab:build
npm run lab:smoke -- --acknowledge-risk
```

**Điều kiện đạt (PASS):**
- `npm test`: `234/234` pass, `0` fail.
- `npm run lab:build`: build xong `mvx-lab:local` với Chromium `156.0.8078.108-1~deb12u1`.
  - *(Nếu Debian sau này lại cập nhật bản Chromium mới hơn và báo `Version ... not found`, kiểm tra bản mới bằng `apt-cache madison chromium` rồi truyền `--build-arg CHROMIUM_VERSION=<ver>` và báo cả nhóm dùng chung đúng 1 version đó.)*
- `npm run lab:smoke -- --acknowledge-risk` phải in đủ:
  ```text
  Lab verdict: no_trigger_observed; contained: yes
  Lab verdict: confirmed_attack; contained: yes
  Dynamic smoke tests passed; evidence: ...
  ```

---

## 4. Cấu hình thực nghiệm khóa cứng (Cả 3 máy dùng giống hệt nhau)

- **File fusion config chuẩn:** `configs/fusion-config.json`
  - `configVersion`: `2026.1-frozen-alpha03`
  - `formula`: `C-2`
  - `staticBlendAlpha`: `0.3` (ưu tiên `0.7 × M2` + `0.3 × M1`)
  - `tierABehavioralFloor`: `90`
  - Canonical SHA-256: `b1c6e412bfcf59907fe84a76790e03a580fd422047c316d26ade4a40a1b6ee6d`
- **Kịch bản dynamic chuẩn:** `./lab/scenarios/credential-exfiltration.json`
- **Tham số chuẩn:**
  ```bash
  node bin/mvx.js research experiment \
    --manifest <duong-dan-manifest.json> \
    --output results/local/<ten-nhom>/experiments \
    --experiment-id <ten-run-rieng> \
    --methods M1,M2,M3,M4 \
    --weights W1,W2,W3,W4,W5 \
    --fusion-config configs/fusion-config.json \
    --scenario ./lab/scenarios/credential-exfiltration.json \
    --m3-repeats 3 \
    --m3-timeout 60000 \
    --require-manifest-v3 \
    --acknowledge-risk \
    --format text
  ```
- Sau khi chạy xong, luôn chạy thêm 3 lệnh kiểm định & xuất bảng:
  ```bash
  node bin/mvx.js research stability <experiment-dir> --output <out>/stability --format json
  node bin/mvx.js research export <experiment-dir> --output <out>/tables --format json
  node bin/mvx.js research inspect <experiment-dir> --format text
  ```

---

## 5. Các lưu ý quan trọng khi chạy thực nghiệm

### 5.1. Thời gian chạy & chống ngắt giữa chừng
- Tốc độ đo thực tế (với `--m3-repeats 3`, mỗi lần Docker mất ~10.4–11 giây):
  - **70 mẫu Controlled:** ~36 phút (210 container).
  - **60 mẫu Real-World Benign:** ~33–35 phút (180 container).
  - **20 mẫu Real-World Malicious:** ~11–12 phút (60 container).
- **Giữ máy thức (không sleep):** trên macOS nên bọc lệnh bằng `caffeinate -i ...` để tránh Colima tạm dừng kết nối socket.
- **Nếu bị gián đoạn giữa chừng (mất điện, đóng terminal, hết pin):**
  - **TUYỆT ĐỐI KHÔNG xóa** thư mục experiment đã tạo.
  - Chạy lệnh tiếp tục (tự kiểm tra SHA-256 artifact cũ và chỉ chạy nốt phần thiếu):
    ```bash
    node bin/mvx.js research resume <experiment-dir> --acknowledge-risk --format text
    ```

### 5.2. Xử lý `M3 = inconclusive` và `completed_with_static_fallback`
- Trên Manifest V3 thực tế (ví dụ 6/60 mẫu ở tập RWB), một số extension dùng **ephemeral Service Worker** hoặc chủ yếu dùng `declarativeNetRequest` tĩnh khiến Chromium không expose background target thường trực (`Chromium did not expose the extension background target; execution is unverified`).
- Đây là **hành vi bình thường của MV3**, không phải lỗi hệ thống:
  - `M3` ghi nhận rõ `inconclusive` (không bao giờ ép về `0`).
  - `M4` tự động chuyển `completed_with_static_fallback` (dùng điểm tĩnh chuẩn hóa).
  - Giữ nguyên các record này trong log (`failure_and_inconclusive_cases.csv`) để báo cáo trung thực trong bài báo.

### 5.3. Khi tải file `.crx` từ Chrome Web Store (nhóm Real-World Benign)
- Nếu dùng endpoint `clients2.google.com/service/update2/crx`, phải truyền `prod=chromecrx&prodversion=150.0.0.0` (nếu để `prodversion` quá thấp, nhiều extension mới sẽ trả về `HTTP 204 No Content`).
- Một số extension mega-bundle ngoài đời thực có thể vượt giới hạn mặc định của `mvx-audit` (`ENCODED_PAYLOAD_LIMIT: 1,000,000 ECMAScript tokens`, `SCAN_LIMIT: 50 MB`, `ARCHIVE_LIMIT: 10,000 entries`, hoặc `External XML DTD`). **Không tự ý sửa giới hạn mặc định** — ghi nhận minh bạch vào `attrition_log.json`.

### 5.4. Cảnh báo an toàn bắt buộc cho 20 mẫu Malicious (`RWM-001`–`RWM-020`)
- **BẮT BUỘC chạy trong VM/sandbox cách ly hoàn toàn** khỏi máy cá nhân (tắt shared folder/clipboard nếu được, tắt mạng ra ngoài sau khi tải gói vào `./quarantine`).
- **TUYỆT ĐỐI KHÔNG** cài lên trình duyệt cá nhân, không giải nén thủ công bằng tay, và **không commit / gửi file `.crx`/`.zip`** lên GitHub hay nhóm chat — chỉ xuất ra ngoài các file báo cáo `JSON` / `CSV` / `JSONL`.
- Nếu `mvx research experiment` báo **`LAB_CONTAINMENT_VIOLATION`**, hệ thống sẽ dừng khẩn cấp ngay lập tức: giữ nguyên log bằng chứng và kiểm tra lại cấu hình `--network none` của Docker trước khi tiếp tục.

### 5.5. Giữ sạch Git & Tách biệt Ground Truth
- Luôn xuất kết quả vào `results/local/...` (đã nằm trong `.gitignore`).
- **Không đưa cột Ground Truth** (`label`, `finalDecision`, …) vào dataset manifest khi chạy `validate` / `experiment` / `export` (hệ thống sẽ chặn bằng mã lỗi `GROUND_TRUTH_FORBIDDEN`).
- Chỉ ghép bảng `Ground_Truth` (đủ 2 reviewer ký duyệt độc lập) ở bước `mvx research evaluate` cuối cùng vào một thư mục output riêng biệt.
