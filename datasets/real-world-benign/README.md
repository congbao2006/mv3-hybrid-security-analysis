# Real-World Benign Candidates (`RWB-001`..`RWB-060`)

- **Target:** `40` minimum / `60` goal.
- **Current status:** **60/60** extensions have verified 32-character Chrome Web Store IDs (`[a-p]{32}`), direct Chrome Web Store URLs, and official GitHub Releases links where open-source (see `candidates.csv`). `0/60` packages are committed in Git (`.crx`, `.zip`, and `unpacked/` are git-ignored).
- **Collection & Verification Steps:**
  1. Download each extension package (`.crx`/`.zip`) from its official Chrome Web Store listing or official GitHub Release listed in `candidates.csv` into this directory.
  2. Unpack safely and verify `manifest_version === 3`, archive SHA-256, and `mvx-package-v1` `packageSha256`.
  3. Complete independent dual-reviewer verification in `Ground_Truth.xlsx` (never assume a Chrome Web Store listing is automatically benign).
  4. Update `../manifest-150.json` (`artifactPath`, `expectedArchiveSha256`, `expectedPackageSha256`, `skip: false`).
