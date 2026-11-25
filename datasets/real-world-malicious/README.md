# Real-World Malicious Artifacts (`RWM-001`..`RWM-020`)

- **Target:** `10` minimum / `20` goal (`20` multi-source verified IDs indexed in `intel/catalog.jsonl`).
- **Current status:** `0/20` CRX files bundled (live malware is never committed to Git; `.crx`, `.zip`, and `unpacked/` are git-ignored).
- **Collection steps:**
  1. Run commands in `fetch-list.txt` (`mvx sample fetch <id> --acknowledge-risk --quarantine ./datasets/real-world-malicious`).
  2. Verify CRX authenticity, `manifest_version === 3`, archive SHA-256, and `mvx-package-v1` `packageSha256`.
  3. Complete independent dual-reviewer verification in `Ground_Truth.xlsx`.
  4. Update each corresponding `RWM-*` entry in `../manifest-150.json` (`artifactPath`, `expectedArchiveSha256`, `expectedPackageSha256`, `skip: false`).
