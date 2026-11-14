# Changes

## 4.2.0 — 2026-11-14

- Add cancellable scanning with completed-result preservation and progress callbacks, plus CLI deadline and progress controls.
- Add target list files, IP/CIDR exclusions, completion metadata, state summaries, HTML and CSV export.
- Add random symmetric key generation and versioned authenticated encryption envelopes using AES-128/256-GCM and ChaCha20/XChaCha20-Poly1305.
- Add SHA-256/384/512 digest verification and readable analysis/layer reports.
- Add interactive menu entries for key generation, encryption, envelope opening and hashing.
- Preserve existing CLI commands and JSON analysis defaults. Scan JSON gains additive completion metadata and a summary; library users must initialize the new ScanOptions/ScanReport fields.
- Add cancellation, tampering, key protection, target exclusion, report format and digest tests. Fix existing formatting differences.

Historical validation documents describe their original versions; see VALIDATION_4_2.md for this release.
