# IQAWX Lab 4.2.0 initial local validation — 2026-11-14

This is the initial local-only record before merging the existing public launcher. Current Windows/Linux results and merged test counts are in [TEST_REPORT_EN.md](TEST_REPORT_EN.md) and [TEST_REPORT_AR.md](TEST_REPORT_AR.md).

Environment: macOS Apple Silicon arm64; Rust/Cargo 1.93.1. This report describes the local 4.2.0 source and release binary, not a published release.

| Check | Result |
|---|---|
| `cargo test --offline --locked` | 63 passed: 47 library, 3 CLI/report unit, 13 integration |
| `cargo clippy --offline --locked --all-targets -- -D warnings` | Passed with no warnings |
| `cargo fmt --check` | Passed |
| `git diff --check` | Passed |
| `cargo build --release --offline --locked` | Passed |
| Independent release smoke checks | 19 passed |

The 19 release checks cover version reporting, binary/Unicode file roundtrips through all four envelope algorithms, independent Python cryptography decryption for AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305, interactive keygen/encrypt/open/hash, SHA-256/384/512 comparison against Python hashlib, real SIGINT cancellation writing a partial report with exit status 130, observed SSH detection, independent XML/CSV parsing, HTML escaping of a hostile banner, and text/grep reports.

New regression coverage includes preservation of completed scan results during cancellation, deadline handling without fabricating missing port states, exclusion of loopback targets, progress/output separation, ciphertext/context/nonce tampering, algorithm/version validation, wrong key rejection, key-file overwrite protection, no-overwrite defaults, Unix key permissions, digest verification, JSON-default compatibility and spreadsheet formula handling. AES-GCM encryption also matches known NIST fixtures already represented in the project's decryption tests.

Network tests used controlled loopback services only. XChaCha20-Poly1305 was roundtrip/tamper tested with the Rust implementation; its existing raw decryption known-answer tests also remain passing. The independent Python check covered the other three envelope algorithms. Windows, Linux, real Nmap, TLS inventory and raw-packet scan modes were not tested or newly implemented. No claim is made of complete protocol coverage, exhaustive input coverage, or an independent security audit.

The historical VALIDATION.md and PUBLICATION_CHECKS.md remain unchanged as records for 4.1. Source and lockfile package versions are now 4.2.0; dependency versions were not changed.
