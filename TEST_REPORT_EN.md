# IQAWX Lab 4.2 — test report

Date: 14 November 2026 (Asia/Baghdad). Tested engine commit: `b9adbc9e606d9f51e25b73c47026835a42357ec8`.

[GitHub Actions run and downloadable evidence](https://github.com/iqawx/iqawx-lab/actions/runs/43580361985)

## Verified results

| Environment | Scope | Result |
|---|---|---|
| Windows Server 2025 x64, GitHub `windows-latest` | Public engine, terminal CLI and installer | Passed: 68 tests; formatting, Clippy with warnings denied, release build, four encryption roundtrips, SHA-256 check and packaged installer |
| Ubuntu 22.04 x64 | Public engine, terminal CLI and installer | Passed: 69 tests and the same quality/build/release/installer checks |
| macOS 15 Apple Silicon | Public engine, terminal CLI and installer | Passed on GitHub Actions |
| macOS 15 Intel | Public engine, terminal CLI and installer | Passed on GitHub Actions |
| Local macOS Apple Silicon | Public engine and both CLI names | Passed: 69 tests; Clippy; formatting; release builds |
| Local macOS Apple Silicon | Private graphical interface | Passed: 10 tests; Clippy; release build; browser verification in Arabic and English |

Windows has one fewer test because the Unix shell-based Nmap argument-boundary fixture is conditionally compiled for Unix. Windows/Linux results were read from their saved `tests.log` and `summary.json` artifacts, not inferred from compilation.

## What was exercised

- TCP/UDP loopback behavior, observed services, target lists and exclusions, partial results on cancellation/deadline, progress separated from machine-readable output, and JSON/XML/text/grep/HTML/CSV reporting.
- Existing decoding and keyed decryption, new random key creation, all four authenticated envelope algorithms, binary/Unicode handling, wrong keys, tampering and no-output-on-authentication-failure behavior.
- Key/output protection, overwrite rules, SHA-256/384/512 vectors and expected digest verification.
- Both public commands (`iqaw`, `iqawx_lab`), terminal menu and platform installers.
- Private UI session checks, restrictions on browser-requested filesystem paths, encryption/opening, key generation, hashing, readable reports, progress and partial-result download. Browser SHA-256 of `abc` matched the known value, and switching Arabic/English retained the input and result.

## Issue found and corrected

The first Windows run failed the strict quality check because a mutable variable was only mutated in Unix-specific code. The implementation was changed to use platform-specific immutable bindings; the second Windows run passed. The existing Windows loopback-refusal timing fix was retained during the merge.

## Scope and publication

The public tests use controlled loopback services only. Hosted Windows testing used Windows Server 2025; it does not establish compatibility with every Windows desktop version. The private GUI was tested on the local Mac only and was not tested on Windows/Linux in this session. It is excluded from the public Git tree, CI uploads and public packages. Real Nmap, remote network accuracy, TLS inspection and a full independent security audit are outside this test scope.

Source and platform packages are available from [the repository](https://github.com/iqawx/iqawx-lab) and the run linked above. Earlier validation documents remain historical records.
