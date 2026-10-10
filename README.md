# IQAWX Security Lab 4.1

Rust toolkit for encoding analysis, decryption with known keys, and network inspection.

[الدليل العربي](README_AR.md) · [Live demo guide (Arabic)](LIVE_DEMO_AR.md)

## Build and run

Requires Rust 1.93 or newer and the native build tools for your operating system. Run these commands in the directory containing `Cargo.toml`:

```sh
cargo build --release --locked
cargo run --release --locked
```

Running without arguments opens an interactive menu. Use `cargo run --release --locked -- --help` for commands. The first build needs internet access to download dependencies. Nmap is optional and only required for the `nmap` subcommand.

## Examples

Decode a Base64 teaching example:

```sh
cargo run --release --locked -- decode --format base64 --data ZmxhZ3tpcWF3eF9kZW1vfQ== --output-format text
```

Expected: `flag{iqawx_demo}`. This is deliberately prepared demo data.

Decrypt the included AES-128-CTR test vector:

```sh
cargo run --release --locked -- decrypt --algorithm aes128-ctr --input examples/aes128-ctr-ciphertext.hex --format hex --key-file examples/aes128-ctr-key.hex --key-format hex --nonce f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
```

Expected: `6bc1bee22e409f96e93d7e117393172a`.

Inspect two ports on your own computer:

```sh
cargo run --release --locked -- scan 127.0.0.1 --ports 8000,8001 --format json
```

Port results depend on the services running locally. Scan systems you own or have permission to test.

## Capabilities and limits

- Decode Hex, Base64, Base64url, Base32, URL, form and binary encodings; explore bounded possible encoding layers.
- File signatures, SHA-256, CRC32, strings and ranked cipher candidates. Candidate scoring uses the first 4096 bytes and can produce false positives.
- Caesar shifts and XOR; decrypt supported AES-GCM/CBC/CTR, ChaCha20/XChaCha20-Poly1305 and RSA-OAEP-SHA256 with the correct keys and parameters.
- TCP connect/basic UDP scanning, IPv4/IPv6, CIDR, limited service detection and text/JSON/XML/grep reports.
- Native scanning is not a full Nmap implementation. The `nmap` command invokes a separately installed Nmap.
- This tool does not generally break modern encryption without keys or reverse hashes. CBC and CTR do not authenticate plaintext.
- Input limit: 64 MiB. Heuristic outputs require independent verification.

## Verification

```sh
cargo test --locked
```

See [original validation](VALIDATION.md) and [publication checks](PUBLICATION_CHECKS.md) for dated results and platform limitations. macOS Apple Silicon is the verified platform; do not interpret the build instructions as Windows/Linux test results.

Example keys and the RSA key in unit tests are disposable public test fixtures. Never use them for real data.
