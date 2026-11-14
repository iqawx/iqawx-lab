# IQAWX Lab 4.2

A terminal toolkit for network inspection, encoding analysis, and decryption with known keys. Install once, then use **`iqaw`** from any terminal. The public distribution runs entirely in the terminal.

[التعليمات بالعربية](README_AR.md)

## Install from source

You need Git, [Rust 1.93 or newer](https://rust-lang.org/tools/install), and the native build tools for your operating system. The first installation downloads Rust dependencies and builds the program once. You do not need to type Cargo commands for everyday use.

### macOS / Linux

```sh
git clone https://github.com/iqawx/iqawx-lab.git
cd iqawx-lab
sh scripts/install.sh
```

The installer places `iqaw` in `~/.local/bin` and adds that directory to your shell startup configuration for sh, Bash, or Zsh. No administrator account is needed. **Open a new terminal window after installation.**

### Windows

Install Rust and the native C++ build tools, then open PowerShell:

```powershell
git clone https://github.com/iqawx/iqawx-lab.git
cd iqawx-lab
powershell -ExecutionPolicy Bypass -File .\scripts\install.ps1
```

The installer places `iqaw.exe` in `%LOCALAPPDATA%\IQAWX\bin` and adds it to your user PATH. Close and reopen your terminal application after installation. The policy override applies only to the installer process.

## Use the short commands

```sh
iqaw                              # interactive terminal menu
iqaw menu                         # the same menu explicitly
iqaw --help                       # all commands
iqaw --version                    # installed version
iqaw scan 127.0.0.1 -p 80,443      # inspect ports on your own computer
iqaw scan --help                  # scan options
iqaw decrypt --help               # decryption options
```

Choose a menu number and press Enter. Choose `8` to exit the menu. Press Ctrl+C to interrupt a running operation. Native scanning does not require Nmap; the `iqaw nmap -- <args>` command requires a separately installed Nmap.

### Decode an encoding

```sh
iqaw decode --format base64 --data ZmxhZ3tpcWF3eF9kZW1vfQ== --output-format text
```

Expected: `flag{iqawx_demo}`. This is deliberately prepared teaching data; Base64 is encoding, not modern encryption.

### Decrypt with a known key

From the repository or an extracted package containing `examples/`:

```sh
iqaw decrypt --algorithm aes128-ctr --input examples/aes128-ctr-ciphertext.hex --format hex --key-file examples/aes128-ctr-key.hex --key-format hex --nonce f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
```

Expected: `6bc1bee22e409f96e93d7e117393172a`. The included key is a public test fixture.

### Save a scan report

```sh
iqaw scan 127.0.0.1 --ports 8000,8001 --format json --out report.json
```

Results depend on the services running locally. Existing output files require `--force` to replace them. Scan systems you own or have permission to test.

## Prebuilt packages

Successful runs of the [build workflow](https://github.com/iqawx/iqawx-lab/actions/workflows/build.yml) provide terminal packages for macOS Apple Silicon, macOS Intel, Linux x64, and Windows x64. Open a successful run, choose the artifact for your platform, extract the downloaded artifact ZIP, then extract the package inside it. A failed or pending build does not provide a verified package for that platform.

Run the included installer from the extracted package:

```sh
sh scripts/install.sh
```

On Windows:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install.ps1
```

Prebuilt packages already contain `iqaw` / `iqaw.exe`, so installing and using them does not require Rust or Cargo. The Unix archives preserve executable permissions. Packages include `Open IQAWX.command` (macOS) and `Open IQAWX.cmd` (Windows) to open the terminal tool by double-clicking. Linux users can also run `./iqaw` directly from the extracted package. Check the accompanying SHA-256 file when verifying a downloaded archive.

The workflow tests and builds each platform separately. macOS Apple Silicon is locally verified; use the workflow result for the current commit to determine Windows, Linux, and Intel Mac status.

## Updates and custom installation

For an existing source checkout, run `git pull --ff-only` and run its installer again. A prebuilt installation can be updated by extracting a newer package and running that package's installer.

Custom directory without changing shell configuration:

```sh
sh scripts/install.sh --bin-dir /path/to/bin --no-path
```

```powershell
.\scripts\install.ps1 -InstallDir 'C:\path\to\bin' -NoPath
```

If `iqaw` is not found, reopen the terminal and check that the installation directory is on PATH. To uninstall, remove the installed executable and its IQAWX PATH entry from your shell configuration or Windows user PATH.

## Capabilities and limits

- Decode Hex, Base64, Base64url, Base32, URL, form and binary encodings; explore bounded possible encoding layers.
- File signatures, SHA-256, CRC32, strings and ranked cipher candidates. Candidate scoring uses the first 4096 bytes and can produce false positives.
- Caesar shifts and XOR; decrypt supported AES-GCM/CBC/CTR, ChaCha20/XChaCha20-Poly1305 and RSA-OAEP-SHA256 with the correct keys and parameters.
- TCP connect/basic UDP scanning, IPv4/IPv6, CIDR, limited service detection and text/JSON/XML/grep reports.
- Native scanning is not a full Nmap implementation. The `nmap` command invokes a separately installed Nmap.
- This tool does not generally break modern encryption without keys or reverse hashes. CBC and CTR do not authenticate plaintext.
- Input limit: 64 MiB. Heuristic outputs require independent verification.

## Developer commands

```sh
cargo build --release --locked --bins
cargo test --locked
./target/release/iqaw --help
```

On Windows, the built executable is `.\target\release\iqaw.exe`. The original `iqawx_lab` executable is also built and included in packages for compatibility. `cargo run --release --locked` defaults to the `iqaw` terminal command.

See [original validation](VALIDATION.md) and [publication checks](PUBLICATION_CHECKS.md) for dated results and platform limitations. Example keys and the RSA key in unit tests are disposable public test fixtures. Never use them for real data.


## 4.2 updates / تحديثات 4.2

[Feature guide / دليل الميزات](GUIDE_4_2.md) · [English test report](TEST_REPORT_EN.md) · [تقرير الاختبار بالعربي](TEST_REPORT_AR.md)
