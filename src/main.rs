use base64::Engine;
use clap::{Args, Parser, Subcommand, ValueEnum};
use iqawx_lab::{analysis, crypto, scanner};
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

mod report;

const MAX_INPUT: usize = 64 * 1024 * 1024;

#[derive(Parser, Debug)]
#[command(
    name = "iqawx_lab",
    version,
    about = "Rust network inspection, encoding analysis and keyed decryption",
    after_help = "No arguments: interactive menu. Native scans are TCP connect/basic UDP, not a complete Nmap reimplementation. Use `nmap -- <args>` to invoke a separately installed Nmap."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Scan IPs, hostnames or CIDRs using the native Rust engine
    Scan(ScanArgs),
    /// Strictly decode an encoding; this is not cryptographic decryption
    Decode {
        #[command(flatten)]
        input: InputArgs,
        #[command(flatten)]
        output: OutputArgs,
    },
    /// Decrypt with a known key; authentication failures produce no plaintext
    Decrypt {
        #[arg(long, value_parser = ["aes128-gcm", "aes256-gcm", "chacha20-poly1305", "xchacha20-poly1305", "aes128-cbc", "aes192-cbc", "aes256-cbc", "aes128-ctr", "aes192-ctr", "aes256-ctr", "rsa-oaep-sha256"])]
        algorithm: String,
        #[command(flatten)]
        input: InputArgs,
        /// Key file (raw key bytes, or PEM for RSA); avoids keys in process arguments
        #[arg(long)]
        key_file: PathBuf,
        #[arg(long, default_value = "raw", value_parser = ["raw", "hex", "base64"])]
        key_format: String,
        /// Hex nonce for AEAD, IV for CBC, or full 16-byte initial counter for CTR
        #[arg(long)]
        nonce: Option<String>,
        /// Additional authenticated data, hex; AEAD only
        #[arg(long)]
        aad: Option<String>,
        #[command(flatten)]
        output: OutputArgs,
    },
    /// File signatures, hashes, strings and ranked heuristic cipher candidates
    Analyze {
        #[command(flatten)]
        input: InputArgs,
        #[arg(long, default_value_t = 5, value_parser = clap::value_parser!(u8).range(1..=20))]
        top: u8,
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long)]
        force: bool,
    },
    /// Explore bounded possible layers of encodings, without claiming certainty
    Auto {
        #[command(flatten)]
        input: InputArgs,
        #[arg(long, default_value_t = 3, value_parser = clap::value_parser!(u8).range(1..=5))]
        depth: u8,
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long)]
        force: bool,
    },
    /// Legacy `xor HEX` analysis, or reversible XOR with --key-hex
    Xor {
        hex_bytes: String,
        #[arg(long)]
        key_hex: Option<String>,
        #[command(flatten)]
        output: OutputArgs,
    },
    /// Rotate Latin letters; negative shifts decrypt a known Caesar rotation
    Caesar {
        #[arg(long)]
        text: String,
        #[arg(long, allow_hyphen_values = true)]
        shift: i32,
    },
    /// Pass arguments directly to a separately installed Nmap (not Rust scanning)
    Nmap {
        #[arg(last = true, required = true)]
        args: Vec<OsString>,
    },
}

#[derive(Args, Debug)]
struct ScanArgs {
    #[arg(required = true)]
    targets: Vec<String>,
    #[arg(short = 'p', long, default_value = "", allow_hyphen_values = true)]
    ports: String,
    /// Read port-name hints and frequencies from an nmap-services format file
    #[arg(long, visible_alias = "servicedb")]
    services_file: Option<PathBuf>,
    /// Scan the N highest-frequency ports in --services-file for this protocol
    #[arg(long, requires = "services_file", conflicts_with = "ports", value_parser = clap::value_parser!(u16).range(1..))]
    top_ports: Option<u16>,
    #[arg(long, value_enum, default_value_t = ScanProtocol::Tcp)]
    protocol: ScanProtocol,
    #[arg(long, default_value_t = 500, value_parser = clap::value_parser!(u64).range(1..=60000))]
    timeout_ms: u64,
    #[arg(long, default_value_t = 128, value_parser = clap::value_parser!(u16).range(1..=1024))]
    concurrency: u16,
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u8).range(0..=5))]
    retries: u8,
    /// Maximum scan attempts started per second (not a packet-level limit)
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..=100000))]
    rate: Option<u32>,
    /// Read banners and send HTTP HEAD on common HTTP ports; not Nmap -sV
    #[arg(long)]
    service_detection: bool,
    #[arg(long, default_value_t = 256, value_parser = clap::value_parser!(u32).range(1..=65536))]
    max_hosts: u32,
    /// Limit terminal/report display to open ports; scanning is unchanged
    #[arg(long)]
    open: bool,
    #[arg(long, value_enum, default_value_t = ReportFormat::Text)]
    format: ReportFormat,
    #[arg(long)]
    out: Option<PathBuf>,
    #[arg(long)]
    force: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ScanProtocol {
    Tcp,
    Udp,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ReportFormat {
    Text,
    Json,
    Xml,
    Grep,
}

#[derive(Args, Debug)]
#[group(required = true, multiple = false)]
struct SourceArgs {
    /// Literal input data; for binary or private data use --input
    #[arg(long)]
    data: Option<String>,
    /// Input file, or '-' for stdin (maximum 64 MiB)
    #[arg(short = 'i', long)]
    input: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct InputArgs {
    #[command(flatten)]
    source: SourceArgs,
    #[arg(long, default_value = "raw", value_parser = ["raw", "text", "hex", "base64", "base64url", "base32", "url", "form", "binary"])]
    format: String,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ByteFormat {
    Hex,
    Base64,
    Text,
    Raw,
}

#[derive(Args, Debug)]
struct OutputArgs {
    /// File to create; existing files require --force
    #[arg(short = 'o', long)]
    out: Option<PathBuf>,
    #[arg(long, value_enum, default_value_t = ByteFormat::Hex)]
    output_format: ByteFormat,
    #[arg(long)]
    force: bool,
}

fn read_limited(mut input: impl Read, limit: usize) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    input
        .by_ref()
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > limit {
        return Err(format!("Input exceeds the {} byte limit", limit));
    }
    Ok(bytes)
}

fn read_file(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    read_limited(
        File::open(path).map_err(|e| format!("Cannot open {}: {e}", path.display()))?,
        limit,
    )
}

fn load_input(input: &InputArgs) -> Result<Vec<u8>, String> {
    let bytes = match (&input.source.data, &input.source.input) {
        (Some(data), None) if data.len() <= MAX_INPUT => data.as_bytes().to_vec(),
        (None, Some(path)) if path == Path::new("-") => {
            read_limited(io::stdin().lock(), MAX_INPUT)?
        }
        (None, Some(path)) => read_file(path, MAX_INPUT)?,
        _ => return Err("Provide exactly one of --data or --input (maximum 64 MiB)".into()),
    };
    crypto::decode(&input.format, &bytes)
}

fn write_output(data: &[u8], path: Option<&Path>, force: bool) -> Result<(), String> {
    if let Some(path) = path {
        let mut options = OpenOptions::new();
        options.write(true);
        if force {
            options.create(true).truncate(true);
        } else {
            options.create_new(true);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path).map_err(|e| {
            format!(
                "Cannot create {}: {e} (use --force only to replace an existing file)",
                path.display()
            )
        })?;
        file.write_all(data).map_err(|e| e.to_string())?;
        file.flush().map_err(|e| e.to_string())?;
        print_notice(&format!("Saved {} bytes to {}", data.len(), path.display()));
    } else {
        let mut stdout = io::stdout().lock();
        stdout.write_all(data).map_err(|e| e.to_string())?;
        stdout.flush().map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn emit_bytes(bytes: &[u8], output: &OutputArgs) -> Result<(), String> {
    let printable = match output.output_format {
        ByteFormat::Hex => hex::encode(bytes).into_bytes(),
        ByteFormat::Base64 => base64::engine::general_purpose::STANDARD
            .encode(bytes)
            .into_bytes(),
        ByteFormat::Text => {
            std::str::from_utf8(bytes)
                .map_err(|_| "Output is not UTF-8; choose raw, hex or base64")?;
            if output.out.is_none() && io::stdout().is_terminal() {
                report::terminal_safe(std::str::from_utf8(bytes).unwrap()).into_bytes()
            } else {
                bytes.to_vec()
            }
        }
        ByteFormat::Raw => {
            if output.out.is_none() && io::stdout().is_terminal() {
                return Err("Raw output needs --out FILE or redirected stdout".into());
            }
            bytes.to_vec()
        }
    };
    let mut printable = Zeroizing::new(printable);
    if output.out.is_none() && matches!(output.output_format, ByteFormat::Hex | ByteFormat::Base64)
    {
        printable.push(b'\n');
    }
    write_output(&printable, output.out.as_deref(), output.force)
}

fn emit_json(value: &impl serde::Serialize, out: Option<&Path>, force: bool) -> Result<(), String> {
    let mut json = serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?;
    json.push(b'\n');
    write_output(&json, out, force)
}

fn print_notice(message: &str) {
    if io::stderr().is_terminal() {
        eprintln!("{}", report::terminal_safe(message));
    } else {
        eprintln!("{message}");
    }
}

async fn execute(command: Commands) -> Result<i32, String> {
    match command {
        Commands::Scan(args) => {
            let protocol = match args.protocol {
                ScanProtocol::Tcp => scanner::Protocol::Tcp,
                ScanProtocol::Udp => scanner::Protocol::Udp,
            };
            let database = args
                .services_file
                .as_deref()
                .map(scanner::ServiceDatabase::load)
                .transpose()?;
            let ports = match (args.top_ports, database.as_ref()) {
                (Some(count), Some(database)) => database.top_ports(protocol, count as usize)?,
                _ => scanner::parse_ports(&args.ports)?,
            };
            let options = scanner::ScanOptions {
                timeout_ms: args.timeout_ms,
                concurrency: args.concurrency as usize,
                retries: args.retries,
                rate: args.rate,
                service_detection: args.service_detection,
                protocol,
                max_hosts: args.max_hosts as usize,
            };
            let mut scan = tokio::select! {
                result = scanner::scan(&args.targets, &ports, options) => result?,
                signal = tokio::signal::ctrl_c() => {
                    signal.map_err(|e| e.to_string())?;
                    return Err("Scan cancelled; no complete report was written".into());
                }
            };
            if let Some(database) = database {
                database.apply_hints(&mut scan);
                scan.warnings.push(format!(
                    "Loaded {} service entries from the supplied database; service-db-hint names are port mappings, not verified services.",
                    database.len()
                ));
            }
            let has_errors = scan
                .hosts
                .iter()
                .flat_map(|h| &h.ports)
                .any(|p| matches!(p.state, scanner::State::Error));
            let rendered = report::render(&scan, args.format, args.open)?;
            write_output(rendered.as_bytes(), args.out.as_deref(), args.force)?;
            return Ok(if has_errors { 2 } else { 0 });
        }
        Commands::Decode { input, output } => emit_bytes(&load_input(&input)?, &output)?,
        Commands::Decrypt {
            algorithm,
            input,
            key_file,
            key_format,
            nonce,
            aad,
            output,
        } => {
            let ciphertext = load_input(&input)?;
            let source_key = Zeroizing::new(read_file(&key_file, 64 * 1024)?);
            let key = Zeroizing::new(crypto::decode(&key_format, &source_key)?);
            let nonce = crypto::decode("hex", nonce.as_deref().unwrap_or("").as_bytes())?;
            let aad = crypto::decode("hex", aad.as_deref().unwrap_or("").as_bytes())?;
            if algorithm.ends_with("-cbc") {
                eprintln!("CBC has no authentication: valid padding does not prove the key or plaintext is correct.");
            }
            if algorithm.ends_with("-ctr") {
                eprintln!("CTR has no authentication: output does not prove the key or plaintext is correct. The counter is a full 128-bit big-endian value.");
            }
            let plaintext = Zeroizing::new(crypto::decrypt(
                &algorithm,
                &ciphertext,
                &key,
                &nonce,
                &aad,
            )?);
            emit_bytes(&plaintext, &output)?;
        }
        Commands::Analyze {
            input,
            top,
            out,
            force,
        } => emit_json(
            &analysis::analyze(&load_input(&input)?, top as usize),
            out.as_deref(),
            force,
        )?,
        Commands::Auto {
            input,
            depth,
            out,
            force,
        } => {
            let data = load_input(&input)?;
            if data.len() > analysis::MAX_LAYER_INPUT_BYTES {
                return Err("Layer exploration supports at most 1 MiB of decoded input".into());
            }
            emit_json(
                &analysis::decode_layers(&data, depth as usize),
                out.as_deref(),
                force,
            )?;
        }
        Commands::Xor {
            hex_bytes,
            key_hex,
            output,
        } => {
            let bytes = crypto::decode("hex", hex_bytes.as_bytes())?;
            if let Some(key) = key_hex {
                let key = Zeroizing::new(crypto::decode("hex", key.as_bytes())?);
                emit_bytes(&crypto::xor(&bytes, &key)?, &output)?;
            } else {
                emit_json(
                    &analysis::analyze(&bytes, 5),
                    output.out.as_deref(),
                    output.force,
                )?;
            }
        }
        Commands::Caesar { text, shift } => {
            let text = crypto::caesar(&text, shift);
            let mut bytes = if io::stdout().is_terminal() {
                report::terminal_safe(&text).into_bytes()
            } else {
                text.into_bytes()
            };
            bytes.push(b'\n');
            write_output(&bytes, None, false)?;
        }
        Commands::Nmap { args } => {
            let status = std::process::Command::new("nmap").args(args).status()
                .map_err(|e| format!("Cannot launch Nmap: {e}. Install Nmap separately and put it on PATH; the native `scan` command does not need it."))?;
            if let Some(code) = status.code() {
                return Ok(code);
            }
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;
                return Ok(status.signal().map_or(1, |signal| 128 + signal));
            }
            #[cfg(not(unix))]
            return Ok(1);
        }
    }
    Ok(0)
}

fn read_line_limited(reader: impl io::BufRead, limit: usize) -> Result<Option<String>, String> {
    use std::io::BufRead;
    let mut line = String::new();
    let n = reader
        .take(limit as u64 + 1)
        .read_line(&mut line)
        .map_err(|e| e.to_string())?;
    if n > limit {
        return Err(format!("Interactive line exceeds the {limit} byte limit"));
    }
    if n == 0 {
        return Ok(None);
    }
    Ok(Some(line.trim_end_matches(['\r', '\n']).to_owned()))
}

fn prompt(label: &str) -> Result<Option<String>, String> {
    print!("{label}");
    io::stdout().flush().map_err(|e| e.to_string())?;
    read_line_limited(io::stdin().lock(), MAX_INPUT)
}

async fn interactive() -> Result<i32, String> {
    loop {
        println!("\nIQAWX SECURITY LAB {}\n1) File analysis\n2) Hex analysis\n3) Text analysis\n4) Base64 decode\n5) Base32 decode\n6) URL decode\n7) Native network scan\n8) Exit\n9) Keyed decryption\n10) Explore encoding layers\nCLI help: iqawx_lab --help", env!("CARGO_PKG_VERSION"));
        let Some(choice) = prompt("MODE > ")? else {
            return Ok(0);
        };
        let mut args = vec!["iqawx_lab".to_string()];
        match choice.trim() {
            "8" | "q" | "exit" => return Ok(0),
            "1" => {
                let Some(path) = prompt("File path: ")? else {
                    return Ok(0);
                };
                args.extend(["analyze".into(), "--input".into(), path]);
            }
            "2" | "3" | "4" | "5" | "6" | "10" => {
                let Some(data) = prompt("Data: ")? else {
                    return Ok(0);
                };
                let (command, format) = match choice.trim() {
                    "2" => ("analyze", "hex"),
                    "3" => ("analyze", "text"),
                    "4" => ("decode", "base64"),
                    "5" => ("decode", "base32"),
                    "6" => ("decode", "url"),
                    _ => ("auto", "raw"),
                };
                args.extend([
                    command.into(),
                    "--data".into(),
                    data,
                    "--format".into(),
                    format.into(),
                ]);
            }
            "7" => {
                let Some(target) = prompt("Target IP / hostname / CIDR: ")? else {
                    return Ok(0);
                };
                let Some(ports) = prompt("Ports (blank = common ports): ")? else {
                    return Ok(0);
                };
                args.extend(["scan".into(), target, "--ports".into(), ports]);
            }
            "9" => {
                let Some(algorithm) = prompt("Algorithm (e.g. aes256-gcm): ")? else {
                    return Ok(0);
                };
                let Some(input) = prompt("Ciphertext file (raw bytes, AEAD includes tag): ")?
                else {
                    return Ok(0);
                };
                let Some(key) = prompt("Key file (raw bytes / RSA PEM): ")? else {
                    return Ok(0);
                };
                let Some(nonce) = prompt("Nonce / IV / full CTR counter in hex (blank for RSA): ")?
                else {
                    return Ok(0);
                };
                args.extend([
                    "decrypt".into(),
                    "--algorithm".into(),
                    algorithm,
                    "--input".into(),
                    input,
                    "--key-file".into(),
                    key,
                ]);
                if !nonce.is_empty() {
                    args.extend(["--nonce".into(), nonce]);
                }
                let Some(aad) = prompt("AAD in hex (blank if unused): ")? else {
                    return Ok(0);
                };
                if !aad.is_empty() {
                    args.extend(["--aad".into(), aad]);
                }
                let Some(out) = prompt("Output file (blank = hex on screen): ")? else {
                    return Ok(0);
                };
                if !out.is_empty() {
                    args.extend(["--out".into(), out, "--output-format".into(), "raw".into()]);
                }
            }
            _ => {
                eprintln!("Choose 1–10.");
                continue;
            }
        }
        match Cli::try_parse_from(args) {
            Ok(Cli {
                command: Some(command),
            }) => {
                if let Err(error) = execute(command).await {
                    print_notice(&format!("Error: {error}"));
                }
            }
            Err(error) => eprintln!("{error}"),
            _ => {}
        }
    }
}

// Preserve v3 positional scan invocations without interpreting normal hostname lists as ports.
fn compatible_args() -> Vec<OsString> {
    let mut args: Vec<OsString> = std::env::args_os().collect();
    if (args.len() == 4 || args.len() == 5) && args[1] == "scan" {
        if let Some(ports) = args[3].to_str() {
            if !ports.is_empty()
                && ports
                    .bytes()
                    .all(|b| b.is_ascii_digit() || b == b',' || b == b'-')
                && (args.len() == 4 || args[4].to_str().is_some_and(|s| s.parse::<u64>().is_ok()))
            {
                let old = args.clone();
                args = vec![
                    old[0].clone(),
                    old[1].clone(),
                    old[2].clone(),
                    "--ports".into(),
                    old[3].clone(),
                ];
                if old.len() == 5 {
                    args.extend(["--timeout-ms".into(), old[4].clone()]);
                }
            }
        }
    }
    args
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse_from(compatible_args());
    let result = match cli.command {
        Some(command) => execute(command).await,
        None => interactive().await,
    };
    match result {
        Ok(code) if code != 0 => std::process::exit(code),
        Ok(_) => {}
        Err(error) => {
            print_notice(&format!("Error: {error}"));
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod input_tests {
    use super::read_line_limited;
    use std::io::Cursor;

    #[test]
    fn interactive_reads_are_bounded_and_preserve_line_boundaries() {
        let mut reader = Cursor::new(b"first\nsecond\n");
        assert_eq!(
            read_line_limited(&mut reader, 8).unwrap(),
            Some("first".into())
        );
        assert_eq!(
            read_line_limited(&mut reader, 8).unwrap(),
            Some("second".into())
        );
        assert_eq!(read_line_limited(&mut reader, 8).unwrap(), None);
        let mut oversized = Cursor::new(b"01234567890123456789");
        assert!(read_line_limited(&mut oversized, 8).is_err());
        assert_eq!(oversized.position(), 9);
        assert!(read_line_limited(Cursor::new([0xff]), 8).is_err());
    }
}
