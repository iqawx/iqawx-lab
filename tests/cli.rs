use std::fs;
use std::io::Write;
use std::net::TcpListener;
use std::process::{Command, Output, Stdio};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_iqawx_lab"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn decoding_is_binary_safe_and_rejects_bad_padding() {
    let out = run(&[
        "decode",
        "--format",
        "base64",
        "--data",
        "AP+A",
        "--output-format",
        "raw",
    ]);
    assert!(out.status.success());
    assert_eq!(out.stdout, [0, 255, 128]);
    let out = run(&["decode", "--format", "base64", "--data", "Z==="]);
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    let out = run(&["decode", "--format", "hex", "--data", "عربي"]);
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn existing_outputs_are_not_overwritten_without_force() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("output.bin");
    fs::write(&file, b"original").unwrap();
    let args = [
        "decode",
        "--data",
        "hello",
        "--output-format",
        "raw",
        "--out",
        file.to_str().unwrap(),
    ];
    assert!(!run(&args).status.success());
    assert_eq!(fs::read(&file).unwrap(), b"original");
    let mut forced = args.to_vec();
    forced.push("--force");
    assert!(run(&forced).status.success());
    assert_eq!(fs::read(&file).unwrap(), b"hello");
}

#[test]
fn aead_cli_uses_key_file_and_never_writes_on_authentication_failure() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("key.bin");
    fs::write(&key, [0u8; 16]).unwrap();
    let out_file = dir.path().join("plaintext.bin");
    let valid = "0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf";
    let bad = "0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bdde";
    let arguments = |ciphertext| {
        vec![
            "decrypt",
            "--algorithm",
            "aes128-gcm",
            "--format",
            "hex",
            "--data",
            ciphertext,
            "--key-file",
            key.to_str().unwrap(),
            "--nonce",
            "000000000000000000000000",
            "--output-format",
            "raw",
            "--out",
            out_file.to_str().unwrap(),
        ]
    };
    let out = run(&arguments(bad));
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    assert!(!out_file.exists());
    assert!(run(&arguments(valid)).status.success());
    assert_eq!(fs::read(&out_file).unwrap(), [0u8; 16]);
    // A failed operation must not even truncate an explicitly replaceable output.
    let mut bad_force = arguments(bad);
    bad_force.push("--force");
    assert!(!run(&bad_force).status.success());
    assert_eq!(fs::read(&out_file).unwrap(), [0u8; 16]);
}

#[test]
fn cli_validates_parameters_and_exits_menu_at_eof() {
    for args in [
        vec!["scan", "127.0.0.1", "--ports", "80-2"],
        vec!["scan", "127.0.0.1", "--timeout-ms", "0"],
        vec!["scan", "127.0.0.1", "--concurrency", "0"],
        vec!["decode", "--data", "x", "--input", "x"],
        vec!["analyze", "--data", "x", "--top", "0"],
    ] {
        assert!(!run(&args).status.success(), "{args:?}");
    }
    let out = Command::new(env!("CARGO_BIN_EXE_iqawx_lab"))
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(run(&["--help"]).status.success());
    assert!(run(&["decrypt", "--help"]).status.success());
}

#[test]
fn native_scan_reports_observed_service_on_loopback() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.write_all(b"SSH-2.0-LocalTest\r\n").unwrap();
    });
    let out = run(&[
        "scan",
        "127.0.0.1",
        "-p",
        &port.to_string(),
        "--service-detection",
        "--format",
        "json",
        "--retries",
        "0",
    ]);
    server.join().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let result = &report["hosts"][0]["ports"][0];
    assert_eq!(result["state"], "open");
    assert_eq!(result["service"]["name"], "ssh");
    assert_eq!(result["service"]["method"], "observed");
}

#[cfg(unix)]
#[test]
fn nmap_bridge_preserves_argument_boundaries_and_exit_status() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("nmap");
    fs::write(&script, "#!/bin/sh\nprintf '%s\\n' \"$@\"\nexit 7\n").unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_iqawx_lab"))
        .env("PATH", dir.path())
        .args([
            "nmap",
            "--",
            "--version",
            "literal argument with spaces",
            ";not-a-shell-command",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(7));
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        "--version\nliteral argument with spaces\n;not-a-shell-command\n"
    );
}

#[test]
fn services_database_selects_top_ports_and_labels_them_as_hints() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("services.txt");
    fs::write(
        &database,
        format!("lab-service {port}/tcp 0.9\ndns 53/udp 1.0\nother 1/tcp 0.1\n"),
    )
    .unwrap();
    let out = run(&[
        "scan",
        "127.0.0.1",
        "--services-file",
        database.to_str().unwrap(),
        "--top-ports",
        "1",
        "--format",
        "json",
        "--retries",
        "0",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let ports = report["hosts"][0]["ports"].as_array().unwrap();
    assert_eq!(ports.len(), 1);
    assert_eq!(ports[0]["port"], port);
    assert_eq!(ports[0]["state"], "open");
    assert_eq!(ports[0]["service"]["name"], "lab-service");
    assert_eq!(ports[0]["service"]["method"], "service-db-hint");
    assert!(ports[0]["service"]["evidence"].is_null());
    for args in [
        vec!["scan", "127.0.0.1", "--top-ports", "1"],
        vec![
            "scan",
            "127.0.0.1",
            "--servicedb",
            database.to_str().unwrap(),
            "--top-ports",
            "1",
            "-p",
            "80",
        ],
        vec![
            "scan",
            "127.0.0.1",
            "--servicedb",
            database.to_str().unwrap(),
            "--top-ports",
            "5",
        ],
    ] {
        let out = run(&args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(out.stdout.is_empty());
    }
}

#[test]
fn ctr_cli_known_answer_and_overflow_preserve_existing_output() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("key.hex");
    fs::write(&key, "2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    let output = dir.path().join("plaintext.bin");
    let out = run(&[
        "decrypt",
        "--algorithm",
        "aes128-ctr",
        "--key-file",
        key.to_str().unwrap(),
        "--key-format",
        "hex",
        "--nonce",
        "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        "--format",
        "hex",
        "--data",
        "874d6191b620e3261bef6864990db6ce",
        "--output-format",
        "raw",
        "--out",
        output.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let expected = hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap();
    assert_eq!(fs::read(&output).unwrap(), expected);
    let out = run(&[
        "decrypt",
        "--algorithm",
        "aes128-ctr",
        "--key-file",
        key.to_str().unwrap(),
        "--key-format",
        "hex",
        "--nonce",
        "ffffffffffffffffffffffffffffffff",
        "--format",
        "hex",
        "--data",
        "0000000000000000000000000000000000",
        "--output-format",
        "raw",
        "--out",
        output.to_str().unwrap(),
        "--force",
    ]);
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    assert_eq!(fs::read(&output).unwrap(), expected);
}

#[test]
fn caesar_redirected_output_preserves_multiline_unicode() {
    let out = run(&["caesar", "--text", "A\nB\tعربي", "--shift", "1"]);
    assert!(out.status.success());
    assert_eq!(out.stdout, "B\nC\tعربي\n".as_bytes());
}

#[test]
fn encrypted_files_roundtrip_and_failures_preserve_outputs_and_keys() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("key.bin");
    let encrypted = dir.path().join("sealed.json");
    let out = dir.path().join("plain.bin");
    let key_s = key.to_str().unwrap();
    let enc_s = encrypted.to_str().unwrap();
    let out_s = out.to_str().unwrap();
    assert!(run(&["keygen", "--out", key_s]).status.success());
    let original_key = fs::read(&key).unwrap();
    assert_eq!(original_key.len(), 32);
    assert!(!run(&["keygen", "--out", key_s]).status.success());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&key).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    assert!(run(&[
        "encrypt",
        "--data",
        "عربي 🔐",
        "--key-file",
        key_s,
        "--out",
        enc_s
    ])
    .status
    .success());
    assert!(run(&[
        "open",
        "--input",
        enc_s,
        "--key-file",
        key_s,
        "--out",
        out_s,
        "--output-format",
        "raw"
    ])
    .status
    .success());
    assert_eq!(fs::read(&out).unwrap(), "عربي 🔐".as_bytes());
    assert!(!run(&[
        "encrypt",
        "--data",
        "x",
        "--key-file",
        key_s,
        "--out",
        key_s,
        "--force"
    ])
    .status
    .success());
    assert!(!run(&[
        "open",
        "--input",
        enc_s,
        "--key-file",
        key_s,
        "--out",
        key_s,
        "--force"
    ])
    .status
    .success());
    assert_eq!(fs::read(&key).unwrap(), original_key);
    let mut value: serde_json::Value =
        serde_json::from_slice(&fs::read(&encrypted).unwrap()).unwrap();
    value["aad_base64"] = "dGFtcGVyZWQ=".into();
    fs::write(&encrypted, serde_json::to_vec(&value).unwrap()).unwrap();
    let failed = run(&[
        "open",
        "--input",
        enc_s,
        "--key-file",
        key_s,
        "--out",
        out_s,
        "--output-format",
        "raw",
        "--force",
    ]);
    assert_eq!(failed.status.code(), Some(2));
    assert!(failed.stdout.is_empty());
    assert_eq!(fs::read(&out).unwrap(), "عربي 🔐".as_bytes());
}

#[test]
fn hashes_verify_and_human_analysis_preserves_json_default() {
    let hash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    assert!(run(&["hash", "--data", "abc", "--expected", hash])
        .status
        .success());
    let failed = run(&["hash", "--data", "abd", "--expected", hash]);
    assert_eq!(failed.status.code(), Some(2));
    assert!(failed.stdout.is_empty());
    for command in ["analyze", "auto"] {
        let result = run(&[command, "--data", "Njg2OQ=="]);
        assert!(serde_json::from_slice::<serde_json::Value>(&result.stdout).is_ok());
        let text = run(&[command, "--data", "Njg2OQ==", "--report-format", "text"]);
        assert!(text.status.success());
        assert!(String::from_utf8_lossy(&text.stdout).contains("IQAWX"));
    }
}

#[test]
fn target_files_exclusions_and_export_formats_work_on_loopback() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port().to_string();
    let dir = tempfile::tempdir().unwrap();
    let targets = dir.path().join("targets.txt");
    fs::write(
        &targets,
        "# local fixtures\n127.0.0.1\n127.0.0.2 # excluded\n",
    )
    .unwrap();
    for format in ["json", "csv", "html", "xml"] {
        let result = run(&[
            "scan",
            "--targets-file",
            targets.to_str().unwrap(),
            "--exclude",
            "127.0.0.2/32",
            "-p",
            &port,
            "--format",
            format,
            "--progress",
        ]);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(String::from_utf8_lossy(&result.stderr).contains("Progress:"));
        assert!(!String::from_utf8_lossy(&result.stdout).contains("Progress:"));
        let text = String::from_utf8_lossy(&result.stdout);
        match format {
            "json" => {
                let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
                assert_eq!(report["total_jobs"], 1);
                assert_eq!(report["completed_jobs"], 1);
                assert_eq!(report["complete"], true);
                assert_eq!(report["summary"]["open"], 1);
            }
            "csv" => assert!(text.starts_with("record,complete,")),
            "html" => assert!(text.starts_with("<!doctype html>")),
            "xml" => {
                assert!(text.contains("<completion complete=\"true\" total=\"1\" completed=\"1\""))
            }
            _ => unreachable!(),
        }
    }
    let result = run(&["scan", "127.0.0.1", "--exclude", "127.0.0.0/8", "-p", &port]);
    assert_eq!(result.status.code(), Some(2));
}

#[test]
fn deadline_returns_partial_json_and_interrupted_status() {
    // Keep a UDP port open but silent, guaranteeing a pending probe at the deadline.
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = socket.local_addr().unwrap().port().to_string();
    let result = run(&[
        "scan",
        "127.0.0.1",
        "-p",
        &port,
        "--protocol",
        "udp",
        "--timeout-ms",
        "5000",
        "--deadline-secs",
        "1",
        "--format",
        "json",
    ]);
    assert_eq!(result.status.code(), Some(130));
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["complete"], false);
    assert_eq!(report["total_jobs"], 1);
    assert_eq!(report["completed_jobs"], 0);
    assert_eq!(report["hosts"][0]["ports"].as_array().unwrap().len(), 0);
}
