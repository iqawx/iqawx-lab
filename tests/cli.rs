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
