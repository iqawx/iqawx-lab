use std::process::{Command, Stdio};

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_iqaw"))
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

#[test]
fn short_command_opens_terminal_menu_without_a_browser() {
    for args in [vec![], vec!["menu"]] {
        let output = run(&args);
        assert!(output.status.success());
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(text.contains("MODE >"));
        assert!(text.contains("CLI help: iqaw --help"));
        assert!(!text.contains("http://"));
    }
}

#[test]
fn public_command_exposes_terminal_help_and_has_no_ui_subcommand() {
    let output = run(&["--help"]);
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("menu"));
    assert!(text.contains("scan"));
    assert!(!text.contains("graphical"));
    assert_eq!(run(&["ui", "--help"]).status.code(), Some(2));
    let version = run(&["--version"]);
    assert!(version.status.success());
    assert!(String::from_utf8(version.stdout)
        .unwrap()
        .starts_with("iqaw "));
}

#[test]
fn short_command_preserves_binary_output_and_keyed_operations() {
    let args = [
        "decode",
        "--format",
        "base64",
        "--data",
        "AP+A",
        "--output-format",
        "raw",
    ];
    let short = run(&args);
    let original = Command::new(env!("CARGO_BIN_EXE_iqawx_lab"))
        .args(args)
        .output()
        .unwrap();
    assert!(short.status.success());
    assert!(original.status.success());
    assert_eq!(short.stdout, [0, 255, 128]);
    assert_eq!(short.stdout, original.stdout);
    let vector = run(&[
        "decrypt",
        "--algorithm",
        "aes128-ctr",
        "--input",
        "examples/aes128-ctr-ciphertext.hex",
        "--format",
        "hex",
        "--key-file",
        "examples/aes128-ctr-key.hex",
        "--key-format",
        "hex",
        "--nonce",
        "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
    ]);
    assert!(vector.status.success());
    assert_eq!(
        String::from_utf8(vector.stdout).unwrap().trim(),
        "6bc1bee22e409f96e93d7e117393172a"
    );
}
