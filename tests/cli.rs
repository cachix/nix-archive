#![cfg(unix)]

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::process::{Command, Stdio};

#[test]
fn pack_and_unpack_round_trip() {
    let tmp = tempfile::tempdir().unwrap();
    let source = tmp.path().join("source");
    let archive = tmp.path().join("tree.nar");
    let restored = tmp.path().join("restored");

    fs::create_dir(&source).unwrap();
    fs::write(source.join("plain"), b"plain contents").unwrap();
    fs::write(source.join("executable"), b"#!/bin/sh\n").unwrap();
    fs::set_permissions(source.join("executable"), fs::Permissions::from_mode(0o755)).unwrap();
    symlink("plain", source.join("link")).unwrap();

    let pack = Command::new(env!("CARGO_BIN_EXE_nix-archive"))
        .args(["pack"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(
        pack.status.success(),
        "{}",
        String::from_utf8_lossy(&pack.stderr)
    );

    let unpack = Command::new(env!("CARGO_BIN_EXE_nix-archive"))
        .args(["unpack"])
        .arg(&archive)
        .arg(&restored)
        .output()
        .unwrap();
    assert!(
        unpack.status.success(),
        "{}",
        String::from_utf8_lossy(&unpack.stderr)
    );

    assert_eq!(fs::read(restored.join("plain")).unwrap(), b"plain contents");
    assert_ne!(
        fs::metadata(restored.join("executable"))
            .unwrap()
            .permissions()
            .mode()
            & 0o100,
        0
    );
    assert_eq!(
        fs::read_link(restored.join("link")).unwrap(),
        std::path::Path::new("plain")
    );
}

#[test]
fn dash_uses_standard_io() {
    let tmp = tempfile::tempdir().unwrap();
    let source = tmp.path().join("source");
    let restored = tmp.path().join("restored");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("file"), b"over the pipe").unwrap();

    let packed = Command::new(env!("CARGO_BIN_EXE_nix-archive"))
        .args(["pack", "-"])
        .arg(&source)
        .output()
        .unwrap();
    assert!(
        packed.status.success(),
        "{}",
        String::from_utf8_lossy(&packed.stderr)
    );

    let mut child = Command::new(env!("CARGO_BIN_EXE_nix-archive"))
        .args(["unpack", "-"])
        .arg(&restored)
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&packed.stdout)
        .unwrap();
    assert!(child.wait().unwrap().success());
    assert_eq!(fs::read(restored.join("file")).unwrap(), b"over the pipe");
}

/// The case hack changes the NAR, so the CLI has to let a caller pick it
/// rather than inferring it from the host.
#[test]
fn case_hack_flag_changes_the_archive() {
    let tmp = tempfile::tempdir().unwrap();
    let source = tmp.path().join("source");
    fs::create_dir(&source).unwrap();
    // A name that only the case hack rewrites.
    fs::write(source.join("notes~nix~case~hack~1"), b"mine").unwrap();

    let pack = |mode: &str, out: &std::path::Path| {
        let status = Command::new(env!("CARGO_BIN_EXE_nix-archive"))
            .args(["pack", "--case-hack", mode])
            .arg(out)
            .arg(&source)
            .output()
            .unwrap();
        assert!(
            status.status.success(),
            "{}",
            String::from_utf8_lossy(&status.stderr)
        );
        fs::read(out).unwrap()
    };

    let enabled = pack("enabled", &tmp.path().join("on.nar"));
    let disabled = pack("disabled", &tmp.path().join("off.nar"));
    let native = pack("native", &tmp.path().join("native.nar"));

    assert_ne!(
        enabled, disabled,
        "the flag must actually reach the encoder"
    );
    // `native` is Nix's platform default, which is `disabled` off macOS.
    let expected_native = if cfg!(target_os = "macos") {
        &enabled
    } else {
        &disabled
    };
    assert_eq!(&native, expected_native, "native must follow the platform");

    let rejected = Command::new(env!("CARGO_BIN_EXE_nix-archive"))
        .args(["pack", "--case-hack", "sometimes"])
        .arg(tmp.path().join("bad.nar"))
        .arg(&source)
        .output()
        .unwrap();
    assert!(!rejected.status.success(), "invalid mode must be rejected");
}
