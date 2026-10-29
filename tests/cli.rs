//! CLI behavior tests (SPEC.md section 8).

#[cfg(all(unix, not(target_vendor = "apple")))]
use std::ffi::OsStr;
use std::fs;
#[cfg(all(unix, not(target_vendor = "apple")))]
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use sha2::{Digest, Sha256};

const BIN: &str = env!("CARGO_BIN_EXE_btsum");

static TMP_COUNTER: AtomicUsize = AtomicUsize::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new(prefix: &str) -> Self {
        let n = TMP_COUNTER.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!("{prefix}-{}-{}", std::process::id(), n));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn write(&self, name: &str, data: &[u8]) -> PathBuf {
        let p = self.0.join(name);
        fs::write(&p, data).unwrap();
        p
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run_in(dir: &Path, args: &[&str]) -> (i32, Vec<u8>, Vec<u8>) {
    let out = Command::new(BIN)
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap();
    (out.status.code().unwrap_or(-1), out.stdout, out.stderr)
}

fn hex_sha256(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

// SPEC §11 V.1 and V.2
const HELLO_BTIH: &str = "7fe09bdbcee8c4d588e6f4193973d7cdd12d380f";
const HELLO_BTMH: &str = "fcd26dfd1a8902f1832ad1613e82fac6d80e25eb2a59335c3d7ad46dab0dd633";
const HELLO_TORRENT_SHA: &str = "eb975502da8a14ceb51eaeffd3e15d68d8d10f00e7a5409c30e79595d867b368";
const HELLO_DATA: &[u8] = b"hello btsum\n";

#[test]
fn version_and_help() {
    let t = TempDir::new("btsum-cli");
    let (rc, out, _) = run_in(t.path(), &["--version"]);
    assert_eq!(rc, 0);
    assert!(String::from_utf8_lossy(&out).contains(env!("CARGO_PKG_VERSION")));

    let (rc, out, _) = run_in(t.path(), &["--help"]);
    assert_eq!(rc, 0);
    assert!(
        String::from_utf8_lossy(&out)
            .to_lowercase()
            .contains("usage")
    );
}

#[test]
fn no_args_is_usage_error() {
    let t = TempDir::new("btsum-cli");
    let (rc, _, _) = run_in(t.path(), &[]);
    assert_eq!(rc, 2);
}

#[test]
fn default_magnet_output() {
    let t = TempDir::new("btsum-cli");
    t.write("hello.txt", HELLO_DATA);
    let (rc, out, _) = run_in(t.path(), &["hello.txt"]);
    assert_eq!(rc, 0);
    let expected =
        format!("magnet:?xt=urn:btih:{HELLO_BTIH}&xt=urn:btmh:1220{HELLO_BTMH}&dn=hello.txt\n");
    assert_eq!(out, expected.as_bytes());
}

#[test]
fn output_filters() {
    let t = TempDir::new("btsum-cli");
    t.write("hello.txt", HELLO_DATA);

    let (rc, out, _) = run_in(t.path(), &["-1", "hello.txt"]);
    assert_eq!(rc, 0);
    assert_eq!(out, format!("{HELLO_BTIH}  hello.txt\n").as_bytes());

    let (rc, out, _) = run_in(t.path(), &["--v2", "hello.txt"]);
    assert_eq!(rc, 0);
    assert_eq!(out, format!("{HELLO_BTMH}  hello.txt\n").as_bytes());

    let (rc, out, _) = run_in(t.path(), &["--hashes", "hello.txt"]);
    assert_eq!(rc, 0);
    let s = String::from_utf8_lossy(&out);
    let lines: Vec<&str> = s.lines().collect();
    assert_eq!(
        lines,
        vec![
            format!("{HELLO_BTIH}  hello.txt"),
            format!("{HELLO_BTMH}  hello.txt"),
        ]
    );

    let (rc, out, _) = run_in(t.path(), &["--pair", "hello.txt"]);
    assert_eq!(rc, 0);
    assert_eq!(
        out,
        format!("{HELLO_BTIH}+{HELLO_BTMH}  hello.txt\n").as_bytes()
    );

    for combo in [
        ["-1", "-2"],
        ["-1", "--hashes"],
        ["-1", "--pair"],
        ["-2", "--pair"],
        ["--hashes", "--pair"],
    ] {
        let mut args: Vec<&str> = combo.to_vec();
        args.push("hello.txt");
        let (rc, _, _) = run_in(t.path(), &args);
        assert_eq!(rc, 2, "combo: {combo:?}");
    }
}

#[test]
fn multiple_files() {
    let t = TempDir::new("btsum-cli");
    t.write("hello.txt", HELLO_DATA);
    t.write("empty.bin", b"");
    let (rc, out, _) = run_in(t.path(), &["hello.txt", "empty.bin"]);
    assert_eq!(rc, 0);
    let s = String::from_utf8_lossy(&out);
    let lines: Vec<&str> = s.lines().collect();
    assert_eq!(lines.len(), 2);
    assert!(lines[0].contains("dn=hello.txt"));
    assert!(lines[1].contains("dn=empty.bin"));
}

#[test]
fn name_override_matches_original() {
    let t = TempDir::new("btsum-cli");
    t.write("hello.txt", HELLO_DATA);
    t.write("renamed-copy.bin", HELLO_DATA);

    let (_, orig, _) = run_in(t.path(), &["hello.txt"]);
    let (_, renamed, _) = run_in(t.path(), &["-n", "hello.txt", "renamed-copy.bin"]);
    assert_eq!(orig, renamed);
    assert!(String::from_utf8_lossy(&renamed).contains("dn=hello.txt"));
}

#[test]
fn name_override_validation() {
    let t = TempDir::new("btsum-cli");
    t.write("hello.txt", HELLO_DATA);
    assert_eq!(run_in(t.path(), &["-n", "", "hello.txt"]).0, 2);
    assert_eq!(run_in(t.path(), &["-n", "a/b", "hello.txt"]).0, 2);
    t.write("split.tmp.bin", b"");
    assert_eq!(
        run_in(t.path(), &["-n", "x", "hello.txt", "split.tmp.bin"]).0,
        2
    );
}

#[test]
fn torrent_output() {
    let t = TempDir::new("btsum-cli");
    t.write("hello.txt", HELLO_DATA);

    // Default path: input + ".torrent"
    let (rc, _, _) = run_in(t.path(), &["-t", "hello.txt"]);
    assert_eq!(rc, 0);
    let bytes = fs::read(t.path().join("hello.txt.torrent")).unwrap();
    assert_eq!(hex_sha256(&bytes), HELLO_TORRENT_SHA);

    // Explicit path, equals form
    let (rc, _, _) = run_in(t.path(), &["--torrent=explicit.torrent", "hello.txt"]);
    assert_eq!(rc, 0);
    assert!(t.path().join("explicit.torrent").exists());

    // Explicit path with two files is rejected
    t.write("two.bin", b"B");
    let (rc, _, _) = run_in(t.path(), &["--torrent=x.torrent", "hello.txt", "two.bin"]);
    assert_eq!(rc, 2);
}

#[test]
fn torrent_output_name_and_path() {
    let t = TempDir::new("btsum-cli");
    t.write("hello.txt", HELLO_DATA);

    // bare name (space form)
    let (rc, _, _) = run_in(t.path(), &["-t", "named.torrent", "hello.txt"]);
    assert_eq!(rc, 0);
    let p = t.path().join("named.torrent");
    assert!(p.exists());
    let bytes = fs::read(&p).unwrap();
    assert_eq!(hex_sha256(&bytes), HELLO_TORRENT_SHA);

    // bare name (equals form)
    let (rc, _, _) = run_in(t.path(), &["--torrent=eq.torrent", "hello.txt"]);
    assert_eq!(rc, 0);
    assert!(t.path().join("eq.torrent").exists());

    // relative path with separator
    fs::create_dir_all(t.path().join("sub")).unwrap();
    let rel = "sub/in.torrent";
    let (rc, _, _) = run_in(t.path(), &["-t", rel, "hello.txt"]);
    assert_eq!(rc, 0);
    assert!(t.path().join(rel).exists());

    // absolute path
    let abs = t.path().join("abs.torrent");
    let abs_str = abs.to_str().unwrap();
    let (rc, _, _) = run_in(t.path(), &["-t", abs_str, "hello.txt"]);
    assert_eq!(rc, 0);
    assert!(abs.exists());

    // flag after positional
    let (rc, _, _) = run_in(t.path(), &["hello.txt", "-t", "after.torrent"]);
    assert_eq!(rc, 0);
    assert!(t.path().join("after.torrent").exists());
}

#[test]
fn torrent_value_with_no_positional_is_input() {
    let t = TempDir::new("btsum-cli");
    t.write("hello.txt", HELLO_DATA);
    let (rc, _, _) = run_in(t.path(), &["-t", "hello.txt"]);
    assert_eq!(rc, 0);
    assert!(t.path().join("hello.txt.torrent").exists());
}

#[test]
fn check_inline_ok() {
    let t = TempDir::new("btsum-cli");
    t.write("hello.txt", HELLO_DATA);

    let refs: Vec<String> = vec![
        HELLO_BTIH.to_string(),
        HELLO_BTMH.to_string(),
        format!("1220{HELLO_BTMH}"),
        format!("{HELLO_BTIH}+{HELLO_BTMH}"),
        format!("magnet:?xt=urn:btih:{HELLO_BTIH}&xt=urn:btmh:1220{HELLO_BTMH}&dn=hello.txt"),
        format!("xt=urn:btih:{HELLO_BTIH}&dn=hello.txt"),
    ];
    for r in &refs {
        let (rc, out, _) = run_in(t.path(), &["-c", r, "hello.txt"]);
        assert_eq!(rc, 0, "ref: {r}");
        assert!(String::from_utf8_lossy(&out).contains(": OK ("), "ref: {r}");
    }
}

#[test]
fn check_labels() {
    let t = TempDir::new("btsum-cli");
    t.write("hello.txt", HELLO_DATA);

    let (rc, out, _) = run_in(
        t.path(),
        &["-c", &format!("{HELLO_BTIH}+{HELLO_BTMH}"), "hello.txt"],
    );
    assert_eq!(rc, 0);
    assert!(String::from_utf8_lossy(&out).contains(": OK (v1+v2)"));

    let (_, out, _) = run_in(t.path(), &["-c", HELLO_BTIH, "hello.txt"]);
    assert!(String::from_utf8_lossy(&out).contains(": OK (v1)"));

    let (_, out, _) = run_in(t.path(), &["-c", HELLO_BTMH, "hello.txt"]);
    assert!(String::from_utf8_lossy(&out).contains(": OK (v2)"));
}

#[test]
fn check_mismatch_exit_1() {
    let t = TempDir::new("btsum-cli");
    t.write("hello.txt", HELLO_DATA);

    let zero_v1 = "0".repeat(40);
    let (rc, out, err) = run_in(t.path(), &["-c", &zero_v1, "hello.txt"]);
    assert_eq!(rc, 1);
    assert!(String::from_utf8_lossy(&out).contains(": FAILED (v1 mismatch)"));
    assert!(String::from_utf8_lossy(&err).contains("--name"));

    let zero_v2 = "0".repeat(64);
    let (rc, out, _) = run_in(
        t.path(),
        &["-c", &format!("{zero_v1}+{zero_v2}"), "hello.txt"],
    );
    assert_eq!(rc, 1);
    assert!(String::from_utf8_lossy(&out).contains(": FAILED (v1+v2 mismatch)"));
}

#[test]
fn check_renamed_file_via_dn() {
    let t = TempDir::new("btsum-cli");
    t.write("renamed.iso", HELLO_DATA);

    let r = format!("magnet:?xt=urn:btih:{HELLO_BTIH}&xt=urn:btmh:1220{HELLO_BTMH}&dn=hello.txt");
    let (rc, out, _) = run_in(t.path(), &["-c", &r, "renamed.iso"]);
    assert_eq!(rc, 0);
    assert!(String::from_utf8_lossy(&out).contains("renamed.iso: OK (v1+v2)"));
}

#[test]
fn check_renamed_file_via_name_flag() {
    let t = TempDir::new("btsum-cli");
    t.write("renamed.iso", HELLO_DATA);
    let (rc, out, _) = run_in(
        t.path(),
        &["-n", "hello.txt", "-c", HELLO_BTIH, "renamed.iso"],
    );
    assert_eq!(rc, 0);
    assert!(String::from_utf8_lossy(&out).contains(": OK (v1)"));
}

#[test]
fn check_missing_file_exit_2() {
    let t = TempDir::new("btsum-cli");
    let (rc, _, _) = run_in(t.path(), &["-c", &"0".repeat(40), "no-such.bin"]);
    assert_eq!(rc, 2);
}

#[test]
fn check_batch() {
    let t = TempDir::new("btsum-cli");
    t.write("hello.txt", HELLO_DATA);
    t.write("empty.bin", b"");

    let (_, listing, _) = run_in(t.path(), &["hello.txt", "empty.bin"]);
    fs::write(t.path().join("sums.magnets"), &listing).unwrap();

    let (rc, out, _) = run_in(t.path(), &["-c", "sums.magnets"]);
    assert_eq!(rc, 0);
    let count = String::from_utf8_lossy(&out).matches(": OK (").count();
    assert_eq!(count, 2);

    // Corrupt one and re-check.
    fs::write(t.path().join("hello.txt"), b"corrupted!").unwrap();
    let (rc, out, _) = run_in(t.path(), &["-c", "sums.magnets"]);
    assert_eq!(rc, 1);
    let s = String::from_utf8_lossy(&out);
    assert!(s.contains("hello.txt: FAILED"));
    assert!(s.contains("empty.bin: OK"));
}

#[test]
fn check_batch_bad_line() {
    let t = TempDir::new("btsum-cli");
    t.write("hello.txt", HELLO_DATA);
    let (_, listing, _) = run_in(t.path(), &["hello.txt"]);
    let mut contents = b"# comment\n\n".to_vec();
    contents.extend_from_slice(&listing);
    contents.extend_from_slice(b"garbage-without-hash\n");
    fs::write(t.path().join("sums.magnets"), contents).unwrap();

    let (rc, _, err) = run_in(t.path(), &["-c", "sums.magnets"]);
    assert_eq!(rc, 2);
    assert!(String::from_utf8_lossy(&err).contains("not a magnet or hash line"));
}

#[test]
fn check_extra_operand_after_listing() {
    let t = TempDir::new("btsum-cli");
    t.write("hello.txt", HELLO_DATA);
    let (_, listing, _) = run_in(t.path(), &["hello.txt"]);
    fs::write(t.path().join("sums.magnets"), &listing).unwrap();
    let (rc, _, _) = run_in(t.path(), &["-c", "sums.magnets", "hello.txt"]);
    assert_eq!(rc, 2);
}

#[test]
fn flag_combination_errors() {
    let t = TempDir::new("btsum-cli");
    t.write("hello.txt", HELLO_DATA);

    let (rc, _, _) = run_in(
        t.path(),
        &["-t", "x.torrent", "-c", &"0".repeat(40), "hello.txt"],
    );
    assert_eq!(rc, 2);

    let (rc, _, _) = run_in(t.path(), &["-1", "-c", &"0".repeat(40), "hello.txt"]);
    assert_eq!(rc, 2);
}

#[test]
fn unicode_name_end_to_end() {
    let t = TempDir::new("btsum-cli");
    let name = "déjà vu.bin";
    t.write(name, b"unicode content\n");

    let (rc, out, _) = run_in(t.path(), &[name]);
    assert_eq!(rc, 0);
    assert!(String::from_utf8_lossy(&out).contains("dn=d%C3%A9j%C3%A0%20vu.bin"));

    // Round-trip through -c.
    let magnet_line = String::from_utf8_lossy(&out).trim().to_string();
    let (rc, out2, _) = run_in(t.path(), &["-c", &magnet_line, name]);
    assert_eq!(rc, 0);
    assert!(String::from_utf8_lossy(&out2).contains(": OK (v1+v2)"));
}

#[test]
fn directory_operand_rejected() {
    let t = TempDir::new("btsum-cli");
    let (rc, _, _) = run_in(t.path(), &[t.path().to_str().unwrap()]);
    assert_eq!(rc, 2);
}

#[cfg(all(unix, not(target_vendor = "apple")))]
#[test]
fn non_utf8_filename_rejected() {
    let t = TempDir::new("btsum-cli");
    let raw: &[u8] = b"bad\xffname.bin";
    let path = t.path().join(OsStr::from_bytes(raw));
    fs::write(&path, b"payload").unwrap();

    let out = Command::new(BIN)
        .current_dir(t.path())
        .arg(OsStr::from_bytes(raw))
        .output()
        .unwrap();
    assert_eq!(out.status.code().unwrap_or(-1), 2);
    assert!(String::from_utf8_lossy(&out.stderr).contains("not valid UTF-8"));
}

#[test]
fn pair_with_name_override() {
    let t = TempDir::new("btsum-cli");
    t.write("renamed.bin", HELLO_DATA);
    let (rc, out, _) = run_in(t.path(), &["--pair", "-n", "hello.txt", "renamed.bin"]);
    assert_eq!(rc, 0);
    assert_eq!(
        out,
        format!("{HELLO_BTIH}+{HELLO_BTMH}  hello.txt\n").as_bytes()
    );
}

#[test]
fn pair_roundtrips_as_check_ref() {
    let t = TempDir::new("btsum-cli");
    t.write("hello.txt", HELLO_DATA);
    let (rc, out, _) = run_in(t.path(), &["--pair", "hello.txt"]);
    assert_eq!(rc, 0);
    let ref_str = String::from_utf8(out).unwrap();
    let ref_str = ref_str.trim_end();
    let (rc, out, _) = run_in(t.path(), &["-c", ref_str, "hello.txt"]);
    assert_eq!(rc, 0);
    assert!(String::from_utf8_lossy(&out).contains(": OK (v1+v2)"));
}

#[test]
fn check_rejects_pair_flag() {
    let t = TempDir::new("btsum-cli");
    t.write("hello.txt", HELLO_DATA);
    let (rc, _, _) = run_in(t.path(), &["-c", &"0".repeat(40), "--pair", "hello.txt"]);
    assert_eq!(rc, 2);
}
