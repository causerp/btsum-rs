//! Golden-vector tests (SPEC.md section 11), plus name and determinism
//! properties that exercise the public `build_identity` API.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use sha2::{Digest, Sha256};

use btsum::{build_identity, hex_encode, validate_name};

static TMP_COUNTER: AtomicUsize = AtomicUsize::new(0);

struct Vector {
    name: &'static str,
    data: &'static [u8],
    btih: &'static str,
    btmh: &'static str,
    torrent_sha: &'static str,
    torrent_len: usize,
}

fn vectors() -> Vec<Vector> {
    let three_leaves: Vec<u8> = b"btsum three leaves vector\n".repeat(1600);
    let three_leaves_static: &'static [u8] = Box::leak(three_leaves.into_boxed_slice());
    let split_piece: &'static [u8] = {
        let mut v = vec![b'A'; 16384];
        v.push(b'B');
        Box::leak(v.into_boxed_slice())
    };
    let two_pieces: &'static [u8] = Box::leak(vec![b'B'; 32768].into_boxed_slice());

    vec![
        Vector {
            name: "hello.txt",
            data: b"hello btsum\n",
            btih: "7fe09bdbcee8c4d588e6f4193973d7cdd12d380f",
            btmh: "fcd26dfd1a8902f1832ad1613e82fac6d80e25eb2a59335c3d7ad46dab0dd633",
            torrent_sha: "eb975502da8a14ceb51eaeffd3e15d68d8d10f00e7a5409c30e79595d867b368",
            torrent_len: 218,
        },
        Vector {
            name: "empty.bin",
            data: b"",
            btih: "a2cbc9d1534378ef64d1e0619d738b2f3d2b7dd4",
            btmh: "882b4b77461bf690ee114e776aa263b6850ea6caf0cfae73a7437e64da8fa8b6",
            torrent_sha: "b7319ccffba6395c58df45dbe6891dfa7a70fdce60cf6232d8d893fc8cd1fe19",
            torrent_len: 146,
        },
        Vector {
            name: "three-leaves.bin",
            data: three_leaves_static,
            btih: "92166ef8a8d5548f51204bbd71b796c9ff0ec791",
            btmh: "8fcfeece6d1c589db95e820b3268935dee1733bdfaed76778c3dbdf081409992",
            torrent_sha: "96c5ff0703e244890c0d05861687bb910e9ab9a9e3b84fd5f2ccd198e26b1729",
            torrent_len: 414,
        },
        Vector {
            name: "split-piece.bin",
            data: split_piece,
            btih: "5572e2e889ddd2ea2d0478ad1bfe3e2b42e96385",
            btmh: "9887734327d915d4ee26ab34d2ab6dac1742e51f78f9255529ae81b07cf33492",
            torrent_sha: "61ed02904fb759053c9db5fa6745673ac7b76343f2b9adcb0a5cc122fbd324cf",
            torrent_len: 360,
        },
        Vector {
            name: "two-pieces.bin",
            data: two_pieces,
            btih: "5e539dbb67a2c44270beef40033616b20cebd6f2",
            btmh: "3198f5a6ad31d5289fbf02d440faddff7ce3b1f5b5f5616b9300b51afb854b5b",
            torrent_sha: "e76da1971e939d6ad785625b143b97f9849435852cc3af9d9c6b6d879fea8775",
            torrent_len: 358,
        },
    ]
}

fn with_tmp<F: FnOnce(&Path)>(data: &[u8], f: F) {
    let n = TMP_COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir: PathBuf =
        std::env::temp_dir().join(format!("btsum-golden-{}-{}", std::process::id(), n));
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("input.bin");
    fs::write(&path, data).unwrap();
    f(&path);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn golden_vectors_match() {
    for v in vectors() {
        with_tmp(v.data, |path| {
            let id = build_identity(path, v.name.as_bytes()).unwrap();
            assert_eq!(hex_encode(&id.btih), v.btih, "{} btih", v.name);
            assert_eq!(hex_encode(&id.btmh), v.btmh, "{} btmh", v.name);
            assert_eq!(id.torrent.len(), v.torrent_len, "{} torrent_len", v.name);
            let sha = hex_encode(&Sha256::digest(&id.torrent));
            assert_eq!(sha, v.torrent_sha, "{} torrent_sha", v.name);
        });
    }
}

#[test]
fn hello_txt_full_torrent_hex() {
    let expected_hex = concat!(
        "64343a696e666f64393a66696c65207472656564393a68656c6c6f2e74787464303a",
        "64363a6c656e6774686931326531313a70696563657320726f6f7433323a21088184",
        "08c7ade7c71fc9ee9064dee95ab0dcd60a2bfd9546ac12f5d8c77a33656565363a6c",
        "656e6774686931326531323a6d6574612076657273696f6e693265343a6e616d6539",
        "3a68656c6c6f2e74787431323a7069656365206c656e67746869313633383465363a",
        "70696563657332303ab382cd2bba066a903f24e97c2cff3861e1158f706531323a70",
        "69656365206c6179657273646565",
    );
    with_tmp(b"hello btsum\n", |path| {
        let id = build_identity(path, b"hello.txt").unwrap();
        assert_eq!(hex_encode(&id.torrent), expected_hex);
    });
}

#[test]
fn determinism() {
    with_tmp(b"payload", |path| {
        let a = build_identity(path, b"x.bin").unwrap();
        let b = build_identity(path, b"x.bin").unwrap();
        assert_eq!(a.torrent, b.torrent);
        assert_eq!(a.btih, b.btih);
        assert_eq!(a.btmh, b.btmh);
    });
}

#[test]
fn name_is_bound() {
    with_tmp(b"payload", |path| {
        let a = build_identity(path, b"a.bin").unwrap();
        let b = build_identity(path, b"b.bin").unwrap();
        assert_ne!(a.btih, b.btih);
        assert_ne!(a.btmh, b.btmh);
    });
}

#[test]
fn nfc_and_nfd_are_distinct_identities() {
    with_tmp(b"", |path| {
        let nfc = b"caf\xc3\xa9.bin"; // café, NFC
        let nfd = b"cafe\xcc\x81.bin"; // café, NFD
        let a = build_identity(path, nfc).unwrap();
        let b = build_identity(path, nfd).unwrap();
        assert_ne!(a.btih, b.btih);
        assert_ne!(a.btmh, b.btmh);
    });
}

#[test]
fn name_validation() {
    for bad in [&b""[..], b"a/b", b"a\0b", b".", b"..", b"\xff\xfe"] {
        assert!(validate_name(bad).is_err(), "expected reject: {:?}", bad);
    }
    assert!(validate_name(b"file.bin").is_ok());
    // Valid UTF-8 non-ASCII: NFC and NFD both accepted, un-normalized.
    assert!(validate_name(b"caf\xc3\xa9.bin").is_ok());
    assert!(validate_name(b"cafe\xcc\x81.bin").is_ok());
    // BOM (U+FEFF) is not special; it is a valid UTF-8 character.
    assert!(validate_name(b"\xef\xbb\xbfhello.bin").is_ok());
}
