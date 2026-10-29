//! Parse `-c` references (SPEC.md section 8.1).

use crate::url::{hexval, url_unquote};
use crate::{BtsumError, Result};

/// Byte length of a v1 infohash (BEP-3).
pub const BTIH_LEN: usize = 20;

/// Byte length of a v2 merkle root (BEP-52).
pub const BTMH_LEN: usize = 32;

type HashPair = (Option<[u8; BTIH_LEN]>, Option<[u8; BTMH_LEN]>);

/// A parsed `-c` reference: any combination of v1 hash, v2 hash, and name.
///
/// Constructed by [`parse_hash_ref`]. At least one of `v1` or `v2` is
/// `Some`; `name` is `Some` when the reference carried a `dn=` or a
/// sha256sum-style trailing name.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct HashRef {
    /// v1 infohash, if the reference carries one.
    pub v1: Option<[u8; BTIH_LEN]>,
    /// v2 merkle root, if the reference carries one.
    pub v2: Option<[u8; BTMH_LEN]>,
    /// Bound file name, if the reference carries one.
    pub name: Option<Vec<u8>>,
}

pub(crate) fn decode_hash_token(token: &str) -> Option<Vec<u8>> {
    if token.len() == 32 {
        return base32_decode(token).filter(|v| v.len() == BTIH_LEN);
    }
    if !token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    match token.len() {
        40 | 64 => Some(hex_decode(token)),
        68 if token.starts_with("1220") => Some(hex_decode(&token[4..])),
        _ => None,
    }
}

pub(crate) fn hex_decode(s: &str) -> Vec<u8> {
    s.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| (hexval(p[0]).unwrap() << 4) | hexval(p[1]).unwrap())
        .collect()
}

pub(crate) fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut bits: u64 = 0;
    let mut nbits: u32 = 0;
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a', // base32 is case-insensitive
            b'2'..=b'7' => c - b'2' + 26,
            _ => return None,
        } as u64;
        bits = (bits << 5) | v;
        nbits += 5;
        if nbits >= 8 {
            nbits -= 8;
            out.push((bits >> nbits) as u8);
        }
    }
    Some(out)
}

pub(crate) fn urn_hash(urn: &str, text: &str) -> Result<(&'static str, Vec<u8>)> {
    let (kind, rest, want) = if let Some(r) = urn.strip_prefix("urn:btih:") {
        ("v1", r, BTIH_LEN)
    } else if let Some(r) = urn.strip_prefix("urn:btmh:") {
        ("v2", r, BTMH_LEN)
    } else {
        return Err(BtsumError::Fatal(format!(
            "unsupported URN in reference: {text}"
        )));
    };
    match decode_hash_token(rest) {
        Some(raw) if raw.len() == want => Ok((kind, raw)),
        _ => Err(BtsumError::Fatal(format!(
            "malformed {kind} in reference: {text}"
        ))),
    }
}

/// Splits a sha256sum-style line into `(hash_part, name_part)`.
///
/// Accepts both coreutils separators — `␣␣` (text mode) and `␣*` (binary
/// mode) — and additionally tolerates a stray `*` immediately after a
/// two-space separator (`␣␣*name`), which sometimes appears in hand-edited
/// checksum files. The leading `*` is not part of the bound name.
pub(crate) fn split_sha256sum(text: &str) -> Option<(&str, &str)> {
    let idx = text.find(' ')?;
    let hash_part = &text[..idx];
    let rest = &text[idx + 1..];
    let name_part = rest.strip_prefix(' ').or_else(|| rest.strip_prefix('*'))?;
    let name_part = name_part.strip_prefix('*').unwrap_or(name_part);
    if name_part.is_empty() {
        return None;
    }
    Some((hash_part, name_part))
}

/// Parses a bare hash token or `A+B` combined reference.
///
/// Returns `(v1, v2)` with at least one `Some`, or `None` if the input is
/// not one of the accepted shapes.
pub(crate) fn parse_hash_pair(hash_part: &str) -> Option<HashPair> {
    let parts: Vec<&str> = hash_part.split('+').collect();
    match parts.as_slice() {
        [single] => {
            let raw = decode_hash_token(single)?;
            match raw.len() {
                BTIH_LEN => Some((Some(raw.try_into().unwrap()), None)),
                BTMH_LEN => Some((None, Some(raw.try_into().unwrap()))),
                _ => None,
            }
        }
        [a, b] => {
            let a_raw = decode_hash_token(a)?;
            let b_raw = decode_hash_token(b)?;
            if a_raw.len() == b_raw.len() {
                return None;
            }
            let (v1, v2) = if a_raw.len() == BTIH_LEN {
                (a_raw, b_raw)
            } else {
                (b_raw, a_raw)
            };
            Some((Some(v1.try_into().unwrap()), Some(v2.try_into().unwrap())))
        }
        _ => None,
    }
}

/// Parses a `-c` reference into a [`HashRef`].
///
/// Accepts, in order of detection:
///
/// - a full magnet URI (`magnet:?...`, leading `magnet:?` optional in
///   some forms; see SPEC.md section 8.1);
/// - a fragment starting with `xt=` or `urn:` (partial magnet);
/// - a sha256sum-style line: `<hash>␣␣<name>` (text mode) or
///   `<hash>␣*<name>` (binary mode); the `*` is a marker, not part of
///   the name; `dn=*name` is also tolerated and strips the `*`;
/// - a bare hash: 40 hex (v1), 64 hex (v2), `1220` + 64 hex (v2 multihash),
///   or 32 base32 chars (v1);
/// - a combined form `<40hex>+<64hex>` in either order.
///
/// Returns `Ok(None)` for inputs that do not look like any of the above,
/// which the caller uses to fall back to "treat as checksum listing path".
///
/// # Errors
///
/// Returns [`BtsumError::Fatal`] when the input clearly *is* a reference
/// (has an `xt=`, `urn:`, or `+`) but is malformed, or when two `xt=`
/// values of the same kind disagree.
pub fn parse_hash_ref(text: &str) -> Result<Option<HashRef>> {
    if text.is_empty() {
        return Ok(None);
    }

    let body: &str = if let Some(rest) = text.strip_prefix("magnet:?") {
        rest
    } else if text.starts_with("urn:") || text.contains("xt=") {
        text
    } else {
        if let Some((hash_part, name_part)) = split_sha256sum(text)
            && let Some((v1, v2)) = parse_hash_pair(hash_part)
        {
            return Ok(Some(HashRef {
                v1,
                v2,
                name: Some(name_part.as_bytes().to_vec()),
            }));
        }

        let parts: Vec<&str> = text.split('+').collect();
        match parts.as_slice() {
            [single] => {
                return Ok(decode_hash_token(single).and_then(|raw| match raw.len() {
                    BTIH_LEN => Some(HashRef {
                        v1: Some(raw.try_into().unwrap()),
                        v2: None,
                        name: None,
                    }),
                    BTMH_LEN => Some(HashRef {
                        v1: None,
                        v2: Some(raw.try_into().unwrap()),
                        name: None,
                    }),
                    _ => None,
                }));
            }
            [a, b] => {
                let (a, b) = (decode_hash_token(a), decode_hash_token(b));
                return match (a, b) {
                    (None, None) => Ok(None),
                    (Some(_), None) | (None, Some(_)) => Err(BtsumError::Fatal(format!(
                        "malformed combined reference: {text}"
                    ))),
                    (Some(a), Some(b)) if a.len() == b.len() => Err(BtsumError::Fatal(format!(
                        "combined reference needs one btih and one btmh: {text}"
                    ))),
                    (Some(a), Some(b)) => {
                        let (v1, v2) = if a.len() == BTIH_LEN { (a, b) } else { (b, a) };
                        Ok(Some(HashRef {
                            v1: Some(v1.try_into().unwrap()),
                            v2: Some(v2.try_into().unwrap()),
                            name: None,
                        }))
                    }
                };
            }
            _ => {
                return Err(BtsumError::Fatal(format!(
                    "malformed hash reference: {text}"
                )));
            }
        }
    };

    let mut v1: Option<[u8; BTIH_LEN]> = None;
    let mut v2: Option<[u8; BTMH_LEN]> = None;
    let mut name: Option<Vec<u8>> = None;
    let mut seen_hash = false;

    for part in body.split('&').filter(|p| !p.is_empty()) {
        if let Some(rest) = part.strip_prefix("dn=") {
            let decoded = url_unquote(rest);
            // Tolerate a stray leading `*` (some tools emit `dn=*name`).
            let bytes = match decoded.strip_prefix(b"*") {
                Some(stripped) => stripped.to_vec(),
                None => decoded,
            };
            name = Some(bytes);
            continue;
        }
        let urn = if let Some(rest) = part.strip_prefix("xt=") {
            rest
        } else if part.starts_with("urn:") {
            part
        } else {
            continue;
        };
        seen_hash = true;
        let (kind, raw) = urn_hash(urn, text)?;
        if kind == "v1" {
            let arr: [u8; BTIH_LEN] = raw.try_into().expect("checked length");
            if v1.replace(arr).is_some_and(|old| old != arr) {
                return Err(BtsumError::Fatal(format!(
                    "conflicting btih values in reference: {text}"
                )));
            }
        } else {
            let arr: [u8; BTMH_LEN] = raw.try_into().expect("checked length");
            if v2.replace(arr).is_some_and(|old| old != arr) {
                return Err(BtsumError::Fatal(format!(
                    "conflicting btmh values in reference: {text}"
                )));
            }
        }
    }
    if !seen_hash {
        return Err(BtsumError::Fatal(format!(
            "reference carries no hash: {text}"
        )));
    }
    Ok(Some(HashRef { v1, v2, name }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const H1: &str = "abababababababababababababababababababab";
    const H2: &str = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";

    #[test]
    fn bare_hashes() {
        let r = parse_hash_ref(H1).unwrap().unwrap();
        assert_eq!(r.v1, Some([0xab; 20]));
        assert!(r.v2.is_none());
        assert!(r.name.is_none());

        let r = parse_hash_ref(H2).unwrap().unwrap();
        assert!(r.v1.is_none());
        assert_eq!(r.v2, Some([0xcd; 32]));
    }

    #[test]
    fn multihash_prefix() {
        let r = parse_hash_ref(&format!("1220{H2}")).unwrap().unwrap();
        assert!(r.v1.is_none());
        assert_eq!(r.v2, Some([0xcd; 32]));
    }

    #[test]
    fn combined() {
        let r = parse_hash_ref(&format!("{H1}+{H2}")).unwrap().unwrap();
        assert_eq!(r.v1, Some([0xab; 20]));
        assert_eq!(r.v2, Some([0xcd; 32]));

        let r = parse_hash_ref(&format!("{H2}+{H1}")).unwrap().unwrap();
        assert_eq!(r.v1, Some([0xab; 20]));
        assert_eq!(r.v2, Some([0xcd; 32]));
    }

    #[test]
    fn combined_malformed() {
        assert!(parse_hash_ref(&format!("{H1}+{H1}")).is_err());
    }

    #[test]
    fn magnet_full() {
        let r = format!("magnet:?xt=urn:btih:{H1}&xt=urn:btmh:1220{H2}&dn=hello%20world.bin");
        let p = parse_hash_ref(&r).unwrap().unwrap();
        assert_eq!(p.v1, Some([0xab; 20]));
        assert_eq!(p.v2, Some([0xcd; 32]));
        assert_eq!(p.name, Some(b"hello world.bin".to_vec()));
    }

    #[test]
    fn magnet_unknown_params_ignored() {
        let r = format!("magnet:?tr=udp%3A%2F%2Fexample&xt=urn:btih:{H1}&dn=y.bin&so=0");
        let p = parse_hash_ref(&r).unwrap().unwrap();
        assert_eq!(p.v1, Some([0xab; 20]));
        assert_eq!(p.name, Some(b"y.bin".to_vec()));
    }

    #[test]
    fn dn_with_star_prefix_ignored() {
        let r = format!("magnet:?xt=urn:btih:{H1}&dn=*hello.txt");
        let p = parse_hash_ref(&r).unwrap().unwrap();
        assert_eq!(p.name, Some(b"hello.txt".to_vec()));

        let r = format!("magnet:?xt=urn:btih:{H1}&dn=%2Ahello.txt");
        let p = parse_hash_ref(&r).unwrap().unwrap();
        assert_eq!(p.name, Some(b"hello.txt".to_vec()));
    }

    #[test]
    fn malformed() {
        assert!(parse_hash_ref("urn:btih:zzzz").is_err());
        assert!(parse_hash_ref("magnet:?dn=only-name").is_err());
        assert!(parse_hash_ref("magnet:?xt=urn:unknown:abcd").is_err());
    }

    #[test]
    fn not_a_hash() {
        assert!(parse_hash_ref("").unwrap().is_none());
        assert!(parse_hash_ref("sums.magnets").unwrap().is_none());
        assert!(parse_hash_ref("/etc/hosts").unwrap().is_none());
    }

    #[test]
    fn sha256sum_text_form() {
        let r = parse_hash_ref(&format!("{H1}  hello.txt"))
            .unwrap()
            .unwrap();
        assert_eq!(r.v1, Some([0xab; 20]));
        assert!(r.v2.is_none());
        assert_eq!(r.name, Some(b"hello.txt".to_vec()));
    }

    #[test]
    fn sha256sum_binary_form() {
        let r = parse_hash_ref(&format!("{H1} *hello.txt"))
            .unwrap()
            .unwrap();
        assert_eq!(r.v1, Some([0xab; 20]));
        assert_eq!(r.name, Some(b"hello.txt".to_vec()));
    }

    #[test]
    fn sha256sum_double_space_star_tolerated() {
        let r = parse_hash_ref(&format!("{H1}  *hello.txt"))
            .unwrap()
            .unwrap();
        assert_eq!(r.v1, Some([0xab; 20]));
        assert_eq!(r.name, Some(b"hello.txt".to_vec()));
    }

    #[test]
    fn sha256sum_v2_form() {
        let r = parse_hash_ref(&format!("{H2} *hello.txt"))
            .unwrap()
            .unwrap();
        assert!(r.v1.is_none());
        assert_eq!(r.v2, Some([0xcd; 32]));
        assert_eq!(r.name, Some(b"hello.txt".to_vec()));
    }

    #[test]
    fn sha256sum_combined_form() {
        let r = parse_hash_ref(&format!("{H1}+{H2}  hello.txt"))
            .unwrap()
            .unwrap();
        assert_eq!(r.v1, Some([0xab; 20]));
        assert_eq!(r.v2, Some([0xcd; 32]));
        assert_eq!(r.name, Some(b"hello.txt".to_vec()));

        let r = parse_hash_ref(&format!("{H2}+{H1} *hello.txt"))
            .unwrap()
            .unwrap();
        assert_eq!(r.v1, Some([0xab; 20]));
        assert_eq!(r.v2, Some([0xcd; 32]));
    }

    #[test]
    fn sha256sum_name_with_plus() {
        let r = parse_hash_ref(&format!("{H1}  file+name.bin"))
            .unwrap()
            .unwrap();
        assert_eq!(r.v1, Some([0xab; 20]));
        assert_eq!(r.name, Some(b"file+name.bin".to_vec()));
    }

    #[test]
    fn sha256sum_name_with_internal_spaces() {
        let r = parse_hash_ref(&format!("{H1}  file  name.bin"))
            .unwrap()
            .unwrap();
        assert_eq!(r.name, Some(b"file  name.bin".to_vec()));
    }

    #[test]
    fn sha256sum_multihash_form() {
        let r = parse_hash_ref(&format!("1220{H2} *hello.txt"))
            .unwrap()
            .unwrap();
        assert!(r.v1.is_none());
        assert_eq!(r.v2, Some([0xcd; 32]));
        assert_eq!(r.name, Some(b"hello.txt".to_vec()));
    }
}
