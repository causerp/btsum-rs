//! Hex and percent-encoding helpers.

/// Encodes `bytes` as lowercase hexadecimal.
///
/// The output is exactly twice the input length. Empty input yields the
/// empty string.
///
/// # Examples
///
/// ```
/// # use btsum::hex_encode;
/// assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
/// assert_eq!(hex_encode(&[]), "");
/// ```
#[must_use]
pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

pub(crate) fn url_quote(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(bytes.len() * 3);
    for &b in bytes {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => {
                out.push('%');
                out.push(HEX[(b >> 4) as usize] as char);
                out.push(HEX[(b & 0xf) as usize] as char);
            }
        }
    }
    out
}

pub(crate) fn url_unquote(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 3 <= b.len()
            && let (Some(hi), Some(lo)) = (hexval(b[i + 1]), hexval(b[i + 2]))
        {
            out.push((hi << 4) | lo);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

pub(crate) fn hexval(b: u8) -> Option<u8> {
    Some(match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => return None,
    })
}

pub(crate) fn latin1_to_string(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| b as char).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_encoding() {
        assert_eq!(hex_encode(b""), "");
        assert_eq!(hex_encode(&[0x00]), "00");
        assert_eq!(hex_encode(&[0xff, 0x12, 0xab]), "ff12ab");
    }

    #[test]
    fn url_roundtrip() {
        for raw in [&b"hello world"[..], b"a/b?c=d&e", b"\xff\x00", b"tab\there"] {
            let q = url_quote(raw);
            assert_eq!(url_unquote(&q), raw, "roundtrip {raw:?}");
        }
    }

    #[test]
    fn url_unquote_edge_cases() {
        assert_eq!(url_unquote("%"), b"%");
        assert_eq!(url_unquote("%4"), b"%4");
        assert_eq!(url_unquote("%41"), b"A");
        assert_eq!(url_unquote("%zz"), b"%zz");
    }

    #[test]
    fn url_quote_reserved() {
        assert_eq!(url_quote(b"a b"), "a%20b");
        assert_eq!(url_quote(b"a+b"), "a%2Bb");
        assert_eq!(url_quote(b"~-_."), "~-_.");
    }

    #[test]
    fn latin1_is_bijection() {
        let bytes: Vec<u8> = (0u8..=255).collect();
        let s = latin1_to_string(&bytes);
        assert_eq!(s.chars().count(), 256);
    }
}
