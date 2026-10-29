//! Magnet URI rendering (SPEC.md section 7).

use crate::url::{hex_encode, url_quote};

/// Renders a dual-stack magnet URI for the given identity.
///
/// Format (SPEC.md section 7):
///
/// ```text
/// magnet:?xt=urn:btih:<40 hex>&xt=urn:btmh:1220<64 hex>&dn=<urlencoded name>
/// ```
///
/// `btih` comes first so that v1-only clients that honor only the first
/// `xt` still work. The name is percent-encoded byte-for-byte over its
/// UTF-8 form; spaces become `%20`, never `+`.
///
/// # Examples
///
/// ```
/// # use btsum::magnet_for;
/// let uri = magnet_for(&[0u8; 20], &[0u8; 32], b"hello.txt");
/// assert!(uri.starts_with("magnet:?xt=urn:btih:0000000000000000000000000000000000000000"));
/// assert!(uri.contains("&dn=hello.txt"));
/// ```
#[must_use]
pub fn magnet_for(btih: &[u8; 20], btmh: &[u8; 32], name: &[u8]) -> String {
    format!(
        "magnet:?xt=urn:btih:{}&xt=urn:btmh:1220{}&dn={}",
        hex_encode(btih),
        hex_encode(btmh),
        url_quote(name)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format() {
        let uri = magnet_for(&[0xaa; 20], &[0xbb; 32], b"file.bin");
        let expected = format!(
            "magnet:?xt=urn:btih:{}&xt=urn:btmh:1220{}&dn=file.bin",
            "aa".repeat(20),
            "bb".repeat(32),
        );
        assert_eq!(uri, expected);
    }

    #[test]
    fn btih_first() {
        let uri = magnet_for(&[0xaa; 20], &[0xbb; 32], b"f");
        assert!(uri.find("urn:btih").unwrap() < uri.find("urn:btmh").unwrap());
    }

    #[test]
    fn percent_encoding() {
        let uri = magnet_for(&[0xaa; 20], &[0xbb; 32], b"ren amed.bin");
        assert!(uri.contains("dn=ren%20amed.bin"));
        assert!(!uri.contains('+'));
    }
}
