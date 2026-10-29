//! Canonical bencode (encoder only: btsum never parses bencode).

use std::collections::BTreeMap;

#[derive(Clone, Debug)]
pub(crate) enum Bencode {
    Bytes(Vec<u8>),
    Int(i64),
    Dict(BTreeMap<Vec<u8>, Bencode>),
}

impl Bencode {
    pub(crate) fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Bencode::Int(i) => {
                out.push(b'i');
                out.extend_from_slice(i.to_string().as_bytes());
                out.push(b'e');
            }
            Bencode::Bytes(b) => {
                out.extend_from_slice(b.len().to_string().as_bytes());
                out.push(b':');
                out.extend_from_slice(b);
            }
            Bencode::Dict(map) => {
                out.push(b'd');
                // BTreeMap<Vec<u8>, _> iterates keys in raw byte order.
                for (k, v) in map {
                    out.extend_from_slice(k.len().to_string().as_bytes());
                    out.push(b':');
                    out.extend_from_slice(k);
                    v.encode_into(out);
                }
                out.push(b'e');
            }
        }
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        out
    }
}

pub(crate) fn dict<K, I>(entries: I) -> Bencode
where
    K: AsRef<[u8]>,
    I: IntoIterator<Item = (K, Bencode)>,
{
    Bencode::Dict(
        entries
            .into_iter()
            .map(|(k, v)| (k.as_ref().to_vec(), v))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalars() {
        assert_eq!(Bencode::Int(0).encode(), b"i0e");
        assert_eq!(Bencode::Int(-3).encode(), b"i-3e");
        assert_eq!(Bencode::Int(1024).encode(), b"i1024e");
        assert_eq!(Bencode::Bytes(b"".to_vec()).encode(), b"0:");
        assert_eq!(Bencode::Bytes(b"spam".to_vec()).encode(), b"4:spam");
    }

    #[test]
    fn dict_keys_sort_as_raw_bytes() {
        let enc = dict([
            (b"pieces".as_slice(), Bencode::Bytes(b"x".to_vec())),
            (b"piece length".as_slice(), Bencode::Int(1)),
            (b"piece layers".as_slice(), dict::<&[u8], _>([])),
        ])
        .encode();
        assert_eq!(enc, b"d12:piece layersde12:piece lengthi1e6:pieces1:xe");
    }

    #[test]
    fn dict_sorts_nested() {
        let nested = dict([
            (b"cow".as_slice(), Bencode::Bytes(b"moo".to_vec())),
            (b"aba".as_slice(), Bencode::Bytes(b"".to_vec())),
        ])
        .encode();
        assert_eq!(nested, b"d3:aba0:3:cow3:mooe");
    }
}
