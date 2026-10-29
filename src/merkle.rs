//! BEP-52 Merkle tree.

use sha2::{Digest, Sha256};

use crate::{BtsumError, Result, ZERO_HASH};

pub(crate) fn pow2_at_least(n: u64) -> u64 {
    let mut p = 1u64;
    while p < n {
        p <<= 1;
    }
    p
}

/// Equivalent of Python's `int.bit_length()`: number of bits needed to
/// represent `n`, with `bit_length(0) == 0`.
pub(crate) fn bit_length(n: u64) -> u32 {
    if n == 0 { 0 } else { 64 - n.leading_zeros() }
}

pub(crate) struct ZeroCache(Vec<[u8; 32]>);

impl ZeroCache {
    pub(crate) fn new() -> Self {
        Self(vec![ZERO_HASH])
    }
    pub(crate) fn at(&mut self, levels: u32) -> [u8; 32] {
        while self.0.len() <= levels as usize {
            let prev = *self.0.last().unwrap();
            let mut h = Sha256::new();
            h.update(prev);
            h.update(prev);
            self.0.push(h.finalize().into());
        }
        self.0[levels as usize]
    }
}

pub(crate) fn bits_desc(n: u64) -> impl Iterator<Item = u32> {
    (0..bit_length(n)).rev().filter(move |i| (n >> i) & 1 == 1)
}

pub(crate) fn bits_asc(n: u64) -> impl Iterator<Item = u32> {
    (0..bit_length(n)).filter(move |i| (n >> i) & 1 == 1)
}

pub(crate) fn fold(spans: impl IntoIterator<Item = (u32, [u8; 32])>) -> Result<[u8; 32]> {
    let mut st: Vec<(u32, [u8; 32])> = Vec::new();
    for (lvl, h) in spans {
        st.push((lvl, h));
        while st.len() >= 2 && st[st.len() - 1].0 == st[st.len() - 2].0 {
            let (right_lvl, right) = st.pop().unwrap();
            let (_, left) = st.pop().unwrap();
            let mut h = Sha256::new();
            h.update(left);
            h.update(right);
            st.push((right_lvl + 1, h.finalize().into()));
        }
    }
    match st.as_slice() {
        [(_, h)] => Ok(*h),
        _ => Err(BtsumError::Fatal(
            "internal error: merkle spans do not tile".into(),
        )),
    }
}

pub(crate) fn piece_hash(real: &[[u8; 32]], span: u64, zc: &mut ZeroCache) -> Result<[u8; 32]> {
    let mut spans: Vec<(u32, [u8; 32])> = real.iter().map(|h| (0u32, *h)).collect();
    for lvl in bits_asc(span - real.len() as u64) {
        spans.push((lvl, zc.at(lvl)));
    }
    fold(spans)
}

pub(crate) fn file_root(
    leaf_count: u64,
    stack: &[Option<[u8; 32]>],
    zc: &mut ZeroCache,
) -> Result<[u8; 32]> {
    let mut spans: Vec<(u32, [u8; 32])> = bits_desc(leaf_count)
        .map(|lvl| (lvl, stack[lvl as usize].expect("tiling invariant")))
        .collect();
    let pad = pow2_at_least(leaf_count) - leaf_count;
    for lvl in bits_asc(pad) {
        spans.push((lvl, zc.at(lvl)));
    }
    fold(spans)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bit_iterators() {
        assert_eq!(bits_asc(0b1011).collect::<Vec<_>>(), vec![0, 1, 3]);
        assert_eq!(bits_desc(0b1011).collect::<Vec<_>>(), vec![3, 1, 0]);
        assert_eq!(bits_asc(0).collect::<Vec<_>>(), Vec::<u32>::new());
        assert_eq!(bits_desc(0).collect::<Vec<_>>(), Vec::<u32>::new());
    }

    #[test]
    fn zero_subtree_matches_manual() {
        let mut zc = ZeroCache::new();
        let z1 = zc.at(1);
        let manual: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(ZERO_HASH);
            h.update(ZERO_HASH);
            h.finalize().into()
        };
        assert_eq!(z1, manual);
    }

    #[test]
    fn file_root_matches_brute_force() {
        for n in 1u64..41 {
            let leaves: Vec<[u8; 32]> = (0..n)
                .map(|i| Sha256::digest(i.to_string().as_bytes()).into())
                .collect();

            // Streaming counter tiling (independent re-implementation).
            let mut stack: Vec<Option<[u8; 32]>> = Vec::new();
            for (count, &leaf) in leaves.iter().enumerate() {
                let count = count as u64;
                let mut cur = leaf;
                let mut lvl = 0u32;
                while (count >> lvl) & 1 == 1 {
                    let left = stack[lvl as usize].take().unwrap();
                    let mut h = Sha256::new();
                    h.update(left);
                    h.update(cur);
                    cur = h.finalize().into();
                    lvl += 1;
                }
                if stack.len() <= lvl as usize {
                    stack.resize(lvl as usize + 1, None);
                }
                stack[lvl as usize] = Some(cur);
            }

            // Brute force padded tree.
            let total = pow2_at_least(n) as usize;
            let mut layer: Vec<[u8; 32]> = leaves.clone();
            layer.resize(total, ZERO_HASH);
            while layer.len() > 1 {
                let mut next = Vec::with_capacity(layer.len() / 2);
                for i in (0..layer.len()).step_by(2) {
                    let mut h = Sha256::new();
                    h.update(layer[i]);
                    h.update(layer[i + 1]);
                    next.push(h.finalize().into());
                }
                layer = next;
            }

            let mut zc = ZeroCache::new();
            let got = file_root(n, &stack, &mut zc).unwrap();
            assert_eq!(got, layer[0], "leaf count {n}");
        }
    }
}
