//! Piece-size ladder (SPEC.md section 4).

use crate::{BtsumError, MAX_FILE_SIZE, MAX_PIECE_SIZE, MIN_PIECE_SIZE, PIECE_BAND, Result};

pub(crate) fn piece_length_for(file_size: u64) -> Result<u64> {
    if file_size > MAX_FILE_SIZE {
        return Err(BtsumError::Fatal(format!(
            "file size {file_size} exceeds the format domain limit \
             ({MAX_FILE_SIZE} bytes, ~2 EiB); no v1-valid encoding exists beyond it"
        )));
    }
    let mut p = MIN_PIECE_SIZE;
    while p < MAX_PIECE_SIZE && file_size.div_ceil(p) > PIECE_BAND {
        p <<= 1;
    }
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MAX_PIECES;

    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;
    const TIB: u64 = 1024 * GIB;

    /// One row per transition of the ladder (SPEC.md section 4):
    /// `(size at the boundary, piece length there, piece length at +1 byte)`.
    ///
    /// At every boundary `S = 1024 * p_old` the old piece length still
    /// applies with exactly 1024 pieces. At `S + 1` the ladder doubles the
    /// piece length, dropping the count to 513 (which then climbs back to
    /// 1024 by the next boundary).
    const TRANSITIONS: &[(u64, u64, u64)] = &[
        (16 * MIB, 16 * KIB, 32 * KIB),
        (32 * MIB, 32 * KIB, 64 * KIB),
        (64 * MIB, 64 * KIB, 128 * KIB),
        (128 * MIB, 128 * KIB, 256 * KIB),
        (256 * MIB, 256 * KIB, 512 * KIB),
        (512 * MIB, 512 * KIB, MIB),
        (GIB, MIB, 2 * MIB),
        (2 * GIB, 2 * MIB, 4 * MIB),
        (4 * GIB, 4 * MIB, 8 * MIB),
        (8 * GIB, 8 * MIB, 16 * MIB),
        (16 * GIB, 16 * MIB, 32 * MIB),
        (32 * GIB, 32 * MIB, 64 * MIB),
        (64 * GIB, 64 * MIB, 128 * MIB),
        (128 * GIB, 128 * MIB, 256 * MIB),
        (256 * GIB, 256 * MIB, 512 * MIB),
        (512 * GIB, 512 * MIB, GIB),
    ];

    fn count(size: u64, p: u64) -> u64 {
        size.div_ceil(p)
    }

    #[test]
    fn small_sizes_use_minimum_piece_length() {
        for size in [0u64, 1, 16 * KIB, 16 * MIB - 1] {
            assert_eq!(piece_length_for(size).unwrap(), 16 * KIB, "size={size}");
        }
        assert_eq!(count(0, 16 * KIB), 0);
    }

    #[test]
    fn every_boundary_transitions_cleanly() {
        for &(size, p_at, p_above) in TRANSITIONS {
            assert_eq!(
                piece_length_for(size).unwrap(),
                p_at,
                "size={size}: piece length at boundary"
            );
            assert_eq!(
                count(size, p_at),
                1024,
                "size={size}: piece count at boundary"
            );
            assert_eq!(
                piece_length_for(size + 1).unwrap(),
                p_above,
                "size={}: piece length one byte past boundary",
                size + 1
            );
            assert_eq!(
                count(size + 1, p_above),
                513,
                "size={}: piece count one byte past boundary",
                size + 1
            );
        }
    }

    #[test]
    fn transitions_are_monotonic() {
        // Piece lengths never shrink as the file grows.
        let mut prev = 0u64;
        for &(size, _, _) in TRANSITIONS {
            let p = piece_length_for(size).unwrap();
            assert!(p > prev, "size={size}: {p} <= {prev}");
            prev = p;
        }
    }

    #[test]
    fn cap_holds_beyond_last_transition() {
        // 512 GiB + 1 is where the last transition happens; past it the
        // piece length is 1 GiB forever.
        for &size in &[512 * GIB + 1, TIB, TIB + 1, 2 * TIB, 100 * TIB, 1024 * TIB] {
            assert_eq!(piece_length_for(size).unwrap(), GIB, "size={size} (cap)");
        }
        assert_eq!(count(TIB, GIB), 1024);
        assert_eq!(count(TIB + 1, GIB), 1025);
        assert_eq!(count(1024 * TIB, GIB), 1 << 20);
    }

    #[test]
    fn domain_limit() {
        assert_eq!(piece_length_for(MAX_FILE_SIZE).unwrap(), MAX_PIECE_SIZE);
        assert_eq!(count(MAX_FILE_SIZE, MAX_PIECE_SIZE), MAX_PIECES);
        assert!(piece_length_for(MAX_FILE_SIZE + 1).is_err());
    }

    #[test]
    fn always_power_of_two() {
        for exp in 0..50u32 {
            let size = (1u64 << exp) + (1u64 << exp) / 3 + 7;
            let p = piece_length_for(size).unwrap();
            assert!((p & (p - 1)) == 0 && (16 * KIB..=(1u64 << 30)).contains(&p));
        }
    }
}
