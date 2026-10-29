//! btsum -- deterministic BitTorrent identity tool.
//!
//! The public API is [`build_identity`] (mint), [`magnet_for`] (render),
//! [`parse_hash_ref`] (parse `-c` references), [`validate_name`], and
//! [`hex_encode`] (format). Everything else is an implementation detail.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(rustdoc::missing_crate_level_docs)]
#![warn(rustdoc::broken_intra_doc_links)]
#![warn(clippy::all)]

pub mod bencode;
pub mod cli;
pub mod identity;
pub mod ladder;
pub mod magnet;
pub mod merkle;
pub mod reference;
pub mod url;

pub use identity::{Identity, build_identity, validate_name};
pub use magnet::magnet_for;
pub use reference::{HashRef, parse_hash_ref};
pub use url::hex_encode;

/// Program name, taken from `Cargo.toml`.
pub const PROG: &str = env!("CARGO_PKG_NAME");

/// Program version, taken from `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

// Format constants (SPEC.md sections 3 and 4).

pub(crate) const KIB: u64 = 1024;
pub(crate) const LEAF_SIZE: u64 = 16 * KIB;
pub(crate) const MIN_PIECE_SIZE: u64 = LEAF_SIZE;
pub(crate) const MAX_PIECE_SIZE: u64 = 1 << 30;
pub(crate) const PIECE_BAND: u64 = 1024;
pub(crate) const MAX_PIECES: u64 = (1 << 31) - 1;
pub(crate) const MAX_FILE_SIZE: u64 = MAX_PIECES * MAX_PIECE_SIZE;
pub(crate) const ZERO_HASH: [u8; 32] = [0u8; 32];
pub(crate) const META_VERSION: i64 = 2;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Any error returned by this crate.
///
/// [`BtsumError::Usage`] indicates the caller invoked the tool incorrectly;
/// [`BtsumError::Fatal`] covers I/O failures and any other unrecoverable
/// condition. Both map to process exit code 2.
#[derive(Debug)]
#[non_exhaustive]
pub enum BtsumError {
    /// I/O failure, malformed input on disk, or another unrecoverable error.
    Fatal(String),
    /// Command-line or API misuse.
    Usage(String),
}

impl std::fmt::Display for BtsumError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BtsumError::Fatal(m) | BtsumError::Usage(m) => f.write_str(m),
        }
    }
}
impl std::error::Error for BtsumError {}

impl From<std::io::Error> for BtsumError {
    fn from(e: std::io::Error) -> Self {
        BtsumError::Fatal(e.to_string())
    }
}

/// Convenience alias for `Result<T, BtsumError>`.
pub type Result<T> = std::result::Result<T, BtsumError>;
