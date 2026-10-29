//! Identity minting (SPEC.md section 3).

use std::fs::{self, File};
use std::io::{self, BufReader, Read};
use std::path::Path;

use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::bencode::{Bencode, dict};
use crate::ladder::piece_length_for;
use crate::merkle::{ZeroCache, file_root, piece_hash};
use crate::{BtsumError, LEAF_SIZE, MAX_FILE_SIZE, META_VERSION, Result};

/// A minted identity: the two infohashes and the wrapper that carries them.
///
/// Produced by [`build_identity`]. All fields are exposed because the values
/// are already public facts (they end up in magnets and `.torrent` files);
/// nothing here is a secret.
#[derive(Debug)]
pub struct Identity {
    /// SHA-1 of the canonical `info` dictionary (BEP-3 infohash, 20 bytes).
    pub btih: [u8; 20],
    /// SHA-256 of the canonical `info` dictionary (BEP-52 infohash, 32 bytes).
    pub btmh: [u8; 32],
    /// The wrapper bytes: `{ "info": info, "piece layers": {...} }`.
    pub torrent: Vec<u8>,
    /// Piece length in bytes, as chosen by the ladder (SPEC.md section 4).
    pub piece_length: u64,
    /// The bound file name; a single path component of valid UTF-8.
    pub name: Vec<u8>,
    /// File size in bytes.
    pub size: u64,
}

/// Validates a candidate file name for use as a btsum identity name.
///
/// A name must be non-empty, a single path component (no `/`), free of NUL
/// bytes, not `.` or `..`, and valid UTF-8 (RFC 3629). No Unicode
/// normalization is applied; NFC and NFD spellings are distinct identities.
///
/// # Errors
///
/// Returns [`BtsumError::Usage`] when `name` violates any of the above.
pub fn validate_name(name: &[u8]) -> Result<()> {
    match name {
        [] => return Err(BtsumError::Usage("name must not be empty".into())),
        _ if name.contains(&0) => {
            return Err(BtsumError::Usage("name must not contain NUL bytes".into()));
        }
        _ if name.contains(&b'/') => {
            return Err(BtsumError::Usage(
                "name must be a single path component (no '/')".into(),
            ));
        }
        b"." | b".." => return Err(BtsumError::Usage("name must not be '.' or '..'".into())),
        _ => {}
    }
    // Valid UTF-8 (RFC 3629).
    if let Err(e) = std::str::from_utf8(name) {
        return Err(BtsumError::Usage(format!(
            "name is not valid UTF-8 (bad byte at offset {}); BitTorrent \
             clients decode names as UTF-8, so this identity would not be \
             usable. Rename the file, or pass -n NAME to bind a portable \
             name.",
            e.valid_up_to()
        )));
    }
    Ok(())
}

/// Mints an [`Identity`] for a single file bound to `name`.
///
/// The file at `path` is read once; both v1 (SHA-1 piece hashes) and v2
/// (BEP-52 merkle root and piece layers) are computed in a single pass
/// (SPEC.md section 5.3).
///
/// # Errors
///
/// Returns [`BtsumError::Usage`] for invalid names, and
/// [`BtsumError::Fatal`] for I/O errors, non-regular files, or sizes beyond
/// the ~2 EiB domain limit.
pub fn build_identity(path: &Path, name: &[u8]) -> Result<Identity> {
    validate_name(name)?;
    let meta = fs::metadata(path)?;
    if !meta.is_file() {
        return Err(BtsumError::Fatal(format!(
            "{}: not a regular file",
            path.display()
        )));
    }
    let size = meta.len();
    if size > MAX_FILE_SIZE {
        return Err(BtsumError::Fatal(format!(
            "{}: file size {size} exceeds the format domain limit (~2 EiB)",
            path.display()
        )));
    }
    let piece_length = piece_length_for(size)?;
    let per_piece = piece_length / LEAF_SIZE;

    let mut zc = ZeroCache::new();
    let mut stack: Vec<Option<[u8; 32]>> = Vec::new();
    let mut leaf_count: u64 = 0;
    let mut pieces_v1: Vec<u8> = Vec::new();
    let mut layers_v2: Vec<u8> = Vec::new();
    let mut pending: Vec<[u8; 32]> = Vec::with_capacity(per_piece as usize);
    let mut sha1_cur = Sha1::new();
    let mut blocks_in_piece: u64 = 0;

    let mut reader = BufReader::with_capacity(LEAF_SIZE as usize, File::open(path)?);
    let mut buf = vec![0u8; LEAF_SIZE as usize];

    loop {
        let n = read_up_to(&mut reader, &mut buf)?;
        if n == 0 {
            break;
        }
        let block = &buf[..n];

        let leaf: [u8; 32] = Sha256::digest(block).into();
        let mut cur = leaf;
        let mut lvl = 0u32;
        while (leaf_count >> lvl) & 1 == 1 {
            let left = stack[lvl as usize].take().expect("tiling invariant");
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
        leaf_count += 1;

        pending.push(leaf);
        sha1_cur.update(block);
        blocks_in_piece += 1;
        if blocks_in_piece == per_piece {
            pieces_v1.extend_from_slice(&sha1_cur.finalize_reset());
            layers_v2.extend_from_slice(&piece_hash(&pending, per_piece, &mut zc)?);
            pending.clear();
            blocks_in_piece = 0;
        }
    }
    if blocks_in_piece > 0 {
        pieces_v1.extend_from_slice(&sha1_cur.finalize());
        layers_v2.extend_from_slice(&piece_hash(&pending, per_piece, &mut zc)?);
    }

    let pieces_root: Option<[u8; 32]> = if leaf_count > 0 {
        Some(file_root(leaf_count, &stack, &mut zc)?)
    } else {
        None
    };

    let mut file_entry: Vec<(&[u8], Bencode)> = vec![(b"length", Bencode::Int(size as i64))];
    if let Some(root) = pieces_root {
        file_entry.push((b"pieces root", Bencode::Bytes(root.to_vec())));
    }

    let info = dict([
        (
            b"file tree".as_slice(),
            dict([(name, dict([(b"".as_slice(), dict(file_entry))]))]),
        ),
        (b"length", Bencode::Int(size as i64)),
        (b"meta version", Bencode::Int(META_VERSION)),
        (b"name", Bencode::Bytes(name.to_vec())),
        (b"piece length", Bencode::Int(piece_length as i64)),
        (b"pieces", Bencode::Bytes(pieces_v1)),
    ]);
    let info_bytes = info.encode();

    let piece_layers = match pieces_root {
        Some(root) if size > piece_length => dict([(root.as_slice(), Bencode::Bytes(layers_v2))]),
        _ => dict::<&[u8], _>([]),
    };

    let torrent = dict([(b"info".as_slice(), info), (b"piece layers", piece_layers)]).encode();

    Ok(Identity {
        btih: Sha1::digest(&info_bytes).into(),
        btmh: Sha256::digest(&info_bytes).into(),
        torrent,
        piece_length,
        name: name.to_vec(),
        size,
    })
}

/// Fills `buf` from `r`, stopping at EOF or when the buffer is full.
///
/// `r` is expected to be a file-backed reader where `read` returning `0`
/// means EOF; that assumption is relied on by [`build_identity`].
fn read_up_to<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..])? {
            0 => break,
            k => n += k,
        }
    }
    Ok(n)
}
