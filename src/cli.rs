//! CLI: argument parsing and dispatch (SPEC.md section 8).

use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{ArgAction, Parser};

use crate::identity::build_identity;
use crate::magnet::magnet_for;
use crate::reference::{BTIH_LEN, BTMH_LEN, parse_hash_ref};
use crate::url::{hex_encode, latin1_to_string};
use crate::{BtsumError, PROG, Result, VERSION};

#[derive(Parser, Debug)]
#[command(
    name = PROG,
    version = VERSION,
    about = "Deterministic BitTorrent identity for single files."
)]
struct Cli {
    #[arg(short = '1', long = "v1", action = ArgAction::SetTrue)]
    v1: bool,
    #[arg(short = '2', long = "v2", action = ArgAction::SetTrue, conflicts_with = "v1")]
    v2: bool,
    #[arg(long = "hashes", action = ArgAction::SetTrue, conflicts_with_all = ["v1", "v2", "pair"])]
    hashes: bool,
    #[arg(long = "pair", action = ArgAction::SetTrue, conflicts_with_all = ["v1", "v2", "hashes"])]
    pair: bool,
    #[arg(short = 'n', long = "name", value_name = "NAME",
          value_parser = clap::value_parser!(OsString))]
    name: Option<OsString>,
    #[arg(short = 't', long = "torrent", value_name = "PATH",
          num_args = 0..=1, value_parser = clap::value_parser!(OsString))]
    torrent: Option<Option<OsString>>,
    #[arg(short = 'c', long = "check", value_name = "REF",
          value_parser = clap::value_parser!(OsString))]
    check: Option<OsString>,
    #[arg(value_name = "FILE", value_parser = clap::value_parser!(OsString))]
    files: Vec<OsString>,
}

enum TorrentMode {
    Off,
    NextToInput,
    Explicit(PathBuf),
}

/// Entry point: parse argv and dispatch to `run_hash` or `run_check`.
///
/// Returns the process exit code (0 = all OK, 1 = at least one mismatch,
/// 2 = usage or I/O error), matching SPEC.md section 8.3.
pub fn run() -> ExitCode {
    let cli = Cli::parse();
    let res = if cli.check.is_some() {
        run_check(&cli)
    } else {
        run_hash(&cli)
    };
    match res {
        Ok(code) => ExitCode::from(code as u8),
        Err(e) => {
            eprintln!("{PROG}: error: {e}");
            ExitCode::from(2)
        }
    }
}

fn run_check(cli: &Cli) -> Result<i32> {
    if cli.torrent.is_some() {
        return Err(BtsumError::Usage(
            "-c cannot be combined with -t/--torrent".into(),
        ));
    }
    if cli.v1 || cli.v2 || cli.hashes || cli.pair {
        return Err(BtsumError::Usage(
            "-c cannot be combined with -1/-2/--hashes/--pair".into(),
        ));
    }
    let check_os = cli.check.as_ref().unwrap();
    let check = check_os
        .to_str()
        .ok_or_else(|| BtsumError::Usage("check reference is not valid UTF-8".into()))?;
    let parsed = parse_hash_ref(check)?;

    match parsed {
        None => {
            if let Some(first) = cli.files.first() {
                return Err(BtsumError::Usage(format!(
                    "extra operand after checksum listing: {}",
                    first.to_string_lossy()
                )));
            }
            check_listing(
                Path::new(check_os),
                cli.name.as_deref().map(|s| s.as_encoded_bytes()),
            )
        }
        Some(hr) => {
            if cli.files.is_empty() {
                return Err(BtsumError::Usage(
                    "-c needs at least one FILE to check".into(),
                ));
            }
            let hint = hr.name.is_none() && cli.name.is_none();
            let mut status = 0;
            for f in &cli.files {
                let path = Path::new(f);
                let bound: Vec<u8> = if let Some(n) = &cli.name {
                    n.as_encoded_bytes().to_vec()
                } else if let Some(n) = &hr.name {
                    n.clone()
                } else {
                    path.file_name()
                        .map(|s| s.as_encoded_bytes())
                        .unwrap_or(b"")
                        .to_vec()
                };
                if !check_file(
                    f.as_encoded_bytes(),
                    path,
                    &bound,
                    hr.v1.as_ref(),
                    hr.v2.as_ref(),
                    hint,
                )? {
                    status = 1;
                }
            }
            Ok(status)
        }
    }
}

fn run_hash(cli: &Cli) -> Result<i32> {
    let mut files: Vec<OsString> = cli.files.clone();
    let mode = match &cli.torrent {
        None => TorrentMode::Off,
        Some(None) => TorrentMode::NextToInput,
        Some(Some(p)) => {
            if files.is_empty() {
                // `-t PATH` with no other operand: PATH is the input.
                files.push(p.clone());
                TorrentMode::NextToInput
            } else if files.len() == 1 {
                TorrentMode::Explicit(PathBuf::from(p))
            } else {
                return Err(BtsumError::Usage(
                    "--torrent PATH is only valid with a single FILE".into(),
                ));
            }
        }
    };
    if cli.name.is_some() && files.len() > 1 {
        return Err(BtsumError::Usage(
            "--name is only valid with a single FILE".into(),
        ));
    }
    if files.is_empty() {
        return Err(BtsumError::Usage("no input files".into()));
    }

    let stdout = io::stdout();
    let mut out = stdout.lock();
    for input in &files {
        let path = Path::new(input);
        let name: Vec<u8> = match &cli.name {
            Some(n) => n.as_encoded_bytes().to_vec(),
            None => path
                .file_name()
                .map(|s| s.as_encoded_bytes())
                .unwrap_or(b"")
                .to_vec(),
        };
        let ident = build_identity(path, &name)?;

        if cli.v1 {
            writeln!(
                out,
                "{}  {}",
                hex_encode(&ident.btih),
                String::from_utf8_lossy(&name)
            )?;
        } else if cli.v2 {
            writeln!(
                out,
                "{}  {}",
                hex_encode(&ident.btmh),
                String::from_utf8_lossy(&name)
            )?;
        } else if cli.hashes {
            writeln!(
                out,
                "{}  {}",
                hex_encode(&ident.btih),
                String::from_utf8_lossy(&name)
            )?;
            writeln!(
                out,
                "{}  {}",
                hex_encode(&ident.btmh),
                String::from_utf8_lossy(&name)
            )?;
        } else if cli.pair {
            writeln!(
                out,
                "{}+{}  {}",
                hex_encode(&ident.btih),
                hex_encode(&ident.btmh),
                String::from_utf8_lossy(&name)
            )?;
        } else {
            writeln!(out, "{}", magnet_for(&ident.btih, &ident.btmh, &name))?;
        }

        match &mode {
            TorrentMode::Off => {}
            TorrentMode::NextToInput => {
                let mut s = input.clone();
                s.push(".torrent");
                fs::write(PathBuf::from(s), &ident.torrent)?;
            }
            TorrentMode::Explicit(p) => {
                fs::write(p, &ident.torrent)?;
            }
        }
    }
    Ok(0)
}

fn check_file(
    display: &[u8],
    path: &Path,
    bound_name: &[u8],
    v1: Option<&[u8; BTIH_LEN]>,
    v2: Option<&[u8; BTMH_LEN]>,
    hint: bool,
) -> Result<bool> {
    let ident = build_identity(path, bound_name)?;
    let (mut label, mut ok) = (Vec::new(), true);
    if let Some(h) = v1 {
        label.push("v1");
        ok &= &ident.btih == h;
    }
    if let Some(h) = v2 {
        label.push("v2");
        ok &= &ident.btmh == h;
    }
    let label = label.join("+");

    let stdout = io::stdout();
    let mut out = stdout.lock();
    out.write_all(display)?;
    if ok {
        writeln!(out, ": OK ({label})")?;
    } else {
        writeln!(out, ": FAILED ({label} mismatch)")?;
        if hint {
            eprintln!(
                "{PROG}: note: the reference carries no file name and the name \
                 is part of the identity; check against the original magnet or \
                 pass --name NAME to rebind"
            );
        }
    }
    Ok(ok)
}

fn check_listing(listing_path: &Path, name_override: Option<&[u8]>) -> Result<i32> {
    let data = fs::read(listing_path)?;
    let mut status = 0;
    for (i, raw_line) in data.split(|&b| b == b'\n').enumerate() {
        let line = raw_line.trim_ascii();
        if line.is_empty() || line[0] == b'#' {
            continue;
        }
        let text = latin1_to_string(line);
        let hr = match parse_hash_ref(&text)? {
            None => {
                return Err(BtsumError::Fatal(format!(
                    "{}: line {}: not a magnet or hash line: {text}",
                    listing_path.display(),
                    i + 1
                )));
            }
            Some(h) => h,
        };
        let name = hr.name.ok_or_else(|| {
            BtsumError::Fatal(format!(
                "{}: line {}: listing entry carries no dn name: {text}",
                listing_path.display(),
                i + 1
            ))
        })?;
        let bound = name_override
            .map(<[u8]>::to_vec)
            .unwrap_or_else(|| name.clone());
        let bound_str = std::str::from_utf8(&bound).map_err(|_| {
            BtsumError::Fatal(format!(
                "{}: line {}: bound name is not valid UTF-8",
                listing_path.display(),
                i + 1
            ))
        })?;
        let path = PathBuf::from(bound_str);
        if !check_file(&name, &path, &bound, hr.v1.as_ref(), hr.v2.as_ref(), false)? {
            status = 1;
        }
    }
    Ok(status)
}
