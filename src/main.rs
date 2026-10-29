//! Entry point. All logic lives in the `btsum` library crate.

use std::process::ExitCode;

fn main() -> ExitCode {
    btsum::cli::run()
}
