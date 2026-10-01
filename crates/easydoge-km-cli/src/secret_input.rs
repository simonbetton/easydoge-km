//! Resolves secret CLI arguments from a literal flag, a file, or standard input.
//!
//! Secrets passed as literal flag values end up in shell history and are
//! visible to other local users through process listings, so every
//! secret-bearing flag `--<name>` has a companion `--<name>-file <PATH>`.
//! The path `-` selects standard input.

use anyhow::{anyhow, bail, Result};
use std::fs::File;
use std::io::{self, Read};
use zeroize::{Zeroize, Zeroizing};

/// Upper bound on a secret read from a file or standard input.
pub(crate) const MAX_SECRET_BYTES: u64 = 64 * 1024;

/// Path value that selects standard input for a `--<name>-file` flag.
const STDIN_PATH: &str = "-";

/// Resolves the secret arguments of one CLI invocation.
///
/// Standard input can supply at most one secret, so a single value is shared
/// by every secret flag that one subcommand resolves.
#[derive(Default)]
pub(crate) struct SecretInput {
    stdin_taken: bool,
}

impl SecretInput {
    /// Resolves a secret that the subcommand cannot run without.
    ///
    /// `name` is the flag name without dashes, for example `"phrase"` for
    /// `--phrase` and `--phrase-file`.
    pub(crate) fn required(
        &mut self,
        name: &str,
        literal: Option<String>,
        file: Option<String>,
    ) -> Result<String> {
        self.optional(name, literal, file)?
            .ok_or_else(|| anyhow!("provide --{name}-file <path> or --{name}"))
    }

    /// Resolves a secret that may be omitted, such as a BIP39 passphrase.
    pub(crate) fn optional(
        &mut self,
        name: &str,
        literal: Option<String>,
        file: Option<String>,
    ) -> Result<Option<String>> {
        match (literal, file) {
            (Some(_), Some(_)) => bail!("provide only one of --{name} or --{name}-file"),
            (Some(value), None) => {
                eprintln!(
                    "warning: --{name} on the command line is visible in shell history and process listings; prefer --{name}-file <path> or --{name}-file -"
                );
                Ok(Some(value))
            }
            (None, Some(path)) => self.read(name, &path).map(Some),
            (None, None) => Ok(None),
        }
    }

    fn read(&mut self, name: &str, path: &str) -> Result<String> {
        let from_stdin = path == STDIN_PATH;
        // Error messages name the flag and the path only, never what was read.
        let source = if from_stdin {
            format!("--{name}-file - (standard input)")
        } else {
            format!("--{name}-file '{path}'")
        };
        let bytes = if from_stdin {
            if self.stdin_taken {
                bail!("{source}: only one secret may be read from standard input");
            }
            self.stdin_taken = true;
            read_bounded(io::stdin().lock(), MAX_SECRET_BYTES)
        } else {
            File::open(path).and_then(|file| read_bounded(file, MAX_SECRET_BYTES))
        }
        .map_err(|error| anyhow!("cannot read {source}: {error}"))?;
        // The file contents are wiped when this function returns; only the
        // returned copy, without its line ending, stays with the caller.
        let text = Zeroizing::new(String::from_utf8(bytes).map_err(|error| {
            // The error owns the bytes that were read: wipe them, never print them.
            error.into_bytes().zeroize();
            anyhow!("{source} is not valid UTF-8")
        })?);
        let secret = strip_one_line_ending(&text);
        if secret.is_empty() {
            bail!("{source} is empty");
        }
        Ok(secret.to_owned())
    }
}

/// Reads `reader` to its end and fails once it yields more than `max_bytes`.
pub(crate) fn read_bounded(reader: impl Read, max_bytes: u64) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("input is larger than {max_bytes} bytes"),
        ));
    }
    Ok(bytes)
}

/// Removes exactly one trailing `\n` or `\r\n`. Every other character is
/// kept because a BIP39 passphrase may legitimately start or end with
/// whitespace.
fn strip_one_line_ending(text: &str) -> &str {
    text.strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_exactly_one_trailing_line_ending() {
        assert_eq!(strip_one_line_ending("TREZOR\n"), "TREZOR");
        assert_eq!(strip_one_line_ending("TREZOR\r\n"), "TREZOR");
        assert_eq!(strip_one_line_ending("TREZOR\n\n"), "TREZOR\n");
        assert_eq!(strip_one_line_ending(" TREZOR \n"), " TREZOR ");
        assert_eq!(strip_one_line_ending("TREZOR"), "TREZOR");
        assert_eq!(strip_one_line_ending("TREZOR\r"), "TREZOR\r");
        assert_eq!(strip_one_line_ending(""), "");
    }

    #[test]
    fn bounded_read_accepts_the_limit_and_rejects_one_byte_more() {
        assert_eq!(read_bounded(&[7u8; 8][..], 8).unwrap().len(), 8);
        let error = read_bounded(&[7u8; 9][..], 8).unwrap_err();
        assert!(error.to_string().contains("larger than 8 bytes"));
    }
}
