//! Write files that may contain sensitive data with restricted permissions.
//!
//! On Unix the directory is created with `0700` and the file with `0600`.
//! On other platforms the normal OS defaults apply.

use std::io;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

/// Create parent directories and write `contents` to `path` atomically enough
/// for a PoC: the file itself is created with restrictive permissions from
/// the start, so no window exists where another user can read it.
///
/// # Errors
///
/// Returns `std::io::Error` when a directory cannot be created or the file
/// cannot be opened or written.
pub fn write_private(path: &Path, contents: &[u8]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        builder.mode(0o700);
        builder.create(parent)?;
    }

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    options.mode(0o600);

    use std::io::Write as _;
    let mut file = options.open(path)?;
    file.write_all(contents)
}
