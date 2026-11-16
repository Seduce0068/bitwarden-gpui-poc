//! Write files that may contain sensitive data with restricted permissions.
//!
//! On Unix the directory is created with `0700` and the file with `0600`.
//! Writes go to a temporary file followed by an atomic rename, so an
//! interrupted write never leaves a partially written settings/cache file.

use std::io;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

/// Create a sibling temporary path for `path`.
fn temp_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".to_string());
    path.with_file_name(format!(".{name}.tmp"))
}

/// Create parent directories and atomically replace `path` with `contents`.
///
/// # Errors
///
/// Returns `std::io::Error` when a directory cannot be created, the temporary
/// file cannot be written, or the rename fails.
pub fn write_private(path: &Path, contents: &[u8]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        builder.mode(0o700);
        builder.create(parent)?;
    }

    let temp = temp_path(path);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    options.mode(0o600);

    {
        use std::io::Write as _;
        let mut file = options.open(&temp)?;
        file.write_all(contents)?;
        file.flush()?;
        #[cfg(unix)]
        file.sync_all()?;
    }

    match std::fs::rename(&temp, path) {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = std::fs::remove_file(&temp);
            Err(error)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[::core::prelude::v1::test]
    fn write_private_replaces_existing_content_and_leaves_no_temp() {
        let dir = std::env::temp_dir().join("bitwarden-gpui-poc-atomic-test");
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("nested").join("data.json");
        let temp = temp_path(&path);

        write_private(&path, b"first").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"first");
        assert!(!temp.exists());

        write_private(&path, b"second").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second");
        assert!(!temp.exists());
    }
}
