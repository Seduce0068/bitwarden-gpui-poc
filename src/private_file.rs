//! Write files that may contain sensitive data with restricted permissions.
//!
//! On Unix the directory is created with `0700` and the file with `0600`.
//! Writes go to a uniquely named temporary file followed by an atomic rename.
//!
//! `tempfile` is reused rather than hand-rolling temp paths: it uses
//! `create_new(true)` (no symlink following or race), sets `0600` on Unix,
//! and its RAII guard removes the file on normal error returns. A forced
//! process termination can still leave a temporary file behind.

use std::io;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::DirBuilderExt;

/// Resolve the directory that holds `path`.
///
/// `Path::parent()` returns `Some("")` for a bare relative name such as
/// `foo.json`; treating that as a literal empty path would make `File::open`
/// fail after the write already succeeded.
fn parent_dir(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

/// Create parent directories and atomically replace `path` with `contents`.
///
/// # Errors
///
/// Returns `std::io::Error` when a directory cannot be created, the temporary
/// file cannot be written or synced, or the rename fails. Syncing the parent
/// directory afterwards is best-effort: the rename has already committed at
/// that point, so a failure there is not reported as a write failure.
pub fn write_private(path: &Path, contents: &[u8]) -> io::Result<()> {
    let parent = parent_dir(path);
    {
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        builder.mode(0o700);
        builder.create(parent)?;
    }

    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    {
        use std::io::Write as _;
        temp.write_all(contents)?;
        temp.flush()?;
        temp.as_file().sync_all()?;
    }
    // Replaces the destination atomically and corrects its permissions to
    // those of the fresh temporary file. On failure the guard cleans up.
    temp.persist(path)?;

    // Make the rename durable, not just the file contents. Best-effort: the
    // rename is already committed, so a failure here must not be reported as
    // "save failed" to the user.
    #[cfg(unix)]
    {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[::core::prelude::v1::test]
    fn write_private_sets_restrictive_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join("bitwarden-gpui-poc-perms-test");
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("nested").join("data.json");

        write_private(&path, b"secret").unwrap();

        let dir_mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        let file_mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "directory must be private");
        assert_eq!(file_mode, 0o600, "file must be readable only by owner");
    }

    #[::core::prelude::v1::test]
    fn write_private_corrects_permissions_of_an_existing_file() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let dir = std::env::temp_dir().join("bitwarden-gpui-poc-perms-replace");
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("data.json");
            std::fs::write(&path, b"old").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

            write_private(&path, b"new").unwrap();

            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "replacement must be private");
            assert_eq!(std::fs::read(&path).unwrap(), b"new");
        }
    }

    #[::core::prelude::v1::test]
    fn write_private_replaces_existing_content_and_leaves_no_temp() {
        let dir = std::env::temp_dir().join("bitwarden-gpui-poc-atomic-test");
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("nested").join("data.json");

        write_private(&path, b"first").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"first");
        assert_only_file(&dir.join("nested"), "data.json");

        write_private(&path, b"second").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second");
        assert_only_file(&dir.join("nested"), "data.json");
    }

    #[::core::prelude::v1::test]
    fn parallel_writes_to_the_same_path_are_atomic() {
        let dir = std::env::temp_dir().join("bitwarden-gpui-poc-parallel-test");
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("shared.json");

        std::thread::scope(|scope| {
            for byte in *b"abcd" {
                let path = &path;
                scope.spawn(move || write_private(path, &[byte]).unwrap());
            }
        });

        let content = std::fs::read(&path).unwrap();
        assert_eq!(content.len(), 1, "exactly one writer must win: {content:?}");
        assert!(matches!(content[0], b'a' | b'b' | b'c' | b'd'));
        assert_only_file(&dir, "shared.json");
    }

    #[::core::prelude::v1::test]
    fn parent_dir_handles_bare_relative_names() {
        assert_eq!(parent_dir(Path::new("foo.json")), Path::new("."));
        assert_eq!(
            parent_dir(Path::new("/tmp/a/foo.json")),
            Path::new("/tmp/a")
        );
        assert_eq!(parent_dir(Path::new("a/foo.json")), Path::new("a"));
    }

    /// No temporary file survived: the only entry is the destination itself.
    fn assert_only_file(dir: &Path, file_name: &str) {
        let entries: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(entries, vec![file_name.to_string()]);
    }
}
