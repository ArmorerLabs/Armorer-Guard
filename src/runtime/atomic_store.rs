use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;
#[cfg(windows)]
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{de::DeserializeOwned, Serialize};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(1);

pub(super) fn read_json<T: DeserializeOwned>(path: &Path) -> Result<Option<T>, String> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|error| format!("invalid persisted JSON at {}: {error}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("failed to read {}: {error}", path.display())),
    }
}

pub(super) fn atomic_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("failed to serialize {}: {error}", path.display()))?;
    atomic_write(path, &bytes)
}

pub(super) fn append_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    ensure_parent(path)?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| format!("failed to open {}: {error}", path.display()))?;
    restrict(&file)?;
    serde_json::to_writer(&mut file, value)
        .map_err(|error| format!("failed to serialize {}: {error}", path.display()))?;
    file.write_all(b"\n")
        .map_err(|error| format!("failed to append {}: {error}", path.display()))?;
    file.sync_data()
        .map_err(|error| format!("failed to flush {}: {error}", path.display()))
}

pub(super) fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    ensure_parent(path)?;
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| format!("invalid snapshot path: {}", path.display()))?;
    let temp = path.with_file_name(format!(
        ".{file_name}.tmp-{}-{}",
        std::process::id(),
        TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .map_err(|error| format!("failed to create {}: {error}", temp.display()))?;
        restrict(&file)?;
        file.write_all(bytes)
            .map_err(|error| format!("failed to write {}: {error}", temp.display()))?;
        file.sync_all()
            .map_err(|error| format!("failed to sync {}: {error}", temp.display()))?;
        drop(file);
        activate(&temp, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

#[cfg(unix)]
fn activate(temp: &Path, path: &Path) -> Result<(), String> {
    rename(temp, path)?;
    if let Some(parent) = path.parent() {
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("failed to sync {}: {error}", parent.display()))?;
    }
    Ok(())
}

#[cfg(windows)]
fn activate(temp: &Path, path: &Path) -> Result<(), String> {
    use std::iter;
    use std::os::windows::ffi::OsStrExt;

    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    let canonical_parent = path
        .parent()
        .ok_or_else(|| format!("snapshot path has no parent: {}", path.display()))?
        .canonicalize()
        .map_err(|error| format!("failed to resolve snapshot directory: {error}"))?;
    let source = canonical_sibling(&canonical_parent, temp)?;
    let destination = canonical_sibling(&canonical_parent, path)?;
    let source_wide: Vec<u16> = source
        .as_os_str()
        .encode_wide()
        .chain(iter::once(0))
        .collect();
    let destination_wide: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(iter::once(0))
        .collect();
    let flags = MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH;
    let moved = unsafe { MoveFileExW(source_wide.as_ptr(), destination_wide.as_ptr(), flags) };
    if moved == 0 {
        return Err(format!(
            "failed to atomically activate {} from {}: {}",
            path.display(),
            temp.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn canonical_sibling(parent: &Path, path: &Path) -> Result<PathBuf, String> {
    let file_name = path
        .file_name()
        .ok_or_else(|| format!("snapshot path has no file name: {}", path.display()))?;
    Ok(parent.join(file_name))
}

#[cfg(not(any(unix, windows)))]
fn activate(temp: &Path, path: &Path) -> Result<(), String> {
    rename(temp, path)
}

#[cfg(not(windows))]
fn rename(temp: &Path, path: &Path) -> Result<(), String> {
    fs::rename(temp, path).map_err(|error| {
        format!(
            "failed to atomically activate {} from {}: {error}",
            path.display(),
            temp.display()
        )
    })
}

fn ensure_parent(path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("failed to create {}: {error}", parent.display()))?;
    }
    Ok(())
}

#[cfg(unix)]
fn restrict(file: &File) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("failed to restrict persisted Guard state: {error}"))
}

#[cfg(not(unix))]
fn restrict(_file: &File) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_snapshot_round_trips() {
        let directory = std::env::temp_dir().join(format!(
            "guard-atomic-test-{}-{}",
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let path = directory.join("snapshot.json");
        atomic_json(&path, &serde_json::json!({"revision": 3})).unwrap();
        let value: serde_json::Value = read_json(&path).unwrap().unwrap();
        assert_eq!(value["revision"], 3);

        atomic_json(&path, &serde_json::json!({"revision": 4})).unwrap();
        let replaced: serde_json::Value = read_json(&path).unwrap().unwrap();
        assert_eq!(replaced["revision"], 4);
    }

    #[test]
    fn interrupted_temporary_snapshot_cannot_replace_last_known_good() {
        let directory = std::env::temp_dir().join(format!(
            "guard-atomic-recovery-{}-{}",
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let path = directory.join("snapshot.json");
        atomic_json(&path, &serde_json::json!({"revision": 8})).unwrap();
        fs::write(directory.join(".snapshot.json.tmp-interrupted"), b"{broken").unwrap();
        let value: serde_json::Value = read_json(&path).unwrap().unwrap();
        assert_eq!(value["revision"], 8);
    }
}
