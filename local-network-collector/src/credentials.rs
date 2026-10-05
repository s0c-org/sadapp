use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};

use crate::model::Credentials;

const CREDENTIAL_FILE: &str = "credentials.json";

pub fn ensure_state_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)
        .with_context(|| format!("create state directory {}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("secure state directory {}", path.display()))
}

pub fn load(state_dir: &Path) -> Result<Option<Credentials>> {
    let path = state_dir.join(CREDENTIAL_FILE);
    match fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .context("parse persisted collector credentials")
            .map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("read {}", path.display())),
    }
}

pub fn persist(state_dir: &Path, credentials: &Credentials) -> Result<()> {
    ensure_state_dir(state_dir)?;
    atomic_write(
        &state_dir.join(CREDENTIAL_FILE),
        &serde_json::to_vec(credentials)?,
    )
}

pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let temporary = temporary_path(path);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .with_context(|| format!("create temporary state file {}", temporary.display()))?;
    let result = (|| -> Result<()> {
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)?;
        if let Some(parent) = path.parent() {
            OpenOptions::new().read(true).open(parent)?.sync_all()?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.with_context(|| format!("atomically write {}", path.display()))
}

fn temporary_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("state");
    path.with_file_name(format!(".{name}.{}.tmp", uuid::Uuid::new_v4()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persists_with_restricted_permissions() {
        let directory = tempfile::tempdir().unwrap();
        let state = directory.path().join("state");
        let credentials = Credentials {
            collector_id: "a".into(),
            collector_secret: "s".into(),
        };
        persist(&state, &credentials).unwrap();
        assert_eq!(
            fs::metadata(&state).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(state.join(CREDENTIAL_FILE))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(load(&state).unwrap().unwrap().collector_id, "a");
    }
}
