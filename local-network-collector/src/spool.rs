use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use serde::{de::DeserializeOwned, Serialize};

use crate::credentials::{atomic_write, ensure_state_dir};

#[derive(Clone, Copy, Debug, Default)]
pub struct SpoolStats {
    pub items: usize,
    pub bytes: u64,
}

#[derive(Clone, Debug)]
pub struct Spool {
    directory: PathBuf,
    max_items: usize,
    max_bytes: u64,
}

impl Spool {
    pub fn open(state_dir: &Path, name: &str, max_items: usize, max_bytes: u64) -> Result<Self> {
        ensure_state_dir(state_dir)?;
        let directory = state_dir.join(name);
        fs::create_dir_all(&directory)?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
        let spool = Self {
            directory,
            max_items,
            max_bytes,
        };
        spool.enforce_bounds()?;
        Ok(spool)
    }

    pub fn push<T: Serialize>(&self, value: &T) -> Result<PathBuf> {
        let bytes = serde_json::to_vec(value)?;
        if bytes.len() as u64 > self.max_bytes {
            bail!("spool item exceeds byte limit");
        }
        let name = format!(
            "{:020}-{}.json",
            chrono::Utc::now().timestamp_micros(),
            uuid::Uuid::new_v4()
        );
        let path = self.directory.join(name);
        atomic_write(&path, &bytes)?;
        self.enforce_bounds()?;
        Ok(path)
    }

    pub fn oldest<T: DeserializeOwned>(&self) -> Result<Option<(PathBuf, T)>> {
        let Some(path) = self.paths()?.into_iter().next() else {
            return Ok(None);
        };
        let value = serde_json::from_slice(&fs::read(&path)?)
            .with_context(|| format!("parse spool item {}", path.display()))?;
        Ok(Some((path, value)))
    }

    pub fn remove(&self, path: &Path) -> Result<()> {
        if path.parent() != Some(self.directory.as_path()) {
            bail!("refusing to remove a file outside the spool");
        }
        fs::remove_file(path)
            .with_context(|| format!("remove acknowledged spool item {}", path.display()))
    }

    pub fn stats(&self) -> Result<SpoolStats> {
        self.paths()?
            .iter()
            .try_fold(SpoolStats::default(), |mut stats, path| {
                stats.items += 1;
                stats.bytes += fs::metadata(path)?.len();
                Ok(stats)
            })
    }

    fn enforce_bounds(&self) -> Result<()> {
        let paths = self.paths()?;
        let mut stats = paths
            .iter()
            .try_fold(SpoolStats::default(), |mut stats, path| {
                stats.items += 1;
                stats.bytes += fs::metadata(path)?.len();
                Ok::<_, std::io::Error>(stats)
            })?;
        for path in paths {
            if stats.items <= self.max_items && stats.bytes <= self.max_bytes {
                break;
            }
            let size = fs::metadata(&path)?.len();
            fs::remove_file(path)?;
            stats.items -= 1;
            stats.bytes -= size;
        }
        Ok(())
    }

    fn paths(&self) -> Result<Vec<PathBuf>> {
        let mut paths = fs::read_dir(&self.directory)?
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("json"))
            .collect::<Vec<_>>();
        paths.sort();
        Ok(paths)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persists_across_reopen_and_removes_only_after_ack() {
        let directory = tempfile::tempdir().unwrap();
        let spool = Spool::open(directory.path(), "results", 4, 1024).unwrap();
        spool.push(&serde_json::json!({"sequence": 1})).unwrap();
        let reopened = Spool::open(directory.path(), "results", 4, 1024).unwrap();
        let (path, value) = reopened.oldest::<serde_json::Value>().unwrap().unwrap();
        assert_eq!(value["sequence"], 1);
        reopened.remove(&path).unwrap();
        assert_eq!(reopened.stats().unwrap().items, 0);
    }

    #[test]
    fn evicts_oldest_items_to_enforce_bounds() {
        let directory = tempfile::tempdir().unwrap();
        let spool = Spool::open(directory.path(), "results", 2, 1024).unwrap();
        spool.push(&serde_json::json!({"sequence": 1})).unwrap();
        spool.push(&serde_json::json!({"sequence": 2})).unwrap();
        spool.push(&serde_json::json!({"sequence": 3})).unwrap();
        assert_eq!(spool.stats().unwrap().items, 2);
        let (_, oldest) = spool.oldest::<serde_json::Value>().unwrap().unwrap();
        assert_eq!(oldest["sequence"], 2);
    }
}
