use std::{path::Path, sync::Arc};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::{credentials::atomic_write, network_policy::NetworkPolicy};

const CONFIG_FILE: &str = "collector-config.json";

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectorConfig {
    pub revision: u64,
    pub allowed_cidrs: Vec<String>,
}

impl CollectorConfig {
    pub fn policy(&self) -> Result<NetworkPolicy> {
        NetworkPolicy::new(&self.allowed_cidrs)
    }
}

pub type SharedCollectorConfig = Arc<RwLock<CollectorConfig>>;

pub fn load(state_dir: &Path) -> Result<CollectorConfig> {
    let path = state_dir.join(CONFIG_FILE);
    match std::fs::read(&path) {
        Ok(bytes) => {
            let config: CollectorConfig = serde_json::from_slice(&bytes)
                .context("parse persisted collector configuration")?;
            config.policy()?;
            Ok(config)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(CollectorConfig::default())
        }
        Err(error) => Err(error).with_context(|| format!("read {}", path.display())),
    }
}

pub fn persist(state_dir: &Path, config: &CollectorConfig) -> Result<()> {
    config.policy()?;
    atomic_write(&state_dir.join(CONFIG_FILE), &serde_json::to_vec(config)?)
}
