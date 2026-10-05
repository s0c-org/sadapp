use std::{env, path::PathBuf, time::Duration};

use anyhow::{bail, Context, Result};
use url::Url;

pub const MIN_HEARTBEAT_SECONDS: u64 = 5;
pub const MAX_HEARTBEAT_SECONDS: u64 = 300;
pub const MAX_CONCURRENT_TASKS: usize = 32;

#[derive(Clone, Debug)]
pub struct Config {
    pub control_plane_url: Url,
    pub enrollment_token: Option<String>,
    pub collector_id: Option<String>,
    pub collector_secret: Option<String>,
    pub state_dir: PathBuf,
    pub heartbeat_interval: Duration,
    pub max_concurrent_tasks: usize,
    pub health_port: Option<u16>,
    pub spool_max_items: usize,
    pub spool_max_bytes: u64,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        Self::from_lookup(|key| env::var(key).ok())
    }

    fn from_lookup(mut lookup: impl FnMut(&str) -> Option<String>) -> Result<Self> {
        let raw_url = required(&mut lookup, "CONTROL_PLANE_URL")?;
        let control_plane_url = Url::parse(&raw_url).context("CONTROL_PLANE_URL is invalid")?;
        if control_plane_url.scheme() != "https"
            && !(control_plane_url.scheme() == "http"
                && matches!(
                    control_plane_url.host_str(),
                    Some("127.0.0.1" | "localhost" | "::1")
                ))
        {
            bail!(
                "CONTROL_PLANE_URL must use HTTPS (HTTP is allowed only for loopback development)"
            );
        }

        let heartbeat_seconds = parse(&mut lookup, "HEARTBEAT_INTERVAL_SECONDS", 30_u64)?;
        if !(MIN_HEARTBEAT_SECONDS..=MAX_HEARTBEAT_SECONDS).contains(&heartbeat_seconds) {
            bail!("HEARTBEAT_INTERVAL_SECONDS must be between {MIN_HEARTBEAT_SECONDS} and {MAX_HEARTBEAT_SECONDS}");
        }
        let max_concurrent_tasks = parse(&mut lookup, "MAX_CONCURRENT_TASKS", 4_usize)?;
        if !(1..=MAX_CONCURRENT_TASKS).contains(&max_concurrent_tasks) {
            bail!("MAX_CONCURRENT_TASKS must be between 1 and {MAX_CONCURRENT_TASKS}");
        }

        let enrollment_token = lookup("ENROLLMENT_TOKEN").filter(|value| !value.is_empty());
        let collector_id = lookup("COLLECTOR_ID").filter(|value| !value.is_empty());
        let collector_secret = lookup("COLLECTOR_SECRET").filter(|value| !value.is_empty());
        if collector_id.is_some() != collector_secret.is_some() {
            bail!("COLLECTOR_ID and COLLECTOR_SECRET must be provided together");
        }

        Ok(Self {
            control_plane_url,
            enrollment_token,
            collector_id,
            collector_secret,
            state_dir: PathBuf::from(
                lookup("STATE_DIR")
                    .unwrap_or_else(|| "/var/lib/sadapp-local-network-collector".into()),
            ),
            heartbeat_interval: Duration::from_secs(heartbeat_seconds),
            max_concurrent_tasks,
            health_port: optional_parse(&mut lookup, "HEALTH_PORT")?,
            spool_max_items: parse(&mut lookup, "SPOOL_MAX_ITEMS", 10_000_usize)?,
            spool_max_bytes: parse(&mut lookup, "SPOOL_MAX_BYTES", 64 * 1024 * 1024_u64)?,
        })
    }
}

fn required(lookup: &mut impl FnMut(&str) -> Option<String>, key: &str) -> Result<String> {
    lookup(key)
        .filter(|value| !value.is_empty())
        .with_context(|| format!("{key} is required"))
}

fn parse<T: std::str::FromStr>(
    lookup: &mut impl FnMut(&str) -> Option<String>,
    key: &str,
    default: T,
) -> Result<T>
where
    T::Err: std::error::Error + Send + Sync + 'static,
{
    lookup(key)
        .map(|value| value.parse().with_context(|| format!("{key} is invalid")))
        .unwrap_or(Ok(default))
}

fn optional_parse<T: std::str::FromStr>(
    lookup: &mut impl FnMut(&str) -> Option<String>,
    key: &str,
) -> Result<Option<T>>
where
    T::Err: std::error::Error + Send + Sync + 'static,
{
    lookup(key)
        .map(|value| {
            value
                .parse()
                .map(Some)
                .with_context(|| format!("{key} is invalid"))
        })
        .unwrap_or(Ok(None))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn config(values: &[(&str, &str)]) -> Result<Config> {
        let values = values
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect::<HashMap<_, _>>();
        Config::from_lookup(|key| values.get(key).cloned())
    }

    #[test]
    fn parses_valid_config() {
        let value = config(&[
            ("CONTROL_PLANE_URL", "https://control.example"),
            ("MAX_CONCURRENT_TASKS", "8"),
        ])
        .unwrap();
        assert_eq!(value.max_concurrent_tasks, 8);
        assert_eq!(value.heartbeat_interval, Duration::from_secs(30));
    }

    #[test]
    fn rejects_non_loopback_http_and_out_of_bounds_values() {
        assert!(config(&[("CONTROL_PLANE_URL", "http://control.example")]).is_err());
        assert!(config(&[
            ("CONTROL_PLANE_URL", "https://control.example"),
            ("HEARTBEAT_INTERVAL_SECONDS", "1")
        ])
        .is_err());
        assert!(config(&[
            ("CONTROL_PLANE_URL", "https://control.example"),
            ("MAX_CONCURRENT_TASKS", "0")
        ])
        .is_err());
    }

    #[test]
    fn requires_complete_explicit_credentials() {
        assert!(config(&[
            ("CONTROL_PLANE_URL", "https://control.example"),
            ("COLLECTOR_ID", "collector")
        ])
        .is_err());
    }
}
