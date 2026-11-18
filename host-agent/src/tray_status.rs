use serde::{Deserialize, Serialize};

#[cfg(windows)]
pub const FILE_NAME: &str = "tray-status.json";
#[cfg(windows)]
pub const SERVICE_NAME: &str = "SadappHostAgent";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Release {
    tag_name: String,
    channel: String,
    product: Option<String>,
    assets: Vec<ReleaseAsset>,
}

#[derive(Deserialize)]
struct ReleaseAsset {
    name: String,
    platform: String,
    architecture: String,
    kind: String,
}

#[derive(Deserialize)]
pub struct ReleaseFeed {
    stale: bool,
    releases: Vec<Release>,
}

fn version(value: &str) -> Option<(u32, u32, u32)> {
    let mut parts = value.split('.');
    let version = (
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
    );
    parts.next().is_none().then_some(version)
}

impl ReleaseFeed {
    pub fn available(&self, current: &str, channel: &str) -> Option<String> {
        let current = version(current)?;
        let channel = match channel {
            "prototype" => "canary",
            "canary" | "stable" | "prerelease" => channel,
            _ => return None,
        };
        if self.stale {
            return None;
        }
        self.releases
            .iter()
            .filter_map(|release| {
                let (candidate, suffix) = release
                    .tag_name
                    .strip_prefix("host-agent-v")?
                    .split_once("-windows")?;
                let parsed = version(candidate)?;
                (parsed > current
                    && (suffix.is_empty() || suffix.starts_with('-'))
                    && release.channel == channel
                    && release.product.as_deref() == Some("hostAgent")
                    && release.assets.iter().any(|asset| {
                        asset.platform == "windows"
                            && asset.architecture == "x64"
                            && asset.kind == "installer"
                            && asset.name
                                == format!("sadapp-host-agent-{candidate}-windows-x64.msi")
                    }))
                .then_some((parsed, candidate))
            })
            .max()
            .map(|(_, candidate)| candidate.to_string())
    }
}

#[cfg(windows)]
pub fn check_update(
    endpoint: &str,
    current: &str,
    channel: &str,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    use reqwest::{Url, blocking::Client, redirect::Policy};
    use std::{io::Read, time::Duration};
    let mut url = Url::parse(endpoint)?;
    if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
        return Err("Update metadata requires an HTTPS endpoint without URL credentials".into());
    }
    url.set_path("/api/public/releases");
    url.set_query(None);
    url.set_fragment(None);
    let response = Client::builder()
        .timeout(Duration::from_secs(8))
        .redirect(Policy::none())
        .build()?
        .get(url)
        .send()
        .map_err(reqwest::Error::without_url)?
        .error_for_status()
        .map_err(reqwest::Error::without_url)?;
    let mut data = Vec::new();
    response.take(2 * 1024 * 1024 + 1).read_to_end(&mut data)?;
    if data.len() > 2 * 1024 * 1024 {
        return Err("Release metadata exceeds size limit".into());
    }
    let feed: ReleaseFeed = serde_json::from_slice(&data)?;
    if feed.stale {
        return Err("Release metadata is stale".into());
    }
    Ok(feed.available(current, channel))
}

#[derive(Serialize, Deserialize)]
pub struct TrayStatus {
    pub pid: u32,
    pub started_at: u64,
    pub interval_seconds: u64,
    pub last_success: Option<u64>,
    pub retrying: bool,
    pub version: String,
    pub available_version: Option<String>,
    #[serde(default)]
    pub diagnostics: Option<DeliveryDiagnostics>,
}

#[derive(Serialize, Deserialize)]
pub struct DeliveryDiagnostics {
    pub queued: usize,
    pub oldest_queued_at: Option<u64>,
    pub dropped: u64,
    pub consecutive_failures: u64,
    pub last_failed_at: Option<u64>,
}

#[cfg(windows)]
pub fn read_service_status() -> Result<TrayStatus, &'static str> {
    use std::{fs::File, io::Read};
    use windows_service::{
        service::{ServiceAccess, ServiceState},
        service_manager::{ServiceManager, ServiceManagerAccess},
    };
    let service = (|| {
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?
            .open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS)?
            .query_status()
    })()
    .map_err(|_| "Agent service status unavailable")?;
    if service.current_state == ServiceState::StartPending {
        return Err("Agent starting");
    }
    if service.current_state != ServiceState::Running {
        return Err("Agent service is not running");
    }
    let file = state_dir()
        .and_then(|path| File::open(path.join("state").join(FILE_NAME)))
        .map_err(|_| "Agent running; delivery status unavailable")?;
    let status: TrayStatus = serde_json::from_reader(file.take(4096))
        .map_err(|_| "Agent running; delivery status unreadable")?;
    if Some(status.pid) != service.process_id {
        return Err("Agent running; waiting for current delivery status");
    }
    Ok(status)
}

#[cfg(windows)]
pub fn local_diagnostics() -> Result<String, Box<dyn std::error::Error>> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let status = read_service_status()?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    Ok(serde_json::to_string_pretty(
        &status.diagnostic_report(now),
    )?)
}

impl TrayStatus {
    #[cfg(any(windows, test))]
    fn diagnostic_report(&self, now: u64) -> serde_json::Value {
        serde_json::json!({
            "health": self.health(now).1,
            "version": version(&self.version).map(|_| self.version.as_str()),
            "available_version": self.available_version.as_deref().filter(|v| version(v).is_some()),
            "interval_seconds": self.interval_seconds,
            "last_success_epoch_seconds": self.last_success,
            "oldest_queued_age_seconds": self.diagnostics.as_ref()
                .and_then(|diagnostics| diagnostics.oldest_queued_at)
                .and_then(|timestamp| now.checked_sub(timestamp)),
            "delivery": self.diagnostics,
        })
    }

    pub fn health(&self, now: u64) -> (u8, &'static str) {
        let last = self.last_success.unwrap_or(self.started_at);
        let grace = self.interval_seconds.saturating_mul(3).max(120);
        if last > now || now - last > grace {
            (2, "Telemetry delivery stale")
        } else if self.retrying {
            (1, "Retrying telemetry delivery")
        } else if self.last_success.is_some() {
            (0, "Telemetry active")
        } else {
            (1, "Waiting for first delivery")
        }
    }
}

#[cfg(windows)]
pub fn state_dir() -> std::io::Result<std::path::PathBuf> {
    use std::{ffi::OsString, os::windows::ffi::OsStringExt, path::PathBuf, ptr};
    use windows_sys::Win32::{
        System::Com::CoTaskMemFree,
        UI::Shell::{FOLDERID_ProgramData, SHGetKnownFolderPath},
    };
    let mut folder = ptr::null_mut();
    let result =
        unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramData, 0, ptr::null_mut(), &mut folder) };
    if result < 0 {
        return Err(std::io::Error::other(format!(
            "Cannot resolve ProgramData (HRESULT {result:#x})"
        )));
    }
    let base = unsafe {
        let mut length = 0;
        while *folder.add(length) != 0 {
            length += 1;
        }
        let path = PathBuf::from(OsString::from_wide(std::slice::from_raw_parts(
            folder, length,
        )));
        CoTaskMemFree(folder.cast());
        path
    };
    Ok(base.join("Sadapp").join("HostAgent"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostics_only_export_safe_fields_and_compute_queue_age() {
        let status: TrayStatus = serde_json::from_value(serde_json::json!({
            "pid": 42, "started_at": 10, "interval_seconds": 60,
            "last_success": 110, "retrying": true,
            "version": "0.2.17", "available_version": "fixture-secret",
            "enrollment_token": "fixture-secret",
            "diagnostics": {
                "queued": 2, "oldest_queued_at": 120, "dropped": 1,
                "consecutive_failures": 3, "last_failed_at": 130,
                "raw_error": "fixture-secret"
            }
        }))
        .unwrap();
        let report = status.diagnostic_report(145);
        assert_eq!(report["health"], "Retrying telemetry delivery");
        assert_eq!(report["oldest_queued_age_seconds"], 25);
        assert_eq!(report["delivery"]["queued"], 2);
        assert!(report.get("pid").is_none());
        assert!(!report.to_string().contains("fixture-secret"));
    }

    #[test]
    fn health_requires_recent_delivery_and_surfaces_retries_and_staleness() {
        let mut status = TrayStatus {
            pid: 1,
            started_at: 10,
            interval_seconds: 60,
            last_success: None,
            retrying: false,
            version: "0.2.17".into(),
            available_version: None,
            diagnostics: None,
        };
        assert_eq!(status.health(20).0, 1);
        assert_eq!(status.health(191).0, 2);
        status.last_success = Some(190);
        assert_eq!(status.health(200).0, 0);
        status.retrying = true;
        assert_eq!(status.health(201).0, 1);
        assert_eq!(status.health(371).0, 2);
    }

    #[test]
    fn update_notice_requires_newer_matching_channel_and_windows_installer() {
        let release = |version: &str, channel: &str, architecture: &str| {
            serde_json::json!({
                "tagName": format!("host-agent-v{version}-windows"),
                "channel": channel, "product": "hostAgent",
                "assets": [{ "name": format!("sadapp-host-agent-{version}-windows-x64.msi"),
                    "platform": "windows", "architecture": architecture, "kind": "installer" }]
            })
        };
        let mut feed: ReleaseFeed = serde_json::from_value(serde_json::json!({
            "stale": false, "releases": [
                release("0.2.18", "canary", "x64"), release("0.2.20", "stable", "x64"),
                release("0.2.21", "canary", "arm64"), release("0.2.9", "canary", "x64")
            ]
        }))
        .unwrap();
        assert_eq!(
            feed.available("0.2.17", "prototype").as_deref(),
            Some("0.2.18")
        );
        assert_eq!(
            feed.available("0.2.17", "stable").as_deref(),
            Some("0.2.20")
        );
        assert_eq!(feed.available("0.2.18", "canary"), None);
        assert_eq!(feed.available("0.2.17", "unknown"), None);
        feed.stale = true;
        assert_eq!(feed.available("0.2.17", "canary"), None);
    }
}
