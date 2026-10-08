use reqwest::{
    Url,
    blocking::{Client, RequestBuilder},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{HashMap, VecDeque};
use std::env;
use std::error::Error;
use std::fs;
#[cfg(unix)]
use std::io::Read;
use std::io::{self, Write};
use std::net::{SocketAddr, TcpStream};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use sysinfo::{CpuExt, DiskExt, NetworkExt, NetworksExt, PidExt, ProcessExt, System, SystemExt};

#[cfg(windows)]
mod windows;
mod windows_config;

const DEFAULT_ENDPOINT: &str = "https://sadapp.org/api/v1/agent";
#[cfg(not(windows))]
const DEFAULT_QUEUE_PATH: &str = "/var/lib/sadapp-host-agent/telemetry-queue.json";
#[cfg(not(windows))]
const DEFAULT_UPDATE_STATE_PATH: &str = "/var/lib/sadapp-host-agent/update-state.json";
const DEFAULT_QUEUE_MAX_SAMPLES: usize = 200;
const MAX_QUEUE_MAX_SAMPLES: usize = 10_000;
const DEFAULT_MEDIUM_COLLECTOR_INTERVAL_SECONDS: u64 = 120;
const DEFAULT_SLOW_COLLECTOR_INTERVAL_SECONDS: u64 = 3600;
const OUTBOUND_HTTP_TIMEOUT_SECONDS: u64 = 15;
static JOURNAL_CURSOR: OnceLock<Mutex<Option<String>>> = OnceLock::new();

fn agent_version() -> &'static str {
    option_env!("SADAPP_AGENT_VERSION").unwrap_or(env!("CARGO_PKG_VERSION"))
}

#[derive(Clone, Default)]
struct MediumCollectorSnapshot {
    collected_at: u64,
    disk_total_bytes: u64,
    disk_devices: Vec<DiskInfo>,
    network_interfaces: Vec<NetworkInterface>,
    temperature_sensors: Vec<TemperatureSensor>,
    fan_sensors: Vec<FanSensor>,
    top_cpu_processes: Vec<ProcessInfo>,
    top_memory_processes: Vec<ProcessInfo>,
    listening_ports: Vec<ListeningPort>,
    gpu_devices: Vec<GpuInfo>,
    docker_metrics: Option<DockerMetrics>,
    virtualization_metrics: Option<VirtualizationMetrics>,
    log_events: Vec<LogEvent>,
    health: Vec<CollectorHealth>,
}

#[derive(Clone, Default)]
struct SlowCollectorSnapshot {
    smartctl: Option<Value>,
    update_status: Option<UpdateStatusPayload>,
    health: Vec<CollectorHealth>,
}

#[derive(Clone, Default)]
struct CollectorSnapshots {
    medium: Option<MediumCollectorSnapshot>,
    slow: Option<SlowCollectorSnapshot>,
}

#[derive(Clone)]
struct StaticInventory {
    host_name: String,
    os_name: String,
    os_version: String,
    kernel_version: String,
    processor: String,
    cpu_frequency_mhz: u64,
    aes_ni_enabled: Option<bool>,
    virtualization_hw_enabled: Option<bool>,
    distro: String,
    vm_type: Option<String>,
    ipv4_online: bool,
    ipv6_online: bool,
    ipv4_network_info: Option<Ipv4NetworkInfo>,
    environment: Option<String>,
    server_role: Option<String>,
    datacenter: Option<String>,
    rack: Option<String>,
    cluster: Option<String>,
    provider: Option<String>,
    owner_team: Option<String>,
    architecture: String,
    timezone: Option<String>,
    machine_id: Option<String>,
    agent_version: String,
}

#[derive(Clone, Serialize)]
struct CollectorHealth {
    name: String,
    status: String,
    last_collected_at: u64,
    duration_ms: u64,
    interval_seconds: u64,
    last_error: Option<String>,
}

impl CollectorHealth {
    fn unsupported(name: &str, interval_seconds: u64, reason: &str) -> Self {
        Self {
            name: name.into(),
            status: "unsupported".into(),
            last_collected_at: unix_timestamp(),
            duration_ms: 0,
            interval_seconds,
            last_error: Some(reason.into()),
        }
    }

    fn completed(
        name: &str,
        started_at: Instant,
        interval_seconds: u64,
        available: bool,
        unavailable_message: Option<&str>,
    ) -> Self {
        if cfg!(windows)
            && matches!(
                name,
                "ports"
                    | "sensors"
                    | "gpu"
                    | "docker"
                    | "virtualization"
                    | "logs"
                    | "smart"
                    | "packages"
            )
        {
            return Self::unsupported(
                name,
                interval_seconds,
                "Not supported by the Windows prototype",
            );
        }
        Self {
            name: name.to_string(),
            status: if available {
                String::from("healthy")
            } else {
                String::from("unavailable")
            },
            last_collected_at: unix_timestamp(),
            duration_ms: started_at.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
            interval_seconds,
            last_error: (!available).then(|| {
                unavailable_message
                    .unwrap_or("collector unavailable")
                    .to_string()
            }),
        }
    }
}

#[derive(Clone, Serialize)]
struct ConfigurationHealth {
    endpoint_source: String,
    authentication_source: String,
    interval_source: String,
    queue_source: String,
    update_channel_source: String,
    platform: &'static str,
    execution_mode: &'static str,
    credential_storage: &'static str,
}

#[derive(Clone, Serialize)]
struct AgentUpdateHealth {
    current_version: String,
    desired_version: Option<String>,
    channel: String,
    state: String,
    verification_mode: String,
    rollback_result: Option<String>,
}

#[derive(Clone, Serialize)]
struct AgentHealth {
    contract_version: u8,
    reported_at: u64,
    collectors: Vec<CollectorHealth>,
    configuration: ConfigurationHealth,
    update: AgentUpdateHealth,
}

fn collector_due(
    now: u64,
    last_started_at: Option<u64>,
    interval_seconds: u64,
    in_flight: bool,
) -> bool {
    !in_flight
        && last_started_at
            .map(|last_started| now.saturating_sub(last_started) >= interval_seconds)
            .unwrap_or(true)
}

#[derive(Clone, Serialize, Deserialize)]
struct QueuedHeartbeat {
    id: String,
    timestamp: u64,
    payload: Value,
    attempts: u32,
    next_attempt_at: u64,
}

#[derive(Default, Serialize, Deserialize)]
struct PersistedTelemetryQueue {
    items: VecDeque<QueuedHeartbeat>,
    dropped_samples: u64,
}

struct TelemetryQueue {
    path: PathBuf,
    max_samples: usize,
    state: PersistedTelemetryQueue,
}

impl TelemetryQueue {
    fn open(path: PathBuf, max_samples: usize) -> io::Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let max_samples = max_samples.clamp(1, MAX_QUEUE_MAX_SAMPLES);
        let mut state = if path.exists() {
            let raw = fs::read(&path)?;
            serde_json::from_slice(&raw)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
        } else {
            PersistedTelemetryQueue::default()
        };

        while state.items.len() > max_samples {
            state.items.pop_front();
            state.dropped_samples = state.dropped_samples.saturating_add(1);
        }

        let queue = Self {
            path,
            max_samples,
            state,
        };
        queue.persist()?;
        Ok(queue)
    }

    fn enqueue(
        &mut self,
        host_name: &str,
        timestamp: u64,
        payload: Value,
        now: u64,
    ) -> io::Result<bool> {
        let id = format!("{}:{}", host_name, timestamp);
        if self.state.items.iter().any(|item| item.id == id) {
            return Ok(false);
        }

        if self.state.items.len() >= self.max_samples {
            self.state.items.pop_front();
            self.state.dropped_samples = self.state.dropped_samples.saturating_add(1);
        }

        self.state.items.push_back(QueuedHeartbeat {
            id: id.clone(),
            timestamp,
            payload,
            attempts: 1,
            next_attempt_at: now.saturating_add(retry_delay_seconds(1, &id)),
        });
        self.persist()?;
        Ok(true)
    }

    fn persist(&self) -> io::Result<()> {
        let encoded = serde_json::to_vec(&self.state)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        persist_private_json(&self.path, &encoded)
    }

    fn len(&self) -> usize {
        self.state.items.len()
    }

    fn dropped_samples(&self) -> u64 {
        self.state.dropped_samples
    }

    fn due_item(&self, now: u64) -> Option<QueuedHeartbeat> {
        self.state
            .items
            .front()
            .filter(|item| item.next_attempt_at <= now)
            .cloned()
    }

    fn record_success(&mut self, id: &str) -> io::Result<()> {
        if self.state.items.front().map(|item| item.id.as_str()) == Some(id) {
            self.state.items.pop_front();
            self.persist()?;
        }
        Ok(())
    }

    fn record_failure(&mut self, id: &str, now: u64) -> io::Result<()> {
        if let Some(item) = self.state.items.front_mut().filter(|item| item.id == id) {
            item.attempts = item.attempts.saturating_add(1);
            item.next_attempt_at = now.saturating_add(retry_delay_seconds(item.attempts, &item.id));
            self.persist()?;
        }
        Ok(())
    }
}

fn retry_delay_seconds(attempts: u32, id: &str) -> u64 {
    let exponent = attempts.saturating_sub(1).min(6);
    let base = 5_u64.saturating_mul(1_u64 << exponent).min(300);
    let jitter = id
        .bytes()
        .fold(0_u64, |sum, byte| sum.wrapping_add(u64::from(byte)))
        % 5;
    base.saturating_add(jitter)
}

#[cfg(unix)]
fn set_private_file_permissions(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

fn persist_private_json(path: &Path, data: &[u8]) -> io::Result<()> {
    #[cfg(windows)]
    {
        windows::atomic_write(path, data, false)
    }
    #[cfg(not(windows))]
    {
        let temp_path = path.with_extension("tmp");
        fs::write(&temp_path, data)?;
        set_private_file_permissions(&temp_path)?;
        fs::rename(temp_path, path)
    }
}

fn default_queue_path() -> io::Result<PathBuf> {
    #[cfg(windows)]
    {
        Ok(windows::state_dir()?
            .join("state")
            .join("telemetry-queue.json"))
    }
    #[cfg(not(windows))]
    {
        Ok(PathBuf::from(DEFAULT_QUEUE_PATH))
    }
}

fn default_update_state_path() -> io::Result<PathBuf> {
    #[cfg(windows)]
    {
        Ok(windows::state_dir()?
            .join("state")
            .join("update-state.json"))
    }
    #[cfg(not(windows))]
    {
        Ok(PathBuf::from(DEFAULT_UPDATE_STATE_PATH))
    }
}

#[derive(Clone, Serialize)]
struct DiskInfo {
    name: String,
    mount_point: String,
    total_bytes: u64,
    available_bytes: u64,
    file_system: String,
}

#[derive(Clone, Serialize)]
struct NetworkInterface {
    name: String,
    received_bytes: u64,
    transmitted_bytes: u64,
}

#[derive(Clone, Serialize)]
struct TemperatureSensor {
    name: String,
    value_celsius: f32,
}

#[derive(Clone, Serialize)]
struct FanSensor {
    name: String,
    rpm: u64,
}

#[derive(Clone, Serialize)]
struct ProcessInfo {
    name: String,
    cpu_usage_percent: f32,
    memory_bytes: u64,
}

#[derive(Clone, Serialize)]
struct ListeningPort {
    protocol: String,
    port: u16,
}

#[derive(Clone, Debug, Serialize)]
struct GpuInfo {
    id: String,
    name: String,
    vendor: String,
    driver_version: Option<String>,
    pci_bus_id: Option<String>,
    utilization_percent: Option<f32>,
    memory_total_bytes: Option<u64>,
    memory_used_bytes: Option<u64>,
    temperature_celsius: Option<f32>,
    power_draw_watts: Option<f32>,
    power_limit_watts: Option<f32>,
    fan_speed_percent: Option<f32>,
}

#[derive(Serialize)]
struct ServerStatus {
    timestamp: u64,
    host_name: String,
    os_name: String,
    os_version: String,
    kernel_version: String,
    processor: String,
    cpu_frequency_mhz: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    aes_ni_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    virtualization_hw_enabled: Option<bool>,
    distro: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    vm_type: Option<String>,
    ipv4_online: bool,
    ipv6_online: bool,
    disk_total_bytes: u64,
    uptime_seconds: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    load_average: Option<LoadAverage>,
    cpu_usage_percent: f32,
    cpu_count: usize,
    memory_total_bytes: u64,
    memory_used_bytes: u64,
    swap_total_bytes: u64,
    swap_used_bytes: u64,
    disk_devices: Vec<DiskInfo>,
    network_interfaces: Vec<NetworkInterface>,
    temperature_sensors: Vec<TemperatureSensor>,
    fan_sensors: Vec<FanSensor>,
    top_cpu_processes: Vec<ProcessInfo>,
    top_memory_processes: Vec<ProcessInfo>,
    listening_ports: Vec<ListeningPort>,
    gpu_devices: Vec<GpuInfo>,
    processes: usize,
    ipv4_network_info: Option<Ipv4NetworkInfo>,
    environment: Option<String>,
    server_role: Option<String>,
    datacenter: Option<String>,
    rack: Option<String>,
    cluster: Option<String>,
    provider: Option<String>,
    owner_team: Option<String>,
    architecture: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    timezone: Option<String>,
    machine_id: Option<String>,
    agent_version: String,
    agent_runtime: Option<AgentRuntime>,
    delivery_health: DeliveryHealth,
    docker_metrics: Option<DockerMetrics>,
    virtualization_metrics: Option<VirtualizationMetrics>,
    smartctl: Option<Value>,
    agent_health: AgentHealth,
}

/// Resource footprint of this Sadapp agent process, separate from host telemetry.
#[derive(Serialize)]
struct AgentRuntime {
    cpu_percent: f32,
    memory_bytes: u64,
    disk_read_bytes: u64,
    disk_written_bytes: u64,
}

#[derive(Clone, Serialize)]
struct DeliveryHealth {
    started_at: u64,
    last_successful_submit_at: Option<u64>,
    last_failed_submit_at: Option<u64>,
    last_error: Option<String>,
    consecutive_failures: u64,
    total_attempts: u64,
    total_successes: u64,
    queue_depth: usize,
    dropped_samples: u64,
    persistent_queue_enabled: bool,
}

impl DeliveryHealth {
    fn new(started_at: u64) -> Self {
        Self {
            started_at,
            last_successful_submit_at: None,
            last_failed_submit_at: None,
            last_error: None,
            consecutive_failures: 0,
            total_attempts: 0,
            total_successes: 0,
            queue_depth: 0,
            dropped_samples: 0,
            persistent_queue_enabled: false,
        }
    }

    fn record_success(&mut self, timestamp: u64) {
        self.total_attempts = self.total_attempts.saturating_add(1);
        self.total_successes = self.total_successes.saturating_add(1);
        self.consecutive_failures = 0;
        self.last_successful_submit_at = Some(timestamp);
        self.last_error = None;
    }

    fn record_failure(&mut self, timestamp: u64, error: &str) {
        self.total_attempts = self.total_attempts.saturating_add(1);
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.last_failed_submit_at = Some(timestamp);
        self.last_error = Some(error.chars().take(500).collect());
    }
}

#[derive(Clone, Serialize)]
struct DockerMetrics {
    collected_at: u64,
    running_containers: usize,
    stopped_containers: usize,
    unhealthy_containers: usize,
    engine_version: Option<String>,
    disk_usage_bytes: Option<u64>,
    containers: Vec<DockerContainerMetric>,
}

#[derive(Clone, Serialize)]
struct DockerContainerMetric {
    container_id: String,
    name: String,
    image: String,
    image_digest: Option<String>,
    state: Option<String>,
    health: Option<String>,
    restart_count: Option<u64>,
    cpu_percent: Option<f32>,
    memory_usage_bytes: Option<u64>,
    memory_limit_bytes: Option<u64>,
    memory_percent: Option<f32>,
    net_rx_bytes: Option<u64>,
    net_tx_bytes: Option<u64>,
    block_read_bytes: Option<u64>,
    block_write_bytes: Option<u64>,
    started_at: Option<String>,
    finished_at: Option<String>,
    labels: HashMap<String, String>,
}

#[derive(Clone, Serialize)]
struct VirtualizationMetrics {
    provider: String,
    collected_at: u64,
    guests: Vec<VirtualGuestMetric>,
}

#[derive(Clone, Serialize)]
struct VirtualGuestMetric {
    guest_id: String,
    name: String,
    guest_type: String,
    status: String,
    cpu_percent: Option<f32>,
    memory_used_bytes: Option<u64>,
    memory_total_bytes: Option<u64>,
    disk_used_bytes: Option<u64>,
    disk_total_bytes: Option<u64>,
    uptime_seconds: Option<u64>,
    tags: Option<String>,
}

#[derive(Clone, Serialize)]
struct LogEvent {
    timestamp: u64,
    source: String,
    severity: String,
    message: String,
    fingerprint: Option<String>,
    container_id: Option<String>,
    container_name: Option<String>,
    unit: Option<String>,
    #[serde(skip_serializing)]
    journal_cursor: Option<String>,
}

#[derive(Serialize)]
struct LogsPayload<'a> {
    timestamp: u64,
    host_name: &'a str,
    events: &'a [LogEvent],
}

#[derive(Clone, Serialize)]
struct UpdateStatusPayload {
    timestamp: u64,
    host_name: String,
    package_manager: Option<String>,
    pending_updates: u64,
    pending_security_updates: u64,
    reboot_required: bool,
    last_successful_upgrade_at: Option<u64>,
    last_failed_update_at: Option<u64>,
    last_failed_update_message: Option<String>,
    package_summary: Value,
    current_version: String,
    previous_version: Option<String>,
    desired_version: Option<String>,
    update_channel: String,
    update_state: String,
    verification_mode: String,
    rollback_result: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
struct UpdateLifecycleState {
    current_version: String,
    previous_version: Option<String>,
    desired_version: Option<String>,
    channel: String,
    state: String,
    verification_mode: String,
    last_successful_upgrade_at: Option<u64>,
    last_failed_update_at: Option<u64>,
    last_failed_update_message: Option<String>,
    rollback_result: Option<String>,
}

impl UpdateLifecycleState {
    fn reconcile(
        previous: Option<Self>,
        current_version: &str,
        desired_version: Option<String>,
        channel: &str,
        now: u64,
    ) -> Self {
        let version_changed = previous
            .as_ref()
            .map(|state| state.current_version != current_version)
            .unwrap_or(false);
        let previous_version = if version_changed {
            previous.as_ref().map(|state| state.current_version.clone())
        } else {
            previous
                .as_ref()
                .and_then(|state| state.previous_version.clone())
        };
        let rollback_detected = previous
            .as_ref()
            .filter(|_| version_changed)
            .map(|state| state.current_version.as_str())
            .map(|version| compare_versions(current_version, version).is_lt())
            .unwrap_or(false);
        let desired_pending = desired_version
            .as_deref()
            .map(|desired| desired != current_version)
            .unwrap_or(false);

        Self {
            current_version: current_version.to_string(),
            previous_version,
            desired_version,
            channel: channel.to_string(),
            state: if rollback_detected {
                String::from("rolled_back")
            } else if version_changed {
                String::from("updated")
            } else if desired_pending {
                String::from("pending")
            } else {
                String::from("current")
            },
            verification_mode: if cfg!(windows) {
                String::from("external_authenticode_check_required")
            } else {
                String::from("os_package_signature")
            },
            last_successful_upgrade_at: if version_changed && !rollback_detected {
                Some(now)
            } else {
                previous
                    .as_ref()
                    .and_then(|state| state.last_successful_upgrade_at)
            },
            last_failed_update_at: previous
                .as_ref()
                .and_then(|state| state.last_failed_update_at),
            last_failed_update_message: previous
                .as_ref()
                .and_then(|state| state.last_failed_update_message.clone()),
            rollback_result: if rollback_detected {
                Some(String::from("succeeded"))
            } else {
                previous
                    .as_ref()
                    .and_then(|state| state.rollback_result.clone())
            },
        }
    }

    fn load_and_reconcile(
        path: &Path,
        current_version: &str,
        desired_version: Option<String>,
        channel: &str,
        now: u64,
    ) -> io::Result<Self> {
        let previous = match fs::read(path) {
            Ok(raw) => Some(serde_json::from_slice(&raw).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Invalid agent update state: {error}"),
                )
            })?),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        let state = Self::reconcile(previous, current_version, desired_version, channel, now);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        persist_private_json(path, &serde_json::to_vec(&state)?)?;
        Ok(state)
    }
}

fn compare_versions(left: &str, right: &str) -> std::cmp::Ordering {
    let parse = |version: &str| {
        version
            .split(|character: char| !character.is_ascii_digit())
            .filter(|part| !part.is_empty())
            .map(|part| part.parse::<u64>().unwrap_or(0))
            .collect::<Vec<_>>()
    };
    let left_parts = parse(left);
    let right_parts = parse(right);
    let length = left_parts.len().max(right_parts.len());
    for index in 0..length {
        let ordering = left_parts
            .get(index)
            .unwrap_or(&0)
            .cmp(right_parts.get(index).unwrap_or(&0));
        if !ordering.is_eq() {
            return ordering;
        }
    }
    std::cmp::Ordering::Equal
}

#[derive(Serialize)]
struct LoadAverage {
    one: f64,
    five: f64,
    fifteen: f64,
}

#[derive(Clone, Serialize)]
struct Ipv4NetworkInfo {
    ip: String,
    isp: String,
    asn: String,
    host: String,
    location: String,
    country: String,
}

#[derive(Deserialize)]
struct IpWhoIsResponse {
    success: bool,
    ip: Option<String>,
    city: Option<String>,
    region: Option<String>,
    country: Option<String>,
    connection: Option<IpWhoIsConnection>,
}

#[derive(Deserialize)]
struct IpWhoIsConnection {
    isp: Option<String>,
    org: Option<String>,
    asn: Option<u64>,
}

struct AuthConfig {
    invite_token: Option<String>,
    key_id: Option<String>,
    key_secret: Option<String>,
}

impl AuthConfig {
    fn apply(&self, mut request: RequestBuilder) -> RequestBuilder {
        if let Some(invite_token) = &self.invite_token {
            request = request.query(&[("invite_token", invite_token)]);
        } else if let (Some(key_id), Some(key_secret)) = (&self.key_id, &self.key_secret) {
            request = request
                .header("x-agent-key-id", key_id)
                .header("x-agent-key-secret", key_secret);
        }
        request
    }
}

#[derive(Clone, Copy)]
enum LogLevel {
    Info,
    Warn,
    Error,
    Debug,
}

impl LogLevel {
    fn priority(&self) -> u8 {
        match self {
            Self::Debug => 10,
            Self::Info => 20,
            Self::Warn => 30,
            Self::Error => 40,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::Error => "ERROR",
            Self::Debug => "DEBUG",
        }
    }
}

#[derive(Clone)]
struct StartupNetworkSnapshot {
    ipv4_online: bool,
    ipv6_online: bool,
    ipv4_network_info: Option<Ipv4NetworkInfo>,
}

fn parse_register_once(args: &[String]) -> Option<bool> {
    for arg in args.iter().skip(1) {
        if arg == "--register-once" {
            return Some(true);
        }

        if arg == "--monitor" {
            return Some(false);
        }

        if let Some(value) = arg.strip_prefix("--register-once=") {
            let normalized = value.trim().to_ascii_lowercase();
            return Some(matches!(normalized.as_str(), "1" | "true" | "yes" | "on"));
        }
    }

    None
}

fn parse_bool_env(name: &str) -> Option<bool> {
    let value = env::var(name).ok()?;
    let normalized = value.trim().to_ascii_lowercase();
    Some(matches!(normalized.as_str(), "1" | "true" | "yes" | "on"))
}

fn parse_log_level_value(value: &str) -> Option<LogLevel> {
    match value.trim().to_ascii_lowercase().as_str() {
        "debug" => Some(LogLevel::Debug),
        "info" => Some(LogLevel::Info),
        "warn" | "warning" => Some(LogLevel::Warn),
        "error" => Some(LogLevel::Error),
        _ => None,
    }
}

fn parse_log_level(args: &[String]) -> Option<LogLevel> {
    for arg in args.iter().skip(1) {
        if let Some(value) = arg.strip_prefix("--log-level=") {
            return parse_log_level_value(value);
        }
    }
    None
}

fn log_message(configured_level: LogLevel, level: LogLevel, message: &str) {
    if level.priority() >= configured_level.priority() {
        #[cfg(windows)]
        if windows::is_service() {
            windows::write_log(&format!("[{}] {}", level.as_str(), message));
            return;
        }
        println!("[{}] {}", level.as_str(), message);
    }
}

fn log_status_snapshot(configured_level: LogLevel, status: &ServerStatus) {
    let memory_used_mb = status.memory_used_bytes / (1024 * 1024);
    let memory_total_mb = status.memory_total_bytes / (1024 * 1024);
    let disk_total_gb = status.disk_total_bytes / (1024 * 1024 * 1024);
    log_message(
        configured_level,
        LogLevel::Debug,
        &format!(
            "Collected status host={} cpu={:.1}% mem={}MB/{}MB disk={}GB proc={} docker_containers={}",
            status.host_name,
            status.cpu_usage_percent,
            memory_used_mb,
            memory_total_mb,
            disk_total_gb,
            status.processes,
            status
                .docker_metrics
                .as_ref()
                .map(|docker| docker.containers.len())
                .unwrap_or(0)
        ),
    );
}

fn main() -> Result<(), Box<dyn Error>> {
    if env::args().len() == 2 && env::args().nth(1).as_deref() == Some("--version") {
        println!("Sadapp Host Agent {}", agent_version());
        return Ok(());
    }
    #[cfg(windows)]
    {
        let args: Vec<String> = env::args().skip(1).collect();
        if args.iter().any(|arg| {
            matches!(
                arg.as_str(),
                "--service" | "--configure" | "--validate-config" | "--purge-state"
            )
        }) {
            if args.len() != 1 {
                return Err("Windows management commands must be used alone; credentials are entered interactively".into());
            }
            return match args[0].as_str() {
                "--service" => windows::run_service(),
                "--configure" => windows::configure(),
                "--validate-config" => {
                    windows::load_config()?;
                    println!(
                        "Protected Windows configuration is structurally valid; API authentication is checked when the service sends telemetry."
                    );
                    Ok(())
                }
                "--purge-state" => windows::purge_state(),
                _ => unreachable!(),
            };
        }
    }
    let shutdown = Arc::new(AtomicBool::new(false));
    let signal = Arc::clone(&shutdown);
    ctrlc::set_handler(move || signal.store(true, Ordering::Release))?;
    run_agent(None, shutdown)
}

fn run_agent(
    windows_configuration: Option<windows_config::WindowsConfig>,
    shutdown_requested: Arc<AtomicBool>,
) -> Result<(), Box<dyn Error>> {
    if let Some(config) = &windows_configuration {
        config.validate()?;
    }
    let args: Vec<String> = env::args().collect();
    let invitation_link_arg = parse_invitation_link(&args);
    let invite_token_arg = parse_invite_token(&args);
    let invitation_link = invitation_link_arg
        .clone()
        .or_else(|| env::var("API_INVITATION_LINK").ok())
        .unwrap_or_default();

    let mut endpoint = windows_configuration
        .as_ref()
        .map(|config| config.endpoint.clone())
        .or_else(|| parse_endpoint(&args))
        .or_else(|| env::var("API_ENDPOINT").ok())
        .unwrap_or_else(|| DEFAULT_ENDPOINT.to_string());
    if endpoint.is_empty() && !invitation_link.is_empty() {
        endpoint = invitation_link.clone();
    }

    let invite_token = invite_token_arg
        .clone()
        .or_else(|| env::var("API_INVITE_TOKEN").ok())
        .or_else(|| extract_invite_token(&invitation_link))
        .or_else(|| extract_invite_token(&endpoint));
    let key_id_arg = parse_argument_value(&args, "--key-id");
    let key_secret_arg = parse_argument_value(&args, "--key-secret");
    let key_id = key_id_arg.clone().or_else(|| env::var("API_KEY_ID").ok());
    let key_secret = key_secret_arg
        .clone()
        .or_else(|| env::var("API_KEY_SECRET").ok());

    let mut auth = AuthConfig {
        invite_token,
        key_id: non_empty(key_id),
        key_secret: non_empty(key_secret),
    };
    if let Some(config) = &windows_configuration {
        auth = AuthConfig {
            invite_token: config.invite_token.clone(),
            key_id: config.key_id.clone(),
            key_secret: config.key_secret.clone(),
        };
    }

    let no_send = windows_configuration.is_none() && args.iter().any(|arg| arg == "--no-send");
    let configured_log_level = parse_log_level(&args)
        .or_else(|| {
            env::var("API_LOG_LEVEL")
                .ok()
                .and_then(|value| parse_log_level_value(&value))
        })
        .unwrap_or(LogLevel::Info);
    let interval_seconds = windows_configuration
        .as_ref()
        .map(|config| config.interval_seconds)
        .or_else(|| parse_interval(&args))
        .or_else(|| {
            env::var("API_INTERVAL_SECONDS")
                .ok()
                .and_then(|val| val.parse().ok())
        })
        .unwrap_or(30);
    let interval = Duration::from_secs(interval_seconds.max(1));
    let medium_interval_seconds = env::var("API_MEDIUM_COLLECTOR_INTERVAL_SECONDS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(DEFAULT_MEDIUM_COLLECTOR_INTERVAL_SECONDS)
        .max(interval.as_secs());
    let slow_interval_seconds = env::var("API_SLOW_COLLECTOR_INTERVAL_SECONDS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(DEFAULT_SLOW_COLLECTOR_INTERVAL_SECONDS)
        .max(medium_interval_seconds);
    let queue_path = env::var("API_QUEUE_PATH")
        .map(PathBuf::from)
        .unwrap_or(default_queue_path()?);
    let update_state_path = env::var("API_UPDATE_STATE_PATH")
        .map(PathBuf::from)
        .unwrap_or(default_update_state_path()?);
    #[cfg(windows)]
    let (queue_path, update_state_path) = if windows::is_service() {
        let path = windows::state_dir()?.join("state");
        (
            path.join("telemetry-queue.json"),
            path.join("update-state.json"),
        )
    } else {
        (queue_path, update_state_path)
    };
    let update_channel = env::var("API_UPDATE_CHANNEL")
        .unwrap_or_else(|_| String::from(if cfg!(windows) { "prototype" } else { "stable" }));
    let desired_version = env::var("API_DESIRED_AGENT_VERSION")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let queue_max_samples = env::var("API_QUEUE_MAX_SAMPLES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(DEFAULT_QUEUE_MAX_SAMPLES);
    let registration_once = windows_configuration.is_none()
        && parse_register_once(&args)
            .or_else(|| parse_bool_env("API_REGISTER_ONCE"))
            .unwrap_or(false);
    let configuration_health = ConfigurationHealth {
        endpoint_source: if windows_configuration.is_some() {
            String::from("protected_config")
        } else if parse_endpoint(&args).is_some() {
            String::from("argument")
        } else if env::var("API_ENDPOINT").is_ok() {
            String::from("environment")
        } else {
            String::from("default")
        },
        authentication_source: if windows_configuration.is_some() {
            String::from("protected_config")
        } else if invite_token_arg.is_some()
            || invitation_link_arg.is_some()
            || key_id_arg.is_some()
            || key_secret_arg.is_some()
        {
            String::from("argument")
        } else {
            String::from("environment")
        },
        interval_source: if windows_configuration.is_some() {
            String::from("protected_config")
        } else if parse_interval(&args).is_some() {
            String::from("argument")
        } else if env::var("API_INTERVAL_SECONDS").is_ok() {
            String::from("environment")
        } else {
            String::from("default")
        },
        queue_source: if env::var("API_QUEUE_PATH").is_ok() {
            String::from("environment")
        } else {
            String::from("default")
        },
        update_channel_source: if env::var("API_UPDATE_CHANNEL").is_ok() {
            String::from("environment")
        } else {
            String::from("default")
        },
        platform: env::consts::OS,
        execution_mode: if windows_configuration.is_some() {
            "windows_service"
        } else {
            "console"
        },
        credential_storage: if windows_configuration.is_some() {
            "machine_dpapi_with_windows_acl"
        } else {
            "external_configuration"
        },
    };

    let has_auth =
        auth.invite_token.is_some() || (auth.key_id.is_some() && auth.key_secret.is_some());

    if !no_send && !has_auth {
        log_message(
            configured_log_level,
            LogLevel::Error,
            "Missing API credentials. Provide an invite token or both --key-id and --key-secret. --endpoint is optional and defaults to https://sadapp.org/api/v1/agent.",
        );
        return Err("Missing API credentials".into());
    }

    if registration_once {
        log_message(
            configured_log_level,
            LogLevel::Info,
            "Starting one-time registration (--register-once).",
        );
    } else {
        log_message(
            configured_log_level,
            LogLevel::Info,
            &format!(
                "Starting server monitoring with {} second interval.",
                interval.as_secs()
            ),
        );
        let auth_mode = if auth.invite_token.is_some() {
            "invitation token"
        } else {
            "agent key pair"
        };
        log_message(
            configured_log_level,
            LogLevel::Info,
            &format!("Using {} for continuous authentication.", auth_mode),
        );
    }
    if no_send {
        log_message(
            configured_log_level,
            LogLevel::Warn,
            "Data will be collected but not sent because --no-send was provided.",
        );
    }

    let startup_network = StartupNetworkSnapshot {
        ipv4_online: is_socket_reachable("1.1.1.1:53"),
        ipv6_online: is_socket_reachable("[2606:4700:4700::1111]:53"),
        ipv4_network_info: fetch_ipv4_network_info(),
    };

    let mut sys = System::new_all();
    sys.refresh_all();
    let static_inventory = collect_static_inventory(&sys, &startup_network);
    let update_lifecycle = if no_send {
        UpdateLifecycleState::reconcile(
            None,
            agent_version(),
            desired_version,
            &update_channel,
            unix_timestamp(),
        )
    } else {
        UpdateLifecycleState::load_and_reconcile(
            &update_state_path,
            agent_version(),
            desired_version,
            &update_channel,
            unix_timestamp(),
        )?
    };
    let collector_snapshots = Arc::new(Mutex::new(CollectorSnapshots::default()));
    let medium_in_flight = Arc::new(AtomicBool::new(false));
    let slow_in_flight = Arc::new(AtomicBool::new(false));
    let initial_collection_at = registration_once.then(unix_timestamp);
    if registration_once {
        let mut snapshots = collector_snapshots
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        snapshots.medium = Some(collect_medium_snapshot(medium_interval_seconds));
        snapshots.slow = Some(collect_slow_snapshot(
            &static_inventory.host_name,
            &update_lifecycle,
            slow_interval_seconds,
        ));
    }
    let mut medium_last_started_at = initial_collection_at;
    let mut slow_last_started_at = initial_collection_at;
    let mut last_docker_sent_at = 0_u64;
    let mut last_logs_sent_at = 0_u64;
    let mut last_updates_sent_at = 0_u64;
    let mut delivery_health = DeliveryHealth::new(unix_timestamp());
    let mut telemetry_queue = if no_send {
        None
    } else {
        Some(TelemetryQueue::open(queue_path, queue_max_samples)?)
    };
    if let Some(queue) = telemetry_queue.as_ref() {
        delivery_health.persistent_queue_enabled = true;
        delivery_health.queue_depth = queue.len();
        delivery_health.dropped_samples = queue.dropped_samples();
    }
    loop {
        #[cfg(windows)]
        if windows::is_service() {
            windows::check_logging()?;
        }
        let final_cycle = shutdown_requested.load(Ordering::Acquire);
        let now = unix_timestamp();
        if !final_cycle
            && collector_due(
                now,
                medium_last_started_at,
                medium_interval_seconds,
                medium_in_flight.load(Ordering::Acquire),
            )
        {
            medium_last_started_at = Some(now);
            spawn_medium_collector(
                Arc::clone(&collector_snapshots),
                Arc::clone(&medium_in_flight),
                medium_interval_seconds,
            );
        }
        if !final_cycle
            && collector_due(
                now,
                slow_last_started_at,
                slow_interval_seconds,
                slow_in_flight.load(Ordering::Acquire),
            )
        {
            slow_last_started_at = Some(now);
            spawn_slow_collector(
                static_inventory.host_name.clone(),
                update_lifecycle.clone(),
                Arc::clone(&collector_snapshots),
                Arc::clone(&slow_in_flight),
                slow_interval_seconds,
            );
        }

        render_status_screen(
            if registration_once {
                "Registration Mode"
            } else {
                "Monitoring Mode"
            },
            "[INFO] Collecting server status...",
            &endpoint,
        );

        let snapshots = collector_snapshots
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let status = gather_status(
            &mut sys,
            &static_inventory,
            snapshots.medium.as_ref(),
            snapshots.slow.as_ref(),
            &delivery_health,
            &configuration_health,
            &update_lifecycle,
            interval.as_secs(),
        );
        log_status_snapshot(configured_log_level, &status);

        if !no_send {
            let telemetry_queue = telemetry_queue
                .as_mut()
                .expect("telemetry queue is initialized when delivery is enabled");
            render_status_screen(
                if registration_once {
                    "Registration Mode"
                } else {
                    "Monitoring Mode"
                },
                "[INFO] Sending payload to backend...",
                &endpoint,
            );

            let payload = serde_json::to_value(&status)?;
            match send_status(&endpoint, &auth, &payload, configured_log_level) {
                Ok(_) => {
                    delivery_health.record_success(unix_timestamp());
                    render_status_screen(
                        if registration_once {
                            "Registration Mode"
                        } else {
                            "Monitoring Mode"
                        },
                        "[INFO] Send successful",
                        &endpoint,
                    );
                    log_message(
                        configured_log_level,
                        LogLevel::Info,
                        &format!("Status successfully sent to {}", endpoint),
                    );

                    if let Some(medium) = snapshots
                        .medium
                        .as_ref()
                        .filter(|_| !shutdown_requested.load(Ordering::Acquire))
                    {
                        if medium.collected_at > last_docker_sent_at {
                            if let Some(docker) = medium.docker_metrics.as_ref() {
                                if let Err(err) = send_docker_metrics(
                                    &endpoint,
                                    &auth,
                                    &status.host_name,
                                    medium.collected_at,
                                    docker,
                                    configured_log_level,
                                ) {
                                    log_message(
                                        configured_log_level,
                                        LogLevel::Warn,
                                        &format!("Failed to send docker metrics: {}", err),
                                    );
                                } else {
                                    last_docker_sent_at = medium.collected_at;
                                }
                            } else {
                                last_docker_sent_at = medium.collected_at;
                            }
                        }
                    }

                    if let Some(medium) = snapshots
                        .medium
                        .as_ref()
                        .filter(|_| !shutdown_requested.load(Ordering::Acquire))
                        .filter(|snapshot| snapshot.collected_at > last_logs_sent_at)
                    {
                        if medium.log_events.is_empty() {
                            last_logs_sent_at = medium.collected_at;
                        } else if let Err(err) = send_log_events(
                            &endpoint,
                            &auth,
                            &status.host_name,
                            medium.collected_at,
                            &medium.log_events,
                            configured_log_level,
                        ) {
                            log_message(
                                configured_log_level,
                                LogLevel::Warn,
                                &format!("Failed to send log events: {}", err),
                            );
                        } else {
                            last_logs_sent_at = medium.collected_at;
                        }
                    }

                    if let Some(slow) = snapshots
                        .slow
                        .as_ref()
                        .filter(|_| !shutdown_requested.load(Ordering::Acquire))
                    {
                        if let Some(update_status) = slow
                            .update_status
                            .as_ref()
                            .filter(|update| update.timestamp > last_updates_sent_at)
                        {
                            if let Err(err) = send_update_status(
                                &endpoint,
                                &auth,
                                &status.host_name,
                                update_status,
                                configured_log_level,
                            ) {
                                log_message(
                                    configured_log_level,
                                    LogLevel::Warn,
                                    &format!("Failed to send update status: {}", err),
                                );
                            } else {
                                last_updates_sent_at = update_status.timestamp;
                            }
                        }
                    }

                    if let Some(queued) = telemetry_queue
                        .due_item(unix_timestamp())
                        .filter(|_| !shutdown_requested.load(Ordering::Acquire))
                    {
                        match send_status(&endpoint, &auth, &queued.payload, configured_log_level) {
                            Ok(_) => {
                                delivery_health.record_success(unix_timestamp());
                                telemetry_queue.record_success(&queued.id)?;
                                log_message(
                                    configured_log_level,
                                    LogLevel::Info,
                                    &format!("Replayed queued heartbeat {}", queued.id),
                                );
                            }
                            Err(err) => {
                                delivery_health.record_failure(unix_timestamp(), &err.to_string());
                                telemetry_queue.record_failure(&queued.id, unix_timestamp())?;
                                log_message(
                                    configured_log_level,
                                    LogLevel::Warn,
                                    &format!(
                                        "Failed to replay queued heartbeat {}: {}",
                                        queued.id, err
                                    ),
                                );
                            }
                        }
                    }
                }
                Err(err) => {
                    delivery_health.record_failure(unix_timestamp(), &err.to_string());
                    telemetry_queue.enqueue(
                        &status.host_name,
                        status.timestamp,
                        payload,
                        unix_timestamp(),
                    )?;
                    render_status_screen(
                        if registration_once {
                            "Registration Mode"
                        } else {
                            "Monitoring Mode"
                        },
                        "[ERROR] Send failed",
                        &endpoint,
                    );
                    log_message(
                        configured_log_level,
                        LogLevel::Error,
                        &format!("Failed to send status: {}", err),
                    );
                }
            }
            delivery_health.queue_depth = telemetry_queue.len();
            delivery_health.dropped_samples = telemetry_queue.dropped_samples();
        }

        if registration_once || final_cycle || shutdown_requested.load(Ordering::Acquire) {
            if !registration_once {
                log_message(
                    configured_log_level,
                    LogLevel::Info,
                    "Shutdown requested; final heartbeat handled and queue state persisted.",
                );
            }
            break;
        }

        wait_for_interval_or_shutdown(interval, &shutdown_requested);
    }

    Ok(())
}

fn wait_for_interval_or_shutdown(interval: Duration, shutdown_requested: &AtomicBool) {
    let started_at = Instant::now();
    while started_at.elapsed() < interval && !shutdown_requested.load(Ordering::Acquire) {
        let remaining = interval.saturating_sub(started_at.elapsed());
        thread::sleep(remaining.min(Duration::from_secs(1)));
    }
}

fn parse_endpoint(args: &[String]) -> Option<String> {
    let mut iter = args.iter().skip(1).peekable();
    while let Some(arg) = iter.next() {
        if let Some(value) = arg.strip_prefix("--endpoint=") {
            return Some(value.to_string());
        }

        if arg == "--endpoint" {
            if let Some(next) = iter.peek() {
                return Some((**next).to_string());
            }
        }
    }
    None
}

fn parse_interval(args: &[String]) -> Option<u64> {
    for arg in args.iter().skip(1) {
        if let Some(value) = arg.strip_prefix("--interval=") {
            return value.parse().ok();
        }
    }
    None
}

fn parse_invitation_link(args: &[String]) -> Option<String> {
    for arg in args.iter().skip(1) {
        if let Some(value) = arg.strip_prefix("--invitation-link=") {
            return Some(value.to_string());
        }
    }
    None
}

fn parse_invite_token(args: &[String]) -> Option<String> {
    let mut iter = args.iter().skip(1).peekable();
    while let Some(arg) = iter.next() {
        if let Some(value) = arg.strip_prefix("--invite-token=") {
            return Some(value.to_string());
        }
        if let Some(value) = arg.strip_prefix("--invitation=") {
            return Some(value.to_string());
        }
        if let Some(value) = arg.strip_prefix("--token=") {
            return Some(value.to_string());
        }
        if let Some(value) = arg.strip_prefix("--agent-token=") {
            return Some(value.to_string());
        }

        if arg == "--invite-token"
            || arg == "--invitation"
            || arg == "--token"
            || arg == "--agent-token"
        {
            if let Some(next) = iter.peek() {
                return Some((**next).to_string());
            }
        }
    }

    if let Some(positional) = args.iter().skip(1).find(|arg| !arg.starts_with('-')) {
        return Some(positional.to_string());
    }

    None
}

fn extract_invite_token(url: &str) -> Option<String> {
    if url.is_empty() {
        return None;
    }

    let parsed = Url::parse(url).ok()?;
    for (key, value) in parsed.query_pairs() {
        if key == "invite_token" {
            return Some(value.into_owned());
        }
    }

    None
}

fn parse_argument_value(args: &[String], name: &str) -> Option<String> {
    for (index, arg) in args.iter().enumerate() {
        if let Some(value) = arg.strip_prefix(&format!("{}=", name)) {
            return non_empty(Some(value.to_string()));
        }
        if arg == name {
            return args
                .get(index + 1)
                .cloned()
                .and_then(|value| non_empty(Some(value)));
        }
    }
    None
}

fn non_empty(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    })
}

fn render_status_screen(mode: &str, state: &str, endpoint: &str) {
    #[cfg(windows)]
    if windows::is_service() {
        return;
    }
    print!("\x1B[2J\x1B[1;1H");
    println!("sadapp");
    println!("{}", "=".repeat(40));
    println!("Mode: {}", mode);
    println!("State: {}", state);
    println!("Endpoint: {}", endpoint);
    let _ = io::stdout().flush();
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Rounds to a fixed number of decimals before submission; the control plane stores
/// this value as-is in its raw telemetry blob, so noise here (e.g. 42.384719...) is
/// noise there too, with no benefit at the precision the dashboard displays.
fn round_to(value: f32, decimals: i32) -> f32 {
    let factor = 10_f32.powi(decimals);
    (value * factor).round() / factor
}

fn collect_static_inventory(
    sys: &System,
    startup_network: &StartupNetworkSnapshot,
) -> StaticInventory {
    let (aes_ni_enabled, virtualization_hw_enabled) = cpu_feature_flags();
    StaticInventory {
        host_name: sys.host_name().unwrap_or_else(|| String::from("unknown")),
        os_name: sys.name().unwrap_or_else(|| String::from("unknown")),
        os_version: sys
            .long_os_version()
            .unwrap_or_else(|| String::from("unknown")),
        kernel_version: sys
            .kernel_version()
            .unwrap_or_else(|| String::from("unknown")),
        processor: sys
            .cpus()
            .first()
            .map(|cpu| cpu.brand().to_string())
            .unwrap_or_else(|| String::from("unknown")),
        cpu_frequency_mhz: average_cpu_frequency_mhz(sys),
        aes_ni_enabled: (!cfg!(windows)).then_some(aes_ni_enabled),
        virtualization_hw_enabled: (!cfg!(windows)).then_some(virtualization_hw_enabled),
        distro: sys
            .long_os_version()
            .unwrap_or_else(|| String::from("unknown")),
        vm_type: (!cfg!(windows)).then(detect_vm_type),
        ipv4_online: startup_network.ipv4_online,
        ipv6_online: startup_network.ipv6_online,
        ipv4_network_info: startup_network.ipv4_network_info.clone(),
        environment: first_non_empty_env(&["SADAPP_ENVIRONMENT", "MONITORING_ENVIRONMENT"]),
        server_role: first_non_empty_env(&["SADAPP_SERVER_ROLE", "MONITORING_SERVER_ROLE"]),
        datacenter: first_non_empty_env(&["SADAPP_DATACENTER", "MONITORING_DATACENTER"]),
        rack: first_non_empty_env(&["SADAPP_RACK", "MONITORING_RACK"]),
        cluster: first_non_empty_env(&["SADAPP_CLUSTER", "MONITORING_CLUSTER"]),
        provider: first_non_empty_env(&["SADAPP_PROVIDER", "MONITORING_PROVIDER"]),
        owner_team: first_non_empty_env(&["SADAPP_OWNER_TEAM", "MONITORING_OWNER_TEAM"]),
        architecture: env::consts::ARCH.to_string(),
        timezone: {
            #[cfg(windows)]
            {
                windows::timezone()
            }
            #[cfg(not(windows))]
            {
                Some(detect_timezone())
            }
        },
        machine_id: detect_machine_id(),
        agent_version: agent_version().to_string(),
    }
}

fn spawn_medium_collector(
    snapshots: Arc<Mutex<CollectorSnapshots>>,
    in_flight: Arc<AtomicBool>,
    interval_seconds: u64,
) {
    if in_flight.swap(true, Ordering::AcqRel) {
        return;
    }
    thread::spawn(move || {
        let snapshot = collect_medium_snapshot(interval_seconds);
        snapshots
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .medium = Some(snapshot);
        in_flight.store(false, Ordering::Release);
    });
}

fn parse_optional_f32(value: &str) -> Option<f32> {
    let value = value.trim();
    if value.is_empty() || value.eq_ignore_ascii_case("n/a") || value == "[Not Supported]" {
        return None;
    }
    value
        .parse::<f32>()
        .ok()
        .filter(|number| number.is_finite())
}

fn parse_nvidia_smi_csv(output: &str) -> Vec<GpuInfo> {
    output
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.splitn(12, ',').map(str::trim).collect();
            if fields.len() != 12 || fields[0].is_empty() || fields[1].is_empty() {
                return None;
            }
            let mib_to_bytes = |value: &str| {
                parse_optional_f32(value).map(|mib| (mib.max(0.0) * 1024.0 * 1024.0) as u64)
            };
            Some(GpuInfo {
                id: fields[2].to_string(),
                name: fields[1].to_string(),
                vendor: String::from("NVIDIA"),
                driver_version: (!fields[3].is_empty() && !fields[3].eq_ignore_ascii_case("n/a"))
                    .then(|| fields[3].to_string()),
                pci_bus_id: (!fields[4].is_empty() && !fields[4].eq_ignore_ascii_case("n/a"))
                    .then(|| fields[4].to_string()),
                utilization_percent: parse_optional_f32(fields[5]),
                memory_total_bytes: mib_to_bytes(fields[6]),
                memory_used_bytes: mib_to_bytes(fields[7]),
                temperature_celsius: parse_optional_f32(fields[8]),
                power_draw_watts: parse_optional_f32(fields[9]),
                power_limit_watts: parse_optional_f32(fields[10]),
                fan_speed_percent: parse_optional_f32(fields[11]),
            })
        })
        .collect()
}

fn read_trimmed(path: impl AsRef<Path>) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn read_scaled_f32(path: impl AsRef<Path>, divisor: f32) -> Option<f32> {
    read_trimmed(path)?
        .parse::<f32>()
        .ok()
        .filter(|value| value.is_finite())
        .map(|value| value / divisor)
}

fn first_hwmon_value(device_path: &Path, file_name: &str, divisor: f32) -> Option<f32> {
    fs::read_dir(device_path.join("hwmon"))
        .ok()?
        .filter_map(Result::ok)
        .find_map(|entry| read_scaled_f32(entry.path().join(file_name), divisor))
}

fn collect_sysfs_gpu_metrics_from(drm_root: &Path, skip_nvidia: bool) -> Vec<GpuInfo> {
    let entries = match fs::read_dir(drm_root) {
        Ok(entries) => entries,
        Err(_) => return Vec::new(),
    };
    let mut devices = HashMap::new();

    for entry in entries.filter_map(Result::ok) {
        let drm_node_name = entry.file_name().to_string_lossy().into_owned();
        let device_path = entry.path().join("device");
        let canonical_device = match fs::canonicalize(&device_path) {
            Ok(path) => path,
            Err(_) => continue,
        };
        let vendor_id = match read_trimmed(device_path.join("vendor")) {
            Some(value) => value.to_lowercase(),
            None => continue,
        };
        let vendor = match vendor_id.as_str() {
            "0x10de" if skip_nvidia => continue,
            "0x10de" => "NVIDIA",
            "0x1002" => "AMD",
            "0x8086" => "Intel",
            _ => continue,
        };
        let pci_bus_id = canonical_device
            .file_name()
            .map(|value| value.to_string_lossy().into_owned());
        let device_id =
            read_trimmed(device_path.join("device")).unwrap_or_else(|| String::from("unknown"));
        let driver_version = fs::canonicalize(device_path.join("driver"))
            .ok()
            .and_then(|path| {
                path.file_name()
                    .map(|value| value.to_string_lossy().into_owned())
            });
        let utilization_percent = read_scaled_f32(device_path.join("gpu_busy_percent"), 1.0)
            .or_else(|| read_scaled_f32(entry.path().join("gt_busy_percent"), 1.0));
        let memory_total_bytes = read_trimmed(device_path.join("mem_info_vram_total"))
            .and_then(|value| value.parse().ok());
        let memory_used_bytes = read_trimmed(device_path.join("mem_info_vram_used"))
            .and_then(|value| value.parse().ok());
        let temperature_celsius = first_hwmon_value(&device_path, "temp1_input", 1000.0);
        let power_draw_watts = first_hwmon_value(&device_path, "power1_average", 1_000_000.0)
            .or_else(|| first_hwmon_value(&device_path, "power1_input", 1_000_000.0));
        let power_limit_watts = first_hwmon_value(&device_path, "power1_cap", 1_000_000.0);
        let fan_speed_percent =
            first_hwmon_value(&device_path, "pwm1", 2.55).map(|value| value.clamp(0.0, 100.0));
        let id = pci_bus_id.clone().unwrap_or_else(|| drm_node_name.clone());

        devices.entry(canonical_device).or_insert(GpuInfo {
            id,
            name: format!("{vendor} GPU {device_id}"),
            vendor: vendor.to_string(),
            driver_version,
            pci_bus_id,
            utilization_percent,
            memory_total_bytes,
            memory_used_bytes,
            temperature_celsius,
            power_draw_watts,
            power_limit_watts,
            fan_speed_percent,
        });
    }

    devices.into_values().collect()
}

fn collect_sysfs_gpu_metrics(skip_nvidia: bool) -> Vec<GpuInfo> {
    collect_sysfs_gpu_metrics_from(Path::new("/sys/class/drm"), skip_nvidia)
}

fn collect_gpu_metrics() -> Vec<GpuInfo> {
    if cfg!(windows) {
        return Vec::new();
    }
    let nvidia_devices = Command::new("nvidia-smi")
        .args([
            "--query-gpu=index,name,uuid,driver_version,pci.bus_id,utilization.gpu,memory.total,memory.used,temperature.gpu,power.draw,power.limit,fan.speed",
            "--format=csv,noheader,nounits",
        ])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| parse_nvidia_smi_csv(&String::from_utf8_lossy(&output.stdout)))
        .unwrap_or_default();
    let mut devices = collect_sysfs_gpu_metrics(!nvidia_devices.is_empty());
    devices.extend(nvidia_devices);
    devices.sort_by(|left, right| left.id.cmp(&right.id));
    devices
}

fn read_sysfs_u64(path: &Path) -> Option<u64> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn collect_hwmon_sensors() -> (Vec<TemperatureSensor>, Vec<FanSensor>) {
    if cfg!(windows) {
        return (Vec::new(), Vec::new());
    }
    let mut temperatures = Vec::new();
    let mut fans = Vec::new();
    let Ok(entries) = fs::read_dir("/sys/class/hwmon") else {
        return (temperatures, fans);
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let device_name = fs::read_to_string(path.join("name"))
            .ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "Hardware monitor".to_string());
        let Ok(files) = fs::read_dir(&path) else {
            continue;
        };

        for file in files.flatten() {
            let file_name = file.file_name();
            let file_name = file_name.to_string_lossy();
            if let Some(channel) = file_name
                .strip_prefix("temp")
                .and_then(|suffix| suffix.strip_suffix("_input"))
            {
                let label = fs::read_to_string(path.join(format!("temp{channel}_label")))
                    .ok()
                    .map(|value| value.trim().to_owned())
                    .filter(|value| !value.is_empty())
                    .unwrap_or_else(|| format!("Temperature {channel}"));
                if let Some(milli_celsius) = read_sysfs_u64(&file.path()) {
                    let value_celsius = milli_celsius as f32 / 1_000.0;
                    if (0.0..=150.0).contains(&value_celsius) {
                        temperatures.push(TemperatureSensor {
                            name: format!("{device_name}: {label}"),
                            value_celsius,
                        });
                    }
                }
            }
            if let Some(channel) = file_name
                .strip_prefix("fan")
                .and_then(|suffix| suffix.strip_suffix("_input"))
            {
                let label = fs::read_to_string(path.join(format!("fan{channel}_label")))
                    .ok()
                    .map(|value| value.trim().to_owned())
                    .filter(|value| !value.is_empty())
                    .unwrap_or_else(|| format!("Fan {channel}"));
                if let Some(rpm) = read_sysfs_u64(&file.path()) {
                    fans.push(FanSensor {
                        name: format!("{device_name}: {label}"),
                        rpm,
                    });
                }
            }
        }
    }

    temperatures.sort_by(|left, right| left.name.cmp(&right.name));
    fans.sort_by(|left, right| left.name.cmp(&right.name));
    (temperatures, fans)
}

fn collect_listening_ports() -> Vec<ListeningPort> {
    if cfg!(windows) {
        return Vec::new();
    }
    let mut ports = Vec::new();
    for (protocol, path, listening_state) in [
        ("tcp", "/proc/net/tcp", "0A"),
        ("tcp6", "/proc/net/tcp6", "0A"),
        ("udp", "/proc/net/udp", "07"),
        ("udp6", "/proc/net/udp6", "07"),
    ] {
        let Ok(contents) = fs::read_to_string(path) else {
            continue;
        };
        for row in contents.lines().skip(1) {
            let fields: Vec<&str> = row.split_whitespace().collect();
            let Some(local_address) = fields.get(1) else {
                continue;
            };
            if fields.get(3).copied() != Some(listening_state) {
                continue;
            }
            let Some(port_hex) = local_address.rsplit(':').next() else {
                continue;
            };
            if let Ok(port) = u16::from_str_radix(port_hex, 16) {
                ports.push(ListeningPort {
                    protocol: protocol.to_string(),
                    port,
                });
            }
        }
    }
    ports.sort_by(|left, right| {
        left.protocol
            .cmp(&right.protocol)
            .then(left.port.cmp(&right.port))
    });
    ports.dedup_by(|left, right| left.protocol == right.protocol && left.port == right.port);
    ports.truncate(100);
    ports
}

fn collect_medium_snapshot(interval_seconds: u64) -> MediumCollectorSnapshot {
    let disk_started = Instant::now();
    let mut sys = System::new_all();
    sys.refresh_all();
    if cfg!(windows) {
        thread::sleep(Duration::from_millis(250));
        sys.refresh_processes();
    }
    let disk_devices: Vec<DiskInfo> = sys
        .disks()
        .iter()
        .map(|disk| DiskInfo {
            name: disk.name().to_string_lossy().into_owned(),
            mount_point: disk.mount_point().to_string_lossy().into_owned(),
            total_bytes: disk.total_space(),
            available_bytes: disk.available_space(),
            file_system: String::from_utf8_lossy(disk.file_system()).into_owned(),
        })
        .collect();
    let disk_health =
        CollectorHealth::completed("disk", disk_started, interval_seconds, true, None);
    let network_started = Instant::now();
    let network_interfaces = sys
        .networks()
        .iter()
        .map(
            |(name, data): (&String, &sysinfo::NetworkData)| NetworkInterface {
                name: name.clone(),
                received_bytes: data.total_received(),
                transmitted_bytes: data.total_transmitted(),
            },
        )
        .collect();
    let network_health =
        CollectorHealth::completed("network", network_started, interval_seconds, true, None);
    let process_started = Instant::now();
    let processes: Vec<ProcessInfo> = sys
        .processes()
        .values()
        .map(|process| ProcessInfo {
            name: process.name().to_string(),
            cpu_usage_percent: round_to(process.cpu_usage(), 1),
            memory_bytes: process.memory(),
        })
        .collect();
    let mut top_cpu_processes = processes.clone();
    top_cpu_processes
        .sort_by(|left, right| right.cpu_usage_percent.total_cmp(&left.cpu_usage_percent));
    top_cpu_processes.truncate(5);
    let mut top_memory_processes = processes;
    top_memory_processes.sort_by(|left, right| right.memory_bytes.cmp(&left.memory_bytes));
    top_memory_processes.truncate(5);
    let process_health =
        CollectorHealth::completed("processes", process_started, interval_seconds, true, None);
    let ports_started = Instant::now();
    let listening_ports = collect_listening_ports();
    let ports_health =
        CollectorHealth::completed("ports", ports_started, interval_seconds, true, None);
    let sensors_started = Instant::now();
    let (temperature_sensors, fan_sensors) = collect_hwmon_sensors();
    let sensors_health =
        CollectorHealth::completed("sensors", sensors_started, interval_seconds, true, None);
    let gpu_started = Instant::now();
    let gpu_devices = collect_gpu_metrics();
    let gpu_health = CollectorHealth::completed("gpu", gpu_started, interval_seconds, true, None);
    let docker_started = Instant::now();
    let docker_metrics = collect_docker_metrics();
    let docker_health = CollectorHealth::completed(
        "docker",
        docker_started,
        interval_seconds,
        docker_metrics.is_some(),
        Some("Docker daemon unavailable"),
    );
    let virtualization_started = Instant::now();
    let virtualization_metrics = collect_virtualization_metrics();
    let virtualization_health = CollectorHealth::completed(
        "virtualization",
        virtualization_started,
        interval_seconds,
        virtualization_metrics.is_some(),
        Some("Proxmox guest API unavailable"),
    );
    let logs_started = Instant::now();
    let log_events = collect_log_events(80);
    let logs_health =
        CollectorHealth::completed("logs", logs_started, interval_seconds, true, None);
    MediumCollectorSnapshot {
        collected_at: unix_timestamp(),
        disk_total_bytes: disk_devices.iter().map(|disk| disk.total_bytes).sum(),
        disk_devices,
        network_interfaces,
        temperature_sensors,
        fan_sensors,
        top_cpu_processes,
        top_memory_processes,
        listening_ports,
        gpu_devices,
        docker_metrics,
        virtualization_metrics,
        log_events,
        health: vec![
            disk_health,
            network_health,
            process_health,
            ports_health,
            sensors_health,
            gpu_health,
            docker_health,
            virtualization_health,
            logs_health,
        ],
    }
}

fn spawn_slow_collector(
    host_name: String,
    update_lifecycle: UpdateLifecycleState,
    snapshots: Arc<Mutex<CollectorSnapshots>>,
    in_flight: Arc<AtomicBool>,
    interval_seconds: u64,
) {
    if in_flight.swap(true, Ordering::AcqRel) {
        return;
    }
    thread::spawn(move || {
        let snapshot = collect_slow_snapshot(&host_name, &update_lifecycle, interval_seconds);
        snapshots
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .slow = Some(snapshot);
        in_flight.store(false, Ordering::Release);
    });
}

fn collect_slow_snapshot(
    host_name: &str,
    update_lifecycle: &UpdateLifecycleState,
    interval_seconds: u64,
) -> SlowCollectorSnapshot {
    let now = unix_timestamp();
    let smart_started = Instant::now();
    let smartctl = collect_smartctl_metrics();
    let smart_health = CollectorHealth::completed(
        "smart",
        smart_started,
        interval_seconds,
        smartctl.is_some(),
        Some("smartctl unavailable"),
    );
    let packages_started = Instant::now();
    let update_status = collect_update_status(now, host_name, update_lifecycle);
    let packages_health = CollectorHealth::completed(
        "packages",
        packages_started,
        interval_seconds,
        update_status.is_some(),
        Some("supported package manager unavailable"),
    );
    SlowCollectorSnapshot {
        smartctl,
        update_status,
        health: vec![smart_health, packages_health],
    }
}

fn collect_smartctl_metrics() -> Option<Value> {
    let scan_output = Command::new("smartctl")
        .args(["--scan-open", "-j"])
        .output()
        .ok()?;
    let scan: Value = serde_json::from_slice(&scan_output.stdout).ok()?;
    let mut devices = Vec::new();

    for scanned in scan
        .get("devices")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(name) = scanned.get("name").and_then(Value::as_str) else {
            continue;
        };
        let mut command = Command::new("smartctl");
        command.args(["-a", "-j", name]);
        if let Some(device_type) = scanned.get("type").and_then(Value::as_str) {
            command.args(["-d", device_type]);
        }
        let Ok(output) = command.output() else {
            continue;
        };
        let Ok(raw) = serde_json::from_slice::<Value>(&output.stdout) else {
            continue;
        };
        devices.push(smartctl_device_summary(name, &raw));
    }

    Some(json!({
        "collected_at": unix_timestamp(),
        "devices": devices,
    }))
}

fn smartctl_device_summary(name: &str, raw: &Value) -> Value {
    json!({
        "device": name,
        "model": raw.get("model_name").and_then(Value::as_str),
        "health": raw.pointer("/smart_status/passed").and_then(Value::as_bool).map(|passed| if passed { "passed" } else { "failed" }),
        "temperature_c": raw.pointer("/temperature/current").and_then(Value::as_i64),
        "pending_sectors": smart_attribute_raw(raw, &["Current_Pending_Sector", "Current Pending Sector"]),
        "reallocated_sectors": smart_attribute_raw(raw, &["Reallocated_Sector_Ct", "Reallocated Sector Count"]),
        "uncorrectable_sectors": smart_attribute_raw(raw, &["Offline_Uncorrectable", "Reported_Uncorrect"])
            .or_else(|| raw.pointer("/nvme_smart_health_information_log/media_errors").and_then(Value::as_i64)),
    })
}

fn smart_attribute_raw(raw: &Value, names: &[&str]) -> Option<i64> {
    raw.pointer("/ata_smart_attributes/table")
        .and_then(Value::as_array)?
        .iter()
        .find(|attribute| {
            attribute
                .get("name")
                .and_then(Value::as_str)
                .map(|name| {
                    names
                        .iter()
                        .any(|candidate| name.eq_ignore_ascii_case(candidate))
                })
                .unwrap_or(false)
        })
        .and_then(|attribute| attribute.pointer("/raw/value"))
        .and_then(Value::as_i64)
}

fn gather_status(
    sys: &mut System,
    static_inventory: &StaticInventory,
    medium: Option<&MediumCollectorSnapshot>,
    slow: Option<&SlowCollectorSnapshot>,
    delivery_health: &DeliveryHealth,
    configuration_health: &ConfigurationHealth,
    update_lifecycle: &UpdateLifecycleState,
    interval_seconds: u64,
) -> ServerStatus {
    let heartbeat_started = Instant::now();
    sys.refresh_cpu();
    sys.refresh_memory();
    sys.refresh_processes();

    let cpu_count = sys.cpus().len();
    let cpu_usage_percent = sys.global_cpu_info().cpu_usage();
    let agent_runtime = sys
        .process(sysinfo::Pid::from_u32(std::process::id()))
        .map(|process| {
            let disk_usage = process.disk_usage();
            AgentRuntime {
                cpu_percent: round_to(process.cpu_usage(), 1),
                memory_bytes: process.memory(),
                disk_read_bytes: disk_usage.total_read_bytes,
                disk_written_bytes: disk_usage.total_written_bytes,
            }
        });

    let timestamp = unix_timestamp();
    let mut collector_health = Vec::new();
    collector_health.push(CollectorHealth::completed(
        "heartbeat",
        heartbeat_started,
        interval_seconds,
        true,
        None,
    ));
    if let Some(snapshot) = medium {
        collector_health.extend(snapshot.health.clone());
    }
    if let Some(snapshot) = slow {
        collector_health.extend(snapshot.health.clone());
    }

    ServerStatus {
        timestamp,
        host_name: static_inventory.host_name.clone(),
        os_name: static_inventory.os_name.clone(),
        os_version: static_inventory.os_version.clone(),
        kernel_version: static_inventory.kernel_version.clone(),
        processor: static_inventory.processor.clone(),
        cpu_frequency_mhz: static_inventory.cpu_frequency_mhz,
        aes_ni_enabled: static_inventory.aes_ni_enabled,
        virtualization_hw_enabled: static_inventory.virtualization_hw_enabled,
        distro: static_inventory.distro.clone(),
        vm_type: static_inventory.vm_type.clone(),
        ipv4_online: static_inventory.ipv4_online,
        ipv6_online: static_inventory.ipv6_online,
        disk_total_bytes: medium
            .map(|snapshot| snapshot.disk_total_bytes)
            .unwrap_or(0),
        uptime_seconds: sys.uptime(),
        load_average: (!cfg!(windows)).then(|| LoadAverage {
            one: round_to(sys.load_average().one as f32, 2) as f64,
            five: round_to(sys.load_average().five as f32, 2) as f64,
            fifteen: round_to(sys.load_average().fifteen as f32, 2) as f64,
        }),
        cpu_usage_percent: round_to(cpu_usage_percent, 1),
        cpu_count,
        memory_total_bytes: sys.total_memory(),
        memory_used_bytes: sys.used_memory(),
        swap_total_bytes: sys.total_swap(),
        swap_used_bytes: sys.used_swap(),
        disk_devices: medium
            .map(|snapshot| snapshot.disk_devices.clone())
            .unwrap_or_default(),
        network_interfaces: medium
            .map(|snapshot| snapshot.network_interfaces.clone())
            .unwrap_or_default(),
        temperature_sensors: medium
            .map(|snapshot| snapshot.temperature_sensors.clone())
            .unwrap_or_default(),
        fan_sensors: medium
            .map(|snapshot| snapshot.fan_sensors.clone())
            .unwrap_or_default(),
        top_cpu_processes: medium
            .map(|snapshot| snapshot.top_cpu_processes.clone())
            .unwrap_or_default(),
        top_memory_processes: medium
            .map(|snapshot| snapshot.top_memory_processes.clone())
            .unwrap_or_default(),
        listening_ports: medium
            .map(|snapshot| snapshot.listening_ports.clone())
            .unwrap_or_default(),
        gpu_devices: medium
            .map(|snapshot| snapshot.gpu_devices.clone())
            .unwrap_or_default(),
        processes: sys.processes().len(),
        ipv4_network_info: static_inventory.ipv4_network_info.clone(),
        environment: static_inventory.environment.clone(),
        server_role: static_inventory.server_role.clone(),
        datacenter: static_inventory.datacenter.clone(),
        rack: static_inventory.rack.clone(),
        cluster: static_inventory.cluster.clone(),
        provider: static_inventory.provider.clone(),
        owner_team: static_inventory.owner_team.clone(),
        architecture: static_inventory.architecture.clone(),
        timezone: static_inventory.timezone.clone(),
        machine_id: static_inventory.machine_id.clone(),
        agent_version: static_inventory.agent_version.clone(),
        agent_runtime,
        delivery_health: delivery_health.clone(),
        docker_metrics: medium.and_then(|snapshot| snapshot.docker_metrics.clone()),
        virtualization_metrics: medium.and_then(|snapshot| snapshot.virtualization_metrics.clone()),
        smartctl: slow.and_then(|snapshot| snapshot.smartctl.clone()),
        agent_health: AgentHealth {
            contract_version: 1,
            reported_at: timestamp,
            collectors: collector_health,
            configuration: configuration_health.clone(),
            update: AgentUpdateHealth {
                current_version: update_lifecycle.current_version.clone(),
                desired_version: update_lifecycle.desired_version.clone(),
                channel: update_lifecycle.channel.clone(),
                state: update_lifecycle.state.clone(),
                verification_mode: update_lifecycle.verification_mode.clone(),
                rollback_result: update_lifecycle.rollback_result.clone(),
            },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_queue_path(name: &str) -> PathBuf {
        env::temp_dir().join(format!(
            "sadapp-host-agent-{}-{}-{}.json",
            name,
            std::process::id(),
            unix_timestamp()
        ))
    }

    #[test]
    fn journal_events_keep_original_timestamp_and_metadata() {
        let event = parse_journal_event(r#"{"__REALTIME_TIMESTAMP":"1790512235000000","__CURSOR":"cursor-1","MESSAGE":"containerd.service: Found left-over process 1001445.","SYSLOG_IDENTIFIER":"systemd","_SYSTEMD_UNIT":"containerd.service","PRIORITY":"4"}"#)
            .expect("parse journal JSON event");

        assert_eq!(event.timestamp, 1_790_512_235);
        assert_eq!(event.source, "systemd");
        assert_eq!(event.severity, "warn");
        assert_eq!(
            event.message,
            "containerd.service: Found left-over process 1001445."
        );
        assert_eq!(event.unit.as_deref(), Some("containerd.service"));
        assert_eq!(event.journal_cursor.as_deref(), Some("cursor-1"));
    }

    #[test]
    fn journal_events_without_a_realtime_timestamp_are_ignored() {
        assert!(
            parse_journal_event(r#"{"MESSAGE":"missing timestamp","SYSLOG_IDENTIFIER":"systemd"}"#)
                .is_none()
        );
    }

    #[cfg(unix)]
    #[test]
    fn decodes_chunked_docker_engine_json() {
        let decoded = decode_chunked_http_body(b"7\r\n{\"ok\":1\r\n1\r\n}\r\n0\r\n\r\n")
            .expect("decode chunked body");
        let json: Value = serde_json::from_slice(&decoded).expect("parse JSON response");
        assert_eq!(json.get("ok").and_then(Value::as_u64), Some(1));
    }

    #[cfg(unix)]
    #[test]
    fn docker_cpu_rate_uses_counter_deltas_and_needs_a_baseline() {
        assert_eq!(
            docker_cpu_percent(150, 1_100, Some((100, 1_000)), 2),
            Some(100.0)
        );
        assert_eq!(docker_cpu_percent(150, 1_100, None, 2), None);
        assert_eq!(docker_cpu_percent(100, 1_100, Some((150, 1_000)), 2), None);
    }

    #[cfg(unix)]
    #[test]
    fn docker_stats_helpers_match_docker_cli() {
        assert!(docker_api_at_least("1.52", 1, 41));
        assert!(docker_api_at_least("1.41", 1, 41));
        assert!(!docker_api_at_least("1.40", 1, 41));
        let v2 = serde_json::json!({ "memory_stats": { "usage": 1_000, "stats": { "inactive_file": 400 } } });
        assert_eq!(docker_memory_usage(&v2), Some(600));
        let v1 = serde_json::json!({ "memory_stats": { "usage": 1_000, "stats": { "total_inactive_file": 100 } } });
        assert_eq!(docker_memory_usage(&v1), Some(900));
        assert_eq!(
            docker_memory_usage(&serde_json::json!({ "memory_stats": {} })),
            None
        );
    }

    #[test]
    fn parses_proxmox_qemu_and_lxc_inventory_fields() {
        let rows = json!([
            { "vmid": 101, "name": "web-vm", "status": "running", "cpu": 0.125, "mem": 512, "maxmem": 1024, "disk": 200, "maxdisk": 800, "uptime": 45, "tags": "web;prod" },
            { "vmid": "102", "status": "stopped", "maxmem": "2048" }
        ]);
        let guests = parse_proxmox_guest_rows(&rows, "qemu");
        assert_eq!(guests.len(), 2);
        assert_eq!(guests[0].guest_id, "101");
        assert_eq!(guests[0].cpu_percent, Some(12.5));
        assert_eq!(guests[0].memory_used_bytes, Some(512));
        assert_eq!(guests[0].tags.as_deref(), Some("web;prod"));
        assert_eq!(guests[1].name, "qemu-102");
        assert_eq!(guests[1].memory_total_bytes, Some(2048));
        assert_eq!(parse_proxmox_guest_rows(&rows, "lxc")[0].guest_type, "lxc");
    }

    #[test]
    fn delivery_health_tracks_failures_and_recovery() {
        let mut health = DeliveryHealth::new(100);

        health.record_failure(110, "network unavailable");
        health.record_failure(120, "request timed out");
        assert_eq!(health.total_attempts, 2);
        assert_eq!(health.total_successes, 0);
        assert_eq!(health.consecutive_failures, 2);
        assert_eq!(health.last_failed_submit_at, Some(120));
        assert_eq!(health.last_error.as_deref(), Some("request timed out"));

        health.record_success(130);
        assert_eq!(health.total_attempts, 3);
        assert_eq!(health.total_successes, 1);
        assert_eq!(health.consecutive_failures, 0);
        assert_eq!(health.last_successful_submit_at, Some(130));
        assert!(health.last_error.is_none());
    }

    #[test]
    fn delivery_health_bounds_error_messages() {
        let mut health = DeliveryHealth::new(100);
        health.record_failure(110, &"x".repeat(600));
        assert_eq!(health.last_error.as_deref().map(str::len), Some(500));
    }

    #[test]
    fn parses_key_arguments_in_both_supported_forms() {
        let args = vec![
            String::from("agent"),
            String::from("--key-id=key-1"),
            String::from("--key-secret"),
            String::from("secret-1"),
        ];

        assert_eq!(
            parse_argument_value(&args, "--key-id").as_deref(),
            Some("key-1")
        );
        assert_eq!(
            parse_argument_value(&args, "--key-secret").as_deref(),
            Some("secret-1")
        );
    }

    #[test]
    fn invite_token_takes_precedence_over_key_headers() {
        let client = Client::new();
        let key_auth = AuthConfig {
            invite_token: None,
            key_id: Some(String::from("key-1")),
            key_secret: Some(String::from("secret-1")),
        };
        let key_request = key_auth
            .apply(client.post("https://sadapp.org/api/v1/agent"))
            .build()
            .expect("build key request");
        assert_eq!(key_request.headers()["x-agent-key-id"], "key-1");
        assert_eq!(key_request.headers()["x-agent-key-secret"], "secret-1");

        let invite_auth = AuthConfig {
            invite_token: Some(String::from("invite-1")),
            key_id: Some(String::from("key-1")),
            key_secret: Some(String::from("secret-1")),
        };
        let invite_request = invite_auth
            .apply(client.post("https://sadapp.org/api/v1/agent"))
            .build()
            .expect("build invite request");
        assert!(
            invite_request
                .url()
                .query()
                .unwrap_or_default()
                .contains("invite_token=invite-1")
        );
        assert!(!invite_request.headers().contains_key("x-agent-key-id"));
    }

    #[test]
    fn telemetry_queue_persists_deduplicates_and_evicts_oldest() {
        let path = temp_queue_path("bounded");
        let mut queue = TelemetryQueue::open(path.clone(), 2).expect("open queue");

        assert!(
            queue
                .enqueue("host", 1, json!({"timestamp": 1}), 100)
                .unwrap()
        );
        assert!(
            !queue
                .enqueue("host", 1, json!({"timestamp": 1}), 100)
                .unwrap()
        );
        assert!(
            queue
                .enqueue("host", 2, json!({"timestamp": 2}), 100)
                .unwrap()
        );
        assert!(
            queue
                .enqueue("host", 3, json!({"timestamp": 3}), 100)
                .unwrap()
        );
        assert_eq!(queue.len(), 2);
        assert_eq!(queue.dropped_samples(), 1);
        assert_eq!(
            queue.state.items.front().map(|item| item.timestamp),
            Some(2)
        );

        queue.record_failure("host:2", 200).expect("record retry");
        assert_eq!(queue.state.items.front().map(|item| item.attempts), Some(2));
        assert!(queue.due_item(200).is_none());

        let mut reloaded = TelemetryQueue::open(path.clone(), 2).expect("reload queue");
        assert_eq!(reloaded.len(), 2);
        assert_eq!(reloaded.dropped_samples(), 1);
        assert_eq!(
            reloaded.state.items.front().map(|item| item.attempts),
            Some(2)
        );
        reloaded
            .record_success("host:2")
            .expect("remove delivered item");
        assert_eq!(reloaded.len(), 1);
        assert_eq!(
            reloaded.state.items.front().map(|item| item.timestamp),
            Some(3)
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn telemetry_queue_preserves_outage_backoff_across_restart() {
        let path = temp_queue_path("outage-recovery");
        let mut queue = TelemetryQueue::open(path.clone(), 4).expect("open queue");
        assert!(
            queue
                .enqueue("host", 1, json!({"timestamp": 1}), 100)
                .unwrap()
        );

        queue
            .record_failure("host:1", 200)
            .expect("record outage failure");
        let expected_attempts = queue.state.items.front().map(|item| item.attempts);
        let expected_next_attempt = queue.state.items.front().map(|item| item.next_attempt_at);

        let reloaded = TelemetryQueue::open(path.clone(), 4).expect("reload queue");
        assert_eq!(
            reloaded.state.items.front().map(|item| item.attempts),
            expected_attempts
        );
        assert_eq!(
            reloaded
                .state
                .items
                .front()
                .map(|item| item.next_attempt_at),
            expected_next_attempt
        );
        assert!(
            reloaded
                .due_item(expected_next_attempt.unwrap().saturating_sub(1))
                .is_none()
        );
        assert!(reloaded.due_item(expected_next_attempt.unwrap()).is_some());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn retry_delay_is_bounded_and_increases() {
        let first = retry_delay_seconds(1, "host:1");
        let second = retry_delay_seconds(2, "host:1");
        let late = retry_delay_seconds(100, "host:1");
        assert!(first >= 5);
        assert!(second > first);
        assert!(late <= 304);
    }

    #[test]
    fn collector_schedule_respects_interval_and_in_flight_state() {
        assert!(collector_due(100, None, 60, false));
        assert!(!collector_due(100, None, 60, true));
        assert!(!collector_due(159, Some(100), 60, false));
        assert!(collector_due(160, Some(100), 60, false));
        assert!(!collector_due(10, Some(100), 60, false));
    }

    #[test]
    fn smart_attribute_parser_extracts_raw_sector_count() {
        let raw = json!({
            "ata_smart_attributes": {
                "table": [{
                    "name": "Current_Pending_Sector",
                    "raw": { "value": 3 }
                }]
            }
        });
        assert_eq!(
            smart_attribute_raw(&raw, &["Current_Pending_Sector"]),
            Some(3)
        );
        assert_eq!(smart_attribute_raw(&raw, &["Offline_Uncorrectable"]), None);
    }

    #[test]
    fn smartctl_device_summary_excludes_serial_and_raw_payload() {
        let raw = json!({
            "model_name": "Example SSD",
            "serial_number": "sensitive-serial",
            "smart_status": { "passed": true },
            "temperature": { "current": 34 },
            "ata_smart_attributes": {
                "table": [{ "name": "Current_Pending_Sector", "raw": { "value": 2 } }]
            }
        });

        let summary = smartctl_device_summary("/dev/sda", &raw);

        assert_eq!(summary["device"], "/dev/sda");
        assert_eq!(summary["model"], "Example SSD");
        assert_eq!(summary["pending_sectors"], 2);
        assert!(summary.get("serial").is_none());
        assert!(summary.get("serial_number").is_none());
        assert!(summary.get("raw").is_none());
    }

    #[test]
    fn collector_health_marks_optional_collector_unavailable() {
        let health = CollectorHealth::completed(
            "smart",
            Instant::now(),
            3600,
            false,
            Some("smartctl unavailable"),
        );
        assert_eq!(
            health.status,
            if cfg!(windows) {
                "unsupported"
            } else {
                "unavailable"
            }
        );
        assert_eq!(
            health.last_error.as_deref(),
            Some(if cfg!(windows) {
                "Not supported by the Windows prototype"
            } else {
                "smartctl unavailable"
            })
        );
        assert_eq!(health.interval_seconds, 3600);
    }

    #[test]
    fn update_state_corruption_is_not_silently_reset() {
        let path = temp_queue_path("invalid-update-state");
        fs::write(&path, b"invalid state").unwrap();
        let result =
            UpdateLifecycleState::load_and_reconcile(&path, agent_version(), None, "stable", 100);
        assert_eq!(result.err().unwrap().kind(), io::ErrorKind::InvalidData);
        assert_eq!(fs::read(&path).unwrap(), b"invalid state");
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn request_failures_do_not_disclose_invitation_urls_or_response_secrets() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut buffer = [0_u8; 8192];
            std::io::Read::read(&mut socket, &mut buffer).unwrap();
            socket.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 16\r\nConnection: close\r\n\r\nsynthetic-secret").unwrap();
        });
        let auth = AuthConfig {
            invite_token: Some("synthetic-secret".into()),
            key_id: None,
            key_secret: None,
        };
        let error = send_status(
            &format!("http://{address}/api/v1/agent"),
            &auth,
            &json!({}),
            LogLevel::Error,
        )
        .unwrap_err()
        .to_string();
        server.join().unwrap();
        assert!(error.contains("403"));
        assert!(!error.contains("synthetic-secret"));
        let error = send_status(
            &format!("http://{address}/api/v1/agent"),
            &auth,
            &json!({}),
            LogLevel::Error,
        )
        .unwrap_err()
        .to_string();
        assert!(!error.contains("synthetic-secret"));
        assert!(!error.contains("invite_token"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_projection_omits_unsupported_facts_and_marks_collectors() {
        let mut sys = System::new_all();
        sys.refresh_all();
        let network = StartupNetworkSnapshot {
            ipv4_online: false,
            ipv6_online: false,
            ipv4_network_info: None,
        };
        let inventory = collect_static_inventory(&sys, &network);
        let config = ConfigurationHealth {
            endpoint_source: "protected_config".into(),
            authentication_source: "protected_config".into(),
            interval_source: "protected_config".into(),
            queue_source: "default".into(),
            update_channel_source: "default".into(),
            platform: "windows",
            execution_mode: "windows_service",
            credential_storage: "machine_dpapi_with_windows_acl",
        };
        let update = UpdateLifecycleState::reconcile(
            None,
            agent_version(),
            None,
            "stable",
            unix_timestamp(),
        );
        let medium = collect_medium_snapshot(120);
        let slow = collect_slow_snapshot(&inventory.host_name, &update, 3600);
        let status = gather_status(
            &mut sys,
            &inventory,
            Some(&medium),
            Some(&slow),
            &DeliveryHealth::new(unix_timestamp()),
            &config,
            &update,
            30,
        );
        let value = serde_json::to_value(status).unwrap();
        for key in [
            "load_average",
            "aes_ni_enabled",
            "virtualization_hw_enabled",
            "vm_type",
        ] {
            assert!(
                value.get(key).is_none(),
                "{key} must not masquerade as a Windows measurement"
            );
        }
        assert_eq!(
            value["agent_health"]["update"]["verification_mode"],
            "external_authenticode_check_required"
        );
        for name in [
            "ports",
            "sensors",
            "gpu",
            "docker",
            "virtualization",
            "logs",
            "smart",
            "packages",
        ] {
            let collector = value["agent_health"]["collectors"]
                .as_array()
                .unwrap()
                .iter()
                .find(|collector| collector["name"] == name)
                .unwrap();
            assert_eq!(collector["status"], "unsupported", "{name}");
        }
        assert!(value["memory_total_bytes"].as_u64().unwrap() > 0);
        assert!(value["cpu_count"].as_u64().unwrap() > 0);
    }

    #[test]
    fn parses_nvidia_gpu_metrics() {
        let devices = parse_nvidia_smi_csv(
            "0, NVIDIA GeForce RTX 4090, GPU-abc, 580.12, 00000000:01:00.0, 37, 24564, 8192, 61, 188.5, 450.0, 42\n",
        );

        assert_eq!(devices.len(), 1);
        let gpu = &devices[0];
        assert_eq!(gpu.id, "GPU-abc");
        assert_eq!(gpu.vendor, "NVIDIA");
        assert_eq!(gpu.driver_version.as_deref(), Some("580.12"));
        assert_eq!(gpu.utilization_percent, Some(37.0));
        assert_eq!(gpu.memory_total_bytes, Some(24_564 * 1024 * 1024));
        assert_eq!(gpu.memory_used_bytes, Some(8_192 * 1024 * 1024));
        assert_eq!(gpu.temperature_celsius, Some(61.0));
        assert_eq!(gpu.power_draw_watts, Some(188.5));
        assert_eq!(gpu.fan_speed_percent, Some(42.0));
    }

    #[test]
    fn accepts_unsupported_optional_nvidia_metrics() {
        let devices = parse_nvidia_smi_csv(
            "0, NVIDIA A100, GPU-def, 580.12, 00000000:02:00.0, 0, 40960, 0, 35, 48.0, 300.0, [Not Supported]\n",
        );

        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].fan_speed_percent, None);
        assert_eq!(devices[0].memory_used_bytes, Some(0));
    }

    #[cfg(unix)]
    #[test]
    fn discovers_render_only_integrated_gpu() {
        use std::os::unix::fs::symlink;

        let root = env::temp_dir().join(format!("sadapp-gpu-test-{}", std::process::id()));
        let drm_root = root.join("drm");
        let pci_device = root.join("0000:00:02.0");
        fs::create_dir_all(drm_root.join("renderD128")).unwrap();
        fs::create_dir_all(&pci_device).unwrap();
        fs::write(pci_device.join("vendor"), "0x8086\n").unwrap();
        fs::write(pci_device.join("device"), "0x46a6\n").unwrap();
        symlink(&pci_device, drm_root.join("renderD128/device")).unwrap();

        let devices = collect_sysfs_gpu_metrics_from(&drm_root, false);

        fs::remove_dir_all(root).unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].vendor, "Intel");
        assert_eq!(devices[0].pci_bus_id.as_deref(), Some("0000:00:02.0"));
    }

    #[test]
    fn update_lifecycle_reconciles_upgrade_pending_and_rollback() {
        let pending = UpdateLifecycleState::reconcile(
            None,
            "1.0.0",
            Some(String::from("1.1.0")),
            "canary",
            100,
        );
        assert_eq!(pending.state, "pending");

        let upgraded = UpdateLifecycleState::reconcile(
            Some(pending),
            "1.1.0",
            Some(String::from("1.1.0")),
            "canary",
            200,
        );
        assert_eq!(upgraded.state, "updated");
        assert_eq!(upgraded.previous_version.as_deref(), Some("1.0.0"));
        assert_eq!(upgraded.last_successful_upgrade_at, Some(200));

        let rolled_back = UpdateLifecycleState::reconcile(
            Some(upgraded),
            "1.0.0",
            Some(String::from("1.0.0")),
            "stable",
            300,
        );
        assert_eq!(rolled_back.state, "rolled_back");
        assert_eq!(rolled_back.rollback_result.as_deref(), Some("succeeded"));

        let restarted = UpdateLifecycleState::reconcile(
            Some(rolled_back),
            "1.0.0",
            Some(String::from("1.0.0")),
            "stable",
            400,
        );
        assert_eq!(restarted.state, "current");
        assert_eq!(restarted.previous_version.as_deref(), Some("1.1.0"));
        assert_eq!(restarted.rollback_result.as_deref(), Some("succeeded"));
    }
}

#[cfg(unix)]
const DOCKER_HTTP_RESPONSE_LIMIT: usize = 8 * 1024 * 1024;

#[cfg(unix)]
fn docker_socket_path() -> Option<PathBuf> {
    match env::var("DOCKER_HOST").ok().as_deref() {
        Some(value) if value.starts_with("unix://") => Some(PathBuf::from(&value[7..])),
        Some(value) if !value.is_empty() => None,
        _ => Some(PathBuf::from("/var/run/docker.sock")),
    }
}

#[cfg(unix)]
fn docker_api_get(socket_path: &Path, path: &str) -> Option<Value> {
    let mut stream = UnixStream::connect(socket_path).ok()?;
    let timeout = Duration::from_secs(3);
    stream.set_read_timeout(Some(timeout)).ok()?;
    stream.set_write_timeout(Some(timeout)).ok()?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    )
    .ok()?;

    let mut response = Vec::new();
    stream
        .take((DOCKER_HTTP_RESPONSE_LIMIT + 1) as u64)
        .read_to_end(&mut response)
        .ok()?;
    if response.len() > DOCKER_HTTP_RESPONSE_LIMIT {
        return None;
    }
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")?;
    let headers = std::str::from_utf8(&response[..header_end]).ok()?;
    let status = headers
        .lines()
        .next()?
        .split_whitespace()
        .nth(1)?
        .parse::<u16>()
        .ok()?;
    if !(200..300).contains(&status) {
        return None;
    }
    let body = &response[header_end + 4..];
    let body = if headers.lines().any(|line| {
        let (name, value) = line.split_once(':').unwrap_or(("", ""));
        name.eq_ignore_ascii_case("transfer-encoding")
            && value.to_ascii_lowercase().contains("chunked")
    }) {
        decode_chunked_http_body(body)?
    } else {
        body.to_vec()
    };
    serde_json::from_slice(&body).ok()
}

#[cfg(unix)]
fn decode_chunked_http_body(mut body: &[u8]) -> Option<Vec<u8>> {
    let mut decoded = Vec::new();
    loop {
        let line_end = body.windows(2).position(|window| window == b"\r\n")?;
        let size_text = std::str::from_utf8(&body[..line_end])
            .ok()?
            .split(';')
            .next()?
            .trim();
        let size = usize::from_str_radix(size_text, 16).ok()?;
        body = &body[line_end + 2..];
        if size == 0 {
            return Some(decoded);
        }
        if size > body.len() || decoded.len().saturating_add(size) > DOCKER_HTTP_RESPONSE_LIMIT {
            return None;
        }
        decoded.extend_from_slice(&body[..size]);
        body = body.get(size + 2..)?;
    }
}

#[cfg(unix)]
fn docker_u64(value: Option<&Value>) -> Option<u64> {
    value.and_then(|value| {
        value
            .as_u64()
            .or_else(|| value.as_i64().and_then(|number| u64::try_from(number).ok()))
    })
}

#[cfg(unix)]
fn docker_api_at_least(version: &str, major: u64, minor: u64) -> bool {
    let mut parts = version
        .split('.')
        .map(|part| part.parse::<u64>().unwrap_or(0));
    let found = (parts.next().unwrap_or(0), parts.next().unwrap_or(0));
    found >= (major, minor)
}

#[cfg(unix)]
/// Matches `docker stats`: page cache that the kernel can reclaim is not counted as used.
fn docker_memory_usage(stats: &Value) -> Option<u64> {
    let usage = docker_u64(stats.pointer("/memory_stats/usage"))?;
    let cache = docker_u64(stats.pointer("/memory_stats/stats/inactive_file"))
        .or_else(|| docker_u64(stats.pointer("/memory_stats/stats/total_inactive_file")))
        .unwrap_or(0);
    Some(usage.saturating_sub(cache))
}

#[cfg(unix)]
fn docker_cpu_percent(
    current_cpu: u64,
    current_system: u64,
    baseline: Option<(u64, u64)>,
    online_cpus: u64,
) -> Option<f32> {
    let (previous_cpu, previous_system) = baseline?;
    let cpu_delta = current_cpu.checked_sub(previous_cpu)?;
    let system_delta = current_system.checked_sub(previous_system)?;
    (system_delta > 0).then(|| {
        round_to(
            (cpu_delta as f64 / system_delta as f64 * online_cpus.max(1) as f64 * 100.0) as f32,
            2,
        )
    })
}

#[cfg(unix)]
fn docker_string(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

#[cfg(target_os = "linux")]
fn collect_virtualization_metrics() -> Option<VirtualizationMetrics> {
    if !Path::new("/etc/pve").is_dir() {
        return None;
    }
    let node = fs::read_to_string("/etc/hostname").ok()?.trim().to_string();
    if node.is_empty()
        || !node.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
    {
        return None;
    }
    let qemu = pvesh_get_json(&format!("/nodes/{node}/qemu"));
    let lxc = pvesh_get_json(&format!("/nodes/{node}/lxc"));
    if qemu.is_none() && lxc.is_none() {
        return None;
    }
    let mut guests = Vec::new();
    if let Some(value) = qemu.as_ref() {
        guests.extend(parse_proxmox_guest_rows(value, "qemu"));
    }
    if let Some(value) = lxc.as_ref() {
        guests.extend(parse_proxmox_guest_rows(value, "lxc"));
    }
    Some(VirtualizationMetrics {
        provider: String::from("proxmox"),
        collected_at: unix_timestamp(),
        guests,
    })
}

#[cfg(not(target_os = "linux"))]
fn collect_virtualization_metrics() -> Option<VirtualizationMetrics> {
    None
}

#[cfg(target_os = "linux")]
fn pvesh_get_json(path: &str) -> Option<Value> {
    let output = Command::new("timeout")
        .args(["5s", "pvesh", "get", path, "--output-format", "json"])
        .output()
        .ok()?;
    if !output.status.success() || output.stdout.len() > 2 * 1024 * 1024 {
        return None;
    }
    serde_json::from_slice(&output.stdout).ok()
}

#[cfg(any(target_os = "linux", test))]
fn parse_proxmox_guest_rows(rows: &Value, guest_type: &str) -> Vec<VirtualGuestMetric> {
    rows.as_array()
        .into_iter()
        .flatten()
        .take(500)
        .filter_map(|row| {
            let guest_id = row.get("vmid").and_then(|value| {
                value
                    .as_str()
                    .map(str::to_string)
                    .or_else(|| value.as_u64().map(|id| id.to_string()))
            })?;
            let name = row
                .get("name")
                .and_then(Value::as_str)
                .filter(|name| !name.trim().is_empty())
                .map(str::to_string)
                .unwrap_or_else(|| format!("{guest_type}-{guest_id}"));
            let cpu = row
                .get("cpu")
                .and_then(Value::as_f64)
                .filter(|value| value.is_finite());
            let cpu_percent = cpu.map(|value| {
                round_to(
                    if value <= 1.0 {
                        (value * 100.0) as f32
                    } else {
                        value as f32
                    },
                    2,
                )
            });
            Some(VirtualGuestMetric {
                guest_id,
                name,
                guest_type: guest_type.to_string(),
                status: row
                    .get("status")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_ascii_lowercase(),
                cpu_percent,
                memory_used_bytes: json_u64(row.get("mem")),
                memory_total_bytes: json_u64(row.get("maxmem")),
                disk_used_bytes: json_u64(row.get("disk")),
                disk_total_bytes: json_u64(row.get("maxdisk")),
                uptime_seconds: json_u64(row.get("uptime")),
                tags: row.get("tags").and_then(Value::as_str).map(str::to_string),
            })
        })
        .collect()
}

#[cfg(any(target_os = "linux", test))]
fn json_u64(value: Option<&Value>) -> Option<u64> {
    value.and_then(|value| {
        value
            .as_u64()
            .or_else(|| value.as_i64().and_then(|number| u64::try_from(number).ok()))
            .or_else(|| value.as_str().and_then(|number| number.parse().ok()))
    })
}

#[cfg(unix)]
fn collect_docker_metrics() -> Option<DockerMetrics> {
    let socket_path = docker_socket_path()?;
    let version = docker_api_get(&socket_path, "/version")?;
    let engine_version = docker_string(version.get("Version"));
    let api_version = docker_string(version.get("ApiVersion"))?;
    let api = format!("/v{api_version}");
    // one-shot (API >= 1.41) returns immediately instead of waiting ~1s for a second sample,
    // so all running containers fit into the stats budget. CPU deltas use our own history.
    let stats_query = if docker_api_at_least(&api_version, 1, 41) {
        "stream=false&one-shot=true"
    } else {
        "stream=false"
    };
    let stats_started = Instant::now();
    let listed = docker_api_get(&socket_path, &format!("{api}/containers/json?all=1"))?;
    let entries = listed.as_array()?;
    let mut containers = Vec::with_capacity(entries.len().min(500));
    let detailed_started = Instant::now();
    let cpu_history = DOCKER_CPU_SNAPSHOTS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut cpu_history = cpu_history
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut seen = Vec::new();

    for (entry_index, entry) in entries.iter().take(500).enumerate() {
        let Some(container_id) = docker_string(entry.get("Id")) else {
            continue;
        };
        let name = entry
            .get("Names")
            .and_then(Value::as_array)
            .and_then(|names| names.first())
            .and_then(Value::as_str)
            .map(|name| name.trim_start_matches('/').to_string())
            .unwrap_or_default();
        let image = docker_string(entry.get("Image")).unwrap_or_default();
        if name.is_empty() || image.is_empty() {
            continue;
        }
        let state = docker_string(entry.get("State"));
        let mut labels: HashMap<String, String> = entry
            .get("Labels")
            .and_then(Value::as_object)
            .map(|labels| {
                labels
                    .iter()
                    .filter_map(|(key, value)| {
                        value.as_str().map(|value| (key.clone(), value.to_string()))
                    })
                    .collect()
            })
            .unwrap_or_default();
        labels.retain(|key, value| key.len() <= 128 && value.len() <= 512);

        let inspect_details =
            entry_index < 128 && detailed_started.elapsed() < Duration::from_secs(10);
        let inspected = inspect_details
            .then(|| {
                docker_api_get(
                    &socket_path,
                    &format!("{api}/containers/{container_id}/json"),
                )
            })
            .flatten();
        if let Some(inspected_labels) = inspected
            .as_ref()
            .and_then(|value| value.pointer("/Config/Labels"))
            .and_then(Value::as_object)
        {
            for (key, value) in inspected_labels {
                if let Some(value) = value
                    .as_str()
                    .filter(|value| key.len() <= 128 && value.len() <= 512)
                {
                    labels.insert(key.clone(), value.to_string());
                }
            }
        }
        let state_data = inspected.as_ref().and_then(|value| value.get("State"));
        let health = state_data
            .and_then(|value| value.pointer("Health/Status"))
            .and_then(Value::as_str)
            .map(str::to_string)
            .or_else(|| {
                entry
                    .get("Status")
                    .and_then(Value::as_str)
                    .and_then(|status| {
                        let status = status.to_ascii_lowercase();
                        if status.contains("unhealthy") {
                            Some(String::from("unhealthy"))
                        } else if status.contains("healthy") {
                            Some(String::from("healthy"))
                        } else {
                            None
                        }
                    })
            });
        let stats = if entry_index < 256
            && stats_started.elapsed() < Duration::from_secs(20)
            && state.as_deref() == Some("running")
        {
            docker_api_get(
                &socket_path,
                &format!("{api}/containers/{container_id}/stats?{stats_query}"),
            )
        } else {
            None
        };

        let cpu = stats.as_ref().and_then(|stats| {
            let cpu_usage = docker_u64(stats.pointer("/cpu_stats/cpu_usage/total_usage"))?;
            let system_usage = docker_u64(stats.pointer("/cpu_stats/system_cpu_usage"))?;
            let online_cpus = docker_u64(stats.pointer("/cpu_stats/online_cpus"))
                .or_else(|| {
                    stats
                        .pointer("/cpu_stats/cpu_usage/percpu_usage")
                        .and_then(Value::as_array)
                        .map(|cpus| cpus.len() as u64)
                })
                .unwrap_or(1);
            let previous = cpu_history.get(&container_id).copied();
            let baseline = previous.or_else(|| {
                let system = docker_u64(stats.pointer("/precpu_stats/system_cpu_usage"))?;
                // one-shot responses carry an empty precpu sample; it is not a baseline.
                (system > 0).then_some((
                    docker_u64(stats.pointer("/precpu_stats/cpu_usage/total_usage"))?,
                    system,
                ))
            });
            cpu_history.insert(container_id.clone(), (cpu_usage, system_usage));
            docker_cpu_percent(cpu_usage, system_usage, baseline, online_cpus)
        });
        seen.push(container_id.clone());

        let memory_usage = stats.as_ref().and_then(docker_memory_usage);
        let memory_limit = stats
            .as_ref()
            .and_then(|stats| docker_u64(stats.pointer("/memory_stats/limit")));
        let network_totals = stats
            .as_ref()
            .and_then(|stats| stats.get("networks"))
            .and_then(Value::as_object)
            .map(|networks| {
                networks.values().fold((0_u64, 0_u64), |totals, network| {
                    (
                        totals
                            .0
                            .saturating_add(docker_u64(network.get("rx_bytes")).unwrap_or(0)),
                        totals
                            .1
                            .saturating_add(docker_u64(network.get("tx_bytes")).unwrap_or(0)),
                    )
                })
            });
        let block_totals = stats
            .as_ref()
            .and_then(|stats| stats.pointer("/blkio_stats/io_service_bytes_recursive"))
            .and_then(Value::as_array)
            .map(|entries| {
                entries.iter().fold((0_u64, 0_u64), |totals, entry| {
                    let value = docker_u64(entry.get("value")).unwrap_or(0);
                    match entry
                        .get("op")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_ascii_lowercase()
                        .as_str()
                    {
                        "read" => (totals.0.saturating_add(value), totals.1),
                        "write" => (totals.0, totals.1.saturating_add(value)),
                        _ => totals,
                    }
                })
            });
        let image_digest = inspected
            .as_ref()
            .and_then(|value| value.get("RepoDigests"))
            .and_then(Value::as_array)
            .and_then(|digests| digests.first())
            .and_then(Value::as_str)
            .map(str::to_string);
        containers.push(DockerContainerMetric {
            container_id,
            name,
            image,
            image_digest,
            state,
            health,
            restart_count: inspected
                .as_ref()
                .and_then(|value| docker_u64(value.get("RestartCount"))),
            cpu_percent: cpu,
            memory_usage_bytes: memory_usage,
            memory_limit_bytes: memory_limit,
            memory_percent: memory_usage.zip(memory_limit).and_then(|(used, limit)| {
                (limit > 0).then(|| round_to(used as f32 / limit as f32 * 100.0, 2))
            }),
            net_rx_bytes: network_totals.map(|totals| totals.0),
            net_tx_bytes: network_totals.map(|totals| totals.1),
            block_read_bytes: block_totals.map(|totals| totals.0),
            block_write_bytes: block_totals.map(|totals| totals.1),
            started_at: state_data.and_then(|value| docker_string(value.get("StartedAt"))),
            finished_at: state_data.and_then(|value| docker_string(value.get("FinishedAt"))),
            labels,
        });
    }
    cpu_history.retain(|container_id, _| seen.contains(container_id));
    drop(cpu_history);

    let running_containers = containers
        .iter()
        .filter(|container| container.state.as_deref() == Some("running"))
        .count();
    let unhealthy_containers = containers
        .iter()
        .filter(|container| container.health.as_deref() == Some("unhealthy"))
        .count();
    let stopped_containers = containers.len().saturating_sub(running_containers);
    Some(DockerMetrics {
        collected_at: unix_timestamp(),
        running_containers,
        stopped_containers,
        unhealthy_containers,
        engine_version,
        disk_usage_bytes: None,
        containers,
    })
}

#[cfg(not(unix))]
fn collect_docker_metrics() -> Option<DockerMetrics> {
    None
}

#[cfg(unix)]
static DOCKER_CPU_SNAPSHOTS: OnceLock<Mutex<HashMap<String, (u64, u64)>>> = OnceLock::new();

fn docker_endpoint_from(agent_endpoint: &str) -> String {
    format!("{}/docker", normalize_agent_endpoint(agent_endpoint))
}

fn logs_endpoint_from(agent_endpoint: &str) -> String {
    format!("{}/logs", normalize_agent_endpoint(agent_endpoint))
}

fn updates_endpoint_from(agent_endpoint: &str) -> String {
    format!("{}/updates", normalize_agent_endpoint(agent_endpoint))
}

fn normalize_agent_endpoint(endpoint: &str) -> String {
    let without_fragment = endpoint.split('#').next().unwrap_or(endpoint);
    let without_query = without_fragment
        .split('?')
        .next()
        .unwrap_or(without_fragment);
    without_query.trim_end_matches('/').to_string()
}

fn collect_log_events(max_events: usize) -> Vec<LogEvent> {
    if cfg!(windows) {
        return Vec::new();
    }
    let mut events = collect_journal_events(max_events);
    let remaining = max_events.saturating_sub(events.len());
    if remaining > 0 {
        events.extend(collect_docker_events(remaining));
    }
    events.truncate(max_events);
    events
}

fn journal_cursor_store() -> &'static Mutex<Option<String>> {
    JOURNAL_CURSOR.get_or_init(|| Mutex::new(None))
}

fn parse_journal_event(line: &str) -> Option<LogEvent> {
    let entry: Value = serde_json::from_str(line).ok()?;
    let timestamp_micros = entry.get("__REALTIME_TIMESTAMP").and_then(|value| {
        value
            .as_str()
            .and_then(|text| text.parse::<u64>().ok())
            .or_else(|| value.as_u64())
    })?;
    let message = entry.get("MESSAGE").and_then(Value::as_str)?.trim();
    if message.is_empty() {
        return None;
    }
    let source = entry
        .get("SYSLOG_IDENTIFIER")
        .or_else(|| entry.get("_COMM"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .unwrap_or("systemd")
        .to_string();
    let severity = match entry.get("PRIORITY").and_then(|value| {
        value
            .as_str()
            .and_then(|text| text.parse::<u8>().ok())
            .or_else(|| value.as_u64().map(|number| number as u8))
    }) {
        Some(0..=2) => String::from("critical"),
        Some(3) => String::from("error"),
        Some(4) => String::from("warn"),
        Some(5 | 6) => String::from("info"),
        Some(7) => String::from("debug"),
        _ => infer_severity(message),
    };
    Some(LogEvent {
        timestamp: timestamp_micros / 1_000_000,
        source: source.clone(),
        severity,
        message: message.to_string(),
        fingerprint: Some(make_fingerprint(&source, message)),
        container_id: None,
        container_name: None,
        unit: entry
            .get("_SYSTEMD_UNIT")
            .or_else(|| entry.get("UNIT"))
            .and_then(Value::as_str)
            .map(str::to_string),
        journal_cursor: entry
            .get("__CURSOR")
            .and_then(Value::as_str)
            .map(str::to_string),
    })
}

fn collect_journal_events(max_events: usize) -> Vec<LogEvent> {
    let cursor = journal_cursor_store()
        .lock()
        .ok()
        .and_then(|saved| saved.clone());
    let event_limit = max_events.to_string();
    let mut command = Command::new("journalctl");
    command.args([
        "--no-pager",
        "-p",
        "warning",
        "-n",
        event_limit.as_str(),
        "-o",
        "json",
    ]);
    if let Some(cursor) = cursor.as_deref() {
        command.args(["--after-cursor", cursor]);
    }
    let output = match command.output() {
        Ok(output) if output.status.success() => output,
        _ if cursor.is_some() => {
            if let Ok(mut saved) = journal_cursor_store().lock() {
                *saved = None;
            }
            return collect_journal_events(max_events);
        }
        _ => return Vec::new(),
    };

    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(parse_journal_event)
        .collect()
}

fn collect_docker_events(max_events: usize) -> Vec<LogEvent> {
    let now_ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let since_ts = now_ts.saturating_sub(90);

    let output = match Command::new("docker")
        .args([
            "events",
            "--since",
            &since_ts.to_string(),
            "--until",
            &now_ts.to_string(),
            "--format",
            "{{json .}}",
        ])
        .output()
    {
        Ok(output) if output.status.success() => output,
        _ => return Vec::new(),
    };

    let mut events: Vec<LogEvent> = Vec::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        if events.len() >= max_events {
            break;
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let parsed: Value = match serde_json::from_str(trimmed) {
            Ok(value) => value,
            Err(_) => continue,
        };

        let status = parsed
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("event")
            .to_string();
        let event_type = parsed
            .get("Type")
            .and_then(Value::as_str)
            .unwrap_or("docker")
            .to_string();
        let action = parsed
            .get("Action")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let actor = parsed
            .get("Actor")
            .and_then(|actor| actor.get("Attributes"))
            .cloned()
            .unwrap_or(Value::Null);
        let container_name = actor
            .get("name")
            .and_then(Value::as_str)
            .map(|value| value.to_string());

        let message = format!("{} {} {}", event_type, action, status)
            .trim()
            .to_string();
        events.push(LogEvent {
            timestamp: now_ts,
            source: String::from("docker"),
            severity: infer_severity(&message),
            message: message.clone(),
            fingerprint: Some(make_fingerprint("docker", &message)),
            container_id: parsed
                .get("id")
                .and_then(Value::as_str)
                .map(|value| value.to_string()),
            container_name,
            unit: None,
            journal_cursor: None,
        });
    }

    events
}

fn infer_severity(message: &str) -> String {
    let lower = message.to_ascii_lowercase();
    if lower.contains("critical") || lower.contains("panic") || lower.contains("fatal") {
        return String::from("critical");
    }
    if lower.contains("error") || lower.contains("failed") || lower.contains("unhealthy") {
        return String::from("error");
    }
    if lower.contains("warn") || lower.contains("degraded") {
        return String::from("warn");
    }
    String::from("info")
}

fn make_fingerprint(source: &str, message: &str) -> String {
    let compact_message: String = message
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || *ch == ':' || *ch == '-' || *ch == '_')
        .take(80)
        .collect();
    format!("{}:{}", source, compact_message)
}

fn collect_update_status(
    now_ts: u64,
    host_name: &str,
    lifecycle: &UpdateLifecycleState,
) -> Option<UpdateStatusPayload> {
    if cfg!(windows) {
        return None;
    }
    let package_manager = detect_package_manager()?;
    let (pending_updates, pending_security_updates, sample_packages) =
        match package_manager.as_str() {
            "apt" => collect_apt_updates(),
            "dnf" => collect_dnf_updates(),
            _ => (0, 0, Vec::new()),
        };

    let reboot_required = fs::metadata("/var/run/reboot-required").is_ok();
    let package_summary = json!({
        "sample": sample_packages,
        "agent": {
            "current_version": lifecycle.current_version,
            "previous_version": lifecycle.previous_version,
            "desired_version": lifecycle.desired_version,
            "channel": lifecycle.channel,
            "state": lifecycle.state,
            "verification_mode": lifecycle.verification_mode,
            "rollback_result": lifecycle.rollback_result,
        }
    });

    Some(UpdateStatusPayload {
        timestamp: now_ts,
        host_name: host_name.to_string(),
        package_manager: Some(package_manager),
        pending_updates,
        pending_security_updates,
        reboot_required,
        last_successful_upgrade_at: lifecycle.last_successful_upgrade_at,
        last_failed_update_at: lifecycle.last_failed_update_at,
        last_failed_update_message: lifecycle.last_failed_update_message.clone(),
        package_summary,
        current_version: lifecycle.current_version.clone(),
        previous_version: lifecycle.previous_version.clone(),
        desired_version: lifecycle.desired_version.clone(),
        update_channel: lifecycle.channel.clone(),
        update_state: lifecycle.state.clone(),
        verification_mode: lifecycle.verification_mode.clone(),
        rollback_result: lifecycle.rollback_result.clone(),
    })
}

fn detect_package_manager() -> Option<String> {
    for candidate in ["apt", "dnf", "yum", "pacman", "zypper"] {
        if Command::new("sh")
            .args(["-c", &format!("command -v {} >/dev/null 2>&1", candidate)])
            .status()
            .ok()
            .map(|status| status.success())
            .unwrap_or(false)
        {
            return Some(candidate.to_string());
        }
    }
    None
}

fn collect_apt_updates() -> (u64, u64, Vec<String>) {
    let output = match Command::new("apt").args(["list", "--upgradable"]).output() {
        Ok(output) if output.status.success() => output,
        _ => return (0, 0, Vec::new()),
    };

    let mut sample: Vec<String> = Vec::new();
    let mut total = 0_u64;
    let mut security = 0_u64;

    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("Listing") {
            continue;
        }
        total = total.saturating_add(1);
        if trimmed.to_ascii_lowercase().contains("security") {
            security = security.saturating_add(1);
        }
        if sample.len() < 15 {
            sample.push(trimmed.to_string());
        }
    }

    (total, security, sample)
}

fn collect_dnf_updates() -> (u64, u64, Vec<String>) {
    let output = match Command::new("dnf")
        .args(["check-update", "--refresh"])
        .output()
    {
        Ok(output) => output,
        _ => return (0, 0, Vec::new()),
    };

    let mut sample: Vec<String> = Vec::new();
    let mut total = 0_u64;
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("Last metadata") {
            continue;
        }
        if trimmed.contains(".") && trimmed.contains(' ') {
            total = total.saturating_add(1);
            if sample.len() < 15 {
                sample.push(trimmed.to_string());
            }
        }
    }

    (total, 0, sample)
}

fn first_non_empty_env(keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Ok(value) = env::var(key) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

fn detect_machine_id() -> Option<String> {
    #[cfg(windows)]
    {
        windows::machine_id()
    }
    #[cfg(target_os = "linux")]
    {
        for path in ["/etc/machine-id", "/var/lib/dbus/machine-id"] {
            if let Ok(content) = fs::read_to_string(path) {
                let trimmed = content.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            }
        }
    }

    #[cfg(not(windows))]
    {
        None
    }
}

#[cfg(not(windows))]
fn detect_timezone() -> String {
    if let Ok(tz) = env::var("TZ") {
        let trimmed = tz.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(link) = fs::read_link("/etc/localtime") {
            let path = link.to_string_lossy();
            if let Some(idx) = path.find("zoneinfo/") {
                return path[(idx + "zoneinfo/".len())..].to_string();
            }
        }

        if let Ok(content) = fs::read_to_string("/etc/timezone") {
            let trimmed = content.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }

    String::from("UTC")
}

fn average_cpu_frequency_mhz(sys: &System) -> u64 {
    if sys.cpus().is_empty() {
        return 0;
    }

    let total: u64 = sys.cpus().iter().map(|cpu| cpu.frequency()).sum();
    total / sys.cpus().len() as u64
}

fn cpu_feature_flags() -> (bool, bool) {
    #[cfg(target_os = "linux")]
    {
        if let Ok(cpuinfo) = fs::read_to_string("/proc/cpuinfo") {
            let lower = cpuinfo.to_lowercase();
            let aes = lower.contains(" aes ") || lower.contains("\naes");
            let virt = lower.contains(" vmx ") || lower.contains(" svm ");
            return (aes, virt);
        }
    }

    (false, false)
}

fn detect_vm_type() -> String {
    #[cfg(target_os = "linux")]
    {
        if let Ok(output) = Command::new("systemd-detect-virt").arg("--vm").output() {
            if output.status.success() {
                let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if value.is_empty() || value == "none" {
                    return String::from("NONE");
                }
                return value.to_uppercase();
            }
        }
    }

    String::from("NONE")
}

fn is_socket_reachable(address: &str) -> bool {
    let timeout = Duration::from_secs(2);
    if let Ok(socket) = address.parse::<SocketAddr>() {
        return TcpStream::connect_timeout(&socket, timeout).is_ok();
    }
    false
}

fn fetch_ipv4_network_info() -> Option<Ipv4NetworkInfo> {
    let client = Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .ok()?;
    let response = client
        .get("https://ipwho.is/?output=json")
        .send()
        .ok()?
        .json::<IpWhoIsResponse>()
        .ok()?;

    if !response.success {
        return None;
    }

    let ip = response.ip?.trim().to_string();
    if ip.is_empty() {
        return None;
    }
    let connection = response.connection?;
    let isp = connection.isp.unwrap_or_else(|| String::from("unknown"));
    let org = connection.org.unwrap_or_else(|| String::from("unknown"));
    let asn = connection
        .asn
        .map(|value| format!("AS{}", value))
        .unwrap_or_else(|| String::from("unknown"));
    let city = response.city.unwrap_or_else(|| String::from("unknown"));
    let region = response.region.unwrap_or_else(|| String::from("unknown"));
    let country = response.country.unwrap_or_else(|| String::from("unknown"));

    Some(Ipv4NetworkInfo {
        ip,
        isp,
        asn,
        host: org,
        location: format!("{}, {}", city, region),
        country,
    })
}

fn send_status(
    endpoint: &str,
    auth: &AuthConfig,
    status: &Value,
    configured_log_level: LogLevel,
) -> Result<(), Box<dyn Error>> {
    let client = outbound_http_client()?;
    let response = auth
        .apply(client.post(endpoint))
        .json(status)
        .send()
        .map_err(reqwest::Error::without_url)?;

    if response.status().is_success() {
        log_message(configured_log_level, LogLevel::Debug, "Heartbeat accepted");
        Ok(())
    } else {
        let status = response.status();
        Err(format!("API request failed: {status}").into())
    }
}

fn outbound_http_client() -> Result<Client, reqwest::Error> {
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(OUTBOUND_HTTP_TIMEOUT_SECONDS))
        .connect_timeout(Duration::from_secs(5))
        .build()
}

#[derive(Serialize)]
struct DockerPayload<'a> {
    timestamp: u64,
    host_name: &'a str,
    docker: &'a DockerMetrics,
}

fn send_docker_metrics(
    endpoint: &str,
    auth: &AuthConfig,
    host_name: &str,
    timestamp: u64,
    docker: &DockerMetrics,
    configured_log_level: LogLevel,
) -> Result<(), Box<dyn Error>> {
    let docker_endpoint = docker_endpoint_from(endpoint);
    let payload = DockerPayload {
        timestamp,
        host_name,
        docker,
    };

    let client = outbound_http_client()?;
    let response = auth
        .apply(client.post(docker_endpoint))
        .json(&payload)
        .send()
        .map_err(reqwest::Error::without_url)?;
    if response.status().is_success() {
        log_message(
            configured_log_level,
            LogLevel::Debug,
            "Docker metrics successfully sent",
        );
        Ok(())
    } else {
        let status = response.status();
        Err(format!("Docker metrics request failed: {status}").into())
    }
}

fn commit_journal_cursor(events: &[LogEvent]) {
    if let Some(cursor) = events
        .iter()
        .filter_map(|event| event.journal_cursor.as_deref())
        .last()
    {
        if let Ok(mut saved) = journal_cursor_store().lock() {
            *saved = Some(cursor.to_string());
        }
    }
}

fn send_log_events(
    endpoint: &str,
    auth: &AuthConfig,
    host_name: &str,
    timestamp: u64,
    events: &[LogEvent],
    configured_log_level: LogLevel,
) -> Result<(), Box<dyn Error>> {
    if events.is_empty() {
        return Ok(());
    }

    let logs_endpoint = logs_endpoint_from(endpoint);
    let payload = LogsPayload {
        timestamp,
        host_name,
        events,
    };

    let client = outbound_http_client()?;
    let response = auth
        .apply(client.post(logs_endpoint))
        .json(&payload)
        .send()
        .map_err(reqwest::Error::without_url)?;
    if response.status().is_success() {
        commit_journal_cursor(events);
        log_message(
            configured_log_level,
            LogLevel::Debug,
            &format!("Log events successfully sent: {} entries", events.len()),
        );
        Ok(())
    } else {
        let status = response.status();
        Err(format!("Log events request failed: {status}").into())
    }
}

fn send_update_status(
    endpoint: &str,
    auth: &AuthConfig,
    _host_name: &str,
    update_status: &UpdateStatusPayload,
    configured_log_level: LogLevel,
) -> Result<(), Box<dyn Error>> {
    let updates_endpoint = updates_endpoint_from(endpoint);

    let client = outbound_http_client()?;
    let response = auth
        .apply(client.post(updates_endpoint))
        .json(update_status)
        .send()
        .map_err(reqwest::Error::without_url)?;
    if response.status().is_success() {
        log_message(
            configured_log_level,
            LogLevel::Debug,
            "Update status successfully sent",
        );
        Ok(())
    } else {
        let status = response.status();
        Err(format!("Update status request failed: {status}").into())
    }
}
