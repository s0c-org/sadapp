use std::{collections::HashMap, fmt};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub const PROTOCOL_VERSION: u8 = 2;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Credentials {
    pub collector_id: String,
    pub collector_secret: String,
}

impl fmt::Debug for Credentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Credentials")
            .field("collector_id", &self.collector_id)
            .field("collector_secret", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrollmentResponse {
    pub collector_id: String,
    pub collector_secret: String,
    pub heartbeat_interval_seconds: u64,
    pub max_concurrent_tasks: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HeartbeatRequest<'a> {
    pub protocol_version: u8,
    pub collector_version: &'a str,
    pub applied_config_revision: u64,
    pub capabilities: &'a [&'a str],
    pub running_task_count: usize,
    pub queue_depth: usize,
    pub max_concurrent_tasks: usize,
    pub claim_limit: usize,
    pub health: HeartbeatHealth,
    pub resource_usage: CollectorResourceUsage,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectorResourceUsage {
    pub cpu_percent: f32,
    pub memory_used_bytes: u64,
    pub memory_total_bytes: u64,
    pub disk_mount: Option<String>,
    pub disk_used_bytes: Option<u64>,
    pub disk_total_bytes: Option<u64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HeartbeatHealth {
    pub status: &'static str,
    pub spool_bytes: u64,
    pub spool_items: usize,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HeartbeatResponse {
    pub protocol_version: u8,
    pub next_heartbeat_seconds: u64,
    pub config_revision: u64,
    #[serde(default)]
    pub configuration: Option<Map<String, Value>>,
    pub drain: bool,
    #[serde(default)]
    pub tasks: Vec<TaskLease>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskLease {
    pub id: String,
    #[serde(rename = "type")]
    pub task_type: TaskType,
    pub lease_token: String,
    pub payload: Map<String, Value>,
    #[serde(default)]
    pub secrets: HashMap<String, String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TaskType {
    Discover,
    CollectSnmp,
    CollectPrometheus,
    CollectRest,
    RunCheck,
    RefreshConfig,
    RotateCredential,
    Drain,
    Upgrade,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskResult {
    pub task_id: String,
    pub lease_token: String,
    pub idempotency_key: String,
    pub status: TaskResultStatus,
    pub completed_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Map<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TaskResultStatus {
    Succeeded,
    Failed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_debug_redacts_secret() {
        let output = format!(
            "{:?}",
            Credentials {
                collector_id: "collector-1".into(),
                collector_secret: "do-not-print".into()
            }
        );
        assert!(output.contains("collector-1"));
        assert!(!output.contains("do-not-print"));
    }
}
