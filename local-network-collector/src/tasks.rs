use std::{
    future::Future,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    pin::Pin,
    process::Stdio,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, OnceLock,
    },
    time::{Duration, Instant},
};

use anyhow::Result;
use futures::{stream, StreamExt};
use ipnet::IpNet;
use reqwest::redirect::Policy;
use reqwest::{
    header::{HeaderMap, HeaderName, HeaderValue, CONTENT_TYPE},
    Method,
};
use sadapp_snmp_profile_engine::capability_discovery::{
    profile_column_group, scalar_group, standard_column_group, CapabilityRecorder, ColumnResult,
};
use sadapp_snmp_profile_engine::discovery_cache::{DiscoveryCache, DiscoveryKey};
use sadapp_snmp_profile_engine::profile_tables::{
    normalize_profile_tables, parse_profile_column, validate_plans, ProfileColumns,
    ProfileSnapshot, TablePlan,
};
use sadapp_snmp_profile_engine::standard_tables::{
    aggregate_storage_kind, normalize_standard_tables_with_issues, StandardColumns,
    StandardSnapshot, STANDARD_GROUP_TIMEOUT, STANDARD_MAX_PARALLEL, STANDARD_TABLES,
};
use sadapp_snmp_profile_engine::table_transport::{
    classify_table_failure, execute_table_command_partial, TableCommandOutput, TableOutputBudget,
    TableWalkFailure, TableWalkPolicy, DEFAULT_TABLE_MAX_ROWS,
};
use sadapp_snmp_profile_engine::{
    apply_numeric_transform, detect as detect_snmp_profiles, detection_bundle_checksum,
    metric_capability_group, DetectionProfile, IdentityProbe, Transform,
};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use tokio::{
    net::{lookup_host, TcpStream},
    process::Command,
    time::timeout,
};

use crate::{
    api::ApiClient,
    collectors::{map_rest_json, parse_prometheus, MetricSample, MAX_RESPONSE_BYTES},
    discovery_protocols::discover_multicast,
    model::{Credentials, TaskLease, TaskResult, TaskResultStatus, TaskType},
    network_policy::{NetworkPolicy, MAX_DISCOVERY_HOSTS},
    runtime_config::{self, CollectorConfig, SharedCollectorConfig},
    spool::Spool,
};

const MAX_DISCOVERY_PORTS: usize = 32;
const MAX_PROBE_CONCURRENCY: usize = 64;
const MAX_DISCOVERY_PORT_CONCURRENCY: usize = 4;
const MAX_HTTP_DISCOVERY_CONCURRENCY: usize = 2;
const HTTP_DISCOVERY_PORTS: &[u16] = &[
    80, 81, 443, 5000, 5001, 5357, 8000, 8006, 8080, 8443, 8899, 9000,
];
const REVERSE_DNS_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_SNMP_OIDS: usize = 128;
const MAX_SNMP_COMMAND_TIMEOUT: Duration = Duration::from_secs(45);
const MAX_SNMP_STORAGE_ROWS: usize = DEFAULT_TABLE_MAX_ROWS;
const OID_HR_STORAGE_TYPE: &str = "1.3.6.1.2.1.25.2.3.1.2";
const OID_HR_STORAGE_ALLOC_UNITS: &str = "1.3.6.1.2.1.25.2.3.1.4";
const OID_HR_STORAGE_SIZE: &str = "1.3.6.1.2.1.25.2.3.1.5";
const OID_HR_STORAGE_USED: &str = "1.3.6.1.2.1.25.2.3.1.6";
const OID_HR_STORAGE_TYPE_FIXED_DISK: &str = "1.3.6.1.2.1.25.2.1.4";
const OID_HR_STORAGE_TYPE_RAM: &str = "1.3.6.1.2.1.25.2.1.2";
const OID_HR_PROCESSOR_LOAD: &str = "1.3.6.1.2.1.25.3.3.1.2";
const OID_SNMP_SYS_OBJECT_ID: &str = "1.3.6.1.2.1.1.2.0";
const OID_SNMP_SYS_DESCR: &str = "1.3.6.1.2.1.1.1.0";
const SNMP_DISCOVERY_TIMEOUT: Duration = Duration::from_millis(900);

#[derive(Clone, Debug)]
pub struct CommandOutput {
    pub success: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

pub trait CommandExecutor: Send + Sync {
    fn run<'a>(
        &'a self,
        program: &'a str,
        args: &'a [String],
    ) -> Pin<Box<dyn Future<Output = Result<CommandOutput>> + Send + 'a>>;

    fn run_with_stderr<'a>(
        &'a self,
        program: &'a str,
        args: &'a [String],
    ) -> Pin<Box<dyn Future<Output = Result<CommandOutput>> + Send + 'a>> {
        self.run(program, args)
    }

    fn run_table<'a>(
        &'a self,
        program: &'a str,
        args: &'a [String],
        policy: TableWalkPolicy,
        deadline: tokio::time::Instant,
    ) -> Pin<Box<dyn Future<Output = Result<CommandOutput, TableWalkFailure>> + Send + 'a>> {
        Box::pin(async move {
            let output = self
                .run_table_partial(program, args, policy, deadline)
                .await?;
            if let Some(limit) = output.limit {
                return Err(limit);
            }
            Ok(CommandOutput {
                success: output.success,
                stdout: output.stdout,
                stderr: output.stderr,
            })
        })
    }

    fn run_table_partial<'a>(
        &'a self,
        program: &'a str,
        args: &'a [String],
        policy: TableWalkPolicy,
        deadline: tokio::time::Instant,
    ) -> Pin<Box<dyn Future<Output = Result<TableCommandOutput, TableWalkFailure>> + Send + 'a>>
    {
        Box::pin(async move {
            let output = tokio::time::timeout_at(deadline, self.run_with_stderr(program, args))
                .await
                .map_err(|_| TableWalkFailure::Timeout)?
                .map_err(|_| TableWalkFailure::Io)?;
            let mut budget = TableOutputBudget::new(policy);
            let mut stdout = Vec::new();
            let mut limit = None;
            for line in output.stdout.split_inclusive(|byte| *byte == b'\n') {
                if let Err(error) = budget.push(line, true) {
                    limit = Some(error);
                    break;
                }
                stdout.extend_from_slice(line);
            }
            if limit.is_none() {
                limit = budget.push(&output.stderr, false).err();
            }
            Ok(TableCommandOutput {
                success: output.success,
                stdout,
                stderr: output.stderr,
                limit,
            })
        })
    }
}

#[derive(Debug)]
pub struct TokioCommandExecutor;

impl CommandExecutor for TokioCommandExecutor {
    fn run_table_partial<'a>(
        &'a self,
        program: &'a str,
        args: &'a [String],
        policy: TableWalkPolicy,
        deadline: tokio::time::Instant,
    ) -> Pin<Box<dyn Future<Output = Result<TableCommandOutput, TableWalkFailure>> + Send + 'a>>
    {
        Box::pin(async move {
            let mut command = Command::new(program);
            command.args(args);
            execute_table_command_partial(command, policy, deadline).await
        })
    }
    fn run<'a>(
        &'a self,
        program: &'a str,
        args: &'a [String],
    ) -> Pin<Box<dyn Future<Output = Result<CommandOutput>> + Send + 'a>> {
        Box::pin(async move {
            let output = Command::new(program)
                .args(args)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .output()
                .await?;
            Ok(CommandOutput {
                success: output.status.success(),
                stdout: output.stdout,
                stderr: Vec::new(),
            })
        })
    }

    fn run_with_stderr<'a>(
        &'a self,
        program: &'a str,
        args: &'a [String],
    ) -> Pin<Box<dyn Future<Output = Result<CommandOutput>> + Send + 'a>> {
        Box::pin(async move {
            let output = Command::new(program)
                .args(args)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true)
                .output()
                .await?;
            Ok(CommandOutput {
                success: output.status.success(),
                stdout: output.stdout,
                stderr: output.stderr,
            })
        })
    }
}

#[derive(Clone)]
pub struct TaskContext {
    pub api: ApiClient,
    pub credentials: Credentials,
    pub config: SharedCollectorConfig,
    pub state_dir: PathBuf,
    pub draining: Arc<AtomicBool>,
    pub telemetry_spool: Spool,
    pub command_executor: Arc<dyn CommandExecutor>,
}

pub async fn execute(context: &TaskContext, task: TaskLease) -> TaskResult {
    let idempotency_key = format!("{}-{}", task.id, uuid::Uuid::new_v4());
    let task_id = task.id.clone();
    let task_type = format!("{:?}", task.task_type);
    let diagnostic_label = task_diagnostic_label(&task.task_type, &task.payload);
    let task_scope = task
        .payload
        .get("cidr")
        .and_then(Value::as_str)
        .or_else(|| task.payload.get("target").and_then(Value::as_str))
        .unwrap_or("unspecified");
    let started = Instant::now();
    tracing::info!(task_id = %task_id, task_type = %task_type, scope = %task_scope, "collector task started");
    let outcome = match task.task_type {
        TaskType::RefreshConfig => refresh_config(context, &task.payload).await,
        TaskType::Drain => {
            context.draining.store(true, Ordering::SeqCst);
            Ok(json_object(json!({"draining": true})))
        }
        TaskType::Discover => discover(context, &task.payload).await,
        TaskType::RunCheck => run_check(context, &task.payload).await,
        TaskType::CollectSnmp => collect_snmp(context, &task).await,
        TaskType::CollectPrometheus => collect_prometheus(context, &task).await,
        TaskType::CollectRest => collect_rest(context, &task).await,
        TaskType::RotateCredential => Err(TaskError::unsupported(
            "UNSUPPORTED_TASK",
            "credential rotation is not implemented by the current protocol",
        )),
        TaskType::Upgrade => Err(TaskError::unsupported(
            "UNSUPPORTED_TASK",
            "self-upgrade is not implemented by the current protocol",
        )),
    };
    match outcome {
        Ok(result) => {
            tracing::info!(task_id = %task_id, task_type = %task_type, elapsed_ms = started.elapsed().as_millis(), "collector task succeeded");
            TaskResult {
                task_id: task.id,
                lease_token: task.lease_token,
                idempotency_key,
                status: TaskResultStatus::Succeeded,
                completed_at: chrono::Utc::now().to_rfc3339(),
                result: Some(result),
                error_code: None,
                error_message: None,
            }
        }
        Err(error) => {
            let error_message = format_task_error(&diagnostic_label, &task.payload, error.message);
            tracing::warn!(task_id = %task_id, task_type = %task_type, elapsed_ms = started.elapsed().as_millis(), error_code = %error.code, error_message = %error_message, "collector task failed");
            TaskResult {
                task_id: task.id,
                lease_token: task.lease_token,
                idempotency_key,
                status: TaskResultStatus::Failed,
                completed_at: chrono::Utc::now().to_rfc3339(),
                result: None,
                error_code: Some(error.code),
                error_message: Some(error_message),
            }
        }
    }
}

fn task_diagnostic_label(task_type: &TaskType, payload: &Map<String, Value>) -> &'static str {
    match task_type {
        TaskType::Discover => "DISCOVERY",
        TaskType::CollectSnmp => "SNMP",
        TaskType::CollectPrometheus => "PROMETHEUS",
        TaskType::CollectRest => "REST",
        TaskType::RunCheck => match payload
            .get("checkType")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_ascii_uppercase()
            .as_str()
        {
            "ICMP" => "ICMP",
            "TCP" => "TCP",
            "HTTP" => "HTTP",
            "HTTPS" => "HTTPS",
            _ => "CHECK",
        },
        TaskType::RefreshConfig => "CONFIG",
        TaskType::RotateCredential => "CREDENTIAL ROTATION",
        TaskType::Drain => "DRAIN",
        TaskType::Upgrade => "UPGRADE",
    }
}

fn format_task_error(label: &str, payload: &Map<String, Value>, message: String) -> String {
    let target = match label {
        "DISCOVERY" => payload
            .get("cidr")
            .and_then(Value::as_str)
            .and_then(|value| value.parse::<IpNet>().ok())
            .map(|cidr| cidr.to_string()),
        "SNMP" | "ICMP" => payload
            .get("target")
            .and_then(Value::as_str)
            .and_then(|value| value.parse::<IpAddr>().ok())
            .map(|address| address.to_string()),
        "TCP" => payload
            .get("target")
            .and_then(Value::as_str)
            .and_then(|value| value.parse::<IpAddr>().ok())
            .map(|address| {
                let port = payload.get("port").and_then(Value::as_u64);
                port.map_or_else(|| address.to_string(), |port| format!("{address}:{port}"))
            }),
        "HTTP" | "HTTPS" | "PROMETHEUS" | "REST" => payload
            .get("url")
            .or_else(|| payload.get("target"))
            .and_then(Value::as_str)
            .and_then(|value| url::Url::parse(value).ok())
            .and_then(|url| Some((url.host_str()?.to_owned(), url.port_or_known_default()?)))
            .map(|(host, port)| format!("{host}:{port}")),
        _ => None,
    };
    match target {
        Some(target) => format!("{label} {target}: {message}"),
        None => format!("{label}: {message}"),
    }
}

async fn collect_prometheus(context: &TaskContext, task: &TaskLease) -> TaskOutcome {
    let body = fetch_collection_body(context, task, Method::GET, false).await?;
    let mappings = task
        .payload
        .get("mappings")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let node_exporter = task.payload.get("preset").and_then(Value::as_str) == Some("NODE_EXPORTER");
    let samples = parse_prometheus(&body, &mappings, node_exporter).map_err(TaskError::invalid)?;
    spool_collection(context, &task.id, &task.payload, samples)
}

async fn collect_rest(context: &TaskContext, task: &TaskLease) -> TaskOutcome {
    let method = match task
        .payload
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or("GET")
    {
        "GET" => Method::GET,
        "POST" => Method::POST,
        _ => return Err(TaskError::invalid("REST method must be GET or POST")),
    };
    let body = fetch_collection_body(context, task, method, true).await?;
    let mappings = task
        .payload
        .get("mappings")
        .and_then(Value::as_array)
        .ok_or_else(|| TaskError::invalid("mappings must be an array"))?;
    let samples = map_rest_json(&body, mappings).map_err(TaskError::invalid)?;
    spool_collection(context, &task.id, &task.payload, samples)
}

async fn fetch_collection_body(
    context: &TaskContext,
    task: &TaskLease,
    method: Method,
    require_json: bool,
) -> Result<Vec<u8>, TaskError> {
    let raw_url = text(&task.payload, "url")?;
    let url = url::Url::parse(raw_url).map_err(|_| TaskError::invalid("url is invalid"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(TaskError::invalid("url scheme must be HTTP or HTTPS"));
    }
    let host = url
        .host_str()
        .ok_or_else(|| TaskError::invalid("url host is required"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| TaskError::invalid("url port is invalid"))?;
    let policy = context
        .config
        .read()
        .await
        .policy()
        .map_err(TaskError::internal)?;
    let addresses = resolve_allowed(host, port, &policy).await?;
    let client = reqwest::Client::builder()
        .redirect(Policy::none())
        .resolve_to_addrs(host, &addresses)
        .build()
        .map_err(TaskError::internal)?;
    let headers = secret_headers(task)?;
    let mut request = client
        .request(method.clone(), url)
        .headers(headers)
        .timeout(task_timeout(&task.payload));
    if method == Method::POST {
        let body_key = task
            .payload
            .get("bodySecretId")
            .and_then(Value::as_str)
            .ok_or_else(|| TaskError::invalid("bodySecretId is required for REST POST"))?;
        let body = task.secrets.get(body_key).ok_or_else(|| {
            TaskError::failed("REST_SECRET_UNAVAILABLE", "REST body secret is unavailable")
        })?;
        request = request
            .header(CONTENT_TYPE, "application/json")
            .body(body.clone());
    }
    let response = request.send().await.map_err(|error| {
        let message = if error.is_timeout() {
            "request timed out"
        } else if error.is_connect() {
            "connection failed"
        } else {
            "request failed"
        };
        TaskError::failed("HTTP_REQUEST_FAILED", message)
    })?;
    read_collection_response(response, require_json).await
}

async fn read_collection_response(
    mut response: reqwest::Response,
    require_json: bool,
) -> Result<Vec<u8>, TaskError> {
    if response.status().is_redirection() {
        return Err(TaskError::policy("redirects are not allowed"));
    }
    if !response.status().is_success() {
        return Err(TaskError::failed(
            "HTTP_STATUS",
            format!("collector returned {}", response.status()),
        ));
    }
    if require_json
        && response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_none_or(|value| {
                let media_type = value
                    .split(';')
                    .next()
                    .unwrap_or_default()
                    .trim()
                    .to_ascii_lowercase();
                media_type != "application/json"
                    && !(media_type.starts_with("application/") && media_type.ends_with("+json"))
            })
    {
        tracing::warn!(
            error_code = "REST_CONTENT_TYPE",
            "REST response has a missing or non-JSON content type; validating JSON body and numeric mappings"
        );
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err(TaskError::failed(
            "RESPONSE_TOO_LARGE",
            "collector response exceeds byte limit",
        ));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|error| {
        let message = if error.is_timeout() {
            "response body read timed out"
        } else {
            "response body could not be read"
        };
        TaskError::failed("HTTP_READ_FAILED", message)
    })? {
        if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err(TaskError::failed(
                "RESPONSE_TOO_LARGE",
                "collector response exceeds byte limit",
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn secret_headers(task: &TaskLease) -> Result<HeaderMap, TaskError> {
    let Some(key) = task.payload.get("headersSecretId").and_then(Value::as_str) else {
        return Ok(HeaderMap::new());
    };
    let raw = task.secrets.get(key).ok_or_else(|| {
        TaskError::failed("HEADER_SECRET_UNAVAILABLE", "header secret is unavailable")
    })?;
    let values = serde_json::from_str::<Map<String, Value>>(raw)
        .map_err(|_| TaskError::invalid("header secret must be a JSON object"))?;
    if values.len() > 32 {
        return Err(TaskError::invalid("too many secret headers"));
    }
    let mut headers = HeaderMap::new();
    for (name, value) in values {
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| TaskError::invalid("invalid secret header name"))?;
        let value = value
            .as_str()
            .filter(|value| value.len() <= 8_192)
            .ok_or_else(|| TaskError::invalid("invalid secret header value"))?;
        headers.insert(
            name,
            HeaderValue::from_str(value)
                .map_err(|_| TaskError::invalid("invalid secret header value"))?,
        );
    }
    Ok(headers)
}

fn spool_collection(
    context: &TaskContext,
    task_id: &str,
    payload: &Map<String, Value>,
    samples: Vec<MetricSample>,
) -> TaskOutcome {
    let observed_at = chrono::Utc::now().to_rfc3339();
    let resource = payload
        .get("resource")
        .and_then(Value::as_object)
        .cloned()
        .ok_or_else(|| TaskError::invalid("resource is required"))?;
    let collector = payload
        .get("collector")
        .and_then(Value::as_object)
        .cloned()
        .ok_or_else(|| TaskError::invalid("collector is required"))?;
    let count = samples.len();
    let samples = samples
        .into_iter()
        .map(|sample| {
            json!({
                "resource": resource, "collector": collector, "metricKey": sample.metric_key,
                "unit": sample.unit, "valueType": sample.value_type, "labels": sample.labels,
                "observedAt": observed_at, "value": sample.value, "quality": "GOOD"
            })
        })
        .collect::<Vec<_>>();
    context
        .telemetry_spool
        .push(&json!({ "idempotencyKey": format!("task:{task_id}"), "samples": samples, "inventory": [] }))
        .map_err(TaskError::internal)?;
    Ok(json_object(json!({ "sampleCount": count })))
}

async fn refresh_config(context: &TaskContext, payload: &Map<String, Value>) -> TaskOutcome {
    let revision = payload
        .get("configRevision")
        .and_then(Value::as_u64)
        .ok_or_else(|| TaskError::invalid("configRevision is required"))?;
    let allowed_cidrs = string_array(payload.get("allowedCidrs"), "allowedCidrs")?;
    let updated = CollectorConfig {
        revision,
        allowed_cidrs,
    };
    updated
        .policy()
        .map_err(|error| TaskError::invalid(error.to_string()))?;
    if revision < context.config.read().await.revision {
        return Err(TaskError::invalid(
            "configRevision is older than the applied configuration",
        ));
    }
    runtime_config::persist(&context.state_dir, &updated).map_err(TaskError::internal)?;
    *context.config.write().await = updated;
    Ok(json_object(json!({"appliedConfigRevision": revision})))
}

fn normalize_discovered_hostname(hostname: String) -> Option<String> {
    let hostname = hostname.trim().trim_end_matches('.').to_owned();
    if hostname.is_empty()
        || hostname.len() > 253
        || hostname
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return None;
    }
    Some(hostname)
}

async fn reverse_dns_hostname(address: IpAddr) -> Option<String> {
    let lookup = tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&address));
    let hostname = match timeout(REVERSE_DNS_TIMEOUT, lookup).await {
        Ok(Ok(Ok(hostname))) => hostname,
        _ => return None,
    };
    normalize_discovered_hostname(hostname)
}

fn tcp_discovery_evidence(open_ports: &[u16], observed_at: &str) -> Value {
    json!({
        "schemaVersion": 1,
        "observedAt": observed_at,
        "probes": ["tcp-connect"],
        "services": open_ports.iter().map(|port| json!({ "transport": "tcp", "port": port })).collect::<Vec<_>>(),
    })
}

fn merge_discovery_candidate(candidates: &mut Vec<Value>, observation: Value) {
    let Some(address) = observation.get("address").and_then(Value::as_str) else {
        return;
    };
    let Some(existing) = candidates
        .iter_mut()
        .find(|candidate| candidate["address"].as_str() == Some(address))
    else {
        candidates.push(observation);
        return;
    };
    let (Some(existing_evidence), Some(incoming_evidence)) = (
        existing.get_mut("evidence").and_then(Value::as_object_mut),
        observation.get("evidence").and_then(Value::as_object),
    ) else {
        return;
    };
    for key in [
        "services",
        "httpResponses",
        "snmpResponses",
        "protocolObservations",
        "probes",
    ] {
        let Some(incoming) = incoming_evidence.get(key).and_then(Value::as_array) else {
            continue;
        };
        let target = existing_evidence
            .entry(key.to_owned())
            .or_insert_with(|| json!([]));
        if let Some(target) = target.as_array_mut() {
            for item in incoming {
                if !target.contains(item) {
                    target.push(item.clone());
                }
            }
        }
    }
    if let Some(identity) = incoming_evidence.get("identity") {
        match existing_evidence.get("identity") {
            None if existing_evidence.get("identityConflict") != Some(&json!(true)) => {
                existing_evidence.insert("identity".to_owned(), identity.clone());
            }
            Some(existing_identity) if existing_identity != identity => {
                existing_evidence.remove("identity");
                existing_evidence.insert("identityConflict".to_owned(), json!(true));
            }
            _ => {}
        }
    }
}

fn safe_http_header(headers: &reqwest::header::HeaderMap, name: HeaderName) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .chars()
                .filter(|character| !character.is_control())
                .take(160)
                .collect()
        })
        .filter(|value: &String| !value.is_empty())
}

async fn probe_http_service(client: &reqwest::Client, address: IpAddr, port: u16) -> Option<Value> {
    let scheme = if [443, 5001, 8006, 8443].contains(&port) {
        "https"
    } else {
        "http"
    };
    let host = match address {
        IpAddr::V4(address) => address.to_string(),
        IpAddr::V6(address) => format!("[{address}]"),
    };
    let url = format!("{scheme}://{host}:{port}/");
    let mut method = Method::HEAD;
    let mut response = client.head(&url).send().await.ok()?;
    if response.status() == reqwest::StatusCode::METHOD_NOT_ALLOWED
        || response.status() == reqwest::StatusCode::NOT_IMPLEMENTED
    {
        method = Method::OPTIONS;
        response = client.request(method.clone(), &url).send().await.ok()?;
    }
    let status = response.status().as_u16();
    let authenticate = safe_http_header(
        response.headers(),
        HeaderName::from_static("www-authenticate"),
    );
    let server = safe_http_header(response.headers(), HeaderName::from_static("server"));
    let content_type = safe_http_header(response.headers(), CONTENT_TYPE);
    let auth_schemes = authenticate
        .as_deref()
        .and_then(|value| value.split_whitespace().next())
        .map(str::to_owned);
    Some(json!({
        "transport": "tcp",
        "port": port,
        "protocol": "http",
        "method": method.as_str(),
        "statusCode": status,
        "authentication": if status == 401 || status == 403 || authenticate.is_some() { "required" } else { "not-required-for-root" },
        "authScheme": auth_schemes,
        "server": server,
        "contentType": content_type,
    }))
}

fn snmpv3_discovery_args(target: IpAddr) -> Vec<String> {
    vec![
        "-v3".into(),
        "-l".into(),
        "noAuthNoPriv".into(),
        "-u".into(),
        "sadapp-discovery".into(),
        "-t".into(),
        "0.5".into(),
        "-r".into(),
        "0".into(),
        "-On".into(),
        "-Oqv".into(),
        snmp_transport_address(target, 161),
        OID_SNMP_SYS_OBJECT_ID.into(),
    ]
}

fn snmpv3_discovery_evidence(output: &CommandOutput) -> Option<Value> {
    const MAX_SNMP_DISCOVERY_OUTPUT_BYTES: usize = 1024;
    if output.stdout.len() + output.stderr.len() > MAX_SNMP_DISCOVERY_OUTPUT_BYTES {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let diagnostics = format!(
        "{} {}",
        stdout.to_ascii_lowercase(),
        String::from_utf8_lossy(&output.stderr).to_ascii_lowercase()
    );
    let auth_required = [
        "unknown username",
        "unknown user name",
        "authorizationerror",
        "authenticationfailure",
        "usmstatsunknownusernames",
        "usmstatswrongdigests",
    ]
    .iter()
    .any(|marker| diagnostics.contains(marker));
    if auth_required {
        return Some(json!({
            "transport": "udp",
            "port": 161,
            "protocol": "snmpv3",
            "state": "authentication-required",
            "authentication": "required",
        }));
    }
    if !output.success {
        return None;
    }
    let sys_object_id = stdout.trim_start_matches('.').trim().to_owned();
    Some(json!({
        "transport": "udp",
        "port": 161,
        "protocol": "snmpv3",
        "state": "responded",
        "authentication": "noAuthNoPriv",
        "sysObjectId": numeric_oid(&sys_object_id).then_some(sys_object_id),
    }))
}

async fn probe_snmpv3_service(context: &TaskContext, target: IpAddr) -> Option<Value> {
    let args = snmpv3_discovery_args(target);
    let output = timeout(
        SNMP_DISCOVERY_TIMEOUT,
        context.command_executor.run_with_stderr("snmpget", &args),
    )
    .await
    .ok()?
    .ok()?;
    snmpv3_discovery_evidence(&output)
}

async fn discover(context: &TaskContext, payload: &Map<String, Value>) -> TaskOutcome {
    let cidr = text(payload, "cidr")?
        .parse::<IpNet>()
        .map_err(|_| TaskError::invalid("cidr is invalid"))?;
    let ports = ports(payload.get("ports"))?;
    let concurrency = payload
        .get("concurrency")
        .and_then(Value::as_u64)
        .unwrap_or(16)
        .clamp(1, MAX_PROBE_CONCURRENCY as u64) as usize;
    let probe_timeout = task_timeout(payload);
    let policy = context
        .config
        .read()
        .await
        .policy()
        .map_err(TaskError::internal)?;
    policy
        .validate_discovery_cidr(cidr)
        .map_err(|error| TaskError::policy(error.to_string()))?;
    let addresses = addresses(cidr)?;
    let http_client = reqwest::Client::builder()
        .redirect(Policy::none())
        .timeout(probe_timeout.min(Duration::from_secs(2)))
        .build()
        .map_err(TaskError::internal)?;
    tracing::info!(cidr = %cidr, hosts = addresses.len(), port_count = ports.len(), concurrency, timeout_ms = probe_timeout.as_millis(), "local network discovery started");
    let mut candidates = stream::iter(addresses)
        .map(|address| {
            let ports = ports.clone();
            let http_client = http_client.clone();
            async move {
                let mut open_ports = stream::iter(ports)
                    .map(|port| async move {
                        timeout(
                            probe_timeout,
                            TcpStream::connect(SocketAddr::new(address, port)),
                        )
                        .await
                        .is_ok_and(|result| result.is_ok())
                        .then_some(port)
                    })
                    .buffer_unordered(MAX_DISCOVERY_PORT_CONCURRENCY)
                    .filter_map(async move |port| port)
                    .collect::<Vec<_>>()
                    .await;
                open_ports.sort_unstable();
                let snmp_response = probe_snmpv3_service(context, address).await;
                if open_ports.is_empty() && snmp_response.is_none() {
                    return None;
                }
                let observed_at = chrono::Utc::now().to_rfc3339();
                let http_responses = stream::iter(
                    open_ports
                        .iter()
                        .copied()
                        .filter(|port| HTTP_DISCOVERY_PORTS.contains(port)),
                )
                .map(|port| probe_http_service(&http_client, address, port))
                .buffer_unordered(MAX_HTTP_DISCOVERY_CONCURRENCY)
                .filter_map(async move |result| result)
                .collect::<Vec<_>>()
                .await;
                let mut probe_names = vec!["tcp-connect"];
                for response in &http_responses {
                    let name = if response["method"] == "OPTIONS" {
                        "http-options"
                    } else {
                        "http-head"
                    };
                    if !probe_names.contains(&name) {
                        probe_names.push(name);
                    }
                }
                if snmp_response.is_some() {
                    probe_names.push("snmpv3-noAuthNoPriv");
                }
                let mut candidate = json!({
                    "address": address.to_string(),
                    "kind": "network_host",
                    "evidence": tcp_discovery_evidence(&open_ports, &observed_at),
                });
                candidate["evidence"]["probes"] = json!(probe_names);
                candidate["evidence"]["httpResponses"] = json!(http_responses);
                if let Some(snmp_response) = snmp_response {
                    candidate["evidence"]["snmpResponses"] = json!([snmp_response]);
                }
                if let Some(hostname) = reverse_dns_hostname(address).await {
                    candidate["hostname"] = json!(hostname);
                }
                Some(candidate)
            }
        })
        .buffer_unordered(concurrency)
        .filter_map(async move |candidate| candidate)
        .collect::<Vec<_>>()
        .await;
    let multicast_candidates = discover_multicast(cidr, Duration::from_millis(1_200)).await;
    let multicast_count = multicast_candidates.len();
    for candidate in multicast_candidates {
        merge_discovery_candidate(&mut candidates, candidate);
    }
    for batch in candidates.chunks(250) {
        context
            .api
            .submit_candidates(&context.credentials, batch)
            .await
            .map_err(TaskError::internal)?;
    }
    tracing::info!(cidr = %cidr, scanned_hosts = addresses_len(cidr), candidates_submitted = candidates.len(), multicast_candidates = multicast_count, "local network discovery completed");
    Ok(json_object(
        json!({"scannedHosts": addresses_len(cidr), "candidatesSubmitted": candidates.len(), "multicastCandidates": multicast_count}),
    ))
}

async fn run_check(context: &TaskContext, payload: &Map<String, Value>) -> TaskOutcome {
    match text(payload, "checkType")?.to_ascii_uppercase().as_str() {
        "TCP" => tcp_check(context, payload).await,
        "HTTP" | "HTTPS" => http_check(context, payload).await,
        "ICMP" => icmp_check(context, payload).await,
        _ => Err(TaskError::unsupported(
            "UNSUPPORTED_CHECK_TYPE",
            "supported check types are ICMP, TCP, HTTP, and HTTPS",
        )),
    }
}

async fn icmp_check(context: &TaskContext, payload: &Map<String, Value>) -> TaskOutcome {
    let target = text(payload, "target")?
        .parse::<IpAddr>()
        .map_err(|_| TaskError::invalid("ICMP target must be an IP address"))?;
    let policy = context
        .config
        .read()
        .await
        .policy()
        .map_err(TaskError::internal)?;
    policy
        .validate_target(target)
        .map_err(|error| TaskError::policy(error.to_string()))?;

    let started = Instant::now();
    let duration = task_timeout(payload);
    let timeout_secs = duration
        .as_secs()
        .saturating_add(u64::from(duration.subsec_nanos() > 0))
        .max(1);
    let args = icmp_command_args(target, timeout_secs);
    let output = timeout(duration, context.command_executor.run("ping", &args))
        .await
        .map_err(|_| TaskError::failed("ICMP_TIMEOUT", "ICMP check timed out"))?
        .map_err(|_| {
            TaskError::failed("ICMP_EXEC_FAILED", "ping is unavailable or could not start")
        })?;
    if !output.success {
        let output_text = format!(
            "{} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .to_ascii_lowercase();
        if [
            "administratively prohibited",
            "administratively-prohibited",
            "administrative prohibited",
            "admin prohibited",
            "prohibited by administrative policy",
        ]
        .iter()
        .any(|phrase| output_text.contains(phrase))
        {
            return Err(TaskError::failed(
                "ICMP_POLICY_BLOCKED",
                "ICMP echo was administratively prohibited; target reachability is unknown",
            ));
        }
        return Err(TaskError::failed(
            "ICMP_ECHO_FAILED",
            "ping did not receive a reply",
        ));
    }

    Ok(json_object(
        json!({"success": true, "target": target.to_string(), "latencyMs": started.elapsed().as_secs_f64() * 1000.0}),
    ))
}

fn icmp_command_args(target: IpAddr, timeout_secs: u64) -> Vec<String> {
    let family_flag = if target.is_ipv6() { "-6" } else { "-4" };
    vec![
        family_flag.into(),
        "-c".into(),
        "1".into(),
        "-W".into(),
        timeout_secs.to_string(),
        "--".into(),
        target.to_string(),
    ]
}

async fn collect_snmp(context: &TaskContext, task: &TaskLease) -> TaskOutcome {
    let started = Instant::now();
    let payload = &task.payload;
    let target = text(payload, "target")?
        .parse::<IpAddr>()
        .map_err(|_| TaskError::invalid("SNMP target must be an IP address"))?;
    context
        .config
        .read()
        .await
        .policy()
        .map_err(TaskError::internal)?
        .validate_target(target)
        .map_err(|error| TaskError::policy(error.to_string()))?;
    let port = bounded_u64(payload.get("port"), 1, u16::MAX as u64, "port")? as u16;
    let timeout_ms = bounded_u64(payload.get("timeoutMs"), 100, 10_000, "timeoutMs")?;
    let retries = bounded_u64(payload.get("retries"), 0, 3, "retries")?;
    let verify_only = payload.get("verifyOnly").and_then(Value::as_bool) == Some(true);
    let discovery_only = payload.get("discoveryOnly").and_then(Value::as_bool) == Some(true);
    if discovery_only && (verify_only || text(payload, "discoveryToken")?.len() > 128) {
        return Err(TaskError::invalid(
            "discoveryOnly requires a separate bounded discovery token",
        ));
    }
    let table_plans: Vec<TablePlan> = if verify_only {
        Vec::new()
    } else {
        payload
            .get("tablePlans")
            .map(|value| serde_json::from_value(value.clone()))
            .transpose()
            .map_err(|_| TaskError::invalid("tablePlans are invalid"))?
            .unwrap_or_default()
    };
    validate_plans(&table_plans)
        .map_err(|_| TaskError::invalid("tablePlans exceed supported collection bounds"))?;
    let poll_plan = if verify_only {
        text(payload, "verificationServerId")?;
        text(payload, "verificationToken")?;
        vec![SnmpPollEntry {
            oid: OID_SNMP_SYS_OBJECT_ID.into(),
            metric_key: "snmp.sys_object_id".into(),
            unit: None,
            scale: 1.0,
            value_type: "GAUGE".into(),
            required: false,
            labels: None,
            transform: None,
        }]
    } else {
        snmp_poll_plan(payload.get("pollPlan"))?
    };
    let profile_metadata = if verify_only {
        None
    } else {
        let profile = payload
            .get("profile")
            .and_then(Value::as_object)
            .ok_or_else(|| TaskError::invalid("profile is required"))?;
        let name = text(profile, "name")?.to_owned();
        let version = bounded_u64(
            profile.get("version"),
            1,
            u32::MAX as u64,
            "profile.version",
        )?;
        let checksum = text(profile, "checksum")?.to_owned();
        if checksum.len() != 64 || !checksum.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(TaskError::invalid("profile.checksum must be SHA-256 hex"));
        }
        Some((name, version, checksum))
    };
    let detection_context = if verify_only || payload.get("detectionBundle").is_none() {
        None
    } else {
        let configured_profile = payload
            .get("configuredProfile")
            .and_then(Value::as_str)
            .unwrap_or("auto");
        Some((
            configured_profile.to_owned(),
            snmp_detection_bundle(payload.get("detectionBundle"))?,
        ))
    };
    let detection_outcome =
        if let Some((configured_profile, bundle)) = detection_context.as_ref() {
            let identity_plan = [
                SnmpPollEntry {
                    oid: OID_SNMP_SYS_OBJECT_ID.into(),
                    metric_key: "snmp.sys_object_id".into(),
                    unit: None,
                    scale: 1.0,
                    value_type: "GAUGE".into(),
                    required: false,
                    labels: None,
                    transform: None,
                },
                SnmpPollEntry {
                    oid: OID_SNMP_SYS_DESCR.into(),
                    metric_key: "snmp.sys_descr".into(),
                    unit: None,
                    scale: 1.0,
                    value_type: "GAUGE".into(),
                    required: false,
                    labels: None,
                    transform: None,
                },
            ];
            let identity_args = snmp_arguments(
                payload,
                &task.secrets,
                target,
                port,
                1_000,
                0,
                &identity_plan,
            )?;
            let identity_output = timeout(
                Duration::from_secs(3),
                context.command_executor.run("snmpget", &identity_args),
            )
            .await;
            match identity_output {
                Ok(Ok(output)) if output.success => parse_snmp_identity_probe(&output.stdout)
                    .ok()
                    .map(|identity| {
                        detect_snmp_profiles(
                            configured_profile,
                            &bundle.profiles,
                            &identity,
                            &bundle.checksum,
                        )
                    }),
                Ok(Ok(_)) => None,
                Ok(Err(_)) | Err(_) => None,
            }
        } else {
            None
        };
    let args = snmp_arguments(
        payload,
        &task.secrets,
        target,
        port,
        timeout_ms,
        retries,
        &poll_plan,
    )?;
    let total_timeout =
        Duration::from_millis(timeout_ms.saturating_mul(retries + 1).saturating_add(2_000))
            .min(MAX_SNMP_COMMAND_TIMEOUT);
    let output = timeout(
        total_timeout,
        context.command_executor.run("snmpget", &args),
    )
    .await
    .map_err(|_| TaskError::failed("SNMP_TIMEOUT", "SNMP command timed out"))?
    .map_err(|_| {
        TaskError::failed(
            "SNMP_EXEC_FAILED",
            "snmpget is unavailable or could not start",
        )
    })?;
    if !output.success {
        return Err(classify_snmp_command_failure(&output));
    }
    if verify_only {
        let sys_object_id = parse_snmp_identity_output(&output.stdout)?;
        return Ok(json_object(json!({
            "verified": true,
            "sysObjectId": sys_object_id,
            "latencyMs": started.elapsed().as_secs_f64() * 1000.0,
        })));
    }
    let raw_values = parse_snmp_output(&output.stdout, &poll_plan)?;
    let values = transform_snmp_values(&poll_plan, &raw_values);
    let uptime_seconds = poll_plan
        .iter()
        .zip(&raw_values)
        .find_map(|(entry, value)| {
            (entry.oid.trim_start_matches('.') == "1.3.6.1.2.1.1.3.0")
                .then_some(*value)
                .flatten()
                .map(|value| value / 100.0)
        });
    let mut group_counts =
        std::collections::BTreeMap::<&'static str, (usize, usize, Vec<Value>)>::new();
    let mut missing_metrics = Vec::new();
    for (entry, value) in poll_plan.iter().zip(&values) {
        let available = value.is_some();
        let group = metric_capability_group(&entry.metric_key);
        let counts = group_counts.entry(group).or_default();
        counts.0 += 1;
        if available {
            counts.1 += 1;
        } else {
            let missing = json!({ "metricKey": entry.metric_key, "oid": entry.oid, "required": entry.required });
            counts.2.push(missing.clone());
            missing_metrics.push(missing);
        }
    }
    let capability_groups = group_counts
        .into_iter()
        .map(|(name, (requested, available, missing))| {
            json!({
                "name": name,
                "requested": requested,
                "available": available,
                "status": if missing.is_empty() { "complete" } else if available > 0 { "partial" } else { "unavailable" },
            })
        })
        .collect::<Vec<_>>();
    let (profile_name, profile_version, profile_checksum) =
        profile_metadata.ok_or_else(|| TaskError::internal("SNMP profile metadata is missing"))?;
    let observed_at = chrono::Utc::now().to_rfc3339();
    let resource = payload
        .get("resource")
        .and_then(Value::as_object)
        .cloned()
        .ok_or_else(|| TaskError::invalid("resource is required"))?;
    let collector = payload
        .get("collector")
        .and_then(Value::as_object)
        .cloned()
        .ok_or_else(|| TaskError::invalid("collector is required"))?;
    let samples = poll_plan
        .iter()
        .zip(values)
        .filter_map(|(entry, value)| {
            let value = value?;
            let mut sample = json!({
                "resource": resource,
                "collector": collector,
                "metricKey": entry.metric_key,
                "unit": entry.unit,
                "valueType": entry.value_type,
                "observedAt": observed_at,
                "value": value,
                "quality": "GOOD",
                "metadata": { "oid": entry.oid, "profile": profile_name },
            });
            if let Some(labels) = &entry.labels {
                sample["labels"] = Value::Object(labels.clone());
            }
            Some(sample)
        })
        .collect::<Vec<_>>();
    let mut samples = samples;
    let mut capability_recorder = CapabilityRecorder::new();
    let raw_lines = std::str::from_utf8(&output.stdout)
        .unwrap_or_default()
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect::<Vec<_>>();
    for ((entry, value), raw) in poll_plan.iter().zip(&raw_values).zip(raw_lines) {
        capability_recorder.record_column(
            scalar_group(&entry.metric_key),
            &entry.oid,
            if value.is_some() {
                vec!["0"]
            } else {
                Vec::new()
            },
            if value.is_some() {
                ColumnResult::Rows { code: None }
            } else if parse_snmp_number(raw).is_err_and(|error| error.code == "SNMP_NO_SUCH_OID") {
                ColumnResult::Empty
            } else {
                ColumnResult::Failed("SNMP_INVALID_VALUE".into())
            },
        );
    }
    let host_resources = poll_snmp_host_resources(
        context,
        task,
        target,
        port,
        timeout_ms,
        retries,
        uptime_seconds,
    )
    .await;
    let (standard, standard_issues) = poll_snmp_standard_tables(
        context,
        task,
        target,
        port,
        (timeout_ms, retries),
        uptime_seconds,
        &host_resources.columns,
        &mut capability_recorder,
    )
    .await;
    let mut collection_issues = host_resources.collection_issues;
    collection_issues.extend(standard_issues);
    let (profile_tables, profile_issues) = poll_snmp_profile_tables(
        context,
        task,
        target,
        port,
        (timeout_ms, retries),
        uptime_seconds,
        &table_plans,
        &mut capability_recorder,
    )
    .await;
    collection_issues.extend(profile_issues);
    let mut supplemental_samples = Vec::new();
    for metric in &standard.metrics {
        let sample = json!({
            "resource": resource, "collector": collector, "metricKey": metric.metric_key,
            "unit": metric.unit, "valueType": metric.value_type, "observedAt": observed_at,
            "value": metric.value, "labels": metric.labels, "quality": "GOOD",
            "metadata": { "source": "SNMP-standard-tables", "legacyProjection": metric.name.starts_with("sensor.") },
        });
        if !metric.name.starts_with("sensor.") {
            supplemental_samples.push(sample);
        } else {
            samples.push(sample);
        }
    }
    for metric in &profile_tables.metrics {
        supplemental_samples.push(json!({
            "resource": resource, "collector": collector, "metricKey": metric.metric_key,
            "unit": metric.unit, "valueType": metric.value_type, "observedAt": observed_at,
            "value": metric.value, "labels": metric.labels, "quality": "GOOD",
            "metadata": { "source": "SNMP-profile-tables", "legacyProjection": false },
        }));
    }
    let aggregate_keys = [
        (
            "interface.in_octets",
            "network.receive.bytes_total",
            "bytes",
            "COUNTER",
        ),
        (
            "interface.out_octets",
            "network.transmit.bytes_total",
            "bytes",
            "COUNTER",
        ),
        (
            "interface.in_errors",
            "network.interface.receive.errors_total",
            "count",
            "COUNTER",
        ),
        (
            "interface.out_errors",
            "network.interface.transmit.errors_total",
            "count",
            "COUNTER",
        ),
    ];
    for (name, key, unit, value_type) in aggregate_keys {
        let metrics = standard
            .metrics
            .iter()
            .filter(|metric| metric.name == name)
            .collect::<Vec<_>>();
        if !metrics.is_empty() {
            let value: f64 = metrics.iter().map(|metric| metric.value).sum();
            if value.is_finite() {
                samples.push(json!({ "resource": resource, "collector": collector, "metricKey": key, "unit": unit, "valueType": value_type, "observedAt": observed_at, "value": value, "metadata": { "source": "SNMP-standard-tables" } }));
            }
        }
    }
    let statuses = standard
        .metrics
        .iter()
        .filter(|metric| metric.name == "interface.oper_status")
        .collect::<Vec<_>>();
    if !statuses.is_empty() {
        for (key, value) in [
            (
                "network.interface.up_count",
                statuses.iter().filter(|metric| metric.value == 1.0).count(),
            ),
            (
                "network.interface.down_count",
                statuses.iter().filter(|metric| metric.value != 1.0).count(),
            ),
        ] {
            samples.push(json!({ "resource": resource, "collector": collector, "metricKey": key, "unit": "count", "valueType": "GAUGE", "observedAt": observed_at, "value": value, "metadata": { "source": "SNMP-standard-tables" } }));
        }
    }
    let has_metric = |samples: &[Value], keys: &[&str]| {
        samples.iter().any(|sample| {
            sample
                .get("metricKey")
                .and_then(Value::as_str)
                .is_some_and(|key| keys.contains(&key))
        })
    };
    let mut derived = Vec::new();
    if let Some((disk_used, disk_total)) = host_resources.disk {
        let labels = json!({ "device": "snmp-fixed-disks" });
        derived.push((
            "filesystem.used_bytes",
            "bytes",
            disk_used,
            Some(labels.clone()),
        ));
        derived.push(("filesystem.total_bytes", "bytes", disk_total, Some(labels)));
    }
    if let Some((memory_used, memory_total)) = host_resources.memory {
        if !has_metric(
            &samples,
            &["system.memory.used_bytes", "system.memory.available_bytes"],
        ) {
            derived.push(("system.memory.used_bytes", "bytes", memory_used, None));
        }
        if !has_metric(
            &samples,
            &["system.memory.total_bytes", "system.memory.ucd_total_bytes"],
        ) {
            derived.push(("system.memory.total_bytes", "bytes", memory_total, None));
        }
    }
    if let Some(cpu) = host_resources.cpu_utilization {
        if !has_metric(
            &samples,
            &["system.cpu.utilization", "system.cpu.idle_percent"],
        ) {
            derived.push(("system.cpu.utilization", "percent", cpu, None));
        }
    }
    for (metric_key, unit, value, labels) in derived {
        let mut sample = json!({
            "resource": resource,
            "collector": collector,
            "metricKey": metric_key,
            "unit": unit,
            "valueType": "GAUGE",
            "observedAt": observed_at,
            "value": value,
            "quality": "GOOD",
            "metadata": { "source": "HOST-RESOURCES-MIB" },
        });
        if let Some(labels) = labels {
            sample["labels"] = labels;
        }
        samples.push(sample);
    }
    let capability_report = capability_recorder.finish(&profile_checksum, &observed_at);
    if discovery_only {
        return Ok(json_object(json!({
            "success": true, "discoveryOnly": true, "capabilityReport": capability_report,
            "latencyMs": started.elapsed().as_secs_f64() * 1000.0,
            "profile": { "name": profile_name, "version": profile_version, "checksum": profile_checksum },
            "detectionStatus": if payload.get("detectionBundle").is_some() {
                if detection_outcome.is_some() { "completed" } else { "unavailable" }
            } else { "not_due" },
            "detection": detection_outcome,
        })));
    }
    if samples.is_empty() && supplemental_samples.is_empty() {
        return Err(TaskError::failed(
            "SNMP_NO_METRICS",
            "SNMP returned no usable profile metrics",
        ));
    }
    samples.extend(supplemental_samples);
    let mut inventory = Vec::new();
    for (category, entries) in [
        (
            "snmp.standard",
            serde_json::to_value(&standard.inventory).map_err(TaskError::internal)?,
        ),
        (
            "snmp.profile",
            serde_json::to_value(&profile_tables.inventory).map_err(TaskError::internal)?,
        ),
    ] {
        if entries.as_array().is_none_or(Vec::is_empty) {
            continue;
        }
        use sha2::{Digest, Sha256};
        let payload = json!({ "entries": entries });
        let checksum = Sha256::digest(serde_json::to_vec(&payload).map_err(TaskError::internal)?)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        inventory.push(json!({
            "resource": resource, "collector": collector, "category": category,
            "schemaVersion": 1, "checksum": checksum, "payload": payload, "observedAt": observed_at,
        }));
    }
    for (index, chunk) in samples.chunks(500 - inventory.len()).enumerate() {
        context.telemetry_spool.push(&json!({
            "idempotencyKey": if index == 0 { format!("task:{}", task.id) } else { format!("task:{}:{index}", task.id) },
            "samples": chunk, "inventory": if index == 0 { inventory.clone() } else { Vec::new() },
        })).map_err(TaskError::internal)?;
    }
    collection_issues.sort_by_key(|issue| {
        (
            issue["code"] == "SNMP_UNSUPPORTED",
            issue["group"].as_str().unwrap_or("").to_owned(),
            issue["oid"].as_str().unwrap_or("").to_owned(),
            issue["code"].as_str().unwrap_or("").to_owned(),
        )
    });
    collection_issues.dedup();
    collection_issues.truncate(256);
    Ok(json_object(json!({
        "success": true,
        "latencyMs": started.elapsed().as_secs_f64() * 1000.0,
        "sampleCount": samples.len(),
        "partial": !missing_metrics.is_empty() || collection_issues.iter().any(|issue| issue["code"] != "SNMP_UNSUPPORTED"),
        "missingMetrics": missing_metrics,
        "capabilityGroups": capability_groups,
        "capabilityReport": capability_report,
        "collectionIssues": collection_issues,
        "detectionStatus": if payload.get("detectionBundle").is_some() {
            if detection_outcome.is_some() { "completed" } else { "unavailable" }
        } else {
            "not_due"
        },
        "detection": detection_outcome,
        "profile": { "name": profile_name, "version": profile_version, "checksum": profile_checksum }
    })))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SnmpDetectionBundle {
    schema_version: u32,
    checksum: String,
    profiles: Vec<DetectionProfile>,
}

fn snmp_detection_bundle(value: Option<&Value>) -> Result<SnmpDetectionBundle, TaskError> {
    let bundle: SnmpDetectionBundle = serde_json::from_value(
        value
            .cloned()
            .ok_or_else(|| TaskError::invalid("detectionBundle is required"))?,
    )
    .map_err(|_| TaskError::invalid("detectionBundle has an invalid shape"))?;
    if bundle.schema_version != 1 || bundle.profiles.is_empty() || bundle.profiles.len() > 64 {
        return Err(TaskError::invalid(
            "detectionBundle version or profile count is invalid",
        ));
    }
    let mut names = std::collections::BTreeSet::new();
    for profile in &bundle.profiles {
        if profile.profile_name.is_empty()
            || profile.profile_name.len() > 64
            || !profile
                .profile_name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            || profile.schema_version == 0
            || profile.schema_version > 1_000
            || !profile.detection.minimum_confidence.is_finite()
            || !(0.0..=1.0).contains(&profile.detection.minimum_confidence)
            || !(-100_000..=100_000).contains(&profile.detection.priority)
            || profile.detection.sys_object_id_prefixes.len() > 64
            || profile.detection.sys_descr_regexes.len() > 64
            || profile.detection.required_oids.len() > 64
            || profile.detection.optional_oids.len() > 64
            || profile
                .detection
                .sys_descr_regexes
                .iter()
                .any(|pattern| pattern.is_empty() || pattern.len() > 512)
            || profile
                .detection
                .sys_object_id_prefixes
                .iter()
                .chain(&profile.detection.required_oids)
                .chain(&profile.detection.optional_oids)
                .any(|oid| oid.len() > 255 || !numeric_oid(oid))
            || !names.insert(profile.profile_name.as_str())
        {
            return Err(TaskError::invalid(
                "detectionBundle contains invalid profile metadata",
            ));
        }
    }
    if bundle.checksum.len() != 64 || !bundle.checksum.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(TaskError::invalid("detectionBundle checksum is invalid"));
    }
    let checksum = detection_bundle_checksum(&bundle.profiles).map_err(TaskError::internal)?;
    if !checksum.eq_ignore_ascii_case(&bundle.checksum) {
        return Err(TaskError::invalid(
            "detectionBundle checksum does not match its profiles",
        ));
    }
    Ok(bundle)
}

fn parse_snmp_identity_probe(stdout: &[u8]) -> Result<IdentityProbe, TaskError> {
    if stdout.is_empty() || stdout.len() > 2_048 {
        return Err(TaskError::failed(
            "SNMP_IDENTITY_INVALID",
            "SNMP identity response was empty or oversized",
        ));
    }
    let output = std::str::from_utf8(stdout)
        .map_err(|_| TaskError::failed("SNMP_PARSE_FAILED", "SNMP identity was not UTF-8"))?;
    let lines = output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    if lines.len() != 2 {
        return Err(TaskError::failed(
            "SNMP_IDENTITY_INVALID",
            "SNMP identity response did not contain both standard identity scalars",
        ));
    }
    let sys_object_id = if lines[0].to_ascii_lowercase().contains("no such") {
        None
    } else {
        parse_snmp_identity_output(lines[0].as_bytes()).ok()
    };
    let sys_descr = if lines[1].to_ascii_lowercase().contains("no such") || lines[1].len() > 1_024 {
        None
    } else {
        let description = lines[1].trim_matches('"').trim();
        (!description.is_empty() && !description.chars().any(char::is_control))
            .then(|| description.to_owned())
    };
    let mut responsive_oids = std::collections::BTreeSet::new();
    if sys_object_id.is_some() {
        responsive_oids.insert(OID_SNMP_SYS_OBJECT_ID.to_owned());
    }
    Ok(IdentityProbe {
        sys_object_id,
        sys_descr,
        responsive_oids,
        ..IdentityProbe::default()
    })
}

#[derive(Debug, Default, PartialEq)]
struct HostResourceUsage {
    disk: Option<(f64, f64)>,
    memory: Option<(f64, f64)>,
    cpu_utilization: Option<f64>,
    collection_issues: Vec<Value>,
    columns: StandardColumns,
}

type StorageMetadata = (
    std::collections::HashMap<u32, String>,
    std::collections::HashMap<u32, String>,
);
static STORAGE_DISCOVERY: OnceLock<Mutex<DiscoveryCache<StorageMetadata>>> = OnceLock::new();
type StandardMetadata = (StandardColumns, Vec<Value>);
static STANDARD_DISCOVERY: OnceLock<Mutex<DiscoveryCache<StandardMetadata>>> = OnceLock::new();
type ProfileTableCache = DiscoveryCache<ProfileColumns, (String, String, String)>;
static PROFILE_TABLE_DISCOVERY: OnceLock<Mutex<ProfileTableCache>> = OnceLock::new();

#[allow(clippy::too_many_arguments)]
async fn poll_snmp_profile_tables(
    context: &TaskContext,
    task: &TaskLease,
    target: IpAddr,
    port: u16,
    request: (u64, u64),
    uptime_seconds: Option<f64>,
    plans: &[TablePlan],
    capability_recorder: &mut CapabilityRecorder,
) -> (ProfileSnapshot, Vec<Value>) {
    let deadline = tokio::time::Instant::now() + STANDARD_GROUP_TIMEOUT;
    let collect = |metadata| {
        let mut requested = Vec::new();
        for plan in plans {
            for column in &plan.columns {
                if (column.value_type == "STRING") == metadata {
                    requested.push((plan.clone(), column.clone()));
                }
            }
        }
        let mut pending = Vec::new();
        for (plan, column) in requested {
            pending.push(async move {
                let oid = format!("{}.{}", plan.base_oid, column.oid_suffix);
                let result = snmp_walk_partial_until(
                    context,
                    task,
                    target,
                    port,
                    request,
                    &oid,
                    Some(deadline),
                    plan.max_rows as usize,
                )
                .await;
                (plan, column, oid, result)
            });
        }
        stream::iter(pending).buffer_unordered(STANDARD_MAX_PARALLEL)
    };
    let mut columns = ProfileColumns::new();
    let mut issues = Vec::new();
    let mut retained_bytes = 0usize;
    for metadata in [false, true] {
        let indices = columns
            .iter()
            .flat_map(|(table, values)| {
                values.iter().flat_map(move |(column, rows)| {
                    rows.keys()
                        .map(move |index| (table.clone(), column.clone(), index.clone()))
                })
            })
            .collect();
        let mut auth_identity = task
            .secrets
            .iter()
            .map(|(key, value)| format!("{key}:{value}"))
            .collect::<Vec<_>>();
        auth_identity.sort();
        auth_identity.push(
            task.payload
                .get("auth")
                .map(Value::to_string)
                .unwrap_or_default(),
        );
        let identity = plans
            .iter()
            .map(|plan| format!("{plan:?}"))
            .collect::<Vec<_>>()
            .join(";");
        let key = DiscoveryKey::new(
            task.payload
                .get("serverId")
                .and_then(Value::as_str)
                .unwrap_or(""),
            &snmp_transport_address(target, port),
            &identity,
            task.payload
                .get("version")
                .and_then(Value::as_str)
                .unwrap_or("2c"),
            &auth_identity,
        );
        let cache =
            PROFILE_TABLE_DISCOVERY.get_or_init(|| Mutex::new(DiscoveryCache::with_capacity(128)));
        if metadata && task.payload.get("discoveryOnly").and_then(Value::as_bool) != Some(true) {
            let cached = cache
                .lock()
                .expect("SNMP profile discovery cache lock")
                .get(&key, uptime_seconds, &indices, Instant::now());
            if let Some(cached) = cached {
                for plan in plans {
                    for column in &plan.columns {
                        if let Some(rows) = cached
                            .get(&plan.name)
                            .and_then(|values| values.get(&column.name))
                        {
                            capability_recorder.record_column(
                                profile_column_group(plan, column),
                                &format!("{}.{}", plan.base_oid, column.oid_suffix),
                                rows.keys(),
                                ColumnResult::Rows { code: None },
                            );
                        }
                    }
                }
                for (table, metadata_columns) in cached {
                    columns.entry(table).or_default().extend(metadata_columns);
                }
                break;
            }
        }
        let mut discovered = ProfileColumns::new();
        let mut pending = collect(metadata);
        while let Some((plan, column, oid, result)) = pending.next().await {
            let (output, limit) = match result {
                Ok(output) => output,
                Err(error) => {
                    capability_recorder.record_column(
                        profile_column_group(&plan, &column),
                        &oid,
                        Vec::<String>::new(),
                        if error.code == "SNMP_UNSUPPORTED" {
                            ColumnResult::Empty
                        } else {
                            ColumnResult::Failed(error.code.to_string())
                        },
                    );
                    issues.push(json!({ "group": "vendor", "oid": oid, "code": error.code }));
                    continue;
                }
            };
            if let Some(limit) = limit {
                issues.push(
                    json!({ "group": "vendor", "oid": oid, "code": limit.diagnostic_code() }),
                );
            }
            let remaining = 1_048_576usize.saturating_sub(retained_bytes);
            let clipped = output.len() > remaining;
            let output = if output.len() > remaining {
                issues
                    .push(json!({ "group": "vendor", "oid": oid, "code": "SNMP_RESPONSE_LIMIT" }));
                let end = output
                    .as_bytes()
                    .iter()
                    .take(remaining)
                    .rposition(|byte| *byte == b'\n')
                    .map_or(0, |index| index + 1);
                &output[..end]
            } else {
                &output
            };
            retained_bytes = retained_bytes.saturating_add(output.len());
            let parsed = parse_profile_column(&plan, &column, output.as_bytes());
            capability_recorder.record_column(
                profile_column_group(&plan, &column),
                &oid,
                parsed.rows.keys(),
                if output.to_ascii_lowercase().contains("no such")
                    || output.to_ascii_lowercase().contains("no more variables")
                {
                    ColumnResult::Empty
                } else {
                    ColumnResult::Rows {
                        code: limit
                            .map(|value| value.diagnostic_code().to_owned())
                            .or_else(|| clipped.then(|| "SNMP_RESPONSE_LIMIT".to_owned()))
                            .or_else(|| parsed.issues.first().map(|issue| issue.code.clone())),
                    }
                },
            );
            for issue in parsed.issues {
                issues.push(json!({ "group": "vendor", "oid": oid, "code": issue.code }));
            }
            if metadata {
                discovered
                    .entry(plan.name.clone())
                    .or_default()
                    .insert(column.name.clone(), parsed.rows.clone());
            }
            columns
                .entry(plan.name.clone())
                .or_default()
                .insert(column.name.clone(), parsed.rows);
        }
        if metadata && issues.is_empty() {
            cache
                .lock()
                .expect("SNMP profile discovery cache lock")
                .insert(key, discovered, uptime_seconds, indices, Instant::now());
        }
    }
    let (snapshot, normalization_issues) = normalize_profile_tables(plans, &columns);
    for issue in normalization_issues {
        if let Some(plan) = plans.iter().find(|plan| plan.name == issue.table) {
            let oid = issue
                .column
                .as_ref()
                .and_then(|name| plan.columns.iter().find(|column| &column.name == name))
                .map(|column| format!("{}.{}", plan.base_oid, column.oid_suffix))
                .unwrap_or_else(|| plan.base_oid.clone());
            issues.push(json!({ "group": "vendor", "oid": oid, "code": issue.code }));
        }
    }
    (snapshot, issues)
}

#[allow(clippy::too_many_arguments)]
async fn poll_snmp_standard_tables(
    context: &TaskContext,
    task: &TaskLease,
    target: IpAddr,
    port: u16,
    request: (u64, u64),
    uptime_seconds: Option<f64>,
    seeded_columns: &StandardColumns,
    capability_recorder: &mut CapabilityRecorder,
) -> (StandardSnapshot, Vec<Value>) {
    let deadline = tokio::time::Instant::now() + STANDARD_GROUP_TIMEOUT;
    let collect = |metadata| async move {
        let mut pending = Vec::new();
        for spec in STANDARD_TABLES {
            if spec.metadata != metadata || seeded_columns.contains_key(spec.key) {
                continue;
            }
            pending.push(async move {
                let result = snmp_walk_values_partial_until(
                    context,
                    task,
                    target,
                    port,
                    request,
                    spec.oid,
                    Some(deadline),
                )
                .await;
                (spec, result)
            });
        }
        stream::iter(pending)
            .buffer_unordered(STANDARD_MAX_PARALLEL)
            .collect::<Vec<_>>()
            .await
    };
    let mut columns = seeded_columns.clone();
    let mut issues = Vec::new();
    for (spec, result) in collect(false).await {
        match result {
            Ok((values, limit)) => {
                columns.insert(spec.key.to_owned(), values.into_iter().collect());
                if let Some(limit) = limit {
                    issues.push(json!({ "group": "inventory", "oid": spec.oid, "code": limit.diagnostic_code() }));
                }
            }
            Err(error) => issues.push(json!({
                "group": if spec.key.starts_with("if.") { "interfaces" } else if spec.oid.starts_with("1.3.6.1.2.1.25.2.3.") { "storage" } else { "sensors" },
                "oid": spec.oid, "code": error.code,
            })),
        }
    }
    let indices = columns
        .values()
        .flat_map(|values| values.keys().copied())
        .collect();
    let index_identity = columns
        .iter()
        .map(|(key, values)| format!("{key}:{:?}", values.keys().collect::<Vec<_>>()))
        .collect::<Vec<_>>()
        .join(";");
    let mut auth_identity = task
        .secrets
        .iter()
        .map(|(key, value)| format!("{key}:{value}"))
        .collect::<Vec<_>>();
    auth_identity.sort();
    auth_identity.push(
        task.payload
            .get("auth")
            .map(Value::to_string)
            .unwrap_or_default(),
    );
    let key = DiscoveryKey::new(
        task.payload
            .get("serverId")
            .and_then(Value::as_str)
            .or_else(|| {
                task.payload
                    .get("resource")
                    .and_then(|resource| resource.get("externalKey"))
                    .and_then(Value::as_str)
            })
            .unwrap_or(""),
        &snmp_transport_address(target, port),
        &format!(
            "{}:{index_identity}",
            task.payload
                .get("profile")
                .map(Value::to_string)
                .unwrap_or_default()
        ),
        task.payload
            .get("version")
            .and_then(Value::as_str)
            .unwrap_or("2c"),
        &auth_identity,
    );
    let cache = STANDARD_DISCOVERY.get_or_init(|| Mutex::new(DiscoveryCache::with_capacity(128)));
    let cached = cache
        .lock()
        .expect("SNMP standard discovery cache lock")
        .get(&key, uptime_seconds, &indices, Instant::now())
        .filter(|_| task.payload.get("discoveryOnly").and_then(Value::as_bool) != Some(true));
    let (metadata, metadata_issues) = if let Some(value) = cached {
        value
    } else {
        let mut metadata = StandardColumns::new();
        let mut metadata_issues = Vec::new();
        for (spec, result) in collect(true).await {
            match result {
                Ok((values, limit)) => {
                    metadata.insert(spec.key.to_owned(), values.into_iter().collect());
                    if let Some(limit) = limit {
                        metadata_issues.push(json!({ "group": "inventory", "oid": spec.oid, "code": limit.diagnostic_code() }));
                    }
                }
                Err(error) => metadata_issues.push(json!({
                    "group": if spec.key.starts_with("if.") { "interfaces" } else if spec.key.starts_with("sensor.") { "sensors" } else if spec.oid.starts_with("1.3.6.1.2.1.25.2.3.") { "storage" } else { "inventory" },
                    "oid": spec.oid, "code": error.code,
                })),
            }
        }
        if metadata_issues
            .iter()
            .all(|issue| issue["code"] == "SNMP_UNSUPPORTED")
            && issues.is_empty()
        {
            cache
                .lock()
                .expect("SNMP standard discovery cache lock")
                .insert(
                    key,
                    (metadata.clone(), metadata_issues.clone()),
                    uptime_seconds,
                    indices,
                    Instant::now(),
                );
        }
        (metadata, metadata_issues)
    };
    for (key, values) in metadata {
        columns.entry(key).or_insert(values);
    }
    issues.extend(metadata_issues);
    for spec in STANDARD_TABLES {
        let code = issues
            .iter()
            .find(|issue| issue["oid"] == spec.oid)
            .and_then(|issue| issue["code"].as_str());
        match columns.get(spec.key) {
            Some(rows) => capability_recorder.record_column(
                standard_column_group(spec.key),
                spec.oid,
                rows.keys().map(u32::to_string),
                ColumnResult::Rows {
                    code: code.map(str::to_owned),
                },
            ),
            None => capability_recorder.record_column(
                standard_column_group(spec.key),
                spec.oid,
                Vec::<String>::new(),
                if code == Some("SNMP_UNSUPPORTED") {
                    ColumnResult::Empty
                } else {
                    ColumnResult::Failed(code.unwrap_or("SNMP_NOT_ATTEMPTED").to_owned())
                },
            ),
        }
    }
    let (snapshot, normalization_issues) = normalize_standard_tables_with_issues(&columns);
    for issue in normalization_issues {
        issues.push(json!({
            "group": if ["interfaces", "sensors", "inventory", "storage"].contains(&issue.table.as_str()) { issue.table.as_str() } else { "inventory" },
            "oid": issue.column.as_ref().and_then(|column| STANDARD_TABLES.iter().find(|spec| spec.key == column)).map_or("1.3.6.1.2.1", |spec| spec.oid),
            "code": issue.code,
        }));
    }
    (snapshot, issues)
}

async fn poll_snmp_host_resources(
    context: &TaskContext,
    task: &TaskLease,
    target: IpAddr,
    port: u16,
    timeout_ms: u64,
    retries: u64,
    uptime_seconds: Option<f64>,
) -> HostResourceUsage {
    let walk =
        |oid: &'static str| snmp_walk_values(context, task, target, port, timeout_ms, retries, oid);
    let (sizes, used, processor_load) = tokio::join!(
        walk(OID_HR_STORAGE_SIZE),
        walk(OID_HR_STORAGE_USED),
        walk(OID_HR_PROCESSOR_LOAD),
    );
    let indices = sizes
        .iter()
        .chain(used.iter())
        .flat_map(|values| values.keys().copied())
        .collect();
    let mut auth_identity = task
        .secrets
        .iter()
        .map(|(key, value)| format!("{key}:{value}"))
        .collect::<Vec<_>>();
    auth_identity.sort();
    auth_identity.push(
        task.payload
            .get("auth")
            .map(Value::to_string)
            .unwrap_or_default(),
    );
    let key = DiscoveryKey::new(
        task.payload
            .get("serverId")
            .and_then(Value::as_str)
            .or_else(|| {
                task.payload
                    .get("resource")
                    .and_then(|resource| resource.get("externalKey"))
                    .and_then(Value::as_str)
            })
            .unwrap_or(""),
        &snmp_transport_address(target, port),
        &task
            .payload
            .get("profile")
            .map(Value::to_string)
            .unwrap_or_default(),
        task.payload
            .get("version")
            .and_then(Value::as_str)
            .unwrap_or("2c"),
        &auth_identity,
    );
    let cache = STORAGE_DISCOVERY.get_or_init(|| Mutex::new(DiscoveryCache::default()));
    let cached = cache.lock().expect("SNMP discovery cache lock").get(
        &key,
        uptime_seconds,
        &indices,
        Instant::now(),
    );
    let (storage_types, allocation_units) = if let Some((types, units)) = cached {
        (Ok(types), Ok(units))
    } else {
        let (types, units) =
            tokio::join!(walk(OID_HR_STORAGE_TYPE), walk(OID_HR_STORAGE_ALLOC_UNITS));
        if let (Ok(types), Ok(units)) = (&types, &units) {
            if sizes.is_ok() && used.is_ok() {
                cache.lock().expect("SNMP discovery cache lock").insert(
                    key,
                    (types.clone(), units.clone()),
                    uptime_seconds,
                    indices,
                    Instant::now(),
                );
            }
        }
        (types, units)
    };
    let mut usage = HostResourceUsage {
        cpu_utilization: processor_load
            .as_ref()
            .ok()
            .and_then(average_processor_load),
        ..HostResourceUsage::default()
    };
    for (oid, result) in [
        (OID_HR_STORAGE_TYPE, &storage_types),
        (OID_HR_STORAGE_ALLOC_UNITS, &allocation_units),
        (OID_HR_STORAGE_SIZE, &sizes),
        (OID_HR_STORAGE_USED, &used),
        (OID_HR_PROCESSOR_LOAD, &processor_load),
    ] {
        if let (Ok(values), Some(spec)) =
            (result, STANDARD_TABLES.iter().find(|spec| spec.oid == oid))
        {
            usage.columns.insert(
                spec.key.to_owned(),
                values
                    .iter()
                    .map(|(index, value)| (*index, value.clone()))
                    .collect(),
            );
        }
        if let Err(error) = result {
            usage.collection_issues.push(json!({
                "group": if oid == OID_HR_PROCESSOR_LOAD { "cpu" } else { "storage" },
                "oid": oid,
                "code": error.code,
            }));
        }
    }
    if let (Ok(storage_types), Ok(allocation_units), Ok(sizes), Ok(used)) =
        (&storage_types, &allocation_units, &sizes, &used)
    {
        usage.disk = aggregate_storage_usage(
            storage_types,
            allocation_units,
            sizes,
            used,
            StorageKind::FixedDisk,
        );
        usage.memory = aggregate_storage_usage(
            storage_types,
            allocation_units,
            sizes,
            used,
            StorageKind::Ram,
        );
        for (kind, available, group) in [
            (StorageKind::FixedDisk, usage.disk.is_some(), "storage"),
            (StorageKind::Ram, usage.memory.is_some(), "memory"),
        ] {
            if !available && storage_types.values().any(|value| kind.matches(value)) {
                usage.collection_issues.push(json!({
                    "group": group, "oid": OID_HR_STORAGE_USED, "code": "SNMP_TABLE_INCOMPLETE",
                }));
            }
        }
    }
    usage
}

fn average_processor_load(loads: &std::collections::HashMap<u32, String>) -> Option<f64> {
    let values = loads
        .values()
        .filter_map(|value| parse_snmp_number(value).ok())
        .filter(|value| (0.0..=100.0).contains(value))
        .collect::<Vec<_>>();
    (!values.is_empty()).then(|| values.iter().sum::<f64>() / values.len() as f64)
}

#[derive(Clone, Copy)]
enum StorageKind {
    FixedDisk,
    Ram,
}

impl StorageKind {
    fn matches(self, storage_type: &str) -> bool {
        let (name, oid) = match self {
            Self::FixedDisk => ("hrstoragefixeddisk", OID_HR_STORAGE_TYPE_FIXED_DISK),
            Self::Ram => ("hrstorageram", OID_HR_STORAGE_TYPE_RAM),
        };
        let normalized = storage_type.trim().to_ascii_lowercase();
        normalized.ends_with(name) || normalized.ends_with(oid)
    }
}

fn aggregate_storage_usage(
    storage_types: &std::collections::HashMap<u32, String>,
    allocation_units: &std::collections::HashMap<u32, String>,
    sizes: &std::collections::HashMap<u32, String>,
    used: &std::collections::HashMap<u32, String>,
    kind: StorageKind,
) -> Option<(f64, f64)> {
    let numeric = |values: &std::collections::HashMap<u32, String>| {
        values
            .iter()
            .filter_map(|(index, value)| parse_snmp_number(value).ok().map(|value| (*index, value)))
            .collect()
    };
    aggregate_storage_kind(
        match kind {
            StorageKind::FixedDisk => "disk",
            StorageKind::Ram => "ram",
        },
        storage_types,
        &numeric(allocation_units),
        &numeric(sizes),
        &numeric(used),
    )
    .map(|(total, used)| (used, total))
}

async fn snmp_walk_values(
    context: &TaskContext,
    task: &TaskLease,
    target: IpAddr,
    port: u16,
    timeout_ms: u64,
    retries: u64,
    oid: &str,
) -> Result<std::collections::HashMap<u32, String>, TaskError> {
    snmp_walk_values_until(
        context,
        task,
        target,
        port,
        (timeout_ms, retries),
        oid,
        None,
    )
    .await
}

async fn snmp_walk_values_until(
    context: &TaskContext,
    task: &TaskLease,
    target: IpAddr,
    port: u16,
    request: (u64, u64),
    oid: &str,
    deadline: Option<tokio::time::Instant>,
) -> Result<std::collections::HashMap<u32, String>, TaskError> {
    let (values, limit) =
        snmp_walk_values_partial_until(context, task, target, port, request, oid, deadline).await?;
    if let Some(limit) = limit {
        return Err(TaskError::failed(
            limit.diagnostic_code(),
            limit.to_string(),
        ));
    }
    Ok(values)
}

async fn snmp_walk_values_partial_until(
    context: &TaskContext,
    task: &TaskLease,
    target: IpAddr,
    port: u16,
    request: (u64, u64),
    oid: &str,
    deadline: Option<tokio::time::Instant>,
) -> Result<
    (
        std::collections::HashMap<u32, String>,
        Option<TableWalkFailure>,
    ),
    TaskError,
> {
    let (output, limit) = snmp_walk_partial_until(
        context,
        task,
        target,
        port,
        request,
        oid,
        deadline,
        DEFAULT_TABLE_MAX_ROWS,
    )
    .await?;
    let values = parse_snmp_walk_values(&output, oid);
    if values.is_empty() {
        return Err(TaskError::failed(
            if output.to_ascii_lowercase().contains("no such")
                || output.to_ascii_lowercase().contains("no more variables")
            {
                "SNMP_UNSUPPORTED"
            } else {
                "SNMP_PARSE_FAILED"
            },
            "SNMP table returned no usable rows",
        ));
    }
    Ok((values, limit))
}

#[allow(clippy::too_many_arguments)]
async fn snmp_walk_partial_until(
    context: &TaskContext,
    task: &TaskLease,
    target: IpAddr,
    port: u16,
    request: (u64, u64),
    oid: &str,
    deadline: Option<tokio::time::Instant>,
    max_rows: usize,
) -> Result<(String, Option<TableWalkFailure>), TaskError> {
    let (timeout_ms, retries) = request;
    let mut args = snmp_arguments(
        &task.payload,
        &task.secrets,
        target,
        port,
        timeout_ms,
        retries,
        &[],
    )?;
    args.retain(|argument| argument != "-Oqv");
    args.push(oid.to_owned());
    let policy = TableWalkPolicy::new(
        task.payload
            .get("version")
            .and_then(Value::as_str)
            .unwrap_or("2c"),
        max_rows,
    );
    let deadline = deadline.unwrap_or_else(|| tokio::time::Instant::now() + policy.timeout);
    if tokio::time::Instant::now() >= deadline {
        return Err(TaskError::failed(
            "SNMP_TIMEOUT",
            "SNMP table group deadline expired",
        ));
    }
    let mut attempt = policy.initial();
    let output = loop {
        let attempt_args = attempt.args(&args);
        let result = context
            .command_executor
            .run_table_partial(attempt.program(), &attempt_args, policy, deadline)
            .await;
        let failure = match result {
            Ok(output) if output.success || output.limit.is_some() => break output,
            Ok(output) => classify_table_failure(&[output.stdout, output.stderr].concat()),
            Err(error) => error,
        };
        if let Some(next) = policy.retry_after(attempt, failure) {
            attempt = next;
        } else {
            return Err(TaskError::failed(
                failure.diagnostic_code(),
                failure.to_string(),
            ));
        }
    };
    let limit = output.limit;
    let output = std::str::from_utf8(&output.stdout)
        .map_err(|_| TaskError::failed("SNMP_PARSE_FAILED", "SNMP table was not UTF-8"))?;
    if output
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count()
        > max_rows
    {
        return Err(TaskError::failed(
            "SNMP_RESPONSE_LIMIT",
            "SNMP table exceeded row limit",
        ));
    }
    Ok((output.to_owned(), limit))
}

fn parse_snmp_walk_values(output: &str, oid: &str) -> std::collections::HashMap<u32, String> {
    let mut values = std::collections::HashMap::new();
    for line in output.lines().take(MAX_SNMP_STORAGE_ROWS) {
        let Some((row_oid, value)) = line.split_once(" = ") else {
            continue;
        };
        let normalized_oid = row_oid.trim().trim_start_matches('.');
        let root = format!("{}.", oid);
        let Some(suffix) = normalized_oid.strip_prefix(&root) else {
            continue;
        };
        let Ok(index) = suffix.parse::<u32>() else {
            continue;
        };
        values.insert(index, value.trim().chars().take(256).collect());
    }
    values
}

#[derive(Debug)]
struct SnmpPollEntry {
    oid: String,
    metric_key: String,
    unit: Option<String>,
    scale: f64,
    value_type: String,
    required: bool,
    labels: Option<Map<String, Value>>,
    transform: Option<Transform>,
}

fn snmp_poll_plan(value: Option<&Value>) -> Result<Vec<SnmpPollEntry>, TaskError> {
    let entries = value
        .and_then(Value::as_array)
        .ok_or_else(|| TaskError::invalid("pollPlan must be an array"))?;
    if entries.is_empty() || entries.len() > MAX_SNMP_OIDS {
        return Err(TaskError::invalid(format!(
            "pollPlan must contain 1-{MAX_SNMP_OIDS} entries"
        )));
    }
    entries
        .iter()
        .map(|value| {
            let entry = value
                .as_object()
                .ok_or_else(|| TaskError::invalid("pollPlan entry must be an object"))?;
            let oid = text(entry, "oid")?;
            if oid.len() > 255 || !numeric_oid(oid) {
                return Err(TaskError::invalid(
                    "pollPlan contains an invalid numeric OID",
                ));
            }
            let metric_key = text(entry, "metricKey")?;
            if metric_key.len() > 200 || !canonical_key(metric_key) {
                return Err(TaskError::invalid(
                    "pollPlan contains an invalid metric key",
                ));
            }
            let scale = entry
                .get("scale")
                .and_then(Value::as_f64)
                .ok_or_else(|| TaskError::invalid("pollPlan scale must be numeric"))?;
            if !scale.is_finite() || scale.abs() > 1_000_000_000.0 {
                return Err(TaskError::invalid("pollPlan scale is outside bounds"));
            }
            let value_type = text(entry, "valueType")?;
            if value_type != "GAUGE" && value_type != "COUNTER" {
                return Err(TaskError::invalid("pollPlan valueType is invalid"));
            }
            let required = entry
                .get("required")
                .map(|value| {
                    value
                        .as_bool()
                        .ok_or_else(|| TaskError::invalid("pollPlan required must be boolean"))
                })
                .transpose()?
                .unwrap_or(false);
            Ok(SnmpPollEntry {
                oid: oid.to_owned(),
                metric_key: metric_key.to_owned(),
                scale,
                unit: entry.get("unit").and_then(Value::as_str).map(str::to_owned),
                value_type: value_type.to_owned(),
                required,
                labels: entry.get("labels").and_then(Value::as_object).cloned(),
                transform: entry
                    .get("transform")
                    .filter(|value| !value.is_null())
                    .map(|value| {
                        serde_json::from_value(value.clone())
                            .map_err(|_| TaskError::invalid("pollPlan transform is invalid"))
                    })
                    .transpose()?,
            })
        })
        .collect()
}

fn snmp_transport_address(target: IpAddr, port: u16) -> String {
    match target {
        IpAddr::V4(address) => format!("{address}:{port}"),
        IpAddr::V6(address) => format!("udp6:[{address}]:{port}"),
    }
}

fn snmp_arguments(
    payload: &Map<String, Value>,
    secrets: &std::collections::HashMap<String, String>,
    target: IpAddr,
    port: u16,
    timeout_ms: u64,
    retries: u64,
    poll_plan: &[SnmpPollEntry],
) -> Result<Vec<String>, TaskError> {
    let version = text(payload, "version")?;
    let auth = payload
        .get("auth")
        .and_then(Value::as_object)
        .ok_or_else(|| TaskError::invalid("auth is required"))?;
    let mut args = vec![
        "-On".into(),
        "-Oqv".into(),
        "-t".into(),
        format!("{:.3}", timeout_ms as f64 / 1000.0),
        "-r".into(),
        retries.to_string(),
    ];
    match version {
        "1" | "2c" => {
            let key = text(auth, "communitySecretKeyId")?;
            args.extend([
                if version == "1" { "-v1" } else { "-v2c" }.into(),
                "-c".into(),
                secret(secrets, key)?.to_owned(),
            ]);
        }
        "3" => {
            let username = safe_token(text(auth, "username")?, "username")?;
            let auth_protocol = allowed_enum(
                text(auth, "authProtocol")?,
                &["MD5", "SHA", "SHA-224", "SHA-256", "SHA-384", "SHA-512"],
                "authProtocol",
            )?;
            let auth_key = text(auth, "authPassphraseSecretKeyId")?;
            let privacy_protocol = auth.get("privacyProtocol").and_then(Value::as_str);
            let privacy_key = auth
                .get("privacyPassphraseSecretKeyId")
                .and_then(Value::as_str);
            let level = if privacy_protocol.is_some() || privacy_key.is_some() {
                "authPriv"
            } else {
                "authNoPriv"
            };
            args.extend([
                "-v3".into(),
                "-l".into(),
                level.into(),
                "-u".into(),
                username.into(),
                "-a".into(),
                auth_protocol.into(),
                "-A".into(),
                secret(secrets, auth_key)?.to_owned(),
            ]);
            if level == "authPriv" {
                let protocol = allowed_enum(
                    privacy_protocol
                        .ok_or_else(|| TaskError::invalid("privacyProtocol is required"))?,
                    &["DES", "AES", "AES-128", "AES-192", "AES-256"],
                    "privacyProtocol",
                )?;
                let key = privacy_key.ok_or_else(|| {
                    TaskError::invalid("privacyPassphraseSecretKeyId is required")
                })?;
                args.extend([
                    "-x".into(),
                    protocol.into(),
                    "-X".into(),
                    secret(secrets, key)?.to_owned(),
                ]);
            }
            if let Some(context) = auth.get("context").and_then(Value::as_str) {
                args.extend(["-n".into(), safe_token(context, "context")?.into()]);
            }
        }
        _ => return Err(TaskError::invalid("version must be 1, 2c or 3")),
    }
    args.push(snmp_transport_address(target, port));
    args.extend(poll_plan.iter().map(|entry| entry.oid.clone()));
    Ok(args)
}

fn parse_snmp_output(
    stdout: &[u8],
    poll_plan: &[SnmpPollEntry],
) -> Result<Vec<Option<f64>>, TaskError> {
    let output = std::str::from_utf8(stdout)
        .map_err(|_| TaskError::failed("SNMP_PARSE_FAILED", "snmpget output was not UTF-8"))?;
    let lines = output
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect::<Vec<_>>();
    if lines.len() != poll_plan.len() {
        return Err(TaskError::failed(
            "SNMP_PARSE_FAILED",
            format!(
                "snmpget returned {} values for {} profile OIDs",
                lines.len(),
                poll_plan.len()
            ),
        ));
    }
    lines
        .into_iter()
        .map(|line| match parse_snmp_number(line) {
            Ok(value) => Ok(Some(value)),
            Err(error)
                if matches!(
                    error.code.as_str(),
                    "SNMP_NO_SUCH_OID" | "SNMP_NON_FINITE" | "SNMP_PARSE_FAILED"
                ) =>
            {
                Ok(None)
            }
            Err(error) => Err(error),
        })
        .collect::<Result<Vec<_>, _>>()
}

fn parse_snmp_identity_output(stdout: &[u8]) -> Result<String, TaskError> {
    if stdout.is_empty() || stdout.len() > 1_024 {
        return Err(TaskError::failed(
            "SNMP_IDENTITY_INVALID",
            "SNMP sysObjectID response was empty or oversized",
        ));
    }
    let output = std::str::from_utf8(stdout)
        .map_err(|_| TaskError::failed("SNMP_PARSE_FAILED", "SNMP identity was not UTF-8"))?;
    let value = output
        .trim()
        .strip_prefix("OID:")
        .unwrap_or(output.trim())
        .trim();
    let oid = value.strip_prefix('.').unwrap_or(value);
    if !numeric_oid(oid) {
        return Err(TaskError::failed(
            "SNMP_IDENTITY_INVALID",
            "SNMP sysObjectID response was not a numeric OID",
        ));
    }
    Ok(oid.to_owned())
}

fn classify_snmp_command_failure(output: &CommandOutput) -> TaskError {
    let diagnostic = format!(
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
    .to_ascii_lowercase();
    if [
        "authentication failure",
        "unknown user name",
        "unknown engine id",
        "unsupported security level",
        "wrong digest",
        "decryption error",
        "not in time window",
    ]
    .iter()
    .any(|marker| diagnostic.contains(marker))
    {
        TaskError::failed(
            "SNMP_AUTH_FAILED",
            "SNMP authentication or security validation failed",
        )
    } else if diagnostic.contains("timeout") || diagnostic.contains("no response") {
        TaskError::failed(
            "SNMP_TARGET_TIMEOUT",
            "SNMP target did not respond before the request timed out",
        )
    } else {
        TaskError::failed("SNMP_GET_FAILED", "SNMP target rejected the read request")
    }
}

fn parse_snmp_number(line: &str) -> Result<f64, TaskError> {
    let trimmed = line.trim();
    if trimmed.to_ascii_lowercase().contains("no such") {
        return Err(TaskError::failed(
            "SNMP_NO_SUCH_OID",
            "SNMP OID is unavailable",
        ));
    }
    if let Some(start) = trimmed.find('(') {
        if let Some(end) = trimmed[start + 1..].find(')') {
            if let Ok(value) = trimmed[start + 1..start + 1 + end].trim().parse::<f64>() {
                return Ok(value);
            }
        }
    }
    let candidate = trimmed
        .rsplit_once(':')
        .map_or(trimmed, |(_, value)| value)
        .split_whitespace()
        .next()
        .unwrap_or("");
    let value = candidate
        .trim_matches('"')
        .parse::<f64>()
        .map_err(|_| TaskError::failed("SNMP_PARSE_FAILED", "SNMP value was not numeric"))?;
    if !value.is_finite() {
        return Err(TaskError::failed(
            "SNMP_NON_FINITE",
            "SNMP value was not finite",
        ));
    }
    Ok(value)
}

fn scale_snmp_value(value: f64, scale: f64) -> Option<f64> {
    let scaled = value * scale;
    scaled.is_finite().then_some(scaled)
}

fn transform_snmp_values(plan: &[SnmpPollEntry], raw: &[Option<f64>]) -> Vec<Option<f64>> {
    plan.iter()
        .zip(raw)
        .map(|(entry, raw_value)| {
            let related = match entry.transform.as_ref() {
                Some(
                    Transform::Percentage { total_metric }
                    | Transform::UsedFromTotal { total_metric }
                    | Transform::UsedFromFree { total_metric },
                ) => plan.iter().zip(raw).find_map(|(candidate, value)| {
                    (candidate.metric_key == *total_metric)
                        .then_some(*value)
                        .flatten()
                        .and_then(|value| scale_snmp_value(value, candidate.scale))
                }),
                _ => None,
            };
            apply_numeric_transform(
                (*raw_value)?,
                entry.scale,
                entry.transform.as_ref(),
                related,
            )
        })
        .collect()
}

fn numeric_oid(value: &str) -> bool {
    let value = value.strip_prefix('.').unwrap_or(value);
    !value.is_empty()
        && value.split('.').count() > 1
        && value
            .split('.')
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

fn canonical_key(value: &str) -> bool {
    value.bytes().enumerate().all(|(index, byte)| {
        byte.is_ascii_lowercase()
            || byte.is_ascii_digit()
            || (index > 0 && matches!(byte, b'.' | b'_' | b'-'))
    })
}

fn bounded_u64(
    value: Option<&Value>,
    minimum: u64,
    maximum: u64,
    name: &str,
) -> Result<u64, TaskError> {
    value
        .and_then(Value::as_u64)
        .filter(|value| *value >= minimum && *value <= maximum)
        .ok_or_else(|| TaskError::invalid(format!("{name} is outside bounds")))
}

fn secret<'a>(
    secrets: &'a std::collections::HashMap<String, String>,
    key: &str,
) -> Result<&'a str, TaskError> {
    secrets
        .get(key)
        .map(String::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            TaskError::failed(
                "SNMP_SECRET_UNAVAILABLE",
                "required SNMP secret is unavailable",
            )
        })
}

fn safe_token<'a>(value: &'a str, name: &str) -> Result<&'a str, TaskError> {
    if value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        Ok(value)
    } else {
        Err(TaskError::invalid(format!(
            "{name} contains invalid characters"
        )))
    }
}

fn allowed_enum<'a>(value: &'a str, allowed: &[&str], name: &str) -> Result<&'a str, TaskError> {
    if allowed.contains(&value) {
        Ok(value)
    } else {
        Err(TaskError::invalid(format!("{name} is unsupported")))
    }
}

async fn tcp_check(context: &TaskContext, payload: &Map<String, Value>) -> TaskOutcome {
    let target = text(payload, "target")?;
    let port = payload
        .get("port")
        .and_then(Value::as_u64)
        .filter(|port| *port > 0 && *port <= u16::MAX as u64)
        .ok_or_else(|| TaskError::invalid("port must be between 1 and 65535"))?
        as u16;
    let policy = context
        .config
        .read()
        .await
        .policy()
        .map_err(TaskError::internal)?;
    let addresses = resolve_allowed(target, port, &policy).await?;
    let started = Instant::now();
    let mut last_error = None;
    for address in addresses {
        match timeout(task_timeout(payload), TcpStream::connect(address)).await {
            Ok(Ok(_)) => {
                return Ok(json_object(
                    json!({"success": true, "latencyMs": started.elapsed().as_millis(), "address": address.ip().to_string(), "port": port}),
                ))
            }
            Ok(Err(error)) => last_error = Some(error.to_string()),
            Err(_) => last_error = Some("connection timed out".into()),
        }
    }
    Err(TaskError::failed(
        "TCP_CONNECT_FAILED",
        last_error.unwrap_or_else(|| "no target addresses".into()),
    ))
}

async fn http_check(context: &TaskContext, payload: &Map<String, Value>) -> TaskOutcome {
    let raw_url = text(payload, "url").or_else(|_| text(payload, "target"))?;
    let url = url::Url::parse(raw_url).map_err(|_| TaskError::invalid("url is invalid"))?;
    if url.scheme() != "http" && url.scheme() != "https" {
        return Err(TaskError::invalid("url scheme must be HTTP or HTTPS"));
    }
    let host = url
        .host_str()
        .ok_or_else(|| TaskError::invalid("url host is required"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| TaskError::invalid("url port is invalid"))?;
    let policy = context
        .config
        .read()
        .await
        .policy()
        .map_err(TaskError::internal)?;
    let addresses = resolve_allowed(host, port, &policy).await?;
    let client = reqwest::Client::builder()
        .redirect(Policy::none())
        .resolve_to_addrs(host, &addresses)
        .build()
        .map_err(TaskError::internal)?;
    let started = Instant::now();
    let response = client
        .get(url)
        .timeout(task_timeout(payload))
        .send()
        .await
        .map_err(|error| {
            let message = if error.is_timeout() {
                "request timed out"
            } else if error.is_connect() {
                "connection failed"
            } else {
                "request failed"
            };
            TaskError::failed("HTTP_REQUEST_FAILED", message)
        })?;
    Ok(json_object(
        json!({"success": response.status().is_success(), "latencyMs": started.elapsed().as_millis(), "statusCode": response.status().as_u16()}),
    ))
}

async fn resolve_allowed(
    target: &str,
    port: u16,
    policy: &NetworkPolicy,
) -> Result<Vec<SocketAddr>, TaskError> {
    let addresses = if let Ok(address) = target.parse::<IpAddr>() {
        vec![SocketAddr::new(address, port)]
    } else {
        lookup_host((target, port))
            .await
            .map_err(|error| TaskError::failed("DNS_RESOLUTION_FAILED", error.to_string()))?
            .collect::<Vec<_>>()
    };
    if addresses.is_empty() {
        return Err(TaskError::failed(
            "DNS_NO_ADDRESSES",
            "target resolved to no addresses",
        ));
    }
    for address in &addresses {
        policy
            .validate_target(address.ip())
            .map_err(|error| TaskError::policy(error.to_string()))?;
    }
    Ok(addresses)
}

fn addresses(cidr: IpNet) -> Result<Vec<IpAddr>, TaskError> {
    if super::network_policy::host_count(cidr) > MAX_DISCOVERY_HOSTS {
        return Err(TaskError::policy("discovery host limit exceeded"));
    }
    Ok(match cidr {
        IpNet::V4(net) => net.hosts().map(IpAddr::V4).collect(),
        IpNet::V6(net) => net.hosts().map(IpAddr::V6).collect(),
    })
}

fn addresses_len(cidr: IpNet) -> usize {
    addresses(cidr).map(|values| values.len()).unwrap_or(0)
}

fn ports(value: Option<&Value>) -> Result<Vec<u16>, TaskError> {
    let values = value
        .and_then(Value::as_array)
        .ok_or_else(|| TaskError::invalid("ports must be an explicitly supplied array"))?;
    if values.is_empty() || values.len() > MAX_DISCOVERY_PORTS {
        return Err(TaskError::invalid(format!(
            "ports must contain 1-{MAX_DISCOVERY_PORTS} entries"
        )));
    }
    values
        .iter()
        .map(|value| {
            value
                .as_u64()
                .filter(|port| *port > 0 && *port <= u16::MAX as u64)
                .map(|port| port as u16)
                .ok_or_else(|| TaskError::invalid("ports contains an invalid port"))
        })
        .collect()
}

fn string_array(value: Option<&Value>, name: &str) -> Result<Vec<String>, TaskError> {
    value
        .and_then(Value::as_array)
        .ok_or_else(|| TaskError::invalid(format!("{name} must be an array")))?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| TaskError::invalid(format!("{name} must contain strings")))
        })
        .collect()
}

fn text<'a>(payload: &'a Map<String, Value>, name: &str) -> Result<&'a str, TaskError> {
    payload
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| TaskError::invalid(format!("{name} is required")))
}

fn task_timeout(payload: &Map<String, Value>) -> Duration {
    Duration::from_millis(
        payload
            .get("timeoutMs")
            .and_then(Value::as_u64)
            .unwrap_or(5_000)
            .clamp(100, MAX_TIMEOUT.as_millis() as u64),
    )
}

fn json_object(value: Value) -> Map<String, Value> {
    value.as_object().cloned().unwrap_or_default()
}

type TaskOutcome = Result<Map<String, Value>, TaskError>;

#[derive(Debug)]
struct TaskError {
    code: String,
    message: String,
}

impl TaskError {
    fn invalid(message: impl ToString) -> Self {
        Self {
            code: "INVALID_TASK_PAYLOAD".into(),
            message: message.to_string(),
        }
    }
    fn policy(message: impl ToString) -> Self {
        Self {
            code: "TARGET_POLICY_REJECTED".into(),
            message: message.to_string(),
        }
    }
    fn unsupported(code: &str, message: &str) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
    fn failed(code: &str, message: impl ToString) -> Self {
        Self {
            code: code.into(),
            message: message.to_string(),
        }
    }
    fn internal(error: impl std::fmt::Display) -> Self {
        Self {
            code: "INTERNAL_ERROR".into(),
            message: error.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sadapp_snmp_profile_engine::{Detection, ProfileState};
    use std::{
        collections::{HashMap, VecDeque},
        sync::Mutex,
    };
    use tokio::sync::RwLock;

    #[derive(Debug)]
    struct MockExecutor {
        output: CommandOutput,
        error: Option<String>,
        calls: Mutex<Vec<Vec<String>>>,
    }

    impl CommandExecutor for MockExecutor {
        fn run<'a>(
            &'a self,
            _program: &'a str,
            args: &'a [String],
        ) -> Pin<Box<dyn Future<Output = Result<CommandOutput>> + Send + 'a>> {
            self.calls.lock().unwrap().push(args.to_vec());
            Box::pin(async move {
                if let Some(error) = &self.error {
                    anyhow::bail!(error.clone());
                }
                Ok(self.output.clone())
            })
        }
    }

    #[derive(Debug)]
    struct SequenceMockExecutor {
        outputs: Mutex<VecDeque<CommandOutput>>,
        calls: Mutex<Vec<Vec<String>>>,
    }

    struct StorageMockExecutor {
        calls: Mutex<Vec<(String, Vec<String>)>>,
        index: std::sync::atomic::AtomicU32,
        used: std::sync::atomic::AtomicU32,
    }

    struct StandardMockExecutor {
        rows: usize,
    }

    struct ProfileTableMockExecutor {
        calls: Mutex<Vec<String>>,
        used: std::sync::atomic::AtomicU32,
        index: std::sync::atomic::AtomicU32,
    }

    impl CommandExecutor for ProfileTableMockExecutor {
        fn run<'a>(
            &'a self,
            program: &'a str,
            args: &'a [String],
        ) -> Pin<Box<dyn Future<Output = Result<CommandOutput>> + Send + 'a>> {
            Box::pin(async move {
                if program == "snmpget" {
                    return Ok(CommandOutput {
                        success: true,
                        stdout: b"10000\n128\n".to_vec(),
                        stderr: Vec::new(),
                    });
                }
                let oid = args.last().unwrap();
                self.calls.lock().unwrap().push(oid.clone());
                let value = match oid.as_str() {
                    "1.3.6.1.4.1.999.10.1" => "STRING: \"Data volume\"".to_string(),
                    "1.3.6.1.4.1.999.10.2" => {
                        format!("Gauge32: {}", self.used.load(Ordering::SeqCst))
                    }
                    "1.3.6.1.4.1.999.10.3" => "Gauge32: 10".to_string(),
                    _ => {
                        return Ok(CommandOutput {
                            success: true,
                            stdout: b"No Such Object available\n".to_vec(),
                            stderr: Vec::new(),
                        })
                    }
                };
                let index = self.index.load(Ordering::SeqCst);
                Ok(CommandOutput {
                    success: true,
                    stdout: format!(".{oid}.7.{index} = {value}\n").into_bytes(),
                    stderr: Vec::new(),
                })
            })
        }
    }

    fn profile_table_plan() -> Value {
        json!([{
            "name": "volumes", "baseOid": "1.3.6.1.4.1.999.10", "indexStrategy": "suffix", "maxRows": 128,
            "columns": [
                { "name": "name", "oidSuffix": "1", "unit": "text", "scale": 1.0, "valueType": "STRING" },
                { "name": "used", "oidSuffix": "2", "metricKey": "filesystem.used_bytes", "unit": "bytes", "scale": 1024.0, "valueType": "GAUGE" },
                { "name": "total", "oidSuffix": "3", "metricKey": "filesystem.total_bytes", "unit": "bytes", "scale": 1024.0, "valueType": "GAUGE" },
            ],
        }])
    }

    impl CommandExecutor for StandardMockExecutor {
        fn run<'a>(
            &'a self,
            program: &'a str,
            args: &'a [String],
        ) -> Pin<Box<dyn Future<Output = Result<CommandOutput>> + Send + 'a>> {
            Box::pin(async move {
                if program == "snmpget" {
                    return Ok(CommandOutput {
                        success: true,
                        stdout: b"10000\n128\n".to_vec(),
                        stderr: Vec::new(),
                    });
                }
                let oid = args.last().unwrap();
                let Some(spec) = STANDARD_TABLES.iter().find(|spec| spec.oid == oid) else {
                    return Ok(CommandOutput {
                        success: true,
                        stdout: b"No Such Object available\n".to_vec(),
                        stderr: Vec::new(),
                    });
                };
                let value = match spec.key {
                    "if.hc_in" => "Counter64: 1000",
                    "if.hc_out" => "Counter64: 2000",
                    "if.in" | "if.out" => "Counter32: 12",
                    "if.status" | "sensor.status" => "INTEGER: 1",
                    "if.high_speed" => "Gauge32: 1000",
                    "if.speed" => "Gauge32: 1000000000",
                    "if.in_errors" | "if.out_errors" => "Counter32: 0",
                    "sensor.type" => "INTEGER: 8",
                    "sensor.scale" => "INTEGER: 9",
                    "sensor.precision" => "INTEGER: 1",
                    "sensor.value" => "INTEGER: 250",
                    "entity.class" => "INTEGER: 3",
                    _ => "STRING: \"synthetic component\"",
                };
                Ok(CommandOutput {
                    success: true,
                    stdout: (1..=self.rows)
                        .map(|index| format!(".{oid}.{index} = {value}\n"))
                        .collect::<String>()
                        .into_bytes(),
                    stderr: Vec::new(),
                })
            })
        }
    }

    impl CommandExecutor for StorageMockExecutor {
        fn run<'a>(
            &'a self,
            program: &'a str,
            args: &'a [String],
        ) -> Pin<Box<dyn Future<Output = Result<CommandOutput>> + Send + 'a>> {
            self.calls
                .lock()
                .unwrap()
                .push((program.to_owned(), args.to_vec()));
            let oid = args.last().unwrap().clone();
            let index = self.index.load(Ordering::SeqCst);
            let used = self.used.load(Ordering::SeqCst);
            Box::pin(async move {
                let value = match oid.as_str() {
                    OID_HR_STORAGE_TYPE => "OID: 1.3.6.1.2.1.25.2.1.4",
                    OID_HR_STORAGE_ALLOC_UNITS => "INTEGER: 1024",
                    OID_HR_STORAGE_SIZE => "INTEGER: 100",
                    OID_HR_STORAGE_USED => "",
                    OID_HR_PROCESSOR_LOAD => "INTEGER: 12",
                    _ => return Err(anyhow::anyhow!("unexpected test OID")),
                };
                Ok(CommandOutput {
                    success: true,
                    stdout: format!(
                        ".{oid}.{index} = {}\n",
                        if oid == OID_HR_STORAGE_USED {
                            format!("INTEGER: {used}")
                        } else {
                            value.to_owned()
                        }
                    )
                    .into_bytes(),
                    stderr: Vec::new(),
                })
            })
        }
    }

    impl CommandExecutor for SequenceMockExecutor {
        fn run<'a>(
            &'a self,
            _program: &'a str,
            args: &'a [String],
        ) -> Pin<Box<dyn Future<Output = Result<CommandOutput>> + Send + 'a>> {
            self.calls.lock().unwrap().push(args.to_vec());
            Box::pin(async move {
                self.outputs
                    .lock()
                    .unwrap()
                    .pop_front()
                    .ok_or_else(|| anyhow::anyhow!("mock output exhausted"))
            })
        }
    }

    fn snmp_task(target: &str) -> TaskLease {
        let detection_profiles = vec![DetectionProfile {
            profile_name: "generic-host".into(),
            schema_version: 1,
            state: ProfileState::Enabled,
            detection: Detection::default(),
        }];
        let detection_checksum = detection_bundle_checksum(&detection_profiles).unwrap();
        TaskLease {
            id: "task-1".into(),
            task_type: TaskType::CollectSnmp,
            lease_token: "lease-token".into(),
            secrets: HashMap::from([("community-1".into(), "very-secret".into())]),
            payload: json_object(json!({
                "target": target,
                "port": 161,
                "version": "2c",
                "profile": { "name": "generic-host", "version": 1, "checksum": "a".repeat(64) },
                "configuredProfile": "auto",
                "detectionBundle": { "schemaVersion": 1, "checksum": detection_checksum, "profiles": detection_profiles },
                "pollPlan": [
                    { "oid": "1.3.6.1.2.1.1.3.0", "metricKey": "uptime", "unit": "seconds", "scale": 0.01, "valueType": "GAUGE", "required": true },
                    { "oid": "1.3.6.1.2.1.2.1.0", "metricKey": "interface.count", "unit": "count", "scale": 1.0, "valueType": "GAUGE", "required": false }
                ],
                "timeoutMs": 1000,
                "retries": 1,
                "auth": { "communitySecretKeyId": "community-1" },
                "resource": { "externalKey": "server:1", "class": "HARDWARE", "kind": "server", "name": "switch", "address": target },
                "collector": { "type": "SNMP", "sourceKey": "local-network-collector-snmp:1" }
            })),
        }
    }

    #[test]
    fn task_errors_include_safe_type_and_target_context() {
        let snmp = snmp_task("10.0.0.7");
        assert_eq!(
            format_task_error("SNMP", &snmp.payload, "OID 1.3.6.1 returned text".into()),
            "SNMP 10.0.0.7: OID 1.3.6.1 returned text"
        );

        let tcp_payload = json_object(json!({ "target": "10.0.0.7", "port": 161 }));
        assert_eq!(
            format_task_error("TCP", &tcp_payload, "connection timed out".into()),
            "TCP 10.0.0.7:161: connection timed out"
        );

        let http_payload = json_object(
            json!({ "url": "https://user:secret@example.test:8443/health?token=hidden" }),
        );
        let message = format_task_error("HTTPS", &http_payload, "TLS handshake failed".into());
        assert_eq!(message, "HTTPS example.test:8443: TLS handshake failed");
        assert!(!message.contains("secret"));
        assert!(!message.contains("token"));
        assert!(!message.contains("/health"));

        let discovery_payload = json_object(json!({ "cidr": "10.0.0.0/24" }));
        assert_eq!(
            format_task_error("DISCOVERY", &discovery_payload, "scan failed".into()),
            "DISCOVERY 10.0.0.0/24: scan failed"
        );
        assert_eq!(
            format_task_error("REST", &http_payload, "response mapping failed".into()),
            "REST example.test:8443: response mapping failed"
        );

        assert_eq!(
            task_diagnostic_label(
                &TaskType::RunCheck,
                &json_object(json!({ "checkType": "TCP" }))
            ),
            "TCP"
        );
    }

    #[test]
    fn formats_ipv4_and_ipv6_icmp_arguments_with_target_terminator() {
        assert_eq!(
            icmp_command_args("10.20.0.8".parse().unwrap(), 2),
            ["-4", "-c", "1", "-W", "2", "--", "10.20.0.8"]
        );
        assert_eq!(
            icmp_command_args("fd00::8".parse().unwrap(), 2),
            ["-6", "-c", "1", "-W", "2", "--", "fd00::8"]
        );
    }

    #[tokio::test]
    async fn runs_icmp_for_an_allowed_private_target() {
        let directory = tempfile::tempdir().unwrap();
        let executor = Arc::new(MockExecutor {
            output: CommandOutput {
                success: true,
                stdout: Vec::new(),
                stderr: Vec::new(),
            },
            error: None,
            calls: Mutex::new(Vec::new()),
        });
        let context = test_context(directory.path(), executor.clone());
        let payload = json_object(json!({ "target": "192.168.1.10", "timeoutMs": 1000 }));

        let result = icmp_check(&context, &payload).await.unwrap();

        assert_eq!(result["success"], true);
        assert_eq!(
            executor.calls.lock().unwrap()[0],
            icmp_command_args("192.168.1.10".parse().unwrap(), 1)
        );
    }

    #[tokio::test]
    async fn reports_administratively_prohibited_icmp_as_unknown_reachability() {
        let directory = tempfile::tempdir().unwrap();
        let executor = Arc::new(MockExecutor {
            output: CommandOutput {
                success: false,
                stdout: Vec::new(),
                stderr: b"icmp_seq=5 Destination unreachable: Administratively prohibited".to_vec(),
            },
            error: None,
            calls: Mutex::new(Vec::new()),
        });
        let context = test_context(directory.path(), executor);
        let payload = json_object(json!({ "target": "192.168.1.10", "timeoutMs": 1000 }));

        let error = icmp_check(&context, &payload).await.unwrap_err();

        assert_eq!(error.code, "ICMP_POLICY_BLOCKED");
        assert!(error.message.contains("reachability is unknown"));
    }

    #[tokio::test]
    async fn rejects_public_icmp_targets_before_running_ping() {
        let directory = tempfile::tempdir().unwrap();
        let executor = Arc::new(MockExecutor {
            output: CommandOutput {
                success: true,
                stdout: Vec::new(),
                stderr: Vec::new(),
            },
            error: None,
            calls: Mutex::new(Vec::new()),
        });
        let context = test_context(directory.path(), executor.clone());
        let payload = json_object(json!({ "target": "8.8.8.8", "timeoutMs": 1000 }));

        let error = icmp_check(&context, &payload).await.unwrap_err();

        assert_eq!(error.code, "TARGET_POLICY_REJECTED");
        assert!(executor.calls.lock().unwrap().is_empty());
    }

    fn test_context(
        directory: &std::path::Path,
        executor: Arc<dyn CommandExecutor>,
    ) -> TaskContext {
        TaskContext {
            api: ApiClient::new("http://127.0.0.1:3000".parse().unwrap()).unwrap(),
            credentials: Credentials {
                collector_id: "collector-1".into(),
                collector_secret: "collector-secret".into(),
            },
            config: Arc::new(RwLock::new(CollectorConfig {
                revision: 1,
                allowed_cidrs: vec!["192.168.0.0/16".into()],
            })),
            state_dir: directory.to_path_buf(),
            draining: Arc::new(AtomicBool::new(false)),
            telemetry_spool: Spool::open(directory, "telemetry", 10, 100_000).unwrap(),
            command_executor: executor,
        }
    }

    #[tokio::test]
    async fn task_target_validation_rejects_public_and_outside_addresses() {
        let policy = NetworkPolicy::new(&["192.168.0.0/16".into()]).unwrap();
        assert!(resolve_allowed("8.8.8.8", 53, &policy).await.is_err());
        assert!(resolve_allowed("10.0.0.1", 80, &policy).await.is_err());
        assert!(resolve_allowed("192.168.1.10", 80, &policy).await.is_ok());
    }

    #[tokio::test]
    async fn rest_validates_body_instead_of_trusting_content_type() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        for header in [
            "",
            "Content-Type: text/plain\r\n",
            "Content-Type: text/html\r\n",
            "Content-Type: application/json; charset=utf-8\r\n",
            "Content-Type: Application/JSON\r\n",
            "Content-Type: application/vnd.device+json\r\n",
        ] {
            for body in [
                r#"{"value":3}"#,
                r#"{"value":true}"#,
                r#"{"value":"ok"}"#,
                "<html>Not JSON</html>",
                r#"{"other":3}"#,
                r#"{"value":null}"#,
                r#"{"value":3"#,
            ] {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let address = listener.local_addr().unwrap();
                let raw = format!(
                    "HTTP/1.1 200 OK\r\n{header}Content-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                tokio::spawn(async move {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let mut request = [0; 1024];
                    stream.read(&mut request).await.unwrap();
                    stream.write_all(raw.as_bytes()).await.unwrap();
                });
                let response = reqwest::Client::builder()
                    .no_proxy()
                    .build()
                    .unwrap()
                    .get(format!("http://{address}/"))
                    .send()
                    .await
                    .unwrap();
                let bytes = read_collection_response(response, true).await.unwrap();
                let samples =
                    map_rest_json(&bytes, &[json!({ "path": "value", "metricKey": "value" })]);
                if body == r#"{"value":3}"# {
                    assert_eq!(samples.unwrap()[0].value, json!(3.0));
                } else if body == r#"{"value":true}"# {
                    assert_eq!(samples.unwrap()[0].value, json!(true));
                } else if body == r#"{"value":"ok"}"# {
                    assert_eq!(samples.unwrap()[0].value, json!("ok"));
                } else {
                    assert!(samples.is_err(), "accepted invalid reading: {body}");
                }
            }
        }
    }

    #[tokio::test]
    async fn collector_rejects_redirect_responses() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).await.unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 302 Found\r\nLocation: http://8.8.8.8/\r\nContent-Length: 0\r\n\r\n",
                )
                .await
                .unwrap();
        });
        let directory = tempfile::tempdir().unwrap();
        let context = test_context(directory.path(), Arc::new(TokioCommandExecutor));
        context.config.write().await.allowed_cidrs = vec!["127.0.0.0/8".into()];
        let task = TaskLease {
            id: "redirect-task".into(),
            task_type: TaskType::CollectPrometheus,
            lease_token: "lease-token".into(),
            secrets: HashMap::new(),
            payload: json_object(json!({ "url": format!("http://{address}/metrics") })),
        };
        let error = fetch_collection_body(&context, &task, Method::GET, false)
            .await
            .unwrap_err();
        assert_eq!(error.code, "TARGET_POLICY_REJECTED");
    }

    #[test]
    fn discovery_requires_explicit_bounded_ports() {
        assert!(ports(None).is_err());
        assert!(ports(Some(&json!([22, 443]))).is_ok());
        assert!(ports(Some(&json!([0]))).is_err());
    }

    #[test]
    fn discovery_evidence_retains_every_open_tcp_service() {
        let evidence = tcp_discovery_evidence(&[22, 80, 554, 9100], "2026-10-04T00:00:00Z");
        assert_eq!(evidence["schemaVersion"], 1);
        assert_eq!(evidence["services"].as_array().unwrap().len(), 4);
        assert_eq!(
            evidence["services"][2],
            json!({ "transport": "tcp", "port": 554 })
        );
    }

    #[test]
    fn merges_multicast_protocol_evidence_without_overwriting_tcp_services() {
        let observed_at = "2026-10-04T00:00:00Z";
        let mut candidates = vec![json!({
            "address": "10.0.0.20",
            "kind": "network_host",
            "evidence": tcp_discovery_evidence(&[80, 443], observed_at),
        })];
        merge_discovery_candidate(
            &mut candidates,
            json!({
                "address": "10.0.0.20",
                "kind": "camera",
                "profile": "camera",
                "evidence": {
                    "identity": { "method": "onvif", "verified": true, "keyHash": "a".repeat(64), "deviceProfile": "camera" },
                    "services": [{ "transport": "udp", "port": 3702, "service": "onvif" }],
                    "protocolObservations": [{ "protocol": "onvif-wsd", "port": 3702, "state": "responded", "interfaceAddress": "10.0.0.8" }],
                },
            }),
        );

        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0]["evidence"]["services"]
                .as_array()
                .unwrap()
                .len(),
            3
        );
        assert_eq!(
            candidates[0]["evidence"]["identity"]["deviceProfile"],
            "camera"
        );
        assert_eq!(
            candidates[0]["evidence"]["protocolObservations"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            candidates[0]["evidence"]["protocolObservations"][0]["interfaceAddress"],
            "10.0.0.8"
        );
    }

    #[test]
    fn conflicting_protocol_identities_disable_identity_correlation() {
        let mut candidates = vec![json!({
            "address": "10.0.0.20", "evidence": { "identity": { "keyHash": "a" } },
        })];
        merge_discovery_candidate(
            &mut candidates,
            json!({
                "address": "10.0.0.20", "evidence": { "identity": { "keyHash": "b" } },
            }),
        );

        assert!(candidates[0]["evidence"].get("identity").is_none());
        assert_eq!(candidates[0]["evidence"]["identityConflict"], true);
    }

    #[tokio::test]
    async fn unauthenticated_http_probe_records_auth_required_without_sending_credentials() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut chunk = [0_u8; 512];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let count = socket.read(&mut chunk).await.unwrap();
                if count == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..count]);
            }
            let request = String::from_utf8_lossy(&request).to_ascii_lowercase();
            assert!(
                request.starts_with("head / http/1.1") || request.starts_with("options / http/1.1")
            );
            assert!(!request.contains("authorization:"));
            socket.write_all(b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"device\"\r\nServer: ExampleDevice/1.0\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
        });
        let client = reqwest::Client::builder()
            .redirect(Policy::none())
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        let evidence = probe_http_service(&client, IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), port)
            .await
            .unwrap();

        assert_eq!(evidence["statusCode"], 401);
        assert_eq!(evidence["authentication"], "required");
        assert_eq!(evidence["authScheme"], "Basic");
        assert_eq!(evidence["server"], "ExampleDevice/1.0");
        server.await.unwrap();
    }

    #[test]
    fn snmpv3_discovery_uses_no_auth_and_only_reads_sys_object_id() {
        let args = snmpv3_discovery_args("192.168.1.20".parse().unwrap());
        assert!(args.windows(2).any(|pair| pair == ["-l", "noAuthNoPriv"]));
        assert!(args.contains(&OID_SNMP_SYS_OBJECT_ID.to_string()));
        assert!(!args
            .iter()
            .any(|argument| ["-c", "-A", "-X"].contains(&argument.as_str())));
        assert!(snmpv3_discovery_args("fd00::20".parse().unwrap())
            .iter()
            .any(|argument| argument == "udp6:[fd00::20]:161"));
    }

    #[test]
    fn snmpv3_discovery_normalizes_auth_required_reports_without_leaking_diagnostics() {
        let evidence = snmpv3_discovery_evidence(&CommandOutput {
            success: false,
            stdout: Vec::new(),
            stderr: b"Unknown user name: private-user-details".to_vec(),
        })
        .unwrap();
        assert_eq!(evidence["state"], "authentication-required");
        assert_eq!(evidence["authentication"], "required");
        assert!(evidence.to_string().find("private-user-details").is_none());
    }

    #[test]
    fn snmpv3_discovery_records_system_object_id_on_no_auth_response() {
        let evidence = snmpv3_discovery_evidence(&CommandOutput {
            success: true,
            stdout: b".1.3.6.1.4.1.9.1.1208\n".to_vec(),
            stderr: Vec::new(),
        })
        .unwrap();
        assert_eq!(evidence["state"], "responded");
        assert_eq!(evidence["sysObjectId"], "1.3.6.1.4.1.9.1.1208");
    }

    #[test]
    fn discovered_hostnames_are_trimmed_and_bounded() {
        assert_eq!(
            normalize_discovered_hostname("printer.local.".into()).as_deref(),
            Some("printer.local")
        );
        assert_eq!(normalize_discovered_hostname("  ".into()), None);
        assert_eq!(normalize_discovered_hostname("bad host".into()), None);
        assert_eq!(normalize_discovered_hostname("x".repeat(254)), None);
    }

    #[test]
    fn parses_common_numeric_net_snmp_output() {
        assert_eq!(parse_snmp_number("12345").unwrap(), 12345.0);
        assert_eq!(
            parse_snmp_number("Timeticks: (321) 0:00:03.21").unwrap(),
            321.0
        );
        assert_eq!(parse_snmp_number("INTEGER: up(1)").unwrap(), 1.0);
        assert!(parse_snmp_number("No Such Object available").is_err());
        assert!(parse_snmp_number("NaN").is_err());
        assert!(parse_snmp_number("Infinity").is_err());
    }

    #[test]
    fn keeps_supported_snmp_values_when_optional_oids_are_missing() {
        let poll_plan = [
            SnmpPollEntry {
                oid: "1.3.6.1.2.1.1.3.0".into(),
                metric_key: "system.uptime.seconds".into(),
                unit: None,
                scale: 1.0,
                value_type: "GAUGE".into(),
                required: false,
                labels: None,
                transform: None,
            },
            SnmpPollEntry {
                oid: "1.3.6.1.2.1.2.1.0".into(),
                metric_key: "network.interface.count".into(),
                unit: None,
                scale: 1.0,
                value_type: "GAUGE".into(),
                required: false,
                labels: None,
                transform: None,
            },
            SnmpPollEntry {
                oid: "1.3.6.1.2.1.25.2.2.0".into(),
                metric_key: "system.memory.total_bytes".into(),
                unit: None,
                scale: 1.0,
                value_type: "GAUGE".into(),
                required: false,
                labels: None,
                transform: None,
            },
        ];
        assert_eq!(
            parse_snmp_output(
                b"No Such Object available\nSTRING: \"private device description\"\n42\n",
                &poll_plan,
            )
            .unwrap(),
            vec![None, None, Some(42.0)],
        );
    }

    #[test]
    fn preserves_other_samples_when_required_metrics_are_unavailable() {
        let poll_plan = [SnmpPollEntry {
            oid: "1.3.6.1.2.1.1.3.0".into(),
            metric_key: "system.uptime.seconds".into(),
            unit: None,
            scale: 1.0,
            value_type: "GAUGE".into(),
            required: true,
            labels: None,
            transform: None,
        }];
        assert_eq!(
            parse_snmp_output(b"STRING: \"private device description\"\n", &poll_plan).unwrap(),
            vec![None],
        );
    }

    #[test]
    fn omits_snmp_values_that_overflow_when_scaled() {
        assert_eq!(scale_snmp_value(12.0, 0.5), Some(6.0));
        assert_eq!(scale_snmp_value(f64::MAX, 2.0), None);
    }

    #[test]
    fn aggregates_only_fixed_disk_rows_from_host_resources_walks() {
        let storage_type = parse_snmp_walk_values(
            ".1.3.6.1.2.1.25.2.3.1.2.3 = OID: HOST-RESOURCES-TYPES::hrStorageFixedDisk\n.1.3.6.1.2.1.25.2.3.1.2.7 = OID: HOST-RESOURCES-TYPES::hrStorageRam",
            OID_HR_STORAGE_TYPE,
        );
        let units = parse_snmp_walk_values(
            ".1.3.6.1.2.1.25.2.3.1.4.3 = INTEGER: 4096\n.1.3.6.1.2.1.25.2.3.1.4.7 = INTEGER: 1024",
            OID_HR_STORAGE_ALLOC_UNITS,
        );
        let size = parse_snmp_walk_values(
            ".1.3.6.1.2.1.25.2.3.1.5.3 = INTEGER: 1000",
            OID_HR_STORAGE_SIZE,
        );
        let used = parse_snmp_walk_values(
            ".1.3.6.1.2.1.25.2.3.1.6.3 = INTEGER: 250",
            OID_HR_STORAGE_USED,
        );

        assert_eq!(
            aggregate_storage_usage(&storage_type, &units, &size, &used, StorageKind::FixedDisk),
            Some((1_024_000.0, 4_096_000.0))
        );
    }

    #[tokio::test]
    async fn table_failures_keep_valid_scalar_samples_and_report_safe_diagnostics() {
        let directory = tempfile::tempdir().unwrap();
        let executor = Arc::new(MockExecutor {
            output: CommandOutput {
                success: true,
                stdout: b"200\n2\n".to_vec(),
                stderr: Vec::new(),
            },
            error: None,
            calls: Mutex::new(Vec::new()),
        });
        let context = test_context(directory.path(), executor);
        let outcome = collect_snmp(&context, &snmp_task("192.168.1.20"))
            .await
            .unwrap();
        assert_eq!(outcome["sampleCount"], 2);
        assert_eq!(outcome["partial"], true);
        let expected_oids = STANDARD_TABLES
            .iter()
            .map(|spec| spec.oid)
            .chain([
                OID_HR_STORAGE_TYPE,
                OID_HR_STORAGE_ALLOC_UNITS,
                OID_HR_STORAGE_SIZE,
                OID_HR_STORAGE_USED,
                OID_HR_PROCESSOR_LOAD,
            ])
            .collect::<std::collections::BTreeSet<_>>();
        let issues = outcome["collectionIssues"].as_array().unwrap();
        assert_eq!(issues.len(), expected_oids.len());
        assert_eq!(
            issues
                .iter()
                .filter_map(|issue| issue["oid"].as_str())
                .collect::<std::collections::BTreeSet<_>>(),
            expected_oids
        );
        assert_eq!(outcome["collectionIssues"][0]["code"], "SNMP_PARSE_FAILED");
        assert!(!serde_json::to_string(&outcome)
            .unwrap()
            .contains("very-secret"));
        let (_, batch) = context.telemetry_spool.oldest::<Value>().unwrap().unwrap();
        assert_eq!(batch["samples"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn aggregates_windows_physical_memory_and_processor_load() {
        // Captured from the Windows SNMP service (numeric output, -On).
        let storage_type = parse_snmp_walk_values(
            ".1.3.6.1.2.1.25.2.3.1.2.1 = OID: .1.3.6.1.2.1.25.2.1.4\n.1.3.6.1.2.1.25.2.3.1.2.6 = OID: .1.3.6.1.2.1.25.2.1.3\n.1.3.6.1.2.1.25.2.3.1.2.7 = OID: .1.3.6.1.2.1.25.2.1.2",
            OID_HR_STORAGE_TYPE,
        );
        let units = parse_snmp_walk_values(
            ".1.3.6.1.2.1.25.2.3.1.4.1 = INTEGER: 4096\n.1.3.6.1.2.1.25.2.3.1.4.6 = INTEGER: 65536\n.1.3.6.1.2.1.25.2.3.1.4.7 = INTEGER: 65536",
            OID_HR_STORAGE_ALLOC_UNITS,
        );
        let size = parse_snmp_walk_values(
            ".1.3.6.1.2.1.25.2.3.1.5.1 = INTEGER: 1000\n.1.3.6.1.2.1.25.2.3.1.5.6 = INTEGER: 771899\n.1.3.6.1.2.1.25.2.3.1.5.7 = INTEGER: 500",
            OID_HR_STORAGE_SIZE,
        );
        let used = parse_snmp_walk_values(
            ".1.3.6.1.2.1.25.2.3.1.6.1 = INTEGER: 250\n.1.3.6.1.2.1.25.2.3.1.6.6 = INTEGER: 643524\n.1.3.6.1.2.1.25.2.3.1.6.7 = INTEGER: 125",
            OID_HR_STORAGE_USED,
        );
        assert_eq!(
            aggregate_storage_usage(&storage_type, &units, &size, &used, StorageKind::Ram),
            Some((125.0 * 65_536.0, 500.0 * 65_536.0))
        );
        assert_eq!(
            aggregate_storage_usage(&storage_type, &units, &size, &used, StorageKind::FixedDisk),
            Some((1_024_000.0, 4_096_000.0))
        );
        let load = parse_snmp_walk_values(
            ".1.3.6.1.2.1.25.3.3.1.2.2 = INTEGER: 20\n.1.3.6.1.2.1.25.3.3.1.2.3 = INTEGER: 10\n.1.3.6.1.2.1.25.3.3.1.2.4 = INTEGER: 0",
            OID_HR_PROCESSOR_LOAD,
        );
        assert_eq!(average_processor_load(&load), Some(10.0));
        assert_eq!(
            average_processor_load(&std::collections::HashMap::new()),
            None
        );
    }

    #[test]
    fn builds_validated_v3_auth_arguments() {
        let mut task = snmp_task("192.168.1.20");
        task.secrets = HashMap::from([
            ("auth-1".into(), "auth-secret".into()),
            ("priv-1".into(), "priv-secret".into()),
        ]);
        task.payload.insert("version".into(), json!("3"));
        task.payload.insert("auth".into(), json!({
            "username": "snmp_user", "authProtocol": "SHA", "authPassphraseSecretKeyId": "auth-1",
            "privacyProtocol": "AES", "privacyPassphraseSecretKeyId": "priv-1", "context": "edge_1"
        }));
        let plan = snmp_poll_plan(task.payload.get("pollPlan")).unwrap();
        let args = snmp_arguments(
            &task.payload,
            &task.secrets,
            "192.168.1.20".parse().unwrap(),
            161,
            1000,
            1,
            &plan,
        )
        .unwrap();
        assert!(args.windows(2).any(|pair| pair == ["-l", "authPriv"]));
        assert!(args.windows(2).any(|pair| pair == ["-A", "auth-secret"]));
        assert!(args.windows(2).any(|pair| pair == ["-X", "priv-secret"]));
    }

    #[test]
    fn builds_v1_community_auth_arguments() {
        let mut task = snmp_task("192.168.1.20");
        task.payload.insert("version".into(), json!("1"));
        let plan = snmp_poll_plan(task.payload.get("pollPlan")).unwrap();
        let args = snmp_arguments(
            &task.payload,
            &task.secrets,
            "192.168.1.20".parse().unwrap(),
            161,
            1000,
            1,
            &plan,
        )
        .unwrap();
        assert!(args.windows(2).any(|pair| pair == ["-v1", "-c"]));
        assert!(args.windows(2).any(|pair| pair == ["-c", "very-secret"]));
    }

    #[test]
    fn builds_ipv6_snmp_transport_target() {
        let mut task = snmp_task("2001:db8::20");
        task.payload.insert("version".into(), json!("2c"));
        let plan = snmp_poll_plan(task.payload.get("pollPlan")).unwrap();
        let args = snmp_arguments(
            &task.payload,
            &task.secrets,
            "2001:db8::20".parse().unwrap(),
            161,
            1000,
            1,
            &plan,
        )
        .unwrap();

        assert!(args
            .iter()
            .any(|argument| argument == "udp6:[2001:db8::20]:161"));
    }

    #[tokio::test]
    async fn discovery_reports_capabilities_without_spooling_telemetry() {
        let directory = tempfile::tempdir().unwrap();
        let executor = Arc::new(MockExecutor {
            output: CommandOutput {
                success: true,
                stdout: b"No Such Object available on this agent at this OID\nNo Such Object available on this agent at this OID\n".to_vec(),
                stderr: Vec::new(),
            },
            error: None,
            calls: Mutex::new(Vec::new()),
        });
        let context = test_context(directory.path(), executor);
        let mut task = snmp_task("192.168.1.209");
        task.payload.insert("discoveryOnly".into(), json!(true));
        task.payload
            .insert("discoveryToken".into(), json!("discovery-token"));
        let outcome = collect_snmp(&context, &task).await.unwrap();
        assert_eq!(outcome["discoveryOnly"], true);
        assert!(outcome.get("sampleCount").is_none());
        assert!(context.telemetry_spool.oldest::<Value>().unwrap().is_none());
        let report = &outcome["capabilityReport"];
        assert!(sadapp_snmp_profile_engine::capability_discovery::validate_report(report).is_ok());
        let scalar = report["groups"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|group| group["columns"].as_array().unwrap())
            .find(|column| column["oid"] == "1.3.6.1.2.1.2.1.0")
            .unwrap();
        assert_eq!(scalar["status"], "unsupported");
        assert!(!report.to_string().contains("very-secret"));
    }

    #[tokio::test]
    async fn spools_scaled_canonical_snmp_samples() {
        let directory = tempfile::tempdir().unwrap();
        let executor = Arc::new(MockExecutor {
            output: CommandOutput {
                success: true,
                stdout: b"Timeticks: (1234) 0:00:12.34\n2\n".to_vec(),
                stderr: Vec::new(),
            },
            error: None,
            calls: Mutex::new(Vec::new()),
        });
        let context = test_context(directory.path(), executor.clone());
        let outcome = collect_snmp(&context, &snmp_task("192.168.1.20"))
            .await
            .unwrap();
        assert_eq!(outcome["sampleCount"], 2);
        let (_, batch) = context.telemetry_spool.oldest::<Value>().unwrap().unwrap();
        assert_eq!(batch["samples"][0]["value"], 12.34);
        assert_eq!(batch["samples"][0]["collector"]["type"], "SNMP");
        assert!(batch["samples"][0].get("labels").is_none());
        let args = executor.calls.lock().unwrap();
        assert!(args[0].windows(2).any(|pair| pair == ["-c", "very-secret"]));
    }

    #[tokio::test]
    async fn reports_partial_metric_coverage_without_echoing_unusable_values() {
        let directory = tempfile::tempdir().unwrap();
        let executor = Arc::new(MockExecutor {
            output: CommandOutput {
                success: true,
                stdout: b"Timeticks: (1234) 0:00:12.34\nSTRING: \"private device description\"\n"
                    .to_vec(),
                stderr: Vec::new(),
            },
            error: None,
            calls: Mutex::new(Vec::new()),
        });
        let context = test_context(directory.path(), executor);

        let outcome = collect_snmp(&context, &snmp_task("192.168.1.20"))
            .await
            .unwrap();

        assert_eq!(outcome["sampleCount"], 1);
        assert_eq!(outcome["partial"], true);
        assert_eq!(outcome["missingMetrics"][0]["metricKey"], "interface.count");
        assert_eq!(outcome["missingMetrics"][0]["oid"], "1.3.6.1.2.1.2.1.0");
        assert_eq!(outcome["capabilityGroups"][0]["name"], "health");
        assert_eq!(outcome["capabilityGroups"][0]["status"], "complete");
        assert_eq!(outcome["capabilityGroups"][1]["name"], "interfaces");
        assert_eq!(outcome["capabilityGroups"][1]["status"], "unavailable");
        assert!(!Value::Object(outcome.clone())
            .to_string()
            .contains("private device description"));
    }

    #[tokio::test]
    async fn applies_shared_profile_detection_to_bounded_identity_response() {
        let directory = tempfile::tempdir().unwrap();
        let detection_profiles = vec![
            DetectionProfile {
                profile_name: "generic-host".into(),
                schema_version: 1,
                state: ProfileState::Enabled,
                detection: Detection::default(),
            },
            DetectionProfile {
                profile_name: "esphome-snmp".into(),
                schema_version: 1,
                state: ProfileState::Enabled,
                detection: Detection {
                    sys_object_id_prefixes: vec!["1.3.6.1.4.1.99999".into()],
                    sys_descr_regexes: vec!["(?i)esphome".into()],
                    minimum_confidence: 0.8,
                    ..Detection::default()
                },
            },
        ];
        let detection_checksum = detection_bundle_checksum(&detection_profiles).unwrap();
        let executor = Arc::new(SequenceMockExecutor {
            outputs: Mutex::new(VecDeque::from([
                CommandOutput {
                    success: true,
                    stdout: b"1.3.6.1.4.1.99999.1\nESPHome sensor\n".to_vec(),
                    stderr: Vec::new(),
                },
                CommandOutput {
                    success: true,
                    stdout: b"Timeticks: (1234) 0:00:12.34\n2\n".to_vec(),
                    stderr: Vec::new(),
                },
            ])),
            calls: Mutex::new(Vec::new()),
        });
        let context = test_context(directory.path(), executor.clone());
        let mut task = snmp_task("192.168.1.20");
        task.payload.insert(
            "detectionBundle".into(),
            json!({
                "schemaVersion": 1,
                "checksum": detection_checksum,
                "profiles": detection_profiles,
            }),
        );

        let outcome = collect_snmp(&context, &task).await.unwrap();

        assert_eq!(outcome["detectionStatus"], "completed");
        assert_eq!(outcome["detection"]["detectedProfile"], "esphome-snmp");
        assert_eq!(outcome["detection"]["effectiveProfile"], "esphome-snmp");
        assert_eq!(outcome["detection"]["confidence"], 0.95);
        let calls = executor.calls.lock().unwrap();
        assert!(calls.len() >= 2);
        assert!(calls[0].contains(&OID_SNMP_SYS_OBJECT_ID.to_string()));
        assert!(calls[0].contains(&OID_SNMP_SYS_DESCR.to_string()));
        assert!(calls[1].contains(&"1.3.6.1.2.1.1.3.0".to_string()));
    }

    #[tokio::test]
    async fn verifies_snmp_credentials_using_only_sys_object_id_without_spooling() {
        let directory = tempfile::tempdir().unwrap();
        let executor = Arc::new(MockExecutor {
            output: CommandOutput {
                success: true,
                stdout: b".1.3.6.1.4.1.9.1.1208\n".to_vec(),
                stderr: Vec::new(),
            },
            error: None,
            calls: Mutex::new(Vec::new()),
        });
        let context = test_context(directory.path(), executor.clone());
        let mut task = snmp_task("192.168.1.20");
        task.payload.insert("verifyOnly".into(), json!(true));
        task.payload
            .insert("verificationServerId".into(), json!("server-1"));
        task.payload
            .insert("verificationToken".into(), json!("token-1"));
        task.payload.remove("profile");
        task.payload.remove("pollPlan");

        let outcome = collect_snmp(&context, &task).await.unwrap();

        assert_eq!(outcome["verified"], true);
        assert_eq!(outcome["sysObjectId"], "1.3.6.1.4.1.9.1.1208");
        assert!(context.telemetry_spool.oldest::<Value>().unwrap().is_none());
        let calls = executor.calls.lock().unwrap();
        assert!(calls[0]
            .iter()
            .any(|argument| argument == OID_SNMP_SYS_OBJECT_ID));
        assert!(!calls[0]
            .iter()
            .any(|argument| argument == "1.3.6.1.2.1.1.3.0"));
    }

    #[test]
    fn rejects_malformed_snmp_identity_response() {
        assert_eq!(
            parse_snmp_identity_output(b"OID: .1.3.6.1.4.1.9.1.1208\n").unwrap(),
            "1.3.6.1.4.1.9.1.1208"
        );
        assert_eq!(
            parse_snmp_identity_output(b"No Such Object available\n")
                .unwrap_err()
                .code,
            "SNMP_IDENTITY_INVALID"
        );
    }

    #[test]
    fn distinguishes_snmp_authentication_failure_from_target_timeout_without_leaking_details() {
        let authentication_error = classify_snmp_command_failure(&CommandOutput {
            success: false,
            stdout: Vec::new(),
            stderr: b"Authentication failure: incorrect password".to_vec(),
        });
        assert_eq!(authentication_error.code, "SNMP_AUTH_FAILED");
        assert!(!authentication_error.message.contains("password"));

        let timeout_error = classify_snmp_command_failure(&CommandOutput {
            success: false,
            stdout: Vec::new(),
            stderr: b"Timeout: No Response from 10.0.0.5".to_vec(),
        });
        assert_eq!(timeout_error.code, "SNMP_TARGET_TIMEOUT");
    }

    #[tokio::test]
    async fn spools_available_snmp_metrics_when_a_required_oid_is_missing() {
        let directory = tempfile::tempdir().unwrap();
        let executor = Arc::new(MockExecutor {
            output: CommandOutput {
                success: true,
                stdout: b"Timeticks: (200) 0:00:02.00\nNo Such Object available\n".to_vec(),
                stderr: Vec::new(),
            },
            error: None,
            calls: Mutex::new(Vec::new()),
        });
        let context = test_context(directory.path(), executor);
        let mut task = snmp_task("192.168.1.20");
        task.payload.get_mut("pollPlan").unwrap()[1]["required"] = json!(true);
        let outcome = collect_snmp(&context, &task).await.unwrap();
        assert_eq!(outcome["sampleCount"], 1);
        assert_eq!(outcome["partial"], true);
        assert_eq!(outcome["missingMetrics"][0]["metricKey"], "interface.count");
        assert_eq!(outcome["missingMetrics"][0]["required"], true);
        let (_, batch) = context.telemetry_spool.oldest::<Value>().unwrap().unwrap();
        assert_eq!(batch["samples"].as_array().unwrap().len(), 1);
        assert_eq!(batch["samples"][0]["metricKey"], "uptime");
    }

    #[tokio::test]
    async fn command_failures_redact_secrets_and_public_targets_never_execute() {
        let directory = tempfile::tempdir().unwrap();
        let executor = Arc::new(MockExecutor {
            output: CommandOutput {
                success: false,
                stdout: Vec::new(),
                stderr: Vec::new(),
            },
            error: Some("runner leaked very-secret".into()),
            calls: Mutex::new(Vec::new()),
        });
        let context = test_context(directory.path(), executor.clone());
        let error = collect_snmp(&context, &snmp_task("192.168.1.20"))
            .await
            .unwrap_err();
        assert!(!error.message.contains("very-secret"));
        let calls_after_private_target = executor.calls.lock().unwrap().len();
        assert_eq!(calls_after_private_target, 2);
        let public_error = collect_snmp(&context, &snmp_task("8.8.8.8"))
            .await
            .unwrap_err();
        assert_eq!(public_error.code, "TARGET_POLICY_REJECTED");
        assert_eq!(
            executor.calls.lock().unwrap().len(),
            calls_after_private_target
        );
    }

    #[tokio::test]
    async fn wholly_unavailable_metrics_fail_without_spooling_zero_values() {
        let directory = tempfile::tempdir().unwrap();
        let context = test_context(
            directory.path(),
            Arc::new(MockExecutor {
                output: CommandOutput {
                    success: true,
                    stdout: b"No Such Object available\nNo Such Object available\n".to_vec(),
                    stderr: Vec::new(),
                },
                error: None,
                calls: Mutex::new(Vec::new()),
            }),
        );
        let error = collect_snmp(&context, &snmp_task("192.168.1.20"))
            .await
            .unwrap_err();
        assert_eq!(error.code, "SNMP_NO_METRICS");
        assert!(context.telemetry_spool.oldest::<Value>().unwrap().is_none());
    }

    #[tokio::test]
    async fn snmp_tables_reduce_bulk_size_and_fall_back_without_changing_deadline_policy() {
        let directory = tempfile::tempdir().unwrap();
        let too_big = CommandOutput {
            success: false,
            stdout: Vec::new(),
            stderr: b"tooBig".to_vec(),
        };
        let executor = Arc::new(SequenceMockExecutor {
            outputs: Mutex::new(VecDeque::from([
                too_big.clone(),
                too_big,
                CommandOutput {
                    success: true,
                    stdout: format!(".{OID_HR_STORAGE_SIZE}.1 = INTEGER: 100\n").into_bytes(),
                    stderr: Vec::new(),
                },
            ])),
            calls: Mutex::new(Vec::new()),
        });
        let context = test_context(directory.path(), executor.clone());
        let values = snmp_walk_values(
            &context,
            &snmp_task("192.168.1.20"),
            "192.168.1.20".parse().unwrap(),
            161,
            1000,
            1,
            OID_HR_STORAGE_SIZE,
        )
        .await
        .unwrap();
        assert_eq!(values.get(&1).map(String::as_str), Some("INTEGER: 100"));
        let calls = executor.calls.lock().unwrap();
        assert_eq!(calls.len(), 3);
        assert!(calls[0].iter().any(|arg| arg == "-Cr10"));
        assert!(calls[1].iter().any(|arg| arg == "-Cr5"));
        assert!(!calls[2].iter().any(|arg| arg.starts_with("-Cr")));
    }

    #[tokio::test]
    async fn snmp_v1_tables_use_getnext_and_row_limits_do_not_truncate_to_success() {
        let directory = tempfile::tempdir().unwrap();
        let executor = Arc::new(MockExecutor {
            output: CommandOutput {
                success: true,
                stdout: (0..=DEFAULT_TABLE_MAX_ROWS)
                    .map(|index| format!(".{OID_HR_STORAGE_SIZE}.{index} = INTEGER: 100\n"))
                    .collect::<String>()
                    .into_bytes(),
                stderr: Vec::new(),
            },
            error: None,
            calls: Mutex::new(Vec::new()),
        });
        let context = test_context(directory.path(), executor.clone());
        let mut task = snmp_task("192.168.1.20");
        task.payload.insert("version".into(), json!("1"));
        let error = snmp_walk_values(
            &context,
            &task,
            "192.168.1.20".parse().unwrap(),
            161,
            1000,
            1,
            OID_HR_STORAGE_SIZE,
        )
        .await
        .unwrap_err();
        assert!(!error.message.contains("very-secret"));
        let calls = executor.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert!(!calls[0].iter().any(|arg| arg.starts_with("-Cr")));
    }

    #[tokio::test]
    async fn snmp_discovery_caches_only_metadata_and_refreshes_after_reboot_index_or_profile_changes(
    ) {
        let directory = tempfile::tempdir().unwrap();
        let executor = Arc::new(StorageMockExecutor {
            calls: Mutex::new(Vec::new()),
            index: std::sync::atomic::AtomicU32::new(1),
            used: std::sync::atomic::AtomicU32::new(25),
        });
        let context = test_context(directory.path(), executor.clone());
        let mut task = snmp_task("192.168.1.201");
        task.payload
            .insert("serverId".into(), json!("metadata-cache-test"));
        let target = "192.168.1.201".parse().unwrap();
        let first =
            poll_snmp_host_resources(&context, &task, target, 161, 1000, 1, Some(100.0)).await;
        assert_eq!(first.disk, Some((25600.0, 102400.0)));
        assert_eq!(executor.calls.lock().unwrap().len(), 5);
        executor.used.store(50, Ordering::SeqCst);
        let second =
            poll_snmp_host_resources(&context, &task, target, 161, 1000, 1, Some(110.0)).await;
        assert_eq!(second.disk, Some((51200.0, 102400.0)));
        assert_eq!(executor.calls.lock().unwrap().len(), 8);
        poll_snmp_host_resources(&context, &task, target, 161, 1000, 1, Some(1.0)).await;
        assert_eq!(executor.calls.lock().unwrap().len(), 13);
        executor.index.store(2, Ordering::SeqCst);
        poll_snmp_host_resources(&context, &task, target, 161, 1000, 1, Some(2.0)).await;
        assert_eq!(executor.calls.lock().unwrap().len(), 18);
        task.payload.get_mut("profile").unwrap()["checksum"] = json!("b".repeat(64));
        poll_snmp_host_resources(&context, &task, target, 161, 1000, 1, Some(3.0)).await;
        assert_eq!(executor.calls.lock().unwrap().len(), 23);
        task.secrets
            .insert("community-1".into(), "rotated-test-secret".into());
        poll_snmp_host_resources(&context, &task, target, 161, 1000, 1, Some(4.0)).await;
        assert_eq!(executor.calls.lock().unwrap().len(), 28);
        poll_snmp_host_resources(&context, &task, target, 161, 1000, 1, None).await;
        assert_eq!(executor.calls.lock().unwrap().len(), 33);
        assert!(executor
            .calls
            .lock()
            .unwrap()
            .iter()
            .all(|(program, _)| program == "snmpbulkwalk"));
    }

    #[test]
    fn snmp_scalar_transforms_match_shared_worker_semantics() {
        let plan = snmp_poll_plan(Some(&json!([
            { "oid": "1.2.3.0", "metricKey": "memory.free", "scale": 1024, "valueType": "GAUGE", "transform": { "operation": "used_from_free", "total_metric": "memory.total" } },
            { "oid": "1.2.4.0", "metricKey": "memory.total", "scale": 1024, "valueType": "GAUGE" },
            { "oid": "1.2.5.0", "metricKey": "cpu.usage", "scale": 1, "valueType": "GAUGE", "transform": { "operation": "offset", "value": 2 } }
        ]))).unwrap();
        assert_eq!(
            transform_snmp_values(&plan, &[Some(25.0), Some(100.0), Some(10.0)]),
            vec![Some(76800.0), Some(102400.0), Some(12.0)]
        );
        assert_eq!(
            transform_snmp_values(&plan, &[Some(25.0), None, Some(10.0)]),
            vec![None, None, Some(12.0)]
        );
    }

    #[test]
    fn incomplete_disk_rows_never_become_a_successful_whole_host_subtotal() {
        let types = HashMap::from([
            (1, OID_HR_STORAGE_TYPE_FIXED_DISK.to_owned()),
            (2, OID_HR_STORAGE_TYPE_FIXED_DISK.to_owned()),
        ]);
        let units = HashMap::from([(1, "1024".into()), (2, "1024".into())]);
        let sizes = HashMap::from([(1, "100".into()), (2, "200".into())]);
        let mut used = HashMap::from([(1, "25".into())]);
        assert_eq!(
            aggregate_storage_usage(&types, &units, &sizes, &used, StorageKind::FixedDisk),
            None
        );
        used.insert(2, "201".into());
        assert_eq!(
            aggregate_storage_usage(&types, &units, &sizes, &used, StorageKind::FixedDisk),
            None
        );
        used.insert(2, "50".into());
        assert_eq!(
            aggregate_storage_usage(&types, &units, &sizes, &used, StorageKind::FixedDisk),
            Some((76800.0, 307200.0))
        );
    }

    #[tokio::test]
    async fn profile_tables_keep_composite_indexes_live_values_and_cached_metadata() {
        let directory = tempfile::tempdir().unwrap();
        let executor = Arc::new(ProfileTableMockExecutor {
            calls: Mutex::new(Vec::new()),
            used: std::sync::atomic::AtomicU32::new(3),
            index: std::sync::atomic::AtomicU32::new(8),
        });
        let context = test_context(directory.path(), executor.clone());
        let mut task = snmp_task("192.168.1.203");
        task.payload
            .insert("serverId".into(), json!("profile-cache-fixture"));
        let plans: Vec<TablePlan> = serde_json::from_value(profile_table_plan()).unwrap();
        validate_plans(&plans).unwrap();
        let poll = |uptime| {
            let (context, task, plans) = (&context, &task, &plans);
            async move {
                poll_snmp_profile_tables(
                    context,
                    task,
                    "192.168.1.203".parse().unwrap(),
                    161,
                    (1000, 0),
                    Some(uptime),
                    plans,
                    &mut CapabilityRecorder::new(),
                )
                .await
            }
        };
        let (first, issues) = poll(100.0).await;
        assert!(issues.is_empty(), "{issues:?}");
        assert_eq!(first.metrics.len(), 2);
        assert!(first
            .metrics
            .iter()
            .any(|metric| metric.value == 3072.0 && metric.labels["table_index"] == "7.8"));
        assert_eq!(first.inventory[0].name, "Data volume");
        executor.used.store(4, Ordering::SeqCst);
        let (second, issues) = poll(101.0).await;
        assert!(issues.is_empty());
        assert!(second.metrics.iter().any(|metric| metric.value == 4096.0));
        assert_eq!(
            executor
                .calls
                .lock()
                .unwrap()
                .iter()
                .filter(|oid| oid.ends_with(".10.1"))
                .count(),
            1
        );
        poll(1.0).await;
        assert_eq!(
            executor
                .calls
                .lock()
                .unwrap()
                .iter()
                .filter(|oid| oid.ends_with(".10.1"))
                .count(),
            2
        );
        executor.index.store(9, Ordering::SeqCst);
        let (changed, issues) = poll(2.0).await;
        assert!(issues.is_empty());
        assert!(changed
            .metrics
            .iter()
            .all(|metric| metric.labels["table_index"] == "7.9"));
        assert_eq!(
            executor
                .calls
                .lock()
                .unwrap()
                .iter()
                .filter(|oid| oid.ends_with(".10.1"))
                .count(),
            3
        );
    }

    #[tokio::test]
    async fn profile_tables_upload_supplemental_metrics_and_inventory_without_duplicate_history() {
        let directory = tempfile::tempdir().unwrap();
        let executor = Arc::new(ProfileTableMockExecutor {
            calls: Mutex::new(Vec::new()),
            used: std::sync::atomic::AtomicU32::new(3),
            index: std::sync::atomic::AtomicU32::new(8),
        });
        let context = test_context(directory.path(), executor.clone());
        let mut task = snmp_task("192.168.1.204");
        task.payload.remove("detectionBundle");
        task.payload
            .insert("tablePlans".into(), profile_table_plan());
        let result = collect_snmp(&context, &task).await.unwrap();
        let (_, batch) = context.telemetry_spool.oldest::<Value>().unwrap().unwrap();
        assert_eq!(
            batch["samples"].as_array().unwrap().len(),
            result["sampleCount"].as_u64().unwrap() as usize
        );
        let supplemental = batch["samples"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|sample| sample["metadata"]["source"] == "SNMP-profile-tables")
            .collect::<Vec<_>>();
        assert_eq!(supplemental.len(), 2);
        assert!(supplemental
            .iter()
            .all(|sample| sample["metadata"]["legacyProjection"] == false));
        assert_eq!(batch["inventory"][0]["category"], "snmp.profile");
        assert_eq!(
            batch["inventory"][0]["payload"]["entries"][0]["index"],
            "7.8"
        );
        let before = executor.calls.lock().unwrap().len();
        task.payload["tablePlans"][0]["baseOid"] = json!("-c public");
        assert!(collect_snmp(&context, &task).await.is_err());
        assert_eq!(executor.calls.lock().unwrap().len(), before);
    }

    #[tokio::test]
    async fn profile_table_row_limits_preserve_complete_rows_with_explicit_diagnostics() {
        let directory = tempfile::tempdir().unwrap();
        let executor = Arc::new(SequenceMockExecutor {
            outputs: Mutex::new(VecDeque::from([CommandOutput {
                success: true,
                stdout: b".1.3.6.1.4.1.999.10.2.7.8 = Gauge32: 3\n.1.3.6.1.4.1.999.10.2.7.9 = Gauge32: 4\n".to_vec(),
                stderr: Vec::new(),
            }])),
            calls: Mutex::new(Vec::new()),
        });
        let context = test_context(directory.path(), executor);
        let task = snmp_task("192.168.1.205");
        let mut plans: Vec<TablePlan> = serde_json::from_value(profile_table_plan()).unwrap();
        plans[0].max_rows = 1;
        plans[0].columns.retain(|column| column.name == "used");
        let (snapshot, issues) = poll_snmp_profile_tables(
            &context,
            &task,
            "192.168.1.205".parse().unwrap(),
            161,
            (1000, 0),
            Some(100.0),
            &plans,
            &mut CapabilityRecorder::new(),
        )
        .await;
        assert_eq!(snapshot.metrics.len(), 1);
        assert_eq!(snapshot.metrics[0].value, 3072.0);
        assert_eq!(snapshot.metrics[0].labels["table_index"], "7.8");
        assert!(issues
            .iter()
            .any(|issue| issue["code"] == "SNMP_RESPONSE_LIMIT"));
    }

    #[tokio::test]
    async fn standard_tables_spool_canonical_sensors_interfaces_and_inventory_in_bounded_batches() {
        let directory = tempfile::tempdir().unwrap();
        let mut context = test_context(
            directory.path(),
            Arc::new(StandardMockExecutor { rows: 128 }),
        );
        context.telemetry_spool =
            Spool::open(directory.path(), "telemetry", 10, 4 * 1024 * 1024).unwrap();
        let mut task = snmp_task("192.168.1.202");
        task.payload.remove("detectionBundle");
        task.payload
            .insert("serverId".into(), json!("standard-spool-fixture"));
        let result = collect_snmp(&context, &task).await.unwrap();
        let mut samples = Vec::new();
        let mut inventory = Vec::new();
        let mut batches = 0;
        while let Some((path, batch)) = context.telemetry_spool.oldest::<Value>().unwrap() {
            let batch_samples = batch["samples"].as_array().unwrap();
            let batch_inventory = batch["inventory"].as_array().unwrap();
            assert!(batch_samples.len() + batch_inventory.len() <= 500);
            if batches > 0 {
                assert!(batch_samples
                    .iter()
                    .all(|sample| sample["metadata"]["legacyProjection"] == false));
            }
            samples.extend(batch_samples.clone());
            inventory.extend(batch_inventory.clone());
            batches += 1;
            context.telemetry_spool.remove(&path).unwrap();
        }
        assert!(batches > 1);
        assert_eq!(
            samples.len(),
            result["sampleCount"].as_u64().unwrap() as usize
        );
        assert_eq!(inventory.len(), 1);
        assert_eq!(inventory[0]["category"], "snmp.standard");
        assert_eq!(
            inventory[0]["payload"]["entries"].as_array().unwrap().len(),
            256
        );
        let counter = samples
            .iter()
            .find(|sample| {
                sample["metricKey"] == "network.receive.bytes_total"
                    && sample["labels"]["interface_index"] == "1"
            })
            .unwrap();
        assert_eq!(counter["value"], 1000.0);
        assert_eq!(counter["valueType"], "COUNTER");
        assert!(samples.iter().any(
            |sample| sample["metricKey"] == "hardware.temperature.celsius"
                && sample["value"] == 25.0
        ));
        assert!(samples.iter().any(
            |sample| sample["metricKey"] == "network.receive.bytes_total"
                && sample["labels"].is_null()
                && sample["value"] == 128000.0
        ));
    }
}
