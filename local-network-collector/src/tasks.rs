use std::{
    future::Future,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    pin::Pin,
    process::Stdio,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
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
use sadapp_snmp_profile_engine::{
    detect as detect_snmp_profiles, detection_bundle_checksum, metric_capability_group,
    DetectionProfile, IdentityProbe,
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
const MAX_SNMP_STORAGE_ROWS: usize = 256;
const MAX_SNMP_WALK_BYTES: usize = 128 * 1024;
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
}

#[derive(Debug)]
pub struct TokioCommandExecutor;

impl CommandExecutor for TokioCommandExecutor {
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
    let mut response = request.send().await.map_err(|error| {
        let message = if error.is_timeout() {
            "request timed out"
        } else if error.is_connect() {
            "connection failed"
        } else {
            "request failed"
        };
        TaskError::failed("HTTP_REQUEST_FAILED", message)
    })?;
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
            .is_none_or(|value| value.split(';').next() != Some("application/json"))
    {
        return Err(TaskError::failed(
            "REST_CONTENT_TYPE",
            "REST response must be application/json",
        ));
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
                },
                SnmpPollEntry {
                    oid: OID_SNMP_SYS_DESCR.into(),
                    metric_key: "snmp.sys_descr".into(),
                    unit: None,
                    scale: 1.0,
                    value_type: "GAUGE".into(),
                    required: false,
                    labels: None,
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
    let values = parse_snmp_output(&output.stdout, &poll_plan)?;
    let mut group_counts =
        std::collections::BTreeMap::<&'static str, (usize, usize, Vec<Value>)>::new();
    let mut missing_metrics = Vec::new();
    for (entry, value) in poll_plan.iter().zip(&values) {
        let available = value
            .and_then(|value| scale_snmp_value(value, entry.scale))
            .is_some();
        let group = metric_capability_group(&entry.metric_key);
        let counts = group_counts.entry(group).or_default();
        counts.0 += 1;
        if available {
            counts.1 += 1;
        } else {
            let missing = json!({ "metricKey": entry.metric_key, "oid": entry.oid });
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
            let value = scale_snmp_value(value?, entry.scale)?;
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
    let host_resources =
        poll_snmp_host_resources(context, task, target, port, timeout_ms, retries).await;
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
    if samples.is_empty() {
        return Err(TaskError::failed(
            "SNMP_NO_METRICS",
            "SNMP returned no usable profile metrics",
        ));
    }
    context
        .telemetry_spool
        .push(&json!({ "idempotencyKey": format!("task:{}", task.id), "samples": samples, "inventory": [] }))
        .map_err(TaskError::internal)?;
    Ok(json_object(json!({
        "success": true,
        "latencyMs": started.elapsed().as_secs_f64() * 1000.0,
        "sampleCount": samples.len(),
        "partial": !missing_metrics.is_empty(),
        "missingMetrics": missing_metrics,
        "capabilityGroups": capability_groups,
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
}

async fn poll_snmp_host_resources(
    context: &TaskContext,
    task: &TaskLease,
    target: IpAddr,
    port: u16,
    timeout_ms: u64,
    retries: u64,
) -> HostResourceUsage {
    let walk =
        |oid: &'static str| snmp_walk_values(context, task, target, port, timeout_ms, retries, oid);
    let (storage_types, allocation_units, sizes, used, processor_load) = tokio::join!(
        walk(OID_HR_STORAGE_TYPE),
        walk(OID_HR_STORAGE_ALLOC_UNITS),
        walk(OID_HR_STORAGE_SIZE),
        walk(OID_HR_STORAGE_USED),
        walk(OID_HR_PROCESSOR_LOAD),
    );
    let mut usage = HostResourceUsage {
        cpu_utilization: processor_load.as_ref().and_then(average_processor_load),
        ..HostResourceUsage::default()
    };
    if let (Some(storage_types), Some(allocation_units), Some(sizes), Some(used)) =
        (storage_types, allocation_units, sizes, used)
    {
        usage.disk = aggregate_storage_usage(
            &storage_types,
            &allocation_units,
            &sizes,
            &used,
            StorageKind::FixedDisk,
        );
        usage.memory = aggregate_storage_usage(
            &storage_types,
            &allocation_units,
            &sizes,
            &used,
            StorageKind::Ram,
        );
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
    let mut total_used = 0.0;
    let mut total_size = 0.0;
    for (index, storage_type) in storage_types {
        if !kind.matches(storage_type) {
            continue;
        }
        let (Some(unit), Some(size), Some(used_units)) = (
            allocation_units
                .get(index)
                .and_then(|value| parse_snmp_number(value).ok()),
            sizes
                .get(index)
                .and_then(|value| parse_snmp_number(value).ok()),
            used.get(index)
                .and_then(|value| parse_snmp_number(value).ok()),
        ) else {
            continue;
        };
        if unit <= 0.0 || size < 0.0 || used_units < 0.0 {
            continue;
        }
        total_size += unit * size;
        total_used += unit * used_units;
    }
    (total_size > 0.0 && total_used.is_finite() && total_size.is_finite())
        .then_some((total_used, total_size))
}

async fn snmp_walk_values(
    context: &TaskContext,
    task: &TaskLease,
    target: IpAddr,
    port: u16,
    timeout_ms: u64,
    retries: u64,
    oid: &str,
) -> Option<std::collections::HashMap<u32, String>> {
    let mut args = snmp_arguments(
        &task.payload,
        &task.secrets,
        target,
        port,
        timeout_ms,
        retries,
        &[],
    )
    .ok()?;
    args.retain(|argument| argument != "-Oqv");
    args.push(oid.to_owned());
    let duration =
        Duration::from_millis(timeout_ms.saturating_mul(retries + 1).saturating_add(2_000))
            .min(Duration::from_secs(12));
    let output = timeout(duration, context.command_executor.run("snmpwalk", &args))
        .await
        .ok()?
        .ok()?;
    if !output.success || output.stdout.len() > MAX_SNMP_WALK_BYTES {
        return None;
    }
    let output = std::str::from_utf8(&output.stdout).ok()?;
    Some(parse_snmp_walk_values(output, oid))
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
        values.insert(index, value.trim().to_owned());
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
        .zip(poll_plan)
        .map(|(line, entry)| match parse_snmp_number(line) {
            Ok(value) => Ok(Some(value)),
            Err(error)
                if matches!(
                    error.code.as_str(),
                    "SNMP_NO_SUCH_OID" | "SNMP_NON_FINITE" | "SNMP_PARSE_FAILED"
                ) && !entry.required =>
            {
                Ok(None)
            }
            Err(error)
                if matches!(
                    error.code.as_str(),
                    "SNMP_NO_SUCH_OID" | "SNMP_NON_FINITE" | "SNMP_PARSE_FAILED"
                ) =>
            {
                Err(TaskError::failed(
                    "SNMP_REQUIRED_METRIC_UNAVAILABLE",
                    format!(
                        "required metric '{}' (OID {}) is unavailable or unusable",
                        entry.metric_key, entry.oid
                    ),
                ))
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
            },
            SnmpPollEntry {
                oid: "1.3.6.1.2.1.2.1.0".into(),
                metric_key: "network.interface.count".into(),
                unit: None,
                scale: 1.0,
                value_type: "GAUGE".into(),
                required: false,
                labels: None,
            },
            SnmpPollEntry {
                oid: "1.3.6.1.2.1.25.2.2.0".into(),
                metric_key: "system.memory.total_bytes".into(),
                unit: None,
                scale: 1.0,
                value_type: "GAUGE".into(),
                required: false,
                labels: None,
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
    fn fails_for_unavailable_required_metrics_without_echoing_device_values() {
        let poll_plan = [SnmpPollEntry {
            oid: "1.3.6.1.2.1.1.3.0".into(),
            metric_key: "system.uptime.seconds".into(),
            unit: None,
            scale: 1.0,
            value_type: "GAUGE".into(),
            required: true,
            labels: None,
        }];
        let error =
            parse_snmp_output(b"STRING: \"private device description\"\n", &poll_plan).unwrap_err();

        assert_eq!(error.code, "SNMP_REQUIRED_METRIC_UNAVAILABLE");
        assert!(error.message.contains("system.uptime.seconds"));
        assert!(error.message.contains("1.3.6.1.2.1.1.3.0"));
        assert!(!error.message.contains("private device description"));
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
    async fn spools_available_snmp_metrics_when_an_optional_oid_is_missing() {
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
        let outcome = collect_snmp(&context, &snmp_task("192.168.1.20"))
            .await
            .unwrap();
        assert_eq!(outcome["sampleCount"], 1);
        assert_eq!(outcome["partial"], true);
        assert_eq!(outcome["missingMetrics"][0]["metricKey"], "interface.count");
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
}
