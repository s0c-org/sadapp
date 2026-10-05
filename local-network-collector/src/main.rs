use std::{
    path::Path,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use rand::Rng;
use sadapp_local_network_collector::{
    api::ApiClient,
    config::{Config, MAX_HEARTBEAT_SECONDS, MIN_HEARTBEAT_SECONDS},
    credentials,
    model::{Credentials, HeartbeatHealth, HeartbeatRequest, TaskResult, PROTOCOL_VERSION},
    runtime_config,
    spool::Spool,
    tasks::{self, TaskContext, TokioCommandExecutor},
};
use sysinfo::{CpuExt, DiskExt, System, SystemExt};
use tokio::{
    sync::{RwLock, Semaphore},
    task::JoinSet,
    time::sleep,
};
use tracing::{debug, info, warn};

const CAPABILITIES: &[&str] = &[
    "discovery",
    "snmp",
    "icmp",
    "tcp",
    "http",
    "prometheus",
    "node_exporter",
    "rest",
];

#[derive(Clone, Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeDiagnostics {
    last_heartbeat_at: Option<DateTime<Utc>>,
    heartbeat_failures: u64,
    consecutive_heartbeat_failures: u64,
    tasks_completed: u64,
    tasks_failed: u64,
    results_acknowledged: u64,
    telemetry_batches_acknowledged: u64,
}

#[derive(Clone)]
struct HealthContext {
    started_at: DateTime<Utc>,
    diagnostics: Arc<RwLock<RuntimeDiagnostics>>,
    draining: Arc<AtomicBool>,
    running: Arc<AtomicUsize>,
    config: runtime_config::SharedCollectorConfig,
    result_spool: Spool,
    telemetry_spool: Spool,
}

fn runtime_health_status(diagnostics: &RuntimeDiagnostics, draining: bool) -> &'static str {
    if draining {
        "draining"
    } else if diagnostics.consecutive_heartbeat_failures > 0 {
        "degraded"
    } else if diagnostics.last_heartbeat_at.is_none() {
        "waiting-for-heartbeat"
    } else {
        "healthy"
    }
}

fn collect_resource_usage(
    system: &mut System,
    state_dir: &Path,
) -> sadapp_local_network_collector::model::CollectorResourceUsage {
    system.refresh_cpu();
    system.refresh_memory();
    system.refresh_disks();

    let state_path = state_dir
        .canonicalize()
        .unwrap_or_else(|_| state_dir.to_path_buf());
    let state_disk = system
        .disks()
        .iter()
        .filter(|disk| state_path.starts_with(disk.mount_point()))
        .max_by_key(|disk| disk.mount_point().components().count());
    let disk_total_bytes = state_disk.map(DiskExt::total_space);
    let disk_used_bytes =
        state_disk.map(|disk| disk.total_space().saturating_sub(disk.available_space()));

    sadapp_local_network_collector::model::CollectorResourceUsage {
        cpu_percent: system.global_cpu_info().cpu_usage().clamp(0.0, 100.0),
        memory_used_bytes: system.used_memory(),
        memory_total_bytes: system.total_memory(),
        disk_mount: state_disk.map(|disk| disk.mount_point().to_string_lossy().into_owned()),
        disk_used_bytes,
        disk_total_bytes,
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_ansi(false)
        .init();
    let config = Config::from_env()?;
    credentials::ensure_state_dir(&config.state_dir)?;
    let api = ApiClient::new(config.control_plane_url.clone())?;
    let (collector_credentials, enrolled_concurrency) = resolve_credentials(&config, &api).await?;
    let max_concurrent = config
        .max_concurrent_tasks
        .min(enrolled_concurrency.unwrap_or(usize::MAX));
    let collector_config = Arc::new(RwLock::new(runtime_config::load(&config.state_dir)?));
    {
        let applied = collector_config.read().await;
        info!(collector_id = %collector_credentials.collector_id, collector_version = env!("CARGO_PKG_VERSION"), protocol_version = PROTOCOL_VERSION, config_revision = applied.revision, network_count = applied.allowed_cidrs.len(), max_concurrent_tasks = max_concurrent, heartbeat_interval_seconds = config.heartbeat_interval.as_secs(), "local network collector started");
        debug!(collector_id = %collector_credentials.collector_id, allowed_cidrs = ?applied.allowed_cidrs, state_dir = %config.state_dir.display(), control_plane = %config.control_plane_url, "collector runtime configuration loaded");
    }
    let result_spool = Spool::open(
        &config.state_dir,
        "task-results",
        config.spool_max_items,
        config.spool_max_bytes,
    )?;
    let telemetry_spool = Spool::open(
        &config.state_dir,
        "telemetry",
        config.spool_max_items,
        config.spool_max_bytes,
    )?;
    let draining = Arc::new(AtomicBool::new(false));
    let running = Arc::new(AtomicUsize::new(0));
    let diagnostics = Arc::new(RwLock::new(RuntimeDiagnostics::default()));
    let semaphore = Arc::new(Semaphore::new(max_concurrent));

    let uploader = tokio::spawn(upload_loop(
        api.clone(),
        collector_credentials.clone(),
        result_spool.clone(),
        telemetry_spool.clone(),
        draining.clone(),
        diagnostics.clone(),
    ));
    if let Some(port) = config.health_port {
        tokio::spawn(health_server(
            port,
            HealthContext {
                started_at: Utc::now(),
                diagnostics: diagnostics.clone(),
                draining: draining.clone(),
                running: running.clone(),
                config: collector_config.clone(),
                result_spool: result_spool.clone(),
                telemetry_spool: telemetry_spool.clone(),
            },
        ));
    }

    let task_context = TaskContext {
        api: api.clone(),
        credentials: collector_credentials.clone(),
        config: collector_config.clone(),
        state_dir: config.state_dir.clone(),
        draining: draining.clone(),
        telemetry_spool: telemetry_spool.clone(),
        command_executor: Arc::new(TokioCommandExecutor),
    };
    let mut tasks = JoinSet::new();
    let mut backoff = config.heartbeat_interval.min(Duration::from_secs(60));
    let mut resource_system = System::new_all();
    resource_system.refresh_all();

    loop {
        if draining.load(Ordering::SeqCst) && running.load(Ordering::SeqCst) == 0 {
            break;
        }
        let spool_stats = combined_stats(&result_spool, &telemetry_spool)?;
        let applied_revision = collector_config.read().await.revision;
        let running_count = running.load(Ordering::SeqCst);
        let resource_usage = collect_resource_usage(&mut resource_system, &config.state_dir);
        let heartbeat = HeartbeatRequest {
            protocol_version: PROTOCOL_VERSION,
            collector_version: env!("CARGO_PKG_VERSION"),
            applied_config_revision: applied_revision,
            capabilities: CAPABILITIES,
            running_task_count: running_count,
            queue_depth: spool_stats.0,
            max_concurrent_tasks: max_concurrent,
            claim_limit: if draining.load(Ordering::SeqCst) {
                0
            } else {
                max_concurrent.saturating_sub(running_count).min(32)
            },
            health: HeartbeatHealth {
                status: "healthy",
                spool_bytes: spool_stats.1,
                spool_items: spool_stats.0,
            },
            resource_usage,
        };

        let next_interval = match api.heartbeat(&collector_credentials, &heartbeat).await {
            Ok(response) => {
                if response.protocol_version != PROTOCOL_VERSION {
                    bail!(
                        "control plane selected unsupported protocol version {}",
                        response.protocol_version
                    );
                }
                backoff = Duration::from_secs(1);
                let interval = Duration::from_secs(
                    response
                        .next_heartbeat_seconds
                        .clamp(MIN_HEARTBEAT_SECONDS, MAX_HEARTBEAT_SECONDS),
                );
                if response.drain {
                    draining.store(true, Ordering::SeqCst);
                }
                info!(collector_id = %collector_credentials.collector_id, config_revision = response.config_revision, applied_config_revision = heartbeat.applied_config_revision, running_tasks = running_count, queue_depth = spool_stats.0, leased_tasks = response.tasks.len(), drain = response.drain, next_heartbeat_seconds = response.next_heartbeat_seconds, "collector heartbeat accepted");
                if let Some(configuration) = response.configuration {
                    let network_count = configuration
                        .get("allowedCidrs")
                        .and_then(serde_json::Value::as_array)
                        .map_or(0, Vec::len);
                    apply_heartbeat_config(
                        &config.state_dir,
                        &collector_config,
                        response.config_revision,
                        configuration,
                    )
                    .await?;
                    info!(collector_id = %collector_credentials.collector_id, config_revision = response.config_revision, network_count, "collector configuration applied");
                }
                {
                    let mut health = diagnostics.write().await;
                    health.last_heartbeat_at = Some(Utc::now());
                    health.consecutive_heartbeat_failures = 0;
                }
                for lease in response.tasks {
                    if draining.load(Ordering::SeqCst) {
                        break;
                    }
                    let permit = match semaphore.clone().try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => break,
                    };
                    let context = task_context.clone();
                    let spool = result_spool.clone();
                    let running = running.clone();
                    let diagnostics = diagnostics.clone();
                    running.fetch_add(1, Ordering::SeqCst);
                    tasks.spawn(async move {
                        let _permit = permit;
                        info!(task_id = %lease.id, task_type = ?lease.task_type, "collector task started");
                        let result = tasks::execute(&context, lease).await;
                        info!(task_id = %result.task_id, status = ?result.status, error_code = ?result.error_code, "collector task completed");
                        {
                            let mut health = diagnostics.write().await;
                            health.tasks_completed += 1;
                            if matches!(result.status, sadapp_local_network_collector::model::TaskResultStatus::Failed) {
                                health.tasks_failed += 1;
                            }
                        }
                        if let Err(error) = spool.push(&result) {
                            warn!(%error, "failed to spool task result");
                        }
                        running.fetch_sub(1, Ordering::SeqCst);
                    });
                }
                interval
            }
            Err(error) => {
                {
                    let mut health = diagnostics.write().await;
                    health.heartbeat_failures += 1;
                    health.consecutive_heartbeat_failures += 1;
                }
                warn!(collector_id = %collector_credentials.collector_id, %error, retry_in_seconds = backoff.as_secs(), "collector heartbeat failed; retry scheduled");
                let interval = backoff;
                backoff = (backoff * 2).min(Duration::from_secs(60));
                interval
            }
        };
        let jitter = rand::thread_rng().gen_range(0.9..=1.1);
        tokio::select! {
            _ = sleep(next_interval.mul_f64(jitter)) => {},
            _ = tokio::signal::ctrl_c() => { info!("shutdown requested; entering drain mode"); draining.store(true, Ordering::SeqCst); }
        }
        while tasks.try_join_next().is_some() {}
    }

    while tasks.join_next().await.is_some() {}
    let flush_deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while combined_stats(&result_spool, &telemetry_spool)?.0 > 0
        && tokio::time::Instant::now() < flush_deadline
    {
        sleep(Duration::from_millis(250)).await;
    }
    uploader.abort();
    Ok(())
}

async fn resolve_credentials(
    config: &Config,
    api: &ApiClient,
) -> Result<(Credentials, Option<usize>)> {
    if let Some(credentials) = credentials::load(&config.state_dir)? {
        return Ok((credentials, None));
    }
    if let (Some(collector_id), Some(collector_secret)) =
        (&config.collector_id, &config.collector_secret)
    {
        return Ok((
            Credentials {
                collector_id: collector_id.clone(),
                collector_secret: collector_secret.clone(),
            },
            None,
        ));
    }
    let token = config
        .enrollment_token
        .as_deref()
        .context("ENROLLMENT_TOKEN or persisted/explicit collector credentials are required")?;
    let response = api.enroll(token).await?;
    let credentials = Credentials {
        collector_id: response.collector_id,
        collector_secret: response.collector_secret,
    };
    credentials::persist(&config.state_dir, &credentials)?;
    info!(collector_id = %credentials.collector_id, "collector enrollment completed");
    Ok((credentials, Some(response.max_concurrent_tasks)))
}

async fn apply_heartbeat_config(
    state_dir: &std::path::Path,
    shared: &runtime_config::SharedCollectorConfig,
    revision: u64,
    value: serde_json::Map<String, serde_json::Value>,
) -> Result<()> {
    let allowed_cidrs = value
        .get("allowedCidrs")
        .and_then(serde_json::Value::as_array)
        .context("heartbeat configuration omitted allowedCidrs")?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .context("allowedCidrs must contain strings")
        })
        .collect::<Result<Vec<_>>>()?;
    let updated = runtime_config::CollectorConfig {
        revision,
        allowed_cidrs,
    };
    if revision < shared.read().await.revision {
        bail!("heartbeat configuration revision is older than the applied configuration");
    }
    runtime_config::persist(state_dir, &updated)?;
    *shared.write().await = updated;
    Ok(())
}

async fn upload_loop(
    api: ApiClient,
    credentials: Credentials,
    results: Spool,
    telemetry: Spool,
    draining: Arc<AtomicBool>,
    diagnostics: Arc<RwLock<RuntimeDiagnostics>>,
) {
    loop {
        let mut progressed = false;
        match results.oldest::<TaskResult>() {
            Ok(Some((path, result))) => match api.submit_result(&credentials, &result).await {
                Ok(()) => match results.remove(&path) {
                    Ok(()) => {
                        diagnostics.write().await.results_acknowledged += 1;
                        info!(task_id = %result.task_id, "task result acknowledged by control plane");
                        progressed = true;
                    }
                    Err(error) => warn!(%error, "failed to remove acknowledged task result"),
                },
                Err(error) => warn!(%error, "task result upload failed"),
            },
            Ok(None) => {}
            Err(error) => warn!(%error, "task result spool read failed"),
        }
        match telemetry.oldest::<serde_json::Value>() {
            Ok(Some((path, batch))) => match api.submit_telemetry(&credentials, &batch).await {
                Ok(()) => match telemetry.remove(&path) {
                    Ok(()) => {
                        diagnostics.write().await.telemetry_batches_acknowledged += 1;
                        info!("telemetry batch acknowledged by control plane");
                        progressed = true;
                    }
                    Err(error) => warn!(%error, "failed to remove acknowledged telemetry batch"),
                },
                Err(error) => warn!(%error, "telemetry upload failed"),
            },
            Ok(None) => {}
            Err(error) => warn!(%error, "telemetry spool read failed"),
        }
        if !progressed {
            sleep(if draining.load(Ordering::SeqCst) {
                Duration::from_secs(1)
            } else {
                Duration::from_secs(5)
            })
            .await;
        }
    }
}

fn combined_stats(results: &Spool, telemetry: &Spool) -> Result<(usize, u64)> {
    let results = results.stats()?;
    let telemetry = telemetry.stats()?;
    Ok((
        results.items + telemetry.items,
        results.bytes + telemetry.bytes,
    ))
}

async fn health_server(port: u16, context: HealthContext) {
    let app = axum::Router::new().route("/health", axum::routing::get(move || {
        let context = context.clone();
        async move {
            let diagnostics = context.diagnostics.read().await.clone();
            let config = context.config.read().await.clone();
            let spool = combined_stats(&context.result_spool, &context.telemetry_spool);
            axum::Json(serde_json::json!({
                "status": if spool.is_err() { "degraded" } else { runtime_health_status(&diagnostics, context.draining.load(Ordering::SeqCst)) },
                "version": env!("CARGO_PKG_VERSION"),
                "uptimeSeconds": Utc::now().signed_duration_since(context.started_at).num_seconds().max(0),
                "activity": diagnostics,
                "runningTasks": context.running.load(Ordering::SeqCst),
                "queueDepth": spool.as_ref().ok().map(|stats| stats.0),
                "spoolBytes": spool.as_ref().ok().map(|stats| stats.1),
                "configRevision": config.revision,
                "allowedNetworkCount": config.allowed_cidrs.len(),
                "capabilities": CAPABILITIES,
            }))
        }
    }));
    let address = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    match tokio::net::TcpListener::bind(address).await {
        Ok(listener) => {
            if let Err(error) = axum::serve(listener, app).await {
                warn!(%error, "health server stopped");
            }
        }
        Err(error) => warn!(%error, "health server could not bind"),
    }
}

#[cfg(test)]
mod tests {
    use std::{net::IpAddr, sync::Arc};

    use serde_json::json;
    use tokio::sync::RwLock;

    use super::apply_heartbeat_config;
    use super::{runtime_health_status, RuntimeDiagnostics};
    use sadapp_local_network_collector::runtime_config::{self, CollectorConfig};

    #[test]
    fn health_distinguishes_initial_connection_retry_and_drain() {
        let mut diagnostics = RuntimeDiagnostics::default();
        assert_eq!(
            runtime_health_status(&diagnostics, false),
            "waiting-for-heartbeat"
        );
        diagnostics.last_heartbeat_at = Some(chrono::Utc::now());
        assert_eq!(runtime_health_status(&diagnostics, false), "healthy");
        diagnostics.consecutive_heartbeat_failures = 1;
        assert_eq!(runtime_health_status(&diagnostics, false), "degraded");
        assert_eq!(runtime_health_status(&diagnostics, true), "draining");
        let serialized = serde_json::to_value(diagnostics).unwrap();
        assert!(serialized.get("lastHeartbeatAt").is_some());
        assert!(serialized.get("consecutiveHeartbeatFailures").is_some());
        assert!(serialized.get("collectorSecret").is_none());
    }

    #[tokio::test]
    async fn initial_heartbeat_config_applies_cidrs_and_persists_revision() {
        let directory = tempfile::tempdir().unwrap();
        let shared = Arc::new(RwLock::new(CollectorConfig::default()));
        let configuration = json!({
            "allowedCidrs": ["10.20.0.0/16"],
            "discoveryEnabled": true,
            "autoAddEnabled": false,
            "siteKey": "office",
            "limits": { "maxConcurrentTasks": 4 }
        })
        .as_object()
        .unwrap()
        .clone();

        apply_heartbeat_config(directory.path(), &shared, 0, configuration)
            .await
            .unwrap();

        let persisted = runtime_config::load(directory.path()).unwrap();
        assert_eq!(persisted.revision, 0);
        assert_eq!(persisted.allowed_cidrs, vec!["10.20.0.0/16"]);
        assert!(persisted
            .policy()
            .unwrap()
            .allows("10.20.1.2".parse::<IpAddr>().unwrap()));
    }
}
