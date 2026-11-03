use crate::{UpdateLifecycleState, UpdateStatusPayload, smartctl_device_summary};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    io::{self, Read},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    ptr,
    sync::mpsc,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    System::{Com::CoTaskMemFree, SystemInformation::GetSystemDirectoryW},
    UI::Shell::{FOLDERID_ProgramFiles, SHGetKnownFolderPath},
};

const OUTPUT_LIMIT: usize = 1024 * 1024;
const ERROR_LIMIT: usize = 16 * 1024;

struct Output {
    code: i32,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

#[cfg(test)]
fn run(command: &mut Command, timeout: Duration) -> io::Result<Output> {
    run_cancelable(command, timeout, None)
}

fn run_cancelable(
    command: &mut Command,
    timeout: Duration,
    shutdown: Option<&AtomicBool>,
) -> io::Result<Output> {
    if shutdown.is_some_and(|signal| signal.load(Ordering::Acquire)) {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "Inventory service is stopping",
        ));
    }
    use std::os::windows::process::CommandExt;
    command
        .creation_flags(0x08000000)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("Inventory stdout unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("Inventory stderr unavailable"))?;
    let (sender, receiver) = mpsc::channel();
    let out_sender = sender.clone();
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = stdout
            .take((OUTPUT_LIMIT + 1) as u64)
            .read_to_end(&mut bytes)
            .map(|_| bytes);
        let _ = out_sender.send((true, result));
    });
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = stderr
            .take((ERROR_LIMIT + 1) as u64)
            .read_to_end(&mut bytes)
            .map(|_| bytes);
        let _ = sender.send((false, result));
    });
    let deadline = Instant::now() + timeout;
    let mut output = None;
    let mut errors = None;
    let result = (|| {
        loop {
            if shutdown.is_some_and(|signal| signal.load(Ordering::Acquire)) {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "Inventory service is stopping",
                ));
            }
            while let Ok((stdout, result)) = receiver.try_recv() {
                let bytes = result?;
                let limit = if stdout { OUTPUT_LIMIT } else { ERROR_LIMIT };
                if bytes.len() > limit {
                    return Err(io::Error::other(
                        "Inventory subprocess output exceeds its size budget",
                    ));
                }
                if stdout {
                    output = Some(bytes);
                } else {
                    errors = Some(bytes);
                }
            }
            if let Some(status) = child.try_wait()? {
                if let (Some(stdout), Some(stderr)) = (&mut output, &mut errors) {
                    return Ok(Output {
                        code: status.code().unwrap_or(-1),
                        stdout: std::mem::take(stdout),
                        stderr: std::mem::take(stderr),
                    });
                }
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Inventory subprocess exceeded its deadline",
                ));
            }
            thread::sleep(Duration::from_millis(20));
        }
    })();
    if result.is_err() && child.try_wait()?.is_none() {
        child.kill()?;
        child.wait()?;
    }
    result
}

fn program_files() -> io::Result<PathBuf> {
    let mut folder = ptr::null_mut();
    let result =
        unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramFiles, 0, ptr::null_mut(), &mut folder) };
    if result < 0 || folder.is_null() {
        return Err(io::Error::other(format!(
            "Cannot resolve ProgramFiles ({result:#x})"
        )));
    }
    let path = unsafe {
        let mut length = 0;
        while *folder.add(length) != 0 {
            length += 1;
        }
        let value = String::from_utf16_lossy(std::slice::from_raw_parts(folder, length));
        CoTaskMemFree(folder.cast());
        PathBuf::from(value)
    };
    Ok(path)
}

fn powershell() -> io::Result<PathBuf> {
    let mut buffer = [0_u16; 32768];
    let length = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    if length == 0 || length >= buffer.len() {
        return Err(io::Error::other("Cannot resolve Windows system directory"));
    }
    Ok(PathBuf::from(String::from_utf16_lossy(&buffer[..length]))
        .join("WindowsPowerShell/v1.0/powershell.exe"))
}

fn failure(label: &str, output: &Output) -> io::Error {
    io::Error::other(format!(
        "{label} failed (exit {}): {}",
        output.code,
        String::from_utf8_lossy(&output.stderr)
            .chars()
            .take(500)
            .collect::<String>()
    ))
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct UpdateInventory {
    pending_updates: u64,
    pending_security_updates: u64,
    reboot_required: bool,
    sample: Vec<String>,
    inventory_source: String,
}

fn decode_inventory(bytes: &[u8]) -> io::Result<UpdateInventory> {
    let inventory: UpdateInventory = serde_json::from_slice(bytes).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid Windows Update inventory: {error}"),
        )
    })?;
    if inventory.pending_security_updates > inventory.pending_updates
        || inventory.pending_updates > 10000
        || inventory.sample.len() > 15
        || inventory
            .sample
            .iter()
            .any(|entry| entry.chars().count() > 300)
        || inventory.inventory_source != "windows_update_cached"
    {
        return Err(io::Error::other(
            "Windows Update inventory violates collection bounds",
        ));
    }
    Ok(inventory)
}

fn updates_payload(
    bytes: &[u8],
    now: u64,
    host: &str,
    lifecycle: &UpdateLifecycleState,
) -> io::Result<UpdateStatusPayload> {
    let inventory = decode_inventory(bytes)?;
    Ok(UpdateStatusPayload {
        timestamp: now,
        host_name: host.into(),
        package_manager: Some("windows-update".into()),
        pending_updates: inventory.pending_updates,
        pending_security_updates: inventory.pending_security_updates,
        reboot_required: inventory.reboot_required,
        last_successful_upgrade_at: lifecycle.last_successful_upgrade_at,
        last_failed_update_at: lifecycle.last_failed_update_at,
        last_failed_update_message: lifecycle.last_failed_update_message.clone(),
        package_summary: json!({
            "sample": inventory.sample,
            "inventory_source": inventory.inventory_source,
            "freshness": "Cached Windows Update applicability; this agent does not perform an online scan.",
            "agent": {
                "current_version": lifecycle.current_version, "previous_version": lifecycle.previous_version,
                "desired_version": lifecycle.desired_version, "channel": lifecycle.channel,
                "state": lifecycle.state, "verification_mode": lifecycle.verification_mode,
                "rollback_result": lifecycle.rollback_result,
            }
        }),
        current_version: lifecycle.current_version.clone(),
        previous_version: lifecycle.previous_version.clone(),
        desired_version: lifecycle.desired_version.clone(),
        update_channel: lifecycle.channel.clone(),
        update_state: lifecycle.state.clone(),
        verification_mode: lifecycle.verification_mode.clone(),
        rollback_result: lifecycle.rollback_result.clone(),
    })
}

fn probe_updates(shutdown: Option<&AtomicBool>) -> io::Result<Vec<u8>> {
    let mut command = Command::new(powershell()?);
    // Fixed embedded read-only script; no credentials, interpolation, policy bypass or downloaded scripts.
    command.args([
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        include_str!("windows_update_inventory.ps1"),
    ]);
    let output = run_cancelable(&mut command, Duration::from_secs(60), shutdown)?;
    if output.code != 0 {
        return Err(failure("Windows Update inventory", &output));
    }
    if !output.stderr.is_empty() {
        return Err(failure("Windows Update diagnostics", &output));
    }
    decode_inventory(&output.stdout)?;
    Ok(output.stdout)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InventorySnapshot {
    collected_at: u64,
    inventory: Option<Value>,
    error: Option<String>,
    smart: Option<Value>,
    smart_error: Option<String>,
}

fn snapshot(result: io::Result<Vec<u8>>) -> InventorySnapshot {
    let result = result
        .and_then(|bytes| decode_inventory(&bytes))
        .and_then(|inventory| serde_json::to_value(inventory).map_err(io::Error::other));
    let (inventory, error) = match result {
        Ok(inventory) => (Some(inventory), None),
        Err(error) => (None, Some(error.to_string())),
    };
    InventorySnapshot {
        collected_at: crate::unix_timestamp(),
        inventory,
        error,
        smart: None,
        smart_error: Some("SMART snapshot has not been collected".into()),
    }
}

pub fn produce_snapshots(shutdown: Arc<AtomicBool>) -> io::Result<()> {
    // This service has no request/configuration input, enrollment or telemetry path.
    let file = crate::windows::state_dir()?.join("windows-update-inventory.json");
    while !shutdown.load(Ordering::Acquire) {
        let mut inventory = snapshot(probe_updates(Some(&shutdown)));
        if shutdown.load(Ordering::Acquire) {
            break;
        }
        match direct_smart(Some(&shutdown)) {
            Ok((metrics, warning)) => {
                inventory.smart = Some(metrics);
                inventory.smart_error = warning;
            }
            Err(error) => inventory.smart_error = Some(error.to_string()),
        }
        if shutdown.load(Ordering::Acquire) {
            break;
        }
        let bytes = serde_json::to_vec(&inventory)?;
        if bytes.len() > OUTPUT_LIMIT {
            return Err(io::Error::other(
                "Inventory helper snapshot exceeds size limit",
            ));
        }
        crate::windows::atomic_write(&file, &bytes, true)?;
        let next = Instant::now() + Duration::from_secs(3600);
        while !shutdown.load(Ordering::Acquire) && Instant::now() < next {
            thread::sleep(Duration::from_millis(250));
        }
    }
    Ok(())
}

fn cached_payload(
    bytes: &[u8],
    now: u64,
    host: &str,
    lifecycle: &UpdateLifecycleState,
) -> io::Result<UpdateStatusPayload> {
    let snapshot: InventorySnapshot = serde_json::from_slice(bytes).map_err(io::Error::other)?;
    if snapshot.collected_at > now || now.saturating_sub(snapshot.collected_at) > 7200 {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "Windows Update helper snapshot is stale or future-dated",
        ));
    }
    match (snapshot.inventory, snapshot.error) {
        (Some(inventory), None) => {
            let mut payload = updates_payload(
                &serde_json::to_vec(&inventory)?,
                snapshot.collected_at,
                host,
                lifecycle,
            )?;
            payload.package_summary["inventory_collected_at"] = json!(snapshot.collected_at);
            Ok(payload)
        }
        (None, Some(error)) if !error.is_empty() => {
            Err(io::Error::other(format!("Windows Update helper: {error}")))
        }
        _ => Err(io::Error::other("Invalid Windows Update helper snapshot")),
    }
}

pub fn updates(
    now: u64,
    host: &str,
    lifecycle: &UpdateLifecycleState,
) -> io::Result<UpdateStatusPayload> {
    if !crate::windows::is_service() {
        return updates_payload(&probe_updates(None)?, now, host, lifecycle);
    }
    cached_payload(
        &serde_json::to_vec(&read_snapshot()?)?,
        crate::unix_timestamp(),
        host,
        lifecycle,
    )
}

fn read_snapshot() -> io::Result<InventorySnapshot> {
    let file = crate::windows::state_dir()?.join("windows-update-inventory.json");
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let result = (|| {
            let mut bytes = Vec::new();
            std::fs::File::open(&file)?
                .take((OUTPUT_LIMIT + 1) as u64)
                .read_to_end(&mut bytes)?;
            if bytes.len() > OUTPUT_LIMIT {
                return Err(io::Error::other(
                    "Windows Update helper snapshot exceeds size limit",
                ));
            }
            let snapshot: InventorySnapshot =
                serde_json::from_slice(&bytes).map_err(io::Error::other)?;
            let now = crate::unix_timestamp();
            if snapshot.collected_at > now || now.saturating_sub(snapshot.collected_at) > 7200 {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "Inventory helper snapshot is stale or future-dated",
                ));
            }
            Ok(snapshot)
        })();
        match result {
            Ok(payload) => return Ok(payload),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::WouldBlock
                ) && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(250));
            }
            Err(error) => {
                return Err(io::Error::other(format!(
                    "Protected host inventory helper unavailable: {error}"
                )));
            }
        }
    }
}

fn smart_json(output: Output) -> io::Result<Value> {
    if output.code < 0 || output.code & 7 != 0 || !output.stderr.is_empty() {
        return Err(failure(
            "smartctl query (tool/device access error)",
            &output,
        ));
    }
    serde_json::from_slice(&output.stdout).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid smartctl JSON: {error}"),
        )
    })
}

fn smart_with(
    executable: &Path,
    mut invoke: impl FnMut(&mut Command) -> io::Result<Output>,
) -> io::Result<(Value, Option<String>)> {
    let scan = smart_json(invoke(Command::new(executable).args(["--scan", "-j"]))?)?;
    let entries = scan
        .get("devices")
        .and_then(Value::as_array)
        .ok_or_else(|| io::Error::other("smartctl scan did not provide a device list"))?;
    if entries.is_empty() {
        return Err(io::Error::other(
            "No SMART-capable devices reported by smartctl",
        ));
    }
    let mut devices = Vec::new();
    let mut errors = Vec::new();
    if entries.len() > 8 {
        errors.push("SMART device budget is 8; additional devices were not queried".into());
    }
    for entry in entries.iter().take(8) {
        let result = (|| {
            let name = entry
                .get("name")
                .and_then(Value::as_str)
                .filter(|name| {
                    name.starts_with("/dev/") && !name.contains('\0') && name.len() <= 256
                })
                .ok_or_else(|| io::Error::other("Invalid smartctl scan device name"))?;
            let mut command = Command::new(executable);
            command.args(["-a", "-j", "-n", "standby", name]);
            if let Some(kind) = entry.get("type").and_then(Value::as_str) {
                if kind.len() > 100
                    || !kind
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b",+_-".contains(&byte))
                {
                    return Err(io::Error::other("Invalid smartctl scan device type"));
                }
                command.args(["-d", kind]);
            }
            let raw = smart_json(invoke(&mut command)?)?;
            if raw
                .pointer("/smart_status/passed")
                .and_then(Value::as_bool)
                .is_none()
            {
                return Err(io::Error::other(format!(
                    "SMART health unavailable for {name}: permission/driver support or standby state"
                )));
            }
            Ok(smartctl_device_summary(name, &raw))
        })();
        match result {
            Ok(device) => devices.push(device),
            Err(error) => errors.push(error.to_string()),
        }
    }
    if devices.is_empty() {
        return Err(io::Error::other(errors.join("; ")));
    }
    Ok((
        json!({"collected_at": crate::unix_timestamp(), "devices": devices}),
        (!errors.is_empty()).then(|| errors.join("; ")),
    ))
}

fn direct_smart(shutdown: Option<&AtomicBool>) -> io::Result<(Value, Option<String>)> {
    let executable = program_files()?.join("smartmontools/bin/smartctl.exe");
    if !executable.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Optional smartmontools is missing from ProgramFiles\\smartmontools\\bin; SMART is unavailable",
        ));
    }
    smart_with(&executable, |command| {
        run_cancelable(command, Duration::from_secs(5), shutdown)
    })
}

fn cached_smart(snapshot: InventorySnapshot) -> io::Result<(Value, Option<String>)> {
    match (snapshot.smart, snapshot.smart_error) {
        (Some(metrics), warning)
            if metrics
                .get("devices")
                .and_then(Value::as_array)
                .is_some_and(|devices| !devices.is_empty() && devices.len() <= 8) =>
        {
            Ok((metrics, warning))
        }
        (None, Some(error)) if !error.is_empty() => {
            Err(io::Error::other(format!("SMART inventory helper: {error}")))
        }
        _ => Err(io::Error::other("Invalid SMART helper snapshot")),
    }
}

pub fn smart() -> io::Result<(Value, Option<String>)> {
    if crate::windows::is_service() {
        return cached_smart(read_snapshot()?);
    }
    direct_smart(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn output(code: i32, stdout: &str) -> Output {
        Output {
            code,
            stdout: stdout.as_bytes().to_vec(),
            stderr: Vec::new(),
        }
    }

    #[test]
    fn smart_failure_bits_do_not_hide_failing_drives() {
        assert!(smart_json(output(8, r#"{"smart_status":{"passed":false}}"#)).is_ok());
        for code in [1, 2, 4, -1] {
            assert!(smart_json(output(code, "{}")).is_err());
        }
        assert!(smart_json(output(0, "invalid")).is_err());
    }

    #[test]
    fn smart_inventory_preserves_health_without_serials_and_reports_partial_failure() {
        let mut calls = 0;
        let (value, warning) = smart_with(Path::new("fixture.exe"), |_| {
            calls += 1;
            Ok(match calls {
                1 => output(0, r#"{"devices":[{"name":"/dev/sda","type":"sat"},{"name":"/dev/sdb"}]}"#),
                2 => output(8, r#"{"model_name":"fixture","serial_number":"never-upload","smart_status":{"passed":false},"temperature":{"current":42}}"#),
                _ => output(2, "{}"),
            })
        }).unwrap();
        assert_eq!(calls, 3);
        assert_eq!(value["devices"][0]["health"], "failed");
        assert_eq!(value["devices"][0]["temperature_c"], 42);
        assert!(!value.to_string().contains("never-upload"));
        assert!(warning.is_some());
    }

    #[test]
    fn validates_cached_updates_and_preserves_agent_lifecycle() {
        let lifecycle = UpdateLifecycleState::reconcile(None, "0.2.13", None, "prototype", 100);
        let raw = br#"{"pending_updates":3,"pending_security_updates":2,"reboot_required":true,"sample":["KB fixture"],"inventory_source":"windows_update_cached"}"#;
        let result = updates_payload(raw, 123, "fixture", &lifecycle).unwrap();
        assert_eq!(result.pending_updates, 3);
        assert_eq!(result.pending_security_updates, 2);
        assert!(result.reboot_required);
        assert_eq!(result.package_manager.as_deref(), Some("windows-update"));
        assert_eq!(result.current_version, "0.2.13");
        assert!(updates_payload(br#"{"pending_updates":1,"pending_security_updates":2,"reboot_required":false,"sample":[],"inventory_source":"windows_update_cached"}"#, 123, "fixture", &lifecycle).is_err());
        assert!(updates_payload(b"{}", 123, "fixture", &lifecycle).is_err());
    }

    #[test]
    fn helper_snapshots_preserve_errors_and_reject_stale_or_invalid_data() {
        let lifecycle = UpdateLifecycleState::reconcile(None, "0.2.13", None, "prototype", 100);
        let now = crate::unix_timestamp();
        let raw = br#"{"pending_updates":3,"pending_security_updates":2,"reboot_required":true,"sample":["KB fixture"],"inventory_source":"windows_update_cached"}"#;
        let mut good = snapshot(Ok(raw.to_vec()));
        good.collected_at = now;
        let payload = cached_payload(
            &serde_json::to_vec(&good).unwrap(),
            now,
            "fixture",
            &lifecycle,
        )
        .unwrap();
        assert_eq!(payload.pending_updates, 3);
        assert_eq!(payload.package_summary["inventory_collected_at"], now);
        good.collected_at = now - 7201;
        assert!(
            cached_payload(
                &serde_json::to_vec(&good).unwrap(),
                now,
                "fixture",
                &lifecycle
            )
            .is_err()
        );
        good.collected_at = now + 10;
        assert!(
            cached_payload(
                &serde_json::to_vec(&good).unwrap(),
                now,
                "fixture",
                &lifecycle
            )
            .is_err()
        );
        let failed = snapshot(Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "fixture access denied",
        )));
        assert!(failed.inventory.is_none());
        assert!(
            cached_payload(
                &serde_json::to_vec(&failed).unwrap(),
                failed.collected_at,
                "fixture",
                &lifecycle
            )
            .err()
            .unwrap()
            .to_string()
            .contains("fixture access denied")
        );
        assert!(snapshot(Ok(b"{}".to_vec())).error.is_some());
        assert!(cached_payload(b"{}", now, "fixture", &lifecycle).is_err());
        let mut smart_snapshot = snapshot(Ok(raw.to_vec()));
        smart_snapshot.smart = Some(json!({"devices":[{"device":"/dev/pd0","health":"failed"}]}));
        smart_snapshot.smart_error = Some("fixture partial device failure".into());
        let (metrics, warning) = cached_smart(smart_snapshot).unwrap();
        assert_eq!(metrics["devices"][0]["health"], "failed");
        assert_eq!(warning.as_deref(), Some("fixture partial device failure"));
        assert!(cached_smart(snapshot(Ok(raw.to_vec()))).is_err());
    }

    #[test]
    fn embedded_update_script_counts_localized_classifications_and_reports_search_errors() {
        let fixture = r#"
function New-Object {
    param([string]$ComObject)
    if ($ComObject -eq 'Microsoft.Update.SystemInfo') { return [pscustomobject]@{ RebootRequired = $true } }
    $updates = [pscustomobject]@{ Count = 2 }
    $updates | Add-Member ScriptMethod Item {
        param($index)
        if ($index -eq 0) { return [pscustomobject]@{
            Title='Localized security update'; Categories=@([pscustomobject]@{
                CategoryID='0fa1201d-4330-4fa8-8ae9-b877473b6441'; Name='Not an English label'
            })
        } }
        return [pscustomobject]@{ Title='Critical but not classified security'; Categories=@() }
    }
    $searcher = [pscustomobject]@{ Online = $true; FixtureUpdates = $updates }
    $searcher | Add-Member ScriptMethod Search {
        param($criteria)
        if ($this.Online) { throw 'Online scanning must remain disabled' }
        if ($criteria -ne "IsInstalled=0 and IsHidden=0 and Type='Software'") { throw 'Unexpected search' }
        return [pscustomobject]@{ ResultCode=2; Updates=$this.FixtureUpdates }
    }
    $session = [pscustomobject]@{ FixtureSearcher = $searcher }
    $session | Add-Member ScriptMethod CreateUpdateSearcher { return $this.FixtureSearcher }
    return $session
}
"#;
        let script = format!(
            "{fixture}\n{}",
            include_str!("windows_update_inventory.ps1")
        );
        let result = run(
            Command::new(powershell().unwrap()).args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &script,
            ]),
            Duration::from_secs(10),
        )
        .unwrap();
        assert_eq!(
            result.code,
            0,
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let lifecycle = UpdateLifecycleState::reconcile(None, "0.2.13", None, "prototype", 100);
        let payload = updates_payload(&result.stdout, 123, "fixture", &lifecycle).unwrap();
        assert_eq!(payload.pending_updates, 2);
        assert_eq!(payload.pending_security_updates, 1);
        assert!(payload.reboot_required);
        let failing = format!(
            "function New-Object {{ throw 'fixture access denied' }}\n{}",
            include_str!("windows_update_inventory.ps1")
        );
        let result = run(
            Command::new(powershell().unwrap()).args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &failing,
            ]),
            Duration::from_secs(10),
        )
        .unwrap();
        assert_eq!(result.code, 1);
        assert!(String::from_utf8_lossy(&result.stderr).contains("fixture access denied"));
        assert!(result.stdout.is_empty());
        let incomplete = script.replace("ResultCode=2", "ResultCode=3");
        let result = run(
            Command::new(powershell().unwrap()).args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &incomplete,
            ]),
            Duration::from_secs(10),
        )
        .unwrap();
        assert_eq!(result.code, 1);
        assert!(result.stdout.is_empty());
        assert!(String::from_utf8_lossy(&result.stderr).contains("incomplete"));
    }

    #[test]
    fn native_cached_update_probe_is_read_only_and_bounded() {
        let started = Instant::now();
        let lifecycle = UpdateLifecycleState::reconcile(None, "0.2.13", None, "prototype", 100);
        match updates(123, "fixture", &lifecycle) {
            Ok(payload) => {
                assert_eq!(payload.package_manager.as_deref(), Some("windows-update"));
                assert!(payload.pending_security_updates <= payload.pending_updates);
                println!(
                    "Native cached WUA probe: available (cached inventory, not an online scan)"
                );
            }
            Err(error) => {
                assert!(!error.to_string().trim().is_empty());
                println!("Native cached WUA probe explicitly unavailable: {error}");
            }
        }
        assert!(started.elapsed() < Duration::from_secs(65));
    }

    #[test]
    fn smart_never_invents_healthy_zeroes_or_queries_unbounded_devices() {
        assert!(
            smart_with(Path::new("fixture.exe"), |_| Ok(output(
                0,
                r#"{"devices":[]}"#
            )))
            .is_err()
        );
        let mut calls = 0;
        let mut arguments = Vec::new();
        let result = smart_with(Path::new("fixture.exe"), |command| {
            calls += 1;
            arguments.push(command.get_args().map(|arg| arg.to_string_lossy().into_owned()).collect::<Vec<_>>());
            Ok(if calls == 1 {
                output(0, &json!({"devices": (0..20).map(|index| json!({"name":format!("/dev/pd{index}")})).collect::<Vec<_>>()}).to_string())
            } else {
                output(0, r#"{"smart_status":{"passed":true}}"#)
            })
        }).unwrap();
        assert_eq!(calls, 9);
        assert_eq!(result.0["devices"].as_array().unwrap().len(), 8);
        assert!(result.1.unwrap().contains("additional devices"));
        assert!(
            arguments[1..]
                .iter()
                .all(|args| args.windows(2).any(|pair| pair == ["-n", "standby"]))
        );
        let mut calls = 0;
        assert!(
            smart_with(Path::new("fixture.exe"), |_| {
                calls += 1;
                Ok(if calls == 1 {
                    output(0, r#"{"devices":[{"name":"/dev/sda"}]}"#)
                } else {
                    output(0, "{}")
                })
            })
            .is_err()
        );
    }

    #[test]
    fn subprocesses_are_bounded_and_failures_are_not_success_shaped() {
        let exe = powershell().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let signal = Arc::clone(&shutdown);
        let signal_thread = thread::spawn(move || {
            thread::sleep(Duration::from_millis(200));
            signal.store(true, Ordering::Release);
        });
        let started = Instant::now();
        let error = run_cancelable(
            Command::new(&exe).args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Start-Sleep -Seconds 30",
            ]),
            Duration::from_secs(60),
            Some(&shutdown),
        )
        .err()
        .unwrap();
        signal_thread.join().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert!(started.elapsed() < Duration::from_secs(3));
        let error = run(
            Command::new(&exe).args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Start-Sleep -Seconds 30",
            ]),
            Duration::from_millis(200),
        )
        .err()
        .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        let result = run(
            Command::new(&exe).args(["-NoProfile", "-NonInteractive", "-Command", "exit 7"]),
            Duration::from_secs(10),
        )
        .unwrap();
        assert_eq!(result.code, 7);
        assert!(
            run(
                Command::new(&exe).args([
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "[Console]::Out.Write('x' * 1100000)"
                ]),
                Duration::from_secs(10)
            )
            .is_err()
        );
    }
}
