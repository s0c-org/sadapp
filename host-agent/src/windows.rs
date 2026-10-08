use crate::windows_config::WindowsConfig;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{self, IsTerminal, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use windows_service::{
    define_windows_service,
    service::{
        ServiceAccess, ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState,
        ServiceStatus, ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult, ServiceStatusHandle},
    service_dispatcher,
    service_manager::{ServiceManager, ServiceManagerAccess},
};
use windows_sys::Win32::{
    Foundation::LocalFree,
    Security::{
        Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW,
        Cryptography::{
            CRYPT_INTEGER_BLOB, CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_UI_FORBIDDEN,
            CryptProtectData, CryptUnprotectData,
        },
        DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
        SetFileSecurityW,
    },
    Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
        MoveFileExW,
    },
    System::Console::{
        ENABLE_ECHO_INPUT, GetConsoleMode, GetStdHandle, STD_INPUT_HANDLE, SetConsoleMode,
    },
};

pub const SERVICE_NAME: &str = "SadappHostAgent";
static SERVICE_MODE: AtomicBool = AtomicBool::new(false);
static LOG_FAILED: AtomicBool = AtomicBool::new(false);
static LOG: OnceLock<std::sync::Mutex<std::fs::File>> = OnceLock::new();

fn service_sid() -> String {
    service_sid_for(SERVICE_NAME)
}

fn service_sid_for(service_name: &str) -> String {
    // Windows service SIDs are SHA-1 of the upper-case UTF-16LE service name.
    let name: Vec<u8> = service_name
        .to_uppercase()
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &name);
    let mut sid = String::from("S-1-5-80");
    for chunk in digest.as_ref().chunks_exact(4) {
        let value = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        sid.push_str(&format!("-{value}"));
    }
    sid
}

pub fn is_service() -> bool {
    SERVICE_MODE.load(Ordering::Acquire)
}

pub fn check_logging() -> io::Result<()> {
    if LOG_FAILED.load(Ordering::Acquire) {
        Err(io::Error::other(
            "Agent service logging failed; stopping instead of running without diagnostics",
        ))
    } else {
        Ok(())
    }
}

pub fn state_dir() -> io::Result<PathBuf> {
    use windows_sys::Win32::{
        System::Com::CoTaskMemFree,
        UI::Shell::{FOLDERID_ProgramData, SHGetKnownFolderPath},
    };
    let mut folder = ptr::null_mut();
    let result =
        unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramData, 0, ptr::null_mut(), &mut folder) };
    if result < 0 {
        return Err(io::Error::other(format!(
            "Cannot resolve ProgramData (HRESULT {result:#x})"
        )));
    }
    let base = unsafe {
        let mut length = 0;
        while *folder.add(length) != 0 {
            length += 1;
        }
        let path = PathBuf::from(String::from_utf16_lossy(std::slice::from_raw_parts(
            folder, length,
        )));
        CoTaskMemFree(folder.cast());
        path
    };
    Ok(base.join("Sadapp").join("HostAgent"))
}

fn wide(value: &std::ffi::OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}

fn reject_reparse(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 => {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Agent paths cannot be reparse points",
            ))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

pub fn protect(path: &Path, read_only_service: bool) -> io::Result<()> {
    reject_reparse(path)?;
    let service_rights = if read_only_service { "FR" } else { "FA" };
    let sid = service_sid();
    // Limit implicit owner rights: LocalService is shared, but access uses this service's SID.
    let descriptor = if path.is_dir() {
        let rights = if read_only_service { "GRGX" } else { "FA" };
        format!("D:P(A;OICI;RC;;;OW)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;{rights};;;{sid})")
    } else {
        format!("D:P(A;;RC;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)(A;;{service_rights};;;{sid})")
    };
    let descriptor = if read_only_service {
        format!("O:BA{descriptor}")
    } else {
        descriptor
    };
    let descriptor = wide(std::ffi::OsStr::new(&descriptor));
    let path = wide(path.as_os_str());
    let mut security_descriptor = ptr::null_mut();
    // Windows allocates this descriptor; it must be freed with LocalFree.
    unsafe {
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            descriptor.as_ptr(),
            1,
            &mut security_descriptor,
            ptr::null_mut(),
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
        let applied = SetFileSecurityW(
            path.as_ptr(),
            DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION
                | if read_only_service {
                    OWNER_SECURITY_INFORMATION
                } else {
                    0
                },
            security_descriptor,
        );
        let error = (applied == 0).then(io::Error::last_os_error);
        LocalFree(security_descriptor);
        if let Some(error) = error {
            return Err(error);
        }
    }
    Ok(())
}

pub fn prepare_state_dir() -> io::Result<PathBuf> {
    let path = state_dir()?;
    let parent = path.parent().expect("agent state directory has a parent");
    reject_reparse(parent)?;
    reject_reparse(&path)?;
    fs::create_dir_all(&path)?;
    protect(parent, true)?;
    protect(&path, true)?;
    let state = path.join("state");
    reject_reparse(&state)?;
    fs::create_dir_all(&state)?;
    protect(&state, false)?;
    Ok(path)
}

pub fn atomic_write(path: &Path, data: &[u8], read_only_service: bool) -> io::Result<()> {
    reject_reparse(path)?;
    let mut random = [0_u8; 16];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut random)
        .map_err(|_| io::Error::other("Cannot generate temporary file name"))?;
    let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    let temporary = path.with_extension(format!("{suffix}.tmp"));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        protect(&temporary, false)?;
        file.write_all(data)?;
        file.sync_all()?;
        drop(file);
        protect(&temporary, read_only_service)?;
        let source = wide(temporary.as_os_str());
        let target = wide(path.as_os_str());
        // Unlike rename assumptions across platforms, replacement and durability are explicit.
        if unsafe {
            MoveFileExW(
                source.as_ptr(),
                target.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    })();
    if result.is_err() {
        match fs::remove_file(&temporary) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => eprintln!("Cannot clean up agent temporary file: {error}"),
        }
    }
    result
}

fn dpapi(data: &[u8], encrypt: bool) -> io::Result<Vec<u8>> {
    let size = u32::try_from(data.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Configuration is too large"))?;
    let input = CRYPT_INTEGER_BLOB {
        cbData: size,
        pbData: data.as_ptr().cast_mut(),
    };
    let mut output: CRYPT_INTEGER_BLOB = unsafe { std::mem::zeroed() };
    // Machine scope allows the installer administrator and LocalService to share configuration.
    // File ACLs, not machine DPAPI alone, restrict which local users can obtain the ciphertext.
    unsafe {
        let result = if encrypt {
            CryptProtectData(
                &input,
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        } else {
            CryptUnprotectData(
                &input,
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        };
        if result == 0 {
            return Err(io::Error::last_os_error());
        }
        let decoded = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        std::slice::from_raw_parts_mut(output.pbData, output.cbData as usize).fill(0);
        LocalFree(output.pbData.cast());
        Ok(decoded)
    }
}

pub fn load_config() -> io::Result<WindowsConfig> {
    let path = state_dir()?.join("config.dpapi");
    reject_reparse(path.parent().expect("configuration has a parent"))?;
    reject_reparse(&path)?;
    let encoded = fs::read(&path)?;
    let mut plaintext = dpapi(&encoded, false)?;
    let parsed = serde_json::from_slice(&plaintext).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid protected agent configuration",
        )
    });
    plaintext.fill(0);
    let config: WindowsConfig = parsed?;
    config.validate()?;
    Ok(config)
}

fn require_admin() -> io::Result<()> {
    use windows_sys::Win32::Security::{
        CheckTokenMembership, CreateWellKnownSid, SECURITY_MAX_SID_SIZE,
        WinBuiltinAdministratorsSid,
    };
    let mut sid = [0_u8; SECURITY_MAX_SID_SIZE as usize];
    let mut size = sid.len() as u32;
    let mut member = 0;
    unsafe {
        if CreateWellKnownSid(
            WinBuiltinAdministratorsSid,
            ptr::null_mut(),
            sid.as_mut_ptr().cast(),
            &mut size,
        ) == 0
            || CheckTokenMembership(ptr::null_mut(), sid.as_ptr().cast_mut().cast(), &mut member)
                == 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    if member == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Run this command in an elevated Administrator console",
        ));
    }
    Ok(())
}

fn require_stopped() -> Result<(), Box<dyn std::error::Error>> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    match manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
        Ok(service) if service.query_status()?.current_state != ServiceState::Stopped => {
            Err("Stop SadappHostAgent before changing or deleting its configuration".into())
        }
        Ok(_) => Ok(()),
        Err(windows_service::Error::Winapi(error)) if error.raw_os_error() == Some(1060) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn prompt(label: &str, secret: bool) -> io::Result<String> {
    print!("{label}");
    io::stdout().flush()?;
    struct RestoreEcho(windows_sys::Win32::Foundation::HANDLE, u32);
    impl Drop for RestoreEcho {
        fn drop(&mut self) {
            if unsafe { SetConsoleMode(self.0, self.1) } == 0 {
                eprintln!(
                    "Cannot restore console input mode: {}",
                    io::Error::last_os_error()
                );
            }
        }
    }
    let restore = if secret && io::stdin().is_terminal() {
        let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
        let mut mode = 0;
        if unsafe { GetConsoleMode(handle, &mut mode) } == 0
            || unsafe { SetConsoleMode(handle, mode & !ENABLE_ECHO_INPUT) } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Some(RestoreEcho(handle, mode))
    } else {
        None
    };
    let mut value = String::new();
    if io::stdin().read_line(&mut value)? == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "Configuration input ended",
        ));
    }
    if restore.is_some() {
        println!();
    }
    drop(restore);
    Ok(value.trim().to_string())
}

pub fn configure() -> Result<(), Box<dyn std::error::Error>> {
    require_admin()?;
    require_stopped()?;
    let endpoint = prompt(
        "HTTPS endpoint (blank uses https://sadapp.org/api/v1/agent): ",
        false,
    )?;
    let invitation = prompt("Invitation token (hidden; blank uses a key pair): ", true)?;
    let (invite_token, key_id, key_secret) = if invitation.is_empty() {
        (
            None,
            Some(prompt("Key ID: ", false)?),
            Some(prompt("Key secret (hidden): ", true)?),
        )
    } else {
        (Some(invitation), None, None)
    };
    let config = WindowsConfig {
        version: 1,
        endpoint: if endpoint.is_empty() {
            crate::DEFAULT_ENDPOINT.into()
        } else {
            endpoint
        },
        invite_token,
        key_id,
        key_secret,
        interval_seconds: 30,
    };
    config.validate()?;
    let path = prepare_state_dir()?.join("config.dpapi");
    let mut encoded = serde_json::to_vec(&config)?;
    let protected = dpapi(&encoded, true);
    encoded.fill(0);
    atomic_write(&path, &protected?, true)?;
    println!("Protected configuration saved. Start the SadappHostAgent service to enroll.");
    Ok(())
}

pub fn purge_state() -> Result<(), Box<dyn std::error::Error>> {
    require_admin()?;
    require_stopped()?;
    let path = state_dir()?;
    reject_reparse(&path)?;
    // Delete only known agent-owned files; never recursively delete user-created contents.
    for name in [
        "config.dpapi",
        "state/telemetry-queue.json",
        "state/update-state.json",
        "state/agent.log",
        "state/agent.log.old",
    ] {
        let file = path.join(name);
        reject_reparse(file.parent().expect("known file has a parent"))?;
        reject_reparse(&file)?;
        match fs::remove_file(file) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    println!("Known agent configuration, logs and queued telemetry removed.");
    Ok(())
}

pub fn write_log(message: &str) {
    if let Some(log) = LOG.get() {
        let result = log
            .lock()
            .map_err(|_| io::Error::other("Agent log lock poisoned"))
            .and_then(|mut log| {
                if log.metadata()?.len() > 4 * 1024 * 1024 {
                    log.set_len(0)?;
                    writeln!(log, "Log size limit reached; old entries discarded.")?;
                }
                writeln!(log, "{} {message}", crate::unix_timestamp())
            });
        if let Err(error) = result {
            LOG_FAILED.store(true, Ordering::Release);
            eprintln!("Cannot write agent service log: {error}");
        }
    } else {
        eprintln!("{message}");
    }
}

fn initialize_log(path: &Path) -> io::Result<()> {
    reject_reparse(path)?;
    if fs::metadata(path).is_ok_and(|metadata| metadata.len() > 4 * 1024 * 1024) {
        let previous = path.with_extension("log.old");
        reject_reparse(&previous)?;
        if previous.exists() {
            fs::remove_file(&previous)?;
        }
        fs::rename(path, previous)?;
    }
    let log = OpenOptions::new().create(true).append(true).open(path)?;
    protect(path, false)?;
    LOG.set(std::sync::Mutex::new(log))
        .map_err(|_| io::Error::other("Service log already initialized"))
}

pub fn run_service() -> Result<(), Box<dyn std::error::Error>> {
    SERVICE_MODE.store(true, Ordering::Release);
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
    Ok(())
}

define_windows_service!(ffi_service_main, service_main);

fn status(state: ServiceState, exit_code: u32) -> ServiceStatus {
    let pending = matches!(
        state,
        ServiceState::StartPending | ServiceState::StopPending
    );
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: if state == ServiceState::Running {
            ServiceControlAccept::STOP
                | ServiceControlAccept::SHUTDOWN
                | ServiceControlAccept::PRESHUTDOWN
        } else {
            ServiceControlAccept::empty()
        },
        exit_code: ServiceExitCode::Win32(exit_code),
        checkpoint: u32::from(pending),
        wait_hint: if pending {
            Duration::from_secs(90)
        } else {
            Duration::ZERO
        },
        process_id: None,
    }
}

fn service_main(_args: Vec<OsString>) {
    if let Err(error) = service_worker() {
        write_log(&format!("Service failed: {error}"));
    }
}

fn service_worker() -> Result<(), Box<dyn std::error::Error>> {
    let shutdown = Arc::new(AtomicBool::new(false));
    let signal = Arc::clone(&shutdown);
    let handle_cell = Arc::new(OnceLock::<ServiceStatusHandle>::new());
    let control_handle = Arc::clone(&handle_cell);
    let handle = service_control_handler::register(SERVICE_NAME, move |event| match event {
        ServiceControl::Stop | ServiceControl::Shutdown | ServiceControl::Preshutdown => {
            signal.store(true, Ordering::Release);
            if let Some(handle) = control_handle.get()
                && let Err(error) = handle.set_service_status(status(ServiceState::StopPending, 0))
            {
                write_log(&format!("Cannot report StopPending: {error}"));
                return ServiceControlHandlerResult::Other(1);
            }
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })?;
    handle_cell
        .set(handle)
        .map_err(|_| "Service status handle already initialized")?;
    handle.set_service_status(status(ServiceState::StartPending, 0))?;
    let result = (|| {
        let path = state_dir()?;
        reject_reparse(&path)?;
        reject_reparse(&path.join("state"))?;
        initialize_log(&path.join("state").join("agent.log"))?;
        let config = load_config()?;
        handle.set_service_status(status(ServiceState::Running, 0))?;
        write_log("Service running as configured; TLS verification remains enabled.");
        crate::run_agent(Some(config), shutdown)
    })();
    if let Err(error) = &result {
        write_log(&format!("Agent stopped with an error: {error}"));
    }
    handle.set_service_status(status(
        ServiceState::Stopped,
        if result.is_ok() { 0 } else { 1 },
    ))?;
    result
}

pub fn machine_id() -> Option<String> {
    use windows_sys::Win32::System::Registry::{
        HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ, RRF_SUBKEY_WOW6464KEY, RegGetValueW,
    };
    let key = wide(std::ffi::OsStr::new("SOFTWARE\\Microsoft\\Cryptography"));
    let name = wide(std::ffi::OsStr::new("MachineGuid"));
    let mut buffer = [0_u16; 128];
    let mut length = std::mem::size_of_val(&buffer) as u32;
    let result = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            name.as_ptr(),
            RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY,
            ptr::null_mut(),
            buffer.as_mut_ptr().cast(),
            &mut length,
        )
    };
    if result != 0 {
        write_log(&format!(
            "Machine identity unavailable (Windows error {result})"
        ));
        return None;
    }
    let end = buffer
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(buffer.len());
    let value = String::from_utf16_lossy(&buffer[..end]);
    (!value.is_empty()).then_some(value)
}

pub fn timezone() -> Option<String> {
    use windows_sys::Win32::System::Time::{
        DYNAMIC_TIME_ZONE_INFORMATION, GetDynamicTimeZoneInformation,
    };
    let mut info: DYNAMIC_TIME_ZONE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetDynamicTimeZoneInformation(&mut info) } == u32::MAX {
        write_log("Windows time zone unavailable");
        return None;
    }
    let end = info
        .TimeZoneKeyName
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(info.TimeZoneKeyName.len());
    let value = String::from_utf16_lossy(&info.TimeZoneKeyName[..end]);
    (!value.is_empty()).then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_sid_derivation_matches_windows_trusted_installer_identity() {
        assert_eq!(
            service_sid_for("TrustedInstaller"),
            "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
        );
        assert_eq!(service_sid_for("sadapphostagent"), service_sid());
    }

    #[test]
    fn machine_dpapi_round_trip_and_tampering() {
        let secret = b"synthetic-test-secret";
        let encrypted = dpapi(secret, true).unwrap();
        assert!(!encrypted.windows(secret.len()).any(|value| value == secret));
        assert_eq!(dpapi(&encrypted, false).unwrap(), secret);
        let mut modified = encrypted;
        let end = modified.len() - 1;
        modified[end] ^= 0x7f;
        assert!(dpapi(&modified, false).is_err());
    }

    #[test]
    fn service_status_exposes_only_valid_controls() {
        assert!(
            status(ServiceState::Running, 0)
                .controls_accepted
                .contains(ServiceControlAccept::STOP)
        );
        assert!(
            status(ServiceState::StopPending, 0)
                .controls_accepted
                .is_empty()
        );
        assert_eq!(
            status(ServiceState::Stopped, 1).exit_code,
            ServiceExitCode::Win32(1)
        );
    }

    #[test]
    fn atomic_replace_supports_existing_targets() {
        let directory =
            std::env::temp_dir().join(format!("sadapp-atomic-test-{}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("state.json");
        atomic_write(&path, b"one", false).unwrap();
        atomic_write(&path, b"two", false).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"two");
        fs::remove_file(path).unwrap();
        fs::remove_dir(directory).unwrap();
    }
}
