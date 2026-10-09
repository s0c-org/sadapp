use crate::{GpuInfo, bounded_gpu_output, parse_nvidia_smi_csv};
use std::collections::HashSet;
use std::error::Error;
use std::ffi::{c_char, c_void};
use std::mem::{size_of, transmute};
use std::path::PathBuf;
use std::process::Command;
use std::ptr;
use windows_sys::Win32::{
    Foundation::FreeLibrary,
    System::{
        LibraryLoader::{GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW},
        Memory::{GetProcessHeap, HeapAlloc},
        SystemInformation::GetSystemDirectoryW,
    },
};

#[repr(C)]
#[derive(Clone, Copy)]
struct AdapterInfo {
    size: i32,
    index: i32,
    udid: [c_char; 256],
    bus: i32,
    device: i32,
    function: i32,
    vendor: i32,
    name: [c_char; 256],
    display: [c_char; 256],
    present: i32,
    exist: i32,
    driver_path: [c_char; 256],
    driver_path_ext: [c_char; 256],
    pnp: [c_char; 256],
    os_display_index: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Sensor {
    supported: i32,
    value: i32,
}
#[repr(C)]
struct PerformanceLog {
    size: i32,
    sensors: [Sensor; 256],
}
#[repr(C)]
struct MemoryInfo {
    bytes: i64,
    kind: [c_char; 256],
    bandwidth: i64,
    hyper_memory_bytes: i64,
    invisible_bytes: i64,
    visible_bytes: i64,
}

type Context = *mut c_void;
type Create =
    unsafe extern "C" fn(unsafe extern "C" fn(i32) -> *mut c_void, i32, *mut Context) -> i32;
type Destroy = unsafe extern "C" fn(Context) -> i32;
type Count = unsafe extern "C" fn(Context, *mut i32) -> i32;
type Adapters = unsafe extern "C" fn(Context, *mut AdapterInfo, i32) -> i32;
type Query = unsafe extern "C" fn(Context, i32, *mut PerformanceLog) -> i32;
type Memory = unsafe extern "C" fn(Context, i32, *mut MemoryInfo) -> i32;
type UsedMemory = unsafe extern "C" fn(Context, i32, *mut i32) -> i32;

pub fn warn(message: &str) {
    if crate::windows::is_service() {
        crate::windows::write_log(&format!("[WARN] {message}"));
    } else {
        eprintln!("{message}");
    }
}

unsafe extern "C" fn allocate(bytes: i32) -> *mut c_void {
    if bytes <= 0 {
        return ptr::null_mut();
    }
    unsafe { HeapAlloc(GetProcessHeap(), 0, bytes as usize) }
}

fn system_directory() -> Result<PathBuf, Box<dyn Error>> {
    let mut buffer = [0u16; 32768];
    let length = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    if length == 0 || length >= buffer.len() {
        return Err("Cannot resolve Windows system directory".into());
    }

    Ok(PathBuf::from(String::from_utf16(&buffer[..length])?))
}

fn nvidia_executable() -> Result<Option<PathBuf>, Box<dyn Error>> {
    let system_path = system_directory()?.join("nvidia-smi.exe");
    if system_path.is_file() {
        return Ok(Some(system_path));
    }
    use windows_sys::Win32::{
        System::Com::CoTaskMemFree,
        UI::Shell::{FOLDERID_ProgramFiles, SHGetKnownFolderPath},
    };
    let mut folder = ptr::null_mut();
    let result =
        unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramFiles, 0, ptr::null_mut(), &mut folder) };
    if result < 0 || folder.is_null() {
        return Err(format!("Cannot resolve ProgramFiles ({result:#x})").into());
    }
    let path = unsafe {
        let mut length = 0;
        while *folder.add(length) != 0 {
            length += 1;
        }
        let path = PathBuf::from(String::from_utf16_lossy(std::slice::from_raw_parts(
            folder, length,
        )));
        CoTaskMemFree(folder.cast());
        path.join("NVIDIA Corporation")
            .join("NVSMI")
            .join("nvidia-smi.exe")
    };
    Ok(path.is_file().then_some(path))
}

pub fn collect() -> Vec<GpuInfo> {
    let mut devices = Vec::new();
    match nvidia_executable() {
        Ok(Some(nvidia)) => {
            let base = "--query-gpu=index,name,uuid,driver_version,pci.bus_id,utilization.gpu,memory.total,memory.used,temperature.gpu,power.draw,power.limit,fan.speed";
            let clocks = format!("{base},clocks.current.graphics,clocks.current.memory");
            let query = |fields: &str| {
                bounded_gpu_output(
                    Command::new(&nvidia).args([fields, "--format=csv,noheader,nounits"]),
                )
            };
            match query(&clocks).or_else(|error| {
                warn(&format!(
                    "NVIDIA clock query failed; retrying basic readings: {error}"
                ));
                query(base)
            }) {
                Ok(output) => {
                    let parsed = parse_nvidia_smi_csv(&output);
                    if parsed.is_empty() {
                        warn("NVIDIA GPU query returned no parseable devices");
                    }
                    devices.extend(parsed);
                }
                Err(error) => warn(&format!("NVIDIA GPU collection failed: {error}")),
            }
        }
        Ok(None) => {}
        Err(error) => warn(&format!("GPU collection failed: {error}")),
    }
    // Driver calls run in a disposable child so a hung/crashing DLL cannot stall the agent.
    match std::env::current_exe()
        .map_err(|error| -> Box<dyn Error> { error.into() })
        .and_then(|exe| bounded_gpu_output(Command::new(exe).arg("--gpu-probe-amd")))
        .and_then(|output| serde_json::from_str::<Vec<GpuInfo>>(&output).map_err(Into::into))
    {
        Ok(amd) => devices.extend(amd),
        Err(error) => warn(&format!("AMD GPU collection failed: {error}")),
    }
    devices.sort_by(|a, b| a.id.cmp(&b.id));
    devices
}

fn text(bytes: &[c_char]) -> String {
    String::from_utf8_lossy(
        &bytes
            .iter()
            .take_while(|byte| **byte != 0)
            .map(|byte| *byte as u8)
            .collect::<Vec<_>>(),
    )
    .into_owned()
}

fn sensor(log: &PerformanceLog, id: usize, maximum: f32) -> Option<f32> {
    let reading = log.sensors.get(id)?;
    let value = reading.value as f32;
    (reading.supported != 0 && value >= 0.0 && value <= maximum).then_some(value)
}

pub fn collect_amd() -> Result<Vec<GpuInfo>, Box<dyn Error>> {
    let dll = system_directory()?.join("atiadlxx.dll");
    if !dll.is_file() {
        return Ok(Vec::new());
    }
    let path: Vec<u16> = dll.as_os_str().encode_wide().chain(Some(0)).collect();
    use std::os::windows::ffi::OsStrExt;
    let library =
        unsafe { LoadLibraryExW(path.as_ptr(), ptr::null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32) };
    if library.is_null() {
        return Err(std::io::Error::last_os_error().into());
    }
    struct Library(windows_sys::Win32::Foundation::HMODULE);
    impl Drop for Library {
        fn drop(&mut self) {
            unsafe {
                FreeLibrary(self.0);
            }
        }
    }
    let _library = Library(library);
    macro_rules! required {
        ($name:literal, $ty:ty) => {{
            let address = unsafe { GetProcAddress(library, concat!($name, "\0").as_ptr()) }
                .ok_or(concat!("AMD driver API missing: ", $name))?;
            unsafe { transmute::<unsafe extern "system" fn() -> isize, $ty>(address) }
        }};
    }
    let create = required!("ADL2_Main_Control_Create", Create);
    let destroy = required!("ADL2_Main_Control_Destroy", Destroy);
    let count = required!("ADL2_Adapter_NumberOfAdapters_Get", Count);
    let adapters = required!("ADL2_Adapter_AdapterInfo_Get", Adapters);
    let query = required!("ADL2_New_QueryPMLogData_Get", Query);
    let memory =
        unsafe { GetProcAddress(library, c"ADL2_Adapter_MemoryInfo2_Get".as_ptr().cast()) }.map(
            |address| unsafe { transmute::<unsafe extern "system" fn() -> isize, Memory>(address) },
        );
    let used = unsafe {
        GetProcAddress(
            library,
            c"ADL2_Adapter_DedicatedVRAMUsage_Get".as_ptr().cast(),
        )
    }
    .map(|address| unsafe {
        transmute::<unsafe extern "system" fn() -> isize, UsedMemory>(address)
    });
    let mut context = ptr::null_mut();
    if unsafe { create(allocate, 1, &mut context) } != 0 || context.is_null() {
        return Err("AMD driver initialization failed".into());
    }
    struct Session(Context, Destroy);
    impl Drop for Session {
        fn drop(&mut self) {
            unsafe {
                (self.1)(self.0);
            }
        }
    }
    let _session = Session(context, destroy);
    let mut length = 0;
    if unsafe { count(context, &mut length) } != 0 || !(0..=64).contains(&length) {
        return Err("AMD adapter enumeration failed".into());
    }
    if length == 0 {
        return Ok(Vec::new());
    }
    let mut rows: Vec<AdapterInfo> = (0..length)
        .map(|_| {
            let mut row: AdapterInfo = unsafe { std::mem::zeroed() };
            row.size = size_of::<AdapterInfo>() as i32;
            row
        })
        .collect();
    if unsafe {
        adapters(
            context,
            rows.as_mut_ptr(),
            (rows.len() * size_of::<AdapterInfo>()) as i32,
        )
    } != 0
    {
        return Err("AMD adapter details failed".into());
    }
    let mut identities = HashSet::new();
    let mut devices = Vec::new();
    for row in rows {
        if ![1002, 0x1002].contains(&row.vendor) || row.present == 0 {
            continue;
        }
        let identity = format!("amd:{:02x}:{:02x}.{}", row.bus, row.device, row.function);
        if !identities.insert(identity.clone()) {
            continue;
        }
        let mut log = PerformanceLog {
            size: size_of::<PerformanceLog>() as i32,
            sensors: [Sensor::default(); 256],
        };
        if unsafe { query(context, row.index, &mut log) } != 0 {
            log.sensors.fill(Sensor::default());
            eprintln!(
                "AMD performance metrics unavailable for adapter {}",
                row.index
            );
        }
        let mut total: MemoryInfo = unsafe { std::mem::zeroed() };
        let total_bytes = memory.and_then(|get| {
            let result = unsafe { get(context, row.index, &mut total) };
            if result != 0 {
                eprintln!(
                    "AMD VRAM capacity query failed for adapter {} ({result})",
                    row.index
                );
            }
            (result == 0 && total.bytes > 0).then_some(total.bytes as u64)
        });
        let mut used_mib = 0;
        let used_bytes = used.and_then(|get| {
            let result = unsafe { get(context, row.index, &mut used_mib) };
            if result != 0 {
                eprintln!(
                    "AMD VRAM usage query failed for adapter {} ({result})",
                    row.index
                );
            }
            (result == 0 && used_mib >= 0).then_some(used_mib as u64 * 1048576)
        });
        devices.push(GpuInfo {
            id: identity,
            name: text(&row.name),
            vendor: "AMD".into(),
            driver_version: None,
            pci_bus_id: Some(format!(
                "{:02x}:{:02x}.{}",
                row.bus, row.device, row.function
            )),
            utilization_percent: sensor(&log, 19, 100.0),
            memory_total_bytes: total_bytes,
            memory_used_bytes: used_bytes,
            temperature_celsius: sensor(&log, 8, 150.0).or_else(|| sensor(&log, 28, 150.0)),
            hotspot_temperature_celsius: sensor(&log, 27, 150.0),
            power_draw_watts: sensor(&log, 73, 2000.0).or_else(|| sensor(&log, 23, 2000.0)),
            power_limit_watts: None,
            fan_speed_percent: sensor(&log, 15, 100.0),
            core_clock_mhz: sensor(&log, 1, 10000.0),
            memory_clock_mhz: sensor(&log, 2, 30000.0),
        });
    }
    Ok(devices)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn amd_abi_and_supported_sensor_values() {
        assert_eq!(size_of::<AdapterInfo>(), 1572);
        assert_eq!(size_of::<PerformanceLog>(), 2052);
        assert_eq!(size_of::<MemoryInfo>(), 296);
        let mut log = PerformanceLog {
            size: 2052,
            sensors: [Sensor::default(); 256],
        };
        log.sensors[19] = Sensor {
            supported: 1,
            value: 0,
        };
        log.sensors[1] = Sensor {
            supported: 1,
            value: 2400,
        };
        assert_eq!(sensor(&log, 19, 100.0), Some(0.0));
        assert_eq!(sensor(&log, 1, 10000.0), Some(2400.0));
        assert_eq!(sensor(&log, 8, 150.0), None);
        log.sensors[8] = Sensor {
            supported: 1,
            value: 65535,
        };
        assert_eq!(sensor(&log, 8, 150.0), None);
    }
}
