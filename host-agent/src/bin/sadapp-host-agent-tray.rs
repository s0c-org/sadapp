#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(not(windows))]
fn main() {
    eprintln!("The Sadapp tray companion is only available on Windows.");
}

#[cfg(windows)]
#[path = "../tray_status.rs"]
mod tray_status;

#[cfg(windows)]
fn main() -> std::io::Result<()> {
    tray::run()
}

#[cfg(windows)]
mod tray {
    use crate::tray_status::{local_diagnostics, read_service_status};
    use std::{
        cell::RefCell,
        io, ptr,
        time::{SystemTime, UNIX_EPOCH},
    };
    use windows_sys::Win32::{
        Foundation::{
            CloseHandle, ERROR_ALREADY_EXISTS, GetLastError, HWND, LPARAM, LRESULT, POINT, WPARAM,
        },
        System::{
            DataExchange::{CloseClipboard, EmptyClipboard, OpenClipboard, SetClipboardData},
            LibraryLoader::GetModuleHandleW,
            Memory::{GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalUnlock},
            Threading::CreateMutexW,
        },
        UI::{
            Shell::{
                NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE, NIM_MODIFY, NOTIFYICONDATAW,
                Shell_NotifyIconW,
            },
            WindowsAndMessaging::*,
        },
    };

    const TRAY_MESSAGE: u32 = WM_APP + 1;
    const ICON_WIDTH: usize = 32;
    const ICON_HEIGHT: usize = 32;
    const ICON_MASK_STRIDE: usize = ICON_WIDTH / 8;
    const ICON_RGBA: &[u8; ICON_WIDTH * ICON_HEIGHT * 4] = include_bytes!("sadapp-tray.rgba");
    thread_local! {
        static STATE: RefCell<Option<(u8, String)>> = const { RefCell::new(None) };
        static TASKBAR_CREATED: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    }

    fn snapshot() -> (u8, String) {
        let status = match read_service_status() {
            Ok(status) => status,
            Err(error) => {
                let pending = error == "Agent starting" || error.starts_with("Agent running;");
                return (if pending { 1 } else { 2 }, error.into());
            }
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let (color, health) = status.health(now);
        let update = status
            .available_version
            .as_ref()
            .map(|next| format!(" | Update available: {next}"))
            .unwrap_or_default();
        (
            color,
            format!("{health} | Agent {}{update}", status.version),
        )
    }

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(Some(0)).collect()
    }

    fn status_icon(
        rgb: [u8; 3],
    ) -> (
        [u8; ICON_MASK_STRIDE * ICON_HEIGHT],
        [u8; ICON_WIDTH * ICON_HEIGHT * 4],
    ) {
        let mut mask = [0u8; ICON_MASK_STRIDE * ICON_HEIGHT];
        let mut pixels = [0u8; ICON_WIDTH * ICON_HEIGHT * 4];
        for y in 0..ICON_HEIGHT {
            let bitmap_y = ICON_HEIGHT - 1 - y;
            for x in 0..ICON_WIDTH {
                let source = (y * ICON_WIDTH + x) * 4;
                let destination = (bitmap_y * ICON_WIDTH + x) * 4;
                let red = ICON_RGBA[source];
                let green = ICON_RGBA[source + 1];
                let blue = ICON_RGBA[source + 2];
                let alpha = ICON_RGBA[source + 3];
                pixels[destination..destination + 4].copy_from_slice(&[blue, green, red, alpha]);
                if alpha == 0 {
                    mask[bitmap_y * ICON_MASK_STRIDE + x / 8] |= 0x80 >> (x % 8);
                }
            }
        }

        for y in 21..ICON_HEIGHT {
            for x in 21..ICON_WIDTH {
                let dx = x as i32 - 26;
                let dy = y as i32 - 26;
                let distance_squared = dx * dx + dy * dy;
                if distance_squared > 25 {
                    continue;
                }
                let destination = ((ICON_HEIGHT - 1 - y) * ICON_WIDTH + x) * 4;
                pixels[destination..destination + 4]
                    .copy_from_slice(&[rgb[2], rgb[1], rgb[0], 255]);
                let bitmap_y = ICON_HEIGHT - 1 - y;
                mask[bitmap_y * ICON_MASK_STRIDE + x / 8] &= !(0x80 >> (x % 8));
            }
        }
        (mask, pixels)
    }

    fn copy_diagnostics(hwnd: HWND) -> io::Result<()> {
        use windows_sys::Win32::Foundation::GlobalFree;
        const CF_UNICODETEXT: u32 = 13;
        let report = local_diagnostics().unwrap_or_else(|error| error.to_string());
        let text = wide(&report);
        unsafe {
            let memory = GlobalAlloc(GMEM_MOVEABLE, text.len() * size_of::<u16>());
            if memory.is_null() {
                return Err(io::Error::last_os_error());
            }
            let destination = GlobalLock(memory).cast::<u16>();
            if destination.is_null() {
                let error = io::Error::last_os_error();
                GlobalFree(memory);
                return Err(error);
            }
            ptr::copy_nonoverlapping(text.as_ptr(), destination, text.len());
            GlobalUnlock(memory);
            if OpenClipboard(hwnd) == 0 {
                let error = io::Error::last_os_error();
                GlobalFree(memory);
                return Err(error);
            }
            let result =
                if EmptyClipboard() == 0 || SetClipboardData(CF_UNICODETEXT, memory).is_null() {
                    let error = io::Error::last_os_error();
                    GlobalFree(memory);
                    Err(error)
                } else {
                    Ok(())
                };
            CloseClipboard();
            result
        }
    }

    fn refresh(hwnd: HWND, add: bool) {
        let next = snapshot();
        STATE.with_borrow_mut(|previous| {
            if !add && previous.as_ref() == Some(&next) {
                return;
            }
            let mut data = NOTIFYICONDATAW {
                cbSize: size_of::<NOTIFYICONDATAW>() as u32,
                hWnd: hwnd,
                uID: 1,
                uFlags: NIF_ICON | NIF_TIP | NIF_MESSAGE,
                uCallbackMessage: TRAY_MESSAGE,
                ..Default::default()
            };
            for (dest, source) in data
                .szTip
                .iter_mut()
                .take(127)
                .zip(format!("Sadapp: {}", next.1).encode_utf16())
            {
                *dest = source;
            }
            let rgb =
                [[0x32, 0xb9, 0x59], [0xfa, 0xb7, 0x2d], [0xe3, 0x48, 0x50]][usize::from(next.0)];
            let (mask, pixels) = status_icon(rgb);
            unsafe {
                data.hIcon = CreateIcon(
                    GetModuleHandleW(ptr::null()),
                    ICON_WIDTH as i32,
                    ICON_HEIGHT as i32,
                    1,
                    32,
                    mask.as_ptr(),
                    pixels.as_ptr(),
                );
                if data.hIcon.is_null() {
                    data.hIcon = LoadIconW(
                        ptr::null_mut(),
                        [IDI_INFORMATION, IDI_WARNING, IDI_ERROR][usize::from(next.0)],
                    );
                    if data.hIcon.is_null() {
                        return;
                    }
                    if Shell_NotifyIconW(if add { NIM_ADD } else { NIM_MODIFY }, &data) != 0 {
                        *previous = Some(next);
                    }
                } else {
                    if Shell_NotifyIconW(if add { NIM_ADD } else { NIM_MODIFY }, &data) != 0 {
                        *previous = Some(next);
                    }
                    DestroyIcon(data.hIcon);
                }
            }
        });
    }

    unsafe extern "system" fn window_proc(hwnd: HWND, msg: u32, w: WPARAM, l: LPARAM) -> LRESULT {
        unsafe {
            match msg {
                WM_TIMER => refresh(hwnd, STATE.with_borrow(Option::is_none)),
                TRAY_MESSAGE if matches!(l as u32, WM_RBUTTONUP | WM_LBUTTONUP) => {
                    refresh(hwnd, false);
                    let menu = CreatePopupMenu();
                    if !menu.is_null() {
                        STATE.with_borrow(|status| {
                            let text = status
                                .as_ref()
                                .map_or("Sadapp status unavailable", |(_, text)| text.as_str());
                            AppendMenuW(menu, MF_STRING | MF_GRAYED, 0, wide(text).as_ptr());
                        });
                        AppendMenuW(menu, MF_SEPARATOR, 0, ptr::null());
                        AppendMenuW(menu, MF_STRING, 2, wide("Copy local diagnostics").as_ptr());
                        AppendMenuW(
                            menu,
                            MF_STRING,
                            1,
                            wide("Exit tray (agent keeps running)").as_ptr(),
                        );
                        let mut cursor = POINT::default();
                        GetCursorPos(&mut cursor);
                        SetForegroundWindow(hwnd);
                        let result = TrackPopupMenu(
                            menu,
                            TPM_RETURNCMD | TPM_NONOTIFY | TPM_RIGHTBUTTON,
                            cursor.x,
                            cursor.y,
                            0,
                            hwnd,
                            ptr::null(),
                        );
                        DestroyMenu(menu);
                        PostMessageW(hwnd, WM_NULL, 0, 0);
                        if result == 1 {
                            DestroyWindow(hwnd);
                        } else if result == 2
                            && let Err(error) = copy_diagnostics(hwnd)
                        {
                            MessageBoxW(
                                hwnd,
                                wide(&format!("Could not copy diagnostics: {error}")).as_ptr(),
                                wide("Sadapp Agent Status").as_ptr(),
                                MB_OK | MB_ICONERROR,
                            );
                        }
                    }
                }
                WM_DESTROY => {
                    Shell_NotifyIconW(
                        NIM_DELETE,
                        &NOTIFYICONDATAW {
                            cbSize: size_of::<NOTIFYICONDATAW>() as u32,
                            hWnd: hwnd,
                            uID: 1,
                            ..Default::default()
                        },
                    );
                    PostQuitMessage(0);
                }
                _ if TASKBAR_CREATED.get() == msg => {
                    STATE.with_borrow_mut(|state| *state = None);
                    refresh(hwnd, true);
                }
                _ => return DefWindowProcW(hwnd, msg, w, l),
            }
        }
        0
    }

    pub fn run() -> io::Result<()> {
        unsafe {
            let mutex = CreateMutexW(ptr::null(), 0, wide("Local\\SadappHostAgentTray").as_ptr());
            if mutex.is_null() {
                return Err(io::Error::last_os_error());
            }
            let duplicate = GetLastError() == ERROR_ALREADY_EXISTS;
            let result = if duplicate { Ok(()) } else { message_loop() };
            CloseHandle(mutex);
            result
        }
    }

    fn message_loop() -> io::Result<()> {
        unsafe {
            TASKBAR_CREATED.set(RegisterWindowMessageW(wide("TaskbarCreated").as_ptr()));
            let class_name = wide("SadappHostAgentTrayWindow");
            let instance = GetModuleHandleW(ptr::null());
            let class = WNDCLASSW {
                lpfnWndProc: Some(window_proc),
                hInstance: instance,
                lpszClassName: class_name.as_ptr(),
                ..Default::default()
            };
            if RegisterClassW(&class) == 0 {
                return Err(io::Error::last_os_error());
            }
            let hwnd = CreateWindowExW(
                0,
                class_name.as_ptr(),
                class_name.as_ptr(),
                WS_POPUP,
                0,
                0,
                0,
                0,
                ptr::null_mut(),
                ptr::null_mut(),
                instance,
                ptr::null(),
            );
            if hwnd.is_null() {
                return Err(io::Error::last_os_error());
            }
            if SetTimer(hwnd, 1, 10_000, None) == 0 {
                let error = io::Error::last_os_error();
                DestroyWindow(hwnd);
                return Err(error);
            }
            refresh(hwnd, true);
            let mut msg = MSG::default();
            loop {
                match GetMessageW(&mut msg, ptr::null_mut(), 0, 0) {
                    -1 => {
                        let error = io::Error::last_os_error();
                        DestroyWindow(hwnd);
                        return Err(error);
                    }
                    0 => return Ok(()),
                    _ => {
                        TranslateMessage(&msg);
                        DispatchMessageW(&msg);
                    }
                }
            }
        }
    }
}
