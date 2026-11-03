use crate::ListeningPort;
use std::{io, mem, ptr};
use windows_sys::Win32::{
    Foundation::{ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS},
    NetworkManagement::IpHelper::*,
    Networking::WinSock::{AF_INET, AF_INET6},
};

const MAX_TABLE_BYTES: u32 = 16 * 1024 * 1024;

fn table(tcp: bool, family: u32) -> io::Result<Vec<u32>> {
    let mut size = 0;
    for _ in 0..4 {
        let mut buffer = vec![0_u32; (size as usize).div_ceil(mem::size_of::<u32>())];
        let data = if buffer.is_empty() {
            ptr::null_mut()
        } else {
            buffer.as_mut_ptr().cast()
        };
        let result = unsafe {
            if tcp {
                GetExtendedTcpTable(data, &mut size, 0, family, TCP_TABLE_OWNER_PID_LISTENER, 0)
            } else {
                GetExtendedUdpTable(data, &mut size, 0, family, UDP_TABLE_OWNER_PID, 0)
            }
        };
        match result {
            ERROR_SUCCESS if !buffer.is_empty() => {
                buffer.truncate((size as usize).div_ceil(mem::size_of::<u32>()));
                return Ok(buffer);
            }
            ERROR_INSUFFICIENT_BUFFER if (4..=MAX_TABLE_BYTES).contains(&size) => {}
            ERROR_INSUFFICIENT_BUFFER => {
                return Err(io::Error::other(
                    "Windows endpoint table exceeds the 16 MiB collection budget",
                ));
            }
            _ => return Err(io::Error::from_raw_os_error(result as i32)),
        }
    }
    Err(io::Error::other(
        "Windows endpoint table kept changing during collection",
    ))
}

fn decode_rows<T: Copy>(
    buffer: &[u32],
    protocol: &str,
    port: impl Fn(T) -> u32,
) -> io::Result<Vec<ListeningPort>> {
    let count = buffer
        .first()
        .copied()
        .ok_or_else(|| io::Error::other("Missing endpoint table header"))? as usize;
    let bytes = mem::size_of_val(buffer).saturating_sub(4);
    if count > bytes / mem::size_of::<T>() {
        return Err(io::Error::other("Truncated Windows endpoint table"));
    }
    let rows = unsafe { buffer.as_ptr().cast::<u8>().add(4) };
    let mut result = Vec::with_capacity(count.min(1024));
    for index in 0..count {
        // IP Helper tables contain a DWORD count followed by fixed-size C rows.
        let row = unsafe { ptr::read_unaligned(rows.add(index * mem::size_of::<T>()).cast::<T>()) };
        let port = u16::from_be(port(row) as u16);
        if port != 0 {
            result.push(ListeningPort {
                protocol: protocol.into(),
                port,
            });
        }
    }
    Ok(result)
}

pub fn collect() -> io::Result<Vec<ListeningPort>> {
    let mut ports = Vec::new();
    for family in [u32::from(AF_INET), u32::from(AF_INET6)] {
        for tcp in [true, false] {
            let buffer = table(tcp, family).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!(
                        "{} IPv{} endpoint enumeration failed: {error}",
                        if tcp { "TCP" } else { "UDP" },
                        if family == u32::from(AF_INET) { 4 } else { 6 }
                    ),
                )
            })?;
            let rows = match (tcp, family == u32::from(AF_INET)) {
                (true, true) => {
                    decode_rows::<MIB_TCPROW_OWNER_PID>(&buffer, "tcp", |row| row.dwLocalPort)
                }
                (true, false) => {
                    decode_rows::<MIB_TCP6ROW_OWNER_PID>(&buffer, "tcp6", |row| row.dwLocalPort)
                }
                (false, true) => {
                    decode_rows::<MIB_UDPROW_OWNER_PID>(&buffer, "udp", |row| row.dwLocalPort)
                }
                (false, false) => {
                    decode_rows::<MIB_UDP6ROW_OWNER_PID>(&buffer, "udp6", |row| row.dwLocalPort)
                }
            }?;
            ports.extend(rows);
        }
    }
    ports.sort_by(|left, right| {
        left.protocol
            .cmp(&right.protocol)
            .then(left.port.cmp(&right.port))
    });
    ports.dedup_by(|left, right| left.protocol == right.protocol && left.port == right.port);
    ports.truncate(100);
    Ok(ports)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, UdpSocket};

    #[test]
    fn reports_real_tcp_listeners_and_bound_udp_endpoints() {
        let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let tcp6 = TcpListener::bind("[::1]:0").unwrap();
        let udp6 = UdpSocket::bind("[::1]:0").unwrap();
        // Inspect full native tables so an unrelated busy host cannot push fixtures past the 100-entry projection cap.
        let tcp_rows = decode_rows::<MIB_TCPROW_OWNER_PID>(
            &table(true, u32::from(AF_INET)).unwrap(),
            "tcp",
            |row| row.dwLocalPort,
        )
        .unwrap();
        let udp_rows = decode_rows::<MIB_UDPROW_OWNER_PID>(
            &table(false, u32::from(AF_INET)).unwrap(),
            "udp",
            |row| row.dwLocalPort,
        )
        .unwrap();
        assert!(
            tcp_rows
                .iter()
                .any(|entry| entry.port == tcp.local_addr().unwrap().port())
        );
        assert!(
            udp_rows
                .iter()
                .any(|entry| entry.port == udp.local_addr().unwrap().port())
        );
        let tcp6_rows = decode_rows::<MIB_TCP6ROW_OWNER_PID>(
            &table(true, u32::from(AF_INET6)).unwrap(),
            "tcp6",
            |row| row.dwLocalPort,
        )
        .unwrap();
        let udp6_rows = decode_rows::<MIB_UDP6ROW_OWNER_PID>(
            &table(false, u32::from(AF_INET6)).unwrap(),
            "udp6",
            |row| row.dwLocalPort,
        )
        .unwrap();
        assert!(
            tcp6_rows
                .iter()
                .any(|entry| entry.port == tcp6.local_addr().unwrap().port())
        );
        assert!(
            udp6_rows
                .iter()
                .any(|entry| entry.port == udp6.local_addr().unwrap().port())
        );
        let projected = collect().unwrap();
        assert!(projected.len() <= 100);
        assert!(
            projected
                .windows(2)
                .all(|pair| (&pair[0].protocol, pair[0].port) < (&pair[1].protocol, pair[1].port))
        );
    }

    #[test]
    fn rejects_truncated_tables_and_decodes_network_byte_order() {
        assert!(decode_rows::<MIB_TCPROW_OWNER_PID>(&[1], "tcp", |row| row.dwLocalPort).is_err());
        let mut row: MIB_UDPROW_OWNER_PID = unsafe { mem::zeroed() };
        row.dwLocalPort = u32::from(443_u16.to_be());
        let mut bytes = vec![0_u32; 1 + mem::size_of::<MIB_UDPROW_OWNER_PID>() / 4];
        bytes[0] = 1;
        unsafe {
            ptr::write_unaligned(
                bytes.as_mut_ptr().add(1).cast::<MIB_UDPROW_OWNER_PID>(),
                row,
            );
        }
        let parsed =
            decode_rows::<MIB_UDPROW_OWNER_PID>(&bytes, "udp", |row| row.dwLocalPort).unwrap();
        assert_eq!(parsed[0].port, 443);
    }
}
