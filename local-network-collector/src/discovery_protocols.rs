use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    time::Duration,
};

use hickory_proto::{
    op::{Message, MessageType, OpCode, Query},
    rr::{domain::Name, RData, RecordType},
};
use if_addrs::{get_if_addrs, Interface};
use ipnet::IpNet;
use quick_xml::{events::Event, Reader, XmlVersion};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::{
    net::UdpSocket,
    time::{timeout, Instant},
};
use uuid::Uuid;

const MAX_MULTICAST_INTERFACES: usize = 8;
const MAX_MULTICAST_RESPONSES: usize = 16;
const MAX_MULTICAST_PACKET_BYTES: usize = 8 * 1024;
const SSDP_GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
const MDNS_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const SSDP_GROUP_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x000c);
const MDNS_GROUP_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x00fb);

fn multicast_socket(interface: Ipv4Addr, group: Ipv4Addr) -> std::io::Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.set_multicast_if_v4(&interface)?;
    socket.set_multicast_ttl_v4(1)?;
    socket.set_multicast_loop_v4(false)?;
    socket.bind(&SockAddr::from(SocketAddrV4::new(interface, 0)))?;
    socket.join_multicast_v4(&group, &interface)?;
    socket.set_nonblocking(true)?;
    let socket: std::net::UdpSocket = socket.into();
    UdpSocket::from_std(socket)
}

fn multicast_socket_v6(
    interface: Ipv6Addr,
    interface_index: u32,
    group: Ipv6Addr,
) -> std::io::Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_only_v6(true)?;
    socket.set_reuse_address(true)?;
    socket.set_multicast_if_v6(interface_index)?;
    socket.set_multicast_hops_v6(1)?;
    socket.set_multicast_loop_v6(false)?;
    let scope_id = if interface.is_unicast_link_local() {
        interface_index
    } else {
        0
    };
    socket.bind(&SockAddr::from(SocketAddrV6::new(
        interface, 0, 0, scope_id,
    )))?;
    socket.join_multicast_v6(&group, interface_index)?;
    socket.set_nonblocking(true)?;
    let socket: std::net::UdpSocket = socket.into();
    UdpSocket::from_std(socket)
}

fn scoped_multicast_destination(group: Ipv6Addr, port: u16, interface_index: u32) -> SocketAddr {
    SocketAddr::V6(SocketAddrV6::new(group, port, 0, interface_index))
}

async fn send_and_collect(
    socket: &UdpSocket,
    destination: SocketAddr,
    request: &[u8],
    timeout_duration: Duration,
) -> Vec<(IpAddr, Vec<u8>)> {
    if socket.send_to(request, destination).await.is_err() {
        return Vec::new();
    }
    let deadline = Instant::now() + timeout_duration;
    let mut responses = Vec::new();
    let mut packet = vec![0_u8; MAX_MULTICAST_PACKET_BYTES + 1];
    while responses.len() < MAX_MULTICAST_RESPONSES {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match timeout(remaining, socket.recv_from(&mut packet)).await {
            Ok(Ok((length, source))) if length <= MAX_MULTICAST_PACKET_BYTES => {
                responses.push((source.ip(), packet[..length].to_vec()));
            }
            Ok(Ok(_)) | Ok(Err(_)) | Err(_) => break,
        }
    }
    responses
}

fn safe_text(value: &str, limit: usize) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .take(limit)
        .collect()
}

fn hash_identity(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

fn parse_ssdp_response(packet: &[u8]) -> Option<(Value, Option<Value>)> {
    let text = std::str::from_utf8(packet).ok()?;
    if !text.lines().next()?.trim().starts_with("HTTP/1.1 200") {
        return None;
    }
    let mut st = None;
    let mut server = None;
    let mut usn = None;
    for line in text.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        match name.trim().to_ascii_lowercase().as_str() {
            "st" => st = Some(safe_text(value.trim(), 200)),
            "server" => server = Some(safe_text(value.trim(), 160)),
            "usn" => usn = Some(safe_text(value.trim(), 256)),
            _ => {}
        }
    }
    let st = st.filter(|value| !value.is_empty())?;
    let identity = usn.as_deref().and_then(|value| {
        let uuid = value.split("::").next()?.strip_prefix("uuid:")?;
        (!uuid.is_empty())
            .then(|| json!({ "method": "ssdp", "observed": true, "keyHash": hash_identity(uuid) }))
    });
    Some((
        json!({ "protocol": "ssdp", "transport": "udp", "port": 1900, "state": "responded", "st": st, "server": server }),
        identity,
    ))
}

async fn probe_ssdp(
    interface: Ipv4Addr,
    timeout_duration: Duration,
) -> Vec<(IpAddr, Value, Option<Value>)> {
    let Ok(socket) = multicast_socket(interface, SSDP_GROUP) else {
        return Vec::new();
    };
    let request = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n";
    send_and_collect(
        &socket,
        SocketAddr::V4(SocketAddrV4::new(SSDP_GROUP, 1900)),
        request,
        timeout_duration,
    )
    .await
    .into_iter()
    .filter_map(|(address, packet)| {
        parse_ssdp_response(&packet).map(|(observation, identity)| (address, observation, identity))
    })
    .collect()
}

async fn probe_ssdp_v6(
    interface: Ipv6Addr,
    interface_index: u32,
    timeout_duration: Duration,
) -> Vec<(IpAddr, Value, Option<Value>)> {
    let Ok(socket) = multicast_socket_v6(interface, interface_index, SSDP_GROUP_V6) else {
        return Vec::new();
    };
    let request = b"M-SEARCH * HTTP/1.1\r\nHOST: [FF02::C]:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n";
    send_and_collect(
        &socket,
        scoped_multicast_destination(SSDP_GROUP_V6, 1900, interface_index),
        request,
        timeout_duration,
    )
    .await
    .into_iter()
    .filter_map(|(address, packet)| {
        parse_ssdp_response(&packet).map(|(observation, identity)| (address, observation, identity))
    })
    .collect()
}

fn local_xml_name(name: &str) -> &str {
    name.rsplit(':').next().unwrap_or(name)
}

fn parse_onvif_response(packet: &[u8]) -> Option<(Value, Option<Value>)> {
    if packet.len() > MAX_MULTICAST_PACKET_BYTES {
        return None;
    }
    let xml = std::str::from_utf8(packet).ok()?;
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut current = String::new();
    let mut address = String::new();
    let mut types = String::new();
    let mut scopes = String::new();
    let mut xaddrs = false;
    loop {
        match reader.read_event().ok()? {
            Event::Start(element) => current = local_xml_name(element.name().as_ref()).to_owned(),
            Event::Text(text) => {
                let value = text.xml_content(XmlVersion::Implicit1_0);
                match current.as_str() {
                    "Address" => address.push_str(&value),
                    "Types" => types.push_str(&value),
                    "Scopes" => scopes.push_str(&value),
                    "XAddrs" => xaddrs = !value.trim().is_empty(),
                    _ => {}
                }
            }
            Event::End(_) => current.clear(),
            Event::Eof => break,
            _ => {}
        }
        if address.len() + types.len() + scopes.len() > 1024 {
            return None;
        }
    }
    if !types
        .to_ascii_lowercase()
        .contains("networkvideotransmitter")
        && !xaddrs
    {
        return None;
    }
    let uuid = address.trim().strip_prefix("urn:uuid:");
    let is_camera = types
        .to_ascii_lowercase()
        .contains("networkvideotransmitter");
    let identity = uuid.filter(|value| !value.is_empty()).map(|value| {
        json!({
            "method": "onvif", "observed": true, "keyHash": hash_identity(value),
            "deviceProfile": if is_camera { "camera" } else { "network_device" },
        })
    });
    Some((
        json!({
            "protocol": "onvif-wsd", "transport": "udp", "port": 3702, "state": "responded",
            "deviceType": safe_text(&types, 512), "scopes": safe_text(&scopes, 512), "hasEndpoint": xaddrs,
        }),
        identity,
    ))
}

async fn probe_onvif(
    interface: Ipv4Addr,
    timeout_duration: Duration,
) -> Vec<(IpAddr, Value, Option<Value>)> {
    let Ok(socket) = multicast_socket(interface, SSDP_GROUP) else {
        return Vec::new();
    };
    let message_id = Uuid::new_v4();
    let request = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><e:Envelope xmlns:e=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:w=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\" xmlns:dn=\"http://www.onvif.org/ver10/network/wsdl\"><e:Header><w:MessageID>uuid:{message_id}</w:MessageID><w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To><w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action></e:Header><e:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe></e:Body></e:Envelope>"
    );
    send_and_collect(
        &socket,
        SocketAddr::V4(SocketAddrV4::new(SSDP_GROUP, 3702)),
        request.as_bytes(),
        timeout_duration,
    )
    .await
    .into_iter()
    .filter_map(|(address, packet)| {
        parse_onvif_response(&packet)
            .map(|(observation, identity)| (address, observation, identity))
    })
    .collect()
}

fn mdns_query() -> anyhow::Result<Vec<u8>> {
    let name = Name::from_ascii("_services._dns-sd._udp.local.")?;
    let mut query = Query::query(name, RecordType::PTR);
    query.set_mdns_unicast_response(true);
    let mut message = Message::new(0, MessageType::Query, OpCode::Query);
    message.add_query(query);
    Ok(message.to_vec()?)
}

fn parse_mdns_response(packet: &[u8]) -> Option<Vec<String>> {
    if packet.len() > MAX_MULTICAST_PACKET_BYTES {
        return None;
    }
    let message = Message::from_vec(packet).ok()?;
    let service_types = message
        .answers
        .iter()
        .chain(message.additionals.iter())
        .filter_map(|record| {
            if record.record_type() != RecordType::PTR {
                return None;
            }
            if let RData::PTR(name) = &record.data {
                Some(safe_text(&name.0.to_utf8(), 253))
            } else {
                None
            }
        })
        .filter(|name| !name.is_empty())
        .take(32)
        .collect::<Vec<_>>();
    (!service_types.is_empty()).then_some(service_types)
}

async fn probe_mdns(
    interface: Ipv4Addr,
    timeout_duration: Duration,
) -> Vec<(IpAddr, Value, Option<Value>)> {
    let Ok(socket) = multicast_socket(interface, MDNS_GROUP) else {
        return Vec::new();
    };
    let Ok(request) = mdns_query() else {
        return Vec::new();
    };
    let responses = send_and_collect(
        &socket,
        SocketAddr::V4(SocketAddrV4::new(MDNS_GROUP, 5353)),
        &request,
        timeout_duration,
    )
    .await;
    responses.into_iter().filter_map(|(address, packet)| {
        parse_mdns_response(&packet).map(|service_types| (address, json!({
            "protocol": "mdns", "transport": "udp", "port": 5353, "state": "responded", "serviceTypes": service_types,
        }), None))
    }).collect()
}

async fn probe_mdns_v6(
    interface: Ipv6Addr,
    interface_index: u32,
    timeout_duration: Duration,
) -> Vec<(IpAddr, Value, Option<Value>)> {
    let Ok(socket) = multicast_socket_v6(interface, interface_index, MDNS_GROUP_V6) else {
        return Vec::new();
    };
    let Ok(request) = mdns_query() else {
        return Vec::new();
    };
    send_and_collect(
        &socket,
        scoped_multicast_destination(MDNS_GROUP_V6, 5353, interface_index),
        &request,
        timeout_duration,
    )
    .await
    .into_iter()
    .filter_map(|(address, packet)| {
        parse_mdns_response(&packet).map(|service_types| {
            (
                address,
                json!({
                    "protocol": "mdns", "transport": "udp", "port": 5353,
                    "state": "responded", "serviceTypes": service_types,
                }),
                None,
            )
        })
    })
    .collect()
}

fn add_observation(
    candidates: &mut HashMap<IpAddr, Value>,
    interface_address: IpAddr,
    interface_index: Option<u32>,
    address: IpAddr,
    mut observation: Value,
    identity: Option<Value>,
) {
    observation["interfaceAddress"] = json!(interface_address.to_string());
    if let Some(interface_index) = interface_index {
        observation["interfaceIndex"] = json!(interface_index);
    }
    let candidate = candidates.entry(address).or_insert_with(|| json!({
        "address": address.to_string(), "kind": "network_host",
        "evidence": { "schemaVersion": 1, "observedAt": chrono::Utc::now().to_rfc3339(), "probes": [], "services": [], "httpResponses": [], "snmpResponses": [], "protocolObservations": [] },
    }));
    let evidence = candidate["evidence"]
        .as_object_mut()
        .expect("candidate evidence is an object");
    let protocol = observation["protocol"]
        .as_str()
        .unwrap_or("unknown")
        .to_owned();
    let port = observation["port"].as_u64().unwrap_or_default();
    let service = match protocol.as_str() {
        "ssdp" => "ssdp",
        "onvif-wsd" => "onvif",
        "mdns" => "mdns",
        _ => "unknown",
    };
    if let Some(services) = evidence.get_mut("services").and_then(Value::as_array_mut) {
        if !services
            .iter()
            .any(|item| item["transport"] == "udp" && item["port"] == port)
        {
            services.push(json!({ "transport": "udp", "port": port, "service": service }));
        }
    }
    let probe_name = match protocol.as_str() {
        "onvif-wsd" => "onvif-wsd",
        other => other,
    };
    if let Some(probes) = evidence.get_mut("probes").and_then(Value::as_array_mut) {
        if !probes.iter().any(|item| item.as_str() == Some(probe_name)) {
            probes.push(json!(probe_name));
        }
    }
    if let Some(observations) = evidence
        .get_mut("protocolObservations")
        .and_then(Value::as_array_mut)
    {
        observations.push(observation);
    }
    if let Some(identity) = identity {
        if evidence.get("identity").is_none() {
            evidence.insert("identity".to_owned(), identity.clone());
            if let Some(profile) = identity.get("deviceProfile").and_then(Value::as_str) {
                candidate["profile"] = json!(profile);
                candidate["kind"] = json!(if profile == "camera" {
                    "camera"
                } else {
                    "network_device"
                });
            }
        } else if evidence.get("identity") != Some(&identity) {
            evidence.remove("identity");
            evidence.insert("identityConflict".to_owned(), json!(true));
        }
    }
}

fn add_responses(
    candidates: &mut HashMap<IpAddr, Value>,
    cidr: IpNet,
    interface_address: IpAddr,
    interface_index: Option<u32>,
    responses: impl IntoIterator<Item = (IpAddr, Value, Option<Value>)>,
) {
    for (address, observation, identity) in responses {
        if !cidr.contains(&address) {
            continue;
        }
        add_observation(
            candidates,
            interface_address,
            interface_index,
            address,
            observation,
            identity,
        );
    }
}

pub async fn discover_multicast(cidr: IpNet, timeout_duration: Duration) -> Vec<Value> {
    let Ok(interfaces) = get_if_addrs() else {
        return Vec::new();
    };
    let interfaces = interfaces
        .into_iter()
        .filter(|interface: &Interface| {
            interface.is_oper_up() && !interface.is_loopback() && cidr.contains(&interface.ip())
        })
        .take(MAX_MULTICAST_INTERFACES)
        .collect::<Vec<_>>();
    let mut candidates = HashMap::new();
    for interface in interfaces {
        match interface.ip() {
            IpAddr::V4(interface_ip) => {
                let (ssdp, onvif, mdns) = tokio::join!(
                    probe_ssdp(interface_ip, timeout_duration),
                    probe_onvif(interface_ip, timeout_duration),
                    probe_mdns(interface_ip, timeout_duration),
                );
                add_responses(
                    &mut candidates,
                    cidr,
                    IpAddr::V4(interface_ip),
                    None,
                    ssdp.into_iter().chain(onvif).chain(mdns),
                );
            }
            IpAddr::V6(interface_ip) => {
                let Some(interface_index) = interface.index else {
                    continue;
                };
                let (ssdp, mdns) = tokio::join!(
                    probe_ssdp_v6(interface_ip, interface_index, timeout_duration),
                    probe_mdns_v6(interface_ip, interface_index, timeout_duration),
                );
                add_responses(
                    &mut candidates,
                    cidr,
                    IpAddr::V6(interface_ip),
                    Some(interface_index),
                    ssdp.into_iter().chain(mdns),
                );
            }
        }
    }
    let mut output = candidates.into_values().collect::<Vec<_>>();
    output.sort_by(|left, right| left["address"].as_str().cmp(&right["address"].as_str()));
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::{rdata::PTR, Record};

    #[test]
    fn parses_ssdp_identity_without_retaining_location_urls() {
        let packet = b"HTTP/1.1 200 OK\r\nST: urn:schemas-upnp-org:device:MediaRenderer:1\r\nUSN: uuid:device-123::urn:schemas-upnp-org:device:MediaRenderer:1\r\nSERVER: ExampleOS/1.0 UPnP/1.1\r\nLOCATION: http://10.0.0.5/root.xml\r\n\r\n";
        let (observation, identity) = parse_ssdp_response(packet).unwrap();
        assert_eq!(
            observation["st"],
            "urn:schemas-upnp-org:device:MediaRenderer:1"
        );
        assert!(observation.get("location").is_none());
        assert_eq!(identity.unwrap()["method"], "ssdp");
    }

    #[test]
    fn parses_onvif_camera_type_and_hashes_endpoint_identity() {
        let response = br#"<?xml version="1.0"?><e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"><e:Body><d:ProbeMatch><w:EndpointReference><w:Address>urn:uuid:camera-123</w:Address></w:EndpointReference><d:Types>dn:NetworkVideoTransmitter</d:Types><d:Scopes>onvif://www.onvif.org/name/Camera</d:Scopes><d:XAddrs>http://10.0.0.5/onvif/device_service</d:XAddrs></d:ProbeMatch></e:Body></e:Envelope>"#;
        let (observation, identity) = parse_onvif_response(response).unwrap();
        assert_eq!(observation["deviceType"], "dn:NetworkVideoTransmitter");
        assert_eq!(observation["hasEndpoint"], true);
        assert_eq!(identity.unwrap()["deviceProfile"], "camera");
    }

    #[test]
    fn builds_and_parses_bounded_mdns_service_discovery() {
        let request = Message::from_vec(&mdns_query().unwrap()).unwrap();
        assert_eq!(request.queries.len(), 1);
        assert_eq!(
            request.queries[0].name().to_utf8(),
            "_services._dns-sd._udp.local."
        );
        assert_eq!(request.queries[0].query_type(), RecordType::PTR);

        let service_type = Name::from_ascii("_http._tcp.local.").unwrap();
        let mut response = Message::response(0, OpCode::Query);
        response.add_answer(Record::from_rdata(
            Name::from_ascii("_services._dns-sd._udp.local.").unwrap(),
            120,
            RData::PTR(PTR(service_type)),
        ));
        assert_eq!(
            parse_mdns_response(&response.to_vec().unwrap()).unwrap(),
            vec!["_http._tcp.local."]
        );
    }

    #[test]
    fn ipv6_multicast_destination_preserves_interface_scope() {
        let destination = scoped_multicast_destination(MDNS_GROUP_V6, 5353, 17);
        let SocketAddr::V6(destination) = destination else {
            panic!("IPv6 multicast destination expected");
        };
        assert_eq!(*destination.ip(), MDNS_GROUP_V6);
        assert_eq!(destination.port(), 5353);
        assert_eq!(destination.scope_id(), 17);
        assert_eq!(SSDP_GROUP_V6, "ff02::c".parse::<Ipv6Addr>().unwrap());
    }
}
