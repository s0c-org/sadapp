use std::net::IpAddr;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use quick_xml::{events::Event, Reader, XmlVersion};
use reqwest::redirect::Policy;
use serde_json::{json, Map, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::{model::TaskLease, network_policy::NetworkPolicy};

const MAX_RESPONSE_BYTES: usize = 256 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

fn text<'a>(payload: &'a Map<String, Value>, key: &str) -> Result<&'a str> {
    payload
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("{key} is required"))
}

fn target(task: &TaskLease, policy: &NetworkPolicy) -> Result<IpAddr> {
    let target = text(&task.payload, "target")?
        .parse::<IpAddr>()
        .context("target must be an IP address")?;
    policy.validate_target(target)?;
    Ok(target)
}

fn secret<'a>(task: &'a TaskLease, id: &str) -> Result<&'a str> {
    task.secrets
        .get(id)
        .map(String::as_str)
        .ok_or_else(|| anyhow!("protocol credential is unavailable"))
}

fn bounded_u16(payload: &Map<String, Value>, key: &str, default: u16) -> Result<u16> {
    let raw = payload
        .get(key)
        .and_then(Value::as_u64)
        .unwrap_or(u64::from(default));
    u16::try_from(raw).map_err(|_| anyhow!("{key} is invalid"))
}

async fn read_bounded(mut response: reqwest::Response) -> Result<Value> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        bail!("protocol response exceeds the response limit");
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .context("protocol response read failed")?
    {
        if bytes.len() + chunk.len() > MAX_RESPONSE_BYTES {
            bail!("protocol response exceeds the response limit");
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).context("protocol response is not valid JSON")
}

async fn collect_redfish(task: &TaskLease, policy: &NetworkPolicy) -> Result<Map<String, Value>> {
    let target = target(task, policy)?;
    let port = bounded_u16(&task.payload, "port", 443)?;
    let system = task
        .payload
        .get("resourcePath")
        .and_then(Value::as_str)
        .unwrap_or("/redfish/v1/Systems/1");
    if !system.starts_with("/redfish/v1/") || system.contains('?') || system.contains('#') {
        bail!("Redfish resource path is not allowlisted");
    }
    let username = text(&task.payload, "usernameSecretId").and_then(|key| secret(task, key))?;
    let password = text(&task.payload, "passwordSecretId").and_then(|key| secret(task, key))?;
    let client = reqwest::Client::builder()
        .redirect(Policy::none())
        .timeout(REQUEST_TIMEOUT)
        .danger_accept_invalid_certs(
            task.payload.get("allowSelfSigned").and_then(Value::as_bool) == Some(true),
        )
        .build()?;
    let address = std::net::SocketAddr::new(target, port);
    let url = format!("https://{address}{system}");
    let response = client
        .get(url)
        .basic_auth(username, Some(password))
        .send()
        .await
        .context("Redfish request failed")?;
    if !response.status().is_success() {
        bail!("Redfish request returned {}", response.status());
    }
    let value = read_bounded(response).await?;
    let Some(object) = value.as_object() else {
        bail!("Redfish response must be an object");
    };
    let allowed = [
        "Id",
        "Name",
        "Manufacturer",
        "Model",
        "SerialNumber",
        "SystemType",
        "PowerState",
        "Status",
        "ProcessorSummary",
        "MemorySummary",
        "BiosVersion",
    ];
    Ok(object
        .iter()
        .filter(|(key, _)| allowed.contains(&key.as_str()))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect())
}

async fn collect_modbus(task: &TaskLease, policy: &NetworkPolicy) -> Result<Map<String, Value>> {
    let target = target(task, policy)?;
    let port = bounded_u16(&task.payload, "port", 502)?;
    let unit_id = task
        .payload
        .get("unitId")
        .and_then(Value::as_u64)
        .unwrap_or(1);
    let start = task.payload.get("startAddress").and_then(Value::as_u64);
    let quantity = task
        .payload
        .get("quantity")
        .and_then(Value::as_u64)
        .unwrap_or(1);
    if unit_id > 255 || start.is_none_or(|value| value > 65_535) || !(1..=100).contains(&quantity) {
        bail!("Modbus unit, address or quantity is invalid");
    }
    let mut stream = tokio::time::timeout(REQUEST_TIMEOUT, TcpStream::connect((target, port)))
        .await
        .context("Modbus connect timed out")?
        .context("Modbus connect failed")?;
    let transaction = 1_u16;
    let start = u16::try_from(start.unwrap())?;
    let quantity = u16::try_from(quantity)?;
    let mut request = Vec::with_capacity(12);
    request.extend_from_slice(&transaction.to_be_bytes());
    request.extend_from_slice(&0_u16.to_be_bytes());
    request.extend_from_slice(&6_u16.to_be_bytes());
    request.push(u8::try_from(unit_id)?);
    request.push(3);
    request.extend_from_slice(&start.to_be_bytes());
    request.extend_from_slice(&quantity.to_be_bytes());
    stream.write_all(&request).await?;
    let mut header = [0_u8; 7];
    tokio::time::timeout(REQUEST_TIMEOUT, stream.read_exact(&mut header)).await??;
    if header[6] != u8::try_from(unit_id)? || header[5] != 3 {
        let function = header[5];
        bail!("Modbus rejected read request with function {function}");
    }
    let mut count = [0_u8; 1];
    tokio::time::timeout(REQUEST_TIMEOUT, stream.read_exact(&mut count)).await??;
    if count[0] as usize != usize::from(quantity) * 2 || count[0] > 200 {
        bail!("Modbus response length is invalid");
    }
    let mut data = vec![0_u8; count[0] as usize];
    tokio::time::timeout(REQUEST_TIMEOUT, stream.read_exact(&mut data)).await??;
    let registers = data
        .chunks_exact(2)
        .enumerate()
        .map(|(index, pair)| json!({ "address": u32::from(start) + index as u32, "value": u16::from_be_bytes([pair[0], pair[1]]) }))
        .collect::<Vec<_>>();
    Ok(Map::from_iter([(
        "registers".into(),
        Value::Array(registers),
    )]))
}

fn mqtt_remaining_length(mut value: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    loop {
        let mut digit = (value % 128) as u8;
        value /= 128;
        if value > 0 {
            digit |= 128;
        }
        bytes.push(digit);
        if value == 0 {
            break;
        }
    }
    bytes
}

fn mqtt_string(value: &str) -> Vec<u8> {
    let bytes = value.as_bytes();
    let mut encoded = Vec::with_capacity(2 + bytes.len());
    encoded.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    encoded.extend_from_slice(bytes);
    encoded
}

async fn collect_mqtt(task: &TaskLease, policy: &NetworkPolicy) -> Result<Map<String, Value>> {
    let target = target(task, policy)?;
    let port = bounded_u16(&task.payload, "port", 1883)?;
    let topic = text(&task.payload, "topic")?;
    if topic.len() > 256 || topic.contains(['+', '#', '\0']) {
        bail!("MQTT task requires one bounded topic, not a wildcard");
    }
    let username_id = task.payload.get("usernameSecretId").and_then(Value::as_str);
    let password_id = task.payload.get("passwordSecretId").and_then(Value::as_str);
    let username = username_id.map(|key| secret(task, key)).transpose()?;
    let password = password_id.map(|key| secret(task, key)).transpose()?;
    let client_id = format!(
        "sadapp-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..16]
    );
    let mut variable = mqtt_string("MQTT");
    let flags = 0x02
        | if username.is_some() { 0x80 } else { 0 }
        | if password.is_some() { 0x40 } else { 0 };
    variable.extend_from_slice(&[4, flags, 0, 30]);
    variable.extend_from_slice(&mqtt_string(&client_id));
    if let Some(username) = username {
        variable.extend_from_slice(&mqtt_string(username));
    }
    if let Some(password) = password {
        variable.extend_from_slice(&mqtt_string(password));
    }
    let mut packet = vec![0x10];
    packet.extend(mqtt_remaining_length(variable.len()));
    packet.extend(variable);
    let mut stream =
        tokio::time::timeout(REQUEST_TIMEOUT, TcpStream::connect((target, port))).await??;
    stream.write_all(&packet).await?;
    let mut connack = [0_u8; 4];
    tokio::time::timeout(REQUEST_TIMEOUT, stream.read_exact(&mut connack)).await??;
    if connack[0] != 0x20 || connack[3] != 0 {
        bail!("MQTT connection was not accepted");
    }
    let mut subscribe = vec![0, 1];
    subscribe.extend(mqtt_string(topic));
    subscribe.push(0);
    let mut packet = vec![0x82];
    packet.extend(mqtt_remaining_length(subscribe.len()));
    packet.extend(subscribe);
    stream.write_all(&packet).await?;
    let mut suback = [0_u8; 5];
    tokio::time::timeout(REQUEST_TIMEOUT, stream.read_exact(&mut suback)).await??;
    if suback[0] != 0x90 {
        bail!("MQTT subscribe was not acknowledged");
    }
    let mut header = [0_u8; 1];
    tokio::time::timeout(REQUEST_TIMEOUT, stream.read_exact(&mut header)).await??;
    if header[0] >> 4 != 3 {
        bail!("MQTT subscription did not return a publish packet");
    }
    let mut multiplier = 1;
    let mut remaining = 0;
    loop {
        let mut digit = [0_u8; 1];
        tokio::time::timeout(REQUEST_TIMEOUT, stream.read_exact(&mut digit)).await??;
        remaining += usize::from(digit[0] & 127) * multiplier;
        if digit[0] & 128 == 0 {
            break;
        }
        multiplier *= 128;
        if remaining > MAX_RESPONSE_BYTES {
            bail!("MQTT payload is too large");
        }
    }
    let mut publish = vec![0_u8; remaining];
    tokio::time::timeout(REQUEST_TIMEOUT, stream.read_exact(&mut publish)).await??;
    if publish.len() < 2 {
        bail!("MQTT publish packet is truncated");
    }
    let topic_len = usize::from(u16::from_be_bytes([publish[0], publish[1]]));
    if topic_len + 2 > publish.len() {
        bail!("MQTT topic length is invalid");
    }
    let payload = &publish[topic_len + 2..];
    let value = serde_json::from_slice::<Value>(payload)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(payload).into_owned()));
    Ok(Map::from_iter([
        ("topic".into(), Value::String(topic.into())),
        ("value".into(), value),
    ]))
}

async fn collect_unifi_or_bacula(
    task: &TaskLease,
    policy: &NetworkPolicy,
    unifi: bool,
) -> Result<Map<String, Value>> {
    let target = target(task, policy)?;
    let port = bounded_u16(&task.payload, "port", 443)?;
    let username = text(&task.payload, "usernameSecretId").and_then(|key| secret(task, key))?;
    let password = text(&task.payload, "passwordSecretId").and_then(|key| secret(task, key))?;
    let base = format!("https://{}", std::net::SocketAddr::new(target, port));
    let client = reqwest::Client::builder()
        .redirect(Policy::none())
        .timeout(REQUEST_TIMEOUT)
        .danger_accept_invalid_certs(
            task.payload.get("allowSelfSigned").and_then(Value::as_bool) == Some(true),
        )
        .build()?;
    let login_path = if unifi {
        "/api/auth/login"
    } else {
        "/api/auth"
    };
    let login = client
        .post(format!("{base}{login_path}"))
        .json(&json!({ "username": username, "password": password }))
        .send()
        .await
        .context("controller login failed")?;
    if !login.status().is_success() {
        bail!("controller login returned {}", login.status());
    }
    let cookie = login
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter_map(|value| value.split(';').next())
        .collect::<Vec<_>>()
        .join("; ");
    let resource = if unifi {
        "/proxy/network/api/s/default/stat/device"
    } else {
        text(&task.payload, "resourcePath")?
    };
    if !resource.starts_with('/') || resource.contains('?') || resource.contains('#') {
        bail!("controller resource path is invalid");
    }
    let response = client
        .get(format!("{base}{resource}"))
        .header("cookie", cookie)
        .send()
        .await
        .context("controller request failed")?;
    if !response.status().is_success() {
        bail!("controller request returned {}", response.status());
    }
    let value = read_bounded(response).await?;
    let Some(object) = value.as_object() else {
        bail!("controller response must be an object");
    };
    let mut result = Map::new();
    if let Some(data) = object.get("data") {
        result.insert("data".into(), data.clone());
    }
    for key in ["meta", "count"] {
        if let Some(value) = object.get(key) {
            result.insert((*key).into(), value.clone());
        }
    }
    Ok(result)
}

async fn collect_restconf(task: &TaskLease, policy: &NetworkPolicy) -> Result<Map<String, Value>> {
    let target = target(task, policy)?;
    let port = bounded_u16(&task.payload, "port", 443)?;
    let resource_path = text(&task.payload, "resourcePath")?;
    if !resource_path.starts_with("/restconf/data/")
        || resource_path.contains('?')
        || resource_path.contains('#')
        || resource_path.len() > 512
    {
        bail!("RESTCONF path must select one allowlisted data resource below /restconf/data/");
    }

    let username = text(&task.payload, "usernameSecretId").and_then(|key| secret(task, key))?;
    let password = text(&task.payload, "passwordSecretId").and_then(|key| secret(task, key))?;
    let client = reqwest::Client::builder()
        .redirect(Policy::none())
        .timeout(REQUEST_TIMEOUT)
        .danger_accept_invalid_certs(
            task.payload.get("allowSelfSigned").and_then(Value::as_bool) == Some(true),
        )
        .build()?;
    let response = client
        .get(format!(
            "https://{}{}",
            std::net::SocketAddr::new(target, port),
            resource_path
        ))
        .basic_auth(username, Some(password))
        .header(
            "accept",
            "application/yang-data+json, application/json;q=0.9",
        )
        .send()
        .await
        .context("RESTCONF request failed")?;
    if !response.status().is_success() {
        bail!("RESTCONF request returned {}", response.status());
    }
    let value = read_bounded(response).await?;
    value
        .as_object()
        .cloned()
        .ok_or_else(|| anyhow!("RESTCONF response must be a JSON object"))
}

fn local_xml_name(name: &str) -> String {
    name.rsplit(':').next().unwrap_or("").to_owned()
}

fn decode_xml_entities(value: &str) -> String {
    value
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

fn parse_netgear_attach_devices(xml: &str) -> Result<Vec<Value>> {
    if xml.len() > MAX_RESPONSE_BYTES {
        bail!("Netgear SOAP response exceeded the response limit");
    }
    let marker = xml
        .find("NewAttachDevice")
        .ok_or_else(|| anyhow!("Netgear SOAP returned no attached-device inventory"))?;
    let start = xml[marker..]
        .find('>')
        .map(|offset| marker + offset + 1)
        .ok_or_else(|| anyhow!("Netgear SOAP attached-device element is malformed"))?;
    let end = xml[start..]
        .find("</")
        .map(|offset| start + offset)
        .ok_or_else(|| anyhow!("Netgear SOAP attached-device element is incomplete"))?;
    let attached = decode_xml_entities(&xml[start..end]);
    if !attached.contains('<') {
        bail!("Netgear SOAP returned no attached-device inventory");
    }
    let mut list = Reader::from_str(&attached);
    list.config_mut().trim_text(true);
    let mut field = String::new();
    let mut device = Map::new();
    let mut devices = Vec::new();
    loop {
        match list
            .read_event()
            .context("invalid Netgear attached-device list")?
        {
            Event::Start(element) => field = local_xml_name(element.name().as_ref()),
            Event::Text(text) => {
                if [
                    "IP",
                    "IPAddress",
                    "MAC",
                    "MACAddress",
                    "Name",
                    "DeviceName",
                    "Type",
                    "DeviceType",
                ]
                .contains(&field.as_str())
                {
                    device.insert(
                        field.clone(),
                        Value::String(text.xml_content(XmlVersion::Implicit1_0).into_owned()),
                    );
                }
            }
            Event::End(element) => {
                field.clear();
                if ["Item", "Device"].contains(&local_xml_name(element.name().as_ref()).as_str())
                    && !device.is_empty()
                {
                    devices.push(Value::Object(std::mem::take(&mut device)));
                }
            }
            Event::Eof => break,
            _ => {}
        }
        if devices.len() > 512 {
            bail!("Netgear SOAP returned too many attached devices");
        }
    }
    if devices.is_empty() {
        bail!("Netgear SOAP attached-device inventory was empty");
    }
    Ok(devices)
}

async fn collect_netgear_soap(
    task: &TaskLease,
    policy: &NetworkPolicy,
) -> Result<Map<String, Value>> {
    let target = target(task, policy)?;
    let port = bounded_u16(&task.payload, "port", 5000)?;
    let username = text(&task.payload, "usernameSecretId").and_then(|key| secret(task, key))?;
    let password = text(&task.payload, "passwordSecretId").and_then(|key| secret(task, key))?;
    let service = "urn:NETGEAR-ROUTER:service:DeviceInfo:1";
    let body = format!(
        r#"<?xml version="1.0" encoding="utf-8"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:GetAttachDevice xmlns:u="{service}"/></s:Body></s:Envelope>"#
    );
    let client = reqwest::Client::builder()
        .redirect(Policy::none())
        .timeout(REQUEST_TIMEOUT)
        .build()?;
    let response = client
        .post(format!(
            "http://{}/soap/server_sa/",
            std::net::SocketAddr::new(target, port)
        ))
        .basic_auth(username, Some(password))
        .header("content-type", "text/xml; charset=utf-8")
        .header("soapaction", format!("\"{service}#GetAttachDevice\""))
        .body(body)
        .send()
        .await
        .context("Netgear SOAP request failed")?;
    if !response.status().is_success() {
        bail!("Netgear SOAP request returned {}", response.status());
    }
    let mut bytes = Vec::new();
    let mut response = response;
    while let Some(chunk) = response
        .chunk()
        .await
        .context("Netgear SOAP response failed")?
    {
        if bytes.len() + chunk.len() > MAX_RESPONSE_BYTES {
            bail!("Netgear SOAP response exceeded the response limit");
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(Map::from_iter([(
        "devices".into(),
        Value::Array(parse_netgear_attach_devices(&String::from_utf8_lossy(
            &bytes,
        ))?),
    )]))
}

pub async fn collect(task: &TaskLease, policy: &NetworkPolicy) -> Result<Map<String, Value>> {
    let protocol = text(&task.payload, "protocol")?.to_ascii_uppercase();
    match protocol.as_str() {
        "REDFISH" => collect_redfish(task, policy).await,
        "MODBUS" => collect_modbus(task, policy).await,
        "MQTT" => collect_mqtt(task, policy).await,
        "UNIFI" => collect_unifi_or_bacula(task, policy, true).await,
        "BACULA" => collect_unifi_or_bacula(task, policy, false).await,
        "RESTCONF" => collect_restconf(task, policy).await,
        "NETGEAR_SOAP" => collect_netgear_soap(task, policy).await,
        _ => bail!("protocol is not supported"),
    }
}

#[cfg(test)]
mod tests {
    use super::parse_netgear_attach_devices;

    #[test]
    fn parses_bounded_netgear_attached_device_soap_inventory() {
        let xml = r#"<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><GetAttachDeviceResponse><NewAttachDevice>&lt;Devices&gt;&lt;Device&gt;&lt;IP&gt;10.0.0.44&lt;/IP&gt;&lt;MAC&gt;00:11:22:33:44:55&lt;/MAC&gt;&lt;Name&gt;NAS&lt;/Name&gt;&lt;Type&gt;computer&lt;/Type&gt;&lt;/Device&gt;&lt;/Devices&gt;</NewAttachDevice></GetAttachDeviceResponse></s:Body></s:Envelope>"#;
        let devices = parse_netgear_attach_devices(xml).unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0]["IP"], "10.0.0.44");
        assert_eq!(devices[0]["MAC"], "00:11:22:33:44:55");
        assert_eq!(devices[0]["Name"], "NAS");
    }

    #[test]
    fn rejects_empty_netgear_attached_device_inventory() {
        let error = parse_netgear_attach_devices(
            "<Envelope><Body><NewAttachDevice>none</NewAttachDevice></Body></Envelope>",
        )
        .unwrap_err();
        assert!(error.to_string().contains("inventory"));
    }
}
