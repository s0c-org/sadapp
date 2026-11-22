use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use anyhow::{anyhow, bail, Context, Result};
use md5::{Digest, Md5};
use quick_xml::{events::Event, Reader, XmlVersion};
use rand::{distr::Alphanumeric, RngExt};
use reqwest::{redirect::Policy, Client, Response, StatusCode};
use serde_json::{Map, Value};
use url::Url;

use crate::{model::TaskLease, network_policy::NetworkPolicy};

const MAX_XML_BYTES: usize = 128 * 1024;
const MAX_HTTP_TIMEOUT: Duration = Duration::from_secs(10);

struct Action {
    service_type: &'static str,
    name: &'static str,
    result_fields: &'static [&'static str],
}

const ACTIONS: &[Action] = &[
    Action {
        service_type: "urn:dslforum-org:service:DeviceInfo:1",
        name: "GetInfo",
        result_fields: &[
            "NewManufacturerName",
            "NewModelName",
            "NewSoftwareVersion",
            "NewUpTime",
        ],
    },
    Action {
        service_type: "urn:dslforum-org:service:WANCommonInterfaceConfig:1",
        name: "GetCommonLinkProperties",
        result_fields: &[
            "NewLayer1UpstreamMaxBitRate",
            "NewLayer1DownstreamMaxBitRate",
            "NewPhysicalLinkStatus",
        ],
    },
    Action {
        service_type: "urn:schemas-upnp-org:service:WANIPConnection:1",
        name: "GetExternalIPAddress",
        result_fields: &["NewExternalIPAddress"],
    },
    Action {
        service_type: "urn:dslforum-org:service:LANEthernetInterfaceConfig:1",
        name: "GetStatistics",
        result_fields: &[
            "NewBytesSent",
            "NewBytesReceived",
            "NewPacketsSent",
            "NewPacketsReceived",
        ],
    },
];

pub fn allowed_actions() -> impl Iterator<Item = &'static str> {
    ACTIONS.iter().map(|action| match action.name {
        "GetInfo" => "DeviceInfo:GetInfo",
        "GetCommonLinkProperties" => "WANCommonInterfaceConfig:GetCommonLinkProperties",
        "GetExternalIPAddress" => "WANIPConnection:GetExternalIPAddress",
        "GetStatistics" => "LANEthernetInterfaceConfig:GetStatistics",
        _ => action.name,
    })
}

#[derive(Default)]
struct Service {
    service_type: String,
    control_url: String,
}

fn local_name(name: &str) -> &str {
    name.rsplit(':').next().unwrap_or(name)
}

fn parse_services(xml: &str) -> Result<Vec<Service>> {
    if xml.len() > MAX_XML_BYTES {
        bail!("TR-064 device description exceeded the response limit");
    }
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut current = String::new();
    let mut service = Service::default();
    let mut services = Vec::new();
    loop {
        match reader
            .read_event()
            .context("invalid TR-064 device description")?
        {
            Event::Start(element) => current = local_name(element.name().as_ref()).to_owned(),
            Event::Text(text) => {
                let value = text.xml_content(XmlVersion::Implicit1_0).into_owned();
                match current.as_str() {
                    "serviceType" => service.service_type.push_str(&value),
                    "controlURL" => service.control_url.push_str(&value),
                    _ => {}
                }
            }
            Event::End(element) => {
                if local_name(element.name().as_ref()) == "service" {
                    if !service.service_type.is_empty() && !service.control_url.is_empty() {
                        services.push(std::mem::take(&mut service));
                    } else {
                        service = Service::default();
                    }
                }
                current.clear();
            }
            Event::Eof => break,
            _ => {}
        }
        if services.len() > 32 {
            bail!("TR-064 device description advertised too many services");
        }
    }
    Ok(services)
}

fn parse_allowlisted_values(xml: &str, fields: &[&str]) -> Result<Map<String, Value>> {
    if xml.len() > MAX_XML_BYTES {
        bail!("TR-064 response exceeded the response limit");
    }
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut current = String::new();
    let mut values = Map::new();
    loop {
        match reader
            .read_event()
            .context("invalid TR-064 SOAP response")?
        {
            Event::Start(element) => current = local_name(element.name().as_ref()).to_owned(),
            Event::Text(text) => {
                if fields.contains(&current.as_str()) && values.len() <= fields.len() {
                    let value = text.xml_content(XmlVersion::Implicit1_0);
                    values.insert(current.clone(), Value::String(value.into_owned()));
                }
            }
            Event::End(_) => current.clear(),
            Event::Eof => break,
            _ => {}
        }
    }
    Ok(values)
}

async fn bounded_text(mut response: Response) -> Result<String> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_XML_BYTES as u64)
    {
        bail!("TR-064 response exceeded the response limit");
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .context("TR-064 response body failed")?
    {
        if bytes.len() + chunk.len() > MAX_XML_BYTES {
            bail!("TR-064 response exceeded the response limit");
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn digest_field(challenge: &str, key: &str) -> Option<String> {
    challenge.split(',').find_map(|part| {
        let (name, value) = part.trim().split_once('=')?;
        (name.eq_ignore_ascii_case(key)).then(|| value.trim().trim_matches('"').to_owned())
    })
}

fn md5_hex(value: &[u8]) -> String {
    Md5::digest(value)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn escape_digest(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn digest_authorization(
    challenge: &str,
    username: &str,
    password: &str,
    uri: &str,
) -> Result<String> {
    if challenge.len() > 4_096 {
        bail!("TR-064 digest challenge exceeds the header limit");
    }
    let realm = digest_field(challenge, "realm").ok_or_else(|| anyhow!("Digest realm missing"))?;
    let nonce = digest_field(challenge, "nonce").ok_or_else(|| anyhow!("Digest nonce missing"))?;
    let algorithm = digest_field(challenge, "algorithm").unwrap_or_else(|| "MD5".into());
    if !algorithm.eq_ignore_ascii_case("MD5") {
        bail!("unsupported TR-064 digest algorithm");
    }
    let qop = digest_field(challenge, "qop")
        .unwrap_or_else(|| "auth".into())
        .split(',')
        .any(|value| value.trim().eq_ignore_ascii_case("auth"))
        .then_some("auth")
        .ok_or_else(|| anyhow!("TR-064 server does not support Digest qop=auth"))?;
    let cnonce: String = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(20)
        .map(char::from)
        .collect();
    let nc = "00000001";
    let ha1 = md5_hex(format!("{username}:{realm}:{password}").as_bytes());
    let ha2 = md5_hex(format!("POST:{uri}").as_bytes());
    let response = md5_hex(format!("{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}").as_bytes());
    let opaque = digest_field(challenge, "opaque")
        .map(|value| format!(", opaque=\"{}\"", escape_digest(&value)))
        .unwrap_or_default();
    Ok(format!(
        "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", response=\"{response}\", algorithm=MD5, qop=auth, nc={nc}, cnonce=\"{}\"{opaque}",
        escape_digest(username), escape_digest(&realm), escape_digest(&nonce), escape_digest(uri), escape_digest(&cnonce)
    ))
}

fn endpoint_url(base: &Url, control_url: &str, target: IpAddr) -> Result<Url> {
    let endpoint = base
        .join(control_url)
        .context("invalid TR-064 control URL")?;
    let host = endpoint
        .host_str()
        .ok_or_else(|| anyhow!("TR-064 control URL has no host"))?;
    let host_ip: IpAddr = host
        .trim_matches(&['[', ']'][..])
        .parse()
        .map_err(|_| anyhow!("TR-064 control URL must use the target IP address"))?;
    if host_ip != target {
        bail!("TR-064 control URL points to a different host");
    }
    if endpoint.scheme() != "http" || endpoint.username() != "" || endpoint.password().is_some() {
        bail!("TR-064 control URL must use unauthenticated HTTP");
    }
    if endpoint.port_or_known_default() != Some(49000) {
        bail!("TR-064 control URL must use the FRITZ!Box read-only port 49000");
    }
    Ok(endpoint)
}

fn soap_body(service_type: &str, action: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:{action} xmlns:u="{service_type}"/></s:Body></s:Envelope>"#
    )
}

pub async fn collect(task: &TaskLease, policy: &NetworkPolicy) -> Result<Map<String, Value>> {
    let target: IpAddr = task
        .payload
        .get("target")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("target is required"))?
        .parse()
        .context("target must be an IP address")?;
    policy.validate_target(target)?;
    let action_name = task
        .payload
        .get("action")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("action is required"))?;
    let action = ACTIONS
        .iter()
        .find(|action| action_key(action) == action_name)
        .ok_or_else(|| anyhow!("TR-064 action is not allowlisted"))?;
    let username_id = task
        .payload
        .get("usernameSecretId")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("usernameSecretId is required"))?;
    let password_id = task
        .payload
        .get("passwordSecretId")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("passwordSecretId is required"))?;
    let username = task
        .secrets
        .get(username_id)
        .ok_or_else(|| anyhow!("TR-064 username secret unavailable"))?;
    let password = task
        .secrets
        .get(password_id)
        .ok_or_else(|| anyhow!("TR-064 password secret unavailable"))?;
    if username.is_empty() || password.is_empty() {
        bail!("TR-064 credentials cannot be empty");
    }

    let description_url: Url =
        format!("http://{}/tr64desc.xml", SocketAddr::new(target, 49_000)).parse()?;
    let client = Client::builder()
        .redirect(Policy::none())
        .timeout(MAX_HTTP_TIMEOUT)
        .build()?;
    let description = client
        .get(description_url.clone())
        .send()
        .await
        .context("TR-064 description request failed")?;
    if !description.status().is_success() {
        bail!(
            "TR-064 description request returned {}",
            description.status()
        );
    }

    fn action_key(action: &Action) -> String {
        format!(
            "{}:{}",
            action.service_type.rsplit(':').nth(1).unwrap_or(""),
            action.name
        )
    }
    let services = parse_services(&bounded_text(description).await?)?;
    let service = services
        .iter()
        .find(|service| service.service_type == action.service_type)
        .ok_or_else(|| anyhow!("TR-064 service is not advertised by this device"))?;
    let control_url = endpoint_url(&description_url, &service.control_url, target)?;
    let body = soap_body(action.service_type, action.name);
    let uri = control_url[url::Position::BeforePath..url::Position::AfterQuery].to_owned();
    let soap_action = format!("{}#{}", action.service_type, action.name);
    let first = client
        .post(control_url.clone())
        .header("content-type", "text/xml; charset=utf-8")
        .header("soapaction", format!("\"{soap_action}\""))
        .body(body.clone())
        .send()
        .await
        .context("TR-064 action request failed")?;
    let response = if first.status() == StatusCode::UNAUTHORIZED {
        let challenge = first
            .headers()
            .get("www-authenticate")
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| anyhow!("TR-064 authentication challenge missing"))?
            .trim()
            .strip_prefix("Digest ")
            .ok_or_else(|| anyhow!("TR-064 requires unsupported authentication"))?;
        let authorization = digest_authorization(challenge, username, password, &uri)?;
        client
            .post(control_url)
            .header("content-type", "text/xml; charset=utf-8")
            .header("soapaction", format!("\"{soap_action}\""))
            .header("authorization", authorization)
            .body(body)
            .send()
            .await
            .context("TR-064 authenticated action request failed")?
    } else {
        first
    };
    if !response.status().is_success() {
        bail!("TR-064 action returned {}", response.status());
    }
    parse_allowlisted_values(&bounded_text(response).await?, action.result_fields)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposes_only_read_only_actions() {
        assert_eq!(
            allowed_actions().collect::<Vec<_>>(),
            [
                "DeviceInfo:GetInfo",
                "WANCommonInterfaceConfig:GetCommonLinkProperties",
                "WANIPConnection:GetExternalIPAddress",
                "LANEthernetInterfaceConfig:GetStatistics"
            ]
        );
    }

    #[test]
    fn parses_service_endpoints_without_accepting_unbounded_xml() {
        let xml = r#"<root><service><serviceType>urn:dslforum-org:service:DeviceInfo:1</serviceType><controlURL>/upnp/control/deviceinfo</controlURL></service></root>"#;
        assert_eq!(
            parse_services(xml).unwrap()[0].control_url,
            "/upnp/control/deviceinfo"
        );
    }

    #[test]
    fn rejects_cross_host_control_endpoints() {
        let base = Url::parse("http://192.168.178.1:49000/tr64desc.xml").unwrap();
        assert!(endpoint_url(
            &base,
            "http://192.168.178.2:49000/control",
            "192.168.178.1".parse().unwrap()
        )
        .is_err());
    }
}
