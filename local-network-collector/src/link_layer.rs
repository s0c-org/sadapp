use std::net::IpAddr;

use if_addrs::{get_if_addrs, IfAddr, Interface};
use ipnet::IpNet;
use serde_json::{json, Value};

pub const MAX_NEIGHBOR_CACHE_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug)]
pub struct LinkLayerObservation {
    pub address: IpAddr,
    pub evidence: Value,
}

#[derive(Debug, Default)]
pub struct LinkLayerDiscovery {
    pub observations: Vec<LinkLayerObservation>,
    pub diagnostics: Vec<Value>,
}

#[derive(Clone, Debug)]
struct OnLinkNetwork {
    interface_name: String,
    cidr: IpNet,
}

fn network_from_interface(interface: &Interface) -> Option<IpNet> {
    match &interface.addr {
        IfAddr::V4(address) => {
            network_from_mask(IpAddr::V4(address.ip), IpAddr::V4(address.netmask))
        }
        IfAddr::V6(address) => {
            network_from_mask(IpAddr::V6(address.ip), IpAddr::V6(address.netmask))
        }
    }
}

fn network_from_mask(address: IpAddr, mask: IpAddr) -> Option<IpNet> {
    let prefix = match (address, mask) {
        (IpAddr::V4(_), IpAddr::V4(mask)) => {
            let mask = u32::from(mask);
            let prefix = mask.leading_ones() as u8;
            let expected = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            (prefix > 0 && mask == expected).then_some(prefix)
        }
        (IpAddr::V6(_), IpAddr::V6(mask)) => {
            let mask = u128::from(mask);
            let prefix = mask.leading_ones() as u8;
            let expected = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            (prefix > 0 && mask == expected).then_some(prefix)
        }
        _ => None,
    }?;
    IpNet::new(address, prefix)
        .ok()
        .map(|network| network.trunc())
}

fn networks_overlap(left: IpNet, right: IpNet) -> bool {
    left.addr().is_ipv4() == right.addr().is_ipv4()
        && (left.contains(&right.network()) || right.contains(&left.network()))
}

fn mac_address(value: &str) -> Option<String> {
    let bytes = value
        .split(':')
        .map(|part| {
            (part.len() == 2)
                .then(|| u8::from_str_radix(part, 16).ok())
                .flatten()
        })
        .collect::<Option<Vec<_>>>()?;
    if bytes.len() != 6 || bytes.iter().all(|byte| *byte == 0) || bytes[0] & 1 != 0 {
        return None;
    }
    Some(
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

fn valid_interface_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
}

fn neighbor_state_is_usable(value: &Value) -> bool {
    let usable = |state: &str| {
        matches!(
            state.to_ascii_uppercase().as_str(),
            "REACHABLE" | "STALE" | "DELAY" | "PROBE" | "PERMANENT" | "NOARP"
        )
    };
    match value {
        Value::String(state) => usable(state),
        Value::Array(states) => states.iter().filter_map(Value::as_str).any(usable),
        _ => false,
    }
}

pub fn parse_neighbor_cache(
    cidr: IpNet,
    scanned_targets: &[IpAddr],
    interfaces: &[(String, IpNet)],
    cache: &[u8],
) -> Result<Vec<LinkLayerObservation>, ()> {
    let entries: Vec<Value> = serde_json::from_slice(cache).map_err(|_| ())?;
    let targets = scanned_targets
        .iter()
        .copied()
        .collect::<std::collections::HashSet<_>>();
    let on_link = interfaces
        .iter()
        .filter(|(_, network)| networks_overlap(*network, cidr))
        .map(|(interface_name, cidr)| OnLinkNetwork {
            interface_name: interface_name.clone(),
            cidr: *cidr,
        })
        .collect::<Vec<_>>();
    let mut observations = Vec::new();
    for entry in entries {
        let Some(address) = entry
            .get("dst")
            .and_then(Value::as_str)
            .and_then(|value| value.parse::<IpAddr>().ok())
        else {
            continue;
        };
        let Some(interface_name) = entry
            .get("dev")
            .and_then(Value::as_str)
            .filter(|value| valid_interface_name(value))
        else {
            continue;
        };
        let Some(mac_address) = entry
            .get("lladdr")
            .and_then(Value::as_str)
            .and_then(mac_address)
        else {
            continue;
        };
        if !neighbor_state_is_usable(&entry["state"])
            || !cidr.contains(&address)
            || !targets.contains(&address)
        {
            continue;
        }
        let Some(network) = on_link.iter().find(|network| {
            network.interface_name == interface_name && network.cidr.contains(&address)
        }) else {
            continue;
        };
        let (address_family, source) = match address {
            IpAddr::V4(_) => ("ipv4", "arp"),
            IpAddr::V6(_) => ("ipv6", "ndp"),
        };
        observations.push(LinkLayerObservation {
            address,
            evidence: json!({
                "macAddress": mac_address,
                "interfaceName": network.interface_name,
                "networkCidr": network.cidr.to_string(),
                "addressFamily": address_family,
                "source": source,
            }),
        });
    }
    observations.sort_by(|left, right| {
        left.address
            .cmp(&right.address)
            .then_with(|| {
                left.evidence["interfaceName"]
                    .as_str()
                    .cmp(&right.evidence["interfaceName"].as_str())
            })
            .then_with(|| {
                left.evidence["macAddress"]
                    .as_str()
                    .cmp(&right.evidence["macAddress"].as_str())
            })
    });
    observations
        .dedup_by(|left, right| left.address == right.address && left.evidence == right.evidence);
    Ok(observations)
}

fn local_networks() -> Result<Vec<(String, IpNet)>, ()> {
    let interfaces = get_if_addrs().map_err(|_| ())?;
    let networks = interfaces
        .iter()
        .filter(|interface| interface.is_oper_up() && !interface.is_loopback())
        .filter(|interface| valid_interface_name(&interface.name))
        .filter_map(|interface| {
            network_from_interface(interface).map(|cidr| (interface.name.clone(), cidr))
        })
        .collect::<Vec<_>>();
    if networks.is_empty() {
        return Err(());
    }
    Ok(networks)
}

pub fn from_neighbor_cache(
    cidr: IpNet,
    scanned_targets: &[IpAddr],
    cache: Result<&[u8], ()>,
) -> LinkLayerDiscovery {
    let cache = match cache {
        Ok(cache) => cache,
        Err(()) => {
            return LinkLayerDiscovery {
                diagnostics: vec![json!({ "code": "LINK_LAYER_CACHE_UNAVAILABLE" })],
                ..LinkLayerDiscovery::default()
            }
        }
    };
    let interfaces = match local_networks() {
        Ok(interfaces) => interfaces,
        Err(()) => {
            return LinkLayerDiscovery {
                diagnostics: vec![json!({ "code": "LINK_LAYER_INTERFACE_CONTEXT_UNAVAILABLE" })],
                ..LinkLayerDiscovery::default()
            }
        }
    };
    match parse_neighbor_cache(cidr, scanned_targets, &interfaces, cache) {
        Ok(observations) => LinkLayerDiscovery {
            observations,
            diagnostics: Vec::new(),
        },
        Err(()) => LinkLayerDiscovery {
            diagnostics: vec![json!({ "code": "LINK_LAYER_CACHE_UNAVAILABLE" })],
            ..LinkLayerDiscovery::default()
        },
    }
}

pub fn unsupported_platform() -> LinkLayerDiscovery {
    LinkLayerDiscovery {
        diagnostics: vec![json!({ "code": "LINK_LAYER_UNSUPPORTED_PLATFORM" })],
        ..LinkLayerDiscovery::default()
    }
}

pub fn cache_limit_exceeded() -> LinkLayerDiscovery {
    LinkLayerDiscovery {
        diagnostics: vec![json!({ "code": "LINK_LAYER_CACHE_LIMIT_EXCEEDED" })],
        ..LinkLayerDiscovery::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn parse(cidr: &str, interfaces: &[(&str, &str)], cache: &str) -> Vec<LinkLayerObservation> {
        let interfaces = interfaces
            .iter()
            .map(|(name, network)| ((*name).to_owned(), network.parse().unwrap()))
            .collect::<Vec<_>>();
        let cidr = cidr.parse().unwrap();
        let targets = [
            "10.0.0.9".parse().unwrap(),
            "10.0.1.9".parse().unwrap(),
            "10.0.2.9".parse().unwrap(),
            "fd00::9".parse().unwrap(),
            "fd00:1::9".parse().unwrap(),
        ];
        parse_neighbor_cache(cidr, &targets, &interfaces, cache.as_bytes()).unwrap()
    }

    #[test]
    fn emits_only_valid_on_link_neighbor_observations() {
        let observations = parse(
            "10.0.0.0/16",
            &[("lan0", "10.0.0.0/24"), ("lan1", "10.0.1.0/24")],
            r#"[
                {"dst":"10.0.0.9","dev":"lan0","lladdr":"02:AA:BB:CC:DD:EE","state":["STALE"]},
                {"dst":"10.0.1.9","dev":"lan0","lladdr":"02:00:00:00:00:01","state":"REACHABLE"},
                {"dst":"10.0.0.9","dev":"lan0","lladdr":"01:00:5e:00:00:01","state":"REACHABLE"},
                {"dst":"10.0.0.9","dev":"lan0","lladdr":"00:00:00:00:00:00","state":"REACHABLE"},
                {"dst":"10.0.0.9","dev":"lan0","lladdr":"ff:ff:ff:ff:ff:ff","state":"REACHABLE"},
                {"dst":"10.0.0.9","dev":"lan0","lladdr":"02:00:00:00:00:01","state":"INCOMPLETE"},
                {"dst":"10.0.0.9","dev":"lan0","lladdr":"02:00:00:00:00:01","state":"FAILED"},
                {"dst":"10.0.0.9","dev":"lan0","lladdr":"02:00:00:00:00:01","state":"UNKNOWN"},
                {"dst":"10.0.2.9","dev":"lan0","lladdr":"02:00:00:00:00:02","state":"REACHABLE"}
            ]"#,
        );
        assert_eq!(observations.len(), 1);
        assert_eq!(
            observations[0].address,
            "10.0.0.9".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            observations[0].evidence,
            json!({
                "macAddress":"02:aa:bb:cc:dd:ee",
                "interfaceName":"lan0",
                "networkCidr":"10.0.0.0/24",
                "addressFamily":"ipv4",
                "source":"arp"
            })
        );
    }

    #[test]
    fn scopes_ipv6_ndp_to_the_matching_on_link_interface() {
        let observations = parse(
            "fd00::/64",
            &[("lan0", "fd00::/64"), ("lan1", "fd00:1::/64")],
            r#"[
                {"dst":"fd00::9","dev":"lan0","lladdr":"02:00:00:00:00:09","state":["DELAY"]},
                {"dst":"fd00:1::9","dev":"lan1","lladdr":"02:00:00:00:00:19","state":"PERMANENT"}
            ]"#,
        );
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].evidence["addressFamily"], "ipv6");
        assert_eq!(observations[0].evidence["source"], "ndp");
        assert_eq!(observations[0].evidence["networkCidr"], "fd00::/64");
    }

    #[test]
    fn malformed_cache_and_unavailable_sources_have_explicit_diagnostics() {
        assert!(
            parse_neighbor_cache("10.0.0.0/24".parse().unwrap(), &[], &[], b"not-json",).is_err()
        );
        assert_eq!(
            from_neighbor_cache("10.0.0.0/24".parse().unwrap(), &[], Err(())).diagnostics[0]
                ["code"],
            "LINK_LAYER_CACHE_UNAVAILABLE"
        );
        assert_eq!(
            unsupported_platform().diagnostics[0]["code"],
            "LINK_LAYER_UNSUPPORTED_PLATFORM"
        );
        assert_eq!(
            cache_limit_exceeded().diagnostics[0]["code"],
            "LINK_LAYER_CACHE_LIMIT_EXCEEDED"
        );
    }

    #[test]
    fn rejects_invalid_interface_names_before_emitting_evidence() {
        let observations = parse(
            "10.0.0.0/24",
            &[("lan0", "10.0.0.0/24")],
            r#"[
                {"dst":"10.0.0.9","dev":"lan0","lladdr":"02:00:00:00:00:09","state":"STALE"},
                {"dst":"10.0.0.9","dev":"lan/0","lladdr":"02:00:00:00:00:09","state":"STALE"},
                {"dst":"10.0.0.9","dev":"lan 0","lladdr":"02:00:00:00:00:09","state":"STALE"}
            ]"#,
        );
        assert_eq!(observations.len(), 1);
        assert!(valid_interface_name("vlan.12"));
        assert!(!valid_interface_name("lan 0"));
    }

    #[test]
    fn ipv4_and_ipv6_masks_are_used_without_inventing_prefixes() {
        assert_eq!(
            network_from_mask(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
                IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0))
            )
            .unwrap()
            .to_string(),
            "192.168.1.0/24"
        );
        assert_eq!(
            network_from_mask(
                IpAddr::V6("fd00::2".parse::<Ipv6Addr>().unwrap()),
                IpAddr::V6("ffff:ffff:ffff:ffff::".parse().unwrap())
            )
            .unwrap()
            .to_string(),
            "fd00::/64"
        );
        assert!(network_from_mask(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            IpAddr::V4(Ipv4Addr::new(255, 0, 255, 0))
        )
        .is_none());
        assert!(network_from_mask(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        )
        .is_none());
    }
}
