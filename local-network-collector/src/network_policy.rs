use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{bail, Context, Result};
use ipnet::IpNet;

pub const MAX_DISCOVERY_HOSTS: u128 = 4096;

#[derive(Clone, Debug, Default)]
pub struct NetworkPolicy {
    allowed: Vec<IpNet>,
}

impl NetworkPolicy {
    pub fn new(cidrs: &[String]) -> Result<Self> {
        let allowed = cidrs
            .iter()
            .map(|value| {
                value
                    .parse::<IpNet>()
                    .with_context(|| format!("invalid allowed CIDR: {value}"))
            })
            .collect::<Result<Vec<_>>>()?;
        for cidr in &allowed {
            validate_local_cidr(cidr)?;
        }
        Ok(Self { allowed })
    }

    pub fn cidrs(&self) -> &[IpNet] {
        &self.allowed
    }

    pub fn allows(&self, address: IpAddr) -> bool {
        is_private_local(address) && self.allowed.iter().any(|cidr| cidr.contains(&address))
    }

    pub fn validate_target(&self, address: IpAddr) -> Result<()> {
        if !self.allows(address) {
            bail!("target address is public or outside the collector allowed CIDRs");
        }
        Ok(())
    }

    pub fn validate_discovery_cidr(&self, cidr: IpNet) -> Result<()> {
        validate_local_cidr(&cidr)?;
        if host_count(cidr) > MAX_DISCOVERY_HOSTS {
            bail!("discovery CIDR exceeds the {MAX_DISCOVERY_HOSTS}-host limit");
        }
        if !self
            .allowed
            .iter()
            .any(|allowed| contains_net(*allowed, cidr))
        {
            bail!("discovery CIDR is outside the collector allowed CIDRs");
        }
        Ok(())
    }
}

pub fn is_private_local(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            address.is_private() || address.is_loopback() || address.is_link_local()
        }
        IpAddr::V6(address) => {
            address.is_loopback() || address.is_unique_local() || address.is_unicast_link_local()
        }
    }
}

fn validate_local_cidr(cidr: &IpNet) -> Result<()> {
    if !is_private_local(cidr.network()) || !is_private_local(last_address(*cidr)) {
        bail!("CIDR must be entirely private, loopback, link-local, or IPv6 unique-local");
    }
    Ok(())
}

fn contains_net(parent: IpNet, child: IpNet) -> bool {
    parent.addr().is_ipv4() == child.addr().is_ipv4()
        && parent.prefix_len() <= child.prefix_len()
        && parent.contains(&child.network())
        && parent.contains(&last_address(child))
}

pub fn host_count(cidr: IpNet) -> u128 {
    let bits = if cidr.addr().is_ipv4() { 32 } else { 128 };
    1_u128
        .checked_shl(bits - cidr.prefix_len() as u32)
        .unwrap_or(u128::MAX)
}

fn last_address(cidr: IpNet) -> IpAddr {
    match cidr {
        IpNet::V4(cidr) => IpAddr::V4(Ipv4Addr::from(
            u32::from(cidr.network()) | !u32::from(cidr.netmask()),
        )),
        IpNet::V6(cidr) => IpAddr::V6(Ipv6Addr::from(
            u128::from(cidr.network()) | !u128::from(cidr.netmask()),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_explicitly_allowed_local_addresses() {
        let policy = NetworkPolicy::new(&["10.20.0.0/16".into(), "fd00::/120".into()]).unwrap();
        assert!(policy.allows("10.20.4.5".parse().unwrap()));
        assert!(policy.allows("fd00::10".parse().unwrap()));
        assert!(!policy.allows("10.21.4.5".parse().unwrap()));
    }

    #[test]
    fn rejects_public_cgnat_multicast_documentation_and_benchmark_ranges() {
        for cidr in [
            "8.8.8.0/24",
            "100.64.0.0/10",
            "224.0.0.0/4",
            "192.0.2.0/24",
            "198.18.0.0/15",
            "2001:db8::/32",
            "ff00::/8",
        ] {
            assert!(
                NetworkPolicy::new(&[cidr.into()]).is_err(),
                "accepted {cidr}"
            );
        }
    }

    #[test]
    fn enforces_discovery_host_limit_and_parent_policy() {
        let policy = NetworkPolicy::new(&["10.0.0.0/8".into()]).unwrap();
        assert!(policy
            .validate_discovery_cidr("10.1.2.0/24".parse().unwrap())
            .is_ok());
        assert!(policy
            .validate_discovery_cidr("10.1.0.0/19".parse().unwrap())
            .is_err());
        assert!(policy
            .validate_discovery_cidr("192.168.1.0/24".parse().unwrap())
            .is_err());
    }
}
