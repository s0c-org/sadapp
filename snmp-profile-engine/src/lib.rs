use std::collections::BTreeSet;

use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProfileState {
    #[default]
    Enabled,
    Experimental,
    Disabled,
}

impl ProfileState {
    pub fn is_enabled(self) -> bool {
        self == Self::Enabled
    }

    pub fn is_selectable(self) -> bool {
        self != Self::Disabled
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Detection {
    pub sys_object_id_prefixes: Vec<String>,
    pub sys_descr_regexes: Vec<String>,
    pub required_oids: Vec<String>,
    pub optional_oids: Vec<String>,
    pub priority: i32,
    pub minimum_confidence: f64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DetectionProfile {
    pub profile_name: String,
    pub schema_version: u32,
    pub state: ProfileState,
    #[serde(default)]
    pub detection: Detection,
}

pub fn apply_profile_state_overrides(
    profiles: &[DetectionProfile],
    overrides: &std::collections::BTreeMap<String, ProfileState>,
) -> Vec<DetectionProfile> {
    profiles
        .iter()
        .cloned()
        .map(|mut profile| {
            if let Some(state) = overrides.get(&profile.profile_name) {
                profile.state = *state;
            }
            profile
        })
        .collect()
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct IdentityProbe {
    pub sys_object_id: Option<String>,
    pub sys_descr: Option<String>,
    pub sys_name: Option<String>,
    pub sys_location: Option<String>,
    pub sys_services: Option<i64>,
    pub responsive_oids: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DetectionEvidence {
    pub kind: String,
    pub value: String,
    pub weight: f64,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DetectionAlternative {
    pub profile: String,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DetectionResult {
    pub configured_profile: String,
    pub detected_profile: Option<String>,
    pub effective_profile: String,
    pub confidence: f64,
    pub evidence: Vec<DetectionEvidence>,
    pub alternatives: Vec<DetectionAlternative>,
    pub registry_checksum: String,
    pub manual_override: bool,
    pub disagreement: bool,
    pub ambiguous: bool,
}

pub fn detection_bundle_checksum(
    profiles: &[DetectionProfile],
) -> Result<String, serde_json::Error> {
    let serialized = serde_json::to_vec(profiles)?;
    Ok(format!("{:x}", Sha256::digest(serialized)))
}

pub fn metric_capability_group(metric: &str) -> &'static str {
    let parts = metric
        .to_ascii_lowercase()
        .split(|character: char| !character.is_ascii_alphanumeric())
        .map(str::to_string)
        .collect::<Vec<_>>();
    if parts.iter().any(|part| part == "cpu") {
        "cpu"
    } else if parts
        .iter()
        .any(|part| part == "memory" || part == "mem" || part == "ram")
    {
        "memory"
    } else if parts
        .iter()
        .any(|part| part == "storage" || part == "filesystem" || part == "disk")
    {
        "storage"
    } else if parts
        .iter()
        .any(|part| part == "interface" || part == "network" || part == "traffic")
    {
        "interfaces"
    } else if parts.iter().any(|part| {
        part == "temperature"
            || part == "temp"
            || part == "fan"
            || part == "power"
            || part == "battery"
    }) {
        "sensors"
    } else if parts
        .iter()
        .any(|part| part == "inventory" || part == "hardware" || part == "process")
    {
        "inventory"
    } else if parts.iter().any(|part| part == "uptime" || part == "load") {
        "health"
    } else {
        "vendor"
    }
}

struct ScoredProfile {
    profile: String,
    confidence: f64,
    minimum_confidence: f64,
    evidence: Vec<DetectionEvidence>,
    prefix_length: usize,
    priority: i32,
}

pub fn detect(
    configured_profile: &str,
    profiles: &[DetectionProfile],
    identity: &IdentityProbe,
    registry_checksum: &str,
) -> DetectionResult {
    let configured_profile = if configured_profile.trim().is_empty() {
        "auto"
    } else {
        configured_profile.trim()
    };
    let mut candidates = profiles
        .iter()
        .filter(|profile| profile.state.is_enabled())
        .map(|profile| score_profile(profile, identity))
        .filter(|candidate| candidate.confidence > 0.0)
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| {
        right
            .confidence
            .total_cmp(&left.confidence)
            .then_with(|| right.priority.cmp(&left.priority))
            .then_with(|| right.prefix_length.cmp(&left.prefix_length))
            .then_with(|| left.profile.cmp(&right.profile))
    });
    let ambiguous = candidates.get(1).is_some_and(|second| {
        let first = &candidates[0];
        first.prefix_length == second.prefix_length
            && first.priority == second.priority
            && (first.confidence - second.confidence).abs() < f64::EPSILON
    });
    let detected = candidates
        .first()
        .filter(|candidate| !ambiguous && candidate.confidence >= candidate.minimum_confidence);
    let detected_profile = detected.map(|candidate| candidate.profile.clone());
    let evidence = detected
        .map(|candidate| candidate.evidence.clone())
        .unwrap_or_default();
    let alternatives = candidates
        .iter()
        .skip(usize::from(detected.is_some()))
        .take(3)
        .map(|candidate| DetectionAlternative {
            profile: candidate.profile.clone(),
            confidence: candidate.confidence,
        })
        .collect();
    let manual_override = configured_profile != "auto";
    let effective_profile = if manual_override {
        profiles
            .iter()
            .find(|profile| {
                profile.profile_name == configured_profile && profile.state.is_selectable()
            })
            .map(|profile| profile.profile_name.clone())
            .unwrap_or_else(|| "generic-host".to_string())
    } else {
        detected_profile
            .clone()
            .unwrap_or_else(|| "generic-host".to_string())
    };
    DetectionResult {
        configured_profile: configured_profile.to_string(),
        disagreement: manual_override
            && detected_profile
                .as_deref()
                .is_some_and(|name| name != effective_profile),
        detected_profile,
        effective_profile,
        confidence: detected.map_or(0.0, |candidate| candidate.confidence),
        evidence,
        alternatives,
        registry_checksum: registry_checksum.to_string(),
        manual_override,
        ambiguous,
    }
}

fn score_profile(profile: &DetectionProfile, identity: &IdentityProbe) -> ScoredProfile {
    let normalized_object_id = identity.sys_object_id.as_deref().map(normalize_oid);
    let prefix = normalized_object_id.as_deref().and_then(|object_id| {
        profile
            .detection
            .sys_object_id_prefixes
            .iter()
            .filter(|prefix| oid_has_prefix(object_id, prefix))
            .max_by_key(|prefix| prefix.len())
    });
    let mut confidence: f64 = 0.0;
    let mut evidence = Vec::new();
    if let Some(prefix) = prefix {
        confidence = 0.9;
        evidence.push(DetectionEvidence {
            kind: "sys_object_id_prefix".to_string(),
            value: prefix.clone(),
            weight: 0.9,
        });
    }
    let required_matches = profile
        .detection
        .required_oids
        .iter()
        .filter(|oid| identity.responsive_oids.contains(*oid))
        .count();
    if required_matches > 1 {
        let weight = (0.5 + required_matches as f64 * 0.08).min(0.85);
        confidence = confidence.max(weight);
        evidence.push(DetectionEvidence {
            kind: "required_oids".to_string(),
            value: required_matches.to_string(),
            weight,
        });
    }
    if let Some(description) = identity.sys_descr.as_deref() {
        if profile
            .detection
            .sys_descr_regexes
            .iter()
            .any(|pattern| Regex::new(pattern).is_ok_and(|regex| regex.is_match(description)))
        {
            confidence = confidence.max(0.95);
            evidence.push(DetectionEvidence {
                kind: "sys_descr_regex".to_string(),
                value: "matched".to_string(),
                weight: 0.95,
            });
        }
    }
    ScoredProfile {
        profile: profile.profile_name.clone(),
        confidence,
        minimum_confidence: profile.detection.minimum_confidence,
        evidence,
        prefix_length: prefix.map_or(0, |value| value.len()),
        priority: profile.detection.priority,
    }
}

fn oid_has_prefix(oid: &str, prefix: &str) -> bool {
    oid == prefix
        || oid
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('.'))
}

fn normalize_oid(value: &str) -> String {
    value.trim().trim_start_matches('.').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(name: &str, state: ProfileState, prefix: &str, regex: &str) -> DetectionProfile {
        DetectionProfile {
            profile_name: name.to_string(),
            schema_version: 1,
            state,
            detection: Detection {
                sys_object_id_prefixes: vec![prefix.to_string()],
                sys_descr_regexes: vec![regex.to_string()],
                minimum_confidence: 0.8,
                ..Detection::default()
            },
        }
    }

    #[test]
    fn prefers_description_evidence_and_ignores_experimental_profiles() {
        let profiles = [
            profile(
                "generic-host",
                ProfileState::Enabled,
                "1.3.6.1.2.1",
                "(?i)linux",
            ),
            profile(
                "esphome-snmp",
                ProfileState::Enabled,
                "1.3.6.1.4.1.999",
                "(?i)esphome",
            ),
            profile(
                "experimental",
                ProfileState::Experimental,
                "1.3.6.1.4.1.999",
                "(?i)esphome",
            ),
        ];
        let result = detect(
            "auto",
            &profiles,
            &IdentityProbe {
                sys_object_id: Some(".1.3.6.1.4.1.999.1".into()),
                sys_descr: Some("ESPHome device".into()),
                ..IdentityProbe::default()
            },
            "registry-sha",
        );

        assert_eq!(result.detected_profile.as_deref(), Some("esphome-snmp"));
        assert_eq!(result.effective_profile, "esphome-snmp");
        assert_eq!(result.confidence, 0.95);
        assert_eq!(result.registry_checksum, "registry-sha");
    }

    #[test]
    fn preserves_manual_override_and_reports_disagreement() {
        let profiles = [
            profile(
                "generic-host",
                ProfileState::Enabled,
                "1.3.6.1.2.1",
                "(?i)linux",
            ),
            profile(
                "esphome-snmp",
                ProfileState::Enabled,
                "1.3.6.1.4.1.999",
                "(?i)esphome",
            ),
        ];
        let result = detect(
            "generic-host",
            &profiles,
            &IdentityProbe {
                sys_descr: Some("ESPHome device".into()),
                ..IdentityProbe::default()
            },
            "registry-sha",
        );

        assert_eq!(result.detected_profile.as_deref(), Some("esphome-snmp"));
        assert_eq!(result.effective_profile, "generic-host");
        assert!(result.manual_override);
        assert!(result.disagreement);
    }

    #[test]
    fn signature_checksum_matches_control_plane_json_fixture() {
        let profiles = [DetectionProfile {
            profile_name: "fixture".into(),
            schema_version: 1,
            state: ProfileState::Enabled,
            detection: Detection {
                sys_object_id_prefixes: vec!["1.3.6.1.4.1.999".into()],
                sys_descr_regexes: vec!["(?i)foo".into()],
                required_oids: vec!["1.3.6.1.2.1.1.2.0".into()],
                optional_oids: Vec::new(),
                priority: 0,
                minimum_confidence: 0.8,
            },
        }];

        assert_eq!(
            detection_bundle_checksum(&profiles).unwrap(),
            "aa99d7589ccb5985eb6d9b90a326c1e2f5f7e8aa96a77e8237b1455fb1c57c86"
        );
    }

    #[test]
    fn state_overrides_change_detection_eligibility() {
        let profiles = [DetectionProfile {
            profile_name: "experimental-appliance".into(),
            schema_version: 1,
            state: ProfileState::Experimental,
            detection: Detection {
                sys_descr_regexes: vec!["(?i)appliance".into()],
                minimum_confidence: 0.8,
                ..Detection::default()
            },
        }];
        let overrides = std::collections::BTreeMap::from([(
            "experimental-appliance".to_string(),
            ProfileState::Enabled,
        )]);
        let effective_profiles = apply_profile_state_overrides(&profiles, &overrides);
        let detected = detect(
            "auto",
            &effective_profiles,
            &IdentityProbe {
                sys_descr: Some("Example appliance".into()),
                ..IdentityProbe::default()
            },
            &detection_bundle_checksum(&effective_profiles).unwrap(),
        );

        assert_eq!(
            detected.detected_profile.as_deref(),
            Some("experimental-appliance")
        );
        assert_ne!(
            detection_bundle_checksum(&profiles).unwrap(),
            detection_bundle_checksum(&effective_profiles).unwrap(),
        );
    }

    #[test]
    fn classifies_namespaced_metrics_into_capability_groups() {
        assert_eq!(metric_capability_group("system.cpu.idle_percent"), "cpu");
        assert_eq!(
            metric_capability_group("system.memory.available_bytes"),
            "memory"
        );
        assert_eq!(metric_capability_group("filesystem.used_bytes"), "storage");
        assert_eq!(
            metric_capability_group("network.interface.count"),
            "interfaces"
        );
        assert_eq!(
            metric_capability_group("sensor.temperature.celsius"),
            "sensors"
        );
        assert_eq!(metric_capability_group("system.uptime.seconds"), "health");
    }
}
