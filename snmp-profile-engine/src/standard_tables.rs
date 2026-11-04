//! Standard MIB column plans and pure normalization. No transport or inventory logging.
use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::{Deserialize, Serialize};

pub const STANDARD_GROUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
pub const STANDARD_MAX_PARALLEL: usize = 4;
pub const STANDARD_DISCOVERY_MAX_KEYS: usize = 128;
pub const STANDARD_TEXT_MAX_CHARS: usize = 256;
pub const STANDARD_LABEL_MAX_CHARS: usize = 200;
pub const STANDARD_MAX_METRICS: usize = 4096;
pub const STANDARD_MAX_INVENTORY: usize = 384;
pub const STANDARD_MAX_SNAPSHOT_BYTES: usize = 1536 * 1024;

/// Bound text and rows before retaining standard discovery columns.
pub fn bound_standard_columns(columns: &StandardColumns) -> StandardColumns {
    columns
        .iter()
        .filter(|(key, _)| STANDARD_TABLES.iter().any(|spec| spec.key == key.as_str()))
        .map(|(key, column)| {
            (
                key.clone(),
                column
                    .iter()
                    .take(crate::table_transport::DEFAULT_TABLE_MAX_ROWS)
                    .map(|(index, value)| {
                        (
                            *index,
                            value.chars().take(STANDARD_TEXT_MAX_CHARS).collect(),
                        )
                    })
                    .collect(),
            )
        })
        .collect()
}

pub struct TableSpec {
    pub key: &'static str,
    pub oid: &'static str,
    pub metadata: bool,
}

pub const STANDARD_TABLES: &[TableSpec] = &[
    TableSpec {
        key: "if.in_discards",
        oid: "1.3.6.1.2.1.2.2.1.13",
        metadata: false,
    },
    TableSpec {
        key: "if.out_discards",
        oid: "1.3.6.1.2.1.2.2.1.19",
        metadata: false,
    },
    TableSpec {
        key: "if.hc_in_packets",
        oid: "1.3.6.1.2.1.31.1.1.1.7",
        metadata: false,
    },
    TableSpec {
        key: "if.hc_out_packets",
        oid: "1.3.6.1.2.1.31.1.1.1.11",
        metadata: false,
    },
    TableSpec {
        key: "if.in_packets",
        oid: "1.3.6.1.2.1.2.2.1.11",
        metadata: false,
    },
    TableSpec {
        key: "if.out_packets",
        oid: "1.3.6.1.2.1.2.2.1.17",
        metadata: false,
    },
    TableSpec {
        key: "if.last_change",
        oid: "1.3.6.1.2.1.2.2.1.9",
        metadata: false,
    },
    TableSpec {
        key: "storage.type",
        oid: "1.3.6.1.2.1.25.2.3.1.2",
        metadata: true,
    },
    TableSpec {
        key: "storage.name",
        oid: "1.3.6.1.2.1.25.2.3.1.3",
        metadata: true,
    },
    TableSpec {
        key: "storage.allocation",
        oid: "1.3.6.1.2.1.25.2.3.1.4",
        metadata: true,
    },
    TableSpec {
        key: "storage.size",
        oid: "1.3.6.1.2.1.25.2.3.1.5",
        metadata: false,
    },
    TableSpec {
        key: "storage.used",
        oid: "1.3.6.1.2.1.25.2.3.1.6",
        metadata: false,
    },
    TableSpec {
        key: "if.name",
        oid: "1.3.6.1.2.1.31.1.1.1.1",
        metadata: true,
    },
    TableSpec {
        key: "if.descr",
        oid: "1.3.6.1.2.1.2.2.1.2",
        metadata: true,
    },
    TableSpec {
        key: "if.status",
        oid: "1.3.6.1.2.1.2.2.1.8",
        metadata: false,
    },
    TableSpec {
        key: "if.speed",
        oid: "1.3.6.1.2.1.2.2.1.5",
        metadata: false,
    },
    TableSpec {
        key: "if.high_speed",
        oid: "1.3.6.1.2.1.31.1.1.1.15",
        metadata: false,
    },
    TableSpec {
        key: "if.hc_in",
        oid: "1.3.6.1.2.1.31.1.1.1.6",
        metadata: false,
    },
    TableSpec {
        key: "if.hc_out",
        oid: "1.3.6.1.2.1.31.1.1.1.10",
        metadata: false,
    },
    TableSpec {
        key: "if.in",
        oid: "1.3.6.1.2.1.2.2.1.10",
        metadata: false,
    },
    TableSpec {
        key: "if.out",
        oid: "1.3.6.1.2.1.2.2.1.16",
        metadata: false,
    },
    TableSpec {
        key: "if.in_errors",
        oid: "1.3.6.1.2.1.2.2.1.14",
        metadata: false,
    },
    TableSpec {
        key: "if.out_errors",
        oid: "1.3.6.1.2.1.2.2.1.20",
        metadata: false,
    },
    TableSpec {
        key: "sensor.type",
        oid: "1.3.6.1.2.1.99.1.1.1.1",
        metadata: true,
    },
    TableSpec {
        key: "sensor.scale",
        oid: "1.3.6.1.2.1.99.1.1.1.2",
        metadata: true,
    },
    TableSpec {
        key: "sensor.precision",
        oid: "1.3.6.1.2.1.99.1.1.1.3",
        metadata: true,
    },
    TableSpec {
        key: "sensor.value",
        oid: "1.3.6.1.2.1.99.1.1.1.4",
        metadata: false,
    },
    TableSpec {
        key: "sensor.status",
        oid: "1.3.6.1.2.1.99.1.1.1.5",
        metadata: false,
    },
    TableSpec {
        key: "entity.name",
        oid: "1.3.6.1.2.1.47.1.1.1.1.7",
        metadata: true,
    },
    TableSpec {
        key: "entity.descr",
        oid: "1.3.6.1.2.1.47.1.1.1.1.2",
        metadata: true,
    },
    TableSpec {
        key: "entity.class",
        oid: "1.3.6.1.2.1.47.1.1.1.1.5",
        metadata: true,
    },
    TableSpec {
        key: "entity.model",
        oid: "1.3.6.1.2.1.47.1.1.1.1.13",
        metadata: true,
    },
    TableSpec {
        key: "entity.serial",
        oid: "1.3.6.1.2.1.47.1.1.1.1.11",
        metadata: true,
    },
    TableSpec {
        key: "entity.manufacturer",
        oid: "1.3.6.1.2.1.47.1.1.1.1.12",
        metadata: true,
    },
];

pub type StandardColumns = BTreeMap<String, BTreeMap<u32, String>>;

/// Whole-kind totals are available only when every known matching row is complete.
pub fn aggregate_storage_kind(
    kind: &str,
    types: &HashMap<u32, String>,
    allocation: &HashMap<u32, f64>,
    size: &HashMap<u32, f64>,
    used: &HashMap<u32, f64>,
) -> Option<(f64, f64)> {
    let mut matched = false;
    let mut total_bytes = 0.0;
    let mut used_bytes = 0.0;
    for (index, row_kind) in types {
        let normalized = row_kind.trim().trim_matches('"').to_ascii_lowercase();
        let matches = match kind {
            "disk" => {
                normalized == "disk"
                    || normalized.ends_with("hrstoragefixeddisk")
                    || normalized.ends_with("1.3.6.1.2.1.25.2.1.4")
            }
            "ram" => {
                normalized == "ram"
                    || normalized.ends_with("hrstorageram")
                    || normalized.ends_with("1.3.6.1.2.1.25.2.1.2")
            }
            _ => false,
        };
        if !matches {
            continue;
        }
        matched = true;
        let unit = *allocation.get(index)?;
        let size = *size.get(index)?;
        let used = *used.get(index)?;
        if !unit.is_finite()
            || unit <= 0.0
            || !size.is_finite()
            || size < 0.0
            || !used.is_finite()
            || used < 0.0
            || used > size
        {
            return None;
        }
        total_bytes += unit * size;
        used_bytes += unit * used;
    }
    (matched && total_bytes.is_finite() && used_bytes.is_finite())
        .then_some((total_bytes, used_bytes))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StandardMetric {
    pub name: String,
    pub metric_key: String,
    pub unit: String,
    pub value_type: String,
    pub value: f64,
    pub labels: BTreeMap<String, String>,
}

fn metric_identity(name: &str) -> (&'static str, &'static str, &'static str) {
    match name {
        "interface.in_octets" => ("network.receive.bytes_total", "bytes", "COUNTER"),
        "interface.out_octets" => ("network.transmit.bytes_total", "bytes", "COUNTER"),
        "interface.oper_status" => ("network.interface.oper_status", "state", "GAUGE"),
        "interface.speed_bps" => ("network.interface.speed_bps", "bits_per_second", "GAUGE"),
        "interface.in_errors" => ("network.interface.receive.errors_total", "count", "COUNTER"),
        "interface.out_errors" => (
            "network.interface.transmit.errors_total",
            "count",
            "COUNTER",
        ),
        "interface.in_discards" => (
            "network.interface.receive.discards_total",
            "count",
            "COUNTER",
        ),
        "interface.out_discards" => (
            "network.interface.transmit.discards_total",
            "count",
            "COUNTER",
        ),
        "interface.in_packets" => (
            "network.interface.receive.unicast_packets_total",
            "count",
            "COUNTER",
        ),
        "interface.out_packets" => (
            "network.interface.transmit.unicast_packets_total",
            "count",
            "COUNTER",
        ),
        "interface.last_change_seconds" => {
            ("network.interface.last_change_seconds", "seconds", "GAUGE")
        }
        "volume.total_bytes" => ("disk.volume.total_bytes", "bytes", "GAUGE"),
        "volume.used_bytes" => ("disk.volume.used_bytes", "bytes", "GAUGE"),
        "volume.free_bytes" => ("disk.volume.free_bytes", "bytes", "GAUGE"),
        "volume.used_percent" => ("disk.volume.used_percent", "percent", "GAUGE"),
        "sensor.temperature_celsius" => ("hardware.temperature.celsius", "celsius", "GAUGE"),
        "sensor.fan_rpm" => ("hardware.fan.speed_rpm", "rpm", "GAUGE"),
        _ => unreachable!("only standard metric names are constructed"),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StandardInventory {
    pub kind: String,
    pub index: u32,
    pub name: String,
    pub attributes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StandardSnapshot {
    pub metrics: Vec<StandardMetric>,
    pub inventory: Vec<StandardInventory>,
}

pub fn parse_table_number(raw: &str) -> Option<f64> {
    let value = raw
        .trim()
        .split_once(':')
        .map_or(raw.trim(), |(_, value)| value.trim());
    let value = value.trim_matches('"');
    let number = value
        .parse::<f64>()
        .ok()
        .or_else(|| {
            let value = value.strip_prefix('(')?;
            value.split_once(')')?.0.parse().ok()
        })
        .or_else(|| {
            let (_, number) = value.rsplit_once('(')?;
            number.strip_suffix(')')?.parse().ok()
        })?;
    number.is_finite().then_some(number)
}

pub fn parse_table_text(raw: &str) -> Option<String> {
    let raw = raw.trim();
    let value = match raw.split_once(':') {
        Some((prefix, value))
            if [
                "STRING",
                "OCTET STRING",
                "DISPLAYSTRING",
                "HEX STRING",
                "BITS",
                "INTEGER",
                "INTEGER32",
                "UNSIGNED32",
                "COUNTER32",
                "COUNTER64",
                "GAUGE32",
                "TIMETICKS",
                "OID",
                "OBJECT IDENTIFIER",
            ]
            .contains(&prefix.trim().to_ascii_uppercase().as_str()) =>
        {
            value
        }
        _ => raw,
    }
    .trim()
    .trim_matches('"')
    .trim();
    if value.is_empty() || value.to_ascii_lowercase().starts_with("no such") {
        None
    } else {
        Some(value.to_string())
    }
}

pub fn normalize_entity_sensor_value(
    raw: f64,
    scale: Option<i64>,
    precision: Option<i64>,
) -> Option<f64> {
    let code = scale.unwrap_or(9);
    let power = if (1..=17).contains(&code) {
        (code as i32 - 9) * 3
    } else {
        0
    };
    let precision = precision.unwrap_or(0);
    let mut value = raw * 10_f64.powi(power);
    if precision > 0 {
        let digits = i32::try_from(precision).ok()?;
        value /= 10_f64.powi(digits);
    }
    value.is_finite().then_some(value)
}

pub fn summarize_interface_status(lines: &[String]) -> Option<(u32, u32)> {
    let values = lines
        .iter()
        .filter_map(|value| parse_table_number(value))
        .collect::<Vec<_>>();
    if values.is_empty() {
        return None;
    }
    let up = values.iter().filter(|value| (**value as i64) == 1).count() as u32;
    Some((up, values.len() as u32 - up))
}

pub fn sum_interface_errors(lines: &[String]) -> Option<u64> {
    let values = lines
        .iter()
        .filter_map(|value| parse_table_number(value))
        .collect::<Vec<_>>();
    (!values.is_empty()).then(|| {
        values.into_iter().fold(0_u64, |sum, value| {
            sum.saturating_add(value.max(0.0) as u64)
        })
    })
}

fn number(columns: &StandardColumns, key: &str, index: u32) -> Option<f64> {
    parse_table_number(columns.get(key)?.get(&index)?)
}

fn text(columns: &StandardColumns, key: &str, index: u32) -> Option<String> {
    parse_table_text(columns.get(key)?.get(&index)?)
}

fn indices(columns: &StandardColumns, prefix: &str) -> BTreeSet<u32> {
    columns
        .iter()
        .filter(|(key, _)| key.starts_with(prefix))
        .flat_map(|(_, column)| column.keys().copied())
        .collect()
}

pub fn normalize_standard_tables(columns: &StandardColumns) -> StandardSnapshot {
    normalize_standard_tables_with_issues(columns).0
}

pub fn normalize_standard_tables_with_issues(
    columns: &StandardColumns,
) -> (StandardSnapshot, Vec<crate::profile_tables::TableIssue>) {
    use crate::profile_tables::TableIssue;
    let mut issues = Vec::new();
    for (key, rows) in columns {
        if rows.len() > crate::table_transport::DEFAULT_TABLE_MAX_ROWS {
            issues.push(TableIssue::new(
                "standard",
                Some(key),
                "SNMP_RESPONSE_LIMIT",
            ));
        }
    }
    let bounded = bound_standard_columns(columns);
    let columns = &bounded;
    let mut snapshot = StandardSnapshot::default();
    for index in indices(columns, "if.") {
        let name = text(columns, "if.name", index)
            .or_else(|| text(columns, "if.descr", index))
            .unwrap_or_else(|| format!("interface-{index}"));
        let labels = BTreeMap::from([
            ("interface_index".into(), index.to_string()),
            ("name".into(), name.clone()),
        ]);
        let mut attributes = BTreeMap::new();
        if let Some(description) = text(columns, "if.descr", index) {
            attributes.insert("description".into(), description);
        }
        snapshot.inventory.push(StandardInventory {
            kind: "interface".into(),
            index,
            name,
            attributes,
        });
        for (metric, value) in [
            (
                "interface.in_octets",
                number(columns, "if.hc_in", index)
                    .filter(|v| *v >= 0.0)
                    .or_else(|| number(columns, "if.in", index)),
            ),
            (
                "interface.out_octets",
                number(columns, "if.hc_out", index)
                    .filter(|v| *v >= 0.0)
                    .or_else(|| number(columns, "if.out", index)),
            ),
            ("interface.oper_status", number(columns, "if.status", index)),
            (
                "interface.speed_bps",
                number(columns, "if.high_speed", index)
                    .filter(|v| *v > 0.0)
                    .map(|v| v * 1_000_000.0)
                    .or_else(|| number(columns, "if.speed", index)),
            ),
            (
                "interface.in_errors",
                number(columns, "if.in_errors", index),
            ),
            (
                "interface.out_errors",
                number(columns, "if.out_errors", index),
            ),
            (
                "interface.in_discards",
                number(columns, "if.in_discards", index),
            ),
            (
                "interface.out_discards",
                number(columns, "if.out_discards", index),
            ),
            (
                "interface.in_packets",
                number(columns, "if.hc_in_packets", index)
                    .filter(|value| *value >= 0.0)
                    .or_else(|| number(columns, "if.in_packets", index)),
            ),
            (
                "interface.out_packets",
                number(columns, "if.hc_out_packets", index)
                    .filter(|value| *value >= 0.0)
                    .or_else(|| number(columns, "if.out_packets", index)),
            ),
            (
                "interface.last_change_seconds",
                number(columns, "if.last_change", index).map(|value| value / 100.0),
            ),
        ] {
            if let Some(value) = value.filter(|v| v.is_finite() && *v >= 0.0) {
                snapshot.metrics.push(StandardMetric {
                    name: metric.into(),
                    metric_key: metric_identity(metric).0.into(),
                    unit: metric_identity(metric).1.into(),
                    value_type: metric_identity(metric).2.into(),
                    value,
                    labels: labels.clone(),
                });
            }
        }
    }
    for index in indices(columns, "storage.") {
        let Some(kind) = text(columns, "storage.type", index) else {
            continue;
        };
        let kind = kind.to_ascii_lowercase();
        if kind != "disk"
            && !kind.ends_with("hrstoragefixeddisk")
            && !kind.ends_with("1.3.6.1.2.1.25.2.1.4")
        {
            continue;
        }
        let name =
            text(columns, "storage.name", index).unwrap_or_else(|| format!("volume-{index}"));
        let labels = BTreeMap::from([
            ("volume_index".into(), index.to_string()),
            ("name".into(), name.clone()),
        ]);
        snapshot.inventory.push(StandardInventory {
            kind: "volume".into(),
            index,
            name,
            attributes: BTreeMap::new(),
        });
        let Some(unit) = number(columns, "storage.allocation", index).filter(|value| *value > 0.0)
        else {
            continue;
        };
        let Some(size) = number(columns, "storage.size", index).filter(|value| *value >= 0.0)
        else {
            continue;
        };
        let total = unit * size;
        if !total.is_finite() {
            continue;
        }
        let used = number(columns, "storage.used", index)
            .filter(|used| *used >= 0.0 && *used <= size)
            .map(|used| used * unit)
            .filter(|used| used.is_finite());
        for (metric, value) in [
            ("volume.total_bytes", Some(total)),
            ("volume.used_bytes", used),
            ("volume.free_bytes", used.map(|used| total - used)),
            (
                "volume.used_percent",
                used.filter(|_| total > 0.0)
                    .map(|used| used / total * 100.0),
            ),
        ] {
            if let Some(value) = value {
                let (metric_key, unit, value_type) = metric_identity(metric);
                snapshot.metrics.push(StandardMetric {
                    name: metric.into(),
                    metric_key: metric_key.into(),
                    unit: unit.into(),
                    value_type: value_type.into(),
                    value,
                    labels: labels.clone(),
                });
            }
        }
    }
    for index in indices(columns, "sensor.") {
        if number(columns, "sensor.status", index) == Some(2.0) {
            continue;
        }
        let metric = match number(columns, "sensor.type", index) {
            Some(8.0) => "sensor.temperature_celsius",
            Some(10.0) => "sensor.fan_rpm",
            _ => continue,
        };
        let Some(raw) = number(columns, "sensor.value", index) else {
            continue;
        };
        let Some(value) = normalize_entity_sensor_value(
            raw,
            number(columns, "sensor.scale", index).map(|v| v as i64),
            number(columns, "sensor.precision", index).map(|v| v as i64),
        ) else {
            continue;
        };
        let value = if metric == "sensor.fan_rpm" {
            value.round()
        } else {
            (value * 10.0).round() / 10.0
        };
        snapshot.metrics.push(StandardMetric {
            name: metric.into(),
            metric_key: metric_identity(metric).0.into(),
            unit: metric_identity(metric).1.into(),
            value_type: metric_identity(metric).2.into(),
            value,
            labels: BTreeMap::from([
                ("sensor_index".into(), index.to_string()),
                (
                    "name".into(),
                    text(columns, "entity.name", index)
                        .unwrap_or_else(|| format!("sensor-{index}")),
                ),
            ]),
        });
    }
    for index in indices(columns, "entity.") {
        let name = text(columns, "entity.name", index).unwrap_or_else(|| format!("entity-{index}"));
        let attributes = [
            ("description", "entity.descr"),
            ("class", "entity.class"),
            ("model", "entity.model"),
            ("serial", "entity.serial"),
            ("manufacturer", "entity.manufacturer"),
        ]
        .into_iter()
        .filter_map(|(attribute, key)| {
            text(columns, key, index).map(|value| (attribute.into(), value))
        })
        .collect();
        snapshot.inventory.push(StandardInventory {
            kind: "entity".into(),
            index,
            name,
            attributes,
        });
    }
    if snapshot.metrics.len() > STANDARD_MAX_METRICS
        || snapshot.inventory.len() > STANDARD_MAX_INVENTORY
    {
        issues.push(TableIssue::new("standard", None, "SNMP_RESPONSE_LIMIT"));
        snapshot.metrics.truncate(STANDARD_MAX_METRICS);
        snapshot.inventory.truncate(STANDARD_MAX_INVENTORY);
    }
    for metric in &mut snapshot.metrics {
        for value in metric.labels.values_mut() {
            *value = value.chars().take(STANDARD_LABEL_MAX_CHARS).collect();
        }
    }
    let mut size_issue = false;
    while serde_json::to_vec(&snapshot)
        .map_or(true, |json| json.len() > STANDARD_MAX_SNAPSHOT_BYTES)
    {
        size_issue = true;
        if snapshot.inventory.pop().is_none() && snapshot.metrics.pop().is_none() {
            break;
        }
    }
    if size_issue {
        issues.push(TableIssue::new("standard", None, "SNMP_RESPONSE_LIMIT"));
    }
    (snapshot, issues)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_protocol_golden_fixture_matches_complete_snapshot() {
        #[derive(Deserialize)]
        struct Fixture {
            columns: StandardColumns,
            snapshot: StandardSnapshot,
        }
        let fixture: Fixture =
            serde_json::from_str(include_str!("../fixtures/standard-tables.json")).unwrap();
        assert_eq!(
            normalize_standard_tables(&fixture.columns),
            fixture.snapshot
        );
    }

    #[test]
    fn canonical_serialization_and_discovery_bounds_are_stable() {
        let columns = StandardColumns::from([
            (
                "if.name".into(),
                (1..=200).map(|index| (index, "x".repeat(1000))).collect(),
            ),
            (
                "if.in".into(),
                (1..=200).map(|index| (index, "1".into())).collect(),
            ),
            ("unknown".into(), BTreeMap::from([(1, "ignored".into())])),
        ]);
        let bounded = bound_standard_columns(&columns);
        assert_eq!(bounded["if.name"].len(), 128);
        assert_eq!(bounded["if.name"][&1].len(), 256);
        assert!(!bounded.contains_key("unknown"));
        let snapshot = normalize_standard_tables(&columns);
        let json = serde_json::to_value(snapshot).unwrap();
        assert_eq!(
            json["metrics"][0]["metricKey"],
            "network.receive.bytes_total"
        );
        assert_eq!(json["metrics"][0]["unit"], "bytes");
        assert_eq!(json["metrics"][0]["valueType"], "COUNTER");
        assert_eq!(json["metrics"][0]["labels"]["interface_index"], "1");
        assert_eq!(
            json["metrics"][0]["labels"]["name"]
                .as_str()
                .unwrap()
                .chars()
                .count(),
            200
        );
        assert_eq!(
            json["inventory"][0]["name"]
                .as_str()
                .unwrap()
                .chars()
                .count(),
            256
        );
        assert_eq!(
            metric_identity("interface.oper_status"),
            ("network.interface.oper_status", "state", "GAUGE")
        );
    }

    #[test]
    fn storage_totals_never_publish_partial_subtotals() {
        let types = HashMap::from([(1, "disk".into()), (2, "disk".into()), (3, "ram".into())]);
        let units = HashMap::from([(1, 1024.0), (2, 1024.0), (3, 1024.0)]);
        let sizes = HashMap::from([(1, 100.0), (2, 200.0), (3, 300.0)]);
        let mut used = HashMap::from([(1, 10.0), (2, 20.0), (3, 30.0)]);
        assert_eq!(
            aggregate_storage_kind("disk", &types, &units, &sizes, &used),
            Some((307200.0, 30720.0))
        );
        used.remove(&2);
        assert_eq!(
            aggregate_storage_kind("disk", &types, &units, &sizes, &used),
            None
        );
        assert_eq!(
            aggregate_storage_kind("ram", &types, &units, &sizes, &used),
            Some((307200.0, 30720.0))
        );
        used.insert(2, f64::NAN);
        assert_eq!(
            aggregate_storage_kind("disk", &types, &units, &sizes, &used),
            None
        );
    }

    #[test]
    fn storage_kind_accepts_raw_symbolic_numeric_and_normalized_types() {
        let units = HashMap::from([(1, 1024.0)]);
        let sizes = HashMap::from([(1, 100.0)]);
        let used = HashMap::from([(1, 25.0)]);
        for (kind, raw) in [
            ("disk", "disk"),
            ("disk", "OID: HOST-RESOURCES-TYPES::hrStorageFixedDisk"),
            ("disk", "OID: 1.3.6.1.2.1.25.2.1.4"),
            ("disk", "OID: .1.3.6.1.2.1.25.2.1.4"),
            ("ram", "ram"),
            ("ram", "OID: HOST-RESOURCES-TYPES::hrStorageRam"),
            ("ram", "OID: 1.3.6.1.2.1.25.2.1.2"),
        ] {
            let types = HashMap::from([(1, raw.into())]);
            assert_eq!(
                aggregate_storage_kind(kind, &types, &units, &sizes, &used),
                Some((102400.0, 25600.0))
            );
            assert_eq!(
                aggregate_storage_kind(kind, &types, &units, &sizes, &HashMap::new()),
                None
            );
            assert_eq!(
                aggregate_storage_kind(kind, &types, &units, &sizes, &HashMap::from([(1, 101.0)])),
                None
            );
        }
        assert_eq!(
            aggregate_storage_kind(
                "unknown",
                &HashMap::from([(1, "unknown".into())]),
                &units,
                &sizes,
                &used
            ),
            None
        );
    }

    #[test]
    fn normalizes_standard_interface_sensor_and_inventory_columns() {
        let mut columns = StandardColumns::new();
        for (key, value) in [
            ("if.name", "STRING: \"eth0\""),
            ("if.hc_in", "Counter64: 0"),
            ("if.in", "Counter32: 99"),
            ("if.out", "Counter32: 123"),
            ("if.status", "INTEGER: up(1)"),
            ("if.high_speed", "1000"),
            ("sensor.type", "celsius(8)"),
            ("sensor.value", "421"),
            ("sensor.precision", "1"),
            ("sensor.scale", "units(9)"),
            ("entity.name", "STRING: \"CPU: 1\""),
            ("entity.serial", "STRING: \"private-serial\""),
        ] {
            columns.insert(key.into(), BTreeMap::from([(1, value.into())]));
        }
        let snapshot = normalize_standard_tables(&columns);
        let value = |name| {
            snapshot
                .metrics
                .iter()
                .find(|metric| metric.name == name)
                .unwrap()
                .value
        };
        assert_eq!(value("interface.in_octets"), 0.0);
        assert_eq!(value("interface.out_octets"), 123.0);
        assert_eq!(value("interface.oper_status"), 1.0);
        assert_eq!(value("interface.speed_bps"), 1_000_000_000.0);
        assert_eq!(value("sensor.temperature_celsius"), 42.1);
        assert_eq!(
            snapshot
                .inventory
                .iter()
                .find(|item| item.kind == "entity")
                .unwrap()
                .attributes["serial"],
            "private-serial"
        );
        columns.insert(
            "sensor.status".into(),
            BTreeMap::from([(1, "unavailable(2)".into())]),
        );
        assert!(!normalize_standard_tables(&columns)
            .metrics
            .iter()
            .any(|metric| metric.name.starts_with("sensor.")));
    }

    #[test]
    fn unsupported_values_never_become_zero_and_sensor_scaling_is_shared() {
        assert_eq!(parse_table_number("No Such Instance"), None);
        assert_eq!(
            parse_table_number("Counter64: 18446744073709551615"),
            Some(u64::MAX as f64)
        );
        assert_eq!(parse_table_number("NaN"), None);
        assert_eq!(
            normalize_entity_sensor_value(42000.0, Some(8), None),
            Some(42.0)
        );
        assert_eq!(
            normalize_entity_sensor_value(421.0, Some(9), Some(1)),
            Some(42.1)
        );
        assert_eq!(
            normalize_standard_tables(&StandardColumns::new()),
            StandardSnapshot::default()
        );
        assert_eq!(
            summarize_interface_status(&["INTEGER: up(1)".into(), "down(2)".into()]),
            Some((1, 1))
        );
        assert_eq!(sum_interface_errors(&["Counter32: 0".into()]), Some(0));
    }

    #[test]
    fn richer_interfaces_prefer_hc_and_preserve_uptime_timestamp() {
        let columns = StandardColumns::from([
            (
                "if.in_discards".into(),
                BTreeMap::from([(9, "Counter32: 0".into())]),
            ),
            (
                "if.out_discards".into(),
                BTreeMap::from([(9, "Counter32: 3".into())]),
            ),
            (
                "if.hc_in_packets".into(),
                BTreeMap::from([(9, "Counter64: 0".into())]),
            ),
            (
                "if.in_packets".into(),
                BTreeMap::from([(9, "Counter32: 99".into())]),
            ),
            (
                "if.out_packets".into(),
                BTreeMap::from([(9, "Counter32: 42".into())]),
            ),
            (
                "if.last_change".into(),
                BTreeMap::from([(9, "Timeticks: (12345) 0:02:03.45".into())]),
            ),
        ]);
        let snapshot = normalize_standard_tables(&columns);
        let metric = |key| {
            snapshot
                .metrics
                .iter()
                .find(|metric| metric.metric_key == key)
                .unwrap()
                .value
        };
        assert_eq!(
            metric("network.interface.receive.unicast_packets_total"),
            0.0
        );
        assert_eq!(
            metric("network.interface.transmit.unicast_packets_total"),
            42.0
        );
        assert_eq!(metric("network.interface.last_change_seconds"), 123.45);
        assert_eq!(metric("network.interface.receive.discards_total"), 0.0);
    }

    #[test]
    fn fixed_disk_volumes_preserve_rows_without_fabricated_missing_values() {
        let columns = StandardColumns::from([
            (
                "storage.type".into(),
                BTreeMap::from([
                    (1, "OID: .1.3.6.1.2.1.25.2.1.4".into()),
                    (2, "hrStorageFixedDisk".into()),
                    (3, "hrStorageRam".into()),
                ]),
            ),
            (
                "storage.name".into(),
                BTreeMap::from([(1, "STRING: \"/\"".into())]),
            ),
            (
                "storage.allocation".into(),
                BTreeMap::from([(1, "1024".into()), (2, "1024".into())]),
            ),
            (
                "storage.size".into(),
                BTreeMap::from([(1, "100".into()), (2, "200".into())]),
            ),
            ("storage.used".into(), BTreeMap::from([(1, "25".into())])),
        ]);
        let snapshot = normalize_standard_tables(&columns);
        assert_eq!(
            snapshot
                .inventory
                .iter()
                .filter(|row| row.kind == "volume")
                .count(),
            2
        );
        let row = snapshot
            .metrics
            .iter()
            .filter(|metric| metric.labels["volume_index"] == "1")
            .collect::<Vec<_>>();
        assert_eq!(row.len(), 4);
        assert_eq!(row[0].value, 102400.0);
        assert_eq!(row[1].value, 25600.0);
        assert_eq!(row[2].value, 76800.0);
        assert_eq!(row[3].value, 25.0);
        let incomplete = snapshot
            .metrics
            .iter()
            .filter(|metric| metric.labels["volume_index"] == "2")
            .collect::<Vec<_>>();
        assert_eq!(incomplete.len(), 1);
        assert_eq!(incomplete[0].metric_key, "disk.volume.total_bytes");
    }
}
