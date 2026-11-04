//! Validated, transport-independent declarative table execution.
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::standard_tables::{parse_table_number, parse_table_text, StandardMetric};
use crate::{apply_numeric_transform, Transform};

pub const MAX_TABLES: usize = 16;
pub const MAX_COLUMNS: usize = 32;
pub const MAX_TOTAL_COLUMNS: usize = 128;
pub const MAX_METRICS: usize = 2048;
pub const MAX_INVENTORY: usize = 256;
pub const MAX_SNAPSHOT_BYTES: usize = 1024 * 1024;
pub const MAX_TEXT_CHARS: usize = 200;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TablePlan {
    pub name: String,
    pub base_oid: String,
    pub index_strategy: String,
    pub max_rows: u32,
    pub columns: Vec<ColumnPlan>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ColumnPlan {
    pub name: String,
    pub oid_suffix: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metric_key: Option<String>,
    #[serde(default)]
    pub unit: String,
    pub scale: f64,
    pub value_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transform: Option<Transform>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TableIssue {
    pub table: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column: Option<String>,
    pub code: String,
}

impl TableIssue {
    pub fn new(table: &str, column: Option<&str>, code: &str) -> Self {
        Self {
            table: table.chars().take(80).collect(),
            column: column.map(|value| value.chars().take(80).collect()),
            code: code.into(),
        }
    }
}

pub type ProfileColumns = BTreeMap<String, BTreeMap<String, BTreeMap<String, String>>>;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ParsedColumn {
    pub rows: BTreeMap<String, String>,
    pub issues: Vec<TableIssue>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ProfileInventory {
    pub kind: String,
    pub index: String,
    pub name: String,
    pub attributes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ProfileSnapshot {
    pub metrics: Vec<StandardMetric>,
    pub inventory: Vec<ProfileInventory>,
}

pub fn numeric_oid(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value.split('.').all(|part| {
            !part.is_empty()
                && part.bytes().all(|byte| byte.is_ascii_digit())
                && part.parse::<u32>().is_ok()
        })
}

fn base_oid(value: &str) -> bool {
    if !numeric_oid(value) {
        return false;
    }
    let mut parts = value.split('.').filter_map(|part| part.parse::<u32>().ok());
    match (parts.next(), parts.next()) {
        (Some(first @ 0..=2), Some(second)) => first == 2 || second <= 39,
        _ => false,
    }
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 160
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
}

pub fn validate_plans(plans: &[TablePlan]) -> Result<(), Vec<TableIssue>> {
    let mut issues = Vec::new();
    if plans.len() > MAX_TABLES
        || plans.iter().map(|plan| plan.columns.len()).sum::<usize>() > MAX_TOTAL_COLUMNS
    {
        issues.push(TableIssue::new("", None, "SNMP_TABLE_PLAN_LIMIT"));
    }
    let mut names = BTreeSet::new();
    for plan in plans.iter().take(MAX_TABLES + 1) {
        let invalid = !identifier(&plan.name)
            || !names.insert(&plan.name)
            || !base_oid(&plan.base_oid)
            || !(1..=10000).contains(&plan.max_rows)
            || !["suffix", "integer", "inet_address", "mac_address"]
                .contains(&plan.index_strategy.as_str())
            || plan.columns.is_empty()
            || plan.columns.len() > MAX_COLUMNS;
        if invalid {
            issues.push(TableIssue::new(&plan.name, None, "SNMP_INVALID_TABLE_PLAN"));
        }
        let mut columns = BTreeSet::new();
        let mut metrics = BTreeSet::new();
        for column in plan.columns.iter().take(MAX_COLUMNS + 1) {
            let numeric = column.value_type != "STRING";
            let valid_transform = match &column.transform {
                None => true,
                Some(Transform::Scale { factor }) => factor.is_finite(),
                Some(Transform::Offset { value }) => value.is_finite(),
                Some(
                    Transform::Percentage { total_metric }
                    | Transform::UsedFromTotal { total_metric }
                    | Transform::UsedFromFree { total_metric },
                ) => plan.columns.iter().any(|related| {
                    related.value_type != "STRING"
                        && (related.name == *total_metric
                            || related.metric_key.as_ref() == Some(total_metric))
                }),
                _ => false,
            };
            if !identifier(&column.name)
                || !columns.insert(&column.name)
                || !numeric_oid(&column.oid_suffix)
                || !base_oid(&format!("{}.{}", plan.base_oid, column.oid_suffix))
                || column.unit.len() > 80
                || column.unit.chars().any(char::is_control)
                || !column.scale.is_finite()
                || ![
                    "STRING",
                    "GAUGE",
                    "COUNTER",
                    "INTEGER",
                    "UNSIGNED",
                    "BOOLEAN",
                    "ENUM",
                    "TIMETICKS",
                ]
                .contains(&column.value_type.as_str())
                || (numeric
                    && !column
                        .metric_key
                        .as_ref()
                        .is_some_and(|key| identifier(key) && metrics.insert(key)))
                || (!numeric && (column.metric_key.is_some() || column.transform.is_some()))
                || !valid_transform
            {
                issues.push(TableIssue::new(
                    &plan.name,
                    Some(&column.name),
                    "SNMP_INVALID_TABLE_COLUMN",
                ));
            }
        }
    }
    if issues.is_empty() {
        Ok(())
    } else {
        Err(issues)
    }
}

/// Convert schema-v1 tables, retaining declared row limits. Compact strings are
/// numeric suffixes only; executable expressions and symbolic OIDs are rejected.
pub fn plans_from_profile_json(profile: &serde_json::Value) -> (Vec<TablePlan>, Vec<TableIssue>) {
    let tables = profile.get("tables").unwrap_or(profile);
    let Some(tables) = tables.as_object() else {
        return (
            Vec::new(),
            vec![TableIssue::new("", None, "SNMP_INVALID_TABLE_PLAN")],
        );
    };
    let mut plans = Vec::new();
    let mut issues = Vec::new();
    let mut total_columns = 0;
    for (name, table) in tables {
        if plans.len() >= MAX_TABLES {
            issues.push(TableIssue::new("", None, "SNMP_TABLE_PLAN_LIMIT"));
            break;
        }
        let mut plan = TablePlan {
            name: name.clone(),
            base_oid: table
                .get("base_oid")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .into(),
            index_strategy: table
                .get("index_strategy")
                .and_then(|v| v.as_str())
                .unwrap_or("suffix")
                .into(),
            max_rows: table
                .get("max_rows")
                .and_then(|v| v.as_u64())
                .and_then(|value| u32::try_from(value).ok())
                .unwrap_or(0),
            columns: Vec::new(),
        };
        let Some(columns) = table
            .get("columns")
            .or_else(|| table.get("properties"))
            .and_then(|v| v.as_object())
        else {
            issues.push(TableIssue::new(name, None, "SNMP_INVALID_TABLE_PLAN"));
            continue;
        };
        if columns.len() > MAX_COLUMNS || total_columns + columns.len() > MAX_TOTAL_COLUMNS {
            issues.push(TableIssue::new(name, None, "SNMP_TABLE_PLAN_LIMIT"));
            continue;
        }
        for (column_name, value) in columns {
            let value_type = if value.is_string() {
                "STRING"
            } else {
                match value
                    .get("type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("gauge")
                {
                    "string" | "object_identifier" => "STRING",
                    "counter" => "COUNTER",
                    "gauge" | "integer" | "unsigned" | "boolean" | "enum" | "timeticks" => "GAUGE",
                    _ => {
                        issues.push(TableIssue::new(
                            name,
                            Some(column_name),
                            "SNMP_INVALID_TABLE_COLUMN",
                        ));
                        continue;
                    }
                }
            }
            .to_string();
            if value
                .get("scale")
                .is_some_and(|scale| scale.as_f64().is_none())
            {
                issues.push(TableIssue::new(
                    name,
                    Some(column_name),
                    "SNMP_INVALID_TABLE_COLUMN",
                ));
                continue;
            }
            let transform = match value.get("transform").filter(|v| !v.is_null()) {
                Some(value) => match serde_json::from_value(value.clone()) {
                    Ok(transform) => Some(transform),
                    Err(_) => {
                        issues.push(TableIssue::new(
                            name,
                            Some(column_name),
                            "SNMP_INVALID_TABLE_COLUMN",
                        ));
                        continue;
                    }
                },
                None => None,
            };
            plan.columns.push(ColumnPlan {
                name: column_name.clone(),
                oid_suffix: value
                    .as_str()
                    .or_else(|| value.get("oid_suffix").and_then(|v| v.as_str()))
                    .unwrap_or("")
                    .into(),
                metric_key: (value_type != "STRING").then(|| {
                    value
                        .get("metric")
                        .and_then(|v| v.as_str())
                        .filter(|v| !v.is_empty())
                        .unwrap_or(column_name)
                        .into()
                }),
                unit: value
                    .get("unit")
                    .and_then(|v| v.as_str())
                    .unwrap_or(if value_type == "STRING" {
                        "text"
                    } else {
                        "count"
                    })
                    .into(),
                scale: value.get("scale").and_then(|v| v.as_f64()).unwrap_or(1.0),
                value_type,
                transform,
            });
        }
        match validate_plans(std::slice::from_ref(&plan)) {
            Ok(()) => {
                total_columns += plan.columns.len();
                plans.push(plan);
            }
            Err(errors) => issues.extend(errors),
        }
    }
    (plans, issues)
}

fn valid_index(strategy: &str, index: &str) -> bool {
    if !numeric_oid(index) || index.len() > MAX_TEXT_CHARS {
        return false;
    }
    let parts = index.split('.').collect::<Vec<_>>();
    match strategy {
        "integer" => parts.len() == 1,
        "suffix" => true,
        "mac_address" => {
            let bytes = if parts.len() == 7 && parts[0] == "6" {
                &parts[1..]
            } else {
                &parts
            };
            bytes.len() == 6 && bytes.iter().all(|value| value.parse::<u8>().is_ok())
        }
        "inet_address" => {
            // Preserve the encoded suffix: IPv4/IPv6 fixed and InetAddress
            // type/length-prefixed indices are not tied to particular devices.
            if parts.len() == 4 || parts.len() == 16 {
                parts.iter().all(|value| value.parse::<u8>().is_ok())
            } else if parts.len() >= 2 {
                let expected = match parts[0] {
                    "1" => 4,
                    "2" => 16,
                    _ => return false,
                };
                parts[1].parse::<usize>() == Ok(expected)
                    && parts.len() == expected + 2
                    && parts[2..].iter().all(|value| value.parse::<u8>().is_ok())
            } else {
                false
            }
        }
        _ => false,
    }
}

pub fn parse_profile_column(plan: &TablePlan, column: &ColumnPlan, output: &[u8]) -> ParsedColumn {
    let mut parsed = ParsedColumn::default();
    if let Err(issues) = validate_plans(std::slice::from_ref(plan)) {
        parsed.issues = issues;
        return parsed;
    }
    if !plan.columns.contains(column) {
        parsed.issues.push(TableIssue::new(
            &plan.name,
            Some(&column.name),
            "SNMP_INVALID_TABLE_COLUMN",
        ));
        return parsed;
    }
    let prefix = format!("{}.{}.", plan.base_oid, column.oid_suffix);
    let output = if output.len() > crate::table_transport::MAX_TABLE_RESPONSE_BYTES {
        parsed.issues.push(TableIssue::new(
            &plan.name,
            Some(&column.name),
            "SNMP_RESPONSE_LIMIT",
        ));
        let prefix = &output[..crate::table_transport::MAX_TABLE_RESPONSE_BYTES];
        let end = prefix
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map_or(0, |index| index + 1);
        &prefix[..end]
    } else {
        output
    };
    for line in String::from_utf8_lossy(output).lines() {
        let Some((oid, value)) = line.split_once(" = ") else {
            if !line.trim().is_empty() && parsed.issues.len() < 32 {
                parsed.issues.push(TableIssue::new(
                    &plan.name,
                    Some(&column.name),
                    "SNMP_INVALID_TABLE_ROW",
                ));
            }
            continue;
        };
        let Some(index) = oid.trim().trim_start_matches('.').strip_prefix(&prefix) else {
            continue;
        };
        if !valid_index(&plan.index_strategy, index) {
            if parsed.issues.len() < 32 {
                parsed.issues.push(TableIssue::new(
                    &plan.name,
                    Some(&column.name),
                    "SNMP_INVALID_TABLE_INDEX",
                ));
            }
            continue;
        }
        if parsed.rows.len() >= plan.max_rows as usize {
            parsed.issues.push(TableIssue::new(
                &plan.name,
                Some(&column.name),
                "SNMP_RESPONSE_LIMIT",
            ));
            break;
        }
        if parsed
            .rows
            .insert(index.into(), value.trim().chars().take(256).collect())
            .is_some()
            && parsed.issues.len() < 32
        {
            parsed.issues.push(TableIssue::new(
                &plan.name,
                Some(&column.name),
                "SNMP_DUPLICATE_TABLE_INDEX",
            ));
        }
    }
    parsed.issues.truncate(32);
    parsed
}

pub fn normalize_profile_tables(
    plans: &[TablePlan],
    columns: &ProfileColumns,
) -> (ProfileSnapshot, Vec<TableIssue>) {
    let mut snapshot = ProfileSnapshot::default();
    let mut issues = Vec::new();
    if let Err(errors) = validate_plans(plans) {
        return (snapshot, errors);
    }
    for plan in plans {
        let Some(table) = columns.get(&plan.name) else {
            continue;
        };
        let indices = plan
            .columns
            .iter()
            .filter_map(|column| table.get(&column.name))
            .flat_map(|column| column.keys())
            .collect::<BTreeSet<_>>();
        for (row, index) in indices.into_iter().enumerate() {
            if row >= plan.max_rows as usize {
                issues.push(TableIssue::new(&plan.name, None, "SNMP_RESPONSE_LIMIT"));
                break;
            }
            if !valid_index(&plan.index_strategy, index) {
                issues.push(TableIssue::new(
                    &plan.name,
                    None,
                    "SNMP_INVALID_TABLE_INDEX",
                ));
                continue;
            }
            let mut labels = BTreeMap::from([
                ("table_name".into(), plan.name.clone()),
                ("table_index".into(), index.clone()),
            ]);
            for column in plan
                .columns
                .iter()
                .filter(|column| column.value_type == "STRING")
            {
                if let Some(value) = table
                    .get(&column.name)
                    .and_then(|rows| rows.get(index))
                    .and_then(|raw| parse_table_text(raw))
                {
                    labels.insert(
                        format!("column_{}", column.name),
                        value.chars().take(MAX_TEXT_CHARS).collect(),
                    );
                }
            }
            let mut row_metrics = Vec::new();
            for column in plan
                .columns
                .iter()
                .filter(|column| column.value_type != "STRING")
            {
                let Some(raw) = table.get(&column.name).and_then(|rows| rows.get(index)) else {
                    if issues.len() < 256 {
                        issues.push(TableIssue::new(
                            &plan.name,
                            Some(&column.name),
                            "SNMP_TABLE_INCOMPLETE",
                        ));
                    }
                    continue;
                };
                let related = match &column.transform {
                    Some(
                        Transform::Percentage { total_metric }
                        | Transform::UsedFromFree { total_metric }
                        | Transform::UsedFromTotal { total_metric },
                    ) => plan
                        .columns
                        .iter()
                        .find(|related| {
                            related.name == *total_metric
                                || related.metric_key.as_ref() == Some(total_metric)
                        })
                        .and_then(|related| {
                            table
                                .get(&related.name)
                                .and_then(|rows| rows.get(index))
                                .and_then(|raw| parse_table_number(raw))
                                .and_then(|raw| {
                                    apply_numeric_transform(raw, related.scale, None, None)
                                })
                        }),
                    _ => None,
                };
                let value = parse_table_number(raw).and_then(|raw| {
                    apply_numeric_transform(raw, column.scale, column.transform.as_ref(), related)
                });
                let Some(value) = value else {
                    if issues.len() < 256 {
                        issues.push(TableIssue::new(
                            &plan.name,
                            Some(&column.name),
                            "SNMP_INVALID_TABLE_VALUE",
                        ));
                    }
                    continue;
                };
                row_metrics.push(StandardMetric {
                    name: column.name.clone(),
                    metric_key: column.metric_key.clone().unwrap(),
                    unit: column.unit.clone(),
                    value_type: column.value_type.clone(),
                    value,
                    labels: labels.clone(),
                });
            }
            if snapshot.metrics.len() + row_metrics.len() > MAX_METRICS
                || snapshot.inventory.len() >= MAX_INVENTORY
            {
                issues.push(TableIssue::new(&plan.name, None, "SNMP_RESPONSE_LIMIT"));
                break;
            }
            let name = labels
                .get("column_name")
                .or_else(|| labels.get("column_description"))
                .or_else(|| labels.get("column_descr"))
                .cloned()
                .unwrap_or_else(|| format!("{}-{index}", plan.name));
            let inventory = ProfileInventory {
                kind: "table".into(),
                index: index.clone(),
                name,
                attributes: labels,
            };
            let metrics_len = snapshot.metrics.len();
            snapshot.metrics.extend(row_metrics);
            snapshot.inventory.push(inventory);
            if serde_json::to_vec(&snapshot).map_or(true, |json| json.len() > MAX_SNAPSHOT_BYTES) {
                snapshot.metrics.truncate(metrics_len);
                snapshot.inventory.pop();
                issues.push(TableIssue::new(&plan.name, None, "SNMP_RESPONSE_LIMIT"));
                break;
            }
        }
    }
    issues.truncate(256);
    (snapshot, issues)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> TablePlan {
        plans_from_profile_json(&serde_json::json!({"tables":{"ports":{
            "base_oid":"1.3.6.1.4.1.9", "index_strategy":"suffix", "max_rows":10000,
            "columns":{"name":{"oid_suffix":"1","type":"string"},"total":{"oid_suffix":"2","scale":1024},
                "free":{"oid_suffix":"3","scale":1024,"transform":{"operation":"used_from_free","total_metric":"total"}},
                "compact":"4"}
        }}})).0.pop().unwrap()
    }

    #[test]
    fn composite_rows_transforms_and_metadata_share_wire_contract() {
        let plan = plan();
        assert_eq!(plan.max_rows, 10000);
        assert_eq!(
            serde_json::to_value(&plan).unwrap()["columns"][0]["oidSuffix"],
            "4"
        );
        let mut table = BTreeMap::new();
        for (name, suffix, raw) in [
            ("name", "1", "STRING: \"wan\""),
            ("total", "2", "100"),
            ("free", "3", "25"),
            ("compact", "4", "0"),
        ] {
            let column = plan
                .columns
                .iter()
                .find(|column| column.name == name)
                .unwrap();
            let parsed = parse_profile_column(
                &plan,
                column,
                format!(".1.3.6.1.4.1.9.{suffix}.7.99 = {raw}\n").as_bytes(),
            );
            assert!(parsed.issues.is_empty());
            table.insert(name.into(), parsed.rows);
        }
        let (snapshot, issues) =
            normalize_profile_tables(&[plan], &BTreeMap::from([("ports".into(), table)]));
        assert!(issues.is_empty());
        assert_eq!(
            snapshot
                .metrics
                .iter()
                .find(|m| m.name == "free")
                .unwrap()
                .value,
            76800.0
        );
        assert!(!snapshot.metrics.iter().any(|m| m.name == "compact"));
        assert_eq!(snapshot.metrics[0].labels["table_index"], "7.99");
        assert_eq!(snapshot.metrics[0].labels["column_name"], "wan");
    }

    #[test]
    fn rejects_injection_unsupported_transforms_and_cardinality() {
        let mut plan = plan();
        plan.base_oid = "1.2;touch x".into();
        assert!(validate_plans(&[plan.clone()]).is_err());
        plan = super::tests::plan();
        plan.columns[0].transform = Some(Transform::Sum);
        assert!(validate_plans(&[plan]).is_err());
        assert!(valid_index("inet_address", "1.4.192.0.2.9"));
        assert!(valid_index("mac_address", "0.1.2.3.4.255"));
        assert!(!valid_index("integer", "1.2"));
        assert!(!valid_index("suffix", "1.-2"));
    }

    #[test]
    fn malformed_values_do_not_hide_successful_rows_or_become_zero() {
        let mut plan = plan();
        plan.max_rows = 1;
        let column = plan
            .columns
            .iter()
            .find(|column| column.name == "total")
            .unwrap();
        let parsed = parse_profile_column(
            &plan,
            column,
            b"1.3.6.1.4.1.9.2.9 = 42\n1.3.6.1.4.1.9.2.10 = 17\n",
        );
        assert_eq!(parsed.rows.len(), 1);
        assert_eq!(parsed.issues[0].code, "SNMP_RESPONSE_LIMIT");
        let columns = BTreeMap::from([(
            "ports".into(),
            BTreeMap::from([(
                "total".into(),
                BTreeMap::from([("9".into(), "No Such Instance".into())]),
            )]),
        )]);
        let (snapshot, issues) = normalize_profile_tables(&[plan], &columns);
        assert!(snapshot.metrics.is_empty());
        assert!(issues
            .iter()
            .any(|issue| issue.code == "SNMP_INVALID_TABLE_VALUE"));
    }

    #[test]
    fn synthetic_golden_fixture_exercises_schema_parser_and_normalizer() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../fixtures/profile-tables.json")).unwrap();
        let (plans, issues) = plans_from_profile_json(&fixture["profile"]);
        assert!(issues.is_empty());
        assert_eq!(serde_json::to_value(&plans).unwrap(), fixture["plans"]);
        let plan = &plans[0];
        let mut table = BTreeMap::new();
        for column in &plan.columns {
            let output = fixture["outputs"][&column.name].as_str().unwrap();
            let parsed = parse_profile_column(plan, column, output.as_bytes());
            assert!(parsed.issues.is_empty());
            table.insert(column.name.clone(), parsed.rows);
        }
        let (snapshot, issues) =
            normalize_profile_tables(&plans, &BTreeMap::from([(plan.name.clone(), table)]));
        assert!(issues.is_empty());
        assert_eq!(serde_json::to_value(snapshot).unwrap(), fixture["snapshot"]);
    }

    #[test]
    fn wide_tables_preserve_bounded_rows_with_explicit_limit() {
        let (plans, issues) = plans_from_profile_json(&serde_json::json!({"tables":{"wide":{
            "base_oid":"1.3.6.1.4.1.9","max_rows":10000,
            "columns":{"value":{"oid_suffix":"1"}}
        }}}));
        assert!(issues.is_empty());
        let rows = (1..=300)
            .map(|index| (index.to_string(), "42".into()))
            .collect();
        let (snapshot, issues) = normalize_profile_tables(
            &plans,
            &BTreeMap::from([("wide".into(), BTreeMap::from([("value".into(), rows)]))]),
        );
        assert_eq!(snapshot.inventory.len(), MAX_INVENTORY);
        assert_eq!(snapshot.metrics.len(), MAX_INVENTORY);
        assert!(issues
            .iter()
            .any(|issue| issue.code == "SNMP_RESPONSE_LIMIT"));
        assert!(serde_json::to_vec(&snapshot).unwrap().len() <= MAX_SNAPSHOT_BYTES);
    }
}
