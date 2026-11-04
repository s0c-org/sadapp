//! Bounded, privacy-preserving SNMP capability reports built from executed columns.
//!
//! The recorder captures one outcome per executed OID. Reports never contain values,
//! descriptions or credentials: only OIDs, row index strings, statuses and codes.
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::metric_capability_group;
use crate::profile_tables::{numeric_oid, ColumnPlan, TablePlan};
use crate::table_transport::TableWalkFailure;

pub const CAPABILITY_REPORT_SCHEMA_VERSION: u32 = 1;
pub const MAX_REPORT_GROUPS: usize = 16;
pub const MAX_REPORT_COLUMNS: usize = 256;
pub const MAX_COLUMN_INDEXES: usize = 128;
pub const MAX_INDEX_CHARS: usize = 64;
pub const MAX_OID_CHARS: usize = 128;
pub const MAX_REPORT_BYTES: usize = 64 * 1024;
pub const CAPABILITY_REPORT_TTL: Duration = Duration::from_secs(24 * 60 * 60);
pub const CAPABILITY_GROUPS: &[&str] = &[
    "cpu",
    "memory",
    "storage",
    "interfaces",
    "sensors",
    "inventory",
    "health",
    "vendor",
];
pub const CAPABILITY_CODES: &[&str] = &[
    "SNMP_TIMEOUT",
    "SNMP_RESPONSE_LIMIT",
    "SNMP_EXEC_FAILED",
    "SNMP_AUTH_FAILED",
    "SNMP_GET_FAILED",
    "SNMP_NO_SUCH_OBJECT",
    "SNMP_NO_ROWS",
    "SNMP_NOT_ATTEMPTED",
    "SNMP_INVALID_VALUE",
    "SNMP_INVALID_TABLE_ROW",
    "SNMP_INVALID_TABLE_INDEX",
    "SNMP_DUPLICATE_TABLE_INDEX",
    "SNMP_INVALID_TABLE_COLUMN",
    "SNMP_REPORT_LIMIT",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityStatus {
    Supported,
    Unsupported,
    Unknown,
    Partial,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilityColumn {
    pub oid: String,
    pub status: CapabilityStatus,
    pub indexes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilityGroup {
    pub name: String,
    pub status: CapabilityStatus,
    pub columns: Vec<CapabilityColumn>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilityReport {
    pub schema_version: u32,
    pub profile_checksum: String,
    pub observed_at: String,
    pub groups: Vec<CapabilityGroup>,
}

impl CapabilityReport {
    pub fn column(&self, oid: &str) -> Option<&CapabilityColumn> {
        self.groups
            .iter()
            .flat_map(|group| &group.columns)
            .find(|column| column.oid == oid)
    }
}

/// Outcome of one executed column (table walk or scalar GET).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ColumnResult {
    /// The command returned; `code` records a partial/limit/parse issue for this column.
    Rows { code: Option<String> },
    /// The command succeeded but returned no rows (noSuchObject, noSuchInstance, endOfMibView).
    Empty,
    /// Transport failure; never proves the OID is unsupported.
    Failed(String),
    /// Skipped during this run (budget exhausted or a short-lived skip cache).
    NotAttempted,
}

impl ColumnResult {
    pub fn from_failure(failure: TableWalkFailure) -> Self {
        Self::Failed(failure.diagnostic_code().into())
    }
}

fn known_code(code: &str) -> String {
    if CAPABILITY_CODES.contains(&code) {
        code.into()
    } else {
        "SNMP_GET_FAILED".into()
    }
}

fn valid_index(index: &str) -> bool {
    !index.is_empty()
        && index.len() <= MAX_INDEX_CHARS
        && index
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
}

fn valid_report_oid(oid: &str) -> bool {
    oid.len() <= MAX_OID_CHARS && numeric_oid(oid)
}

fn status_rank(status: CapabilityStatus) -> u8 {
    match status {
        CapabilityStatus::Supported => 3,
        CapabilityStatus::Unsupported => 2,
        _ => 1,
    }
}

#[derive(Debug, Clone)]
struct Entry {
    status: CapabilityStatus,
    indexes: BTreeSet<String>,
    code: Option<String>,
    truncated: bool,
}

#[derive(Debug, Clone, Default)]
pub struct CapabilityRecorder {
    columns: BTreeMap<(String, String), Entry>,
}

impl CapabilityRecorder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.columns.is_empty()
    }

    pub fn record_column<I, S>(&mut self, group: &str, oid: &str, indexes: I, result: ColumnResult)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let oid = oid.trim().trim_start_matches('.');
        if !valid_report_oid(oid) {
            return;
        }
        let group = if CAPABILITY_GROUPS.contains(&group) {
            group
        } else {
            "vendor"
        };
        let mut retained = BTreeSet::new();
        let mut truncated = false;
        for index in indexes {
            let index = index.as_ref();
            if !valid_index(index) {
                continue;
            }
            if retained.len() >= MAX_COLUMN_INDEXES {
                truncated = true;
                break;
            }
            retained.insert(index.to_string());
        }
        let entry = match result {
            ColumnResult::Rows { code } if !retained.is_empty() => Entry {
                status: CapabilityStatus::Supported,
                indexes: retained,
                code: code.as_deref().map(known_code),
                truncated,
            },
            ColumnResult::Rows { code: Some(code) } => Entry {
                status: CapabilityStatus::Unknown,
                indexes: BTreeSet::new(),
                code: Some(known_code(&code)),
                truncated: false,
            },
            ColumnResult::Rows { code: None } | ColumnResult::Empty => Entry {
                status: CapabilityStatus::Unsupported,
                indexes: BTreeSet::new(),
                code: Some("SNMP_NO_ROWS".into()),
                truncated: false,
            },
            ColumnResult::Failed(code) => Entry {
                status: CapabilityStatus::Unknown,
                indexes: BTreeSet::new(),
                code: Some(known_code(&code)),
                truncated: false,
            },
            ColumnResult::NotAttempted => Entry {
                status: CapabilityStatus::Unknown,
                indexes: BTreeSet::new(),
                code: Some("SNMP_NOT_ATTEMPTED".into()),
                truncated: false,
            },
        };
        let key = (group.to_string(), oid.to_string());
        match self.columns.get_mut(&key) {
            None => {
                self.columns.insert(key, entry);
            }
            Some(existing) => {
                if status_rank(entry.status) > status_rank(existing.status) {
                    *existing = entry;
                } else if entry.status == CapabilityStatus::Supported
                    && existing.status == CapabilityStatus::Supported
                {
                    existing.truncated |= entry.truncated;
                    existing.code = existing.code.take().or(entry.code);
                    for index in entry.indexes {
                        if existing.indexes.len() >= MAX_COLUMN_INDEXES {
                            existing.truncated = true;
                            break;
                        }
                        existing.indexes.insert(index);
                    }
                }
            }
        }
    }

    /// Build a deterministic report within every count and byte bound.
    pub fn finish(self, profile_checksum: &str, observed_at: &str) -> CapabilityReport {
        let profile_checksum = sanitize_checksum(profile_checksum);
        let observed_at = observed_at.chars().take(40).collect::<String>();
        let mut cap = MAX_COLUMN_INDEXES;
        loop {
            let report = build(&self.columns, &profile_checksum, &observed_at, cap);
            let fits = serde_json::to_vec(&report)
                .map(|bytes| bytes.len() <= MAX_REPORT_BYTES)
                .unwrap_or(false);
            if fits || cap == 0 {
                return report;
            }
            cap /= 2;
        }
    }
}

fn sanitize_checksum(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || ":._-".contains(*character))
        .take(128)
        .collect()
}

fn build(
    columns: &BTreeMap<(String, String), Entry>,
    profile_checksum: &str,
    observed_at: &str,
    index_cap: usize,
) -> CapabilityReport {
    let mut groups = BTreeMap::<&str, Vec<CapabilityColumn>>::new();
    for ((group, oid), entry) in columns.iter().take(MAX_REPORT_COLUMNS) {
        let truncated = entry.truncated || entry.indexes.len() > index_cap;
        let code = match (&entry.code, truncated) {
            (Some(code), _) => Some(code.clone()),
            (None, true) => Some("SNMP_REPORT_LIMIT".into()),
            (None, false) => None,
        };
        groups.entry(group).or_default().push(CapabilityColumn {
            oid: oid.clone(),
            status: entry.status,
            indexes: entry.indexes.iter().take(index_cap).cloned().collect(),
            code,
        });
    }
    CapabilityReport {
        schema_version: CAPABILITY_REPORT_SCHEMA_VERSION,
        profile_checksum: profile_checksum.into(),
        observed_at: observed_at.into(),
        groups: groups
            .into_iter()
            .take(MAX_REPORT_GROUPS)
            .map(|(name, mut columns)| {
                columns.sort_by(|left, right| left.oid.cmp(&right.oid));
                CapabilityGroup {
                    name: name.into(),
                    status: group_status(&columns),
                    columns,
                }
            })
            .collect(),
    }
}

pub fn group_status(columns: &[CapabilityColumn]) -> CapabilityStatus {
    let mut statuses = columns.iter().map(|column| column.status);
    match statuses.next() {
        None => CapabilityStatus::Unknown,
        Some(first) if statuses.all(|status| status == first) => first,
        Some(_) => CapabilityStatus::Partial,
    }
}

pub fn standard_column_group(standard_key: &str) -> &'static str {
    match standard_key.split('.').next().unwrap_or_default() {
        "if" => "interfaces",
        "storage" => "storage",
        "sensor" => "sensors",
        "entity" => "inventory",
        _ => "vendor",
    }
}

pub fn profile_column_group(plan: &TablePlan, column: &ColumnPlan) -> &'static str {
    match column.metric_key.as_deref() {
        Some(metric) => match metric_capability_group(metric) {
            "vendor" => metric_capability_group(&format!("{}.{}", plan.name, column.name)),
            group => group,
        },
        None => metric_capability_group(&format!("{}.{}", plan.name, column.name)),
    }
}

pub fn scalar_group(metric: &str) -> &'static str {
    metric_capability_group(metric)
}

/// Strictly validate an untrusted report; only the exact v1 shape and known codes are accepted.
pub fn validate_report(value: &serde_json::Value) -> Result<CapabilityReport, &'static str> {
    if serde_json::to_vec(value).map_or(true, |bytes| bytes.len() > MAX_REPORT_BYTES) {
        return Err("report_too_large");
    }
    let report: CapabilityReport =
        serde_json::from_value(value.clone()).map_err(|_| "invalid_shape")?;
    if report.schema_version != CAPABILITY_REPORT_SCHEMA_VERSION {
        return Err("unsupported_schema_version");
    }
    if report.profile_checksum.is_empty()
        || report.profile_checksum.len() > 128
        || sanitize_checksum(&report.profile_checksum) != report.profile_checksum
    {
        return Err("invalid_profile_checksum");
    }
    let observed = report.observed_at.as_bytes();
    if observed.len() > 40
        || observed.len() < 11
        || !observed[..10]
            .iter()
            .enumerate()
            .all(|(position, byte)| match position {
                4 | 7 => *byte == b'-',
                _ => byte.is_ascii_digit(),
            })
        || observed[10] != b'T'
    {
        return Err("invalid_observed_at");
    }
    if report.groups.len() > MAX_REPORT_GROUPS {
        return Err("too_many_groups");
    }
    let mut names = BTreeSet::new();
    let mut total = 0;
    for group in &report.groups {
        if !CAPABILITY_GROUPS.contains(&group.name.as_str()) || !names.insert(&group.name) {
            return Err("invalid_group");
        }
        if group.columns.is_empty() {
            return Err("empty_group");
        }
        total += group.columns.len();
        if total > MAX_REPORT_COLUMNS {
            return Err("too_many_columns");
        }
        let mut oids = BTreeSet::new();
        for column in &group.columns {
            if !valid_report_oid(&column.oid) || !oids.insert(&column.oid) {
                return Err("invalid_oid");
            }
            if column.indexes.len() > MAX_COLUMN_INDEXES
                || !column.indexes.iter().all(|index| valid_index(index))
            {
                return Err("invalid_indexes");
            }
            if column
                .code
                .as_deref()
                .is_some_and(|code| !CAPABILITY_CODES.contains(&code))
            {
                return Err("unknown_code");
            }
            match column.status {
                CapabilityStatus::Partial => return Err("invalid_column_status"),
                CapabilityStatus::Supported if column.indexes.is_empty() => {
                    return Err("supported_without_indexes")
                }
                CapabilityStatus::Unsupported | CapabilityStatus::Unknown
                    if !column.indexes.is_empty() || column.code.is_none() =>
                {
                    return Err("invalid_column_status")
                }
                _ => {}
            }
        }
        if group.status != group_status(&group.columns) {
            return Err("inconsistent_group_status");
        }
    }
    Ok(report)
}

pub fn reboot_detected(previous_uptime_seconds: Option<f64>, current_uptime_seconds: Option<f64>) -> bool {
    matches!(
        (previous_uptime_seconds, current_uptime_seconds),
        (Some(previous), Some(current)) if previous.is_finite() && current.is_finite() && current < previous
    )
}

/// A report may justify skipping `unsupported` OIDs only while it is fresh for the same profile bundle.
pub fn report_is_fresh(
    report: &CapabilityReport,
    current_profile_checksum: &str,
    age: Duration,
    reboot_detected: bool,
) -> bool {
    report.schema_version == CAPABILITY_REPORT_SCHEMA_VERSION
        && !report.profile_checksum.is_empty()
        && report.profile_checksum == current_profile_checksum
        && age < CAPABILITY_REPORT_TTL
        && !reboot_detected
}

/// Future polling helper (not wired into polling): only fresh `unsupported` OIDs are dropped.
/// Unknown, supported and unreported OIDs are always polled, so unknown is never suppressed.
pub fn columns_to_poll<'a>(
    report: Option<&CapabilityReport>,
    fresh: bool,
    candidates: &'a [String],
) -> Vec<&'a String> {
    candidates
        .iter()
        .filter(|oid| match (report, fresh) {
            (Some(report), true) => report
                .column(oid.trim_start_matches('.'))
                .is_none_or(|column| column.status != CapabilityStatus::Unsupported),
            _ => true,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const OID: &str = "1.3.6.1.2.1.2.2.1.8";

    fn rows(code: Option<&str>) -> ColumnResult {
        ColumnResult::Rows {
            code: code.map(str::to_string),
        }
    }

    #[test]
    fn distinguishes_supported_unsupported_and_unknown() {
        let mut recorder = CapabilityRecorder::new();
        recorder.record_column("interfaces", OID, ["2", "1"], rows(None));
        recorder.record_column("interfaces", "1.3.6.1.2.1.2.2.1.5", Vec::<String>::new(), ColumnResult::Empty);
        recorder.record_column(
            "storage",
            "1.3.6.1.2.1.25.2.3.1.5",
            Vec::<String>::new(),
            ColumnResult::from_failure(TableWalkFailure::Timeout),
        );
        let report = recorder.finish("abc123", "2026-11-04T18:00:00Z");
        let value = serde_json::to_value(&report).unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "schemaVersion": 1, "profileChecksum": "abc123", "observedAt": "2026-11-04T18:00:00Z",
                "groups": [
                    {"name": "interfaces", "status": "partial", "columns": [
                        {"oid": "1.3.6.1.2.1.2.2.1.5", "status": "unsupported", "indexes": [], "code": "SNMP_NO_ROWS"},
                        {"oid": OID, "status": "supported", "indexes": ["1", "2"]},
                    ]},
                    {"name": "storage", "status": "unknown", "columns": [
                        {"oid": "1.3.6.1.2.1.25.2.3.1.5", "status": "unknown", "indexes": [], "code": "SNMP_TIMEOUT"},
                    ]},
                ],
            })
        );
        assert_eq!(validate_report(&value).unwrap(), report);
    }

    #[test]
    fn timeouts_and_parse_failures_are_never_unsupported() {
        for failure in [
            TableWalkFailure::Timeout,
            TableWalkFailure::Authentication,
            TableWalkFailure::Failed,
            TableWalkFailure::Unavailable,
            TableWalkFailure::RowLimit,
        ] {
            let mut recorder = CapabilityRecorder::new();
            recorder.record_column("cpu", OID, Vec::<String>::new(), ColumnResult::from_failure(failure));
            let report = recorder.finish("c", "2026-11-04T18:00:00Z");
            assert_eq!(report.groups[0].columns[0].status, CapabilityStatus::Unknown);
        }
        let mut recorder = CapabilityRecorder::new();
        recorder.record_column("cpu", OID, Vec::<String>::new(), rows(Some("SNMP_INVALID_TABLE_INDEX")));
        recorder.record_column("cpu", "1.3.6.1.4.1.9.1", Vec::<String>::new(), ColumnResult::NotAttempted);
        recorder.record_column("cpu", "1.3.6.1.4.1.9.2", Vec::<String>::new(), ColumnResult::Failed("raw secret".into()));
        let report = recorder.finish("c", "2026-11-04T18:00:00Z");
        let codes = report.groups[0]
            .columns
            .iter()
            .map(|column| (column.status, column.code.clone().unwrap()))
            .collect::<Vec<_>>();
        assert_eq!(
            codes,
            vec![
                (CapabilityStatus::Unknown, "SNMP_INVALID_TABLE_INDEX".to_string()),
                (CapabilityStatus::Unknown, "SNMP_NOT_ATTEMPTED".to_string()),
                (CapabilityStatus::Unknown, "SNMP_GET_FAILED".to_string()),
            ]
        );
    }

    #[test]
    fn partial_rows_stay_supported_with_limit_code_and_merge_prefers_evidence() {
        let mut recorder = CapabilityRecorder::new();
        recorder.record_column("interfaces", OID, Vec::<String>::new(), ColumnResult::from_failure(TableWalkFailure::Timeout));
        recorder.record_column("interfaces", OID, ["7"], rows(Some("SNMP_RESPONSE_LIMIT")));
        recorder.record_column("interfaces", OID, Vec::<String>::new(), ColumnResult::Empty);
        let report = recorder.finish("c", "2026-11-04T18:00:00Z");
        let column = &report.groups[0].columns[0];
        assert_eq!(column.status, CapabilityStatus::Supported);
        assert_eq!(column.indexes, vec!["7"]);
        assert_eq!(column.code.as_deref(), Some("SNMP_RESPONSE_LIMIT"));
    }

    #[test]
    fn counts_indexes_and_bytes_are_bounded() {
        let mut recorder = CapabilityRecorder::new();
        for column in 0..400 {
            recorder.record_column(
                "interfaces",
                &format!("1.3.6.1.4.1.9999.{column}"),
                (0..1000).map(|index| format!("{index}.{}", "1".repeat(50))),
                rows(None),
            );
        }
        recorder.record_column("interfaces", "not-an-oid", ["1"], rows(None));
        recorder.record_column("interfaces", "1.3.6.1.9", ["bad index with spaces", "x".repeat(65).as_str()], rows(None));
        let report = recorder.finish("c", "2026-11-04T18:00:00Z");
        let columns = report.groups.iter().map(|group| group.columns.len()).sum::<usize>();
        assert_eq!(columns, MAX_REPORT_COLUMNS);
        let bytes = serde_json::to_vec(&report).unwrap();
        assert!(bytes.len() <= MAX_REPORT_BYTES, "{}", bytes.len());
        assert!(report.groups[0].columns.iter().all(|column| column.indexes.len() <= MAX_COLUMN_INDEXES));
        assert!(report.groups[0].columns.iter().any(|column| column.code.as_deref() == Some("SNMP_REPORT_LIMIT")));
        validate_report(&serde_json::to_value(&report).unwrap()).unwrap();
    }

    #[test]
    fn validator_rejects_unknown_shapes_codes_and_inconsistent_status() {
        let base = serde_json::json!({
            "schemaVersion": 1, "profileChecksum": "abc", "observedAt": "2026-11-04T18:00:00Z",
            "groups": [{"name": "cpu", "status": "unknown", "columns": [
                {"oid": OID, "status": "unknown", "indexes": [], "code": "SNMP_TIMEOUT"}]}],
        });
        assert!(validate_report(&base).is_ok());
        let mutate = |path: &str, value: serde_json::Value| {
            let mut copy = base.clone();
            *copy.pointer_mut(path).unwrap() = value;
            validate_report(&copy)
        };
        assert!(mutate("/schemaVersion", 2.into()).is_err());
        assert!(mutate("/profileChecksum", "".into()).is_err());
        assert!(mutate("/groups/0/name", "bogus".into()).is_err());
        assert!(mutate("/groups/0/status", "supported".into()).is_err());
        assert!(mutate("/groups/0/columns/0/code", "SNMP_SECRET".into()).is_err());
        assert!(mutate("/groups/0/columns/0/status", "unsupported".into()).is_err());
        assert!(mutate("/groups/0/columns/0/status", "partial".into()).is_err());
        assert!(mutate("/groups/0/columns/0/indexes", serde_json::json!(["1"])).is_err());
        assert!(mutate("/groups/0/columns/0/oid", "ifDescr".into()).is_err());
        assert!(mutate("/observedAt", "yesterday".into()).is_err());
        let mut extra = base.clone();
        extra["groups"][0]["columns"][0]["value"] = "public".into();
        assert!(validate_report(&extra).is_err());
        let mut supported = base.clone();
        supported["groups"][0]["status"] = "supported".into();
        supported["groups"][0]["columns"][0] = serde_json::json!({"oid": OID, "status": "supported", "indexes": []});
        assert!(validate_report(&supported).is_err());
    }

    #[test]
    fn unsupported_is_only_skipped_while_fresh_and_unknown_is_always_polled() {
        let mut recorder = CapabilityRecorder::new();
        recorder.record_column("interfaces", "1.3.6.1.1", Vec::<String>::new(), ColumnResult::Empty);
        recorder.record_column("interfaces", "1.3.6.1.2", Vec::<String>::new(), ColumnResult::from_failure(TableWalkFailure::Timeout));
        recorder.record_column("interfaces", "1.3.6.1.3", ["1"], rows(None));
        let report = recorder.finish("sum", "2026-11-04T18:00:00Z");
        let candidates = ["1.3.6.1.1", "1.3.6.1.2", "1.3.6.1.3", "1.3.6.1.4"].map(String::from);
        let fresh = report_is_fresh(&report, "sum", Duration::from_secs(60), false);
        assert!(fresh);
        assert_eq!(columns_to_poll(Some(&report), fresh, &candidates).len(), 3);
        assert!(!report_is_fresh(&report, "other", Duration::from_secs(60), false));
        assert!(!report_is_fresh(&report, "sum", CAPABILITY_REPORT_TTL, false));
        assert!(!report_is_fresh(&report, "sum", Duration::ZERO, true));
        assert_eq!(columns_to_poll(Some(&report), false, &candidates).len(), 4);
        assert_eq!(columns_to_poll(None, true, &candidates).len(), 4);
        assert!(reboot_detected(Some(500.0), Some(10.0)));
        assert!(!reboot_detected(Some(500.0), Some(900.0)));
        assert!(!reboot_detected(None, Some(1.0)));
    }

    #[test]
    fn group_helpers_use_canonical_names() {
        for spec in crate::standard_tables::STANDARD_TABLES {
            assert_ne!(standard_column_group(spec.key), "vendor", "{}", spec.key);
        }
        assert_eq!(scalar_group("cpu.usage"), "cpu");
        assert_eq!(scalar_group("ups.something"), "vendor");
    }
}
