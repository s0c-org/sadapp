use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub const FASTPATH_CPU_OID: &str = "1.3.6.1.4.1.4413.1.1.1.1.4.9.0";

/// Decode net-snmp's value-only day:hour:minute:second TimeTicks as centiseconds.
pub fn parse_formatted_ticks(raw: &str) -> Option<f64> {
    let parts = raw.trim().split(':').collect::<Vec<_>>();
    if parts.len() != 4 {
        return None;
    }
    let days = parts[0].parse::<u32>().ok()?;
    let hours = parts[1].parse::<u32>().ok()?;
    let minutes = parts[2].parse::<u32>().ok()?;
    let seconds = parts[3].parse::<f64>().ok()?;
    if hours >= 24 || minutes >= 60 || !seconds.is_finite() || !(0.0..60.0).contains(&seconds) {
        return None;
    }
    let ticks =
        ((days as f64 * 24.0 + hours as f64) * 3600.0 + minutes as f64 * 60.0 + seconds) * 100.0;
    (ticks <= u32::MAX as f64).then_some(ticks.round())
}

/// FASTPATH reports three interval percentages as text, not a numeric scalar.
/// Select the five-second utilization, never the leading interval duration.
pub fn parse_fastpath_cpu(raw: &str) -> Option<f64> {
    let raw = raw.trim();
    let raw = raw.strip_prefix("STRING:").unwrap_or(raw).trim();
    let raw = raw
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(raw);
    let raw = raw.trim().strip_prefix("5 ")?;
    let raw = raw
        .strip_prefix("Secs")
        .or_else(|| raw.strip_prefix("Sec"))?;
    let raw = raw.trim_start().strip_prefix('(')?;
    let (percentage, _) = raw.split_once("%)")?;
    let value = percentage.trim().parse::<f64>().ok()?;
    (value.is_finite() && (0.0..=100.0).contains(&value)).then_some(value)
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Transform {
    Scale { factor: f64 },
    Offset { value: f64 },
    Percentage { total_metric: String },
    Enum { values: BTreeMap<String, String> },
    Sum,
    Min,
    Max,
    UsedFromTotal { total_metric: String },
    UsedFromFree { total_metric: String },
}

/// Apply the scalar's scale before its transform. `related_value` must already be
/// multiplied by the related scalar's own scale, but not its transform.
/// Percentage divides scaled units; used-from transforms subtract scaled units.
/// Negative differences are preserved, not clamped.
pub fn apply_numeric_transform(
    raw: f64,
    scale: f64,
    transform: Option<&Transform>,
    related_value: Option<f64>,
) -> Option<f64> {
    if !raw.is_finite() || !scale.is_finite() {
        return None;
    }
    let scaled = raw * scale;
    let value = match transform {
        None => scaled,
        Some(Transform::Scale { factor }) if factor.is_finite() => scaled * factor,
        Some(Transform::Offset { value }) if value.is_finite() => scaled + value,
        Some(Transform::Percentage { .. }) => {
            scaled / related_value.filter(|total| total.is_finite() && *total > 0.0)? * 100.0
        }
        Some(Transform::UsedFromTotal { .. } | Transform::UsedFromFree { .. }) => {
            related_value.filter(|total| total.is_finite())? - scaled
        }
        Some(Transform::Sum | Transform::Min | Transform::Max | Transform::Enum { .. }) => {
            return None
        }
        Some(Transform::Scale { .. } | Transform::Offset { .. }) => return None,
    };
    value.is_finite().then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formatted_ticks_preserve_days_and_fractional_seconds() {
        assert_eq!(parse_formatted_ticks("1:14:43:13.00"), Some(13939300.0));
        assert_eq!(parse_formatted_ticks("1:14:35:05.50"), Some(13890550.0));
        assert_eq!(parse_formatted_ticks("0:0:00:00.00"), Some(0.0));
        for raw in [
            "1:24:00:00",
            "1:00:60:00",
            "1:00:00:60",
            "1:00:00:NaN",
            "-1:00:00:00",
            "999:00:00:00",
        ] {
            assert_eq!(parse_formatted_ticks(raw), None);
        }
    }

    #[test]
    fn fastpath_cpu_selects_short_interval_and_rejects_invalid_values() {
        for raw in [
            "    5 Secs ( 24.1207%)   60 Secs ( 17.8787%)  300 Secs ( 16.1427%)",
            "STRING: \"    5 Sec ( 24.1207%)   60 Sec ( 17.8787%)  300 Sec ( 16.1427%)\"",
        ] {
            assert_eq!(parse_fastpath_cpu(raw), Some(24.1207));
        }
        assert_eq!(parse_fastpath_cpu("5 Secs (0%)"), Some(0.0));
        assert_eq!(parse_fastpath_cpu("5 Secs (100%)"), Some(100.0));
        for raw in [
            "No Such Object",
            "5",
            "60 Secs (12%)",
            "5 Secs (NaN%)",
            "5 Secs (inf%)",
            "5 Secs (-1%)",
            "5 Secs (101%)",
            "5 Secs (12) 60 Secs (15%)",
            "5 Secs (bad%)",
        ] {
            assert_eq!(parse_fastpath_cpu(raw), None, "{raw}");
        }
    }

    #[test]
    fn numeric_related_values_are_in_scaled_units() {
        let total = apply_numeric_transform(100.0, 1024.0, None, None);
        for transform in [
            Transform::UsedFromFree {
                total_metric: "total".into(),
            },
            Transform::UsedFromTotal {
                total_metric: "total".into(),
            },
        ] {
            assert_eq!(
                apply_numeric_transform(25.0, 1024.0, Some(&transform), total),
                Some(76800.0)
            );
            assert_eq!(
                apply_numeric_transform(125.0, 1024.0, Some(&transform), total),
                Some(-25600.0)
            );
        }
        let percentage = Transform::Percentage {
            total_metric: "total".into(),
        };
        assert_eq!(
            apply_numeric_transform(25.0, 1024.0, Some(&percentage), total),
            Some(25.0)
        );
        let independently_scaled_total = apply_numeric_transform(1.0, 102400.0, None, None);
        assert_eq!(
            apply_numeric_transform(25.0, 1024.0, Some(&percentage), independently_scaled_total),
            Some(25.0)
        );
    }

    #[test]
    fn numeric_related_values_reject_nonfinite_or_missing_inputs() {
        let percentage = Transform::Percentage {
            total_metric: "total".into(),
        };
        for total in [
            None,
            Some(0.0),
            Some(-1.0),
            Some(f64::INFINITY),
            Some(f64::NAN),
        ] {
            assert_eq!(
                apply_numeric_transform(25.0, 1024.0, Some(&percentage), total),
                None
            );
        }
        assert_eq!(apply_numeric_transform(f64::MAX, 1024.0, None, None), None);
    }
}
