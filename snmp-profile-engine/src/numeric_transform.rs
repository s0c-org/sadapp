use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

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
