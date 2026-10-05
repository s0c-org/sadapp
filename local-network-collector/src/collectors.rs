use std::collections::HashSet;

use anyhow::{bail, Result};
use serde_json::{Map, Value};

pub const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_SAMPLES: usize = 10_000;
pub const MAX_LABELS: usize = 16;
pub const MAX_MAPPINGS: usize = 256;

#[derive(Debug, Clone, PartialEq)]
pub struct MetricSample {
    pub metric_key: String,
    pub unit: Option<String>,
    pub value_type: String,
    pub value: f64,
    pub labels: Map<String, Value>,
}

pub fn parse_prometheus(
    body: &[u8],
    mappings: &[Value],
    node_exporter: bool,
) -> Result<Vec<MetricSample>> {
    if body.len() > MAX_RESPONSE_BYTES {
        bail!("Prometheus response exceeds byte limit");
    }
    if mappings.len() > MAX_MAPPINGS {
        bail!("Prometheus mappings exceed limit");
    }
    let text = std::str::from_utf8(body)?;
    let configured = mappings
        .iter()
        .map(parse_prom_mapping)
        .collect::<Result<Vec<_>>>()?;
    let allowed = configured
        .iter()
        .map(|mapping| mapping.source.as_str())
        .collect::<HashSet<_>>();
    let mut samples = Vec::new();
    for line in text
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let (series, raw_value) = line
            .rsplit_once(char::is_whitespace)
            .ok_or_else(|| anyhow::anyhow!("invalid Prometheus sample"))?;
        let (name, labels) = parse_series(series)?;
        let mapping = configured.iter().find(|mapping| mapping.source == name);
        let preset = node_exporter.then(|| node_mapping(name)).flatten();
        if mapping.is_none() && preset.is_none() {
            continue;
        }
        if !allowed.is_empty() && mapping.is_none() && !node_exporter {
            continue;
        }
        let value = raw_value.trim().parse::<f64>()?;
        if !value.is_finite() {
            continue;
        }
        let (metric_key, unit, value_type) = mapping
            .map(|mapping| {
                (
                    mapping.metric_key.clone(),
                    mapping.unit.clone(),
                    mapping.value_type.clone(),
                )
            })
            .unwrap_or_else(|| preset.unwrap());
        samples.push(MetricSample {
            metric_key,
            unit,
            value_type,
            value,
            labels,
        });
        if samples.len() > MAX_SAMPLES {
            bail!("Prometheus sample limit exceeded");
        }
    }
    Ok(samples)
}

struct PromMapping {
    source: String,
    metric_key: String,
    unit: Option<String>,
    value_type: String,
}

fn parse_prom_mapping(value: &Value) -> Result<PromMapping> {
    let object = value
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("mapping must be an object"))?;
    let source = required_text(object, "metricName")?;
    let metric_key = required_text(object, "metricKey")?;
    let value_type = object
        .get("valueType")
        .and_then(Value::as_str)
        .unwrap_or("GAUGE");
    if !valid_name(source) || !valid_key(metric_key) || !matches!(value_type, "GAUGE" | "COUNTER") {
        bail!("invalid Prometheus mapping");
    }
    Ok(PromMapping {
        source: source.into(),
        metric_key: metric_key.into(),
        unit: object
            .get("unit")
            .and_then(Value::as_str)
            .map(str::to_owned),
        value_type: value_type.into(),
    })
}

fn parse_series(series: &str) -> Result<(&str, Map<String, Value>)> {
    let Some(open) = series.find('{') else {
        return Ok((series, Map::new()));
    };
    if !series.ends_with('}') {
        bail!("invalid Prometheus labels");
    }
    let name = &series[..open];
    let inner = &series[open + 1..series.len() - 1];
    let mut labels = Map::new();
    if !inner.is_empty() {
        for item in inner.split(',') {
            let (key, value) = item
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("invalid Prometheus label"))?;
            if labels.len() >= MAX_LABELS || !valid_name(key) {
                bail!("Prometheus labels exceed bounds");
            }
            let value = value
                .strip_prefix('"')
                .and_then(|value| value.strip_suffix('"'))
                .ok_or_else(|| anyhow::anyhow!("invalid Prometheus label value"))?;
            if value.len() > 200 {
                bail!("Prometheus label value exceeds limit");
            }
            labels.insert(key.into(), Value::String(value.replace("\\\"", "\"")));
        }
    }
    Ok((name, labels))
}

fn node_mapping(name: &str) -> Option<(String, Option<String>, String)> {
    let (key, unit, kind) = match name {
        "node_memory_MemTotal_bytes" => ("memory.total", Some("bytes"), "GAUGE"),
        "node_memory_MemAvailable_bytes" => ("memory.available", Some("bytes"), "GAUGE"),
        "node_load1" => ("load.1m", None, "GAUGE"),
        "node_load5" => ("load.5m", None, "GAUGE"),
        "node_load15" => ("load.15m", None, "GAUGE"),
        "node_filesystem_size_bytes" => ("filesystem.size", Some("bytes"), "GAUGE"),
        "node_filesystem_avail_bytes" => ("filesystem.available", Some("bytes"), "GAUGE"),
        "node_network_receive_bytes_total" => ("network.receive.bytes", Some("bytes"), "COUNTER"),
        "node_network_transmit_bytes_total" => ("network.transmit.bytes", Some("bytes"), "COUNTER"),
        _ => return None,
    };
    Some((key.into(), unit.map(str::to_owned), kind.into()))
}

pub fn map_rest_json(body: &[u8], mappings: &[Value]) -> Result<Vec<MetricSample>> {
    if body.len() > MAX_RESPONSE_BYTES {
        bail!("REST response exceeds byte limit");
    }
    if mappings.is_empty() || mappings.len() > MAX_MAPPINGS {
        bail!("REST mappings are outside bounds");
    }
    let document: Value = serde_json::from_slice(body)?;
    mappings
        .iter()
        .map(|mapping| {
            let object = mapping
                .as_object()
                .ok_or_else(|| anyhow::anyhow!("mapping must be an object"))?;
            let path = required_text(object, "path")?;
            if path.len() > 256
                || path
                    .split('.')
                    .any(|part| part.is_empty() || !valid_name(part))
            {
                bail!("invalid REST mapping path");
            }
            let value = path.split('.').try_fold(&document, |value, part| {
                value
                    .get(part)
                    .ok_or_else(|| anyhow::anyhow!("REST mapping path not found"))
            })?;
            let number = value
                .as_f64()
                .ok_or_else(|| anyhow::anyhow!("REST mapped value is not numeric"))?;
            let metric_key = required_text(object, "metricKey")?;
            if !number.is_finite() || !valid_key(metric_key) {
                bail!("invalid REST mapped value");
            }
            let labels = object
                .get("labels")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            if labels.len() > MAX_LABELS
                || labels
                    .values()
                    .any(|value| value.as_str().is_none_or(|value| value.len() > 200))
            {
                bail!("REST labels exceed bounds");
            }
            Ok(MetricSample {
                metric_key: metric_key.into(),
                unit: object
                    .get("unit")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                value_type: object
                    .get("valueType")
                    .and_then(Value::as_str)
                    .unwrap_or("GAUGE")
                    .into(),
                value: number,
                labels,
            })
        })
        .collect()
}

fn required_text<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a str> {
    object
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 200)
        .ok_or_else(|| anyhow::anyhow!("{key} is required"))
}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b':' | b'-'))
}
fn valid_key(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (index > 0 && matches!(byte, b'.' | b'_' | b'-'))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_allowlisted_prometheus_and_node_exporter_metrics() {
        let mapped = parse_prometheus(
            b"custom_temp{room=\"rack\"} 42\nignored 1\n",
            &[json!({"metricName":"custom_temp","metricKey":"temperature","unit":"celsius"})],
            false,
        )
        .unwrap();
        assert_eq!(mapped.len(), 1);
        assert_eq!(mapped[0].labels["room"], "rack");
        let node = parse_prometheus(
            b"node_memory_MemAvailable_bytes 1024\nnode_cpu_seconds_total 8\n",
            &[],
            true,
        )
        .unwrap();
        assert_eq!(node.len(), 1);
        assert_eq!(node[0].metric_key, "memory.available");
    }

    #[test]
    fn enforces_prometheus_sample_and_label_bounds() {
        let body = "metric 1\n".repeat(MAX_SAMPLES + 1);
        assert!(parse_prometheus(
            body.as_bytes(),
            &[json!({"metricName":"metric","metricKey":"metric"})],
            false
        )
        .is_err());
        let labels = (0..=MAX_LABELS)
            .map(|index| format!("l{index}=\"x\""))
            .collect::<Vec<_>>()
            .join(",");
        assert!(parse_prometheus(
            format!("metric{{{labels}}} 1").as_bytes(),
            &[json!({"metricName":"metric","metricKey":"metric"})],
            false
        )
        .is_err());
    }

    #[test]
    fn maps_only_bounded_numeric_rest_paths() {
        let samples = map_rest_json(
            br#"{"system":{"temperature":37.5}}"#,
            &[json!({"path":"system.temperature","metricKey":"temperature","unit":"celsius"})],
        )
        .unwrap();
        assert_eq!(samples[0].value, 37.5);
        assert!(map_rest_json(
            br#"{"system":{"state":"ok"}}"#,
            &[json!({"path":"system.state","metricKey":"state"})]
        )
        .is_err());
    }
}
