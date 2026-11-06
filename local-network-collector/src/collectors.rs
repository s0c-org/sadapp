use std::collections::{HashMap, HashSet};

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
    pub value: Value,
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
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let (series, fields) = split_prometheus_sample(line)?;
        let (name, labels) = parse_series(series)?;
        let mapping = configured.iter().find(|mapping| mapping.source == name);
        let preset = node_exporter.then(|| node_mapping(name)).flatten();
        if mapping.is_none() && preset.is_none() {
            continue;
        }
        if !allowed.is_empty() && mapping.is_none() && !node_exporter {
            continue;
        }
        let mut fields = fields.split_whitespace();
        let value = fields
            .next()
            .ok_or_else(|| anyhow::anyhow!("missing Prometheus value"))?
            .parse::<f64>()?;
        if let Some(timestamp) = fields.next() {
            timestamp.parse::<i64>()?;
        }
        if fields.next().is_some() {
            bail!("invalid Prometheus sample fields");
        }
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
            value: Value::from(value),
            labels,
        });
        if samples.len() > MAX_SAMPLES {
            bail!("Prometheus sample limit exceeded");
        }
    }
    if node_exporter {
        derive_node_used_bytes(&mut samples)?;
    }
    Ok(samples)
}

fn split_prometheus_sample(line: &str) -> Result<(&str, &str)> {
    let mut quoted = false;
    let mut escaped = false;
    let mut labels = false;
    for (index, ch) in line.char_indices() {
        if escaped {
            escaped = false;
        } else if quoted && ch == '\\' {
            escaped = true;
        } else if ch == '"' {
            quoted = !quoted;
        } else if !quoted && ch == '{' {
            labels = true;
        } else if !quoted && ch == '}' {
            labels = false;
        } else if !quoted && !labels && ch.is_ascii_whitespace() {
            return Ok((&line[..index], &line[index..]));
        }
    }
    bail!("invalid Prometheus sample")
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
    let mut inner = series[open + 1..series.len() - 1].trim();
    let mut labels = Map::new();
    while !inner.is_empty() {
        let (key, rest) = inner
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("invalid Prometheus label"))?;
        let key = key.trim();
        if labels.len() >= MAX_LABELS || !valid_name(key) || labels.contains_key(key) {
            bail!("invalid or excessive Prometheus labels");
        }
        let rest = rest
            .trim_start()
            .strip_prefix('"')
            .ok_or_else(|| anyhow::anyhow!("invalid Prometheus label value"))?;
        let mut value = String::new();
        let mut chars = rest.char_indices();
        let end = loop {
            match chars.next() {
                Some((index, '"')) => break index + 1,
                Some((_, '\\')) => match chars.next() {
                    Some((_, '\\')) => value.push('\\'),
                    Some((_, '"')) => value.push('"'),
                    Some((_, 'n')) => value.push('\n'),
                    _ => bail!("invalid Prometheus label escape"),
                },
                Some((_, ch)) => value.push(ch),
                None => bail!("unterminated Prometheus label value"),
            }
            if value.len() > 200 {
                bail!("Prometheus label value exceeds limit");
            }
        };
        labels.insert(key.into(), Value::String(value));
        inner = rest[end..].trim_start();
        if !inner.is_empty() {
            inner = inner
                .strip_prefix(',')
                .ok_or_else(|| anyhow::anyhow!("invalid Prometheus label separator"))?
                .trim_start();
        }
    }
    Ok((name, labels))
}

fn derive_node_used_bytes(samples: &mut Vec<MetricSample>) -> Result<()> {
    let values = samples
        .iter()
        .map(|sample| {
            Ok((
                (
                    sample.metric_key.as_str(),
                    serde_json::to_string(&sample.labels)?,
                ),
                sample,
            ))
        })
        .collect::<Result<HashMap<_, _>>>()?;
    let mut derived = Vec::new();
    for (total_key, available_key, used_key) in [
        (
            "system.memory.total_bytes",
            "system.memory.available_bytes",
            "system.memory.used_bytes",
        ),
        (
            "filesystem.total_bytes",
            "filesystem.available_bytes",
            "filesystem.used_bytes",
        ),
    ] {
        for sample in samples
            .iter()
            .filter(|sample| sample.metric_key == total_key)
        {
            let labels = serde_json::to_string(&sample.labels)?;
            if values.contains_key(&(used_key, labels.clone())) {
                continue;
            }
            let Some(available) = values.get(&(available_key, labels)) else {
                continue;
            };
            if let (Some(total), Some(available)) =
                (sample.value.as_f64(), available.value.as_f64())
            {
                if total > 0.0 && (0.0..=total).contains(&available) {
                    derived.push(MetricSample {
                        metric_key: used_key.into(),
                        unit: Some("bytes".into()),
                        value_type: "GAUGE".into(),
                        value: Value::from(total - available),
                        labels: sample.labels.clone(),
                    });
                }
            }
        }
    }
    if samples.len() + derived.len() > MAX_SAMPLES {
        bail!("Prometheus sample limit exceeded");
    }
    samples.extend(derived);
    Ok(())
}

fn node_mapping(name: &str) -> Option<(String, Option<String>, String)> {
    let (key, unit, kind) = match name {
        "node_memory_MemTotal_bytes" => ("system.memory.total_bytes", Some("bytes"), "GAUGE"),
        "node_memory_MemAvailable_bytes" => {
            ("system.memory.available_bytes", Some("bytes"), "GAUGE")
        }
        "node_load1" => ("system.load.1m", Some("count"), "GAUGE"),
        "node_load5" => ("system.load.5m", Some("count"), "GAUGE"),
        "node_load15" => ("system.load.15m", Some("count"), "GAUGE"),
        "node_filesystem_size_bytes" => ("filesystem.total_bytes", Some("bytes"), "GAUGE"),
        "node_filesystem_avail_bytes" => ("filesystem.available_bytes", Some("bytes"), "GAUGE"),
        "node_network_receive_bytes_total" => {
            ("network.receive.bytes_total", Some("bytes"), "COUNTER")
        }
        "node_network_transmit_bytes_total" => {
            ("network.transmit.bytes_total", Some("bytes"), "COUNTER")
        }
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
                    .or_else(|| {
                        value.as_array().and_then(|array| {
                            part.parse::<usize>()
                                .ok()
                                .and_then(|index| array.get(index))
                        })
                    })
                    .ok_or_else(|| anyhow::anyhow!("REST mapping path not found"))
            })?;
            let metric_key = required_text(object, "metricKey")?;
            if !valid_key(metric_key) {
                bail!("invalid REST metric key");
            }
            let (mapped_value, value_type, unit) = match value {
                Value::Number(number) => {
                    let number = number
                        .as_f64()
                        .filter(|number| number.is_finite())
                        .ok_or_else(|| anyhow::anyhow!("REST mapped number is not finite"))?;
                    (
                        Value::from(number),
                        object.get("valueType").and_then(Value::as_str).unwrap_or("GAUGE"),
                        object.get("unit").and_then(Value::as_str).map(str::to_owned),
                    )
                }
                Value::Bool(_) => (value.clone(), "BOOLEAN", None),
                Value::String(text) if text.len() <= 4_000 => (value.clone(), "TEXT", None),
                _ => bail!("REST mapped value must be a finite number, boolean, or string of at most 4000 bytes"),
            };
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
                unit,
                value_type: value_type.into(),
                value: mapped_value,
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
        assert_eq!(node[0].metric_key, "system.memory.available_bytes");
    }

    #[test]
    fn parses_timestamped_samples_without_using_the_timestamp_as_the_value() {
        let mappings = [json!({"metricName":"temperature","metricKey":"temperature"})];
        let samples = parse_prometheus(
            b"  # comment\n\n temperature 37.5 1710000000000 \n\
              temperature{room=\"rack a\"}\t-2.5e1\t-123\n\
              temperature 0\n",
            &mappings,
            false,
        )
        .unwrap();
        assert_eq!(
            samples
                .iter()
                .map(|sample| sample.value.clone())
                .collect::<Vec<_>>(),
            vec![json!(37.5), json!(-25.0), json!(0.0)]
        );
        assert_eq!(samples[1].labels["room"], "rack a");
        for line in ["temperature", "temperature 1 bad", "temperature 1 1 2"] {
            assert!(parse_prometheus(line.as_bytes(), &mappings, false).is_err());
        }
    }

    #[test]
    fn parses_quoted_commas_and_prometheus_label_escapes() {
        let samples = parse_prometheus(
            br#"temperature{ location = "rack,a", path="C:\\rack", message="say \"hi\"\nnext", empty="", } 42 123
"#,
            &[json!({"metricName":"temperature","metricKey":"temperature"})], false,
        ).unwrap();
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0].labels["location"], "rack,a");
        assert_eq!(samples[0].labels["path"], r"C:\rack");
        assert_eq!(samples[0].labels["message"], "say \"hi\"\nnext");
        assert_eq!(samples[0].labels["empty"], "");
        for labels in [
            r#"a="unterminated"#,
            r#"a="bad\t""#,
            r#"a="1" b="2""#,
            r#"a="1",a="2""#,
            r#"a="1",,b="2""#,
        ] {
            assert!(
                parse_prometheus(
                    format!("temperature{{{labels}}} 42").as_bytes(),
                    &[json!({"metricName":"temperature","metricKey":"temperature"})],
                    false,
                )
                .is_err(),
                "{labels}"
            );
        }
    }

    #[test]
    fn node_preset_emits_canonical_metrics_and_coherent_used_bytes() {
        let samples = parse_prometheus(
            b"node_memory_MemTotal_bytes 1000\nnode_memory_MemAvailable_bytes 250\n\
              node_load1 1\nnode_load5 2\nnode_load15 3\n\
              node_filesystem_size_bytes{device=\"/dev/a\",mountpoint=\"/\"} 2000\n\
              node_filesystem_avail_bytes{mountpoint=\"/\",device=\"/dev/a\"} 500\n\
              node_filesystem_size_bytes{device=\"/dev/b\"} 3000\n\
              node_network_receive_bytes_total{device=\"eth0\"} 123\n\
              node_network_transmit_bytes_total{device=\"eth0\"} 456\n",
            &[],
            true,
        )
        .unwrap();
        for (key, value, unit, kind) in [
            ("system.memory.total_bytes", 1000.0, "bytes", "GAUGE"),
            ("system.memory.available_bytes", 250.0, "bytes", "GAUGE"),
            ("system.memory.used_bytes", 750.0, "bytes", "GAUGE"),
            ("system.load.1m", 1.0, "count", "GAUGE"),
            ("system.load.5m", 2.0, "count", "GAUGE"),
            ("system.load.15m", 3.0, "count", "GAUGE"),
            ("filesystem.used_bytes", 1500.0, "bytes", "GAUGE"),
            ("network.receive.bytes_total", 123.0, "bytes", "COUNTER"),
            ("network.transmit.bytes_total", 456.0, "bytes", "COUNTER"),
        ] {
            let matching = samples
                .iter()
                .filter(|sample| sample.metric_key == key)
                .collect::<Vec<_>>();
            assert_eq!(matching.len(), 1, "{key}");
            assert_eq!(matching[0].value, json!(value));
            assert_eq!(matching[0].unit.as_deref(), Some(unit));
            assert_eq!(matching[0].value_type, kind);
        }
        let used = samples
            .iter()
            .find(|sample| sample.metric_key == "filesystem.used_bytes")
            .unwrap();
        assert_eq!(used.labels["device"], "/dev/a");
        for available in ["1001", "-1", "NaN"] {
            let samples = parse_prometheus(
                format!(
                    "node_memory_MemTotal_bytes 1000\nnode_memory_MemAvailable_bytes {available}\n"
                )
                .as_bytes(),
                &[],
                true,
            )
            .unwrap();
            assert!(!samples
                .iter()
                .any(|sample| sample.metric_key == "system.memory.used_bytes"));
        }
        let overridden = parse_prometheus(
            b"node_memory_MemTotal_bytes 1000\nnode_memory_MemAvailable_bytes 250\n",
            &[json!({"metricName":"node_memory_MemTotal_bytes","metricKey":"custom.total"})],
            true,
        )
        .unwrap();
        assert!(overridden
            .iter()
            .any(|sample| sample.metric_key == "custom.total"));
        assert!(!overridden
            .iter()
            .any(|sample| sample.metric_key == "system.memory.used_bytes"));
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
        for (length, accepted) in [(200, true), (201, false)] {
            let body = format!("metric{{label=\"{}\"}} 1", "\\n".repeat(length));
            let result = parse_prometheus(
                body.as_bytes(),
                &[json!({"metricName":"metric","metricKey":"metric"})],
                false,
            );
            assert_eq!(result.is_ok(), accepted);
        }
        for (padding, accepted) in [(MAX_SAMPLES - 3, true), (MAX_SAMPLES - 2, false)] {
            let body = format!(
                "{}node_memory_MemTotal_bytes 1000\nnode_memory_MemAvailable_bytes 250\n",
                "metric 1\n".repeat(padding),
            );
            let result = parse_prometheus(
                body.as_bytes(),
                &[json!({"metricName":"metric","metricKey":"metric"})],
                true,
            );
            assert_eq!(result.is_ok(), accepted);
            if let Ok(samples) = result {
                assert_eq!(samples.len(), MAX_SAMPLES);
            }
        }
    }

    #[test]
    fn preserves_numeric_rest_counter_mappings() {
        let samples = map_rest_json(
            br#"{"requests":42}"#,
            &[json!({"path":"requests","metricKey":"requests","valueType":"COUNTER","unit":"requests"})],
        )
        .unwrap();
        assert_eq!(samples[0].value, json!(42.0));
        assert_eq!(samples[0].value_type, "COUNTER");
        assert_eq!(samples[0].unit.as_deref(), Some("requests"));
    }

    #[test]
    fn maps_bounded_numeric_boolean_and_string_rest_paths() {
        let samples = map_rest_json(
            br#"{"system":{"temperature":37.5,"online":true,"state":"ok"}}"#,
            &[
                json!({"path":"system.temperature","metricKey":"temperature","unit":"celsius"}),
                json!({"path":"system.online","metricKey":"online","unit":"ignored"}),
                json!({"path":"system.state","metricKey":"state"}),
            ],
        )
        .unwrap();
        assert_eq!(samples[0].value, json!(37.5));
        assert_eq!(samples[0].value_type, "GAUGE");
        assert_eq!(samples[0].unit.as_deref(), Some("celsius"));
        assert_eq!(samples[1].value, json!(true));
        assert_eq!(samples[1].value_type, "BOOLEAN");
        assert_eq!(samples[1].unit, None);
        assert_eq!(samples[2].value, json!("ok"));
        assert_eq!(samples[2].value_type, "TEXT");
        assert!(map_rest_json(
            br#"{"system":{"state":null}}"#,
            &[json!({"path":"system.state","metricKey":"state"})]
        )
        .is_err());
        assert!(map_rest_json(
            format!(r#"{{"state":"{}"}}"#, "x".repeat(4_001)).as_bytes(),
            &[json!({"path":"state","metricKey":"state"})]
        )
        .is_err());
    }

    #[test]
    fn maps_rest_values_from_multiple_fields_and_array_paths() {
        let samples = map_rest_json(
            br#"{"system":{"heapUsed":12},"sensors":[{"temperature":22.5}]}"#,
            &[
                json!({ "path": "system.heapUsed", "metricKey": "heap.used" }),
                json!({ "path": "sensors.0.temperature", "metricKey": "temperature" }),
            ],
        )
        .unwrap();
        assert_eq!(
            samples
                .iter()
                .map(|sample| sample.value.as_f64().unwrap())
                .collect::<Vec<_>>(),
            vec![12.0, 22.5]
        );
    }
}
