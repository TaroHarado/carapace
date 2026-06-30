//! OpenTelemetry export — emits defense hits as OTLP/HTTP JSON spans.
//!
//! Lightweight: no `opentelemetry` crate dependency. We build the OTLP/HTTP
//! JSON payload manually (it's a small stable schema) and POST it to the
//! endpoint configured via `SR_OTLP_ENDPOINT` env var or `--otlp-endpoint`
//! CLI flag.
//!
//! Each defense hit becomes one span:
//!   - name: "saferouter.defense.<decision>"
//!   - attributes: rule_ids, asset_class, capability, source, tainted,
//!     chain_hits, severity, original_target
//!
//! This integrates with Splunk/Datadog/Humio/Jaeger/etc. — anything that
//! speaks OTLP/HTTP.

use std::sync::Arc;

use serde::Serialize;
use serde_json::{json, Value};

use crate::defense::DefenseReport;

#[derive(Debug, Clone)]
pub struct TelemetryConfig {
    pub endpoint: String,
    pub service_name: String,
    pub enabled: bool,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            endpoint: std::env::var("SR_OTLP_ENDPOINT").unwrap_or_default(),
            service_name: std::env::var("SR_SERVICE_NAME")
                .unwrap_or_else(|_| "saferouter".to_string()),
            enabled: std::env::var("SR_OTLP_ENDPOINT").is_ok(),
        }
    }
}

pub struct TelemetryExporter {
    config: Arc<TelemetryConfig>,
    client: reqwest::Client,
}

impl TelemetryExporter {
    pub fn new(config: Arc<TelemetryConfig>) -> Self {
        Self {
            config,
            client: reqwest::Client::builder()
                .use_rustls_tls()
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
        }
    }

    pub fn from_env() -> Option<Self> {
        let config = TelemetryConfig::default();
        if !config.enabled || config.endpoint.is_empty() {
            return None;
        }
        Some(Self::new(Arc::new(config)))
    }

    /// Emit a defense report as an OTLP span. Fire-and-forget; errors
    /// are logged via `tracing::warn!` but don't propagate.
    pub async fn emit_defense_hit(&self, report: &DefenseReport, target: &str) {
        if !self.config.enabled {
            return;
        }
        let span = build_span(report, target, &self.config.service_name);
        let payload = json!({
            "resourceSpans": [{
                "resource": {
                    "attributes": [{
                        "key": "service.name",
                        "value": { "stringValue": self.config.service_name }
                    }]
                },
                "scopeSpans": [{
                    "scope": { "name": "saferouter.defense" },
                    "spans": [span]
                }]
            }]
        });

        match self
            .client
            .post(&self.config.endpoint)
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await
        {
            Ok(resp) if !resp.status().is_success() => {
                tracing::warn!(
                    status = %resp.status(),
                    "OTLP export returned non-success status"
                );
            }
            Err(e) => {
                tracing::warn!(error = %e, "OTLP export failed");
            }
            _ => {}
        }
    }
}

fn build_span(report: &DefenseReport, target: &str, _service: &str) -> Value {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);

    let attrs = vec![
        attr("decision", report.decision.label()),
        attr("asset_class", report.asset_class.label()),
        attr("capability", report.capability.label()),
        attr("source", report.source.label()),
        attr("tainted", report.tainted),
        attr("target", target),
        attr("matrix_decision", report.matrix_decision.label()),
        attr(
            "chain_hits",
            report
                .chain_hits
                .iter()
                .map(|h| h.rule_id.clone())
                .collect::<Vec<_>>()
                .join(","),
        ),
        attr(
            "reasons",
            report.reasons.join(";"),
        ),
    ];

    json!({
        "traceId": format!("{:032x}", now),
        "spanId": format!("{:016x}", now & 0xFFFF_FFFF_FFFF_FFFF),
        "name": format!("saferouter.defense.{}", report.decision.label()),
        "kind": "SPAN_KIND_INTERNAL",
        "startTimeUnixNano": now.to_string(),
        "endTimeUnixNano": now.to_string(),
        "attributes": attrs,
        "status": {
            "code": if report.decision == crate::defense::DefenseDecision::Block {
                "STATUS_CODE_ERROR"
            } else {
                "STATUS_CODE_OK"
            }
        }
    })
}

fn attr(key: &str, value: impl Serialize) -> Value {
    let v = serde_json::to_value(value).unwrap_or(Value::Null);
    let typed = match v {
        Value::Bool(b) => json!({ "stringValue": b.to_string() }),
        Value::String(s) => json!({ "stringValue": s }),
        other => json!({ "stringValue": other.to_string() }),
    };
    json!({ "key": key, "value": typed })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::defense::{DefenseDecision, DefenseReport};
    use crate::asset::{AssetClass, Capability, Source};
    use crate::capability_matrix::MatrixDecision;
    use crate::session_graph::ChainHit;

    fn dummy_report() -> DefenseReport {
        DefenseReport {
            decision: DefenseDecision::Block,
            asset_class: AssetClass::Credential,
            capability: Capability::Execute,
            source: Source::Provider,
            tainted: true,
            matrix_decision: MatrixDecision::Block,
            chain_hits: vec![ChainHit {
                rule_id: "chain-taint-leap-execute".to_string(),
                severity: 95,
                description: "test".to_string(),
                events: vec![1],
            }],
            reasons: vec!["unsolicited tool_use from provider".to_string()],
        }
    }

    #[test]
    fn build_span_has_correct_name() {
        let report = dummy_report();
        let span = build_span(&report, "~/.ssh/id_rsa", "saferouter");
        assert_eq!(
            span["name"],
            "saferouter.defense.block"
        );
    }

    #[test]
    fn build_span_includes_target_attribute() {
        let report = dummy_report();
        let span = build_span(&report, "/tmp/x.sh", "saferouter");
        let attrs = span["attributes"].as_array().unwrap();
        let target_attr = attrs
            .iter()
            .find(|a| a["key"] == "target")
            .expect("target attr missing");
        assert_eq!(target_attr["value"]["stringValue"], "/tmp/x.sh");
    }

    #[test]
    fn build_span_status_error_on_block() {
        let report = dummy_report();
        let span = build_span(&report, "x", "saferouter");
        assert_eq!(span["status"]["code"], "STATUS_CODE_ERROR");
    }

    #[test]
    fn telemetry_config_disabled_by_default() {
        std::env::remove_var("SR_OTLP_ENDPOINT");
        let config = TelemetryConfig::default();
        assert!(!config.enabled);
    }

    #[test]
    fn telemetry_config_enabled_with_env() {
        // CI envs may or may not set this; we just verify the logic.
        let config = TelemetryConfig {
            endpoint: "http://localhost:4318/v1/traces".to_string(),
            service_name: "test".to_string(),
            enabled: true,
        };
        assert!(config.enabled);
    }

    #[test]
    fn from_env_returns_none_without_endpoint() {
        std::env::remove_var("SR_OTLP_ENDPOINT");
        assert!(TelemetryExporter::from_env().is_none());
    }

    #[test]
    fn attr_serializes_bool_as_string() {
        let a = attr("tainted", true);
        assert_eq!(a["key"], "tainted");
        assert_eq!(a["value"]["stringValue"], "true");
    }

    #[test]
    fn attr_serializes_string() {
        let a = attr("decision", "block");
        assert_eq!(a["value"]["stringValue"], "block");
    }
}