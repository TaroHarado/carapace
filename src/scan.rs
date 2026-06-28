//! `cape scan` — canary probe against an upstream provider.
//!
//! Goal: answer a simple question before the user routes real work through a
//! grey provider: "does this endpoint inject tool_use / known-bad payloads on
//! a harmless, tool-less prompt?"
//!
//! `scan` is intentionally conservative:
//! - it sends a prompt that does **not** require tools;
//! - it requests streaming so we exercise the same SSE path real clients use;
//! - any unsolicited tool_use is high severity by definition;
//! - clean results are *not* a proof of safety (passive prompt theft exists).

use anyhow::{anyhow, Context};
use bytes::Bytes;
use serde::Serialize;

use crate::inspect::Inspector;
use crate::secure::Secret;

#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    pub upstream: String,
    pub protocol: String,
    pub risk_score: u32,
    pub verdict: RiskLevel,
    pub categories: Vec<String>,
    pub unsolicited_tool_uses: u32,
    pub bytes_received: usize,
    pub note: String,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub enum RiskLevel {
    Clean,
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    pub fn from_score(score: u32) -> Self {
        match score {
            0 => Self::Clean,
            1..=29 => Self::Low,
            30..=59 => Self::Medium,
            60..=84 => Self::High,
            _ => Self::Critical,
        }
    }
}

pub async fn run(upstream: &str, key: Option<Secret>) -> anyhow::Result<ScanReport> {
    let protocol = detect_protocol(upstream);
    let endpoint = endpoint_for(upstream, protocol)?;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .context("build scan client")?;

    let request = match protocol {
        Protocol::Anthropic => anthropic_canary_request(&endpoint, key.as_ref()),
        Protocol::OpenAiLike => openai_canary_request(&endpoint, key.as_ref()),
    }?;

    let resp = request.send().await.context("send canary probe")?;
    let status = resp.status();
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let body = resp.bytes().await.context("read canary body")?;

    if !status.is_success() {
        return Ok(ScanReport {
            upstream: upstream.to_string(),
            protocol: protocol.label().to_string(),
            risk_score: 50,
            verdict: RiskLevel::Medium,
            categories: vec![format!("http-status:{}", status.as_u16())],
            unsolicited_tool_uses: 0,
            bytes_received: body.len(),
            note: "Probe failed — non-2xx response. This is not a clean verdict.".to_string(),
        });
    }

    let adapter = pick_adapter_for_scan(upstream, &content_type, &body);
    let mut events = adapter.stream(body.clone());
    let mut inspector = Inspector::builtin(std::collections::HashSet::new());
    let mut matched = Vec::new();
    let mut max_score = 0u32;
    let mut unsolicited = 0u32;

    use futures_util::StreamExt;
    while let Some(ev) = events.next().await {
        let v = inspector.feed(&ev);
        if v.unsolicited_tool_use {
            unsolicited += 1;
            max_score = max_score.max(85);
            matched.push("proto-tooluse-unsolicited".to_string());
        }
        if !v.is_clean() {
            max_score = max_score.max(v.severity);
            matched.extend(v.matched.iter().cloned());
        }
    }

    matched.sort();
    matched.dedup();

    Ok(ScanReport {
        upstream: upstream.to_string(),
        protocol: adapter.name().to_string(),
        risk_score: max_score,
        verdict: RiskLevel::from_score(max_score),
        categories: matched,
        unsolicited_tool_uses: unsolicited,
        bytes_received: body.len(),
        note: "Clean means no active injection was observed on this probe. It does NOT rule out passive prompt theft or future behaviour changes.".to_string(),
    })
}

fn pick_adapter_for_scan(
    upstream: &str,
    content_type: &str,
    body: &Bytes,
) -> Box<dyn crate::protocol::ProtocolAdapter> {
    if let Ok(text) = std::str::from_utf8(body) {
        if text.contains("content_block_delta") || text.contains("content_block_start") {
            return Box::new(crate::protocol::anthropic::AnthropicAdapter);
        }
        if text.contains("\"choices\"") || text.contains("[DONE]") {
            return Box::new(crate::protocol::openai::OpenAiAdapter);
        }
    }
    crate::protocol::pick(upstream, content_type)
}

#[derive(Debug, Clone, Copy)]
enum Protocol {
    Anthropic,
    OpenAiLike,
}

impl Protocol {
    fn label(self) -> &'static str {
        match self {
            Self::Anthropic => "anthropic",
            Self::OpenAiLike => "openai-like",
        }
    }
}

fn detect_protocol(upstream: &str) -> Protocol {
    if upstream.contains("anthropic") || upstream.contains("/v1/messages") {
        Protocol::Anthropic
    } else {
        Protocol::OpenAiLike
    }
}

fn endpoint_for(upstream: &str, protocol: Protocol) -> anyhow::Result<String> {
    let base = upstream.trim_end_matches('/');
    let endpoint = match protocol {
        Protocol::Anthropic => {
            if base.ends_with("/v1/messages") {
                base.to_string()
            } else {
                format!("{base}/v1/messages")
            }
        }
        Protocol::OpenAiLike => {
            if base.ends_with("/v1/chat/completions") {
                base.to_string()
            } else {
                format!("{base}/v1/chat/completions")
            }
        }
    };
    if endpoint.starts_with("http://") || endpoint.starts_with("https://") {
        Ok(endpoint)
    } else {
        Err(anyhow!("invalid upstream endpoint: {endpoint}"))
    }
}

fn anthropic_canary_request(
    endpoint: &str,
    key: Option<&Secret>,
) -> anyhow::Result<reqwest::RequestBuilder> {
    let client = reqwest::Client::new();
    let mut rb = client
        .post(endpoint)
        .header("anthropic-version", "2023-06-01")
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .json(&serde_json::json!({
            "model": "claude-3-5-sonnet",
            "max_tokens": 128,
            "stream": true,
            "messages": [
                {"role": "user", "content": "Reply with the word PONG. Do not call any tools."}
            ]
        }));
    if let Some(k) = key {
        rb = rb.header("x-api-key", k.as_str());
    }
    Ok(rb)
}

fn openai_canary_request(
    endpoint: &str,
    key: Option<&Secret>,
) -> anyhow::Result<reqwest::RequestBuilder> {
    let client = reqwest::Client::new();
    let mut rb = client
        .post(endpoint)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .json(&serde_json::json!({
            "model": "gpt-4.1-mini",
            "stream": true,
            "messages": [
                {"role": "user", "content": "Reply with the word PONG. Do not call any tools."}
            ]
        }));
    if let Some(k) = key {
        rb = rb.bearer_auth(k.as_str());
    }
    Ok(rb)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mockevil;
    use bytes::Bytes;
    use http_body_util::BodyExt;
    use http_body_util::Full;
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper::{Request, Response, StatusCode};
    use hyper_util::rt::TokioIo;
    use tokio::net::TcpListener;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn scan_mockevil_is_high_risk() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        drop(l);
        let handle = tokio::spawn(mockevil::serve(format!("127.0.0.1:{port}").parse().unwrap()));
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;

        let report = run(&format!("http://127.0.0.1:{port}"), None).await.unwrap();
        assert!(matches!(report.verdict, RiskLevel::High | RiskLevel::Critical));
        assert!(report.risk_score >= 85);
        assert!(report.categories.iter().any(|c| c.contains("proto-tooluse-unsolicited") || c.contains("dl-curl-pipe-sh")));

        handle.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn scan_clean_upstream_is_clean() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let handle = tokio::spawn(async move {
            let listener = TcpListener::bind(format!("127.0.0.1:{port}")).await.unwrap();
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let io = TokioIo::new(stream);
                tokio::spawn(async move {
                    let _ = http1::Builder::new()
                        .serve_connection(
                            io,
                            service_fn(|_req: Request<hyper::body::Incoming>| async move {
                                let frame = "event: content_block_start\n\
data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n\
event: content_block_delta\n\
data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"PONG\"}}\n\n\
event: content_block_stop\n\
data: {\"type\":\"content_block_stop\",\"index\":0}\n\n\
event: message_stop\n\
data: {\"type\":\"message_stop\"}\n\n";
                                Ok::<_, std::io::Error>(
                                    Response::builder()
                                        .status(StatusCode::OK)
                                        .header("content-type", "text/event-stream")
                                        .body(Full::new(Bytes::from(frame)))
                                        .unwrap(),
                                )
                            }),
                        )
                        .await;
                });
            }
        });

        tokio::time::sleep(std::time::Duration::from_millis(80)).await;
        let report = run(&format!("http://127.0.0.1:{port}"), None).await.unwrap();
        assert!(matches!(report.verdict, RiskLevel::Clean));
        assert_eq!(report.risk_score, 0);

        handle.abort();
    }
}
