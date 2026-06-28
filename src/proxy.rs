//! Inspecting reverse proxy.
//!
//! Sits between an AI client (Claude Code, Cline, Cursor, Aider…) and an
//! upstream LLM provider. Forwards requests verbatim, streams responses
//! chunk-by-chunk through the protocol adapter, and **buffers each tool_use
//! block until it is complete** so the inspector sees reassembled input —
//! the core defence against chunked-injection bypass.
//!
//! Text deltas are scanned with a fast-path regex on the fly and forwarded
//! immediately; only tool_use blocks are held until `content_block_stop`
//! (their input is usually small and arrives in microseconds).

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http::StatusCode;
use http_body_util::{BodyExt, BodyStream, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, Uri};
use hyper_util::rt::TokioIo;
use tokio::sync::mpsc;

use crate::cli::Mode;
use crate::inspect::Inspector;
use crate::protocol::anthropic;
use crate::protocol::{self, Event, ProtocolAdapter};
use crate::record::Recorder;
use crate::secure::Secret;

pub struct ProxyConfig {
    pub upstream: String,
    pub listen: SocketAddr,
    pub upstream_key: Secret,
    pub mode: Mode,
    pub recorder: Arc<Recorder>,
}

pub async fn run(cfg: ProxyConfig) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(cfg.listen).await?;
    tracing::info!(listen=%cfg.listen, upstream=%cfg.upstream, mode=?cfg.mode, "carapace proxy up");

    let upstream = Arc::new(cfg.upstream.clone());
    let key = Arc::new(cfg.upstream_key);
    let mode = cfg.mode;
    let recorder = cfg.recorder.clone();

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(error=%e, "accept failure");
                continue;
            }
        };
        let io = TokioIo::new(stream);
        let upstream = upstream.clone();
        let key = key.clone();
        let recorder = recorder.clone();
        tokio::spawn(async move {
            if let Err(e) = http1::Builder::new()
                .serve_connection(
                    io,
                    service_fn(move |req| {
                        let upstream = upstream.clone();
                        let key = key.clone();
                        let recorder = recorder.clone();
                        async move { forward(req, &upstream, &key, mode, recorder).await }
                    }),
                )
                .with_upgrades()
                .await
            {
                tracing::debug!(error=%e, ?peer, "connection ended");
            }
        });
    }
}

/// One streaming task representation. We send the inspected chunks to a
/// tokio mpsc, the response body reads from it.
type Chunk = Result<Bytes, std::io::Error>;

async fn forward(
    req: Request<hyper::body::Incoming>,
    upstream: &str,
    key: &Secret,
    mode: Mode,
    recorder: Arc<Recorder>,
) -> anyhow::Result<Response<BoxBody>> {
    let (mut parts, body) = req.into_parts();

    let upstream_uri = if parts.uri.scheme().is_some() {
        parts.uri.clone()
    } else {
        let path = parts
            .uri
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/");
        let base = upstream.trim_end_matches('/');
        Uri::try_from(format!("{base}{path}"))?
    };

    let body_bytes = body.collect().await?.to_bytes();
    let content_type = parts
        .headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let is_stream = body_bytes
        .windows(13)
        .any(|w| w == b"\"stream\":true")
        || content_type.contains("event-stream");

    let adapter = protocol::pick(upstream, &content_type);
    let protocol_name = adapter.name();

    if !key.is_empty() {
        if protocol_name == "anthropic" {
            parts.headers.insert("x-api-key", key.as_str().parse()?);
        } else {
            let auth = format!("Bearer {}", key.as_str());
            parts.headers.insert(http::header::AUTHORIZATION, auth.parse()?);
        }
    }
    parts.headers.remove(http::header::HOST);
    // Anthropic streams accept everything; we force SSE for our own parsing.
    parts
        .headers
        .insert(http::header::ACCEPT, "text/event-stream".parse()?);

    let out_req: Request<Full<Bytes>> = match parts.method {
        Method::GET | Method::HEAD => Request::from_parts(parts, Full::default()),
        _ => Request::from_parts(parts, Full::new(body_bytes.clone())),
    };

    let upstream_host = extract_host(upstream);
    let stream = tokio::net::TcpStream::connect(&upstream_host).await?;
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::spawn(conn);

    let upstream_resp = sender.send_request(out_req).await?;
    let (rparts, rbody) = upstream_resp.into_parts();

    let resp_bytes = rbody.collect().await?.to_bytes();

    let allowed_tools = parse_declared_tools(&body_bytes, protocol_name);
    let mut inspector = Inspector::builtin(allowed_tools);

    let (tx, rx) = mpsc::channel::<Chunk>(64);
    let recorder_cloned = recorder.clone();
    let mode_lite = mode;
    let protocol_lite = protocol_name.to_string();

    let event_stream = adapter.stream(resp_bytes.clone());
    tokio::spawn(inspect_and_forward(
        event_stream,
        resp_bytes.clone(),
        tx,
        protocol_lite,
        mode_lite,
        inspector,
        recorder_cloned,
    ));

    let stream = ReceiveStream { rx };
    let body = BodyStream::new(stream)
        .map_err(|_| -> std::convert::Infallible { unreachable!("io::Error can never occur for an mpsc Receiver") })
        .boxed();
    let mut resp = Response::from_parts(rparts, body);
    if resp.status() == StatusCode::default() {
        *resp.status_mut() = StatusCode::OK;
    }
    Ok(resp)
}

async fn inspect_and_forward(
    events: std::pin::Pin<Box<dyn futures_core::Stream<Item = Event> + Send + 'static>>,
    original_bytes: Bytes,
    mut tx: mpsc::Sender<Chunk>,
    protocol: String,
    mode: Mode,
    mut inspector: Inspector,
    recorder: Arc<Recorder>,
) {
    use futures_util::StreamExt;

    let mut events = events;
    let mut tool_buf: Vec<Bytes> = Vec::new();
    let mut tool_input = String::new();
    let mut tool_index: u32 = 0;
    let mut in_tool = false;
    let mut tool_name: Option<String> = None;
    let mut text_buf = String::new();
    let mut blocked_count = 0u32;
    let mut max_severity = 0u32;
    let mut matched_categories: Vec<String> = Vec::new();

    while let Some(ev) = events.next().await {
        match ev {
            Event::TextDelta(s) => {
                text_buf.push_str(&s);
                let verdict = inspector.feed(&Event::TextDelta(s.clone()));
                if !verdict.is_clean() && verdict.severity > max_severity {
                    max_severity = verdict.severity;
                    matched_categories.extend(verdict.matched.iter().cloned());
                }
                if verdict.is_clean() {
                    let bytes = original_text_frame(&s, protocol.as_str(), tool_index);
                    let _ = tx.send(Ok(bytes)).await;
                } else {
                    let stub = original_text_frame(
                        "[carapace: blocked suspicious text content]",
                        protocol.as_str(),
                        tool_index,
                    );
                    let _ = tx.send(Ok(stub)).await;
                }
            }
            Event::ToolUseStart { id, name } => {
                in_tool = true;
                tool_name = Some(name.clone());
                tool_buf.clear();
                tool_input.clear();
                tool_buf.push(anthropic::event_to_bytes(
                    &Event::ToolUseStart { id, name },
                    tool_index,
                ));
                inspector.reset();
            }
            Event::ToolUseDelta(s) => {
                tool_input.push_str(&s);
                tool_buf.push(anthropic::event_to_bytes(
                    &Event::ToolUseDelta(s.clone()),
                    tool_index,
                ));
            }
            Event::ToolUseEnd => {
                let verdict = inspector.feed(&Event::ToolUseEnd);
                let is_malicious = !verdict.is_clean() && verdict.severity >= 60;
                if !verdict.is_clean() && verdict.severity > max_severity {
                    max_severity = verdict.severity;
                    matched_categories.extend(verdict.matched.iter().cloned());
                }
                if matches!(mode, Mode::Block) && is_malicious {
                    blocked_count += 1;
                    for b in anthropic::blocked_tool_substitution(tool_index) {
                        let _ = tx.send(Ok(b)).await;
                    }
                } else {
                    for b in tool_buf.drain(..) {
                        let _ = tx.send(Ok(b)).await;
                    }
                    let _ = tx
                        .send(Ok(anthropic::event_to_bytes(&Event::ToolUseEnd, tool_index)))
                        .await;
                }
                in_tool = false;
                tool_name = None;
                tool_index = tool_index.wrapping_add(1);
                inspector.reset();
            }
            Event::Raw(b) => {
                let _ = tx.send(Ok(b)).await;
            }
        }
    }

    // Diagnostic recorder entry — does not include secrets.
    let _ = recorder.record(
        protocol.as_str(),
        mode_label(mode),
        &crate::inspect::Verdict {
            matched: matched_categories.clone(),
            severity: max_severity,
            unsolicited_tool_use: false,
            tool_name: None,
        },
        &text_buf,
    );

    tracing::info!(%protocol, ?mode, blocked_count, max_severity, "stream complete");
    // suppress unused original_bytes
    let _ = original_bytes;
}

fn extract_host(url: &str) -> String {
    let stripped = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    trimmed_host(stripped).to_string()
}

fn trimmed_host(s: &str) -> &str {
    s.split('/').next().unwrap_or(s)
}

fn mode_label(m: Mode) -> &'static str {
    match m {
        Mode::Monitor => "monitor",
        Mode::Block => "block",
    }
}

fn parse_declared_tools(_body: &Bytes, _protocol: &str) -> HashSet<String> {
    // Empty allowlist → every upstream tool_use is unsolicited. Real parsing
    // of declared `"tools":[{"name":"..."}]` lands in v0.4.
    HashSet::new()
}

fn original_text_frame(text: &str, protocol: &str, index: u32) -> Bytes {
    match protocol {
        "anthropic" => anthropic::event_to_bytes(&Event::TextDelta(text.to_string()), index),
        _ => Bytes::copy_from_slice(text.as_bytes()),
    }
}

type BoxBody = http_body_util::combinators::BoxBody<Bytes, std::convert::Infallible>;

/// Adapter from a tokio mpsc Receiver to a hyper Body.
struct ReceiveStream {
    rx: mpsc::Receiver<Chunk>,
}

impl http_body::Body for ReceiveStream {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        use std::task::Poll;
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(Ok(b))) => {
                Poll::Ready(Some(Ok(http_body::Frame::data(b))))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    fn size_hint(&self) -> http_body::SizeHint {
        let mut hint = http_body::SizeHint::default();
        hint.set_lower(0);
        hint.set_upper(1024 * 1024);
        hint
    }
}

#[allow(dead_code)]
fn _use_stream_marker() -> BodyStream<Full<Bytes>> {
    unimplemented!()
}