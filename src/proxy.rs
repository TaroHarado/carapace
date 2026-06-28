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
use http_body_util::{BodyExt, BodyStream};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, Uri};
use hyper_util::rt::TokioIo;
use tokio::sync::mpsc;

use crate::cli::Mode;
use crate::inspect::{Inspector, Rules};
use crate::judge::{self, JudgeConfig};
use crate::protocol::anthropic;
use crate::protocol::{self, Event};
use crate::record::{EncryptedForensics, Recorder};
use crate::secure::Secret;

pub struct ProxyConfig {
    pub upstream: String,
    pub listen: SocketAddr,
    pub upstream_key: Secret,
    pub mode: Mode,
    pub recorder: Arc<Recorder>,
    pub forensics: Option<Arc<EncryptedForensics>>,
    pub rules: Arc<Rules>,
    pub judge: Option<Arc<JudgeConfig>>,
}

pub async fn run(cfg: ProxyConfig) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(cfg.listen).await?;
    tracing::info!(listen=%cfg.listen, upstream=%cfg.upstream, mode=?cfg.mode, "carapace proxy up");

    let upstream = Arc::new(cfg.upstream.clone());
    let key = Arc::new(cfg.upstream_key);
    let mode = cfg.mode;
    let recorder = cfg.recorder.clone();
    let forensics = cfg.forensics.clone();
    let rules = cfg.rules.clone();
    let judge = cfg.judge.clone();

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(error=%e, "accept failure");
                continue;
            }
        };
        let io = TokioIo::new(stream);
        let fwd = Arc::new(ForwardCtx {
            upstream: upstream.clone(),
            key: key.clone(),
            mode,
            recorder: recorder.clone(),
            forensics: forensics.clone(),
            rules: rules.clone(),
            judge: judge.clone(),
        });
        tokio::spawn(async move {
            if let Err(e) = http1::Builder::new()
                .serve_connection(
                    io,
                    service_fn(move |req| {
                        let fwd = fwd.clone();
                        async move { forward(req, fwd).await }
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

struct ForwardCtx {
    upstream: Arc<String>,
    key: Arc<Secret>,
    mode: Mode,
    recorder: Arc<Recorder>,
    forensics: Option<Arc<EncryptedForensics>>,
    rules: Arc<Rules>,
    judge: Option<Arc<JudgeConfig>>,
}

async fn forward(
    req: Request<hyper::body::Incoming>,
    fwd: Arc<ForwardCtx>,
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
        let base = fwd.upstream.trim_end_matches('/');
        Uri::try_from(format!("{base}{path}"))?
    };

    let body_bytes = body.collect().await?.to_bytes();
    let content_type = parts
        .headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let _is_stream = body_bytes
        .windows(13)
        .any(|w| w == b"\"stream\":true")
        || content_type.contains("event-stream");

    let adapter = protocol::pick(&fwd.upstream, &content_type);
    let protocol_name = adapter.name();

    if !fwd.key.is_empty() {
        if protocol_name == "anthropic" {
            parts.headers.insert("x-api-key", fwd.key.as_str().parse()?);
        } else {
            let auth = format!("Bearer {}", fwd.key.as_str());
            parts.headers.insert(http::header::AUTHORIZATION, auth.parse()?);
        }
    }
    parts.headers.remove(http::header::HOST);
    // Anthropic streams accept everything; we force SSE for our own parsing.
    parts
        .headers
        .insert(http::header::ACCEPT, "text/event-stream".parse()?);

    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .build()?;
    let method = reqwest::Method::from_bytes(parts.method.as_str().as_bytes())?;
    let mut rb = client.request(method, upstream_uri.to_string());
    for (name, value) in &parts.headers {
        rb = rb.header(name, value);
    }
    if !matches!(parts.method, Method::GET | Method::HEAD) {
        rb = rb.body(body_bytes.clone().to_vec());
    }

    let upstream_resp = rb.send().await?;
    let status = upstream_resp.status();
    let headers = upstream_resp.headers().clone();
    let resp_bytes = upstream_resp.bytes().await?;

    let allowed_tools = parse_declared_tools(&body_bytes, protocol_name);
    let inspector = Inspector::from_rules(&fwd.rules, allowed_tools);

    let (tx, rx) = mpsc::channel::<Chunk>(64);
    let recorder_cloned = fwd.recorder.clone();
    let mode_lite = fwd.mode;
    let protocol_lite = protocol_name.to_string();

    let event_stream = adapter.stream(resp_bytes.clone());
    let ctx = InspectCtx {
        protocol: protocol_lite,
        mode: mode_lite,
        inspector,
        recorder: recorder_cloned,
        forensics: fwd.forensics.clone(),
        judge: fwd.judge.clone(),
    };
    tokio::spawn(inspect_and_forward(event_stream, tx, ctx));

    let stream = ReceiveStream { rx };
    let body = BodyStream::new(stream)
        .map_err(|_| -> std::convert::Infallible { unreachable!("io::Error can never occur for an mpsc Receiver") })
        .boxed();
    let mut resp = Response::builder().status(status.as_u16());
    for (name, value) in &headers {
        resp = resp.header(name, value);
    }
    let resp = resp.body(body).expect("valid proxy response");
    Ok(resp)
}

struct InspectCtx {
    protocol: String,
    mode: Mode,
    inspector: Inspector,
    recorder: Arc<Recorder>,
    forensics: Option<Arc<EncryptedForensics>>,
    judge: Option<Arc<JudgeConfig>>,
}

async fn inspect_and_forward(
    events: std::pin::Pin<Box<dyn futures_core::Stream<Item = Event> + Send + 'static>>,
    tx: mpsc::Sender<Chunk>,
    mut ctx: InspectCtx,
) {
    use futures_util::StreamExt;

    let mut events = events;
    let tx = tx;
    let mut tool_buf: Vec<Bytes> = Vec::new();
    let mut tool_input = String::new();
    let mut tool_index: u32 = 0;
    let mut text_buf = String::new();
    let mut blocked_count = 0u32;
    let mut max_severity = 0u32;
    let mut matched_categories: Vec<String> = Vec::new();

    while let Some(ev) = events.next().await {
        match ev {
            Event::TextDelta(s) => {
                text_buf.push_str(&s);
                let verdict = ctx.inspector.feed(&Event::TextDelta(s.clone()));
                let mut escalated = false;
                let mut effective_severity = verdict.severity;
                if !verdict.is_clean() && (30..60).contains(&verdict.severity) {
                    if let Some(cfg) = &ctx.judge {
                        if let Ok(jv) = judge::judge(&s, cfg).await {
                            if jv.is_malicious() {
                                escalated = true;
                                effective_severity = 85;
                            }
                        }
                    }
                }
                if (!verdict.is_clean() || escalated) && effective_severity > max_severity {
                    max_severity = effective_severity;
                    matched_categories.extend(verdict.matched.iter().cloned());
                    if escalated {
                        matched_categories.push("llm-judge-escalated".to_string());
                    }
                }
                if verdict.is_clean() && !escalated {
                    let bytes = text_frame(&s, ctx.protocol.as_str(), tool_index);
                    let _ = tx.send(Ok(bytes)).await;
                } else {
                    if let Some(store) = &ctx.forensics {
                        let _ = store.record("blocked-text", s.as_bytes());
                    }
                    let stub = text_frame(
                        "[carapace: blocked suspicious text content]",
                        ctx.protocol.as_str(),
                        tool_index,
                    );
                    let _ = tx.send(Ok(stub)).await;
                }
            }
            Event::ToolUseStart { id, name } => {
                tool_buf.clear();
                tool_input.clear();
                tool_buf.push(tool_start_frame(&Event::ToolUseStart { id, name }, ctx.protocol.as_str(), tool_index));
                ctx.inspector.reset();
            }
            Event::ToolUseDelta(s) => {
                tool_input.push_str(&s);
                tool_buf.push(tool_delta_frame(&Event::ToolUseDelta(s.clone()), ctx.protocol.as_str(), tool_index));
            }
            Event::ToolUseEnd => {
                let verdict = ctx.inspector.feed(&Event::ToolUseEnd);
                let mut effective_severity = verdict.severity;
                let mut judge_escalated = false;
                if !verdict.is_clean() && (30..60).contains(&verdict.severity) {
                    if let Some(cfg) = &ctx.judge {
                        if let Ok(jv) = judge::judge(&tool_input, cfg).await {
                            if jv.is_malicious() {
                                effective_severity = 85;
                                judge_escalated = true;
                            }
                        }
                    }
                }
                let is_malicious = !verdict.is_clean() && effective_severity >= 60;
                if !verdict.is_clean() && effective_severity > max_severity {
                    max_severity = effective_severity;
                    matched_categories.extend(verdict.matched.iter().cloned());
                    if judge_escalated {
                        matched_categories.push("llm-judge-escalated".to_string());
                    }
                }
                if matches!(ctx.mode, Mode::Block) && is_malicious {
                    blocked_count += 1;
                    if let Some(store) = &ctx.forensics {
                        let _ = store.record("blocked-tool-use", tool_input.as_bytes());
                    }
                    for b in blocked_tool_substitution(ctx.protocol.as_str(), tool_index) {
                        let _ = tx.send(Ok(b)).await;
                    }
                } else {
                    for b in tool_buf.drain(..) {
                        let _ = tx.send(Ok(b)).await;
                    }
                    let _ = tx.send(Ok(tool_end_frame(ctx.protocol.as_str(), tool_index))).await;
                }
                tool_index = tool_index.wrapping_add(1);
                ctx.inspector.reset();
            }
            Event::Raw(b) => {
                let _ = tx.send(Ok(b)).await;
            }
        }
    }

    // Diagnostic recorder entry — does not include secrets.
    let _ = ctx.recorder.record(
        ctx.protocol.as_str(),
        mode_label(ctx.mode),
        &crate::inspect::Verdict {
            matched: matched_categories.clone(),
            severity: max_severity,
            unsolicited_tool_use: false,
            tool_name: None,
        },
        &text_buf,
    );

    tracing::info!(protocol=%ctx.protocol, ?ctx.mode, blocked_count, max_severity, "stream complete");
}

fn mode_label(m: Mode) -> &'static str {
    match m {
        Mode::Monitor => "monitor",
        Mode::Block => "block",
    }
}

fn parse_declared_tools(body: &Bytes, protocol: &str) -> HashSet<String> {
    crate::tools::parse_request_tools(body, protocol)
}

fn text_frame(text: &str, protocol: &str, index: u32) -> Bytes {
    match protocol {
        "anthropic" => anthropic::event_to_bytes(&Event::TextDelta(text.to_string()), index),
        _ => crate::protocol::openai::event_to_bytes(&Event::TextDelta(text.to_string()), index),
    }
}

fn tool_start_frame(ev: &Event, protocol: &str, index: u32) -> Bytes {
    match protocol {
        "anthropic" => anthropic::event_to_bytes(ev, index),
        _ => crate::protocol::openai::event_to_bytes(ev, index),
    }
}

fn tool_delta_frame(ev: &Event, protocol: &str, index: u32) -> Bytes {
    match protocol {
        "anthropic" => anthropic::event_to_bytes(ev, index),
        _ => crate::protocol::openai::event_to_bytes(ev, index),
    }
}

fn tool_end_frame(protocol: &str, index: u32) -> Bytes {
    match protocol {
        "anthropic" => anthropic::event_to_bytes(&Event::ToolUseEnd, index),
        _ => crate::protocol::openai::event_to_bytes(&Event::ToolUseEnd, index),
    }
}

fn blocked_tool_substitution(protocol: &str, index: u32) -> Vec<Bytes> {
    match protocol {
        "anthropic" => anthropic::blocked_tool_substitution(index),
        _ => crate::protocol::openai::blocked_tool_substitution(index),
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
