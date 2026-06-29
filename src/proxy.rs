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
use crate::defense::{DefenseDecision, DefenseEngine, ToolUseObservation};
use crate::inspect::{Inspector, Rules};
use crate::judge::{self, JudgeConfig};
use crate::protocol::anthropic;
use crate::protocol::{self, Event};
use crate::quarantine::QuarantineStore;
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
    /// SafeRouter defense engine (provenance + matrix + session graph).
    /// None = degraded mode (regex-only, like pre-v2).
    pub defense: Option<Arc<DefenseEngine>>,
    /// Quarantine pipeline for downloads. None = no quarantine.
    pub quarantine: Option<Arc<QuarantineStore>>,
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
    let defense = cfg.defense.clone().unwrap_or_else(|| Arc::new(DefenseEngine::with_default_provenance()));
    let quarantine = cfg.quarantine.clone();

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
            defense: defense.clone(),
            quarantine: quarantine.clone(),
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
    defense: Arc<DefenseEngine>,
    quarantine: Option<Arc<QuarantineStore>>,
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
    let inspector = Inspector::from_rules(&fwd.rules, allowed_tools.clone());

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
        defense: fwd.defense.clone(),
        quarantine: fwd.quarantine.clone(),
        allowed_tools: allowed_tools.clone(),
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
    defense: Arc<DefenseEngine>,
    quarantine: Option<Arc<QuarantineStore>>,
    allowed_tools: HashSet<String>,
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
    let mut tool_name: String = String::new();
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
                tool_name = name.clone();
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

                // ----- SafeRouter defense engine evaluation -------------------
                //
                // Layer 1+2+3 merge: build an observation from the reassembled
                // tool_use, run it through the defense engine (provenance +
                // matrix + session graph), and merge the result with the
                // regex-based inspector verdict.
                let unsolicited = !ctx.allowed_tools.contains(&tool_name);
                let primary_target = extract_primary_target(&tool_name, &tool_input);
                let obs = ToolUseObservation {
                    tool_name: tool_name.clone(),
                    input: tool_input.clone(),
                    unsolicited,
                    primary_target: primary_target.clone(),
                };
                let defense_report = ctx.defense.evaluate(&obs);

                // If defense says Quarantine and we have a quarantine store,
                // divert the write payload there instead of forwarding.
                let mut quarantined = false;
                if matches!(ctx.mode, Mode::Block)
                    && defense_report.decision == DefenseDecision::Quarantine
                {
                    if let Some(store) = &ctx.quarantine {
                        match store.intake(&primary_target, tool_input.as_bytes()) {
                            Ok(entry) => {
                                quarantined = true;
                                tracing::warn!(
                                    rule = "quarantine",
                                    sha256 = %entry.sha256,
                                    original = %entry.original_path,
                                    stored = %entry.stored_path.display(),
                                    "artifact quarantined; tool_use substituted"
                                );
                                matched_categories.push(format!(
                                    "quarantine:{}", entry.sha256
                                ));
                                if effective_severity < 70 {
                                    effective_severity = 70;
                                }
                            }
                            Err(e) => {
                                tracing::warn!(error=%e, "quarantine intake failed, falling back to block");
                            }
                        }
                    }
                }

                // If the target path is currently in quarantine, block the
                // execute outright — the file isn't where the agent thinks.
                let blocked_by_quarantine = matches!(ctx.mode, Mode::Block)
                    && matches!(defense_report.capability, crate::asset::Capability::Execute)
                    && ctx
                        .quarantine
                        .as_ref()
                        .map(|q| q.is_quarantined(&primary_target))
                        .unwrap_or(false);

                let defense_blocks = matches!(ctx.mode, Mode::Block)
                    && matches!(
                        defense_report.decision,
                        DefenseDecision::Block | DefenseDecision::Quarantine
                    );

                let is_malicious =
                    (!verdict.is_clean() && effective_severity >= 60)
                        || defense_blocks
                        || blocked_by_quarantine;

                if !verdict.is_clean() && effective_severity > max_severity {
                    max_severity = effective_severity;
                    matched_categories.extend(verdict.matched.iter().cloned());
                    if judge_escalated {
                        matched_categories.push("llm-judge-escalated".to_string());
                    }
                }
                if !defense_report.reasons.is_empty() {
                    for r in &defense_report.reasons {
                        matched_categories.push(format!("defense:{r}"));
                    }
                    if defense_report.decision as u32 >= DefenseDecision::Ask as u32 && max_severity < 70 {
                        max_severity = 70;
                    }
                }
                for hit in &defense_report.chain_hits {
                    matched_categories.push(format!("chain:{}", hit.rule_id));
                    if hit.severity > max_severity {
                        max_severity = hit.severity;
                    }
                }

                if matches!(ctx.mode, Mode::Block) && (is_malicious || quarantined || blocked_by_quarantine) {
                    blocked_count += 1;
                    if let Some(store) = &ctx.forensics {
                        let _ = store.record("blocked-tool-use", tool_input.as_bytes());
                    }
                    let stub_msg = if quarantined {
                        "[carapace: artifact quarantined — review at ~/.carapace/quarantine/]"
                    } else if blocked_by_quarantine {
                        "[carapace: target path is in quarantine — release it first]"
                    } else {
                        "[carapace: blocked tool_use with high-severity injection]"
                    };
                    for b in blocked_tool_substitution_with_msg(ctx.protocol.as_str(), tool_index, stub_msg) {
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
            tier: if max_severity > 0 {
                Some(crate::inspect::SeverityTier::from_severity(max_severity))
            } else {
                None
            },
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

/// Build a blocked-tool-use substitution with a custom stub message
/// (for quarantine / targeted-block reasons).
fn blocked_tool_substitution_with_msg(protocol: &str, index: u32, msg: &str) -> Vec<Bytes> {
    // For anthropic, we synthesize a text-only block replacement.
    // For openai, we use the existing stub but prepend the custom message.
    match protocol {
        "anthropic" => {
            // Build a text-delta + content_block_stop sequence with the
            // custom message as the text payload.
            let mut out = Vec::new();
            let start = format!(
                "event: content_block_start\ndata: {{\"type\":\"content_block_start\",\"index\":{index},\"content_block\":{{\"type\":\"text\",\"text\":\"\"}}}}\n\n"
            );
            let delta = format!(
                "event: content_block_delta\ndata: {{\"type\":\"content_block_delta\",\"index\":{index},\"delta\":{{\"type\":\"text_delta\",\"text\":{msg_json}}}}}\n\n",
                msg_json = serde_json::to_string(msg).unwrap_or_else(|_| "\"\"".into())
            );
            let stop = format!(
                "event: content_block_stop\ndata: {{\"type\":\"content_block_stop\",\"index\":{index}}}\n\n"
            );
            out.push(Bytes::from(start));
            out.push(Bytes::from(delta));
            out.push(Bytes::from(stop));
            out
        }
        _ => crate::protocol::openai::blocked_tool_substitution(index),
    }
}

/// Extract the primary target (path / URL / command first token) from a
/// reassembled tool_use input. Used for asset classification + provenance
/// keying without a full schema parser.
fn extract_primary_target(tool_name: &str, input: &str) -> String {
    let lower = tool_name.to_lowercase();
    let trimmed = input.trim();
    // For shell tools: take the first non-flag token.
    if matches!(lower.as_str(), "bash" | "shell" | "exec" | "execute" | "run" | "terminal") {
        // Look for the first URL or file path in the command.
        for token in trimmed.split_whitespace() {
            if token.starts_with("http://") || token.starts_with("https://") {
                return token.to_string();
            }
        }
        for token in trimmed.split_whitespace() {
            if token.starts_with('/') || token.starts_with("./") || token.starts_with("../")
                || token.starts_with('~') || token.contains("/tmp/")
                || token.contains("/var/tmp/")
            {
                return token.trim_matches(|c: char| !c.is_alphanumeric() && c != '/' && c != '.' && c != '~' && c != '-' && c != '_').to_string();
            }
        }
        return trimmed.split_whitespace().next().unwrap_or(trimmed).to_string();
    }
    // For read/write: input is often a JSON path string or a bare path.
    if matches!(lower.as_str(), "read" | "cat" | "view" | "head" | "tail" | "less" | "write" | "edit" | "create" | "patch" | "modify") {
        // Try JSON parse first: {"path": "..."} or {"file_path": "..."}.
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) {
            if let Some(p) = v.get("path").and_then(|x| x.as_str()) {
                return p.to_string();
            }
            if let Some(p) = v.get("file_path").and_then(|x| x.as_str()) {
                return p.to_string();
            }
            if let Some(p) = v.get("path").and_then(|x| x.as_str()) {
                return p.to_string();
            }
        }
        // Bare path string.
        return trimmed.split_whitespace().next().unwrap_or(trimmed).trim_matches(|c: char| c == '"' || c == '\'').to_string();
    }
    // For web tools: input is a URL.
    if matches!(lower.as_str(), "webfetch" | "fetch" | "curl" | "wget" | "http" | "websearch" | "search") {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) {
            if let Some(u) = v.get("url").and_then(|x| x.as_str()) {
                return u.to_string();
            }
        }
        return trimmed.split_whitespace().next().unwrap_or(trimmed).to_string();
    }
    // Fallback: first token.
    trimmed.split_whitespace().next().unwrap_or(trimmed).to_string()
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
