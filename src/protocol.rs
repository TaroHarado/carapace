//! Protocol adapters — normalise provider-specific wire formats.
//!
//! holone's first architectural mistake was hardcoding Anthropic/OpenAI in
//! the proxy. We isolate the *protocol* from the *inspection*: each upstream
//! dialect implements [`ProtocolAdapter`] (SSE/HTTP) or [`WsAdapter`]
//! (WebSocket bi-directional), the inspector works on a single [`Event`]
//! enum, the proxy decides what to forward.

use bytes::Bytes;
use futures_core::Stream;

pub mod anthropic;
pub mod openai;
pub mod passthrough;
pub mod ws;

pub use anthropic::AnthropicAdapter;
pub use openai::OpenAiAdapter;
pub use passthrough::PassthroughAdapter;

/// Normalised stream event produced by a protocol adapter.
///
/// Events are produced by both:
///   - SSE/HTTP adapters via `ProtocolAdapter::stream` ((provider→client only)
///   - WebSocket adapters via `WsAdapter::process_inbound` / `process_outbound`
///     (bi-directional).
///
/// The same `Event` enum is consumed by `inspect::Inspector::feed` on both
/// paths.
#[derive(Debug, Clone)]
pub enum Event {
    /// A chunk of assistant text content (downstream direction).
    TextDelta(String),
    /// Announce a tool_use block with the given id/name (no input yet).
    ToolUseStart { id: String, name: String },
    /// A chunk of the tool's JSON input. Reassembled by the inspector before
    /// scanning — see `anthropic.rs` for why this matters.
    ToolUseDelta(String),
    /// End of a tool_use block.
    ToolUseEnd,
    /// Raw passthrough chunk the adapter chose not to interpret.
    Raw(Bytes),
    /// A text WebSocket frame, with the direction flag:
    /// `from_upstream=true` means it was sent by the upstream LLM provider,
    /// `from_upstream=false` means the client sent it (e.g. an audio buffer
    /// commit, a session update, a tool result).
    WsText { text: String, from_upstream: bool },
    /// A binary WebSocket frame (e.g. raw audio bytes for realtime voice).
    WsBinary { data: Bytes, from_upstream: bool },
    /// Control frames from the WebSocket layer (ping/pong keep-alive).
    /// Forwarded to the peer; not inspected further.
    WsPing(Bytes),
    WsPong(Bytes),
    /// Client or upstream closed the WebSocket connection.
    WsClose,
}

impl Event {
    /// True if this event originated from the upstream LLM provider (the
    /// dangerous direction — attackers inject from here).
    pub fn from_upstream(&self) -> bool {
        match self {
            Self::TextDelta(_) | Self::ToolUseStart { .. } | Self::ToolUseDelta(_)
            | Self::ToolUseEnd | Self::Raw(_) => true,
            Self::WsText { from_upstream, .. }
            | Self::WsBinary { from_upstream, .. } => *from_upstream,
            Self::WsPing(_) | Self::WsPong(_) | Self::WsClose => false,
        }
    }
}

/// Per-upstream SSE/HTTP dialect.
pub trait ProtocolAdapter: Send + Sync {
    /// Identifier for logs (`anthropic`, `openai`, `zai`, …).
    fn name(&self) -> &'static str;

    /// Does this Content-Type look like ours?
    fn accepts(&self, content_type: &str) -> bool;

    /// Inspect (and possibly rewrite) a non-streaming response body.
    fn inspect_body(&self, body: Bytes) -> Bytes;

    /// Generator that turns a streaming `text/event-stream` into [`Event`]s.
    fn stream(
        &self,
        body: Bytes,
    ) -> std::pin::Pin<Box<dyn Stream<Item = Event> + Send + 'static>>;
}

/// Per-upstream WebSocket-protocol dialect. Realtime APIs (OpenAI
/// `/v1/realtime`, Twilio Voice, upcoming Anthropic streaming v2) speak
/// bi-directional JSON-over-WS frames. The adapter:
///   - parses inbound frames (from client) and outbound frames (from
///     upstream),
///   - emits [`Event`]s for frames that contain `tool_use` payloads,
///   - falls through to `WsText`/`WsBinary` for everything else so the
///     proxy inspects them兵团-for-bytes.
///
/// Critically, the same `inspect::Inspector::feed` is reused on the
/// WebSocket path. The 9-layer defense model doesn't care about the wire
/// format — it inspects the reassembled tool_use JSON, regardless of
/// whether it came over SSE on `/v1/messages` or WebSocket on
/// `/v1/realtime`.
pub trait WsAdapter: Send + Sync {
    /// Identifier for logs (`openai-realtime`, `twilio-voice`, …).
    fn name(&self) -> &'static str;

    /// Does this URL/host look like ours?
    fn matches(&self, upstream_url: &str) -> bool;

    /// Convert one inbound text frame (client → upstream) into [`Event`]s.
    /// Most frames are passed through as `WsText { from_upstream=false }`;
    /// adapters that recognise a `function_call_output` frame (the client
    /// sending back the result of a tool invocation) may emit Raw events
    /// for downstream taint tracking.
    fn process_inbound_text(&self, text: &str) -> Vec<Event>;

    /// Convert one inbound binary frame into [`Event`]s. Default: pass
    /// through. Adapters that interpret binary (audio bytes for realtime)
    /// may emit events with annotated direction.
    fn process_inbound_binary(&self, data: Bytes) -> Vec<Event> {
        vec![Event::WsBinary { data, from_upstream: false }]
    }

    /// Convert one outbound text frame (upstream → client) into [`Event`]s.
    /// This is where malicious-LLM injection arrives — a `response.create`
    /// frame may carry `function_call` chunks that we want to surface as
    /// `ToolUseStart/Delta/End` the same way SSE adapters do.
    fn process_outbound_text(&self, text: &str) -> Vec<Event>;

    /// Convert one outbound binary frame into [`Event`]s. Default: pass
    /// through.
    fn process_outbound_binary(&self, data: Bytes) -> Vec<Event> {
        vec![Event::WsBinary { data, from_upstream: true }]
    }
}

/// Pick a non-WebSocket adapter by upstream URL / content-type.
///
/// z.ai (GLM) and DeepSeek both expose OpenAI-compatible `/v1/chat/completions`
/// endpoints with `choices[].delta.tool_calls[].function.arguments` chunks —
/// identical to OpenAI. We route them through the OpenAI adapter but tag the
/// protocol name for logs/alerts so users can see which upstream was hit.
pub fn pick(upstream: &str, content_type: &str) -> Box<dyn ProtocolAdapter> {
    if upstream.contains("anthropic.com") || content_type.contains("anthropic") {
        Box::new(AnthropicAdapter)
    } else if upstream.contains("api.z.ai")
        || upstream.contains("z.ai")
        || upstream.contains("deepseek.com")
        || upstream.contains("api.deepseek")
        || upstream.contains("openai.com")
        || upstream.contains("/v1/")
        || content_type.contains("openai")
    {
        Box::new(OpenAiAdapter)
    } else {
        Box::new(PassthroughAdapter)
    }
}

/// Pick a WebSocket adapter by upstream URL.
///
/// Returns None if the URL isn't recognised as a WS-speaking upstream; in
/// that case the proxy falls back to a passthrough WS relay (no
/// `ToolUse` extraction, but the inspector still runs on each text frame
/// via `Event::WsText`).
pub fn pick_ws(upstream_url: &str) -> Option<Box<dyn WsAdapter>> {
    if let Some(a) = ws::openai_realtime::matches(upstream_url) {
        return Some(a);
    }
    if let Some(a) = ws::passthrough::matches(upstream_url) {
        return Some(a);
    }
    None
}
