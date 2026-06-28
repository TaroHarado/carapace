//! Protocol adapters — normalise provider-specific wire formats.
//!
//! holone's first architectural mistake was hardcoding Anthropic/OpenAI in
//! the proxy. We isolate the *protocol* from the *inspection*: each upstream
//! dialect implements [`ProtocolAdapter`], the inspector works on a single
//! [`Event`] enum, the proxy decides what to forward.
//!
//! MVP ships Anthropic + OpenAI + Passthrough. Future adapters (z.ai paas/v4,
//! DeepSeek) drop into this trait without touching the inspector.

use bytes::Bytes;
use futures_core::Stream;

pub mod anthropic;
pub mod openai;
pub mod passthrough;

pub use anthropic::AnthropicAdapter;
pub use openai::OpenAiAdapter;
pub use passthrough::PassthroughAdapter;

/// Normalised stream event produced by a protocol adapter.
///
/// Not serialised — `Raw` carries opaque bytes that we forward untouched.
#[derive(Debug, Clone)]
pub enum Event {
    /// A chunk of assistant text content.
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
}

/// Per-upstream dialect.
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

/// Pick adapter by upstream URL / content-type.
///
/// z.ai (GLM) and DeepSeek both expose OpenAI-compatible `/v1/chat/completions`
/// endpoints with `choices[].delta.tool_calls[].function.arguments` chunks —
/// identical to OpenAI. We route them through the OpenAI adapter but tag the
/// protocol name for logs/alerts so users can see which upstream was hit.
pub fn pick(upstream: &str, content_type: &str) -> Box<dyn ProtocolAdapter> {
    if upstream.contains("anthropic.com") || content_type.contains("anthropic") {
        Box::new(AnthropicAdapter)
    } else if upstream.contains("api.z.ai") || upstream.contains("z.ai") {
        Box::new(OpenAiAdapter) // protocol_name is "openai"; future ZaiAdapter adds reasoning_effort
    } else if upstream.contains("deepseek.com") || upstream.contains("api.deepseek") {
        Box::new(OpenAiAdapter)
    } else if upstream.contains("openai.com")
        || upstream.contains("/v1/")
        || content_type.contains("openai")
    {
        Box::new(OpenAiAdapter)
    } else {
        Box::new(PassthroughAdapter)
    }
}