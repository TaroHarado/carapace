//! OpenAI Realtime API adapter — `/v1/realtime` WebSocket.
//!
//! The Realtime API exposes bi-directional WebSocket sessions for audio
//! agentic chat. Frames are JSON; the dangerous ones for us are:
//!
//!   - upstream → client: `response.function_call_output.done` /
//!     `response.function_call_arguments.delta` /
//!     `response.function_call_arguments.done` — these carry the
//!     tool_use payload analogous to `tool_calls[].function.arguments`
//!     in the SSE API. A malicious realtime provider could inject
//!     `function_call` chunks with shell commands in the arguments.
//!   - client → upstream: `conversation.item.create` with `item.type=`
//!     function_call_output — the client submitting results back. Less
//!     dangerous from the upstream-injection angle but still worth
//!     inspecting for sensitive-path content.
//!   - up → client: `response.audio.delta` frames carry base64-encoded
//!     audio — pass through unchanged.
//!
//! We extract `function_call` events into `ToolUseStart/Delta/End` so
//! they flow through `inspect::Inspector::feed` exactly the same as SSE
//! tool_use chunks. The 9-layer defense engine has no idea the payload
//! arrived over WebSocket instead of SSE — defense is wire-format
//! agnostic.

use crate::protocol::{Event, WsAdapter};

pub struct OpenAiRealtimeAdapter;

impl Default for OpenAiRealtimeAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl OpenAiRealtimeAdapter {
    pub fn new() -> Self {
        Self
    }
}

const NAME: &str = "openai-realtime";

/// True if the URL looks like the OpenAI Realtime endpoint.
pub fn matches(upstream_url: &str) -> Option<Box<dyn WsAdapter>> {
    if upstream_url.contains("openai.com") && upstream_url.contains("/v1/realtime")
        || upstream_url.contains("/realtime?model=")
    {
        Some(Box::new(OpenAiRealtimeAdapter::new()))
    } else {
        None
    }
}

impl WsAdapter for OpenAiRealtimeAdapter {
    fn name(&self) -> &'static str {
        NAME
    }

    fn matches(&self, upstream_url: &str) -> bool {
        upstream_url.contains("openai.com") && upstream_url.contains("/v1/realtime")
    }

    /// Client-to-upstream frames. We don't block client input here —
    /// focus on detecting if the client is sending sensitive paths back
    /// to the (possibly malicious) upstream.
    fn process_inbound_text(&self, text: &str) -> Vec<Event> {
        // Pass through as a WsText so the inspector sees it (potentially
        // detecting sensitive-path-in-outbound messages via the
        // egress layer). Adapters that want deeper detection can pull
        // out payloads like conversation.item.create with function_call_output.
        vec![Event::WsText { text: text.to_string(), from_upstream: false }]
    }

    /// Upstream-to-client frames. This is the danger direction — the
    /// malicious-realtime-provider injection path.
    ///
    /// We surface OpenAI Realtime `response.function_call_arguments.delta`
    /// frames as `Event::ToolUseDelta` so the inspector can match our
    /// existing rules (`curl|sh`, `cat ~/.ssh/id_rsa`, etc.) against
    /// the function-call arguments exactly as if it had arrived over
    /// SSE.
    fn process_outbound_text(&self, text: &str) -> Vec<Event> {
        let mut events = Vec::new();
        // Try to parse the JSON frame.
        let v: serde_json::Value = match serde_json::from_str(text) {
            Ok(v) => v,
            Err(_) => {
                // Not JSON — pass through unfiltered.
                events.push(Event::WsText {
                    text: text.to_string(),
                    from_upstream: true,
                });
                return events;
            }
        };
        let t = v.get("type").and_then(|x| x.as_str()).unwrap_or("");
        match t {
            // function call arguments deltas → ToolUseDelta
            "response.function_call_arguments.delta" => {
                if let Some(delta) = v.get("delta").and_then(|x| x.as_str()) {
                    events.push(Event::ToolUseDelta(delta.to_string()));
                }
            }
            // function call start
            "response.output_item.added" => {
                if let Some(item) = v.get("item").and_then(|x| x.as_object()) {
                    let kind = item.get("type").and_then(|x| x.as_str()).unwrap_or("");
                    if kind == "function_call" {
                        let id = item
                            .get("call_id")
                            .and_then(|x| x.as_str())
                            .unwrap_or("realtime_call")
                            .to_string();
                        let name = item
                            .get("name")
                            .and_then(|x| x.as_str())
                            .unwrap_or("unknown")
                            .to_string();
                        events.push(Event::ToolUseStart { id, name });
                    }
                }
            }
            // function call arguments done — emit ToolUseEnd
            "response.output_item.done" => {
                if let Some(item) = v.get("item").and_then(|x| x.as_object()) {
                    let kind = item.get("type").and_then(|x| x.as_str()).unwrap_or("");
                    if kind == "function_call" {
                        events.push(Event::ToolUseEnd);
                    }
                }
            }
            // function call done after all args
            "response.function_call_arguments.done" => {
                events.push(Event::ToolUseEnd);
            }
            _ => {
                // Pass through as a normal WsText frame.
                events.push(Event::WsText {
                    text: text.to_string(),
                    from_upstream: true,
                });
            }
        }
        events
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn matches_openai_realtime_url() {
        assert!(matches("wss://api.openai.com/v1/realtime?model=gpt-4o-realtime").is_some());
        assert!(matches("https://api.openai.com/v1/messages").is_none());
        assert!(matches("https://deepseek.com/v1/chat/completions").is_none());
    }

    #[test]
    fn outbound_function_args_delta_emits_tooluse_delta() {
        let adapter = OpenAiRealtimeAdapter::new();
        let frame = r#"{"type":"response.function_call_arguments.delta","delta":"curl "}"#;
        let events = adapter.process_outbound_text(frame);
        assert!(matches!(events.last(), Some(Event::ToolUseDelta(d)) if d == "curl "));
    }

    #[test]
    fn outbound_output_item_added_function_call_emits_tooluse_start() {
        let adapter = OpenAiRealtimeAdapter::new();
        let frame = r#"{"type":"response.output_item.added","item":{"type":"function_call","call_id":"call_abc","name":"Bash"}}"#;
        let events = adapter.process_outbound_text(frame);
        assert!(events.iter().any(|e| matches!(e, Event::ToolUseStart { name, .. } if name == "Bash")));
    }

    #[test]
    fn outbound_output_item_done_fires_tooluse_end() {
        let adapter = OpenAiRealtimeAdapter::new();
        let frame = r#"{"type":"response.output_item.done","item":{"type":"function_call","call_id":"call_abc"}}"#;
        let events = adapter.process_outbound_text(frame);
        assert!(events.iter().any(|e| matches!(e, Event::ToolUseEnd)));
    }

    #[test]
    fn outbound_audio_delta_passes_through_unfiltered() {
        let adapter = OpenAiRealtimeAdapter::new();
        let frame = r#"{"type":"response.audio.delta","delta":"//uQZAAAA..."#;
        let events = adapter.process_outbound_text(frame);
        assert!(matches!(events.first(), Some(Event::WsText { from_upstream: true, .. })));
    }

    #[test]
    fn inbound_text_is_pass_through_with_direction_flag() {
        let adapter = OpenAiRealtimeAdapter::new();
        let frame = r#"{"type":"input_audio_buffer.append","audio":"//uQxAAAA"}"#;
        let events = adapter.process_inbound_text(frame);
        assert!(matches!(events.first(), Some(Event::WsText { from_upstream: false, .. })));
    }

    #[test]
    fn invalid_json_outbound_passes_through_unfiltered() {
        let adapter = OpenAiRealtimeAdapter::new();
        let frame = "not even json";
        let events = adapter.process_outbound_text(frame);
        assert!(matches!(events.first(), Some(Event::WsText { from_upstream: true, .. })));
    }

    #[test]
    fn binary_frame_default_passthrough_with_direction() {
        let adapter = OpenAiRealtimeAdapter::new();
        let data = Bytes::from_static(b"\x12\x34");
        let events = adapter.process_outbound_binary(data.clone());
        assert!(matches!(events.first(), Some(Event::WsBinary { data: d, from_upstream: true }) if d == &data));
    }
}