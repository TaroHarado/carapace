//! Passthrough WebSocket adapter — every frame surfaces as WsText / WsBinary
//! with a direction flag. The inspector still runs on each text frame so
//! regex-based detection (`inspect.rs::Inspector::scan_buffer`) sees the
//! payload bytes, but we don't extract `ToolUse` structured events.
//!
//! Used when the upstream URL doesn't match any specific known WS adapter
//! (e.g. Twilio Voice Media Stream, future Anthropic realtime, custom
//! infra). Still better than no inspection — `curl|sh` in any WS frame
//! body still fires the regex rules.

use bytes::Bytes;

use crate::protocol::{Event, WsAdapter};

pub struct PassthroughWsAdapter;

impl Default for PassthroughWsAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl PassthroughWsAdapter {
    pub fn new() -> Self {
        Self
    }
}

const NAME: &str = "ws-passthrough";

/// Always matches — used as a last-resort adapter.
pub fn matches(_upstream_url: &str) -> Option<Box<dyn WsAdapter>> {
    Some(Box::new(PassthroughWsAdapter::new()))
}

impl WsAdapter for PassthroughWsAdapter {
    fn name(&self) -> &'static str {
        NAME
    }
    fn matches(&self, _upstream_url: &str) -> bool {
        true
    }
    fn process_inbound_text(&self, text: &str) -> Vec<Event> {
        vec![Event::WsText { text: text.to_string(), from_upstream: false }]
    }
    fn process_outbound_text(&self, text: &str) -> Vec<Event> {
        vec![Event::WsText { text: text.to_string(), from_upstream: true }]
    }
    fn process_inbound_binary(&self, data: Bytes) -> Vec<Event> {
        vec![Event::WsBinary { data, from_upstream: false }]
    }
    fn process_outbound_binary(&self, data: Bytes) -> Vec<Event> {
        vec![Event::WsBinary { data, from_upstream: true }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_any_url() {
        assert!(matches("wss://anything").is_some());
        assert!(matches("https://api.openai.com/v1/realtime").is_some());
    }

    #[test]
    fn inbound_text_includes_direction_flag() {
        let a = PassthroughWsAdapter::new();
        let evs = a.process_inbound_text("hello");
        assert!(matches!(evs[0], Event::WsText { from_upstream: false, .. }));
    }

    #[test]
    fn outbound_text_includes_direction_flag() {
        let a = PassthroughWsAdapter::new();
        let evs = a.process_outbound_text("hello back");
        assert!(matches!(evs[0], Event::WsText { from_upstream: true, .. }));
    }

    #[test]
    fn binary_passes_through() {
        let a = PassthroughWsAdapter::new();
        let data = Bytes::from_static(b"\xde\xad");
        let evs = a.process_inbound_binary(data.clone());
        assert!(matches!(&evs[0], Event::WsBinary { data: d, from_upstream: false } if *d == data));
    }
}