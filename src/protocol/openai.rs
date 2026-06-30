//! OpenAI Chat Completions adapter.
//!
//! OpenAI streaming shape: `data: {"choices":[{"delta":{"..."},"index":0}]}`,
//! terminated by `data: [DONE]`. Tool calls stream as
//! `delta.tool_calls[i].function.arguments` chunks — JSON string fragments
//! that we reassemble before inspection.

use async_stream::stream;
use bytes::Bytes;
use futures_core::Stream;
use serde_json::Value;

use crate::protocol::Event;

pub struct OpenAiAdapter;

impl crate::protocol::ProtocolAdapter for OpenAiAdapter {
    fn name(&self) -> &'static str {
        "openai"
    }
    fn accepts(&self, c: &str) -> bool {
        c.contains("openai") || c.contains("text/event-stream")
    }
    fn inspect_body(&self, body: Bytes) -> Bytes {
        body
    }
    fn stream(
        &self,
        body: Bytes,
    ) -> std::pin::Pin<Box<dyn Stream<Item = Event> + Send + 'static>> {
        Box::pin(openai_events(body))
    }
}

pub fn openai_events(body: Bytes) -> impl Stream<Item = Event> + Send + 'static {
    stream! {
        let text = String::from_utf8_lossy(&body).into_owned();
        let mut tool_buf: Vec<ToolCallBuffer> = Vec::new();
        for frame in split_data_lines(&text) {
            if frame.trim() == "[DONE]" {
                continue;
            }
            let payload: Value = match serde_json::from_str(frame) {
                Ok(v) => v,
                Err(_) => {
                    yield Event::Raw(Bytes::copy_from_slice(frame.as_bytes()));
                    continue;
                }
            };
            let choices = match payload.get("choices").and_then(|c| c.as_array()) {
                Some(c) => c,
                None => continue,
            };
            for choice in choices {
                let delta = match choice.get("delta") {
                    Some(d) => d,
                    None => continue,
                };
                let finish_reason = choice.get("finish_reason").and_then(|v| v.as_str());
                // text
                if let Some(text) = delta.get("content").and_then(|v| v.as_str()) {
                    yield Event::TextDelta(text.to_string());
                }
                // tool_calls
                if let Some(tcs) = delta.get("tool_calls").and_then(|v| v.as_array()) {
                    for tc in tcs {
                        let idx = tc
                            .get("index")
                            .and_then(|v| v.as_u64())
                            .map(|i| i as usize)
                            .unwrap_or(0);
                        // Ensure buffer exists
                        while tool_buf.len() <= idx {
                            tool_buf.push(ToolCallBuffer::default());
                        }
                        // id + name on first delta
                        if let Some(id) = tc.get("id").and_then(|v| v.as_str()) {
                            tool_buf[idx].id = Some(id.to_string());
                        }
                        if let Some(fn_obj) = tc.get("function") {
                            if let Some(name) = fn_obj.get("name").and_then(|v| v.as_str()) {
                                if !tool_buf[idx].started {
                                    tool_buf[idx].started = true;
                                    tool_buf[idx].name = Some(name.to_string());
                                }
                                if let Some(real_name) = tool_buf[idx].name.clone() {
                                    if !tool_buf[idx].emitted_start {
                                        tool_buf[idx].emitted_start = true;
                                        yield Event::ToolUseStart {
                                            id: tool_buf[idx].id.clone().unwrap_or_default(),
                                            name: real_name,
                                        };
                                    }
                                }
                            }
                            if let Some(args) = fn_obj.get("arguments").and_then(|v| v.as_str()) {
                                tool_buf[idx].args.push_str(args);
                                yield Event::ToolUseDelta(args.to_string());
                            }
                        }
                    }
                }
                if finish_reason == Some("tool_calls") {
                    for tb in &mut tool_buf {
                        if tb.started && !tb.emitted_end {
                            tb.emitted_end = true;
                            yield Event::ToolUseEnd;
                        }
                    }
                }
            }
        }
        // Emit ToolUseEnd for every started tool call.
        for tb in tool_buf {
            if tb.started && !tb.emitted_end {
                yield Event::ToolUseEnd;
            }
        }
    }
}

#[derive(Default)]
struct ToolCallBuffer {
    id: Option<String>,
    name: Option<String>,
    args: String,
    started: bool,
    emitted_start: bool,
    emitted_end: bool,
}

/// Serialize a normalized Event back into OpenAI-compatible SSE.
pub fn event_to_bytes(ev: &Event, tool_index: u32) -> Bytes {
    match ev {
        Event::TextDelta(s) => {
            let payload = serde_json::json!({
                "choices": [{
                    "index": 0,
                    "delta": {"content": s},
                    "finish_reason": null
                }]}
            );
            sse_frame(&payload)
        }
        Event::ToolUseStart { id, name } => {
            let payload = serde_json::json!({
                "choices": [{
                    "index": 0,
                    "delta": {
                        "tool_calls": [{
                            "index": tool_index,
                            "id": id,
                            "type": "function",
                            "function": {"name": name, "arguments": ""}
                        }]
                    },
                    "finish_reason": null
                }]}
            );
            sse_frame(&payload)
        }
        Event::ToolUseDelta(s) => {
            let payload = serde_json::json!({
                "choices": [{
                    "index": 0,
                    "delta": {
                        "tool_calls": [{
                            "index": tool_index,
                            "function": {"arguments": s}
                        }]
                    },
                    "finish_reason": null
                }]}
            );
            sse_frame(&payload)
        }
        Event::ToolUseEnd => {
            let payload = serde_json::json!({
                "choices": [{
                    "index": 0,
                    "delta": {},
                    "finish_reason": "tool_calls"
                }]}
            );
            sse_frame(&payload)
        }
        Event::Raw(b) => b.clone(),
        // WS events shouldn't reach the SSE serializer on this path — see
        // anthropic.rs for the same guard. Pass through bytes if they do.
        Event::WsText { text, .. } => Bytes::from(text.clone()),
        Event::WsBinary { data, .. } => data.clone(),
        Event::WsPing(b) | Event::WsPong(b) => b.clone(),
        Event::WsClose => Bytes::new(),
    }
}

pub fn blocked_tool_substitution(tool_index: u32) -> Vec<Bytes> {
    vec![
        event_to_bytes(
            &Event::TextDelta("[carapace: blocked tool_use with high-severity injection]".to_string()),
            tool_index,
        ),
        done_frame(),
    ]
}

fn sse_frame(payload: &Value) -> Bytes {
    let mut s = String::from("data: ");
    s.push_str(&payload.to_string());
    s.push_str("\n\n");
    Bytes::from(s)
}

fn done_frame() -> Bytes {
    Bytes::from("data: [DONE]\n\n")
}

fn split_data_lines(text: &str) -> Vec<&str> {
    text.lines()
        .filter_map(|l| {
            let l = l.strip_suffix('\r').unwrap_or(l);
            l.strip_prefix("data: ").map(|s| s.trim())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::StreamExt;

    #[tokio::test]
    async fn repeated_name_emits_single_start_and_single_end() {
        let body = Bytes::from(
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"function\":{\"name\":\"Bash\"}}]},\"finish_reason\":null}]}\n\n\
data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"name\":\"Bash\",\"arguments\":\"ls -la\"}}]},\"finish_reason\":\"tool_calls\"}]}\n\n\
data: [DONE]\n\n",
        );
        let mut stream = Box::pin(openai_events(body));
        let mut starts = 0;
        let mut ends = 0;
        while let Some(ev) = stream.next().await {
            match ev {
                Event::ToolUseStart { .. } => starts += 1,
                Event::ToolUseEnd => ends += 1,
                _ => {}
            }
        }
        assert_eq!(starts, 1);
        assert_eq!(ends, 1);
    }

    #[test]
    fn event_to_bytes_is_openai_wire_format() {
        let bytes = event_to_bytes(&Event::TextDelta("PONG".to_string()), 0);
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.starts_with("data: {\"choices\""));
        assert!(text.contains("\"content\":\"PONG\""));
    }

    #[test]
    fn blocked_substitution_ends_with_done() {
        let frames = blocked_tool_substitution(0);
        let last = String::from_utf8_lossy(frames.last().unwrap());
        assert_eq!(last, "data: [DONE]\n\n");
    }
}
