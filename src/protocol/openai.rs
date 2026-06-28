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
                                tool_buf[idx].name = Some(name.to_string());
                                if let Some(real_name) = tool_buf[idx].name.as_ref() {
                                    yield Event::ToolUseStart {
                                        id: tool_buf[idx].id.clone().unwrap_or_default(),
                                        name: real_name.clone(),
                                    };
                                }
                            }
                            if let Some(args) = fn_obj.get("arguments").and_then(|v| v.as_str()) {
                                tool_buf[idx].args.push_str(args);
                                yield Event::ToolUseDelta(args.to_string());
                            }
                        }
                    }
                }
            }
        }
        // Emit ToolUseEnd for every started tool call.
        for tb in tool_buf {
            if tb.id.is_some() {
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
}

fn split_data_lines(text: &str) -> Vec<&str> {
    text.lines()
        .filter_map(|l| {
            let l = l.strip_suffix('\r').unwrap_or(l);
            l.strip_prefix("data: ").map(|s| s.trim())
        })
        .collect()
}