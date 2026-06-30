//! WebSocket protocol adapters — bi-directional frames.
//!
//! Each adapter implements [`super::WsAdapter`]. The proxy:
//!   1. upgrades the incoming HTTP request to a WebSocket connection.
//!   2. opens a corollary WS connection to the upstream provider.
//!   3. relays each frame through the matching adapter, which emits [`Event`]s.
//!   4. The same `inspect::Inspector` + defense engine sees those events and
//!      decides block/substitute/allow exactly like the SSE path.
//!
//! Known adapters:
//!   - `openai_realtime` — for OpenAI Realtime API `/v1/realtime` (audio
//!     chat with tool_use support).
//!   - `anthropic_stream_v2` (planned) — once Anthropic publishes WS endpoints.
//!   - `twilio_voice` (planned) — Twilio Media Stream.
//!   - `passthrough` — last-resort adapter that still surfaces every text
//!     frame through the inspector.

pub mod openai_realtime;
pub mod passthrough;