//! Unknown-protocol passthrough — forwards bytes untouched. The inspector is
//! still run on the buffer so behavioural regex rules fire.

use async_stream::stream;
use bytes::Bytes;
use futures_core::Stream;

use crate::protocol::Event;

pub struct PassthroughAdapter;

impl crate::protocol::ProtocolAdapter for PassthroughAdapter {
    fn name(&self) -> &'static str {
        "passthrough"
    }
    fn accepts(&self, _c: &str) -> bool {
        true
    }
    fn inspect_body(&self, body: Bytes) -> Bytes {
        body
    }
    fn stream(
        &self,
        body: Bytes,
    ) -> std::pin::Pin<Box<dyn Stream<Item = Event> + Send + 'static>> {
        Box::pin(stream! {
            yield Event::Raw(body);
        })
    }
}