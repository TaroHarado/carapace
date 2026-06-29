//! E2E: legitimate Claude Code-style flow with declared tools is NOT
//! blocked. Demonstrates the difference between upstream-injected `tool_use`
//! (high severity / blocked) and a client-declared tool returning clean
//! arguments (allowed through).

#![cfg(test)]

use std::net::SocketAddr;
use std::time::Duration;

use carapace::cli::Mode;
use carapace::proxy::{self, ProxyConfig};
use carapace::record::Recorder;
use carapace::secure::Secret;
use carapace::tools;
use bytes::Bytes;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn declared_tool_use_with_clean_args_is_forwarded() {
    // Stand up a mock upstream that emits a legitimate Bash tool_use
    // with input the inspector should NOT flag.
    let evil_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let l = tokio::net::TcpListener::bind(evil_addr).await.unwrap();
    let upstream_port = l.local_addr().unwrap().port();
    drop(l);

    let upstream_uri = format!("http://127.0.0.1:{upstream_port}");
    let upstream_handle = tokio::spawn(serve_legitimate(upstream_uri.clone()));

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Stand up carapace proxy.
    let proxy_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let lp = tokio::net::TcpListener::bind(proxy_addr).await.unwrap();
    let proxy_port = lp.local_addr().unwrap().port();
    drop(lp);

    let recorder = std::sync::Arc::new(Recorder::open("-").unwrap());
    let cfg = ProxyConfig {
        upstream: upstream_uri,
        listen: format!("127.0.0.1:{proxy_port}").parse().unwrap(),
        upstream_key: Secret::empty(),
        mode: Mode::Block,
        recorder,
        forensics: None,
        rules: std::sync::Arc::new(carapace::inspect::BUILTIN.clone()),
        judge: None,
        defense: Some(std::sync::Arc::new(carapace::defense::DefenseEngine::degraded())),
        quarantine: None,
    };
    let proxy_handle = tokio::spawn(proxy::run(cfg));

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Client request declares Bash + Read tools.
    let req = serde_json::json!({
        "model": "claude-3-5-sonnet-mock",
        "max_tokens": 1024,
        "messages": [{"role": "user", "content": "list files"}],
        "tools": [
            {"name": "Bash", "description": "shell", "input_schema": {}},
            {"name": "Read", "description": "read file", "input_schema": {}}
        ]
    });
    // Sanity-check our local parser sees both names.
    let declared = tools::parse_request_tools(&Bytes::from(req.to_string()), "anthropic");
    assert!(declared.contains("Bash"));
    assert!(declared.contains("Read"));

    let resp = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{proxy_port}/v1/messages"))
        .header("content-type", "application/json")
        .header("anthropic-version", "2023-06-01")
        .timeout(Duration::from_secs(2))
        .body(req.to_string())
        .send()
        .await
        .expect("proxy call succeeded");

    let body = resp.bytes().await.expect("body bytes");
    let text = String::from_utf8_lossy(&body).into_owned();

    // Legitimate Bash call → must reach the client untouched. We must NOT
    // see the blocked stub.
    assert!(
        text.contains("\"name\":\"Bash\""),
        "declared tool_use was stripped/blocked: {text}"
    );
    assert!(
        !text.contains("[carapace: blocked tool_use with high-severity injection]"),
        "false positive — clean declared tool_use got blocked: {text}"
    );

    proxy_handle.abort();
    upstream_handle.abort();
}

async fn serve_legitimate(bind: String) {
    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper::{Request, Response, StatusCode};
    use hyper_util::rt::TokioIo;

    let addr: SocketAddr = bind[7..].parse().unwrap();
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    loop {
        let (stream, _) = listener.accept().await.unwrap();
        let io = TokioIo::new(stream);
        tokio::spawn(async move {
            let _ = http1::Builder::new()
                .serve_connection(
                    io,
                    service_fn(|_req: Request<hyper::body::Incoming>| async move {
                        let frame = "event: message_start\n\
data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_ok\"}}\n\n\
event: content_block_start\n\
data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_ok\",\"name\":\"Bash\",\"input\":{}}}\n\n\
event: content_block_delta\n\
data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"command\\\": \\\"ls -la\\\"}\"}}\n\n\
event: content_block_stop\n\
data: {\"type\":\"content_block_stop\",\"index\":0}\n\n\
event: message_stop\n\
data: {\"type\":\"message_stop\"}\n\n".to_string();
                        let body = Full::new(Bytes::from(frame))
                            .map_err(|_e: std::convert::Infallible| -> std::io::Error {
                                unreachable!("Infallible cannot be constructed")
                            })
                            .boxed();
                        Ok::<_, std::io::Error>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .header("content-type", "text/event-stream")
                                .body(body)
                                .unwrap(),
                        )
                    }),
                )
                .await;
        });
    }
}
