//! Local SafeRouter daemon / web API.
//!
//! One binary, one command, local-first.
//! No Node, no separate backend process, no hosted key sink.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

use crate::deep_scan;
use crate::defense_log;
use crate::certify;
use crate::correlation;
use crate::enforcement;
use crate::history;
use crate::judge;
use crate::policy::{self, Action, ActionKind, Decision, ProviderRisk};
use crate::quarantine;
use crate::registry::{self, Registry};
use crate::scan;
use crate::score;
use crate::secure::Secret;
use crate::session;

#[derive(Clone)]
pub struct WebConfig {
    pub listen: SocketAddr,
    pub site_dir: PathBuf,
}

#[derive(Clone)]
struct AppState {
    site_dir: PathBuf,
    scan_slots: Arc<Semaphore>,
    session_root: PathBuf,
    judge_configured: bool,
}

#[derive(Debug, Deserialize)]
pub struct ScanRequest {
    pub base_url: String,
    pub api_key: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DeepScanRequest {
    pub base_url: String,
    pub api_key: Option<String>,
    pub claimed_model: Option<String>,
    pub use_case: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ScoreRequest {
    pub base_url: String,
    pub api_key: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct VerifyRequest {
    pub base_url: String,
    pub api_key: Option<String>,
    pub claimed_model: Option<String>,
    pub use_case: Option<String>,
    pub signing_key: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SessionInitRequest {
    pub task: String,
}

#[derive(Debug, Deserialize)]
pub struct SessionGrantRequest {
    pub session_id: String,
    pub name: String,
    pub value: bool,
}

#[derive(Debug, Deserialize)]
pub struct SessionShowRequest {
    pub session_id: String,
}

#[derive(Debug, Deserialize)]
pub struct PolicyEvalRequest {
    pub session_id: String,
    pub action_kind: String,
    pub target: String,
    pub provider_risk: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct HistoryQuery {
    pub host: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SessionModeRequest {
    pub session_id: String,
    pub mode: String,
}

#[derive(Debug, Deserialize)]
pub struct EnforcementEvalRequest {
    pub session_id: String,
    pub action_kind: String,
    pub target: String,
    pub provider_risk: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct QuarantineActionRequest {
    pub sha256: String,
}

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub ok: bool,
    pub version: &'static str,
    pub semantic_arbiter: &'static str,
}

pub async fn run(cfg: WebConfig) -> anyhow::Result<()> {
    let state = Arc::new(AppState {
        site_dir: cfg.site_dir,
        scan_slots: Arc::new(Semaphore::new(2)),
        session_root: session::default_root(),
        judge_configured: judge::from_env().is_some(),
    });

    let app = router(state);

    tracing::info!(listen=%cfg.listen, "SafeRouter local web up");
    let listener = tokio::net::TcpListener::bind(cfg.listen).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/health", get(health))
        .route("/api/scan", post(run_scan))
        .route("/api/deep-scan", post(run_deep_scan))
        .route("/api/score", post(run_score))
        .route("/api/verify", post(run_verify))
        .route("/api/registry", get(list_registry))
        .route("/api/history", post(list_history))
        .route("/api/defense-events", get(list_defense_events))
        .route("/api/chain-graph", get(chain_graph))
        .route("/api/correlation-alerts", get(list_correlation_alerts))
        .route("/api/quarantine", get(list_quarantine))
        .route("/api/quarantine/release", post(release_quarantine))
        .route("/api/quarantine/purge", post(purge_quarantine))
        .route("/api/quarantine/clear", post(clear_quarantine))
        .route("/api/session/init", post(init_session))
        .route("/api/session/show", post(show_session))
        .route("/api/session/grant", post(grant_session))
        .route("/api/session/mode", post(set_session_mode))
        .route("/api/policy/evaluate", post(eval_policy))
        .route("/api/enforcement/evaluate", post(eval_enforcement))
        .route("/", get(index))
        .route("/styles.css", get(styles))
        .route("/app.js", get(app_js))
        .route("/assets/*path", get(asset))
        .layer(DefaultBodyLimit::max(16 * 1024))
        .with_state(state)
}

async fn health(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    Json(HealthResponse {
        ok: true,
        version: crate::VERSION,
        semantic_arbiter: if state.judge_configured { "configured" } else { "off" },
    })
}

async fn run_scan(State(state): State<Arc<AppState>>, Json(req): Json<ScanRequest>) -> Result<Json<scan::ScanReport>, ApiError> {
    validate_base_url(&req.base_url)?;
    let key = req.api_key.filter(|k| !k.is_empty()).map(Secret::new);
    let _permit = state.scan_slots.acquire().await.map_err(|_| ApiError::message("scan queue unavailable"))?;
    let report = scan::run(&req.base_url, key).await.map_err(ApiError::from_anyhow)?;
    Ok(Json(report))
}

async fn run_deep_scan(State(state): State<Arc<AppState>>, Json(req): Json<DeepScanRequest>) -> Result<Json<deep_scan::DeepScanReport>, ApiError> {
    validate_base_url(&req.base_url)?;
    let key = req.api_key.filter(|k| !k.is_empty()).map(Secret::new);
    let _permit = state.scan_slots.acquire().await.map_err(|_| ApiError::message("scan queue unavailable"))?;
    let report = deep_scan::run(
        &req.base_url,
        key,
        req.claimed_model,
        req.use_case.as_deref().unwrap_or("coding-agent"),
    )
    .await
    .map_err(ApiError::from_anyhow)?;
    Ok(Json(report))
}

async fn run_score(State(state): State<Arc<AppState>>, Json(req): Json<ScoreRequest>) -> Result<Json<score::ProviderScore>, ApiError> {
    validate_base_url(&req.base_url)?;
    let key = req.api_key.filter(|k| !k.is_empty()).map(Secret::new);
    let _permit = state.scan_slots.acquire().await.map_err(|_| ApiError::message("scan queue unavailable"))?;
    let scan_report = scan::run(&req.base_url, key).await.map_err(ApiError::from_anyhow)?;
    let report = score::score_provider(&req.base_url, scan_report);
    Ok(Json(report))
}

#[derive(Debug, Serialize)]
struct VerifyResponse {
    score: score::ProviderScore,
    deep_scan: deep_scan::DeepScanReport,
    entry: certify::RegistryEntry,
    registry_path: String,
}

async fn run_verify(State(state): State<Arc<AppState>>, Json(req): Json<VerifyRequest>) -> Result<Json<VerifyResponse>, ApiError> {
    validate_base_url(&req.base_url)?;
    let key_for_deep = req.api_key.clone().filter(|k| !k.is_empty()).map(Secret::new);
    let key_for_score = req.api_key.filter(|k| !k.is_empty()).map(Secret::new);
    let _permit = state.scan_slots.acquire().await.map_err(|_| ApiError::message("scan queue unavailable"))?;

    let deep = deep_scan::run(
        &req.base_url,
        key_for_deep,
        req.claimed_model,
        req.use_case.as_deref().unwrap_or("coding-agent"),
    )
    .await
    .map_err(ApiError::from_anyhow)?;
    let score_report = score::score_provider(&req.base_url, scan::run(&req.base_url, key_for_score).await.map_err(ApiError::from_anyhow)?);
    let badge = score::render_badge_svg(&score_report);
    let entry = certify::RegistryEntry::from_score(&score_report, &badge);

    let registry_path = registry::default_registry_path();
    let mut reg = Registry::load(&registry_path).map_err(ApiError::from_anyhow)?;
    reg.add(entry.clone());
    reg.save(&registry_path).map_err(ApiError::from_anyhow)?;

    Ok(Json(VerifyResponse {
        score: score_report,
        deep_scan: deep,
        entry,
        registry_path: registry_path.display().to_string(),
    }))
}

async fn list_registry() -> Result<Json<Registry>, ApiError> {
    let path = registry::default_registry_path();
    let reg = Registry::load(&path).map_err(ApiError::from_anyhow)?;
    Ok(Json(reg))
}

async fn list_history(Json(req): Json<HistoryQuery>) -> Result<Json<Vec<history::HistoryEntry>>, ApiError> {
    let root = history::default_root();
    if let Some(host) = req.host.as_deref() {
        let items = history::load_host(&root, host).map_err(ApiError::from_anyhow)?;
        return Ok(Json(items));
    }
    let mut all = Vec::new();
    if root.exists() {
        for file in std::fs::read_dir(&root).map_err(|e| ApiError::message(&e.to_string()))? {
            let file = file.map_err(|e| ApiError::message(&e.to_string()))?;
            if file.path().extension().and_then(|e| e.to_str()) == Some("jsonl") {
                let raw = std::fs::read_to_string(file.path()).map_err(|e| ApiError::message(&e.to_string()))?;
                let stream = serde_json::Deserializer::from_str(&raw).into_iter::<history::HistoryEntry>();
                for item in stream {
                    all.push(item.map_err(|e| ApiError::message(&e.to_string()))?);
                }
            }
        }
    }
    all.sort_by(|a, b| b.checked_at.cmp(&a.checked_at));
    Ok(Json(all))
}

async fn list_defense_events() -> Result<Json<Vec<defense_log::DefenseEvent>>, ApiError> {
    let events = defense_log::load_recent(100).map_err(ApiError::from_anyhow)?;
    Ok(Json(events))
}

async fn list_correlation_alerts() -> Result<Json<Vec<correlation::CorrelationAlert>>, ApiError> {
    let store = correlation::CorrelationStore::open_default()
        .map_err(|e| ApiError::message(&e.to_string()))?;
    let alerts = store.active_alerts().map_err(|e| ApiError::message(&e.to_string()))?;
    Ok(Json(alerts))
}

#[derive(Debug, Serialize)]
struct GraphNode {
    id: usize,
    label: String,
    capability: String,
    asset: String,
    decision: String,
    tainted: bool,
    ts: String,
}

#[derive(Debug, Serialize)]
struct GraphEdge {
    source: usize,
    target: usize,
    chain: String,
    severity: u8,
}

#[derive(Debug, Serialize)]
struct ChainGraph {
    nodes: Vec<GraphNode>,
    edges: Vec<GraphEdge>,
}

async fn chain_graph() -> Result<Json<ChainGraph>, ApiError> {    let events = defense_log::load_recent(200).map_err(ApiError::from_anyhow)?;
    let mut nodes: Vec<GraphNode> = Vec::new();
    let mut edges: Vec<GraphEdge> = Vec::new();

    for (idx, ev) in events.iter().enumerate() {
        let short_target = ev.target.split('/').next_back().unwrap_or(&ev.target).to_string();
        nodes.push(GraphNode {
            id: idx,
            label: format!("{} · {}", ev.capability, short_target),
            capability: ev.capability.clone(),
            asset: ev.asset_class.clone(),
            decision: ev.decision.clone(),
            tainted: ev.tainted,
            ts: ev.ts.clone(),
        });
    }

    // Build edges: for each chain_hit id shared between any two nodes, draw an edge.
    // Simple heuristic: if event[j] has the same chain id as event[i] and j > i, connect i → j.
    for (i, ev_i) in events.iter().enumerate() {
        for chain_id in &ev_i.chain_hits {
            // find the next event that also carries this chain id
            for (j, ev_j) in events.iter().enumerate().skip(i + 1) {
                if ev_j.chain_hits.contains(chain_id) {
                    // Avoid duplicate edges for the same pair
                    let already = edges.iter().any(|e: &GraphEdge| e.source == i && e.target == j);
                    if !already {
                        edges.push(GraphEdge {
                            source: i,
                            target: j,
                            chain: chain_id.clone(),
                            severity: 75,
                        });
                    }
                    break;
                }
            }
        }
    }

    Ok(Json(ChainGraph { nodes, edges }))
}

async fn list_quarantine() -> Result<Json<Vec<quarantine::QuarantineEntry>>, ApiError> {
    let store = quarantine::QuarantineStore::open_default()
        .map_err(|e| ApiError::message(&e.to_string()))?;
    Ok(Json(store.list()))
}

async fn release_quarantine(Json(req): Json<QuarantineActionRequest>) -> Result<StatusCode, ApiError> {
    let store = quarantine::QuarantineStore::open_default()
        .map_err(|e| ApiError::message(&e.to_string()))?;
    store.release(&req.sha256).map_err(|e| ApiError::message(&e.to_string()))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn purge_quarantine(Json(req): Json<QuarantineActionRequest>) -> Result<StatusCode, ApiError> {
    let store = quarantine::QuarantineStore::open_default()
        .map_err(|e| ApiError::message(&e.to_string()))?;
    store.purge(&req.sha256).map_err(|e| ApiError::message(&e.to_string()))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn clear_quarantine() -> Result<StatusCode, ApiError> {
    let store = quarantine::QuarantineStore::open_default()
        .map_err(|e| ApiError::message(&e.to_string()))?;
    let entries = store.list();
    for e in entries {
        if !e.released {
            let _ = store.purge(&e.sha256);
        }
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn init_session(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SessionInitRequest>,
) -> Result<Json<session::SessionState>, ApiError> {
    if req.task.trim().is_empty() {
        return Err(ApiError::message("task is required"));
    }
    let sess = session::new(&req.task);
    session::save(&state.session_root, &sess).map_err(ApiError::from_anyhow)?;
    Ok(Json(sess))
}

async fn show_session(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SessionShowRequest>,
) -> Result<Json<session::SessionState>, ApiError> {
    let sess = session::load(&state.session_root, &req.session_id).map_err(ApiError::from_anyhow)?;
    Ok(Json(sess))
}

async fn grant_session(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SessionGrantRequest>,
) -> Result<Json<session::SessionState>, ApiError> {
    let mut sess = session::load(&state.session_root, &req.session_id).map_err(ApiError::from_anyhow)?;
    session::set_grant(&mut sess, &req.name, req.value);
    session::save(&state.session_root, &sess).map_err(ApiError::from_anyhow)?;
    Ok(Json(sess))
}

async fn set_session_mode(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SessionModeRequest>,
) -> Result<Json<session::SessionState>, ApiError> {
    let mut sess = session::load(&state.session_root, &req.session_id).map_err(ApiError::from_anyhow)?;
    sess.enforcement_mode = match req.mode.to_lowercase().as_str() {
        "enforce" => session::EnforcementMode::Enforce,
        "correct" => session::EnforcementMode::Correct,
        "observe" => session::EnforcementMode::Observe,
        "off" => session::EnforcementMode::Off,
        _ => return Err(ApiError::message("unknown mode: enforce / correct / observe / off")),
    };
    session::save(&state.session_root, &sess).map_err(ApiError::from_anyhow)?;
    Ok(Json(sess))
}

async fn eval_enforcement(
    State(state): State<Arc<AppState>>,
    Json(req): Json<EnforcementEvalRequest>,
) -> Result<Json<enforcement::EnforcementOutcome>, ApiError> {
    let sess = session::load(&state.session_root, &req.session_id).map_err(ApiError::from_anyhow)?;
    let provider_risk = match req.provider_risk.as_deref().unwrap_or("medium").to_lowercase().as_str() {
        "low" => ProviderRisk::Low,
        "high" => ProviderRisk::High,
        _ => ProviderRisk::Medium,
    };
    let kind = match req.action_kind.to_lowercase().as_str() {
        "file-read" => ActionKind::FileRead { path: req.target },
        "file-write" => ActionKind::FileWrite { path: req.target },
        "command" => ActionKind::Command { command: req.target },
        "outbound-send" => ActionKind::OutboundSend { label: req.target },
        _ => return Err(ApiError::message("unknown action_kind")),
    };
    let action = Action { kind, provider_risk };
    let outcome = enforcement::evaluate(&sess, &action);
    Ok(Json(outcome))
}

#[derive(Debug, Serialize)]
struct PolicyEvalResponse {
    decision: Decision,
}

async fn eval_policy(
    State(state): State<Arc<AppState>>,
    Json(req): Json<PolicyEvalRequest>,
) -> Result<Json<PolicyEvalResponse>, ApiError> {
    let sess = session::load(&state.session_root, &req.session_id).map_err(ApiError::from_anyhow)?;
    let provider_risk = match req.provider_risk.as_deref().unwrap_or("medium").to_lowercase().as_str() {
        "low" => ProviderRisk::Low,
        "high" => ProviderRisk::High,
        _ => ProviderRisk::Medium,
    };
    let kind = match req.action_kind.to_lowercase().as_str() {
        "file-read" => ActionKind::FileRead { path: req.target },
        "file-write" => ActionKind::FileWrite { path: req.target },
        "command" => ActionKind::Command { command: req.target },
        "outbound-send" => ActionKind::OutboundSend { label: req.target },
        _ => return Err(ApiError::message("unknown action_kind")),
    };
    let decision = policy::evaluate(&sess, &Action { kind, provider_risk });
    Ok(Json(PolicyEvalResponse { decision }))
}

fn validate_base_url(url: &str) -> Result<(), ApiError> {
    if url.trim().is_empty() {
        return Err(ApiError::message("base_url is required"));
    }
    let parsed = reqwest::Url::parse(url).map_err(|_| ApiError::message("base_url must be a valid http/https URL"))?;
    match parsed.scheme() {
        "http" | "https" => Ok(()),
        _ => Err(ApiError::message("base_url must use http or https")),
    }
}

async fn index(State(state): State<Arc<AppState>>) -> Result<Html<String>, ApiError> {
    let path = state.site_dir.join("index.html");
    let raw = tokio::fs::read_to_string(&path)
        .await
        .with_context(|| format!("read {}", path.display()))
        .map_err(ApiError::from_anyhow)?;
    Ok(Html(raw))
}

async fn styles(State(state): State<Arc<AppState>>) -> Result<Response, ApiError> {
    static_asset(state.site_dir.join("styles.css"), "text/css").await
}

async fn app_js(State(state): State<Arc<AppState>>) -> Result<Response, ApiError> {
    static_asset(state.site_dir.join("app.js"), "application/javascript").await
}

async fn asset(
    State(state): State<Arc<AppState>>,
    Path(path): Path<String>,
) -> Result<Response, ApiError> {
    if path.contains("..") || path.contains(':') || path.starts_with('/') || path.starts_with('\\') {
        return Err(ApiError::message("invalid asset path"));
    }

    let asset_path = state.site_dir.join("assets").join(&path);
    let content_type = match asset_path.extension().and_then(|e| e.to_str()).unwrap_or("") {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "svg" => "image/svg+xml",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        _ => "application/octet-stream",
    };
    static_asset(asset_path, content_type).await
}

async fn static_asset(path: PathBuf, content_type: &'static str) -> Result<Response, ApiError> {
    let bytes = tokio::fs::read(&path)
        .await
        .with_context(|| format!("read {}", path.display()))
        .map_err(ApiError::from_anyhow)?;
    let mut resp = Response::new(bytes.into_response().into_body());
    resp.headers_mut()
        .insert(axum::http::header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    Ok(resp)
}

pub struct ApiError {
    pub message: String,
}

impl ApiError {
    fn from_anyhow(err: anyhow::Error) -> Self {
        Self {
            message: err.to_string(),
        }
    }

    fn message(msg: &str) -> Self {
        Self {
            message: msg.to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": self.message,
            })),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::util::ServiceExt;

    #[test]
    fn api_error_is_structured() {
        let err = ApiError::from_anyhow(anyhow::anyhow!("boom"));
        assert_eq!(err.message, "boom");
    }

    #[test]
    fn validate_base_url_accepts_http_and_https() {
        assert!(validate_base_url("http://127.0.0.1:8484").is_ok());
        assert!(validate_base_url("https://api.deepseek.com/v1").is_ok());
    }

    #[test]
    fn validate_base_url_rejects_empty_and_non_http() {
        assert!(validate_base_url("").is_err());
        assert!(validate_base_url("file:///tmp/x").is_err());
    }

    #[tokio::test]
    async fn health_endpoint_returns_ok() {
        let state = Arc::new(AppState {
            site_dir: PathBuf::from("site"),
            scan_slots: Arc::new(Semaphore::new(2)),
            session_root: std::env::temp_dir().join("carapace-test-sessions"),
            judge_configured: false,
        });
        let app = router(state);
        let response = app
            .oneshot(Request::builder().uri("/api/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn score_endpoint_rejects_empty_base_url() {
        let state = Arc::new(AppState {
            site_dir: PathBuf::from("site"),
            scan_slots: Arc::new(Semaphore::new(2)),
            session_root: std::env::temp_dir().join("carapace-test-sessions"),
            judge_configured: false,
        });
        let app = router(state);
        let body = serde_json::json!({"base_url": "", "api_key": null}).to_string();
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/score")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn session_init_returns_session_id() {
        let root = std::env::temp_dir().join("carapace-web-sessions");
        let _ = std::fs::remove_dir_all(&root);
        let state = Arc::new(AppState {
            site_dir: PathBuf::from("site"),
            scan_slots: Arc::new(Semaphore::new(2)),
            session_root: root.clone(),
            judge_configured: false,
        });
        let app = router(state);
        let body = serde_json::json!({"task": "fix npm build"}).to_string();
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/session/init")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn asset_endpoint_rejects_path_traversal() {
        let state = Arc::new(AppState {
            site_dir: PathBuf::from("site"),
            scan_slots: Arc::new(Semaphore::new(2)),
            session_root: std::env::temp_dir().join("carapace-test-sessions"),
            judge_configured: false,
        });
        let app = router(state);
        let response = app
            .oneshot(Request::builder().uri("/assets/../Cargo.toml").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn history_endpoint_accepts_empty_query() {
        let state = Arc::new(AppState {
            site_dir: PathBuf::from("site"),
            scan_slots: Arc::new(Semaphore::new(2)),
            session_root: std::env::temp_dir().join("carapace-test-sessions"),
            judge_configured: false,
        });
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/history")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
