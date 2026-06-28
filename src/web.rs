//! Local SafeRouter daemon / web API.
//!
//! One binary, one command, local-first.
//! No Node, no separate backend process, no hosted key sink.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use axum::extract::State;
use axum::http::{HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::deep_scan;
use crate::scan;
use crate::score;
use crate::secure::Secret;

#[derive(Clone)]
pub struct WebConfig {
    pub listen: SocketAddr,
    pub site_dir: PathBuf,
}

#[derive(Clone)]
struct AppState {
    site_dir: PathBuf,
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

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub ok: bool,
    pub version: &'static str,
}

pub async fn run(cfg: WebConfig) -> anyhow::Result<()> {
    let state = Arc::new(AppState {
        site_dir: cfg.site_dir,
    });

    let app = Router::new()
        .route("/api/health", get(health))
        .route("/api/scan", post(run_scan))
        .route("/api/deep-scan", post(run_deep_scan))
        .route("/api/score", post(run_score))
        .route("/", get(index))
        .route("/styles.css", get(styles))
        .route("/app.js", get(app_js))
        .with_state(state);

    tracing::info!(listen=%cfg.listen, "SafeRouter local web up");
    let listener = tokio::net::TcpListener::bind(cfg.listen).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        ok: true,
        version: crate::VERSION,
    })
}

async fn run_scan(Json(req): Json<ScanRequest>) -> Result<Json<scan::ScanReport>, ApiError> {
    let key = req.api_key.filter(|k| !k.is_empty()).map(Secret::new);
    let report = scan::run(&req.base_url, key).await.map_err(ApiError::from_anyhow)?;
    Ok(Json(report))
}

async fn run_deep_scan(Json(req): Json<DeepScanRequest>) -> Result<Json<deep_scan::DeepScanReport>, ApiError> {
    let key = req.api_key.filter(|k| !k.is_empty()).map(Secret::new);
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

async fn run_score(Json(req): Json<ScoreRequest>) -> Result<Json<score::ProviderScore>, ApiError> {
    let key = req.api_key.filter(|k| !k.is_empty()).map(Secret::new);
    let scan_report = scan::run(&req.base_url, key).await.map_err(ApiError::from_anyhow)?;
    let report = score::score_provider(&req.base_url, scan_report);
    Ok(Json(report))
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

    #[test]
    fn api_error_is_structured() {
        let err = ApiError::from_anyhow(anyhow::anyhow!("boom"));
        assert_eq!(err.message, "boom");
    }
}
