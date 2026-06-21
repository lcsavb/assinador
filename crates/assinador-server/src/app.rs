//! Construção do app axum: estado compartilhado e rotas.

use std::sync::Arc;

use assinador::VidaasSigner;
use axum::routing::{get, post};
use axum::Router;

#[derive(Clone)]
pub struct AppState {
    pub signer: Arc<VidaasSigner>,
    pub api_token: Option<String>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/v1/auth/start", post(crate::handlers::auth_start))
        .route("/v1/auth/poll", get(crate::handlers::auth_poll))
        .route("/v1/auth/exchange", post(crate::handlers::auth_exchange))
        .route("/v1/sign", post(crate::handlers::sign))
        .with_state(state)
}
