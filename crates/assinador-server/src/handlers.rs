//! Handlers HTTP do microserviço (stateless).

use assinador::{Approval, DocumentSigningPort, UnsignedDocument};
use axum::extract::{Query, State};
use axum::Json;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::app::AppState;
use crate::error::ApiError;

#[derive(Deserialize)]
pub struct StartRequest {
    pub cpf: String,
}
#[derive(Serialize)]
pub struct StartResponse {
    pub code: String,
    pub verifier: String,
}

pub async fn auth_start(
    State(state): State<AppState>,
    Json(req): Json<StartRequest>,
) -> Result<Json<StartResponse>, ApiError> {
    let auth = state
        .signer
        .begin_authorization(&req.cpf)
        .await
        .map_err(ApiError::from_signing)?;
    Ok(Json(StartResponse { code: auth.code, verifier: auth.verifier }))
}

#[derive(Deserialize)]
pub struct PollQuery {
    pub code: String,
}
#[derive(Serialize)]
pub struct PollResponse {
    pub status: &'static str,
    /// Presente apenas quando `status == "approved"`. Deve ser enviado ao
    /// `/v1/auth/exchange`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_token: Option<String>,
}

pub async fn auth_poll(
    State(state): State<AppState>,
    Query(q): Query<PollQuery>,
) -> Result<Json<PollResponse>, ApiError> {
    let resp = match state.signer.poll(&q.code).await.map_err(ApiError::from_signing)? {
        Approval::Approved { authorization_token } => PollResponse {
            status: "approved",
            authorization_token: Some(authorization_token),
        },
        Approval::Pending => PollResponse { status: "pending", authorization_token: None },
    };
    Ok(Json(resp))
}

#[derive(Deserialize)]
pub struct ExchangeRequest {
    pub authorization_token: String,
    pub verifier: String,
}
#[derive(Serialize)]
pub struct ExchangeResponse {
    pub access_token: String,
    pub expires_in: u32,
}

pub async fn auth_exchange(
    State(state): State<AppState>,
    Json(req): Json<ExchangeRequest>,
) -> Result<Json<ExchangeResponse>, ApiError> {
    let token = state
        .signer
        .exchange(&req.authorization_token, &req.verifier)
        .await
        .map_err(ApiError::from_signing)?;
    Ok(Json(ExchangeResponse { access_token: token.value, expires_in: token.expires_in }))
}

#[derive(Deserialize)]
pub struct SignRequest {
    pub access_token: String,
    pub documents: Vec<SignDocIn>,
}
#[derive(Deserialize)]
pub struct SignDocIn {
    pub id: String,
    pub alias: String,
    pub pdf_base64: String,
}
#[derive(Serialize)]
pub struct SignResponse {
    pub signed: Vec<SignDocOut>,
}
#[derive(Serialize)]
pub struct SignDocOut {
    pub id: String,
    pub pdf_base64: String,
}

pub async fn sign(
    State(state): State<AppState>,
    Json(req): Json<SignRequest>,
) -> Result<Json<SignResponse>, ApiError> {
    let mut docs = Vec::with_capacity(req.documents.len());
    for d in req.documents {
        let pdf_bytes = base64::engine::general_purpose::STANDARD
            .decode(d.pdf_base64.as_bytes())
            .map_err(|e| ApiError::bad_request(format!("pdf_base64 inválido para '{}': {e}", d.id)))?;
        docs.push(UnsignedDocument { id: d.id, alias: d.alias, pdf_bytes });
    }

    let signed = state
        .signer
        .sign_documents(&req.access_token, docs)
        .await
        .map_err(ApiError::from_document)?;

    let out = signed
        .into_iter()
        .map(|s| SignDocOut {
            id: s.id,
            pdf_base64: base64::engine::general_purpose::STANDARD.encode(&s.signed_pdf_bytes),
        })
        .collect();
    Ok(Json(SignResponse { signed: out }))
}
