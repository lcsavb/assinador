//! Mapeamento de erros da biblioteca para respostas HTTP JSON.

use assinador::{DocumentSigningError, SigningError};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub detail: String,
}

impl ApiError {
    pub fn from_signing(err: SigningError) -> Self {
        let (status, code) = match &err {
            SigningError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            SigningError::NetworkError => (StatusCode::BAD_GATEWAY, "network_error"),
            SigningError::ConfigError(_) => (StatusCode::INTERNAL_SERVER_ERROR, "config_error"),
            SigningError::ValidationError(_) => (StatusCode::UNPROCESSABLE_ENTITY, "validation_error"),
            SigningError::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request"),
        };
        Self { status, code, detail: err.to_string() }
    }

    pub fn from_document(err: DocumentSigningError) -> Self {
        let (status, code) = match &err {
            DocumentSigningError::AuthenticationError(_) => (StatusCode::UNAUTHORIZED, "unauthorized"),
            DocumentSigningError::NetworkError(_) => (StatusCode::BAD_GATEWAY, "network_error"),
            DocumentSigningError::InvalidSignedDocument(_) => (StatusCode::UNPROCESSABLE_ENTITY, "invalid_signed_document"),
            DocumentSigningError::ProviderError(_) => (StatusCode::BAD_REQUEST, "provider_error"),
        };
        Self { status, code, detail: err.to_string() }
    }

    pub fn bad_request(detail: impl Into<String>) -> Self {
        Self { status: StatusCode::BAD_REQUEST, code: "bad_request", detail: detail.into() }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "error": self.code, "detail": self.detail }))).into_response()
    }
}
