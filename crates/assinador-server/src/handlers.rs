//! Handlers HTTP (preenchidos na task 11).

use crate::app::AppState;
use crate::error::ApiError;
use axum::extract::State;

pub async fn auth_start(State(_s): State<AppState>) -> Result<&'static str, ApiError> {
    Err(ApiError::bad_request("not implemented"))
}
pub async fn auth_poll(State(_s): State<AppState>) -> Result<&'static str, ApiError> {
    Err(ApiError::bad_request("not implemented"))
}
pub async fn auth_exchange(State(_s): State<AppState>) -> Result<&'static str, ApiError> {
    Err(ApiError::bad_request("not implemented"))
}
pub async fn sign(State(_s): State<AppState>) -> Result<&'static str, ApiError> {
    Err(ApiError::bad_request("not implemented"))
}
