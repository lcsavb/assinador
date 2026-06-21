use std::sync::Arc;

use assinador::{VidaasConfig, VidaasSigner};
use assinador_server::app::{router, AppState};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn spawn(base_url: &str) -> String {
    let state = AppState {
        signer: Arc::new(VidaasSigner::new(VidaasConfig {
            base_url: base_url.to_string(),
            client_id: "c".into(),
            client_secret: "s".into(),
        })),
        api_token: None,
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router(state)).await.unwrap(); });
    format!("http://{addr}")
}

#[tokio::test]
async fn start_poll_exchange_round_trip() {
    let vidaas = MockServer::start().await;
    Mock::given(method("POST")).and(path("/v0/oauth/client_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "ct", "token_type": "Bearer", "expires_in": 3600 })))
        .mount(&vidaas).await;
    Mock::given(method("GET")).and(path("/v0/oauth/authorize"))
        .respond_with(ResponseTemplate::new(200).set_body_string("code=push-code"))
        .mount(&vidaas).await;
    Mock::given(method("GET")).and(path("/valid/api/v1/trusted-services/authentications"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "authorizationToken": "tok", "redirectUrl": null })))
        .mount(&vidaas).await;
    Mock::given(method("POST")).and(path("/v0/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "final", "token_type": "Bearer", "expires_in": 604800 })))
        .mount(&vidaas).await;

    let base = spawn(&vidaas.uri()).await;
    let http = reqwest::Client::new();

    let start: serde_json::Value = http.post(format!("{base}/v1/auth/start"))
        .json(&serde_json::json!({ "cpf": "12345678900" }))
        .send().await.unwrap().json().await.unwrap();
    assert_eq!(start["code"], "push-code");
    let verifier = start["verifier"].as_str().unwrap().to_string();

    let poll: serde_json::Value = http.get(format!("{base}/v1/auth/poll?code=push-code"))
        .send().await.unwrap().json().await.unwrap();
    assert_eq!(poll["status"], "approved");
    assert_eq!(poll["authorization_token"], "tok");

    let exchange: serde_json::Value = http.post(format!("{base}/v1/auth/exchange"))
        .json(&serde_json::json!({ "authorization_token": "tok", "verifier": verifier }))
        .send().await.unwrap().json().await.unwrap();
    assert_eq!(exchange["access_token"], "final");
    assert_eq!(exchange["expires_in"], 604800);
}
