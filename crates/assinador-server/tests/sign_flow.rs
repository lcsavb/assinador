use std::sync::Arc;

use assinador::{VidaasConfig, VidaasSigner};
use assinador_server::app::{router, AppState};
use base64::Engine;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn spawn(base_url: &str) -> String {
    let state = AppState {
        signer: Arc::new(VidaasSigner::new(VidaasConfig {
            base_url: base_url.to_string(), client_id: "c".into(), client_secret: "s".into(),
        })),
        api_token: None,
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router(state)).await.unwrap(); });
    format!("http://{addr}")
}

#[tokio::test]
async fn sign_returns_base64_signed_pdf() {
    let vidaas = MockServer::start().await;
    // base64 of "%PDF-1.7\n" = "JVBERi0xLjcK"
    Mock::given(method("POST")).and(path("/v0/oauth/signatures"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "signatures": [{ "id": "d1", "raw_signature": "r", "file_base64_signed": "JVBERi0xLjcK" }],
            "certificate_alias": "alias" })))
        .mount(&vidaas).await;

    let base = spawn(&vidaas.uri()).await;
    let http = reqwest::Client::new();
    let pdf_b64 = base64::engine::general_purpose::STANDARD.encode(b"%PDF-1.7\n");

    let resp: serde_json::Value = http.post(format!("{base}/v1/sign"))
        .json(&serde_json::json!({
            "access_token": "at",
            "documents": [{ "id": "d1", "alias": "a", "pdf_base64": pdf_b64 }]
        }))
        .send().await.unwrap().json().await.unwrap();

    let signed_b64 = resp["signed"][0]["pdf_base64"].as_str().unwrap();
    let decoded = base64::engine::general_purpose::STANDARD.decode(signed_b64).unwrap();
    assert_eq!(&decoded[0..4], b"%PDF");
    assert_eq!(resp["signed"][0]["id"], "d1");
}

#[tokio::test]
async fn sign_rejects_invalid_base64() {
    let base = spawn("http://unused.invalid").await;
    let http = reqwest::Client::new();
    let resp = http.post(format!("{base}/v1/sign"))
        .json(&serde_json::json!({
            "access_token": "at",
            "documents": [{ "id": "d1", "alias": "a", "pdf_base64": "!!!notbase64!!!" }]
        }))
        .send().await.unwrap();
    assert_eq!(resp.status(), 400);
}
