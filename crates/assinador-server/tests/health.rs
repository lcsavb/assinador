use std::sync::Arc;

use assinador::{VidaasConfig, VidaasSigner};
use assinador_server::app::{router, AppState};

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
    tokio::spawn(async move {
        axum::serve(listener, router(state)).await.unwrap();
    });
    format!("http://{addr}")
}

#[tokio::test]
async fn health_returns_ok() {
    let base = spawn("http://unused.invalid").await;
    let resp = reqwest::get(format!("{base}/health")).await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "ok");
}
