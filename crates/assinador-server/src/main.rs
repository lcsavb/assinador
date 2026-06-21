//! Microserviço HTTP que expõe a assinatura VIDaaS (stateless).

use std::sync::Arc;

use assinador::{VidaasConfig, VidaasSigner};
use assinador_server::app::{router, AppState};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let cfg = VidaasConfig::from_env()?;
    let state = AppState {
        signer: Arc::new(VidaasSigner::new(cfg)),
        api_token: std::env::var("ASSINADOR_API_TOKEN").ok(),
    };

    let addr = std::env::var("ASSINADOR_BIND").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("assinador-server ouvindo em {addr}");
    axum::serve(listener, router(state)).await?;
    Ok(())
}
