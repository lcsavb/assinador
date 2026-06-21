//! Cliente HTTP de baixo nível para a API VIDaaS (portado do rx).
//!
//! O token de cliente (client_credentials) é buscado a cada chamada que o
//! exige — não há cache — de modo que todos os métodos usam `&self` e o cliente
//! é `Clone + Send + Sync`. Logs verbosos do rx foram enxugados.

use crate::config::VidaasConfig;
use crate::error::SigningError;
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct VidaasClient {
    client: reqwest::Client,
    config: VidaasConfig,
}

#[derive(Serialize)]
struct UserDiscoveryRequest {
    client_id: String,
    client_secret: String,
    user_cpf_cnpj: String,
    val_cpf_cnpj: bool,
}

#[derive(Deserialize)]
struct UserDiscoveryResponse {
    status: String, // "Y" = encontrado, "N" = não encontrado
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[allow(dead_code)]
    token_type: String,
    expires_in: u32,
}

impl VidaasClient {
    pub fn new(config: VidaasConfig) -> Self {
        Self { client: reqwest::Client::new(), config }
    }

    /// Busca um token de cliente (grant `client_credentials`).
    async fn fetch_client_token(&self) -> Result<String, SigningError> {
        let response = self
            .client
            .post(format!("{}/v0/oauth/client_token", self.config.base_url))
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", &self.config.client_id),
                ("client_secret", &self.config.client_secret),
            ])
            .send()
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, "VIDAAS client token request failed");
                SigningError::NetworkError
            })?;

        if !response.status().is_success() {
            return Err(SigningError::Unauthorized);
        }
        let token: TokenResponse = response
            .json()
            .await
            .map_err(|_| SigningError::BadRequest("Invalid token response format".to_string()))?;
        Ok(token.access_token)
    }

    /// Verifica se um CPF/CNPJ está habilitado no VIDaaS (`status == "Y"`).
    pub async fn discover_user(&self, cpf: &str) -> Result<bool, SigningError> {
        let client_token = self.fetch_client_token().await?;
        let response = self
            .client
            .post(format!("{}/v0/oauth/user-discovery", self.config.base_url))
            .bearer_auth(client_token)
            .json(&UserDiscoveryRequest {
                client_id: self.config.client_id.clone(),
                client_secret: self.config.client_secret.clone(),
                user_cpf_cnpj: cpf.to_string(),
                val_cpf_cnpj: true,
            })
            .send()
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, "VIDAAS user-discovery request failed");
                SigningError::NetworkError
            })?;

        if !response.status().is_success() {
            return Err(SigningError::BadRequest(format!(
                "User discovery failed: {}",
                response.status()
            )));
        }
        let body: UserDiscoveryResponse = response
            .json()
            .await
            .map_err(|_| SigningError::BadRequest("Invalid response format".to_string()))?;
        Ok(body.status == "Y")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn config_for(server: &MockServer) -> VidaasConfig {
        VidaasConfig {
            base_url: server.uri(),
            client_id: "cid".into(),
            client_secret: "secret".into(),
        }
    }

    #[tokio::test]
    async fn discover_user_returns_true_for_status_y() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v0/oauth/client_token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "ct", "token_type": "Bearer", "expires_in": 3600
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v0/oauth/user-discovery"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"status": "Y"})))
            .mount(&server)
            .await;

        let client = VidaasClient::new(config_for(&server));
        assert!(client.discover_user("12345678900").await.unwrap());
    }
}
