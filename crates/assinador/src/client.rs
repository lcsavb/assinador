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

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct PollAuthResponse {
    #[serde(rename = "authorizationToken")]
    pub authorization_token: Option<String>,
    #[serde(rename = "redirectUrl")]
    pub redirect_url: Option<String>,
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

    /// Inicia a autorização push (redirect_uri=push://). Dispara o aviso no
    /// celular do usuário e retorna o `code` de autorização a ser consultado.
    pub async fn create_push_authorization(
        &self,
        login_hint_cpf: &str,
        code_verifier: &str,
    ) -> Result<String, SigningError> {
        let client_token = self.fetch_client_token().await?;
        let challenge = crate::pkce::generate_pkce_challenge(code_verifier);
        // lifetime=604800 = 7 dias (validade do token).
        let url = format!(
            "{}/v0/oauth/authorize?client_id={}&code_challenge={}&code_challenge_method=S256&response_type=code&redirect_uri=push://&scope=signature_session&lifetime=604800&login_hint={}",
            self.config.base_url, self.config.client_id, challenge, login_hint_cpf
        );

        let response = self
            .client
            .get(url)
            .bearer_auth(client_token)
            .send()
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, "VIDAAS push authorization request failed");
                SigningError::NetworkError
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            return Err(SigningError::BadRequest(format!(
                "Push authorization failed: {status} - {body}"
            )));
        }

        // Resposta em texto: "code=d402d71c-...".
        let text = response
            .text()
            .await
            .map_err(|_| SigningError::BadRequest("Failed to read response".to_string()))?;
        text.strip_prefix("code=")
            .map(|c| c.to_string())
            .ok_or_else(|| {
                SigningError::BadRequest(format!(
                    "Invalid response format, expected 'code=...', got: {text}"
                ))
            })
    }

    /// Consulta o status da autorização. Retorna `(corpo, status_http)`.
    /// `200` = aprovado (token presente); `304` = ainda aguardando.
    pub async fn poll_authentication(
        &self,
        authorization_code: &str,
    ) -> Result<(PollAuthResponse, u16), SigningError> {
        let url = format!(
            "{}/valid/api/v1/trusted-services/authentications?code={}",
            self.config.base_url, authorization_code
        );
        let response = self.client.get(url).send().await.map_err(|e| {
            tracing::warn!(error = %e, "VIDAAS poll authentication request failed");
            SigningError::NetworkError
        })?;

        let status = response.status().as_u16();
        match status {
            200 => {
                let body = response.json().await.map_err(|_| {
                    SigningError::BadRequest("Invalid response format".to_string())
                })?;
                Ok((body, status))
            }
            304 => Ok((
                PollAuthResponse { authorization_token: None, redirect_url: None },
                status,
            )),
            _ => Err(SigningError::BadRequest(format!(
                "Authentication polling failed: {status}"
            ))),
        }
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

    #[tokio::test]
    async fn push_authorization_parses_code() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v0/oauth/client_token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "ct", "token_type": "Bearer", "expires_in": 3600
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v0/oauth/authorize"))
            .respond_with(ResponseTemplate::new(200).set_body_string("code=abc-123"))
            .mount(&server)
            .await;

        let client = VidaasClient::new(config_for(&server));
        let code = client.create_push_authorization("12345678900", "verifier").await.unwrap();
        assert_eq!(code, "abc-123");
    }

    #[tokio::test]
    async fn poll_pending_returns_304_with_none() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/valid/api/v1/trusted-services/authentications"))
            .respond_with(ResponseTemplate::new(304))
            .mount(&server)
            .await;

        let client = VidaasClient::new(config_for(&server));
        let (body, status) = client.poll_authentication("abc-123").await.unwrap();
        assert_eq!(status, 304);
        assert!(body.authorization_token.is_none());
    }

    #[tokio::test]
    async fn poll_approved_returns_token() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/valid/api/v1/trusted-services/authentications"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "authorizationToken": "tok", "redirectUrl": "push://done"
            })))
            .mount(&server)
            .await;

        let client = VidaasClient::new(config_for(&server));
        let (body, status) = client.poll_authentication("abc-123").await.unwrap();
        assert_eq!(status, 200);
        assert_eq!(body.authorization_token.as_deref(), Some("tok"));
    }
}
