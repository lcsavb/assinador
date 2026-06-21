//! Fachada VIDaaS: orquestra o fluxo completo (push → poll → exchange → sign).
//!
//! Os métodos de autenticação são específicos do VIDaaS; a assinatura é exposta
//! via `DocumentSigningPort` (delegada ao `VidaasSigningAdapter`).

use std::sync::Arc;

use async_trait::async_trait;

use crate::adapter::VidaasSigningAdapter;
use crate::client::VidaasClient;
use crate::config::VidaasConfig;
use crate::error::SigningError;
use crate::pkce::generate_code_verifier;
use crate::port::{DocumentSigningError, DocumentSigningPort, SignedDocument, UnsignedDocument};

/// Autorização push iniciada: `code` para consultar, `verifier` para o exchange.
pub struct PushAuthorization {
    pub code: String,
    pub verifier: String,
}

/// Estado da aprovação push.
pub enum Approval {
    Pending,
    Approved,
}

/// Token de acesso obtido no exchange (validade em segundos).
pub struct AccessToken {
    pub value: String,
    pub expires_in: u32,
}

pub struct VidaasSigner {
    client: Arc<VidaasClient>,
    adapter: VidaasSigningAdapter,
}

impl VidaasSigner {
    pub fn new(cfg: VidaasConfig) -> Self {
        let client = Arc::new(VidaasClient::new(cfg));
        let adapter = VidaasSigningAdapter::new(client.clone());
        Self { client, adapter }
    }

    /// Verifica se o CPF/CNPJ está habilitado no VIDaaS.
    pub async fn discover_user(&self, cpf: &str) -> Result<bool, SigningError> {
        self.client.discover_user(cpf).await
    }

    /// Passo 1 — dispara a autorização push no celular do usuário.
    pub async fn begin_authorization(&self, cpf: &str) -> Result<PushAuthorization, SigningError> {
        let verifier = generate_code_verifier();
        let code = self.client.create_push_authorization(cpf, &verifier).await?;
        Ok(PushAuthorization { code, verifier })
    }

    /// Passo 2 — consulta a aprovação. `Approved` quando o usuário confirma.
    pub async fn poll(&self, code: &str) -> Result<Approval, SigningError> {
        let (body, status) = self.client.poll_authentication(code).await?;
        if status == 200 && body.authorization_token.is_some() {
            Ok(Approval::Approved)
        } else {
            Ok(Approval::Pending)
        }
    }

    /// Passo 3 — troca o `code` (push) + `verifier` pelo access token.
    pub async fn exchange(&self, code: &str, verifier: &str) -> Result<AccessToken, SigningError> {
        let (value, expires_in) = self.client.exchange_code(code, verifier).await?;
        Ok(AccessToken { value, expires_in })
    }
}

#[async_trait]
impl DocumentSigningPort for VidaasSigner {
    async fn sign_documents(
        &self,
        access_token: &str,
        documents: Vec<UnsignedDocument>,
    ) -> Result<Vec<SignedDocument>, DocumentSigningError> {
        self.adapter.sign_documents(access_token, documents).await
    }

    fn provider_name(&self) -> &'static str {
        "VIDaaS"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn signer_for(server: &MockServer) -> VidaasSigner {
        VidaasSigner::new(VidaasConfig {
            base_url: server.uri(), client_id: "c".into(), client_secret: "s".into(),
        })
    }

    #[tokio::test]
    async fn poll_maps_304_to_pending() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/valid/api/v1/trusted-services/authentications"))
            .respond_with(ResponseTemplate::new(304))
            .mount(&server)
            .await;
        let signer = signer_for(&server);
        assert!(matches!(signer.poll("code").await.unwrap(), Approval::Pending));
    }

    #[tokio::test]
    async fn full_flow_begin_poll_exchange() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v0/oauth/client_token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "ct", "token_type": "Bearer", "expires_in": 3600
            })))
            .mount(&server).await;
        Mock::given(method("GET"))
            .and(path("/v0/oauth/authorize"))
            .respond_with(ResponseTemplate::new(200).set_body_string("code=push-code"))
            .mount(&server).await;
        Mock::given(method("GET"))
            .and(path("/valid/api/v1/trusted-services/authentications"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "authorizationToken": "tok", "redirectUrl": null
            })))
            .mount(&server).await;
        Mock::given(method("POST"))
            .and(path("/v0/oauth/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "final", "token_type": "Bearer", "expires_in": 604800
            })))
            .mount(&server).await;

        let signer = signer_for(&server);
        let auth = signer.begin_authorization("12345678900").await.unwrap();
        assert_eq!(auth.code, "push-code");
        assert!(matches!(signer.poll(&auth.code).await.unwrap(), Approval::Approved));
        let token = signer.exchange(&auth.code, &auth.verifier).await.unwrap();
        assert_eq!(token.value, "final");
        assert_eq!(token.expires_in, 604800);
    }
}
