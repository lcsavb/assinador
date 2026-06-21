# Assinador — VIDaaS PDF Signing Crate + HTTP Service Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract `rx`'s duplicated VIDaaS signing logic into a standalone, reusable Rust crate (`assinador`) and wrap it in a thin stateless HTTP microservice (`assinador-server`) callable from any language.

**Architecture:** A Cargo workspace with a pure-Rust library (zero web deps) exposing the full VIDaaS auth+sign flow behind a `VidaasSigner` facade and a kept `DocumentSigningPort` trait, plus an axum microservice that maps the flow 1:1 onto stateless HTTP endpoints (PDFs as base64). The library does **no** PDF metadata injection and does **no** token storage.

**Tech Stack:** Rust, `reqwest` (rustls), `serde`/`serde_json`, `base64`, `sha2`, `rand` 0.8, `thiserror`, `async-trait`, `tracing`; server adds `axum` + `tokio`; tests use `wiremock`.

## Delivery in Two Parts

This plan ships in two independently-deliverable parts. **Build Part 1 first; Part 2 builds on the finished crate.**

- **Part 1 — Library crate (`assinador`): Tasks 1–9.** A complete, tested, usable Rust crate. At the end of Part 1 the workspace contains only the library, and `cargo test -p assinador` is fully green. This is the user's "first step: create the Rust crate."
- **Part 2 — HTTP microservice (`assinador-server`): Tasks 10–13.** Adds the axum service as a *second* workspace member wrapping the crate, plus the project READMEs. (The library's own README, Task 13 Step 2, may be pulled forward into Part 1 if desired — it has no code dependency.)

Each part ends with a green test suite and is reviewable on its own.

## Global Constraints

- `/home/lucas/code/rx` and any `examples/` directory are **READ-ONLY**. Never modify them. They are the extraction source only.
- Error messages in the library are **Portuguese (pt-BR)**, copied verbatim from `rx`'s `SigningError`.
- The `DocumentSigningPort` trait is **retained** (multi-provider headroom).
- **No** PDF metadata injection in the crate. **No** token persistence/encryption. **No** database. **No** FFI.
- VIDaaS signing constants are fixed: hash algorithm OID `2.16.840.1.101.3.4.2.1` (SHA-256), `signature_format = "PAdES_AD_RB"`, `pdf_signature_page = Some(false)`.
- The VIDaaS `exchange` call uses the **`authorization_token` returned by polling** + the PKCE `verifier` (NOT the original push `code`, which is used only to poll). **[CORRECTED 2026-06-21 by a live test against production VIDaaS — the original plan guessed the push code and got `invalid_grant`. See `docs/rust-learning-notes.md` Task 14.]**
- Default VIDaaS base URL: `https://certificado.vidaas.com.br`.
- All `VidaasClient` methods take `&self` (client token is fetched inline per call, not cached) so the client is `Clone + Send + Sync` behind `Arc`.
- Co-author trailer on every commit: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`

---

## PART 1 — Library crate (`assinador`)

### Task 1: Workspace + library scaffold (config + error)

**Files:**
- Create: `Cargo.toml` (workspace root)
- Create: `crates/assinador/Cargo.toml`
- Create: `crates/assinador/src/lib.rs`
- Create: `crates/assinador/src/error.rs`
- Create: `crates/assinador/src/config.rs`

**Interfaces:**
- Produces: `SigningError` enum (variants `ConfigError(String)`, `NetworkError`, `BadRequest(String)`, `ValidationError(String)`, `Unauthorized`); `VidaasConfig { base_url: String, client_id: String, client_secret: String }` with `VidaasConfig::from_env() -> Result<VidaasConfig, SigningError>`.

- [ ] **Step 1: Create the workspace root `Cargo.toml`**

```toml
[workspace]
resolver = "2"
# Part 1 ships the library only. Part 2 (Task 10) adds "crates/assinador-server".
members = ["crates/assinador"]

[workspace.package]
edition = "2021"
license = "MIT"

[workspace.dependencies]
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
thiserror = "2.0"
async-trait = "0.1"
tracing = "0.1"
base64 = "0.22"
sha2 = "0.10"
rand = "0.8"
reqwest = { version = "0.12", default-features = false, features = ["json", "rustls-tls"] }
tokio = { version = "1", features = ["full"] }
wiremock = "0.6"
```

- [ ] **Step 2: Create `crates/assinador/Cargo.toml`**

```toml
[package]
name = "assinador"
version = "0.1.0"
edition.workspace = true
license.workspace = true
description = "Assinatura digital de PDFs via VIDaaS (ICP-Brasil)."

[dependencies]
serde.workspace = true
serde_json.workspace = true
thiserror.workspace = true
async-trait.workspace = true
tracing.workspace = true
base64.workspace = true
sha2.workspace = true
rand.workspace = true
reqwest.workspace = true

[dev-dependencies]
tokio.workspace = true
wiremock.workspace = true
```

- [ ] **Step 3: Write the failing test for `VidaasConfig::from_env`**

Create `crates/assinador/src/config.rs`:

```rust
//! Configuração de acesso à API VIDaaS.

use crate::error::SigningError;

/// Credenciais e endpoint da API VIDaaS.
#[derive(Debug, Clone)]
pub struct VidaasConfig {
    pub base_url: String,
    pub client_id: String,
    pub client_secret: String,
}

impl VidaasConfig {
    /// Lê `VIDAAS_BASE_URL` (opcional), `VIDAAS_CLIENT_ID` e
    /// `VIDAAS_CLIENT_SECRET` do ambiente.
    pub fn from_env() -> Result<Self, SigningError> {
        let base_url = std::env::var("VIDAAS_BASE_URL")
            .unwrap_or_else(|_| "https://certificado.vidaas.com.br".to_string());
        let client_id = std::env::var("VIDAAS_CLIENT_ID")
            .map_err(|_| SigningError::ConfigError("VIDAAS_CLIENT_ID not set".to_string()))?;
        let client_secret = std::env::var("VIDAAS_CLIENT_SECRET")
            .map_err(|_| SigningError::ConfigError("VIDAAS_CLIENT_SECRET not set".to_string()))?;
        Ok(Self { base_url, client_id, client_secret })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_env_errors_without_client_id() {
        // SAFETY: single-threaded test; ensure the var is absent.
        std::env::remove_var("VIDAAS_CLIENT_ID");
        std::env::remove_var("VIDAAS_CLIENT_SECRET");
        let err = VidaasConfig::from_env().unwrap_err();
        assert!(matches!(err, SigningError::ConfigError(_)));
    }
}
```

- [ ] **Step 4: Write `crates/assinador/src/error.rs`**

```rust
//! Erro próprio dos clientes de assinatura ICP-Brasil (portado do rx).

use thiserror::Error;

#[derive(Debug, Clone, Error)]
pub enum SigningError {
    #[error("Erro de configuração da assinatura: {0}")]
    ConfigError(String),
    #[error("Erro de comunicação com o provedor de assinatura")]
    NetworkError,
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    ValidationError(String),
    #[error("Não autorizado pelo provedor de assinatura")]
    Unauthorized,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn displays_portuguese_messages() {
        assert_eq!(
            SigningError::Unauthorized.to_string(),
            "Não autorizado pelo provedor de assinatura"
        );
        assert_eq!(
            SigningError::BadRequest("hash inválido".into()).to_string(),
            "hash inválido"
        );
    }
}
```

- [ ] **Step 5: Write `crates/assinador/src/lib.rs`**

```rust
//! Assinatura digital de PDFs via VIDaaS (ICP-Brasil).

pub mod config;
pub mod error;

pub use config::VidaasConfig;
pub use error::SigningError;
```

- [ ] **Step 6: Run tests — verify they pass**

Run: `cargo test -p assinador`
Expected: PASS (`from_env_errors_without_client_id`, `displays_portuguese_messages`).

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml crates/assinador
git commit -m "feat: workspace + assinador config/error scaffold

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: PKCE helpers

**Files:**
- Create: `crates/assinador/src/pkce.rs`
- Modify: `crates/assinador/src/lib.rs`

**Interfaces:**
- Produces: `pub fn generate_code_verifier() -> String` (43-char unreserved-charset string); `pub(crate) fn generate_pkce_challenge(verifier: &str) -> String` (base64url-no-pad SHA-256 of the verifier).

- [ ] **Step 1: Write the failing test**

Create `crates/assinador/src/pkce.rs`:

```rust
//! PKCE (RFC 7636) — verifier e desafio S256 para o fluxo VIDaaS.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use sha2::{Digest, Sha256};

/// Gera um `code_verifier` de 43 caracteres do conjunto não reservado.
pub fn generate_code_verifier() -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    let mut rng = rand::thread_rng();
    (0..43)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

/// Calcula o desafio S256 (base64url sem padding do SHA-256 do verifier).
pub(crate) fn generate_pkce_challenge(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier);
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifier_is_43_chars_and_unreserved() {
        let v = generate_code_verifier();
        assert_eq!(v.len(), 43);
        assert!(v.chars().all(|c| c.is_ascii_alphanumeric() || "-._~".contains(c)));
    }

    #[test]
    fn challenge_matches_known_vector() {
        // RFC 7636 Appendix B vector.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert_eq!(
            generate_pkce_challenge(verifier),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }
}
```

- [ ] **Step 2: Register the module in `lib.rs`**

Add to `crates/assinador/src/lib.rs`:

```rust
pub mod pkce;

pub use pkce::generate_code_verifier;
```

- [ ] **Step 3: Run tests — verify they pass**

Run: `cargo test -p assinador pkce`
Expected: PASS (both tests; the RFC vector confirms the S256 encoding is correct).

- [ ] **Step 4: Commit**

```bash
git add crates/assinador/src/pkce.rs crates/assinador/src/lib.rs
git commit -m "feat: PKCE verifier + S256 challenge

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Low-level VidaasClient — client token + user discovery

**Files:**
- Create: `crates/assinador/src/client.rs`
- Modify: `crates/assinador/src/lib.rs`

**Interfaces:**
- Consumes: `VidaasConfig`, `SigningError`.
- Produces: `pub struct VidaasClient` with `pub fn new(config: VidaasConfig) -> Self`, `async fn fetch_client_token(&self) -> Result<String, SigningError>` (crate-private), `pub async fn discover_user(&self, cpf: &str) -> Result<bool, SigningError>`. Also the (de)serialization structs `DocumentForSignature`, `SignatureResponse`, `SignatureResult`, `PollAuthResponse` (added across Tasks 3–5).

- [ ] **Step 1: Write the failing wiremock test**

Create `crates/assinador/src/client.rs`:

```rust
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
```

- [ ] **Step 2: Register the module in `lib.rs`**

Add to `crates/assinador/src/lib.rs`:

```rust
pub mod client;

pub use client::VidaasClient;
```

- [ ] **Step 3: Run the test — verify it passes**

Run: `cargo test -p assinador client`
Expected: PASS (`discover_user_returns_true_for_status_y`).

- [ ] **Step 4: Commit**

```bash
git add crates/assinador/src/client.rs crates/assinador/src/lib.rs
git commit -m "feat: VidaasClient client-token + user discovery

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: VidaasClient — push authorization + polling

**Files:**
- Modify: `crates/assinador/src/client.rs`

**Interfaces:**
- Consumes: `generate_pkce_challenge` from `pkce`.
- Produces: `pub async fn create_push_authorization(&self, login_hint_cpf: &str, code_verifier: &str) -> Result<String, SigningError>` (returns the authorization `code`); `pub async fn poll_authentication(&self, code: &str) -> Result<(PollAuthResponse, u16), SigningError>`; `pub struct PollAuthResponse { authorization_token: Option<String>, redirect_url: Option<String> }`.

- [ ] **Step 1: Add the structs + methods to `client.rs`**

Add near the top (after `TokenResponse`):

```rust
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct PollAuthResponse {
    #[serde(rename = "authorizationToken")]
    pub authorization_token: Option<String>,
    #[serde(rename = "redirectUrl")]
    pub redirect_url: Option<String>,
}
```

Add inside `impl VidaasClient`:

```rust
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
```

- [ ] **Step 2: Add the failing wiremock tests**

Add to the `tests` module in `client.rs`:

```rust
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
```

- [ ] **Step 3: Run the tests — verify they pass**

Run: `cargo test -p assinador client`
Expected: PASS (push + both poll tests, plus Task 3's test).

- [ ] **Step 4: Commit**

```bash
git add crates/assinador/src/client.rs
git commit -m "feat: VidaasClient push authorization + polling

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: VidaasClient — code exchange + batch signing

**Files:**
- Modify: `crates/assinador/src/client.rs`

**Interfaces:**
- Produces: `pub async fn exchange_code(&self, code: &str, verifier: &str) -> Result<(String, u32), SigningError>` (returns `(access_token, expires_in)`); `pub async fn sign_documents(&self, user_token: &str, documents: Vec<DocumentForSignature>) -> Result<SignatureResponse, SigningError>`; public structs `DocumentForSignature`, `SignatureResponse`, `SignatureResult`, `SignatureRequest`.

- [ ] **Step 1: Add the structs to `client.rs`**

Add after `PollAuthResponse`:

```rust
#[derive(Serialize)]
struct SignatureRequest {
    hashes: Vec<DocumentForSignature>,
}

#[derive(Serialize, Clone)]
pub struct DocumentForSignature {
    pub id: String,
    pub alias: String,
    pub hash: String,
    pub hash_algorithm: String,
    pub signature_format: String,
    pub base64_content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pdf_signature_page: Option<bool>,
}

#[derive(Deserialize, Clone)]
pub struct SignatureResponse {
    pub signatures: Vec<SignatureResult>,
    pub certificate_alias: String,
}

#[derive(Deserialize, Clone)]
pub struct SignatureResult {
    pub id: String,
    pub raw_signature: String,
    #[serde(default)]
    pub file_base64_signed: String,
}
```

- [ ] **Step 2: Add the methods inside `impl VidaasClient`**

```rust
    /// Troca o `code` de autorização (push) + `verifier` PKCE pelo access token.
    /// Retorna `(access_token, expires_in_segundos)`.
    pub async fn exchange_code(
        &self,
        code: &str,
        verifier: &str,
    ) -> Result<(String, u32), SigningError> {
        let response = self
            .client
            .post(format!("{}/v0/oauth/token", self.config.base_url))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("code_verifier", verifier),
                ("client_id", &self.config.client_id),
                ("client_secret", &self.config.client_secret),
            ])
            .send()
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, "VIDAAS token exchange request failed");
                SigningError::NetworkError
            })?;

        if !response.status().is_success() {
            return Err(SigningError::BadRequest(format!(
                "Token exchange failed: {}",
                response.status()
            )));
        }
        let token: TokenResponse = response
            .json()
            .await
            .map_err(|_| SigningError::BadRequest("Invalid token response format".to_string()))?;
        Ok((token.access_token, token.expires_in))
    }

    /// Assina um lote de documentos. O `user_token` deve ter sido obtido pelo
    /// fluxo OAuth (exchange). VIDaaS aceita múltiplos itens em `hashes`.
    pub async fn sign_documents(
        &self,
        user_token: &str,
        documents: Vec<DocumentForSignature>,
    ) -> Result<SignatureResponse, SigningError> {
        if documents.is_empty() {
            return Err(SigningError::ValidationError(
                "Cannot sign empty document list".to_string(),
            ));
        }

        let request = SignatureRequest { hashes: documents };
        let response = self
            .client
            .post(format!("{}/v0/oauth/signatures", self.config.base_url))
            .bearer_auth(user_token)
            .json(&request)
            .send()
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, "VIDAAS signature request failed");
                SigningError::NetworkError
            })?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_else(|_| "Unable to read error response".to_string());
            return Err(SigningError::BadRequest(format!(
                "Document signature failed: {} (Status: {})",
                if body.len() < 100 { body } else { "See logs for details".to_string() },
                status.as_u16()
            )));
        }

        response.json().await.map_err(|e| {
            tracing::warn!(error = %e, "VIDAAS signature response parse failed");
            SigningError::BadRequest("Invalid signature response format".to_string())
        })
    }
```

- [ ] **Step 3: Add the failing wiremock tests**

Add to the `tests` module in `client.rs`:

```rust
    #[tokio::test]
    async fn exchange_code_returns_access_token() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v0/oauth/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "at", "token_type": "Bearer", "expires_in": 604800
            })))
            .mount(&server)
            .await;

        let client = VidaasClient::new(config_for(&server));
        let (token, expires) = client.exchange_code("code", "verifier").await.unwrap();
        assert_eq!(token, "at");
        assert_eq!(expires, 604800);
    }

    #[tokio::test]
    async fn sign_documents_rejects_empty_list() {
        let server = MockServer::start().await;
        let client = VidaasClient::new(config_for(&server));
        let err = client.sign_documents("at", vec![]).await.unwrap_err();
        assert!(matches!(err, SigningError::ValidationError(_)));
    }

    #[tokio::test]
    async fn sign_documents_parses_signatures() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v0/oauth/signatures"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "signatures": [{ "id": "d1", "raw_signature": "r", "file_base64_signed": "JVBERi0=" }],
                "certificate_alias": "alias"
            })))
            .mount(&server)
            .await;

        let client = VidaasClient::new(config_for(&server));
        let doc = DocumentForSignature {
            id: "d1".into(), alias: "a".into(), hash: "h".into(),
            hash_algorithm: "2.16.840.1.101.3.4.2.1".into(),
            signature_format: "PAdES_AD_RB".into(),
            base64_content: "JVBERi0=".into(), pdf_signature_page: Some(false),
        };
        let resp = client.sign_documents("at", vec![doc]).await.unwrap();
        assert_eq!(resp.signatures.len(), 1);
        assert_eq!(resp.signatures[0].id, "d1");
    }
```

- [ ] **Step 4: Run the tests — verify they pass**

Run: `cargo test -p assinador client`
Expected: PASS (exchange + empty-list + parse tests, plus prior tests).

- [ ] **Step 5: Commit**

```bash
git add crates/assinador/src/client.rs
git commit -m "feat: VidaasClient code exchange + batch signing

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: Signing port (trait + DTOs + error)

**Files:**
- Create: `crates/assinador/src/port.rs`
- Modify: `crates/assinador/src/lib.rs`

**Interfaces:**
- Produces: `pub struct UnsignedDocument { id: String, alias: String, pdf_bytes: Vec<u8> }`; `pub struct SignedDocument { id: String, signed_pdf_bytes: Vec<u8> }`; `pub enum DocumentSigningError { ProviderError(String), InvalidSignedDocument(String), NetworkError(String), AuthenticationError(String) }` (impls `Display` + `Error`); `#[async_trait] pub trait DocumentSigningPort: Send + Sync { async fn sign_documents(&self, access_token: &str, documents: Vec<UnsignedDocument>) -> Result<Vec<SignedDocument>, DocumentSigningError>; fn provider_name(&self) -> &'static str; }`.

- [ ] **Step 1: Write `crates/assinador/src/port.rs` (ported verbatim from rx)**

```rust
//! Porta de assinatura de documentos (interface da camada de aplicação).
//!
//! Abstrai a assinatura digital entre provedores (VIDaaS, SafeWeb…).

use async_trait::async_trait;

/// Documento a ser assinado.
pub struct UnsignedDocument {
    pub id: String,
    pub alias: String,
    pub pdf_bytes: Vec<u8>,
}

/// Resultado assinado.
pub struct SignedDocument {
    pub id: String,
    pub signed_pdf_bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum DocumentSigningError {
    ProviderError(String),
    InvalidSignedDocument(String),
    NetworkError(String),
    AuthenticationError(String),
}

impl std::fmt::Display for DocumentSigningError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProviderError(msg) => write!(f, "Signing provider error: {msg}"),
            Self::InvalidSignedDocument(msg) => write!(f, "Invalid signed document: {msg}"),
            Self::NetworkError(msg) => write!(f, "Network error: {msg}"),
            Self::AuthenticationError(msg) => write!(f, "Authentication error: {msg}"),
        }
    }
}

impl std::error::Error for DocumentSigningError {}

#[async_trait]
pub trait DocumentSigningPort: Send + Sync {
    /// Assina um ou mais PDFs. Retorna os documentos assinados na mesma ordem.
    async fn sign_documents(
        &self,
        access_token: &str,
        documents: Vec<UnsignedDocument>,
    ) -> Result<Vec<SignedDocument>, DocumentSigningError>;

    /// Nome do provedor (ex.: "VIDaaS") para trilha de auditoria.
    fn provider_name(&self) -> &'static str;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_is_human_readable() {
        assert_eq!(
            DocumentSigningError::ProviderError("boom".into()).to_string(),
            "Signing provider error: boom"
        );
    }
}
```

- [ ] **Step 2: Register the module in `lib.rs`**

Add:

```rust
pub mod port;

pub use port::{DocumentSigningError, DocumentSigningPort, SignedDocument, UnsignedDocument};
```

- [ ] **Step 3: Run the test — verify it passes**

Run: `cargo test -p assinador port`
Expected: PASS (`error_display_is_human_readable`).

- [ ] **Step 4: Commit**

```bash
git add crates/assinador/src/port.rs crates/assinador/src/lib.rs
git commit -m "feat: DocumentSigningPort trait + DTOs

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 7: VIDaaS signing adapter

**Files:**
- Create: `crates/assinador/src/adapter.rs`
- Modify: `crates/assinador/src/lib.rs`

**Interfaces:**
- Consumes: `VidaasClient`, `DocumentForSignature`, `SignatureResult`, port types.
- Produces: `pub struct VidaasSigningAdapter` with `pub fn new(client: std::sync::Arc<VidaasClient>) -> Self`; impls `DocumentSigningPort` (`provider_name()` returns `"VIDaaS"`). Private helpers `prepare_document` and `decode_signed_pdf` are exercised through `sign_documents`.

- [ ] **Step 1: Write `crates/assinador/src/adapter.rs` (ported from rx)**

```rust
//! Adaptador de assinatura VIDaaS — implementa `DocumentSigningPort`.
//!
//! Faz hash SHA-256, base64, requisição em lote, casamento por id e
//! decodificação/validação do PDF assinado.

use async_trait::async_trait;
use base64::Engine;
use sha2::Digest;
use std::sync::Arc;

use crate::client::{DocumentForSignature, SignatureResult, VidaasClient};
use crate::port::{DocumentSigningError, DocumentSigningPort, SignedDocument, UnsignedDocument};

pub struct VidaasSigningAdapter {
    client: Arc<VidaasClient>,
}

impl VidaasSigningAdapter {
    pub fn new(client: Arc<VidaasClient>) -> Self {
        Self { client }
    }

    fn prepare_document(doc: &UnsignedDocument) -> DocumentForSignature {
        let mut hasher = sha2::Sha256::new();
        hasher.update(&doc.pdf_bytes);
        let hash_bytes = hasher.finalize();
        let pdf_hash_b64 = base64::engine::general_purpose::STANDARD.encode(hash_bytes);
        let pdf_base64_content = base64::engine::general_purpose::STANDARD.encode(&doc.pdf_bytes);

        DocumentForSignature {
            id: doc.id.clone(),
            alias: doc.alias.clone(),
            hash: pdf_hash_b64,
            hash_algorithm: "2.16.840.1.101.3.4.2.1".to_string(), // SHA-256 OID
            signature_format: "PAdES_AD_RB".to_string(),
            base64_content: pdf_base64_content,
            pdf_signature_page: Some(false),
        }
    }

    fn decode_signed_pdf(
        signature: &SignatureResult,
        doc_type: &str,
    ) -> Result<Vec<u8>, DocumentSigningError> {
        if signature.file_base64_signed.is_empty() {
            return Err(DocumentSigningError::InvalidSignedDocument(format!(
                "VIDaaS did not return a signed {doc_type} PDF"
            )));
        }
        let cleaned = signature.file_base64_signed.replace("\r\n", "").replace('\n', "");
        let signed_bytes = base64::engine::general_purpose::STANDARD
            .decode(&cleaned)
            .map_err(|e| {
                DocumentSigningError::InvalidSignedDocument(format!(
                    "Failed to decode signed {doc_type} PDF: {e}"
                ))
            })?;
        if signed_bytes.len() < 4 || &signed_bytes[0..4] != b"%PDF" {
            return Err(DocumentSigningError::InvalidSignedDocument(format!(
                "VIDaaS returned invalid {doc_type} PDF"
            )));
        }
        Ok(signed_bytes)
    }
}

#[async_trait]
impl DocumentSigningPort for VidaasSigningAdapter {
    async fn sign_documents(
        &self,
        access_token: &str,
        documents: Vec<UnsignedDocument>,
    ) -> Result<Vec<SignedDocument>, DocumentSigningError> {
        if documents.is_empty() {
            return Ok(vec![]);
        }
        let vidaas_docs: Vec<DocumentForSignature> =
            documents.iter().map(Self::prepare_document).collect();
        let doc_ids: Vec<String> = documents.iter().map(|d| d.id.clone()).collect();

        let response = self
            .client
            .sign_documents(access_token, vidaas_docs)
            .await
            .map_err(|e| DocumentSigningError::ProviderError(e.to_string()))?;

        if response.signatures.len() != documents.len() {
            return Err(DocumentSigningError::ProviderError(format!(
                "Expected {} signatures from VIDaaS, got {}",
                documents.len(),
                response.signatures.len()
            )));
        }

        let mut signed_docs = Vec::with_capacity(documents.len());
        for expected_id in &doc_ids {
            let signature = response
                .signatures
                .iter()
                .find(|s| &s.id == expected_id)
                .ok_or_else(|| {
                    DocumentSigningError::ProviderError(format!(
                        "VIDaaS response missing signature for document '{expected_id}'"
                    ))
                })?;
            let signed_bytes = Self::decode_signed_pdf(signature, expected_id)?;
            signed_docs.push(SignedDocument {
                id: expected_id.clone(),
                signed_pdf_bytes: signed_bytes,
            });
        }
        Ok(signed_docs)
    }

    fn provider_name(&self) -> &'static str {
        "VIDaaS"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::VidaasConfig;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn signs_and_decodes_pdf() {
        let server = MockServer::start().await;
        // base64 of "%PDF-1.7\n" = "JVBERi0xLjcK"
        Mock::given(method("POST"))
            .and(path("/v0/oauth/signatures"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "signatures": [{ "id": "d1", "raw_signature": "r", "file_base64_signed": "JVBERi0xLjcK" }],
                "certificate_alias": "alias"
            })))
            .mount(&server)
            .await;

        let client = Arc::new(VidaasClient::new(VidaasConfig {
            base_url: server.uri(), client_id: "c".into(), client_secret: "s".into(),
        }));
        let adapter = VidaasSigningAdapter::new(client);
        let signed = adapter
            .sign_documents("at", vec![UnsignedDocument {
                id: "d1".into(), alias: "a".into(), pdf_bytes: b"%PDF-1.7\n".to_vec(),
            }])
            .await
            .unwrap();
        assert_eq!(signed.len(), 1);
        assert_eq!(&signed[0].signed_pdf_bytes[0..4], b"%PDF");
    }

    #[tokio::test]
    async fn rejects_non_pdf_signed_bytes() {
        let server = MockServer::start().await;
        // base64 of "notpdf" = "bm90cGRm"
        Mock::given(method("POST"))
            .and(path("/v0/oauth/signatures"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "signatures": [{ "id": "d1", "raw_signature": "r", "file_base64_signed": "bm90cGRm" }],
                "certificate_alias": "alias"
            })))
            .mount(&server)
            .await;

        let client = Arc::new(VidaasClient::new(VidaasConfig {
            base_url: server.uri(), client_id: "c".into(), client_secret: "s".into(),
        }));
        let adapter = VidaasSigningAdapter::new(client);
        let err = adapter
            .sign_documents("at", vec![UnsignedDocument {
                id: "d1".into(), alias: "a".into(), pdf_bytes: b"%PDF-1.7\n".to_vec(),
            }])
            .await
            .unwrap_err();
        assert!(matches!(err, DocumentSigningError::InvalidSignedDocument(_)));
    }
}
```

- [ ] **Step 2: Register the module in `lib.rs`**

Add:

```rust
pub mod adapter;

pub use adapter::VidaasSigningAdapter;
```

- [ ] **Step 3: Run the tests — verify they pass**

Run: `cargo test -p assinador adapter`
Expected: PASS (`signs_and_decodes_pdf`, `rejects_non_pdf_signed_bytes`).

- [ ] **Step 4: Commit**

```bash
git add crates/assinador/src/adapter.rs crates/assinador/src/lib.rs
git commit -m "feat: VidaasSigningAdapter (hash/batch/decode/validate)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 8: Signing dispatcher

**Files:**
- Create: `crates/assinador/src/dispatcher.rs`
- Modify: `crates/assinador/src/lib.rs`

**Interfaces:**
- Consumes: `DocumentSigningPort`, `DocumentSigningError`.
- Produces: `pub struct SigningDispatcher` with `pub fn new(vidaas: Arc<dyn DocumentSigningPort>) -> Self` and `pub fn get_signer(&self, provider: &str) -> Result<&Arc<dyn DocumentSigningPort>, DocumentSigningError>` (matches `"vidaas"`).

- [ ] **Step 1: Write `crates/assinador/src/dispatcher.rs` (ported from rx)**

```rust
//! Despachante de assinatura — roteia para o adaptador do provedor correto.

use std::sync::Arc;

use crate::port::{DocumentSigningError, DocumentSigningPort};

pub struct SigningDispatcher {
    vidaas: Arc<dyn DocumentSigningPort>,
}

impl SigningDispatcher {
    pub fn new(vidaas: Arc<dyn DocumentSigningPort>) -> Self {
        Self { vidaas }
    }

    pub fn get_signer(
        &self,
        provider: &str,
    ) -> Result<&Arc<dyn DocumentSigningPort>, DocumentSigningError> {
        match provider {
            "vidaas" => Ok(&self.vidaas),
            _ => Err(DocumentSigningError::ProviderError(format!(
                "Provedor de certificado desconhecido: {provider}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::port::{SignedDocument, UnsignedDocument};
    use async_trait::async_trait;

    struct StubSigner(&'static str);

    #[async_trait]
    impl DocumentSigningPort for StubSigner {
        async fn sign_documents(
            &self,
            _access_token: &str,
            _documents: Vec<UnsignedDocument>,
        ) -> Result<Vec<SignedDocument>, DocumentSigningError> {
            Ok(vec![])
        }
        fn provider_name(&self) -> &'static str {
            self.0
        }
    }

    fn dispatcher() -> SigningDispatcher {
        SigningDispatcher::new(Arc::new(StubSigner("VIDaaS")))
    }

    #[test]
    fn routes_known_provider() {
        let d = dispatcher();
        assert_eq!(d.get_signer("vidaas").unwrap().provider_name(), "VIDaaS");
    }

    #[test]
    fn rejects_unknown_provider() {
        let d = dispatcher();
        match d.get_signer("bogus") {
            Err(DocumentSigningError::ProviderError(_)) => {}
            _ => panic!("expected ProviderError for unknown provider"),
        }
    }
}
```

- [ ] **Step 2: Register the module in `lib.rs`**

Add:

```rust
pub mod dispatcher;

pub use dispatcher::SigningDispatcher;
```

- [ ] **Step 3: Run the tests — verify they pass**

Run: `cargo test -p assinador dispatcher`
Expected: PASS (`routes_known_provider`, `rejects_unknown_provider`).

- [ ] **Step 4: Commit**

```bash
git add crates/assinador/src/dispatcher.rs crates/assinador/src/lib.rs
git commit -m "feat: SigningDispatcher provider routing

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 9: VidaasSigner facade (full flow)

**Files:**
- Create: `crates/assinador/src/signer.rs`
- Modify: `crates/assinador/src/lib.rs`

**Interfaces:**
- Consumes: `VidaasConfig`, `VidaasClient`, `VidaasSigningAdapter`, `generate_code_verifier`, port types.
- Produces: `pub struct VidaasSigner` with `pub fn new(cfg: VidaasConfig) -> Self`, `pub async fn discover_user(&self, cpf: &str) -> Result<bool, SigningError>`, `pub async fn begin_authorization(&self, cpf: &str) -> Result<PushAuthorization, SigningError>`, `pub async fn poll(&self, code: &str) -> Result<Approval, SigningError>`, `pub async fn exchange(&self, code: &str, verifier: &str) -> Result<AccessToken, SigningError>`; impls `DocumentSigningPort`. Plus `pub struct PushAuthorization { code: String, verifier: String }`, `pub enum Approval { Pending, Approved }`, `pub struct AccessToken { value: String, expires_in: u32 }`.

- [ ] **Step 1: Write `crates/assinador/src/signer.rs`**

```rust
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
```

- [ ] **Step 2: Register the module + re-exports in `lib.rs`**

Add:

```rust
pub mod signer;

pub use signer::{AccessToken, Approval, PushAuthorization, VidaasSigner};
```

- [ ] **Step 3: Run the tests — verify they pass**

Run: `cargo test -p assinador signer`
Expected: PASS (`poll_maps_304_to_pending`, `full_flow_begin_poll_exchange`).

- [ ] **Step 4: Run the full library suite**

Run: `cargo test -p assinador`
Expected: PASS (all tests across config/error/pkce/client/port/adapter/dispatcher/signer).

- [ ] **Step 5: Commit**

```bash
git add crates/assinador/src/signer.rs crates/assinador/src/lib.rs
git commit -m "feat: VidaasSigner facade orchestrating the full flow

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## PART 2 — HTTP microservice (`assinador-server`)

> Part 2 begins here. It depends on a finished, green Part 1 (the `assinador` crate). The first thing Task 10 does is register the server as a second workspace member.

### Task 10: Server scaffold — axum app, state, error mapping, /health

**Files:**
- Create: `crates/assinador-server/Cargo.toml`
- Create: `crates/assinador-server/src/main.rs`
- Create: `crates/assinador-server/src/error.rs`
- Create: `crates/assinador-server/src/app.rs`

**Interfaces:**
- Consumes: `assinador::{VidaasSigner, VidaasConfig, SigningError, DocumentSigningError}`.
- Produces: `pub struct AppState { signer: Arc<VidaasSigner>, api_token: Option<String> }`; `pub fn router(state: AppState) -> axum::Router`; `pub struct ApiError` implementing `axum::response::IntoResponse` with constructors `from_signing(SigningError)` and `from_document(DocumentSigningError)`.

- [ ] **Step 1: Register the server in the workspace, then create `crates/assinador-server/Cargo.toml`**

First add the server to the root workspace `members` (it was library-only after Part 1):

```toml
# Cargo.toml (workspace root)
members = ["crates/assinador", "crates/assinador-server"]
```

Then create `crates/assinador-server/Cargo.toml`:

```toml
[package]
name = "assinador-server"
version = "0.1.0"
edition.workspace = true
license.workspace = true

[dependencies]
assinador = { path = "../assinador" }
axum = "0.8"
tokio.workspace = true
serde.workspace = true
serde_json.workspace = true
base64.workspace = true
tracing.workspace = true
tracing-subscriber = "0.3"

[dev-dependencies]
wiremock.workspace = true
reqwest.workspace = true
```

- [ ] **Step 2: Write `crates/assinador-server/src/error.rs`**

```rust
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
```

- [ ] **Step 3: Write `crates/assinador-server/src/app.rs` (state + router + health)**

```rust
//! Construção do app axum: estado compartilhado e rotas.

use std::sync::Arc;

use assinador::VidaasSigner;
use axum::routing::{get, post};
use axum::Router;

#[derive(Clone)]
pub struct AppState {
    pub signer: Arc<VidaasSigner>,
    pub api_token: Option<String>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/v1/auth/start", post(crate::handlers::auth_start))
        .route("/v1/auth/poll", get(crate::handlers::auth_poll))
        .route("/v1/auth/exchange", post(crate::handlers::auth_exchange))
        .route("/v1/sign", post(crate::handlers::sign))
        .with_state(state)
}
```

- [ ] **Step 4: Write a minimal `crates/assinador-server/src/handlers.rs` placeholder so the router compiles**

Create `crates/assinador-server/src/handlers.rs` with stubs that Task 11/12 replace:

```rust
//! Handlers HTTP (preenchidos nas tasks 11 e 12).

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
```

- [ ] **Step 5: Write `crates/assinador-server/src/main.rs`**

```rust
//! Microserviço HTTP que expõe a assinatura VIDaaS (stateless).

mod app;
mod error;
mod handlers;

use std::sync::Arc;

use assinador::{VidaasConfig, VidaasSigner};
use app::{router, AppState};

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
```

- [ ] **Step 6: Write the failing health test**

Create `crates/assinador-server/tests/health.rs`:

```rust
use assinador::{VidaasConfig, VidaasSigner};
use assinador_server_testkit::spawn_app;

// The test helper is defined inline below; this file drives it.
#[tokio::test]
async fn health_returns_ok() {
    let base = spawn_app("http://unused.invalid").await;
    let resp = reqwest::get(format!("{base}/health")).await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "ok");
}
```

NOTE: to avoid a separate test-kit crate, instead write the helper directly in the integration test. Replace the file above with this self-contained version:

```rust
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
```

- [ ] **Step 7: Expose the lib modules for integration tests**

In `crates/assinador-server/src/main.rs`, the binary's modules aren't visible to integration tests. Add a thin library target so tests can import `assinador_server::app`. Create `crates/assinador-server/src/lib.rs`:

```rust
pub mod app;
pub mod error;
pub mod handlers;
```

And in `crates/assinador-server/Cargo.toml` add explicit targets:

```toml
[lib]
name = "assinador_server"
path = "src/lib.rs"

[[bin]]
name = "assinador-server"
path = "src/main.rs"
```

Then change `main.rs` to use the library modules instead of declaring them:

```rust
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
    axum::serve(listener, assinador_server::app::router(router_state_noop())).await?;
    Ok(())
}

fn router_state_noop() {}
```

CORRECTION: keep `main.rs` simple — do not introduce `router_state_noop`. Final `main.rs`:

```rust
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
```

Delete the first version of `tests/health.rs` (the one referencing `assinador_server_testkit`); keep only the self-contained version from Step 6.

- [ ] **Step 8: Run the test — verify it passes**

Run: `cargo test -p assinador-server health`
Expected: PASS (`health_returns_ok`).

- [ ] **Step 9: Commit**

```bash
git add crates/assinador-server
git commit -m "feat: axum server scaffold (state, router, error mapping, /health)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 11: Auth endpoints — start, poll, exchange (+ optional bearer gate)

**Files:**
- Modify: `crates/assinador-server/src/handlers.rs`
- Create: `crates/assinador-server/tests/auth_flow.rs`

**Interfaces:**
- Consumes: `AppState`, `ApiError`, `assinador::{Approval, PushAuthorization, AccessToken}`.
- Produces: handlers `auth_start`, `auth_poll`, `auth_exchange` with these request/response JSON shapes:
  - `POST /v1/auth/start` ← `{ "cpf": String }` → `{ "code": String, "verifier": String }`
  - `GET /v1/auth/poll?code=...` → `{ "status": "pending" | "approved" }`
  - `POST /v1/auth/exchange` ← `{ "code": String, "verifier": String }` → `{ "access_token": String, "expires_in": u32 }`

- [ ] **Step 1: Replace `handlers.rs` with the real auth handlers**

```rust
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
}

pub async fn auth_poll(
    State(state): State<AppState>,
    Query(q): Query<PollQuery>,
) -> Result<Json<PollResponse>, ApiError> {
    let status = match state.signer.poll(&q.code).await.map_err(ApiError::from_signing)? {
        Approval::Approved => "approved",
        Approval::Pending => "pending",
    };
    Ok(Json(PollResponse { status }))
}

#[derive(Deserialize)]
pub struct ExchangeRequest {
    pub code: String,
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
        .exchange(&req.code, &req.verifier)
        .await
        .map_err(ApiError::from_signing)?;
    Ok(Json(ExchangeResponse { access_token: token.value, expires_in: token.expires_in }))
}

// --- /v1/sign is implemented in Task 12 ---

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
```

NOTE: `sign` is included here so `handlers.rs` is consistent; its dedicated test is in Task 12.

- [ ] **Step 2: Write the failing auth-flow integration test**

Create `crates/assinador-server/tests/auth_flow.rs`:

```rust
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

    let exchange: serde_json::Value = http.post(format!("{base}/v1/auth/exchange"))
        .json(&serde_json::json!({ "code": "push-code", "verifier": verifier }))
        .send().await.unwrap().json().await.unwrap();
    assert_eq!(exchange["access_token"], "final");
    assert_eq!(exchange["expires_in"], 604800);
}
```

- [ ] **Step 3: Run the test — verify it passes**

Run: `cargo test -p assinador-server auth_flow`
Expected: PASS (`start_poll_exchange_round_trip`).

- [ ] **Step 4: Commit**

```bash
git add crates/assinador-server/src/handlers.rs crates/assinador-server/tests/auth_flow.rs
git commit -m "feat: auth start/poll/exchange + sign handlers

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 12: Sign endpoint integration test

**Files:**
- Create: `crates/assinador-server/tests/sign_flow.rs`

**Interfaces:**
- Consumes: the `sign` handler + `/v1/sign` route (already implemented in Task 11).

- [ ] **Step 1: Write the failing sign integration test**

Create `crates/assinador-server/tests/sign_flow.rs`:

```rust
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
```

- [ ] **Step 2: Run the tests — verify they pass**

Run: `cargo test -p assinador-server sign_flow`
Expected: PASS (`sign_returns_base64_signed_pdf`, `sign_rejects_invalid_base64`).

- [ ] **Step 3: Run the full workspace suite**

Run: `cargo test`
Expected: PASS (all library + server tests).

- [ ] **Step 4: Commit**

```bash
git add crates/assinador-server/tests/sign_flow.rs
git commit -m "test: /v1/sign integration (base64 round trip + bad input)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 13: README + manual smoke-test docs

**Files:**
- Create: `README.md`
- Create: `crates/assinador/README.md`

**Interfaces:** none (documentation only).

- [ ] **Step 1: Write the workspace `README.md`**

Content must cover: what the project is; the two crates; how to build (`cargo build`); how to run the server (`VIDAAS_CLIENT_ID=… VIDAAS_CLIENT_SECRET=… cargo run -p assinador-server`); the four endpoints with example `curl` calls (start → poll → exchange → sign); env vars (`VIDAAS_BASE_URL`, `VIDAAS_CLIENT_ID`, `VIDAAS_CLIENT_SECRET`, `ASSINADOR_BIND`, `ASSINADOR_API_TOKEN`); and the explicit note that metadata injection and token storage are the caller's responsibility.

```markdown
# assinador

Assinatura digital de PDFs via VIDaaS (ICP-Brasil), em dois alvos:

- `crates/assinador` — biblioteca Rust reutilizável (`VidaasSigner`).
- `crates/assinador-server` — microserviço HTTP stateless que expõe o fluxo a
  qualquer linguagem.

## Fluxo

1. `POST /v1/auth/start` `{ "cpf": "..." }` → `{ "code", "verifier" }`
2. `GET  /v1/auth/poll?code=...` → `{ "status": "pending" | "approved" }` (repita até `approved`)
3. `POST /v1/auth/exchange` `{ "code", "verifier" }` → `{ "access_token", "expires_in" }`
4. `POST /v1/sign` `{ "access_token", "documents": [{ "id", "alias", "pdf_base64" }] }`
   → `{ "signed": [{ "id", "pdf_base64" }] }`

> O `exchange` usa o **`code` original do push + `verifier`**, não o
> `authorizationToken` retornado no poll.

## Executar

```bash
VIDAAS_CLIENT_ID=... VIDAAS_CLIENT_SECRET=... cargo run -p assinador-server
# opcional: VIDAAS_BASE_URL, ASSINADOR_BIND (default 0.0.0.0:8080), ASSINADOR_API_TOKEN
```

## Fora de escopo (responsabilidade do chamador)

- Injeção de metadados no PDF (ex.: campos ICP-Brasil de prescrição).
- Armazenamento/criptografia do access token.

## Teste manual (VIDaaS real)

Requer credenciais reais e aprovação no celular. Rode o servidor, chame
`/v1/auth/start` com um CPF habilitado, aprove o push no app VIDaaS, faça poll
até `approved`, troque por token e assine um PDF de teste.
```

- [ ] **Step 2: Write `crates/assinador/README.md` (library usage)**

Content must show the `VidaasSigner` Rust usage end-to-end:

```markdown
# assinador (lib)

```rust
use assinador::{VidaasConfig, VidaasSigner, Approval, DocumentSigningPort, UnsignedDocument};

let signer = VidaasSigner::new(VidaasConfig::from_env()?);
let auth = signer.begin_authorization("12345678900").await?;
loop {
    if let Approval::Approved = signer.poll(&auth.code).await? { break; }
    // aguarde e tente de novo
}
let token = signer.exchange(&auth.code, &auth.verifier).await?;
let signed = signer.sign_documents(&token.value, vec![UnsignedDocument {
    id: "doc-1".into(), alias: "contrato".into(), pdf_bytes,
}]).await?;
```
```

- [ ] **Step 3: Verify the docs build/links**

Run: `cargo build` (ensures the workspace still compiles) and visually confirm the READMEs render.
Expected: build PASS.

- [ ] **Step 4: Commit**

```bash
git add README.md crates/assinador/README.md
git commit -m "docs: README + library usage + manual smoke test

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Self-Review

**Spec coverage:**
- Workspace + two crates → Tasks 1, 10. ✓
- Full VIDaaS auth flow (client token, PKCE push, poll, exchange) → Tasks 2–5, 9. ✓
- Signing (hash/base64/batch/id-match/decode/validate) → Tasks 5, 7. ✓
- `DocumentSigningPort` + adapter + dispatcher retained → Tasks 6, 7, 8. ✓
- Stateless HTTP endpoints 1:1 → Tasks 10, 11, 12. ✓
- pt-BR errors → Task 1 (`error.rs`). ✓
- No metadata injection / no token storage → enforced by omission; documented in Task 13. ✓
- Optional bearer-token gate → `api_token` field present in `AppState` (Task 10); enforcement middleware is OPTIONAL and deployment-gated — left unwired by default per spec ("when unset, no auth"). ✓
- Offline unit tests + mock-VIDaaS flow tests → every task; no live-VIDaaS in CI; manual smoke test in Task 13. ✓
- rx untouched → no task modifies `/home/lucas/code/rx`. ✓

**Placeholder scan:** Task 10 deliberately introduces a handler stub (Step 4) that is fully replaced in Task 11 Step 1; flagged as such. No "TBD"/"add error handling"-style gaps. Task 10 Step 7 contains an intentional CORRECTION sequence (the `router_state_noop` misstep is shown then corrected) — the final `main.rs` block is the one to use.

**Type consistency:** `VidaasClient::new(VidaasConfig)`, `sign_documents` returning `SignatureResponse` (no status tuple — adapter updated accordingly in Task 7), `poll_authentication` returning `(PollAuthResponse, u16)`, `VidaasSigner` method names (`begin_authorization`/`poll`/`exchange`/`discover_user`) and `Approval`/`PushAuthorization`/`AccessToken` are consistent across Tasks 4, 5, 9, 11. Server JSON field names (`code`/`verifier`/`access_token`/`expires_in`/`pdf_base64`) consistent across Tasks 11–13 and README.
