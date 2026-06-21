# Assinador — VIDaaS PDF Signing Crate + HTTP Service

**Date:** 2026-06-21
**Status:** Approved design (pre-implementation)

## Purpose

Provide a reusable, standalone way to digitally sign PDFs with ICP-Brasil
certificates via the **VIDaaS** cloud-signature API. Today this logic is
duplicated across `/home/lucas/code/rx` and `cliquereceita`; both flag it as a
"candidate for a shared crate." This project extracts that logic into:

1. A **pure Rust library crate** (`assinador`) — usable directly by Rust projects.
2. A **thin HTTP microservice** (`assinador-server`) wrapping the crate, so an API
   in **any programming language** can sign PDFs over HTTP.

The logic is **extracted from** `rx` (the reference implementation). `rx` and any
`examples/` directory are treated as **read-only** — nothing there is modified.

## Scope

### In scope
- VIDaaS full auth flow: client-credentials token, PKCE push authorization,
  approval polling, code→access-token exchange.
- PDF signing: SHA-256 hashing, base64 encoding, batch signature request,
  ID-matched response handling, signed-PDF decode + `%PDF` validation.
- Provider-agnostic `DocumentSigningPort` trait + `VidaasSigningAdapter` +
  `SigningDispatcher` (multi-provider headroom retained).
- Stateless HTTP microservice exposing the flow 1:1.
- Offline unit tests + mock-VIDaaS HTTP flow tests.

### Out of scope (explicit)
- Token persistence / encryption (caller holds the access token).
- PDF metadata injection (e.g. rx's `inject_prescription_metadata`) — callers
  inject any `/Info` fields **before** handing PDF bytes to the crate.
- Database, session storage.
- Migrating `rx` to consume this crate (separate follow-up).
- C-ABI / FFI bindings.

## Decisions (from brainstorming)
- **Consumption:** pure Rust crate **and** an HTTP microservice wrapping it.
- **Auth scope:** crate owns the **full** VIDaaS auth flow + signing.
- **Metadata:** **excluded** — crate signs the PDF bytes it is given.
- **rx:** **standalone only**; rx left untouched.
- **Service:** **stateless pass-through**; no DB, no token storage.
- **Messages:** **Portuguese** error strings (matching rx).
- **Abstraction:** **keep** the `DocumentSigningPort` trait.

## Architecture

Cargo workspace:

```
/home/lucas/code/assinador/
├── Cargo.toml                 # [workspace]
├── docs/superpowers/specs/    # this spec
└── crates/
    ├── assinador/             # pure Rust lib — the reusable crate
    │   ├── Cargo.toml
    │   └── src/
    │       ├── lib.rs         # public re-exports + module wiring
    │       ├── config.rs      # VidaasConfig { base_url, client_id, client_secret }, from_env()
    │       ├── error.rs       # SigningError (thiserror, pt-BR) + DocumentSigningError
    │       ├── pkce.rs        # generate_code_verifier(), S256 challenge
    │       ├── client.rs      # low-level VidaasClient (ported from rx client.rs)
    │       ├── port.rs        # DocumentSigningPort trait, UnsignedDocument, SignedDocument
    │       ├── adapter.rs     # VidaasSigningAdapter (impl DocumentSigningPort)
    │       ├── dispatcher.rs  # SigningDispatcher (route by provider name)
    │       └── signer.rs      # VidaasSigner facade: auth flow + Signing
    └── assinador-server/      # thin HTTP microservice (axum)
        ├── Cargo.toml
        └── src/main.rs
```

### Library dependencies
`reqwest` (default-features off, `json` + `rustls-tls`), `serde` (+derive),
`serde_json`, `base64`, `sha2`, `rand` (0.8, matching rx), `thiserror`,
`async-trait`, `tracing`.

### Server dependencies
Adds `axum`, `tokio` (full), `tracing-subscriber`. Depends on the `assinador` crate.

## Library public API

```rust
// config.rs
pub struct VidaasConfig { pub base_url: String, pub client_id: String, pub client_secret: String }
impl VidaasConfig {
    pub fn from_env() -> Result<Self, SigningError>; // VIDAAS_BASE_URL/CLIENT_ID/CLIENT_SECRET
}

// port.rs (ported from rx document_signing.rs)
pub struct UnsignedDocument { pub id: String, pub alias: String, pub pdf_bytes: Vec<u8> }
pub struct SignedDocument   { pub id: String, pub signed_pdf_bytes: Vec<u8> }
pub enum DocumentSigningError { ProviderError(String), InvalidSignedDocument(String),
                                NetworkError(String), AuthenticationError(String) }
#[async_trait]
pub trait DocumentSigningPort: Send + Sync {
    async fn sign_documents(&self, access_token: &str, documents: Vec<UnsignedDocument>)
        -> Result<Vec<SignedDocument>, DocumentSigningError>;
    fn provider_name(&self) -> &'static str;
}

// signer.rs — VIDaaS facade. Auth methods are VIDaaS-specific;
// signing goes through DocumentSigningPort (implemented here / via adapter).
pub struct VidaasSigner { /* holds VidaasClient + VidaasSigningAdapter */ }
impl VidaasSigner {
    pub fn new(cfg: VidaasConfig) -> Self;

    /// Optional pre-check that a CPF/CNPJ is enrolled.
    pub async fn discover_user(&self, cpf: &str) -> Result<bool, SigningError>;

    /// Step 1 — push a signature request to the user's phone.
    /// Generates the PKCE verifier internally; returns it for the later exchange.
    pub async fn begin_authorization(&self, cpf: &str)
        -> Result<PushAuthorization, SigningError>; // { code, verifier }

    /// Step 2 — poll until the user approves on their device.
    pub async fn poll(&self, code: &str) -> Result<Approval, SigningError>; // Pending | Approved

    /// Step 3 — exchange the approved code for the access token (caller stores it).
    pub async fn exchange(&self, code: &str, verifier: &str)
        -> Result<AccessToken, SigningError>; // { value, expires_in }
}
#[async_trait] impl DocumentSigningPort for VidaasSigner { /* step 4 — sign */ }

pub struct PushAuthorization { pub code: String, pub verifier: String }
pub enum Approval { Pending, Approved /* authorization_token/redirect_url retained internally if needed */ }
pub struct AccessToken { pub value: String, pub expires_in: u32 }
```

**Flow fidelity:** mirrors rx's `DoctorCertificateService` exactly — `begin_authorization`
(= `initiate_push`: cpf → verifier → push authorize → `code`), `poll` (= `poll_approval`),
`exchange` (= `exchange_code(code, verifier)`), then `sign_documents`. The `exchange`
uses the **original push `code` + `verifier`**, matching rx.

**Signing internals** (ported verbatim from `VidaasSigningAdapter`): SHA-256 hash
(OID `2.16.840.1.101.3.4.2.1`), `signature_format = "PAdES_AD_RB"`,
`pdf_signature_page = Some(false)`, batch request, signatures matched back by `id`,
base64 decode with `\r\n`/`\n` cleanup, and a `%PDF` header check.

## HTTP microservice API

Stateless. Credentials from env. PDFs cross the wire as base64.

| Method | Path | Request | Response |
|---|---|---|---|
| `GET`  | `/health` | — | `200 OK` |
| `POST` | `/v1/auth/start` | `{ "cpf": "..." }` | `{ "code": "...", "verifier": "..." }` |
| `GET`  | `/v1/auth/poll?code=...` | — | `{ "status": "pending" \| "approved" }` |
| `POST` | `/v1/auth/exchange` | `{ "code": "...", "verifier": "..." }` | `{ "access_token": "...", "expires_in": 604800 }` |
| `POST` | `/v1/sign` | `{ "access_token": "...", "documents": [ { "id", "alias", "pdf_base64" } ] }` | `{ "signed": [ { "id", "pdf_base64" } ] }` |

- Optional `/v1/auth/discover` (`{cpf}` → `{enrolled: bool}`) — include if cheap.
- **Service auth:** optional static bearer token via env (`ASSINADOR_API_TOKEN`); when
  unset, no auth (deployment-gated). TLS termination is a deployment concern.
- The client drives the poll loop (stateless); the service does not block on approval.

## Error handling

- Library: `SigningError` (thiserror, **pt-BR** messages) for the VIDaaS client/auth
  layer; `DocumentSigningError` for the signing port (matching rx's split).
- Server maps errors to JSON `{ "error": "<code>", "detail": "<message>" }` with status:
  - bad input / provider 4xx → `400`
  - unauthorized (client token / token exchange) → `401`
  - invalid signed document → `422`
  - VIDaaS network/5xx → `502`

## Testing

- **Lib unit (offline):** PKCE S256 challenge correctness; document preparation
  (hash + base64 fields); signed-PDF decode/validation (base64 cleanup, `%PDF`
  header, missing-PDF and count-mismatch errors); dispatcher routing (known/unknown
  provider); error `Display` (pt-BR).
- **HTTP flow (mock VIDaaS via `wiremock`):** start → poll(304 pending) →
  poll(200 approved) → exchange → sign, asserting request shapes and the
  pending→approved transition.
- **No live VIDaaS in CI** (needs real credentials + phone approval). Document a
  manual smoke-test procedure in the crate README.

## Milestones (for the implementation plan)
1. Workspace skeleton + `assinador` crate scaffold + deps.
2. Port `config`, `error`, `pkce`, low-level `client` with unit tests.
3. Port `port` + `adapter` + `dispatcher` + `VidaasSigner` facade with unit tests.
4. `assinador-server`: axum app, handlers, error mapping, `/health`.
5. Mock-VIDaaS HTTP flow tests + README (usage + manual smoke test).
