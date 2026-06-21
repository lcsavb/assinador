//! Porta de assinatura de documentos (interface da camada de aplicação).
//!
//! Abstrai a assinatura digital entre provedores (VIDaaS, SafeWeb…).

use async_trait::async_trait;

/// Documento a ser assinado.
#[derive(Debug, Clone)]
pub struct UnsignedDocument {
    pub id: String,
    pub alias: String,
    pub pdf_bytes: Vec<u8>,
}

/// Resultado assinado.
#[derive(Debug, Clone)]
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
