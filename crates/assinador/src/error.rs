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
