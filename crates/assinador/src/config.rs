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
