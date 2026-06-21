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
