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
