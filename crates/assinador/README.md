# assinador (lib)

Biblioteca Rust para assinatura digital de PDFs via VIDaaS (ICP-Brasil).

A `VidaasSigner` orquestra o fluxo completo: `begin_authorization` (dispara o
push) → `poll` (aguarda a aprovação no celular) → `exchange` (obtém o access
token) → `sign_documents` (assina os PDFs). A biblioteca **não** injeta metadados
no PDF nem armazena o token — isso é responsabilidade do chamador.

```rust
use assinador::{
    VidaasConfig, VidaasSigner, Approval, DocumentSigningPort, UnsignedDocument,
};

async fn assinar(pdf_bytes: Vec<u8>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let signer = VidaasSigner::new(VidaasConfig::from_env()?);

    // 1. dispara o push no celular do usuário
    let auth = signer.begin_authorization("12345678900").await?;

    // 2. consulta até aprovar
    loop {
        if let Approval::Approved = signer.poll(&auth.code).await? {
            break;
        }
        // aguarde (ex.: tokio::time::sleep) e tente de novo
    }

    // 3. troca pelo access token (guarde-o; vale ~7 dias)
    let token = signer.exchange(&auth.code, &auth.verifier).await?;

    // 4. assina um ou mais PDFs
    let mut signed = signer
        .sign_documents(
            &token.value,
            vec![UnsignedDocument {
                id: "doc-1".into(),
                alias: "contrato".into(),
                pdf_bytes,
            }],
        )
        .await?;

    Ok(signed.remove(0).signed_pdf_bytes)
}
```

## Configuração

`VidaasConfig::from_env()` lê `VIDAAS_CLIENT_ID`, `VIDAAS_CLIENT_SECRET` e
(opcional) `VIDAAS_BASE_URL`. Ou construa `VidaasConfig { .. }` diretamente.

## Multi-provedor

A trait `DocumentSigningPort` abstrai a assinatura; `VidaasSigner` a implementa.
`SigningDispatcher` roteia por nome de provedor — espaço para um futuro provedor
(ex.: SafeWeb) sem mudar o código chamador.
