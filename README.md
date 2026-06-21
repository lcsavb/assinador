# assinador

Assinatura digital de PDFs via VIDaaS (ICP-Brasil), em dois alvos:

- `crates/assinador` — biblioteca Rust reutilizável (`VidaasSigner`).
- `crates/assinador-server` — microserviço HTTP stateless que expõe o fluxo a
  qualquer linguagem.

## Fluxo

1. `POST /v1/auth/start` `{ "cpf": "..." }` → `{ "code", "verifier" }`
2. `GET  /v1/auth/poll?code=...` → `{ "status": "pending" }` ou, quando aprovado,
   `{ "status": "approved", "authorization_token": "..." }` (repita até `approved`)
3. `POST /v1/auth/exchange` `{ "authorization_token", "verifier" }` → `{ "access_token", "expires_in" }`
4. `POST /v1/sign` `{ "access_token", "documents": [{ "id", "alias", "pdf_base64" }] }`
   → `{ "signed": [{ "id", "pdf_base64" }] }`

> O `exchange` usa o **`authorization_token` retornado no poll** + o `verifier` —
> NÃO o `code` original do push (este serve apenas para consultar a aprovação).
> Confirmado em teste real contra a VIDaaS de produção.

## Executar

```bash
VIDAAS_CLIENT_ID=... VIDAAS_CLIENT_SECRET=... cargo run -p assinador-server
# opcional: VIDAAS_BASE_URL, ASSINADOR_BIND (default 0.0.0.0:8080), ASSINADOR_API_TOKEN
```

### Exemplo com `curl`

```bash
# 1. iniciar (dispara o push no celular do usuário)
curl -s localhost:8080/v1/auth/start -H 'content-type: application/json' \
  -d '{"cpf":"12345678900"}'
# => {"code":"<code>","verifier":"<verifier>"}

# 2. consultar até aprovar
curl -s "localhost:8080/v1/auth/poll?code=<code>"
# => {"status":"pending"}  ... depois  {"status":"approved","authorization_token":"<token>"}

# 3. trocar pelo access token (usa o authorization_token do poll, não o <code>)
curl -s localhost:8080/v1/auth/exchange -H 'content-type: application/json' \
  -d '{"authorization_token":"<authorization_token>","verifier":"<verifier>"}'
# => {"access_token":"<token>","expires_in":604800}

# 4. assinar (pdf_base64 = base64 do PDF)
curl -s localhost:8080/v1/sign -H 'content-type: application/json' \
  -d '{"access_token":"<token>","documents":[{"id":"d1","alias":"contrato","pdf_base64":"<b64>"}]}'
# => {"signed":[{"id":"d1","pdf_base64":"<b64-assinado>"}]}
```

## Variáveis de ambiente

| Variável | Obrigatória | Default | Uso |
|---|---|---|---|
| `VIDAAS_CLIENT_ID` | sim | — | credencial do cliente VIDaaS |
| `VIDAAS_CLIENT_SECRET` | sim | — | segredo do cliente VIDaaS |
| `VIDAAS_BASE_URL` | não | `https://certificado.vidaas.com.br` | endpoint VIDaaS |
| `ASSINADOR_BIND` | não | `0.0.0.0:8080` | endereço de escuta |
| `ASSINADOR_API_TOKEN` | não | — | (reservado) bearer para proteger o serviço |

## Fora de escopo (responsabilidade do chamador)

- Injeção de metadados no PDF (ex.: campos ICP-Brasil de prescrição).
- Armazenamento/criptografia do access token.

## Teste manual (VIDaaS real)

Requer credenciais reais e aprovação no celular. Rode o servidor, chame
`/v1/auth/start` com um CPF habilitado, aprove o push no app VIDaaS, faça poll
até `approved`, troque por token e assine um PDF de teste.

## Desenvolvimento

```bash
cargo test          # toda a suíte (lib + integração HTTP, sem rede real)
cargo clippy        # lint
```
