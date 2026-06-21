# assinador

Assinatura digital de PDFs via VIDaaS (ICP-Brasil), em dois alvos:

- `crates/assinador` — biblioteca Rust reutilizável (`VidaasSigner`).
- `crates/assinador-server` — microserviço HTTP stateless que expõe o fluxo a
  qualquer linguagem.

## Cadastro da aplicação no Valid PSC (uma única vez)

Antes de autorizar/assinar é obrigatório cadastrar a aplicação no Valid PSC para
obter o `client_id` e o `client_secret`. O cadastro é feito **uma única vez** por
ambiente.

URIs base:

| Ambiente | URI base |
|---|---|
| Produção | `https://certificado.vidaas.com.br` |
| Homologação | `https://hml-certificado.vidaas.com.br` |

Requisição — `POST <URI-base>/v0/oauth/application`:

- Cabeçalhos: `Content-Type: application/json`, `Accept: application/json`
- Corpo (`application/json;charset=UTF-8`):
  - `name` (obrigatório) — nome/descrição da aplicação
  - `comments` (obrigatório) — observações gerais de uso
  - `redirect_uris` (obrigatório) — URIs autorizadas para redirecionamento
    (fluxos de authorization code). Para o fluxo **push** use `push://`.
  - `email` (obrigatório) — e-mail de suporte (indisponibilidade, mudança de versão…)

Exemplo (homologação):

```bash
curl -X POST https://hml-certificado.vidaas.com.br/v0/oauth/application \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  -d '{
    "name": "assinador (homologação)",
    "comments": "Microserviço de assinatura de PDFs via VIDaaS",
    "redirect_uris": ["push://"],
    "email": "voce@exemplo.com"
  }'
```

Resposta:

```json
{
  "status": "success",
  "message": "New Client Application registered with Sucess",
  "client_id": "4c9fb552-0387-4e5f-8727-6676fa88dce1",
  "client_secret": "Ny2n3hq67gQEFvH7"
}
```

> ⚠️ Guarde `client_id` e `client_secret` com segurança — eles autenticam todas
> as chamadas de autorização e assinatura. **Nunca** os comite no repositório;
> use variáveis de ambiente / um `.env` local (já ignorado pelo git). O
> `redirect_uris` define quais URIs a aplicação poderá usar no redirecionamento
> pós-assinatura.

Depois do cadastro, exporte as credenciais (veja [Executar](#executar)):
`VIDAAS_CLIENT_ID`, `VIDAAS_CLIENT_SECRET` e, para homologação,
`VIDAAS_BASE_URL=https://hml-certificado.vidaas.com.br`.

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
