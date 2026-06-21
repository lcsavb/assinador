# assinador

Assinatura digital de PDFs via **VIDaaS** (ICP-Brasil).

- `crates/assinador` — biblioteca Rust (`VidaasSigner`).
- `crates/assinador-server` — microserviço HTTP que expõe a assinatura para
  **qualquer linguagem** (você fala HTTP/JSON, não Rust).

Como a assinatura exige aprovação do usuário no app VIDaaS do celular, o fluxo
tem 4 passos: **iniciar → aprovar no celular → obter token → assinar**.

---

## Como assinar um PDF (passo a passo)

### 1. Cadastre sua aplicação (uma vez)

Você precisa de um `client_id` e `client_secret` da VIDaaS. Cadastre a aplicação
(detalhes em [Cadastro da aplicação](#cadastro-da-aplicação-no-valid-psc)):

```bash
curl -X POST https://hml-certificado.vidaas.com.br/v0/oauth/application \
  -H 'Content-Type: application/json' -H 'Accept: application/json' \
  -d '{"name":"assinador","comments":"teste","redirect_uris":["push://"],"email":"voce@exemplo.com"}'
# => { "client_id": "...", "client_secret": "..." }
```

### 2. Suba o servidor

Escolha **uma** das opções (todas sobem em `http://localhost:8080`):

**a) Docker (recomendado — não precisa de Rust):**

```bash
docker run --rm -p 8080:8080 \
  -e VIDAAS_CLIENT_ID=...  -e VIDAAS_CLIENT_SECRET=... \
  -e VIDAAS_BASE_URL=https://hml-certificado.vidaas.com.br \
  ghcr.io/lcsavb/assinador:latest
```

**b) Binário pronto (Linux x86_64, estático):** baixe o `.tar.gz` em
[Releases](https://github.com/lcsavb/assinador/releases), e rode:

```bash
tar xzf assinador-server-*-x86_64-linux-musl.tar.gz
VIDAAS_CLIENT_ID=... VIDAAS_CLIENT_SECRET=... ./assinador-server
```

**c) Compilando do código (precisa do Rust):**

```bash
export VIDAAS_CLIENT_ID=...        # do passo 1
export VIDAAS_CLIENT_SECRET=...    # do passo 1
# homologação (opcional; sem isso, usa produção):
export VIDAAS_BASE_URL=https://hml-certificado.vidaas.com.br
cargo run -p assinador-server
```

### 3. Rode o script Python para assinar

> ⚠️ **O CPF precisa estar obrigatoriamente vinculado a um certificado VIDaaS
> (Certificado em Nuvem) ativo.** Sem um certificado VIDaaS associado àquele CPF,
> o push não chega e a assinatura não funciona.

Salve como `assinar.py`, ajuste `CPF` e `PDF`, e rode `python3 assinar.py`.
Quando ele disparar o push, **aprove no app VIDaaS do seu celular**.

```python
import base64, time, requests

BASE = "http://localhost:8080"   # endereço do assinador-server
CPF  = "12345678900"             # CPF habilitado na VIDaaS (só dígitos)
PDF  = "contrato.pdf"            # PDF que você quer assinar

# 1. inicia: dispara o push no celular
r = requests.post(f"{BASE}/v1/auth/start", json={"cpf": CPF}).json()
code, verifier = r["code"], r["verifier"]
print("Aprove a assinatura no app VIDaaS do seu celular...")

# 2. consulta até o usuário aprovar
while True:
    r = requests.get(f"{BASE}/v1/auth/poll", params={"code": code}).json()
    if r["status"] == "approved":
        authorization_token = r["authorization_token"]
        break
    time.sleep(3)

# 3. troca pelo token de acesso (vale ~7 dias; pode guardar e reusar)
r = requests.post(f"{BASE}/v1/auth/exchange",
                  json={"authorization_token": authorization_token,
                        "verifier": verifier}).json()
access_token = r["access_token"]

# 4. assina o PDF (vai e volta em base64)
pdf_b64 = base64.b64encode(open(PDF, "rb").read()).decode()
r = requests.post(f"{BASE}/v1/sign", json={
    "access_token": access_token,
    "documents": [{"id": "doc-1", "alias": "contrato", "pdf_base64": pdf_b64}],
}).json()

assinado = base64.b64decode(r["signed"][0]["pdf_base64"])
open("assinado.pdf", "wb").write(assinado)
print(f"Pronto! PDF assinado salvo em assinado.pdf ({len(assinado)} bytes)")
```

> 💡 Já existe uma versão pronta em [`scripts/smoke_test.py`](scripts/smoke_test.py)
> que **gera um PDF de teste** automaticamente (não precisa ter um PDF à mão):
> `python3 scripts/smoke_test.py <CPF>`.

Pontos importantes:

- O **token do passo 3 vale ~7 dias**. Numa aplicação real, guarde-o e pule
  direto para o passo 4 nas próximas assinaturas até expirar.
- Dá para assinar **vários PDFs de uma vez**: mande mais objetos em `documents`;
  voltam casados pelo `id`.
- Precisa de metadados no PDF (ex.: campos ICP-Brasil)? Injete-os **antes** de
  enviar — o assinador assina exatamente os bytes que você manda.

---

## Como funciona (a API HTTP)

| Passo | Requisição | Resposta |
|---|---|---|
| 1 | `POST /v1/auth/start` `{cpf}` | `{code, verifier}` |
| 2 | `GET /v1/auth/poll?code=...` | `{status:"pending"}` ou `{status:"approved", authorization_token}` |
| 3 | `POST /v1/auth/exchange` `{authorization_token, verifier}` | `{access_token, expires_in}` |
| 4 | `POST /v1/sign` `{access_token, documents:[{id, alias, pdf_base64}]}` | `{signed:[{id, pdf_base64}]}` |

> ⚠️ No passo 3, troque o **`authorization_token`** que veio do *poll* (passo 2) —
> não o `code` do passo 1 (esse só serve para consultar a aprovação).

Erros voltam como `{ "error": "...", "detail": "..." }` com o status HTTP
adequado (400 entrada inválida, 401 não autorizado, 422 PDF assinado inválido,
502 VIDaaS indisponível). Há também `GET /health`.

---

## Cadastro da aplicação no Valid PSC

Obrigatório **uma única vez** por ambiente, para obter `client_id`/`client_secret`.

| Ambiente | URI base |
|---|---|
| Produção | `https://certificado.vidaas.com.br` |
| Homologação | `https://hml-certificado.vidaas.com.br` |

`POST <URI-base>/v0/oauth/application` (corpo `application/json`):

- `name` — nome/descrição da aplicação
- `comments` — observações de uso
- `redirect_uris` — URIs de redirecionamento; para o fluxo push use `push://`
- `email` — e-mail de suporte

Exemplo (homologação):

```bash
curl -X POST https://hml-certificado.vidaas.com.br/v0/oauth/application \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  -d '{
    "name": "assinador",
    "comments": "Microserviço de assinatura de PDFs via VIDaaS",
    "redirect_uris": ["push://"],
    "email": "voce@exemplo.com"
  }'
```

Resposta:

```json
{ "status": "success", "client_id": "4c9fb552-...", "client_secret": "Ny2n3hq67gQEFvH7" }
```

> ⚠️ `client_id`/`client_secret` são credenciais: **nunca** comite no repositório.
> Use variáveis de ambiente ou um `.env` local (já ignorado pelo git).

📚 Documentação oficial do Valid PSC:
[Manual de Integração com VIDaaS — Certificado em Nuvem](https://valid-sa.atlassian.net/wiki/spaces/PDD/pages/958365697/Manual+de+Integra+o+com+VIDaaS+-+Certificado+em+Nuvem).

---

## Variáveis de ambiente

| Variável | Obrigatória | Default | Uso |
|---|---|---|---|
| `VIDAAS_CLIENT_ID` | sim | — | credencial do cliente VIDaaS |
| `VIDAAS_CLIENT_SECRET` | sim | — | segredo do cliente VIDaaS |
| `VIDAAS_BASE_URL` | não | `https://certificado.vidaas.com.br` | endpoint VIDaaS (use o de homologação para testar) |
| `ASSINADOR_BIND` | não | `0.0.0.0:8080` | endereço de escuta do servidor |

---

## Desenvolvimento

```bash
cargo test     # suíte completa (lib + integração HTTP, sem rede real)
cargo clippy   # lint
```

A biblioteca Rust pode ser usada diretamente — veja
[`crates/assinador/README.md`](crates/assinador/README.md).
