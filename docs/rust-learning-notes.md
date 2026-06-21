# Rust Learning Notes — building `assinador`

Running notes captured while building this crate, one section per implementation
task. The goal is to learn Rust through real code, so each section explains the
Rust-specific reasoning behind what we wrote.

---

## Task 1 — Workspace + config/error scaffold

### Crate vs. workspace
- A **crate** is Rust's unit of compilation: one library *or* one binary.
- A **workspace** is a set of crates sharing one `Cargo.lock` and one `target/`
  build dir. We use one so the lib and (later) the server build together with
  locked-in-step dependency versions.
- `Cargo.toml` is the manifest (like `package.json` / `pyproject.toml`).

### `workspace.dependencies`
Declare a version once at the workspace root, then write `serde.workspace = true`
in each crate. No version drift between crates.

### `#[derive(...)]` — derive macros
Ask the compiler to generate trait impls instead of hand-writing them:
- `Debug` → printable with `{:?}` (diagnostics/tests).
- `Clone` → adds `.clone()` for an explicit deep copy. Rust never deep-copies
  heap data implicitly; you opt in.
- `Error` (from `thiserror`) → wires up `std::error::Error`.

### `thiserror` and `#[error("...")]`
Each enum variant gets a `Display` string. `{0}` interpolates the variant's
first field, so `BadRequest("x")` displays as just `x`. `.to_string()` uses this.

### Enums are sum types
`SigningError` is *exactly one of* its variants; variants can carry data
(`ConfigError(String)`) or not (`Unauthorized`). When you `match`, the compiler
forces you to handle every variant — error handling is exhaustive, not hopeful.

### `Result<T, E>`, `?`, `map_err`, closures
- Fallible functions return `Result<T, E>` — `Ok(v)` or `Err(e)`. No exceptions.
- `?` = early-return-on-error: if `Err`, return it now; if `Ok`, unwrap and
  continue. One character.
- `.map_err(|e| ...)` converts one error type into another. `|e| ...` is a
  closure (lambda); `|_|` ignores the argument.

### Struct literal + `Self`
`Ok(Self { base_url, client_id, client_secret })` — `Self` is the type being
`impl`'d. Field shorthand works when locals share the field names.

### Module wiring
- `pub mod config;` → "there is a file `config.rs`; expose it as a module."
- `pub use config::VidaasConfig;` → re-export at crate root, so users write
  `assinador::VidaasConfig`.
- `use crate::error::SigningError;` → import; `crate::` is this crate's root.

### `#[cfg(test)] mod tests`
Conditional compilation — the test module only exists during `cargo test`, never
in the shipped build. `use super::*;` pulls in the parent module's items.
`matches!(value, Pattern)` returns a bool for "does this match this variant?".

### Footgun noted
`std::env::remove_var` is unsafe across threads; Cargo runs tests in parallel by
default, so env-var tests are a known hazard.

---

## Task 2 — PKCE (verifier + S256 challenge)

### What PKCE is
Stops an attacker who steals an authorization `code` from using it. Generate a
random secret (`verifier`), send only `SHA256(verifier)` (the `challenge`) when
starting auth, and reveal the `verifier` only at the final token exchange. The
server checks they match.

### Byte strings and slices
- `b"ABC...~"` is a *byte string literal*: `&[u8; 65]`, annotated as `&[u8]` (a
  *slice* = a view into bytes whose length isn't known at compile time).
- `const CHARSET` is baked into the binary at compile time.
- We index ASCII *bytes* (cheap) rather than `char`s.

### Iterator chains
```rust
(0..43)                          // Range, an Iterator yielding 0..=42
    .map(|_| { ... a char ... }) // transform each item; |_| ignores the counter
    .collect()                   // consume into a collection
```
`.collect()` is polymorphic — it builds whatever the return type demands (here a
`String` from `char`s). Idiomatic Rust: lazy iterator → collect, no manual loop.

### `as` casts
`CHARSET[idx] as char` — `as` is an explicit primitive cast (`u8` → `char`),
safe here because charset bytes are valid ASCII.

### Immutable by default
`let mut rng` — variables are immutable unless you write `mut`. `gen_range`
mutates RNG state, so it needs `mut`. The compiler makes you announce mutation.

### Traits unlock methods via `use`
`gen_range` lives on the `Rng` trait; `new/update/finalize` on the `Digest`
trait. **A trait's methods are callable only if the trait is in scope.** That's
why we `use rand::Rng;` and `use sha2::Digest;` even though we never name them —
importing the trait turns on its methods. Classic newcomer gotcha.

### Hashing flow
`Sha256::new()` → `update(data)` (repeatable) → `finalize()` (digest bytes), then
`URL_SAFE_NO_PAD.encode(...)` (the `Engine` trait provides `.encode`).

### Visibility granularity
`generate_code_verifier` is `pub` (public API). `generate_pkce_challenge` is
`pub(crate)` (internal to this crate only). Rust has `pub`, `pub(crate)`,
`pub(super)`, and private (default).

### Testing against a spec
`challenge_matches_known_vector` checks our output against the official RFC 7636
Appendix B vector. Passing proves the hash + base64url encoding is byte-exact —
the kind of thing that's otherwise silently wrong.

---

## Task 3 — Low-level `VidaasClient` (client token + user discovery)

### `async` / `.await`
Network calls don't block a thread. An `async fn` returns a **future** — a value
representing "work not finished yet." `.await` pauses the function until the
future resolves, letting the runtime do other work meanwhile. Futures are
**lazy**: nothing runs until something `.await`s them. `#[tokio::test]` provides
the async runtime that drives our test futures to completion.

### serde derive
- `#[derive(Serialize)]` → struct becomes JSON we send (the request bodies).
- `#[derive(Deserialize)]` → JSON we receive becomes a struct (the responses).
- `response.json().await` parses the body into whatever type the binding asks
  for (`let token: TokenResponse = ...`). Type inference drives the parse target.

### `&self` borrowing
Methods take `&self` — a shared, read-only **borrow**. The caller keeps
ownership; the method only reads. Because no method needs exclusive (`&mut`)
access, many can run concurrently behind a shared `Arc` later. This is the
ownership/borrowing model: at any time you have either many shared readers
(`&T`) or exactly one writer (`&mut T`), enforced at compile time.

### Why no client-token cache
`rx` builds a fresh client per call; we mirror that by fetching the client token
inline in each method that needs it. The payoff: every method is `&self` (not
`&mut self`), so `VidaasClient` is trivially `Send + Sync` and shareable.

### `reqwest` builder pattern
`self.client.post(url).bearer_auth(t).json(&body).send().await` chains builder
methods, each returning the builder, until `.send()` fires the request. `.form(&[
(k, v), ... ])` sends `application/x-www-form-urlencoded` (OAuth token endpoints
want forms, not JSON).

### `.clone()` where we hand off owned data
`self.config.client_id.clone()` — the request struct owns its `String` fields, so
we clone out of the borrowed `&self`. We *could* restructure to borrow, but
cloning a short credential string is cheap and clearer.

### `&str` vs `String`
- `String` = owned, growable, heap-allocated text.
- `&str` = a borrowed view into text you don't own.
Take `&str` in parameters (`cpf: &str`) to accept either without forcing a copy;
store/return `String` when you need ownership.

### The dead-code lint as truth-teller
`expires_in` warns "never read" right now because only `access_token` is used so
far. It's not noise — it's accurate. The warning disappears in Task 5 when
`exchange_code` reads `expires_in`. Rust warns about genuinely unused code.

### `#[allow(dead_code)]`
On `token_type` we suppress the lint deliberately: the field documents the JSON
shape and helps deserialization clarity even though we never read it.

### Testing with `wiremock`
`MockServer::start()` spins up a real local HTTP server on a random port. We
`Mock::given(method("POST")).and(path("/...")).respond_with(...)` to script
responses, point our client's `base_url` at `server.uri()`, and assert on real
HTTP round-trips — no network, fully deterministic.
