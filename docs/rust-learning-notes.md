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

---

## Task 4 — Push authorization + polling

### `Option<T>` — Rust's type-safe "nullable"
A value is either `Some(x)` or `None`; **there is no `null`**. `authorization_token:
Option<String>` is absent (`None`) until the user approves, then `Some("tok")`.
The compiler forces you to handle the `None` case, so "forgot to null-check"
bugs don't compile. Helpers: `.is_none()`, `.as_deref()` (turns
`Option<String>` into `Option<&str>` for easy comparison with `Some("tok")`).

### serde field renaming
VIDaaS sends camelCase (`authorizationToken`); Rust convention is snake_case
(`authorization_token`). `#[serde(rename = "authorizationToken")]` maps the JSON
key to the Rust field, so the wire format and our code each stay idiomatic.

### Returning a tuple
`poll_authentication` returns `(PollAuthResponse, u16)`. A **tuple** is an
anonymous, fixed-size group of values — great for a one-off "two things" return
without defining a named struct. Destructure with `let (body, status) = ...`.

### `match` on status codes (exhaustive, with `_`)
```rust
match status {
    200 => { ... }
    304 => { ... }
    _   => Err(...),   // catch-all; required because integers have many values
}
```
`match` must cover every possibility; `_` is the wildcard arm. The compiler
won't let you forget a case (for an enum it would name the missing variants).

### String parsing as `Option`, not sentinels
`text.strip_prefix("code=")` returns `Option<&str>` — `Some(rest)` if the prefix
matched, `None` otherwise. We chain:
```rust
text.strip_prefix("code=")          // Option<&str>
    .map(|c| c.to_string())          // Option<String> — transform the Some, leave None
    .ok_or_else(|| SigningError::...) // Option<T> -> Result<T, E>: Some->Ok, None->Err
```
`ok_or_else` takes a closure that builds the error only when needed (vs `ok_or`
which eagerly builds it). This "convert absence into a typed error" pattern is
everywhere in Rust.

### `unwrap_or_else` for fallback values
`response.text().await.unwrap_or_else(|_| "Unknown error".to_string())` — if
reading the body errors, substitute a default instead of propagating. Use this
when you genuinely want a fallback, not a `?` early return.

### Inline format args
`format!("Push authorization failed: {status} - {body}")` — recent Rust lets you
name variables directly inside `{}` instead of positional `{}` + trailing args.

---

## Task 5 — Code exchange + batch signing

### `Vec<T>` — growable heap array
`Vec<DocumentForSignature>` is like Python's `list`/Java's `ArrayList`. Owned and
heap-allocated. `.is_empty()`, `.len()`, indexing `vec[0]`. `vec![]` is the
empty-vec macro.

### serde attributes for shaping JSON
- `#[serde(skip_serializing_if = "Option::is_none")]` on `pdf_signature_page`:
  when serializing (sending), omit the field entirely if it's `None`. Keeps the
  request body clean and matches what VIDaaS expects.
- `#[serde(default)]` on `file_base64_signed`: when deserializing (receiving), if
  the field is missing, fall back to the type's `Default` (empty `String`)
  instead of failing the parse. Defensive against responses that omit it.

### Guard clause + early `return`
```rust
if documents.is_empty() {
    return Err(SigningError::ValidationError("...".to_string()));
}
```
Validate inputs up front and bail with an explicit `return Err(...)`. Note: most
Rust functions end with a *tail expression* (no `return`, no `;`), but an early
exit in the middle needs the explicit `return` keyword.

### `if/else` is an expression
```rust
if body.len() < 100 { body } else { "See logs for details".to_string() }
```
Rust's `if/else` *evaluates to a value*, so we use it inline as a `format!`
argument. Both branches must produce the same type (`String` here). This replaces
the ternary `?:` operator other languages have.

### Ownership move into the request
`let request = SignatureRequest { hashes: documents };` — `documents` is **moved**
into the struct (not copied). After this line you can no longer use `documents`;
ownership transferred. That's fine because we computed `doc_ids`/length checks
*before* moving (in the adapter, Task 7) — order matters under move semantics.

### Trait bounds surface in surprising places
`.unwrap_err()` requires the `Ok` type to implement `Debug` (so it can print the
unexpected value if it has to panic). That's why the empty-list test forced us to
add `Debug` to `SignatureResponse`/`SignatureResult`. Lesson: a method can demand
traits on a type parameter you didn't think about; the compiler tells you exactly
which trait and where to add it.

---

## Task 6 — The signing port (trait + DTOs)

### A `trait` is an interface
A trait declares methods a type promises to provide. It's Rust's polymorphism
mechanism — **no class inheritance**. Any type can implement any trait. Here
`DocumentSigningPort` defines `sign_documents` + `provider_name`; `VidaasSigner`
(Task 9) will implement it, and a hypothetical SafeWeb signer could implement the
same trait so callers swap providers without code changes.

### Supertraits: `: Send + Sync`
`pub trait DocumentSigningPort: Send + Sync` means "every implementor must also be
`Send` and `Sync`."
- `Send` = safe to **move** to another thread.
- `Sync` = safe to **share** (`&T`) across threads.
These are *auto traits* the compiler derives automatically when all fields
qualify. We require them because the async runtime (tokio) schedules tasks across
a thread pool, so a trait object used in async code must be thread-safe.

### `#[async_trait]`
Plain Rust traits have limited support for `async fn` methods, so the
`async-trait` crate rewrites an async trait method into one returning a boxed
future (`Pin<Box<dyn Future>>`). You annotate both the trait and every `impl`
with `#[async_trait]`. Slight allocation cost, but it's the standard pattern for
async traits today.

### Manual `Display` vs derived
`SigningError` got `Display` for free via `thiserror`'s `#[error("...")]`. Here we
hand-write it to see the machinery:
```rust
impl std::fmt::Display for DocumentSigningError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self { Self::ProviderError(msg) => write!(f, "...: {msg}"), ... }
    }
}
```
`write!(f, ...)` writes into the provided formatter buffer (not stdout). `Display`
is what `.to_string()` and `{}` use. `impl std::error::Error for ... {}` — an
empty impl; the trait's methods all have defaults, we just opt into the marker so
the type counts as a "real error."

### `&'static str` return
`fn provider_name(&self) -> &'static str` — `'static` is a **lifetime**: this
string reference lives for the entire program (it's a string literal baked into
the binary, like `"VIDaaS"`). Returning `&'static str` avoids allocating a
`String` for a constant. First taste of explicit lifetimes.

---

## Task 7 — VIDaaS signing adapter

### `Arc<T>` — shared ownership across threads
**A**tomically **R**eference-**C**ounted pointer. Lets multiple owners share one
heap value; the value is dropped when the last `Arc` goes away. The adapter holds
`Arc<VidaasClient>`, and the signer (Task 9) will hold another `Arc` to the *same*
client. `arc.clone()` is cheap — it bumps an atomic counter, it does NOT copy the
client. Contrast `Rc<T>` (single-thread, non-atomic, faster) — we need `Arc`
because async tasks cross threads.

### Implementing the trait
```rust
#[async_trait]
impl DocumentSigningPort for VidaasSigningAdapter { ... }
```
This is where we fulfill the contract from Task 6. The `impl Trait for Type`
syntax is how a type "becomes a" `DocumentSigningPort`. Both the trait and this
impl carry `#[async_trait]`.

### Associated functions vs methods
`Self::prepare_document(doc)` has no `self` parameter — it's an **associated
function** (like a static method), called on the type. `self.client.sign_documents(...)`
is a **method** (takes `&self`). `documents.iter().map(Self::prepare_document)`
passes the associated function as a value — functions are first-class.

### `.iter()` vs `.into_iter()`
`documents.iter()` yields `&UnsignedDocument` (borrows; the `Vec` stays usable
afterward). We borrow here because we still need `documents` later (for `.len()`).
`.into_iter()` would consume and yield owned values. Choosing borrow-vs-consume is
a constant Rust decision driven by what you need afterward.

### Slice indexing + byte-literal comparison
`signed_bytes.len() < 4 || &signed_bytes[0..4] != b"%PDF"` validates the PDF
magic number. `&signed_bytes[0..4]` is a sub-slice (the first 4 bytes); `b"%PDF"`
is a 4-byte literal. The `len() < 4` check comes first because indexing `[0..4]`
on a shorter slice would **panic** — short-circuit `||` guards against it.

### `.find()` → `Option` → `.ok_or_else()`
```rust
response.signatures.iter()
    .find(|s| &s.id == expected_id)   // Option<&SignatureResult>
    .ok_or_else(|| DocumentSigningError::ProviderError(...))?  // -> Result, then ?
```
We match signatures back to inputs **by id** rather than trusting array order —
defensive against a provider reordering the batch. `Vec::with_capacity(n)`
pre-allocates so the push loop never reallocates.

### The `Debug` lesson, again
`.unwrap_err()` in the test forced `SignedDocument: Debug` (hence `Vec<SignedDocument>:
Debug`). The compiler printed the exact `#[derive(Debug)]` to add and where. Same
pattern as Task 5 — internalize it: **test ergonomics (`unwrap`, `assert_eq`)
often dictate which derives your types need.**
