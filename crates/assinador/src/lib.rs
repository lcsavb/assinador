//! Assinatura digital de PDFs via VIDaaS (ICP-Brasil).

pub mod adapter;
pub mod client;
pub mod config;
pub mod error;
pub mod pkce;
pub mod port;

pub use adapter::VidaasSigningAdapter;
pub use client::VidaasClient;
pub use config::VidaasConfig;
pub use error::SigningError;
pub use pkce::generate_code_verifier;
pub use port::{DocumentSigningError, DocumentSigningPort, SignedDocument, UnsignedDocument};
