//! Assinatura digital de PDFs via VIDaaS (ICP-Brasil).

pub mod config;
pub mod error;
pub mod pkce;

pub use config::VidaasConfig;
pub use error::SigningError;
pub use pkce::generate_code_verifier;
