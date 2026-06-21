//! Assinatura digital de PDFs via VIDaaS (ICP-Brasil).

pub mod config;
pub mod error;

pub use config::VidaasConfig;
pub use error::SigningError;
