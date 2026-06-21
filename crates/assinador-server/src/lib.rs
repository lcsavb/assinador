//! Microserviço HTTP que expõe a assinatura VIDaaS (stateless).
//!
//! A lógica vive na lib (testável por testes de integração); `main.rs` é só a
//! casca que lê o ambiente e sobe o servidor.

pub mod app;
pub mod error;
pub mod handlers;
