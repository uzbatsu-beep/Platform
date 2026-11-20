# ADR-001: Выбор Rust 1.100.0, Axum 0.8 и архитектуры Modular Monolith

- **Статус:** Утверждено (Decision Gate NEON)
- **Дата:** 2026-11-20

## Решение
Использовать [Rust Stable 1.100.0](https://blog.rust-lang.org/releases/latest/) (зафиксирован в `rust-toolchain.toml`), [Axum 0.8.x](https://docs.rs/crate/axum/latest), [Tokio](https://docs.rs/tokio), Tower, Serde, [tracing](https://tokio.rs/tokio/topics/tracing) и [utoipa 6.0](https://docs.rs/utoipa/latest/utoipa/) + [utoipa-axum](https://docs.rs/utoipa-axum) в архитектуре Modular Monolith (`domain / application / infrastructure / presentation`) на единой кодовой базе для Standalone и Server.
