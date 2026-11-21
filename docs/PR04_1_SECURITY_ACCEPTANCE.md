# NEON — PR-04.1 Security Hardening & Runtime Integration Acceptance

## 1. Устранённые P0-дефекты PR-04

| ID | Дефект PR-04 | Решение в PR-04.1 | Затронутые модули |
|---|---|---|---|
| **P0-1** | `platform-server/src/main.rs` не монтировал `identity_router` и не поднимал HTTP runtime | Реализован полный composition root (`runtime.rs` + `main.rs`): загрузка/валидация TOML+env, открытие SQLite 3.54.1 / PostgreSQL 18/19, прогон миграций `0001`+`0002`, персистентный `source_instance_id`, монтирование `identity_router` + `/health/live`, `ConnectInfo<SocketAddr>`, security headers и graceful shutdown | `platform-cli-core/src/config.rs`, `platform-server/src/{lib,runtime,main,http}.rs` |
| **P0-2** | `neon admin init/reset-password` и `neon-cli` оставались заглушками (exit code 2) | Подключён реальный `AdminBootstrapService` к SQLite/PostgreSQL в обоих бинарниках (`neon` и `neon-cli`), с `rpassword` и `--password-stdin`, без вывода секретов | `platform-cli-core/src/lib.rs`, `platform-server/src/{main,runtime}.rs`, `platform-cli/src/main.rs` |
| **P0-3** | `login_handler` передавал захардкоженный `Some("127.0.0.1")` в `LoginRateLimiter` | Реализован `ClientIpResolver`: по умолчанию используется реальный `peer_ip` из `ConnectInfo<SocketAddr>`, заголовки `X-Forwarded-For`/`X-Real-IP` игнорируются, пока `peer_ip` не входит в явный список `trusted_proxies`; при доверенном прокси выполняется right-to-left парсинг с лимитами длины и числа хопов | `platform-core/src/identity/security.rs`, `platform-server/src/http.rs` |
| **P0-4** | IDOR в `deactivate_user` и `revoke_assignment` (проверка по клиентскому `target_scope`) | Полностью удалён клиентский `target_scope`; фактические scope пользователя и назначения загружаются **внутри DB-транзакции** (`deactivate_user_authorized`, `revoke_assignment_authorized`), проверяются политиками `authorize_user_deactivation` / `authorize_assignment_revocation`, с атомарным отзывом сессий и защитой последнего глобального администратора | `platform-core/src/identity/{ports,services}.rs`, `platform-db-sqlite/src/identity_repo.rs`, `platform-db-pg/src/identity_repo.rs` |

## 2. Дополнительное усиление безопасности (Задача E)
- **Argon2id offloading:** хеширование, верификация и timing-equalization dummy verify вынесены в `tokio::task::spawn_blocking`, ограничены `tokio::sync::Semaphore` (`DEFAULT_MAX_CONCURRENT_ARGON2 = 4`), при сохранении параметров OWASP (`m=19456 KiB`, `t=2`, `p=1`).
- **HTTP Security Headers:** middleware выставляет `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, а также `Cache-Control: no-store` для `/api/v1/auth/*` и всех RFC 9457 ответов об ошибках.
- **Zero Schema Changes:** существующие миграции `0001_init_core_metadata.sql` и `0002_identity_rbac_org.sql` не изменялись.

## 3. Матрица покрытия тестами
- **Client IP & Rate Limiter (6 unit-тестов):** `crates/platform-core/src/identity/security.rs`.
- **Argon2id Async Offload:** `crates/platform-core/src/identity/password.rs`.
- **Runtime Config Fail-Fast Validation:** `crates/platform-cli-core/src/config.rs`.
- **9 Negative Scoped RBAC / IDOR + Concurrent Last-Admin тестов:**
  - SQLite 3.54.1: `crates/platform-db-sqlite/tests/identity_rbac_integration.rs`
  - PostgreSQL 18 / 19: `crates/platform-db-pg/tests/identity_rbac_integration.rs`
- **Real HTTP E2E (Axum Router + SQLite):** `crates/platform-server/tests/http_e2e.rs`.
- **Real CLI Binary E2E (`neon` binary):** `crates/platform-server/tests/cli_e2e.rs`.


## 4. GitHub CI reconciliation (2026-11-21)

- Draft PR #6 created from the full 36-file source archive, exact Git blob checksums matched.
- Initial required checks found rustfmt differences and a stale workspace Cargo.lock (locked PostgreSQL jobs fail without regeneration).
- A temporary branch-scoped workflow is used to execute `cargo update --workspace` and `cargo fmt --all` with pinned Rust 1.100.0; it must delete itself before the final code review.
- Tests are **not accepted** until all seven required status checks pass on the same final HEAD; technical acceptance also requires review of real HTTP/CLI runtime and scoped RBAC negative tests.

- GitHub Actions one-time reconciliation **PASS** (run [44905562613](https://github.com/uzbatsu-beep/Platform/actions/runs/44905562613)); `Cargo.lock` regenerated, rustfmt completed, temporary workflow removed in commit `64742d6`. Full required CI is still pending technical acceptance.

- Post-reconciliation Rust Clippy exposed three platform-core compilation defects (renamed session repository field, incorrect Option handling in PHC parameter parsing, unused import); corrected in `9e5c071`. Follow-up CI must pass before acceptance.

- GitHub compiler/Clippy audit found the archive had regressed PR-03 atomic PG/SQLite migration runners. Restored accepted ACID implementation from `main`, retained `core_{postgres,sqlite}_migrations()` helper via namespace-aware `MigrationSpec::new`, fixed `platform-core` Clippy, and explicitly wrapped six SQLx static-template PG Identity queries with `AssertSqlSafe` following audit. Further CI pending.

- Follow-up Rust/PG CI exposed duplicate `identity_repo` exports after restoring accepted PR-03 adapters; deduplicated them. PR remains Draft and requires renewed seven-check CI.
