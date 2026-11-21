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


## 4. Подтверждённая приёмка PR-04.1 (21.11.2026)

- [PR #6](https://github.com/uzbatsu-beep/Platform/pull/6) слит через squash в `42c90e8`.
- На финальном HEAD PR #6 `c664515` успешно завершились **7/7** проверок: [Rust/PG](https://github.com/uzbatsu-beep/Platform/actions/runs/44907581838) и [Frontend](https://github.com/uzbatsu-beep/Platform/actions/runs/44907581847).
- Squash commit и последний HEAD PR #6 содержат **идентичное Git-дерево `3915369`**.
- Однако отдельный [post-merge push-CI `main`](https://github.com/uzbatsu-beep/Platform/actions/runs/44908913799) завершился **5/7 PASS**: Rust Linux/Windows — FAIL из-за недетерминированного SQLite bootstrap-теста; остальные пять — PASS. Следовательно, устойчивость ещё не была доказана.

## 5. PR-04.2 — исправление обнаруженной нестабильности (ожидает приёмки)

- `sqlite_full_pr04_identity_rbac_and_negative_security_suite` принимает успех любого из `admin`/`admin2` при конкурентном bootstrap, но исходно выполнял последующий login и reset-password исключительно для `admin`. При победе `admin2` получался ожидаемый 401 и падал тест.
- Исправление: хранить и использовать пару `(admin_id, admin_username)` фактического победителя во всех последующих проверках (вход, сессия, восстановление пароля); сохранить отрицательную проверку второго конкурентного bootstrap.
- Регрессионная защита: после обычного workspace test в **каждом** обязательном Rust CI на Ubuntu/Windows повторять этот SQLite-тест **10 раз**.
- Статусы серии и семи checks засчитываются только после фактического выполнения на финальном SHA PR; после squash merge дополнительно проверяется push-CI `main`.
- Отдельный security review и проверка TLS/reverse proxy перед промышленной эксплуатацией остаются обязательными; этот тестовый фикс не заменяет их.
