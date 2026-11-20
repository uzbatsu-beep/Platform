# NEON Database Layer & ModuleRegistry (PR-03)

## 1. Схема подключения и конфигурирования

### PostgreSQL (Server — `crates/platform-db-pg`)
- **Baseline:** PostgreSQL **18**; **CI compatibility target:** PostgreSQL **19** (fail-fast для `< 18`).
- Конфигурация `PgConfig` (`host`, `port`, `database`, `username`, `password`, `tls_mode`, `acquire_timeout_secs`, `max_connections`, `min_connections`). Пароль автоматически маскируется в `Debug` как `[REDACTED]`.
- Изоляция пространств имён: `ensure_schema` допускает только `core` или `mod_[a-z][a-z0-9_]*` (защита от SQL-инъекций).

### SQLite (Standalone — `crates/platform-db-sqlite`)
- **Runtime:** статически слинкованный SQLite **3.54.1** (`libsqlite3-sys = "=0.39.1"`, `bundled`).
- **Раздельные пулы:** `writer_pool` (`max_connections = 1`) + `reader_pool` (`read_only = true`, по умолчанию 4 соединения).
- **Прагмы:** `journal_mode = WAL`, `synchronous = FULL` (по умолчанию; `NORMAL` — только явный opt-in с риском потери последних подтверждённых транзакций при потере питания), `foreign_keys = ON`, `busy_timeout = 5000 ms`.
- **Защита от сетевых ФС:** проверка UNC-путей (`\\server\share`, `\\?\UNC\...`, `//server/share`), канонизация родительской директории и на Linux проверка `/proc/mounts` на `nfs`/`nfs4`/`cifs`/`smb3`/`fuse.sshfs` и др. *Известное ограничение:* при `unsafe_code = "forbid"` сетевые диски Windows, смонтированные на букву диска (`Z:\`), не проверяются через Win32 `GetDriveTypeW` и требуют соблюдения эксплуатационного регламента.

## 2. Владение транзакцией (`TxContext`, ADR-010)
- `PgTxContext` оборачивает `Option<sqlx::Transaction<'static, Postgres>>`; `SqliteTxContext` — `Option<sqlx::Transaction<'static, Sqlite>>`.
- Реализуют объектно-безопасный `platform_sdk::TxContext` без добавления `sqlx` в `platform-sdk` и без `unsafe`.
- `downcast_mut` проверяет `TxEngine`, исключая подмену СУБД; `commit`/`rollback` забирают владение через `Option::take()`, делая повторный commit или запросы после завершения невозможными; `Drop` незавершённой транзакции гарантирует откат без утечки соединения.

## 3. Конвертация временных меток (`UtcMillis`)
- В `platform-sdk` используется `UtcMillis(u64)` (Unix milliseconds).
- **PostgreSQL (`TIMESTAMPTZ`):** запись через `TIMESTAMPTZ '1970-01-01 00:00:00+00' + ($1::bigint * INTERVAL '1 millisecond')`; чтение через `((EXTRACT(EPOCH FROM col) * 1000)::numeric)::bigint` (точная целочисленная/десятичная арифметика без потерь `float8`).
- **SQLite (`ISO-8601 TEXT`):** `platform_core::utc_millis_to_iso8601` (`YYYY-MM-DDTHH:MM:SS.sssZ`) и `iso8601_to_utc_millis` (принимает `Z` и `+00:00`, отклоняет не-UTC смещения).

## 4. Протокол миграций и `ModuleRegistry`
- Каталоги: `migrations/postgres/{core,mod_*}/` и `migrations/sqlite/{core,mod_*}/`.
- Реестр `core_module_migrations`: `namespace`, `version`, `name`, `checksum_sha256` (FIPS 180-4 SHA-256), `applied_at`, `status` (`in_progress`/`applied`/`failed`), `error_message`.
- Блокировка конкурентного старта: `pg_advisory_lock` (PostgreSQL) и выделенный single-writer пул (SQLite).
- Жизненный цикл `ModuleRegistry`: `Register -> Validate -> Resolve Dependencies -> Migrate -> Ready`. Модуль никогда не становится `Ready` без успешной миграции.

## 5. Запуск PostgreSQL 18/19 интеграционных тестов локально
```bash
docker run --rm -d --name neon-pg18 -e POSTGRES_USER=neon_test -e POSTGRES_PASSWORD=neon_test_password -e POSTGRES_DB=neon_test -p 5432:5432 postgres:18-alpine
NEON_REQUIRE_PG_TESTS=1 NEON_TEST_PG_URL="postgres://neon_test:neon_test_password@127.0.0.1:5432/neon_test" cargo test -p platform-db-pg --locked -- --nocapture
```

## 6. Отложенная функциональность (вне области PR-03)
- Auth/Argon2id/RBAC (PR-04), таблицы и воркер Transactional Outbox/Audit (PR-05), Blob Store/Backup/Search (PR-06), UI Shell и SPA embedding (PR-07), `mod-equipment` (PR-08/09).
