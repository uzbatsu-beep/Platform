# ADR-011: Единый бинарник Standalone+CLI, SQLite 3.54.1 durability и HTTP 409 / 412

- **Статус:** Принято к реализации (PR-01 / PR-03 / PR-05)
- **Дата:** 2026-11-20

## 1. Единый бинарник Standalone + CLI
- `platform-cli-core` содержит общие подкоманды (`serve`, `admin`, `migrate`, `backup`).
- Standalone — один бинарник `neon` (`platform-server --features standalone`); для Server дополнительно доступен `neon-cli` (`platform-cli`).
- Встраивание SPA (`embed-ui` / `rust-embed`) перенесено в **PR-07** вместе с реализацией Frontend Shell.

## 2. SQLite 3.54.1 (bundled), `synchronous = FULL`, запрет сетевых ФС
- Точная фиксация `libsqlite3-sys = "=0.39.1"` (`bundled`, без `bundled-sqlcipher`) обеспечивает SQLite **3.54.1** на Windows и Linux и устраняет `RUSTSEC-2026-0459` (`CVE-2026-119375`).
- Runtime-тест `verify_sqlite_runtime` проверяет `sqlite_version() >= 3.54.1`, `ENABLE_FTS5 == 1`, `PRAGMA journal_mode == wal` и `PRAGMA foreign_keys == 1` без `.expect()`.
- Профиль по умолчанию — `synchronous = FULL`; UNC/сетевые ФС запрещены.

## 3. HTTP-семантика `412 Precondition Failed` и `409 Conflict`
- `412 Precondition Failed` — несовпадение HTTP `If-Match` / `ETag` (RFC 9110).
- `409 Conflict` — конфликт бизнес-состояния или `expected_row_version` в теле команды без `If-Match`.
