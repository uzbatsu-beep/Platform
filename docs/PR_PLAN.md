# План первых Pull Requests (PR_PLAN)

> **Правило:** небольшие функционально завершённые PR с обязательными тестами, CI и документацией. Автоматическое слияние запрещено — каждый PR согласуется отдельно.

## Phase 1A — Foundation
- **PR-01 — Workspace Bootstrap, Tooling & CI [MERGED — `0bf1589`, 5/5 CI PASS]:** Cargo Workspace (`1.100.0`), `Cargo.lock` + `frontend/pnpm-lock.yaml`, `deny.toml` (v2), `platform-cli-core` + `neon` + `neon-cli`, `libsqlite3-sys = "=0.39.1"` (SQLite 3.54.1, `synchronous = FULL`), `frontend/` (Vite 8.0 + `@vitejs/plugin-react` 6.3.0 + `@tailwindcss/vite` 4.2.2 + Vitest 5.1.1), guard-скрипты с негативными тестами, Linux/Windows CI.
- **PR-02 [MERGED — `376616d`] — `platform-sdk` (Контракты, Порты и Манифест):** типизированные `UUIDv7` ID, `SourceInstanceId`, `SchemaVersion`, `RowVersion` (ETag), `IdempotencyKey`, `ModuleManifest` с валидатором графа, `AuthContext`/`Scope`/`PermissionDef`, `QueryPort`/`CommandPort`, `TxContext` (ADR-010), `EventEnvelope`/`OutboxDeliveryRecord` (at-least-once), RFC 9457 `AppError` с разделением `412`/`409` (ADR-011), тесты и `docs/SDK_API.md`.
- **PR-03 [MERGED — `56034dc`] — DB Layer (PG 18/19 + SQLite 3.54) и `ModuleRegistry`:** `platform-db-pg`, `platform-db-sqlite` (WAL, раздельные writer/reader пулы, `foreign_keys=ON`), версионированный раннер миграций по `db_namespace`, `ModuleRegistry`, контрактные тесты на обеих СУБД.
- **PR-04 [MERGED — `dcc7a02`] — `AuthProvider`, RBAC со скоупами, Оргструктура и `neon-cli`:** локальная аутентификация (Argon2id, HttpOnly-сессии, CSRF, rate limit), `Organization`/`Site`/`Department`/`Location`, серверная проверка RBAC, `neon-cli admin init` и `admin reset-password`, negative-тесты 401/403.
- **PR-04.1 [MERGED — `42c90e8`] — Identity Security Hardening:** HTTP/CLI, защита client IP, Scoped RBAC по фактическим данным, E2E.
- **PR-04.2 [DRAFT — ожидает 7/7 CI] — CI Stabilization & Docs Sync:** корректный победитель конкурентного SQLite bootstrap, 10 повторов теста на Linux/Windows, обновление MD. Слияние по согласованию.
- **PR-05 [PLANNED] — Transactional Outbox, Audit Log, Health и OpenAPI:** `core_outbox_events` + `core_outbox_deliveries` (независимые подписчики, lease, retry/backoff, DLQ) + `core_processed_events` (ADR-010), append-only `core_audit_log` с настраиваемой ретенцией, `/health/live`, `/health/ready`, автогенерация OpenAPI 3.1 (`utoipa`) и TS-клиента.
- **PR-06 — Безопасные вложения, Поиск (PG/FTS5) и Согласованный бэкап:** Immutable SHA-256 Blob Store, проверка magic bytes и настраиваемых лимитов (25/50/100 МБ), безопасная выдача, поиск с RBAC-фильтрацией, согласованный бэкап БД + вложений + `backup-manifest.json` + тест восстановления.
- **PR-07 — Frontend Engineering Workspace Shell (Вариант C) + Standalone SPA Embedding:** сворачиваемая навигация, верхняя панель (`Ctrl+K`, контекст, тема, плотность), вкладки (синхронизация с TanStack Router), правый Inspector Drawer, Dashboard, экран входа, 100% i18n RU, встраивание SPA (`embed-ui` / `rust-embed`) в Standalone-бинарник `neon` (ADR-011), Vitest + Playwright smoke.

## Phase 1B — Vertical Slice (`mod-equipment`)
- **PR-08 — `mod-equipment` Backend:** `Equipment`, `EquipmentComponent` (рекурсивное дерево), оптимистическая блокировка, привязка документов через `DocumentCommandPort`, подписка на события Outbox (история оборудования), индексация в поиске, тесты на PG 18/19 и SQLite.
- **PR-09 — `mod-equipment` Frontend:** виртуализированная таблица (TanStack Table + Virtual с `useFlushSync: false`), дерево узлов, паспорт во вкладке и правом Inspector, загрузка/скачивание PDF/PNG/JPG/DXF/DWG, виджеты Dashboard, E2E-тесты Playwright.

## Phase 1C — Production Hardening
- **PR-10 — Нагрузочные испытания (50k), Air-gapped дистрибутивы и Hardening:** сид на 50 000 записей, прогоны `k6`/`oha` (API, поиск, загрузка файлов на предельных лимитах), публикация реального baseline, офлайн-сборки Standalone и Server (Linux + Windows) с `SHA256SUMS`, тест офлайн-обновления и a11y (`axe-core`).
