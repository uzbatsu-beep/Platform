# Архитектура платформы NEON (ARCHITECTURE)

## 1. Архитектурный стиль: Modular Monolith
Каждый компонент (`platform-core` и любой `mod-*`) организован в 4 строгих слоя:
1. **`domain`** — сущности, Value Objects, инварианты, ошибки, трейты портов (`Repository`, `QueryPort`, `CommandPort`). Нулевые зависимости от Axum/SQLx/Tokio.
2. **`application`** — use cases, проверка RBAC и `Scope`, транзакционные границы, запись в Transactional Outbox и аудит.
3. **`infrastructure`** — адаптеры БД (`Pg*` для PostgreSQL 18/19 и `Sqlite*` для SQLite 3.54), Content-Addressed Blob Store, бэкап, воркер Outbox.
4. **`presentation`** — тонкие HTTP-обработчики [Axum 0.8](https://docs.rs/crate/axum/latest), DTO, OpenAPI ([utoipa 6.0](https://docs.rs/utoipa/latest/utoipa/)). Бизнес-логика и SQL в обработчиках строго запрещены.

## 2. Межмодульные контракты (3 механизма взаимодействия)
1. **`QueryPort` (синхронное чтение):** безопасный read-only фасад, экспортируемый Core или модулем (например, `OrgQueryPort`, `EquipmentQueryPort`, `IdentityDisplayPort`).
2. **`CommandPort` (синхронное/транзакционное изменение состояния):** типизированный контракт для бизнес-операций, требующих изменения состояния в другом модуле (например, `AuditCommandPort::record`, `DocumentCommandPort::attach`, в Phase 3 — `InventoryCommandPort::consume_part`).
   - **Обязательные требования к `CommandPort`:** принимает `AuthContext` (или явный `SystemActor`), `IdempotencyKey`, а для атомарных межмодульных операций — общий `&mut TxContext` (см. `ADR-010`), выполняя проверку прав и доменных инвариантов внутри модуля-владельца.
3. **`DomainEvent` через мультипотребительский Transactional Outbox (асинхронная реакция):** включён в **Phase 1A (Foundation)**. Мутация состояния и запись события в `core_outbox_events` выполняются в **одной транзакции БД** (`TxContext`), а независимая доставка каждому подписчику отслеживается в `core_outbox_deliveries` с `leased_until`, независимыми retry/backoff и DLQ (см. `ADR-010`).

## 3. Уточнённая модель изоляции модулей и реальные ограничения БД
- **Процессная реальность Modular Monolith:** в рамках одного Rust-процесса изоляция обеспечивается **компилятором** (отдельные Cargo crates, закрытые `infrastructure`-модули, `pub(crate)`), **CI-линтером границ и SQL** (`scripts/check_arch_boundaries.py`) и **серверным RBAC**. Аппаратная/процессная песочница относится к будущим внешним расширениям (Phase 4: out-of-process RPC / WASM).
- **PostgreSQL 18 (baseline) / 19 (CI):** каждый модуль владеет отдельной схемой (`core`, `mod_equipment`, `mod_cmms`, ...), нативными типами (`UUID`, `TIMESTAMPTZ`, `JSONB`), MVCC и `tsvector`/`pg_trgm`. При необходимости администратор может дополнительно ограничить права ролей БД по схемам.
- **SQLite 3.54 (Standalone):** в одном файле БД нет независимых схем и ролей доступа; изоляция поддерживается строгими префиксами таблиц (`core_*`, `mod_equipment_*`), отсутствием кросс-модульных FK (только логические `UUIDv7`) и проверкой SQL в CI.
- **Ограничение конкурентной записи SQLite:** в режиме [WAL](https://www.sqlite.org/wal.html) чтение параллельно, но запись сериализуется одним писателем. Поэтому в `platform-db-sqlite` выделяется отдельный writer-пул (`max_connections = 1`) и reader-пул, настроены `busy_timeout = 5000`, `synchronous = FULL` (профиль по умолчанию по ADR-011; `NORMAL` — только явный opt-in), `foreign_keys = ON`, а SQLite официально предназначен только для Standalone.

## 4. Общая кодовая база Standalone и Server
- **Standalone (`--features "standalone"`):** единый бинарник `neon` (с общими CLI-подкомандами из `platform-cli-core`), loopback `127.0.0.1`, статически слинкованный SQLite 3.54.1 (`libsqlite3-sys = "=0.39.1"`, `bundled`, WAL + FTS5 + `synchronous = FULL`, запрет сетевых ФС), без интернета и Node.js. Встраивание SPA (`embed-ui` / `rust-embed`) добавляется в **PR-07** (см. `ADR-011`).
- **Server (`--features "server"`):** сервис Linux/Windows (`neon`) + опциональная отдельная утилита `neon-cli` (поверх `platform-cli-core`), настраиваемые IP/порт, обязательный TLS (или явный режим доверенного reverse proxy), PostgreSQL 18 (baseline) / 19 (CI).
