# План развития NEON (ROADMAP)

## Phase 0: Architecture Research & Planning *(Завершена)*
Утверждён Decision Gate, согласованы стек, модель данных, air-gapped требования, структура репозитория и план PR.

## Phase 1: MVP (разделена на 3 этапа)

### Phase 1A — Foundation (PR-01 завершён `0bf1589`; далее PR-02 — PR-07)
- **[ЗАВЕРШЕНО — PR-01, `0bf1589`]:** каркас репозитория, Rust 1.100.0, `Cargo.lock` + `frontend/pnpm-lock.yaml`, SQLite 3.54.1 (`libsqlite3-sys = "=0.39.1"`, `synchronous = FULL`), `platform-cli-core`, CI на Linux/Windows (5/5 проверок успешно), активный Ruleset `27744630`.
- `platform-sdk` (`ModuleManifest`, `QueryPort`, `CommandPort`, `EventEnvelope`, `UUIDv7`, `source_instance_id`, `schema_version`).
- `platform-core` + `platform-db-pg` + `platform-db-sqlite`: `AuthProvider` (Argon2id + сессии), `neon-cli` (admin init/recovery), RBAC по `Site`/`Department`, оргструктура, `ModuleRegistry`, **Transactional Outbox (с retry/DLQ и идемпотентностью)**, аудит с настраиваемой ретенцией, безопасные вложения (immutable SHA-256), поиск PG/FTS5, согласованный бэкап, OpenAPI 3.1.
- Frontend **Engineering Workspace Shell (Вариант C)** + i18n (RU) + локальные ресурсы + встраивание SPA (`embed-ui` / `rust-embed`) в Standalone-бинарник `neon` (PR-07, ADR-011).
- **DoD Phase 1A:** ядро запускается в Standalone и Server, все базовые тесты и CI зелёные.

### Phase 1B — Vertical Slice: `mod-equipment` (PR-08 — PR-09)
- Полноценный прикладной модуль «Реестр и паспорт оборудования»: иерархия узлов, виртуализированная таблица, карточка + Inspector, безопасные вложения (PDF/PNG/JPG/DXF/DWG), история через Outbox, виджеты Dashboard.
- **DoD Phase 1B:** сквозная работа `mod-equipment` в Standalone и Server с авторизацией, API, хранением и E2E-тестами.

### Phase 1C — Production Hardening (PR-10)
- Нагрузочные испытания на 50 000 записей и проверка лимитов загрузки вложений (фиксация реального baseline).
- Автоматизированный тест согласованного backup/restore (БД + вложения).
- Сборка и проверка офлайн-дистрибутивов (air-gapped) для Linux и Windows, аудит безопасности и a11y.
- **DoD Phase 1C:** подтверждённая готовность MVP к пилотной эксплуатации.

## Phase 2: Эксплуатация, Персонал и ТОиР
- `mod-hr-org` (единственный владелец `Employee`), `mod-shifts`, `mod-tasks`, `mod-cmms` (неисправности и наряды).
- Подключение `OidcAuthProvider` / `LdapAuthProvider`, добавление английской локализации (`en`), экспорт аудита в SIEM.

## Phase 3: Склады ЗИП, База знаний, Обучение и Калькуляторы
- `mod-inventory` (с `InventoryCommandPort`), `mod-knowledge`, `mod-calculators`, `mod-training`.
- Реализация версионированного экспорта/импорта пакетов данных между Standalone и Server (манифест, контроль целостности, анализ конфликтов, RBAC).

## Phase 4: Аналитика, Изолированный OT-контур и Расширяемость
- `mod-analytics` (ECharts, MTBF/MTTR), `mod-integrations` (изолированный read-only коллектор в OT/IT DMZ), `mod-ai`, внешние расширения (out-of-process RPC / WASM Component Model).
