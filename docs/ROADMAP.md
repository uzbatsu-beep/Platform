# План развития NEON (ROADMAP)

## Phase 0: Architecture Research & Planning *(Завершена)*
Утверждён Decision Gate, согласованы стек, модель данных, air-gapped требования, структура репозитория и план PR.

## Phase 1: MVP (разделена на 3 этапа)

### Phase 1A — Foundation (PR-01—PR-04.1 слиты, PR-04.2 на проверке)
**В `main` реализовано:**
- PR-01 (`0bf1589`): Cargo Workspace, Rust 1.100.0, lock-файлы, CI.
- PR-02 (`376616d`): SDK, манифесты, UUIDv7, RBAC-контракты и порты.
- PR-03 (`56034dc`): PostgreSQL 18/19, SQLite 3.54.1, транзакционные миграции, ModuleRegistry.
- PR-04 (`dcc7a02`): Identity/AuthProvider, Argon2id, Scoped RBAC, оргструктура.
- PR-04.1 (`42c90e8`): HTTP/CLI runtime, client IP/rate-limit, исправления IDOR, E2E.

**Блокер CI:** post-merge Rust Linux/Windows — FAIL из-за гонки в SQLite-тесте: победителем bootstrap может быть `admin2`, а тест входит как `admin`. PR-04.2 использует имя реального победителя и добавляет 10 повторов на обеих ОС.

**Остаётся реализовать:**
- PR-05 — Transactional Outbox, retry/DLQ, аудит, `/health/ready`, OpenAPI 3.1 / TS-клиент.
- PR-06 — Blob Store, поиск, согласованный Backup/Restore.
- PR-07 — Engineering Workspace Shell, i18n RU, встраивание SPA, frontend E2E.
- **DoD:** семь обязательных CI-проверок на итоговом `main` зелёные; готовность к производственной эксплуатации оценивается отдельно.

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
