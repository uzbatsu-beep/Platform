# Спецификация модульной системы NEON (MODULE_SPEC)

## 1. Контракт ModuleManifest
Каждый модуль экспортирует статический `ModuleManifest`:
- `id`: уникальный slug (`mod-equipment`)
- `name_key`: ключ i18n (`modules.equipment.title`) — никаких захардкоженных строк
- `version`: SemVer (`0.1.0`)
- `core_api_compat`: SemVer-требование к `platform-sdk` (`>=0.1.0, <0.2.0`)
- `dependencies`: список обязательных/опциональных модулей с диапазонами SemVer
- `db_namespace`: схема PostgreSQL (`mod_equipment`) и префикс таблиц SQLite (`mod_equipment_`)
- `api_prefix`: префикс маршрутов (`/api/v1/equipment`)
- `permissions`: декларация прав `<module>:<resource>:<action>` и допустимых скоупов
- `settings_schema`: JSON Schema настроек модуля
- `ui_routes` и `dashboard_widgets`: декларации маршрутов UI и виджетов
- `events_published` и `events_subscribed`: типы и версии событий

## 2. Жизненный цикл модуля
1. **Registration & Validation:** проверка уникальности `id`/`api_prefix`/`db_namespace`, совместимости `core_api_compat`, отсутствия циклов в графе `dependencies` (fail-fast).
2. **Migration:** выполнение версионированных миграций модуля в его `db_namespace` с фиксацией в `core_module_migrations`.
3. **Sync:** синхронизация прав RBAC и настроек по умолчанию.
4. **Mount:** подключение Axum-роутера, OpenAPI-схем, обработчиков Outbox и health-индикаторов.
5. **Runtime Toggle:** включение/отключение модуля в пределах прав (отключённый модуль блокирует маршруты и скрывает UI-слоты).
6. **Graceful Shutdown:** остановка фоновых задач модуля по `CancellationToken`.

## 3. Гарантии доставки событий, идемпотентность и конфликты
- **Конверт события (`EventEnvelope`):** `event_id` (UUIDv7), `event_type`, `schema_version`, `source_instance_id`, `correlation_id`, `actor_user_id`, `occurred_at` (UTC), `payload` (JSON).
- **Гарантия доставки:** **at-least-once** через двухтабличный Transactional Outbox (`core_outbox_events` + `core_outbox_deliveries` по каждой паре `(event_id, consumer_id)`, см. `ADR-010`).
- **Идемпотентность подписчика:** каждый обработчик обязан проверять и фиксировать `(consumer_id, event_id)` в таблице `core_processed_events` в рамках собственной транзакции обработки. Повторная доставка того же `event_id` является безопасным no-op.
- **Ошибки, Lease и DLQ:** воркер захватывает доставку с `leased_until` (`FOR UPDATE SKIP LOCKED` в PG / `UPDATE ... RETURNING` в SQLite) для безопасного восстановления после crash; каждый потребитель имеет независимые `attempts`, экспоненциальный backoff и перевод в `dead_lettered` (DLQ) с ручным replay (см. `ADR-010`).
- **Конфликты состояния (ADR-011):** несовпадение HTTP-заголовка предусловия `If-Match` / `ETag` возвращает **`412 Precondition Failed`** (RFC 9110); конфликт доменного состояния или несовпадение `expected_row_version` в теле команды без `If-Match` возвращает **`409 Conflict`**.
