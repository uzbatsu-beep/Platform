# NEON Platform SDK — Публичный API и правила версионирования (`crates/platform-sdk`)

## 1. Назначение и архитектурные границы
`platform-sdk` — минимальный контрактный крейт, не зависящий от `axum`, `sqlx`, `tokio`, PostgreSQL, SQLite, `platform-core` и прикладных модулей (`mod-*`).
Единственные разрешённые зависимости: `semver`, `serde`, `serde_json`, `thiserror`, `uuid`.

## 2. Публичные модули и контракты
- **`ids`:** типизированные `UUIDv7` идентификаторы (`OrganizationId`, `SiteId`, `DepartmentId`, `LocationId`, `UserId`, `RoleId`, `EmployeeId`, `DocumentId`, `EquipmentId`, `EquipmentComponentId`, `EventId`, `CorrelationId`), `SourceInstanceId` (отклоняет `nil`/`max`), `SchemaVersion` (`>= 1`), `RowVersion` (конвертация в HTTP `ETag` `"v<N>"` и парсинг strong/weak `If-Match`), `IdempotencyKey` (до 128 байт, без управляющих символов) и `EntityMetadata`.
- **`auth`:** `PermissionKey` (`<module>:<resource>:<action>`), `PermissionDef`, `Scope` (`Global` ⊇ `Site` ⊇ `Department`, `Own`), `ActorKind` (`User { user_id, employee_id }` | `System`), `AuthContext::require_permission` (различает `RbacForbidden` и `RbacScopeDenied`).
- **`manifest`:** `ModuleId` (`mod-*`), `DbNamespace` (`mod_*`), `ApiPrefix` (`/api/v1/*`), `ModuleManifest` и `validate_registry` (SemVer `core_api_compat`, уникальность `id`/`api_prefix`/`db_namespace`/`permission`, проверка принадлежности прав пространству модуля, контроль версий зависимостей и топологическая сортировка с обнаружением циклов).
- **`ports`:** `TxContext` / `TxEngine` (`Postgres` | `Sqlite`) для атомарных межмодульных операций (ADR-010), `QueryPort`, `CommandPort`, `TransactionalCommandPort`, `CommandEnvelope<C>`.
- **`events`:** `EventEnvelope` (`DeliverySemantics::AtLeastOnce`), `OutboxDeliveryRecord` (`core_outbox_deliveries`: `Pending`/`InProgress`/`Delivered`/`DeadLettered`, `leased_until`, экспоненциальный backoff и DLQ), `ProcessedEventRecord` (`core_processed_events`), `OutboxWriter::enqueue_in_tx`.
- **`error`:** `AppError`, `ErrorCode` и RFC 9457 `ProblemDetails` с жёстким разделением **`412 Precondition Failed`** (HTTP `If-Match` / `ETag`) и **`409 Conflict`** (доменные конфликты и `expected_row_version` в теле команды, ADR-011), а также защитой от утечки внутренних деталей `500 Internal Error`.

## 3. Правила версионирования контрактов
- Версия SDK фиксируется в `Cargo.toml` (`SDK_CONTRACT_VERSION`, SemVer).
- Каждый модуль объявляет `core_api_compat: VersionReq` (например, `>=0.1.0, <0.2.0`), проверяемый `validate_registry` при старте платформы (fail-fast).
- Добавление новых опциональных полей/вариантов с сохранением обратной совместимости — минорный релиз (`0.x.0` в `0.y`, затем `1.x.0`); ломающие изменения трейтов/структур — мажорный релиз с обновлением `core_api_compat`.
- Схемы сущностей и событий версионируются независимо через `SchemaVersion` для безопасной эволюции Outbox и будущего экспорта/импорта.

## Временные метки SDK
`UtcMillis` — тип UTC Unix epoch milliseconds (`u64`, сериализация числом). Публичная HTTP-презентация может преобразовывать значение в RFC 3339. Источник системного времени инкапсулирован; новые зависимости от `chrono` не вводятся.
