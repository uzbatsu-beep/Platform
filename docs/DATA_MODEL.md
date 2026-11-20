# Единая предметная модель NEON (DATA_MODEL)

## 1. Общие правила моделирования и готовность к экспорту/импорту
Для всех доменных сущностей уже в **Phase 1** обязательны:
- **Стабильный идентификатор:** `id` типа `UUIDv7` (PostgreSQL: `UUID`; SQLite: `TEXT`).
- **Метаданные происхождения и версий:**
  - `source_instance_id` (`UUID` экземпляра NEON, создавшего запись);
  - `schema_version` (`INTEGER` версии структуры записи / контракта);
  - `row_version` (`BIGINT` для оптимистической блокировки);
  - `created_at`, `updated_at`, `archived_at` (UTC: `TIMESTAMPTZ` в PG, ISO-8601 `TEXT` в SQLite).
- **Обмен данными между Standalone и Server:** полноценная двусторонняя синхронизация не входит в MVP. В последующих фазах обмен будет реализован через версионированный пакет экспорта/импорта с манифестом, SHA-256 контролем целостности, dry-run анализом конфликтов и проверкой RBAC. **Копирование файла SQLite как механизм импорта в PostgreSQL строго запрещено.**

## 2. Чёткое разделение `User` и `Employee`
Чтобы исключить дублирование и размытое владение кадровыми данными:
- **`User` (владелец — `platform-core`):** отвечает исключительно за аутентификацию, авторизацию и UI-профиль (`id`, `username`, `password_hash`, `display_name`, `is_active`, `role_assignments`, `preferences_json`, `employee_id: Option<EmployeeId>`).
- **`Employee` (владелец — `mod-hr-org`, Phase 2):** единственный владелец кадровых данных (ФИО, табельный номер, должность, разряд, допуски, подразделение, статус занятости).
- В Phase 1 (`platform-core` + `mod-equipment`) кадровые таблицы в Core **не создаются**. Отображение ответственных лиц идёт через `IdentityDisplayPort` по `UserId` (с заложенным nullable полем `employee_id` для бесшовной привязки после появления `mod-hr-org`).

## 3. Матрица владения базовыми сущностями (18 сущностей)

| Сущность | Владелец | Ключевые ссылки |
|---|---|---|
| `Organization`, `Site`, `Department`, `Location` | `platform-core` | Иерархия оргструктуры и площадок (источник скоупов RBAC) |
| `User`, `Role` | `platform-core` | Учётные записи, роли, права и скоупы; `User.employee_id` (опц.) |
| `Document` | `platform-core` | Полиморфная привязка `(owner_module, owner_type, owner_id)` + SHA-256 blob |
| `Employee` | `mod-hr-org` | Единственный владелец кадровых данных; опциональная связь 1:1 с `User` |
| `Shift` | `mod-shifts` | `site_id`, `department_id`, `employee_id` |
| `Equipment`, `EquipmentComponent` | `mod-equipment` | `site_id`, `department_id`, `location_id`, дерево узлов, `responsible_user_id` / `employee_id` |
| `Task` | `mod-tasks` | `department_id`, `assignee_employee_id`, `source_ref` |
| `WorkOrder`, `Fault` | `mod-cmms` | `equipment_id`, `component_id`, `task_id`, `employee_id` |
| `SparePart`, `InventoryTransaction` | `mod-inventory` | `department_id`, `equipment_ids`, `work_order_id`, `employee_id` |
| `KnowledgeArticle` | `mod-knowledge` | `equipment_id` / `model_code`, `fault_ids`, `document_ids` |
| `TrainingCourse` | `mod-training` | `department_ids`, `equipment_ids`, `article_ids` |

## 4. Сквозной сценарий совместной работы модулей
`Fault` (`mod-cmms`) → событие `cmms.fault.reported` → `WorkOrder` + `Task` (`mod-tasks`) с назначением `Employee` → вызов `InventoryCommandPort::consume_part` (`mod-inventory`, с `IdempotencyKey` и RBAC) → закрытие `WorkOrder` (`cmms.work_order.completed`) → подписчик `mod-equipment` (с проверкой `core_processed_events`) пишет запись в историю `Equipment` → формирование черновика `KnowledgeArticle` (`mod-knowledge`) → индексация в Core Search.
