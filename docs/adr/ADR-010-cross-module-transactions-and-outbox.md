# ADR-010: Межмодульные транзакции (`CommandPort` / `TxContext`) и мультипотребительский Transactional Outbox

- **Статус:** Принято к реализации (PR-02 / PR-05)
- **Дата:** 2026-11-20

## 1. Межмодульные транзакции (`CommandPort`)
В `platform-sdk` вводится `TxContext`:
- **Атомарные операции (в общей `TxContext`):** доменная запись + `OutboxWriter::enqueue_in_tx`, доменная запись + `AuditCommandPort::record_in_tx`, в Phase 3 — закрытие наряда + `InventoryCommandPort::consume_part_in_tx`. SQL пишет только модуль-владелец.
- **Eventual Consistency (Outbox):** история оборудования (`mod-equipment`), поиск, уведомления, черновики БЗ.
- **Компенсирующие операции:** Blob Store (запись до коммита + tombstone/GC), внешние интеграции (Phase 4).

## 2. Мультипотребительский Transactional Outbox
- `core_outbox_events` (неизменяемый журнал событий) + `core_outbox_deliveries` (независимый статус, `attempts`, `next_attempt_at`, `leased_until`, `lease_owner`, `last_error` на каждую пару `(event_id, consumer_id)`).
- Восстановление после crash обработчика по истечении `leased_until`; идемпотентность через `core_processed_events (consumer_id, event_id)`.
