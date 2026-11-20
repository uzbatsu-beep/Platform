# ADR-007: Transactional Outbox в Foundation, CommandPort и гарантии доставки

- **Статус:** Утверждено (Decision Gate NEON)
- **Дата:** 2026-11-20

## Решение
1. Минимальная инфраструктура **Transactional Outbox** (`core_outbox_events` + `core_outbox_deliveries` с независимыми подписчиками, lease, retry/backoff и DLQ + `core_processed_events`, детализировано в `ADR-010`) включается в **Phase 1A (Foundation)**.
2. Гарантия доставки событий — **at-least-once**; обязательная идемпотентность подписчиков через `(consumer_id, event_id)`; конфликты оптимистической блокировки по HTTP `If-Match` возвращают **`412 Precondition Failed`** (RFC 9110), а доменные конфликты состояния и `expected_row_version` в теле команды — **`409 Conflict`** (уточнено в `ADR-011`).
3. Для межмодульных бизнес-операций, меняющих состояние, вводится контракт **`CommandPort`** (с `AuthContext`, `IdempotencyKey` и общим `&mut TxContext` для атомарных операций, детализировано в `ADR-010`).
