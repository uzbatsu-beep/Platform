# Требования к API NEON (API_CONTRACT)

## 1. Стандарты и OpenAPI
- Базовый префикс: `/api/v1/...`.
- Автоматическая генерация OpenAPI 3.1 из Rust-кода через [utoipa 6.0](https://docs.rs/utoipa/latest/utoipa/) + [utoipa-axum](https://docs.rs/utoipa-axum).
- В CI выполняется проверка отсутствия расхождения (drift check) между сгенерированной OpenAPI-схемой и TypeScript-клиентом во фронтенде.

## 2. Ошибки (RFC 9457 Problem Details)
Все ошибки возвращаются как `application/problem+json` с `request_id`, стабильным машинным `code` (для локализации на клиенте через i18n) и без раскрытия SQL, путей ФС или stack trace.

## 3. Пагинация, фильтры, идемпотентность и конфликты
- Cursor-based пагинация для больших реестров (`Equipment`, `AuditLog`, `WorkOrder`), offset/limit (с лимитом `<= 200`) там, где нужен произвольный переход.
- Строгий allowlist полей сортировки и фильтрации.
- Заголовок `Idempotency-Key` для мутирующих команд, изменяющих состояние.
- Оптимистическая блокировка (ADR-011): нарушение HTTP-заголовка `If-Match` / `ETag` возвращает **`412 Precondition Failed`** (RFC 9110); доменные конфликты состояния или несовпадение `expected_row_version` в теле команды без `If-Match` возвращают **`409 Conflict`**.

## 4. Системные endpoints
- `GET /health/live` — активность процесса.
- `GET /health/ready` — готовность БД, хранилища вложений и статус Outbox/DLQ.
- `GET /api/v1/core/bootstrap` — текущая сессия, профиль, права, активные модули, локаль и настройки пользователя.
- `GET /api/v1/core/search` — глобальный поиск с серверной фильтрацией по правам RBAC.
