# Модель угроз и требования безопасности NEON (SECURITY)

## 1. Аутентификация (`AuthProvider`), Bootstrap и Recovery
- **Абстракция `AuthProvider`:** Core работает через интерфейс провайдера аутентификации. В MVP реализуется `LocalAuthProvider` (Argon2id + серверные сессии в `HttpOnly`, `Secure`, `SameSite=Lax` cookie + CSRF-защита + rate limiting). В Phase 2 подключаются `OidcAuthProvider` / `LdapAuthProvider` без изменения бизнес-логики.
- **Первоначальная настройка администратора (Bootstrap):** платформа не создаёт дефолтный пароль `admin/admin`. Первый администратор создаётся через `neon admin init` (в Standalone) / `neon-cli admin init` (в Server) (интерактивно или через одноразовый setup-токен с коротким TTL, блокируемый автоматически сразу после создания первого администратора).
- **Восстановление административного доступа (Recovery):** выполняется только локально на сервере через `neon admin reset-password --username <admin>` (или `neon-cli admin reset-password`) при наличии OS-доступа к конфигурации; процедура принудительно отзывает все активные сессии пользователя и фиксирует событие в журнале аудита.

## 2. Авторизация (RBAC со скоупами)
- Deny-by-default для всех маршрутов, кроме `/health/live` и `/api/v1/auth/login`.
- Серверная проверка `<module>:<resource>:<action>` + `Scope` (`Global`, `Site`, `Department`, `Own`) на уровне `application` и `CommandPort`.

## 3. Безопасная загрузка, хранение и выдача документов
- **Разрешённые форматы MVP:** `PDF`, `PNG`, `JPG/JPEG` и распространённые инженерные форматы (`DXF`, `DWG`, `STEP`/`STP`, `CSV`, `TXT`, `DOCX`, `XLSX`) — строго как бинарные вложения с безопасным скачиванием. Серверный парсинг DXF/DWG и собственный CAD-просмотрщик в MVP не реализуются.
- **Защита от повреждённых и вредоносных файлов:**
  - Проверка реальных сигнатур (magic bytes) и соответствия расширению/MIME (для текстовых/инженерных форматов — базовая проверка структуры заголовка и запрет исполняемых бинарников ELF/PE/Mach-O/скриптов).
  - Запрет активных веб-типов (`HTML`, `JS`, `SVG` не отдаются inline; исполняемые файлы отклоняются).
  - Запрет автоматической распаковки архивов на сервере (защита от zip-bomb).
  - **Настраиваемые администратором лимиты** (значения по умолчанию для MVP, подлежащие валидации нагрузочными тестами в Phase 1C):
    - `max_file_size_media_mb = 25` (PDF, PNG, JPG/JPEG);
    - `max_file_size_engineering_mb = 50` (DXF, DWG, STEP, DOCX, XLSX);
    - `max_request_body_mb = 100`;
    - квота хранилища на подразделение/систему (настраиваемая).
  - Хранение вне webroot в Content-Addressed хранилище по SHA-256 (оригинальное имя хранится только в метаданных БД и санитизируется при отдаче).
  - Выдача файлов с `Content-Disposition: attachment`, `X-Content-Type-Options: nosniff`, `Cache-Control: private, no-store`; для inline-предпросмотра PDF/PNG/JPEG — изолированный заголовок `Content-Security-Policy: default-src 'none'; sandbox`.
  - Опциональный интерфейс `AttachmentScanner` (hook для ClamAV/ICAP в Server-режиме).

## 4. Аудит изменений (честные гарантии)
- Критичные операции фиксируются в таблице `core_audit_log` (`who`, `when`, `scope`, `entity`, `action`, `diff`, `request_id`).
- **Ограничение изменений:** в MVP реализована модель **append-only на уровне приложения и прав БД** (роль приложения имеет только `INSERT`/`SELECT` на таблицу аудита, без `UPDATE`/`DELETE`), с **настраиваемыми сроками хранения (retention)** и архивацией/очисткой по регламенту администратора.
- **Важная оговорка:** на этапе MVP **не заявляется криптографическая неизменяемость** аудита. Хэш-цепочки, WORM-хранилище и экспорт в SIEM (Syslog/CEF/JSONL) вынесены в последующий этап.

## 5. Изоляция промышленного контура (OT/IT)
Платформа работает в IT/MES-контуре; прямое управление оборудованием/ПЛК запрещено. Будущие промышленные интеграции (Phase 4) выносятся в изолированный read-only коллектор в DMZ.

## PR-04.1 Security Hardening Baseline
- Fail-fast валидация конфигурации (`NeonRuntimeConfig::validate`): запрет plain HTTP на non-loopback адресах в Standalone и запрет запуска Server без TLS или `behind_trusted_proxy = true`.
- Защита от IP spoofing в `LoginRateLimiter`: `ClientIpResolver` игнорирует `X-Forwarded-For` / `X-Real-IP` от недоверенных peer IP.
- Защита от IDOR и TOCTOU в `deactivate_user` и `revoke_assignment`: все проверки выполняются внутри транзакции БД по фактическим данным, без доверия клиентскому `target_scope`.
- Защита Tokio executor от CPU/RAM-голодания: Argon2id выполняется в `spawn_blocking` под ограниченным семафором.
