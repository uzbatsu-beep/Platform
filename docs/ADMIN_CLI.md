# NEON Administrative CLI — Bootstrap и Recovery (PR-04)

## 1. Общие принципы
- Обе команды используют единую логику `platform-cli-core` + `AdminBootstrapService`:
  - **Standalone:** `neon admin init`, `neon admin reset-password --username <admin>`
  - **Server:** `neon-cli admin init`, `neon-cli admin reset-password --username <admin>`
- Ни одна из команд не доступна через публичный HTTP API.
- Ввод пароля выполняется без отображения в терминале (`rpassword 7.5.5`, Linux + Windows) или через `--password-stdin` в автотестах. Пароли никогда не попадают в stdout, stderr, логи или БД в открытом виде.

## 2. Первичная инициализация (`admin init`)
- Атомарно создаёт первого глобального администратора, системную роль `platform_administrator`, глобальное назначение и запись `security.admin_bootstrap_initialized` в `core_security_events`.
- Повторный или конкурентный запуск `admin init` завершается безопасным отказом (`409 Conflict` / ненулевой код выхода). Дефолтный `admin/admin` отсутствует.

## 3. Восстановление доступа (`admin reset-password --username <admin>`)
- Требует локального OS-доступа к серверу/БД.
- В одной транзакции обновляет Argon2id-хэш, **принудительно отзывает все активные сессии пользователя** и записывает `security.admin_password_recovered` в `core_security_events`.
- *Примечание по аудиту:* `core_security_events` — минимальный долговечный фундамент событий безопасности PR-04; полноценный append-only Audit Log и retention реализуются в PR-05.

## PR-04.1 Hardening: Реальная интеграция CLI (`neon` и `neon-cli`)
- Команды `neon admin init`, `neon admin reset-password`, `neon-cli admin init`, `neon-cli admin reset-password` и `migrate` подключены напрямую к реальным адаптерам SQLite 3.54.1 и PostgreSQL 18/19 (заглушки с exit code 2 удалены).
- Пароли принимаются через `rpassword` (без эха в терминале) или `--password-stdin`, никогда не передаются в аргументах и не выводятся в stdout/stderr.
- `source_instance_id` автоматически генерируется (UUIDv7) и сохраняется в `core_instance_meta` при первом запуске.
