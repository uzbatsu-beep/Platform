# NEON Identity, AuthProvider & Sessions (PR-04)

## 1. Архитектура `AuthProvider`
Бизнес-логика аутентификации изолирована за интерфейсом `platform_core::identity::AuthProvider`.
- В PR-04 реализован **`LocalAuthProvider`** (Argon2id + нормализация `username` + timing-safe dummy verify).
- Подключение `OidcAuthProvider` / `LdapAuthProvider` в Phase 2 не требует изменений в `AuthenticationService`, `SessionRepository` или HTTP-слое.

## 2. Параметры Argon2id и политика паролей
- Библиотека: `argon2 = "0.5.3"` (RustCrypto, MIT/Apache-2.0) + `rand_core` (`getrandom` OS CSPRNG).
- Параметры по умолчанию: `Argon2id v0x13`, **`m = 19 456 KiB` (19 MiB), `t = 2`, `p = 1`**, 32-байтный вывод, 16-байтная уникальная соль, хранение в PHC-формате (`$argon2id$v=19$...`). Обоснование: соответствует минимуму OWASP 2026 и обеспечивает приемлемую задержку на автономных цеховых ноутбуках (Standalone) и многопользовательских серверах (Server); параметры ограничены безопасными пределами (`19 MiB..256 MiB`, `t = 2..10`, `p = 1..8`).
- Автоматический rehash (`needs_rehash`) при успешном входе после усиления параметров.
- Политика паролей: минимум **12 символов**, допускаются длинные парольные фразы до **256 символов** без искусственных требований спецсимволов или принудительной периодической смены.

## 3. Серверные сессии, Cookie, CSRF и Rate Limiting
- **Сессии:** непрозрачный 256-битный CSPRNG-токен в cookie `neon_session`; в БД (`core_sessions`) хранится только SHA-256 отпечаток (`token_hash_sha256`).
- **Сроки действия:** sliding idle timeout (по умолчанию 30 мин) + absolute timeout (12 ч); ротация сессии при входе (отзыв предыдущей cookie, защита от session fixation); мгновенный пересчёт прав из БД на каждом запросе.
- **Cookie:** `HttpOnly; SameSite=Lax; Path=/` + обязательный `Secure` в Server-режиме (или за доверенным TLS reverse proxy). Исключение HTTP без `Secure` разрешено **строго** для Standalone loopback (`127.0.0.1` / `::1`) и блокируется на любых внешних адресах.
- **CSRF:** привязанный к сессии 256-битный CSRF-токен (`X-CSRF-Token`, сравнение через `ct_eq`) + обязательная проверка `Origin` по белому списку доверенных origins.
- **Rate Limiting:** ограниченный по памяти in-memory `LoginRateLimiter` по `(source_ip, normalized_username)` без перманентной блокировки администратора. *Ограничение:* in-memory лимитер защищает один экземпляр; для многосерверного Server-развёртывания требуется общий store или лимитирование на reverse proxy.
