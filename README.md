# NEON — Модульная инженерно-технологическая платформа

**Состояние на 21.11.2026:** PR-01—PR-04 и PR-04.1 слиты в `main` (последний merge `42c90e8`). Реализованы SDK, PostgreSQL/SQLite DB Layer, ModuleRegistry, Identity/Auth/RBAC, HTTP runtime и административная CLI. **PR-04.2** исправляет недетерминированный SQLite-тест: post-merge Rust CI `main` завершился 5/7 PASS. PR-05 пока не начинался.

**До эксплуатации:** независимый security review и проверка TLS/reverse proxy.

## Реализованная основа платформы
- Cargo Workspace (`rust-toolchain.toml = 1.100.0`) с жёстким разделением `platform-sdk`, `platform-core`, `platform-db-pg`, `platform-db-sqlite`, `platform-cli-core`, `platform-cli`, `platform-server`.
- Раздельные feature-профили сборки:
  - `standalone` (`db-sqlite`): единый исполняемый файл `neon` с действующими `serve`, `admin init`, `admin reset-password`, миграциями и пока не реализованным `backup` (запланирован PR-06) и статически слинкованным SQLite **3.54.1** (`libsqlite3-sys = "=0.39.1"`, `bundled`, устраняет `RUSTSEC-2026-0459`).
  - `server` (`db-postgres`): серверный профиль для PostgreSQL 18 (baseline) / 19 (CI) + отдельная утилита `neon-cli`.
- Frontend-каркас (`frontend/`): React 19 + TypeScript + Vite 8.0 + `@vitejs/plugin-react` 6.3.0 + `@tailwindcss/vite` 4.2.2 + Vitest 5.1.1 + i18n (RU) без внешних CDN.
- Архитектурные, совместимостные и air-gapped проверки (`scripts/`) с позитивными и негативными автотестами (`scripts/tests/test_guards.py`).
- CI-конфигурации для **Linux** и **Windows** (`.github/workflows/ci-rust.yml`, `ci-frontend.yml`).

## Известные ограничения
1. `Cargo.lock` и `frontend/pnpm-lock.yaml` зафиксированы. Сборки: `--locked` / `--frozen-lockfile`.
2. Встраивание SPA и Engineering Workspace Shell отложены до PR-07.
3. Проверка сетевых файловых систем SQLite имеет ограничения на Windows mapped drives.
4. Полный Transactional Outbox/Audit/Ready/OpenAPI ещё не реализован (PR-05); Blob Store, поиск и согласованный Backup/Restore — PR-06.
5. Стабильность `main` должна быть подтверждена post-merge CI после PR-04.2.

## Сборка и локальная проверка
Подробные команды приведены в [`docs/LOCAL_BUILD.md`](docs/LOCAL_BUILD.md).

## Лицензия
Двойная лицензия **MIT OR Apache-2.0** (`LICENSE-MIT`, `LICENSE-APACHE`, `NOTICE`), Copyright 2026 NEON Engineering Team.
