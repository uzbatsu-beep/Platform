# NEON — Модульная инженерно-технологическая платформа

**Статус ветки `pr/01-workspace-bootstrap`:** Draft PR-01 (Workspace Bootstrap, Tooling & CI).

## Состав PR-01
- Cargo Workspace (`rust-toolchain.toml = 1.100.0`) с жёстким разделением `platform-sdk`, `platform-core`, `platform-db-pg`, `platform-db-sqlite`, `platform-cli-core`, `platform-cli`, `platform-server`.
- Раздельные feature-профили сборки:
  - `standalone` (`db-sqlite`): единый исполняемый файл `neon` с административными подкомандами (`serve`, `admin`, `migrate`, `backup`) и статически слинкованным SQLite **3.54.1** (`libsqlite3-sys = "=0.39.1"`, `bundled`, устраняет `RUSTSEC-2026-0459`).
  - `server` (`db-postgres`): серверный профиль для PostgreSQL 18 (baseline) / 19 (CI) + отдельная утилита `neon-cli`.
- Frontend-каркас (`frontend/`): React 19 + TypeScript + Vite 8.0 + `@vitejs/plugin-react` 6.3.0 + `@tailwindcss/vite` 4.2.2 + Vitest 5.1.1 + i18n (RU) без внешних CDN.
- Архитектурные, совместимостные и air-gapped проверки (`scripts/`) с позитивными и негативными автотестами (`scripts/tests/test_guards.py`).
- CI-конфигурации для **Linux** и **Windows** (`.github/workflows/ci-rust.yml`, `ci-frontend.yml`).

## Известные ограничения PR-01
1. **Lock-файлы (`Cargo.lock`, `frontend/pnpm-lock.yaml`):** не создаются в офлайн-песочнице — должны быть сгенерированы и закоммичены в среде с Rust 1.100.0, Node `>= 22.12`, pnpm `10.6.0` и доступом к реестрам (`cargo generate-lockfile` и `cd frontend && pnpm install --lockfile-only`).
2. **Встраивание SPA в Standalone (`embed-ui` / `rust-embed`):** перенесено в **PR-07** (после реализации Frontend Engineering Workspace Shell).
3. **Защита от сетевых ФС для SQLite:** в PR-01 реализована проверка UNC-путей (`is_unc_network_path`); OS-проверка типа смонтированной ФС (`statfs` / `GetDriveTypeW`) добавляется в **PR-03**.

## Сборка и локальная проверка
Подробные команды приведены в [`docs/LOCAL_BUILD.md`](docs/LOCAL_BUILD.md).

## Лицензия
Двойная лицензия **MIT OR Apache-2.0** (`LICENSE-MIT`, `LICENSE-APACHE`, `NOTICE`), Copyright 2026 NEON Engineering Team.
