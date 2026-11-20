# Структура репозитория NEON (REPOSITORY_STRUCTURE)

```text
neon/
├── .github/workflows/
│   ├── ci-rust.yml                 # fmt, clippy, test (PG 18, PG 19, SQLite 3.54), audit, deny, arch-lint
│   ├── ci-frontend.yml             # typecheck, lint, vitest, vite build, openapi-drift, airgapped-check, playwright
│   └── release-airgapped.yml       # офлайн-архивы Standalone/Server (Linux/Windows) + SHA256SUMS
├── Cargo.toml                      # Workspace + [workspace.dependencies]
├── Cargo.lock
├── rust-toolchain.toml             # channel = "1.100.0"
├── deny.toml                       # Политика cargo-deny
├── config/
│   ├── standalone.example.toml
│   └── server.example.toml
├── docs/                           # Комплект проектной документации + adr/ADR-001..011
├── scripts/
│   ├── check_arch_boundaries.py    # Проверка графа crates и запрета кросс-модульных SQL
│   ├── check_airgapped_assets.py   # Проверка отсутствия внешних/protocol-relative CDN URL
│   ├── check_frontend_compat.py    # Проверка совместимости Vite 8 / plugin-react 6 / tailwindcss 4.2.2 / vitest 5
│   ├── tests/test_guards.py        # Позитивные и негативные тесты guard-скриптов
│   └── loadtest/                   # Скрипты k6/oha и генератор 50k оборудования
├── crates/
│   ├── platform-sdk/               # Контракты: IDs, ModuleManifest, QueryPort, CommandPort, EventEnvelope, AppError
│   ├── platform-core/              # domain / application / presentation ядра
│   ├── platform-db-pg/             # PostgreSQL 18/19 адаптеры Core + migrations/postgres/core/
│   ├── platform-db-sqlite/         # SQLite 3.54 адаптеры Core + migrations/sqlite/core/
│   ├── platform-cli-core/          # Общие определения подкоманд CLI (serve, admin, migrate, backup)
│   ├── platform-cli/               # Отдельная Server-утилита neon-cli поверх platform-cli-core
│   ├── platform-server/            # Composition root: Axum, TLS, embed-ui, graceful shutdown
│   └── modules/
│       └── mod-equipment/          # [Phase 1B] domain / application / infrastructure/{pg,sqlite} / presentation
└── frontend/
    ├── package.json
    ├── pnpm-lock.yaml
    ├── src/
    │   ├── app/                    # Router, QueryClient, i18n, Theme
    │   ├── shell/                  # Engineering Workspace Shell (Вариант C)
    │   ├── shared/                 # OpenAPI-клиент, shadcn/ui, локальные шрифты и иконки
    │   ├── locales/ru/             # Словарь RU (типизированные ключи)
    │   └── modules/equipment/      # [Phase 1B] UI модуля mod-equipment
    └── tests/                      # Vitest + Playwright + axe-core
```
