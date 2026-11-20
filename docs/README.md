# NEON — Модульная инженерно-технологическая платформа

## Назначение
**NEON** — высокопроизводительная, безопасная и масштабируемая модульная программная платформа для инженерно-технического и производственного персонала (инженеры АСУ ТП, технологи, электромеханики, механики, робототехники, энергетики, специалисты ТОиР, руководители служб и инструкторы).

Платформа работает на общей кодовой базе в двух режимах:
- **Standalone** — автономный запуск на локальном ПК (`127.0.0.1`, SQLite 3.54 WAL/FTS5, встроенный SPA, без интернета, без отдельной СУБД и без Node.js).
- **Server** — многопользовательская эксплуатация в локальной сети (Windows и Linux, настраиваемые IP/порт, TLS, PostgreSQL 18 baseline / 19 CI, RBAC).
- **Air-gapped deployment** — обязательное требование: все ресурсы интерфейса (шрифты, иконки, JS, CSS) поставляются локально без внешних CDN.

## Статус проекта
**PR-01 слит в `main` (`0bf1589`, 5/5 CI проверок на Linux/Windows успешно, Ruleset `27744630` активен).** Документация синхронизирована с `ADR-010` и `ADR-011`; следующий этап — `PR-02 (Platform SDK)`.

## Состав комплекта документации
- `VISION.md` — концепция продукта NEON и целевые роли.
- `REQUIREMENTS.md` — функциональные, нефункциональные и air-gapped требования.
- `ARCHITECTURE.md` — Modular Monolith, границы Core/модулей, Command/Query порты, Transactional Outbox и ограничения БД.
- `MODULE_SPEC.md` — контракт `ModuleManifest`, жизненный цикл, гарантии доставки событий и изоляция.
- `DATA_MODEL.md` — единая предметная модель (18 сущностей), строгое разделение `User`/`Employee` и готовность к экспорту/импорту.
- `API_CONTRACT.md` — стандарты REST/OpenAPI 3.1 (`utoipa`), RFC 9457, идемпотентность и оптимистические блокировки.
- `DESIGN_SYSTEM.md` — Engineering Workspace Shell (Вариант C), доступность, локализация (i18n RU) и плотность данных.
- `SECURITY.md` — модель угроз, `AuthProvider`, bootstrap/recovery администратора, безопасная работа с вложениями, честный статус аудита и OT-изоляция.
- `DEPLOYMENT.md` — Standalone, Server, air-gapped офлайн-установка/обновление и согласованный бэкап БД + вложений.
- `TEST_STRATEGY.md` — стратегия тестирования (PG 18/19 + SQLite 3.54), методика нагрузочных испытаний (50k) и CI.
- `ROADMAP.md` — поэтапный план (Phase 0, Phase 1A Foundation, Phase 1B Vertical Slice, Phase 1C Hardening, Phase 2–4).
- `REPOSITORY_STRUCTURE.md` — детальная структура Cargo Workspace и Frontend.
- `PR_PLAN.md` — план первых 10 функционально завершённых PR с критериями приёмки.
- `AGENTS.md` — обязательные правила для AI-разработчиков.
- `adr/` — журнал архитектурных решений (`ADR-001` — `ADR-011`).

## Утверждённый стек (ноябрь 2026)
- **Backend:** [Rust Stable 1.100.0](https://blog.rust-lang.org/releases/latest/), [Axum 0.8.x](https://docs.rs/crate/axum/latest), [Tokio](https://docs.rs/tokio), [SQLx 0.9.x](https://docs.rs/sqlx/latest/sqlx/), Serde, [tracing](https://tokio.rs/tokio/topics/tracing), [utoipa 6.0](https://docs.rs/utoipa/latest/utoipa/) + [utoipa-axum](https://docs.rs/utoipa-axum).
- **Frontend:** React 19 + TypeScript + [Vite 8.x](https://vite.dev/blog/announcing-vite8) + TanStack (Router, Query, [Table](https://tanstack.com/table/latest), [Virtual](https://tanstack.com/virtual/latest/docs/framework/react/react-virtual)) + [shadcn/ui](https://ui.shadcn.com/docs/installation/tanstack-router) + Tailwind CSS.
- **БД:** [PostgreSQL 18](https://www.postgresql.org/about/news/postgresql-187-1712-1616-1520-1425-and-19-rc-2-released-3442/) (server baseline) + [PostgreSQL 19](https://www.postgresql.org/about/news/postgresql-19-released-3449/) (CI); [SQLite 3.54.x](https://www.sqlite.org/download.html) (Standalone).
