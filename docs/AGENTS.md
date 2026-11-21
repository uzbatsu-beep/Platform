# Обязательные правила для AI-разработчиков NEON (AGENTS)

## 1. Архитектурные инварианты
1. **Тонкий presentation-слой:** никакой бизнес-логики и прямого SQL в Axum-обработчиках.
2. **Строгие границы модулей:** `platform-core` не зависит от `mod-*`; модули не обращаются к чужим таблицам/схемам напрямую и взаимодействуют только через `QueryPort`, `CommandPort` и `DomainEvent` (Transactional Outbox).
3. **Никакой фиктивной универсальности SQL:** запрещён `sqlx::AnyPool`; адаптеры и миграции PostgreSQL (18/19) и SQLite (3.54) поддерживаются раздельно за общими доменными трейтами.
4. **Чёткое разделение `User` и `Employee`:** не добавлять кадровые поля в `platform-core::User`.
5. **Air-gapped и i18n:** запрещены внешние CDN/шрифты/скрипты и захардкоженные пользовательские строки в UI/API.
6. **Честность и отсутствие заглушек:** запрещены `todo!()`, фейковые тесты и неподтверждённые заявления (включая заявление криптографической неизменяемости аудита в MVP).

## 2. Правила PR и проверок
- Небольшие функционально завершённые PR строго по `PR_PLAN.md`; **не выполнять автоматическое слияние PR без согласования**.
- **Обязательные проверки действующего CI (Foundation, PR-01—PR-04.2):** `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, `cargo check` Standalone/Server с `--locked`, `cargo test --workspace --locked` (включая SQLite runtime), `cargo-deny`, Python-тесты и архитектурные/air-gapped guards, `pnpm install --frozen-lockfile`, `pnpm typecheck`, `pnpm build` и сканирование готового `dist/` на Linux/Windows.
- **Семь обязательных GitHub checks Ruleset `27744630`:** `arch-and-security-guards`, `rust-quality-and-build (ubuntu-latest)`, `rust-quality-and-build (windows-latest)`, `frontend-build-and-airgap (ubuntu-latest)`, `frontend-build-and-airgap (windows-latest)`, `postgres-18-integration`, `postgres-19-integration`. Не переименовывать и не отключать.
- **Стабильность:** 10 повторов SQLite bootstrap-теста на Linux/Windows, затем отдельная проверка post-merge CI; нельзя подменять успешностью PR CI результат более позднего push-CI.
- **Этапные проверки:** `pnpm lint/test`, Vitest/Playwright и отдельный `cargo audit` вводятся по плану. Запрещено выдавать не реализованную или не выполненную проверку за PASS.
