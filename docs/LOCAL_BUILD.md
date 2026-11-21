# Локальная сборка и проверка NEON (Foundation)

## Предварительные требования
- **Rust:** `1.100.0` (`rust-toolchain.toml`).
- **Node.js:** `>= 22.12.0` и **pnpm:** `10.6.0`.
- **Python 3.11+:** для локального запуска скриптов проверок и их тестов.
- **SQLite:** системная установка не требуется — статически слинкован `libsqlite3-sys = "=0.39.1"` (`bundled`, SQLite **3.54.1**, закрывает `RUSTSEC-2026-0459`; `bundled-sqlcipher` не используется).

## 1. Использование закоммиченных lock-файлов
`Cargo.lock` и `frontend/pnpm-lock.yaml` уже входят в репозиторий. При обычной разработке их **не регенерировать**.
```bash
cargo fetch --locked
cd frontend && pnpm install --frozen-lockfile
```
Обновление зависимостей выполнять отдельным PR с повторной проверкой лицензий и advisories.

## 2. Проверка Backend (locked)
```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo check -p platform-server --no-default-features --features standalone --locked
cargo check -p platform-server --no-default-features --features server --locked
cargo check -p platform-cli --locked
cargo test --workspace --locked
cargo deny check
```

### Проверка устойчивости конкурентного bootstrap (PR-04.2)
После `cargo test --workspace --locked` выполнить на каждой целевой ОС (Bash / Windows Git Bash):

```bash
for i in {1..10}; do
  cargo test -p platform-db-sqlite --test identity_rbac_integration sqlite_full_pr04_identity_rbac_and_negative_security_suite --locked -- --exact || exit 1
done
```

Требование: 10/10 PASS, включая проверку конкурентного создания первого администратора, вход, отзыв сессий и password recovery.

## 3. Проверка Frontend (frozen lockfile)
```bash
python3 scripts/check_frontend_compat.py
cd frontend
pnpm install --frozen-lockfile
pnpm typecheck
pnpm build
```

## 4. Архитектурные, Air-gapped проверки и тесты скриптов
```bash
python3 -m unittest discover -s scripts/tests -v
python3 scripts/check_arch_boundaries.py
python3 scripts/check_airgapped_assets.py --target frontend/src --include-index
# После pnpm build:
python3 scripts/check_airgapped_assets.py --target frontend/dist
```
