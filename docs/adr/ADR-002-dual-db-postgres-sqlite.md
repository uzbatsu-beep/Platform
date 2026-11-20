# ADR-002: Раздельные адаптеры SQLx для PostgreSQL 18/19 и SQLite 3.54

- **Статус:** Утверждено (Decision Gate NEON)
- **Дата:** 2026-11-20

## Решение
Использовать [SQLx 0.9.x](https://docs.rs/sqlx/latest/sqlx/) с раздельными реализациями репозиториев (`platform-db-pg` и `platform-db-sqlite`) и раздельными миграциями без `AnyPool` ([SQLx macro docs](https://docs.rs/sqlx/latest/sqlx/macro.query.html)).
- **Server baseline:** [PostgreSQL 18](https://www.postgresql.org/about/news/postgresql-187-1712-1616-1520-1425-and-19-rc-2-released-3442/), дополнительный CI-таргет — [PostgreSQL 19](https://www.postgresql.org/about/news/postgresql-19-released-3449/).
- **Standalone:** [SQLite 3.54.1](https://www.sqlite.org/download.html) (статическая линковка `libsqlite3-sys = "=0.39.1"`, `bundled`, закрывает `RUSTSEC-2026-0459`), [WAL](https://www.sqlite.org/wal.html), **`synchronous = FULL` по умолчанию** (см. `ADR-011`), запрет сетевых ФС (SMB/NFS/UNC), выделенный writer-пул `max_connections=1`, `busy_timeout=5000`, `foreign_keys=ON`, [FTS5](https://sqlite.org/fts5.html), бэкапы через [`VACUUM INTO`](https://sqlite.org/lang_vacuum.html).
- **Ограничения изоляции:** схемы в PostgreSQL; строгие префиксы таблиц и CI-линтер SQL в SQLite.
