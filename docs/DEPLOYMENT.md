# Сценарии развёртывания и бэкапа NEON (DEPLOYMENT)

## 1. Air-gapped Deployment (обязательное требование)
- В production-сборке **отсутствуют любые обращения к внешним CDN, шрифтам и API** (проверяется в CI скриптом `scripts/check_airgapped_assets.py` и жёстким `Content-Security-Policy: default-src 'self'`).
- **Офлайн-установка:** поставка самодостаточных архивов (`neon-standalone-<os>-<arch>.zip/.tar.gz`, `neon-server-<os>-<arch>.tar.gz` и опционального `docker save` OCI-образа) с файлом `SHA256SUMS`.
- **Процедура офлайн-обновления:**
  1. Проверка `SHA256SUMS` дистрибутива.
  2. Выполнение согласованного бэкапа текущей версии (`neon backup create` (или `neon-cli backup create` для Server)).
  3. Остановка сервиса (graceful shutdown), замена бинарника/статики.
  4. Предварительная проверка миграций (`neon migrate --dry-run` (или `neon-cli migrate --dry-run`) / `--migrate-only`).
  5. Запуск сервиса и проверка `/health/ready`; при сбое — откат бинарника и восстановление из бэкапа.

## 2. Режимы Standalone и Server
- **Standalone:** Windows 10/11 и Linux, единый исполняемый файл `neon` (объединяет HTTP-сервер и CLI-подкоманды из `platform-cli-core`), биндинг строго `127.0.0.1:<port>`, статически слинкованный SQLite 3.54.1 (`libsqlite3-sys = "=0.39.1"`, WAL + FTS5 + `synchronous = FULL`, запрет сетевых ФС SMB/NFS/UNC), без внешней СУБД и Node.js. Встраивание SPA (`embed-ui`) добавляется в PR-07 (ADR-011).
- **Server:** Linux (`systemd` / контейнер) и Windows Server (Windows Service), бинарник `neon` + отдельная административная утилита `neon-cli` (поверх `platform-cli-core`), настраиваемые `bind_ip` и `tcp_port`, обязательный TLS 1.3 (`rustls` или доверенный корпоративный reverse proxy), PostgreSQL 18 (baseline) / 19 (CI).

## 3. Согласованное резервное копирование БД и файловых вложений
Для исключения рассинхронизации между БД и диском используется **Content-Addressed Immutable Blob Store (SHA-256)** с отложенным удалением (tombstone + grace period ≥ 24 ч):
1. Запись нового файла на диск выполняется атомарно (`tmp -> fsync -> rename`) **до** коммита записи в БД; существующие блобы никогда не перезаписываются.
2. При старте бэкапа сначала снимается консистентный снимок БД в точке `T0`:
   - SQLite: [`VACUUM INTO`](https://sqlite.org/lang_vacuum.html) (копирование `cp` запрещено);
   - PostgreSQL: `pg_dump --format=custom` (или `pg_basebackup` + WAL для PITR).
3. Из снимка `T0` читается перечень активных SHA-256 ссылок вложений, и в пакет бэкапа копируются соответствующие immutable-блобы (фоновый GC заблокирован на время бэкапа).
4. Формируется `backup-manifest.json` (дата, `source_instance_id`, версии миграций, SHA-256 снимка БД и всех блобов).
5. Выполняется автоматическая верификация: `PRAGMA integrity_check` (SQLite) / `pg_restore --list` (PG) + сверка SHA-256 манифеста.
