//! Real SQLite 3.54.1 integration tests covering the full PR-03 verification matrix.

use std::path::Path;

use platform_core::{
    MigrationError, MigrationSpec, ModuleRegistry, ModuleState, RegistryError,
    iso8601_to_utc_millis, utc_millis_to_iso8601,
};
use platform_db_sqlite::{
    SqliteBootstrapError, SqliteConfig, SqliteDatabase, SqliteMigrationRunner, SqliteTxContext,
};
use platform_sdk::{
    ActorKind, ApiPrefix, AppError, AuthContext, BoxFuture, CommandEnvelope, CorrelationId,
    DbNamespace, IdempotencyKey, ModuleId, ModuleManifest, TransactionalCommandPort, TxContext,
    UserId, UtcMillis,
};
use semver::{Version, VersionReq};
use sqlx::Row;

struct InsertCmd {
    label: String,
    fail_after_insert: bool,
}

struct SqliteInsertPort;

impl TransactionalCommandPort for SqliteInsertPort {
    type Command = InsertCmd;
    type Output = ();

    fn execute_in_tx<'a>(
        &'a self,
        tx: &'a mut dyn TxContext,
        cmd: CommandEnvelope<Self::Command>,
    ) -> BoxFuture<'a, Result<Self::Output, AppError>> {
        Box::pin(async move {
            let sq_tx =
                SqliteTxContext::downcast_mut(tx).map_err(|e| AppError::internal(e.to_string()))?;
            let conn = sq_tx
                .connection_mut()
                .map_err(|e| AppError::internal(e.to_string()))?;
            sqlx::query("INSERT INTO mod_demo_items (label) VALUES (?)")
                .bind(&cmd.payload.label)
                .execute(conn)
                .await
                .map_err(|e| AppError::internal(e.to_string()))?;
            if cmd.payload.fail_after_insert {
                return Err(AppError::domain_conflict(
                    "forced failure on second operation",
                ));
            }
            Ok(())
        })
    }
}

fn dummy_auth() -> AuthContext {
    AuthContext {
        actor: ActorKind::User {
            user_id: UserId::generate(),
            employee_id: None,
        },
        grants: vec![],
        correlation_id: CorrelationId::generate(),
    }
}

fn test_manifest(
    id: &str,
    ns: &str,
    prefix: &str,
    compat: &str,
) -> Result<ModuleManifest, Box<dyn std::error::Error>> {
    Ok(ModuleManifest {
        id: ModuleId::new(id)?,
        name_key: format!("modules.{id}.title"),
        version: Version::new(0, 1, 0),
        core_api_compat: VersionReq::parse(compat)?,
        dependencies: vec![],
        db_namespace: DbNamespace::new(ns)?,
        api_prefix: ApiPrefix::new(prefix)?,
        permissions: vec![],
        settings_schema: serde_json::json!({}),
        ui_routes: vec![],
        dashboard_widgets: vec![],
        events_published: vec![],
        events_subscribed: vec![],
    })
}

#[tokio::test]
async fn sqlite_full_pr03_integration_matrix() -> Result<(), Box<dyn std::error::Error>> {
    // 0. Reject network UNC location
    let unc_err =
        SqliteDatabase::open(&SqliteConfig::new(Path::new(r"\\fileserver\share\neon.db")))
            .await
            .err();
    assert!(matches!(
        unc_err,
        Some(SqliteBootstrapError::NetworkPathForbidden { .. })
    ));

    let db_path =
        std::env::temp_dir().join(format!("neon-pr03-matrix-{}.db", uuid::Uuid::now_v7()));
    let cfg = SqliteConfig::new(&db_path);
    let db = SqliteDatabase::open(&cfg).await?;

    // 1. Diagnostics: WAL, FTS5, synchronous=FULL, foreign_keys=ON
    assert!(db.diagnostics().fts5_enabled);
    assert!(db.diagnostics().foreign_keys_enabled);
    assert_eq!(db.diagnostics().journal_mode.to_ascii_lowercase(), "wal");
    assert_eq!(db.diagnostics().synchronous_mode, "FULL");

    // 2. Initial migration + idempotent repeat + tampered checksum rejection
    let runner = SqliteMigrationRunner::new(db.clone());
    let core_sql = include_str!("../../../migrations/sqlite/core/0001_init_core_metadata.sql");
    let core_migs = vec![MigrationSpec::new(
        "core",
        1,
        "init_core_metadata",
        core_sql,
    )];

    let first = runner.run_namespace("core", &core_migs).await?;
    assert_eq!(first.applied_versions, vec![1]);
    let repeat = runner.run_namespace("core", &core_migs).await?;
    assert_eq!(repeat.skipped_versions, vec![1]);

    let tampered = vec![MigrationSpec::new(
        "core",
        1,
        "init_core_metadata",
        "-- altered SQL",
    )];
    assert!(matches!(
        runner.run_namespace("core", &tampered).await,
        Err(MigrationError::ChecksumMismatch { .. })
    ));

    // 3. Concurrent migrations on writer pool
    let mod_migs = vec![MigrationSpec::new(
        "mod_demo",
        1,
        "create_demo_items",
        "CREATE TABLE IF NOT EXISTS mod_demo_items (id INTEGER PRIMARY KEY AUTOINCREMENT, label TEXT NOT NULL);",
    )];
    let (r1, r2) = tokio::join!(
        runner.run_namespace("mod_demo", &mod_migs),
        runner.run_namespace("mod_demo", &mod_migs)
    );
    r1?;
    r2?;

    // 4. TxContext atomicity: rollback on 2nd operation error + commit on success + double-commit rejected
    let port = SqliteInsertPort;
    {
        let mut tx = db.begin_tx().await?;
        port.execute_in_tx(
            &mut tx,
            CommandEnvelope {
                auth: dummy_auth(),
                idempotency_key: IdempotencyKey::new("sq-rb-1")?,
                payload: InsertCmd {
                    label: "rollback-1".to_string(),
                    fail_after_insert: false,
                },
            },
        )
        .await?;
        let second = port
            .execute_in_tx(
                &mut tx,
                CommandEnvelope {
                    auth: dummy_auth(),
                    idempotency_key: IdempotencyKey::new("sq-rb-2")?,
                    payload: InsertCmd {
                        label: "rollback-2".to_string(),
                        fail_after_insert: true,
                    },
                },
            )
            .await;
        assert!(second.is_err());
        tx.rollback().await?;
    }
    let count_rb: i64 = sqlx::query("SELECT COUNT(*) FROM mod_demo_items")
        .fetch_one(db.reader_pool())
        .await?
        .try_get(0)?;
    assert_eq!(count_rb, 0);

    {
        let mut tx = db.begin_tx().await?;
        for idx in 1..=2 {
            port.execute_in_tx(
                &mut tx,
                CommandEnvelope {
                    auth: dummy_auth(),
                    idempotency_key: IdempotencyKey::new(format!("sq-ok-{idx}"))?,
                    payload: InsertCmd {
                        label: format!("committed-{idx}"),
                        fail_after_insert: false,
                    },
                },
            )
            .await?;
        }
        tx.commit().await?;
        assert!(tx.commit().await.is_err());
    }

    // 5. Concurrent reader/writer access in WAL mode
    let reader_pool = db.reader_pool().clone();
    let writer_pool = db.writer_pool().clone();
    let (read_res, write_res) = tokio::join!(
        async move {
            sqlx::query("SELECT COUNT(*) FROM mod_demo_items")
                .fetch_one(&reader_pool)
                .await
        },
        async move {
            sqlx::query("INSERT INTO mod_demo_items (label) VALUES ('concurrent-write')")
                .execute(&writer_pool)
                .await
        }
    );
    let _ = read_res?;
    let _ = write_res?;

    // 6. UtcMillis <-> ISO-8601 TEXT persistence round-trip
    let ts = UtcMillis::from_unix_millis(1_795_180_800_789);
    let iso = utc_millis_to_iso8601(ts);
    sqlx::query(
        "INSERT OR REPLACE INTO core_instance_meta (id, source_instance_id, schema_version, created_at, updated_at) VALUES (1, ?, 1, ?, ?)",
    )
    .bind(uuid::Uuid::now_v7().to_string())
    .bind(&iso)
    .bind(&iso)
    .execute(db.writer_pool())
    .await?;
    let stored_iso: String = sqlx::query("SELECT created_at FROM core_instance_meta WHERE id = 1")
        .fetch_one(db.reader_pool())
        .await?
        .try_get(0)?;
    assert_eq!(iso8601_to_utc_millis(&stored_iso)?, ts);

    // 7. ModuleRegistry lifecycle + duplicate ID + incompatible version
    let mut reg = ModuleRegistry::new()?;
    let demo = test_manifest("mod-demo", "mod_demo", "/api/v1/demo", ">=0.1.0, <0.2.0")?;
    reg.register(demo.clone(), mod_migs)?;
    assert!(matches!(
        reg.register(demo.clone(), vec![]),
        Err(RegistryError::DuplicateRegistration(_))
    ));
    reg.validate_and_resolve()?;
    reg.migrate_all(&runner).await?;
    assert_eq!(reg.state(&demo.id), Some(&ModuleState::Ready));

    let mut bad_reg = ModuleRegistry::new()?;
    let bad = test_manifest("mod-old", "mod_old", "/api/v1/old", ">=9.0.0")?;
    bad_reg.register(bad, vec![])?;
    assert!(matches!(
        bad_reg.validate_and_resolve(),
        Err(RegistryError::ValidationFailed(_))
    ));

    // 8. Stop & restart verification
    db.close().await;
    let restarted = SqliteDatabase::open(&cfg).await?;
    let final_count: i64 = sqlx::query("SELECT COUNT(*) FROM mod_demo_items")
        .fetch_one(restarted.reader_pool())
        .await?
        .try_get(0)?;
    assert_eq!(final_count, 3);
    restarted.close().await;

    let _ = std::fs::remove_file(&db_path);
    let _ = std::fs::remove_file(db_path.with_extension("db-wal"));
    let _ = std::fs::remove_file(db_path.with_extension("db-shm"));
    Ok(())
}
