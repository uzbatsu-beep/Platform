//! Real PostgreSQL 18 / 19 integration tests for PR-03.
//!
//! Set `NEON_TEST_PG_URL` to run against a real PostgreSQL 18 or 19 instance.
//! When `NEON_REQUIRE_PG_TESTS=1` (mandatory in GitHub Actions PG jobs), missing `NEON_TEST_PG_URL`
//! causes an immediate test failure (never silently skipped).

use platform_core::{MigrationError, MigrationSpec, ModuleRegistry, ModuleState, RegistryError};
use platform_db_pg::{MIN_POSTGRES_MAJOR_VERSION, PgDatabase, PgMigrationRunner, PgTxContext};
use platform_sdk::{
    ActorKind, ApiPrefix, AppError, AuthContext, BoxFuture, CommandEnvelope, CorrelationId,
    DbNamespace, IdempotencyKey, ModuleId, ModuleManifest, TransactionalCommandPort, TxContext,
    UserId, UtcMillis,
};
use semver::{Version, VersionReq};
use sqlx::Row;

fn test_pg_url() -> Result<Option<String>, String> {
    let required = std::env::var("NEON_REQUIRE_PG_TESTS").unwrap_or_default() == "1";
    match std::env::var("NEON_TEST_PG_URL") {
        Ok(url) if !url.trim().is_empty() => Ok(Some(url)),
        _ if required => {
            Err("NEON_REQUIRE_PG_TESTS=1 is set, but NEON_TEST_PG_URL is missing".to_string())
        }
        _ => Ok(None),
    }
}

struct InsertItemCmd {
    table: String,
    label: String,
    fail_after_insert: bool,
}

struct PgInsertPort;

impl TransactionalCommandPort for PgInsertPort {
    type Command = InsertItemCmd;
    type Output = ();

    fn execute_in_tx<'a>(
        &'a self,
        tx: &'a mut dyn TxContext,
        cmd: CommandEnvelope<Self::Command>,
    ) -> BoxFuture<'a, Result<Self::Output, AppError>> {
        Box::pin(async move {
            let pg_tx =
                PgTxContext::downcast_mut(tx).map_err(|e| AppError::internal(e.to_string()))?;
            let conn = pg_tx
                .connection_mut()
                .map_err(|e| AppError::internal(e.to_string()))?;
            let sql = format!("INSERT INTO {} (label) VALUES ($1)", cmd.payload.table);
            sqlx::query(&sql)
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
async fn pg_full_pr03_integration_matrix() -> Result<(), Box<dyn std::error::Error>> {
    let Some(url) = test_pg_url().map_err(|e| e)? else {
        return Ok(());
    };

    // 1. Connect & version diagnostics (PG 18 or 19)
    let db = PgDatabase::connect_url(&url, 8).await?;
    assert!(db.diagnostics().major_version >= MIN_POSTGRES_MAJOR_VERSION);

    // 2. UtcMillis <-> TIMESTAMPTZ millisecond round-trip
    let ts = UtcMillis::from_unix_millis(1_795_180_800_456);
    assert_eq!(db.roundtrip_utc_millis(ts).await?, ts);

    // 3. Initial migration + idempotent repeat + tampered checksum rejection
    let runner = PgMigrationRunner::new(db.clone());
    let core_sql = include_str!("../../../migrations/postgres/core/0001_init_core_metadata.sql");
    let core_migs = vec![MigrationSpec::new(
        "core",
        1,
        "init_core_metadata",
        core_sql,
    )];

    let first = runner.run_namespace("core", &core_migs).await?;
    assert!(first.applied_versions == vec![1] || first.skipped_versions == vec![1]);
    let repeat = runner.run_namespace("core", &core_migs).await?;
    assert_eq!(repeat.skipped_versions, vec![1]);

    let tampered = vec![MigrationSpec::new(
        "core",
        1,
        "init_core_metadata",
        "-- altered SQL",
    )];
    let tampered_err = runner.run_namespace("core", &tampered).await.err();
    assert!(matches!(
        tampered_err,
        Some(MigrationError::ChecksumMismatch { .. })
    ));

    // 4. Concurrent migrations on isolated test schema (unique per run)
    let suffix = format!("{}", uuid::Uuid::now_v7().simple());
    let ns_a = format!("mod_t{}", &suffix[..8]);
    let create_table_sql = format!(
        "CREATE TABLE IF NOT EXISTS {ns_a}.items (id SERIAL PRIMARY KEY, label TEXT NOT NULL);"
    );
    let mod_migs = vec![MigrationSpec::new(
        &ns_a,
        1,
        "create_items",
        create_table_sql,
    )];
    let (r1, r2) = tokio::join!(
        runner.run_namespace(&ns_a, &mod_migs),
        runner.run_namespace(&ns_a, &mod_migs)
    );
    r1?;
    r2?;

    // 5. TxContext atomicity: rollback on 2nd operation error + commit on success + double-commit rejected
    let port = PgInsertPort;
    let table = format!("{ns_a}.items");

    // 5a. Error mid-transaction -> ROLLBACK leaves 0 rows
    {
        let mut tx = db.begin_tx().await?;
        port.execute_in_tx(
            &mut tx,
            CommandEnvelope {
                auth: dummy_auth(),
                idempotency_key: IdempotencyKey::new("pg-rb-1")?,
                payload: InsertItemCmd {
                    table: table.clone(),
                    label: "should-rollback-1".to_string(),
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
                    idempotency_key: IdempotencyKey::new("pg-rb-2")?,
                    payload: InsertItemCmd {
                        table: table.clone(),
                        label: "should-rollback-2".to_string(),
                        fail_after_insert: true,
                    },
                },
            )
            .await;
        assert!(second.is_err());
        tx.rollback().await?;
    }
    let count_after_rb: i64 = sqlx::query(&format!("SELECT COUNT(*) FROM {table}"))
        .fetch_one(db.pool())
        .await?
        .try_get(0)?;
    assert_eq!(count_after_rb, 0);

    // 5b. Two writes + commit -> both rows persisted; second commit rejected
    {
        let mut tx = db.begin_tx().await?;
        for idx in 1..=2 {
            port.execute_in_tx(
                &mut tx,
                CommandEnvelope {
                    auth: dummy_auth(),
                    idempotency_key: IdempotencyKey::new(format!("pg-ok-{idx}"))?,
                    payload: InsertItemCmd {
                        table: table.clone(),
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
    let count_after_commit: i64 = sqlx::query(&format!("SELECT COUNT(*) FROM {table}"))
        .fetch_one(db.pool())
        .await?
        .try_get(0)?;
    assert_eq!(count_after_commit, 2);

    // 6. ModuleRegistry end-to-end lifecycle + negative duplicate/incompatible cases
    let mut reg = ModuleRegistry::new()?;
    let m1 = test_manifest(
        &format!("mod-t{}", &suffix[..8]),
        &ns_a,
        &format!("/api/v1/t{}", &suffix[..8]),
        ">=0.1.0, <0.2.0",
    )?;
    reg.register(m1.clone(), mod_migs.clone())?;
    assert!(matches!(
        reg.register(m1.clone(), vec![]),
        Err(RegistryError::DuplicateRegistration(_))
    ));
    reg.validate_and_resolve()?;
    reg.migrate_all(&runner).await?;
    assert_eq!(reg.state(&m1.id), Some(&ModuleState::Ready));

    let mut bad_reg = ModuleRegistry::new()?;
    let bad_mod = test_manifest("mod-bad", "mod_bad", "/api/v1/bad", ">=9.0.0")?;
    bad_reg.register(bad_mod, vec![])?;
    assert!(matches!(
        bad_reg.validate_and_resolve(),
        Err(RegistryError::ValidationFailed(_))
    ));

    // 7. Stop & restart cleanly
    db.close().await;
    let db_restarted = PgDatabase::connect_url(&url, 4).await?;
    let count_after_restart: i64 = sqlx::query(&format!("SELECT COUNT(*) FROM {table}"))
        .fetch_one(db_restarted.pool())
        .await?
        .try_get(0)?;
    assert_eq!(count_after_restart, 2);
    db_restarted.close().await;

    Ok(())
}
