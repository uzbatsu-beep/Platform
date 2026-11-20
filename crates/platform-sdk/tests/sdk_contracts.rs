//! Positive, negative, and contract tests for NEON Platform SDK (PR-02).
//! Zero `.unwrap()`, `.expect()`, or `panic!()` calls — compliant with workspace Clippy lints.

use std::any::Any;

use platform_sdk::{
    ActorKind, ApiPrefix, AppError, AuthContext, CommandEnvelope, CommandPort, CorrelationId,
    DashboardWidgetDef, DbNamespace, DeliverySemantics, DeliveryStatus, DepartmentId,
    EntityMetadata, EquipmentId, ErrorCode, EventContractDef, EventEnvelope, EventId,
    IdValidationError, IdempotencyKey, ManifestError, ModuleDependency, ModuleId, ModuleManifest,
    OutboxDeliveryRecord, PermissionDef, PermissionGrant, PermissionKey, QueryPort, RowVersion,
    SchemaVersion, Scope, ScopeKind, SiteId, SourceInstanceId, TransactionalCommandPort, TxContext,
    TxEngine, UiRouteDef, UserId, UtcMillis, sdk_semver, validate_registry,
};
use semver::{Version, VersionReq};
use uuid::Uuid;

#[test]
fn ids_serialize_roundtrip_and_reject_placeholders() -> Result<(), Box<dyn std::error::Error>> {
    let eq = EquipmentId::generate();
    let json = serde_json::to_string(&eq)?;
    let decoded: EquipmentId = serde_json::from_str(&json)?;
    assert_eq!(eq, decoded);

    // Reject nil and max UUIDs on deserialization
    let nil_json = serde_json::to_string(&Uuid::nil())?;
    let max_json = serde_json::to_string(&Uuid::max())?;
    assert!(serde_json::from_str::<EquipmentId>(&nil_json).is_err());
    assert!(serde_json::from_str::<SourceInstanceId>(&max_json).is_err());
    // Domain identifiers must reject UUIDv4, not merely nil/max placeholders.
    let old_uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000")?;
    assert_eq!(
        EquipmentId::try_from_uuid(old_uuid),
        Err(IdValidationError::NonV7Uuid)
    );

    // SchemaVersion rejects 0
    assert_eq!(
        SchemaVersion::new(0),
        Err(IdValidationError::ZeroSchemaVersion)
    );
    assert_eq!(SchemaVersion::V1.get(), 1);

    // RowVersion ETag round-trip (strong & weak) and overflow safety
    let v1 = RowVersion::INITIAL;
    assert_eq!(v1.to_etag(), r#""v1""#);
    assert_eq!(RowVersion::from_etag(r#""v1""#)?, v1);
    assert!(RowVersion::from_etag(r#"W/"v42""#).is_err());
    assert!(RowVersion::from_etag("invalid").is_err());
    assert_eq!(
        RowVersion::new(u64::MAX).next(),
        Err(IdValidationError::RowVersionOverflow)
    );

    // IdempotencyKey validation
    assert_eq!(
        IdempotencyKey::new("   "),
        Err(IdValidationError::EmptyIdempotencyKey)
    );
    assert_eq!(
        IdempotencyKey::new("a".repeat(129)),
        Err(IdValidationError::IdempotencyKeyTooLong)
    );
    assert_eq!(
        IdempotencyKey::new(
            "bad
key"
        ),
        Err(IdValidationError::InvalidIdempotencyKeyChars)
    );
    let key = IdempotencyKey::new("  req-001  ")?;
    assert_eq!(key.as_str(), "req-001");

    // EntityMetadata serialization check
    let meta = EntityMetadata {
        source_instance_id: SourceInstanceId::generate(),
        schema_version: SchemaVersion::V1,
        row_version: RowVersion::INITIAL,
        created_at: UtcMillis::now(),
        updated_at: UtcMillis::now(),
        archived_at: None,
    };
    let meta_json = serde_json::to_string(&meta)?;
    let meta_back: EntityMetadata = serde_json::from_str(&meta_json)?;
    assert_eq!(meta, meta_back);
    Ok(())
}

#[test]
fn rbac_scope_containment_and_error_distinction() -> Result<(), Box<dyn std::error::Error>> {
    let site_a = SiteId::generate();
    let site_b = SiteId::generate();
    let dept_a1 = DepartmentId::generate();
    let dept_a2 = DepartmentId::generate();
    let user_1 = UserId::generate();
    let user_2 = UserId::generate();

    let read_perm = PermissionKey::parse("equipment:asset:read")?;
    let write_perm = PermissionKey::parse("equipment:asset:write")?;
    assert!(PermissionKey::parse("invalid").is_err());
    assert!(PermissionKey::parse("Upper:asset:read").is_err());
    assert!(PermissionKey::parse("a:b:c:d").is_err());

    let ctx = AuthContext {
        actor: ActorKind::User {
            user_id: user_1,
            employee_id: None,
        },
        grants: vec![
            PermissionGrant {
                permission: read_perm.clone(),
                scope: Scope::Site { site_id: site_a },
            },
            PermissionGrant {
                permission: write_perm.clone(),
                scope: Scope::Department {
                    site_id: site_a,
                    department_id: dept_a1,
                },
            },
        ],
        correlation_id: CorrelationId::generate(),
    };

    // Site grant covers departments within the same site, but not another site
    assert!(ctx.has_permission(
        &read_perm,
        &Scope::Department {
            site_id: site_a,
            department_id: dept_a2
        }
    ));
    assert!(!ctx.has_permission(&read_perm, &Scope::Site { site_id: site_b }));

    // Department write grant allows dept_a1, denies dept_a2 with RbacScopeDenied (403)
    assert!(
        ctx.require_permission(
            &write_perm,
            &Scope::Department {
                site_id: site_a,
                department_id: dept_a1
            }
        )
        .is_ok()
    );
    let scope_err = ctx
        .require_permission(
            &write_perm,
            &Scope::Department {
                site_id: site_a,
                department_id: dept_a2,
            },
        )
        .err();
    assert_eq!(
        scope_err.as_ref().map(AppError::code),
        Some(ErrorCode::RbacScopeDenied)
    );

    // Missing permission completely yields RbacForbidden (403)
    let archive_perm = PermissionKey::parse("equipment:asset:archive")?;
    let forb_err = ctx
        .require_permission(&archive_perm, &Scope::Own { user_id: user_2 })
        .err();
    assert_eq!(
        forb_err.as_ref().map(AppError::code),
        Some(ErrorCode::RbacForbidden)
    );
    Ok(())
}

fn sample_manifest(
    id: &str,
    ns: &str,
    prefix: &str,
    compat: &str,
    deps: Vec<ModuleDependency>,
    perm: &str,
) -> Result<ModuleManifest, Box<dyn std::error::Error>> {
    Ok(ModuleManifest {
        id: ModuleId::new(id)?,
        name_key: format!("modules.{id}.title"),
        version: Version::new(0, 1, 0),
        core_api_compat: VersionReq::parse(compat)?,
        dependencies: deps,
        db_namespace: DbNamespace::new(ns)?,
        api_prefix: ApiPrefix::new(prefix)?,
        permissions: vec![PermissionDef {
            key: PermissionKey::parse(perm)?,
            description_key: format!("permissions.{perm}"),
            allowed_scopes: vec![ScopeKind::Site, ScopeKind::Department],
        }],
        settings_schema: serde_json::json!({"type": "object", "additionalProperties": false}),
        ui_routes: vec![UiRouteDef {
            path: "/equipment".to_string(),
            nav_label_key: "nav.equipment".to_string(),
            required_permission: Some(PermissionKey::parse(perm)?),
        }],
        dashboard_widgets: vec![DashboardWidgetDef {
            id: "equipment.summary".to_string(),
            title_key: "widgets.equipment.summary".to_string(),
            required_permission: Some(PermissionKey::parse(perm)?),
        }],
        events_published: vec![EventContractDef {
            event_type: "equipment.created".to_string(),
            schema_version: SchemaVersion::V1,
        }],
        events_subscribed: vec![],
    })
}

#[test]
fn manifest_registry_validates_dag_order_and_rejects_violations()
-> Result<(), Box<dyn std::error::Error>> {
    let sdk = sdk_semver()?;
    let eq = sample_manifest(
        "mod-equipment",
        "mod_equipment",
        "/api/v1/equipment",
        ">=0.1.0, <0.2.0",
        vec![],
        "equipment:asset:read",
    )?;
    let cmms = sample_manifest(
        "mod-cmms",
        "mod_cmms",
        "/api/v1/cmms",
        ">=0.1.0, <0.2.0",
        vec![ModuleDependency {
            module_id: ModuleId::new("mod-equipment")?,
            version_req: VersionReq::parse("^0.1.0")?,
            optional: false,
        }],
        "cmms:order:read",
    )?;

    // Valid dependency order: mod-equipment MUST start before mod-cmms
    let order = validate_registry(&[cmms.clone(), eq.clone()], &sdk)
        .map_err(|errs| format!("unexpected errors: {errs:?}"))?;
    assert_eq!(order, vec![eq.id.clone(), cmms.id.clone()]);

    // Incompatible core_api_compat
    let bad_compat = sample_manifest(
        "mod-legacy",
        "mod_legacy",
        "/api/v1/legacy",
        ">=2.0.0",
        vec![],
        "legacy:item:read",
    )?;
    let errs = validate_registry(&[bad_compat], &sdk)
        .err()
        .unwrap_or_default();
    assert!(
        errs.iter()
            .any(|e| matches!(e, ManifestError::IncompatibleCoreApi { .. }))
    );

    // Cyclic dependency A <-> B
    let cyc_a = sample_manifest(
        "mod-alpha",
        "mod_alpha",
        "/api/v1/alpha",
        ">=0.1.0",
        vec![ModuleDependency {
            module_id: ModuleId::new("mod-beta")?,
            version_req: VersionReq::parse("^0.1.0")?,
            optional: false,
        }],
        "alpha:item:read",
    )?;
    let cyc_b = sample_manifest(
        "mod-beta",
        "mod_beta",
        "/api/v1/beta",
        ">=0.1.0",
        vec![ModuleDependency {
            module_id: ModuleId::new("mod-alpha")?,
            version_req: VersionReq::parse("^0.1.0")?,
            optional: false,
        }],
        "beta:item:read",
    )?;
    let cyc_errs = validate_registry(&[cyc_a, cyc_b], &sdk)
        .err()
        .unwrap_or_default();
    assert!(
        cyc_errs
            .iter()
            .any(|e| matches!(e, ManifestError::CyclicDependency(_)))
    );

    // Invalid module settings_schema must fail at registry validation.
    let mut bad_schema = eq.clone();
    bad_schema.settings_schema = serde_json::json!(42);
    let schema_errors = validate_registry(&[bad_schema], &sdk)
        .err()
        .unwrap_or_default();
    assert!(
        schema_errors
            .iter()
            .any(|e| matches!(e, ManifestError::InvalidSettingsSchema(_)))
    );

    // Permission namespace hijacking
    let hijack = sample_manifest(
        "mod-tasks",
        "mod_tasks",
        "/api/v1/tasks",
        ">=0.1.0",
        vec![],
        "equipment:asset:write",
    )?;
    let hijack_errs = validate_registry(&[hijack], &sdk).err().unwrap_or_default();
    assert!(
        hijack_errs
            .iter()
            .any(|e| matches!(e, ManifestError::PermissionNamespaceMismatch { .. }))
    );
    Ok(())
}

#[test]
fn app_error_rfc9457_separates_412_and_409_and_hides_internal_causes() {
    let req_id = CorrelationId::generate();

    // 412 Precondition Failed (HTTP If-Match mismatch)
    let err_412 = AppError::precondition_failed("ETag mismatch", Some(RowVersion::new(7)));
    let pd_412 = err_412.to_problem_details(Some(req_id));
    assert_eq!(pd_412.status, 412);
    assert_eq!(pd_412.code, ErrorCode::OptimisticLockPreconditionFailed);
    assert_eq!(pd_412.current_etag.as_deref(), Some(r#""v7""#));

    // 409 Conflict (domain state & JSON body row_version)
    let err_409_domain = AppError::domain_conflict("Duplicate inventory code");
    let pd_409_domain = err_409_domain.to_problem_details(Some(req_id));
    assert_eq!(pd_409_domain.status, 409);
    assert_eq!(pd_409_domain.code, ErrorCode::ConflictDomainState);

    let err_409_row = AppError::row_version_conflict(RowVersion::new(3), RowVersion::new(4));
    let pd_409_row = err_409_row.to_problem_details(Some(req_id));
    assert_eq!(pd_409_row.status, 409);
    assert_eq!(pd_409_row.code, ErrorCode::ConflictRowVersion);
    assert_eq!(pd_409_row.current_etag.as_deref(), Some(r#""v4""#));

    // 500 Internal Error must NEVER expose SQL/internal detail in ProblemDetails
    let err_500 = AppError::internal("SQLSTATE 42P01: secret_table does not exist");
    let pd_500 = err_500.to_problem_details(Some(req_id));
    assert_eq!(pd_500.status, 500);
    assert!(!pd_500.detail.contains("SQLSTATE"));
    assert!(!pd_500.detail.contains("secret_table"));
    assert_eq!(
        err_500.internal_detail(),
        Some("SQLSTATE 42P01: secret_table does not exist")
    );
}

#[test]
fn outbox_event_and_per_consumer_delivery_backoff_dlq() -> Result<(), Box<dyn std::error::Error>> {
    let env = EventEnvelope::new(
        "equipment.status_changed",
        SchemaVersion::V1,
        SourceInstanceId::generate(),
        CorrelationId::generate(),
        ActorKind::System {
            service: "mod-equipment".to_string(),
        },
        serde_json::json!({"status": "maintenance"}),
    );
    assert_eq!(env.delivery_semantics(), DeliverySemantics::AtLeastOnce);
    assert_eq!(env.actor_user_id, None);
    let user_id = UserId::generate();
    let user_event = EventEnvelope::new(
        "equipment.assigned",
        SchemaVersion::V1,
        SourceInstanceId::generate(),
        CorrelationId::generate(),
        ActorKind::User {
            user_id,
            employee_id: None,
        },
        serde_json::json!({"equipment": "test"}),
    );
    assert_eq!(user_event.actor_user_id, Some(user_id));
    assert_eq!(
        serde_json::from_str::<EventEnvelope>(&serde_json::to_string(&user_event)?)?.actor_user_id,
        Some(user_id)
    );

    let now = UtcMillis::now();
    let mut delivery = OutboxDeliveryRecord::new_pending(env.event_id, "mod-search", 2, now);
    assert_eq!(delivery.status, DeliveryStatus::Pending);
    assert!(delivery.is_lease_expired(now));

    // First failure -> Pending with backoff
    delivery.record_failure("temporary lock", now, 5);
    assert_eq!(delivery.status, DeliveryStatus::Pending);
    assert_eq!(delivery.attempts, 1);
    assert_eq!(delivery.next_attempt_at, now.add_seconds(5));

    // Second failure -> DeadLettered (max_attempts = 2)
    delivery.record_failure("permanent schema mismatch", now.add_seconds(10), 5);
    assert_eq!(delivery.status, DeliveryStatus::DeadLettered);
    assert_eq!(delivery.attempts, 2);

    // Independent second consumer can still succeed
    let mut second = OutboxDeliveryRecord::new_pending(EventId::generate(), "mod-audit", 5, now);
    second.mark_delivered();
    assert_eq!(second.status, DeliveryStatus::Delivered);
    Ok(())
}

// Compile-time contract verification for QueryPort, CommandPort, TransactionalCommandPort, and TxContext
struct DummyTx(TxEngine);
impl TxContext for DummyTx {
    fn engine(&self) -> TxEngine {
        self.0
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

struct DummyQuery;
impl QueryPort for DummyQuery {
    type Request = EquipmentId;
    type Response = String;

    fn execute<'a>(
        &'a self,
        _ctx: &'a AuthContext,
        req: Self::Request,
    ) -> platform_sdk::BoxFuture<'a, Result<Self::Response, AppError>> {
        Box::pin(async move { Ok(req.to_string()) })
    }
}

struct DummyCmd;
impl CommandPort for DummyCmd {
    type Command = EquipmentId;
    type Output = RowVersion;

    fn execute<'a>(
        &'a self,
        _cmd: CommandEnvelope<Self::Command>,
    ) -> platform_sdk::BoxFuture<'a, Result<Self::Output, AppError>> {
        Box::pin(async { Ok(RowVersion::INITIAL) })
    }
}

impl TransactionalCommandPort for DummyCmd {
    type Command = EquipmentId;
    type Output = RowVersion;

    fn execute_in_tx<'a>(
        &'a self,
        tx: &'a mut dyn TxContext,
        _cmd: CommandEnvelope<Self::Command>,
    ) -> platform_sdk::BoxFuture<'a, Result<Self::Output, AppError>> {
        let engine = tx.engine();
        Box::pin(async move {
            match engine {
                TxEngine::Postgres | TxEngine::Sqlite => Ok(RowVersion::INITIAL),
            }
        })
    }
}

#[test]
fn port_traits_support_both_standalone_and_server_tx_engines() {
    let mut pg_tx = DummyTx(TxEngine::Postgres);
    let sqlite_tx = DummyTx(TxEngine::Sqlite);
    assert_eq!(pg_tx.engine(), TxEngine::Postgres);
    assert_eq!(sqlite_tx.engine(), TxEngine::Sqlite);
    assert!(pg_tx.as_any_mut().is::<DummyTx>());
    let _q: &dyn QueryPort<Request = EquipmentId, Response = String> = &DummyQuery;
    let _c: &dyn CommandPort<Command = EquipmentId, Output = RowVersion> = &DummyCmd;
    let _tc: &dyn TransactionalCommandPort<Command = EquipmentId, Output = RowVersion> = &DummyCmd;
}
