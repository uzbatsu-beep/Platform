//! Transactional Outbox event contracts, per-consumer delivery tracking, and at-least-once semantics (ADR-010).

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::auth::ActorKind;
use crate::error::AppError;
use crate::ids::{CorrelationId, EventId, SchemaVersion, SourceInstanceId, UtcMillis};
use crate::ports::{BoxFuture, TxContext};

/// Formal delivery guarantee of the NEON Transactional Outbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliverySemantics {
    AtLeastOnce,
}

/// Immutable domain event envelope persisted in `core_outbox_events` inside the mutating transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventEnvelope {
    pub event_id: EventId,
    pub event_type: String,
    pub schema_version: SchemaVersion,
    pub source_instance_id: SourceInstanceId,
    pub correlation_id: CorrelationId,
    pub actor: ActorKind,
    pub occurred_at: UtcMillis,
    pub payload: Value,
}

impl EventEnvelope {
    #[must_use]
    pub fn new(
        event_type: impl Into<String>,
        schema_version: SchemaVersion,
        source_instance_id: SourceInstanceId,
        correlation_id: CorrelationId,
        actor: ActorKind,
        payload: Value,
    ) -> Self {
        Self {
            event_id: EventId::generate(),
            event_type: event_type.into(),
            schema_version,
            source_instance_id,
            correlation_id,
            actor,
            occurred_at: UtcMillis::now(),
            payload,
        }
    }

    #[must_use]
    pub const fn delivery_semantics(&self) -> DeliverySemantics {
        DeliverySemantics::AtLeastOnce
    }
}

/// Independent delivery state per `(event_id, consumer_id)` in `core_outbox_deliveries` (ADR-010).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryStatus {
    Pending,
    InProgress,
    Delivered,
    DeadLettered,
}

/// Per-consumer delivery record supporting independent retry, lease recovery, and DLQ.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboxDeliveryRecord {
    pub event_id: EventId,
    pub consumer_id: String,
    pub status: DeliveryStatus,
    pub attempts: u32,
    pub max_attempts: u32,
    pub next_attempt_at: UtcMillis,
    pub leased_until: Option<UtcMillis>,
    pub lease_owner: Option<String>,
    pub last_error: Option<String>,
}

impl OutboxDeliveryRecord {
    #[must_use]
    pub fn new_pending(
        event_id: EventId,
        consumer_id: impl Into<String>,
        max_attempts: u32,
        now: UtcMillis,
    ) -> Self {
        Self {
            event_id,
            consumer_id: consumer_id.into(),
            status: DeliveryStatus::Pending,
            attempts: 0,
            max_attempts: max_attempts.max(1),
            next_attempt_at: now,
            leased_until: None,
            lease_owner: None,
            last_error: None,
        }
    }

    #[must_use]
    pub fn is_lease_expired(&self, now: UtcMillis) -> bool {
        match self.leased_until {
            Some(until) => now >= until,
            None => true,
        }
    }

    pub fn mark_delivered(&mut self) {
        self.status = DeliveryStatus::Delivered;
        self.leased_until = None;
        self.lease_owner = None;
        self.last_error = None;
    }

    /// Records a failed consumer attempt, scheduling exponential backoff or transitioning to DLQ.
    pub fn record_failure(
        &mut self,
        error: impl Into<String>,
        now: UtcMillis,
        base_backoff_secs: i64,
    ) {
        self.attempts = self.attempts.saturating_add(1);
        self.leased_until = None;
        self.lease_owner = None;
        self.last_error = Some(error.into());
        if self.attempts >= self.max_attempts {
            self.status = DeliveryStatus::DeadLettered;
        } else {
            self.status = DeliveryStatus::Pending;
            let shift = self.attempts.saturating_sub(1).min(10);
            let delay_secs = u64::try_from(base_backoff_secs.max(1))
                .unwrap_or(1)
                .saturating_mul(1_u64 << shift);
            self.next_attempt_at = now.add_seconds(delay_secs);
        }
    }
}

/// Deduplication record stored in `core_processed_events` inside each consumer's transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessedEventRecord {
    pub consumer_id: String,
    pub event_id: EventId,
    pub processed_at: UtcMillis,
}

/// Port implemented by `platform-core` / DB adapters for atomic outbox writes inside `TxContext`.
pub trait OutboxWriter: Send + Sync {
    fn enqueue_in_tx<'a>(
        &'a self,
        tx: &'a mut dyn TxContext,
        event: EventEnvelope,
    ) -> BoxFuture<'a, Result<(), AppError>>;
}
