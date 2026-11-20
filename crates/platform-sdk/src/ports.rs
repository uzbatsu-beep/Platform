//! Database-agnostic `TxContext`, `QueryPort`, and `CommandPort` contracts (ADR-010).

use std::any::Any;
use std::future::Future;
use std::pin::Pin;

use crate::auth::AuthContext;
use crate::error::AppError;
use crate::ids::IdempotencyKey;

/// Object-safe boxed future alias avoiding external async-trait dependencies in `platform-sdk`.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Underlying database engine executing a `TxContext`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxEngine {
    Postgres,
    Sqlite,
}

/// Database-agnostic transaction boundary shared across atomic `CommandPort` calls (ADR-010).
///
/// Concrete adapters (`platform-db-pg`, `platform-db-sqlite`) implement `TxContext` and downcast
/// via `as_any_mut()` inside their own infrastructure layer, keeping `platform-sdk` free of `sqlx`.
pub trait TxContext: Send {
    fn engine(&self) -> TxEngine;
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

/// Declares whether a cross-module command joins a caller's transaction or manages its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandExecutionMode {
    AtomicInTx,
    StandaloneTx,
}

/// Envelope required by every state-mutating `CommandPort` (AuthContext + IdempotencyKey).
#[derive(Debug, Clone)]
pub struct CommandEnvelope<C> {
    pub auth: AuthContext,
    pub idempotency_key: IdempotencyKey,
    pub payload: C,
}

/// Read-only cross-module query facade.
pub trait QueryPort: Send + Sync {
    type Request: Send + Sync;
    type Response: Send;

    fn execute<'a>(
        &'a self,
        ctx: &'a AuthContext,
        req: Self::Request,
    ) -> BoxFuture<'a, Result<Self::Response, AppError>>;
}

/// State-mutating cross-module command port operating in its own transaction.
pub trait CommandPort: Send + Sync {
    type Command: Send + Sync;
    type Output: Send;

    fn execute<'a>(
        &'a self,
        cmd: CommandEnvelope<Self::Command>,
    ) -> BoxFuture<'a, Result<Self::Output, AppError>>;
}

/// State-mutating cross-module command port participating in a caller's atomic `TxContext` (ADR-010).
pub trait TransactionalCommandPort: Send + Sync {
    type Command: Send + Sync;
    type Output: Send;

    fn execute_in_tx<'a>(
        &'a self,
        tx: &'a mut dyn TxContext,
        cmd: CommandEnvelope<Self::Command>,
    ) -> BoxFuture<'a, Result<Self::Output, AppError>>;
}
