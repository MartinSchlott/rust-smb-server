//! Dispatch incidents: the channel through which a stuck, panicking or
//! malformed request reports itself to the embedding application.
//!
//! The server answers every admitted request or closes the connection; this
//! module is how it says *why* it had to deviate from a plain response. It
//! never decides where incidents go — the caller wires in an
//! `Arc<dyn IncidentSink>` through `SmbServer::builder().incident_sink(...)`.
//! Without a sink, incidents fall back to `tracing`.
//!
//! Like [`crate::trace`], an incident carries names, ids and statuses only —
//! never request or response bodies or file content.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

/// What happened to a request, a frame or a connection.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum IncidentKind {
    /// A handler is still running after the slow-dispatch threshold.
    Slow,
    /// A handler reported `Slow` earlier and has now completed within its
    /// deadline; `elapsed` is measured from the handler's start.
    Finished { elapsed: Duration },
    /// A handler panicked; the request was answered `STATUS_INTERNAL_ERROR`.
    Panicked { message: String },
    /// A handler outlived its frame's deadline and was cancelled; the request
    /// was answered `STATUS_IO_TIMEOUT`.
    TimedOut,
    /// A frame's framing or compound chain is malformed; the connection is
    /// closed and nothing in the frame was executed.
    MalformedFrame { reason: String },
    /// The server closed the connection: a handler could not be cancelled
    /// within the grace period, or the server's own glue panicked.
    ConnectionClosed { reason: String },
}

/// One reported incident.
///
/// The identity of a sub-request is `(connection_id, message_id,
/// compound_ordinal)` — exactly the fields of [`crate::TraceKey`]. All
/// incidents of one sub-request carry the same identity, from `Slow` through
/// its terminal incident.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Incident {
    pub at: SystemTime,
    pub connection_id: u64,
    pub kind: IncidentKind,
    /// The sub-request's command, as in `TraceEvent::Request`.
    pub command: Option<&'static str>,
    pub message_id: Option<u64>,
    /// The sub-request's position in its frame, as in [`crate::TraceKey`].
    pub compound_ordinal: Option<u32>,
    /// Best effort and never waiting: a CREATE's requested name, or the
    /// `Open`'s path for a command carrying a FileId; `None` where it cannot
    /// be resolved without blocking.
    pub path: Option<String>,
}

/// Caller-supplied receiver of incidents.
///
/// Called synchronously from the frame task: it must be cheap and must not
/// block. A sink that panics closes the connection it was reporting on.
pub trait IncidentSink: Send + Sync {
    fn record(&self, incident: &Incident);
}

/// The sink as threaded through `ServerState`.
pub type IncidentSinkHandle = Option<Arc<dyn IncidentSink>>;
