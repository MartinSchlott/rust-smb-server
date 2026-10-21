//! Shared machinery of dispatch supervision: panic capture and incident
//! emission.
//!
//! The server's contract is that every admitted request is answered, or the
//! connection is closed. The pieces here are what the reader and dispatcher
//! use to keep that contract when something goes wrong: a panic is caught
//! instead of silently dropping a request, and every deviation is reported
//! through the caller's `IncidentSink`.

use std::any::Any;
use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::SystemTime;

use tracing::{error, warn};

use crate::conn::state::Connection;
use crate::incident::{Incident, IncidentKind};
use crate::server::ServerState;

/// A future that resolves to `Err(payload)` when the wrapped future panics
/// while being polled, instead of unwinding into its caller.
///
/// Hand-rolled because `futures::FutureExt::catch_unwind` would add a
/// dependency for a dozen lines. After a panic the wrapped future is dropped
/// unpolled; this future is then finished.
pub(crate) struct CatchUnwind<F> {
    future: Option<Pin<Box<F>>>,
}

pub(crate) fn catch_future_unwind<F: Future>(future: F) -> CatchUnwind<F> {
    CatchUnwind {
        future: Some(Box::pin(future)),
    }
}

impl<F: Future> Future for CatchUnwind<F> {
    type Output = Result<F::Output, Box<dyn Any + Send>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        let future = this
            .future
            .as_mut()
            .expect("CatchUnwind is not polled after it finished");
        match catch_unwind(AssertUnwindSafe(|| future.as_mut().poll(cx))) {
            Ok(Poll::Pending) => Poll::Pending,
            Ok(Poll::Ready(output)) => {
                this.future = None;
                Poll::Ready(Ok(output))
            }
            Err(payload) => {
                // Dropping the future here, rather than at our own drop, keeps
                // the state it held out of reach of a second poll.
                this.future = None;
                Poll::Ready(Err(payload))
            }
        }
    }
}

/// The text of a panic payload; `"<non-string panic payload>"` when it is
/// neither a `&str` nor a `String`.
pub(crate) fn panic_message(payload: &(dyn Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_owned()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "<non-string panic payload>".to_owned()
    }
}

/// Reports `incident` to the configured sink, or to `tracing` without one.
///
/// A sink that panics cannot unwind the caller: the panic is caught, reported
/// through `tracing`, and the connection is closed — a sink that fails has
/// lost the server its only channel for explaining what it is doing to this
/// connection.
pub(crate) fn emit(server: &ServerState, conn: &Connection, incident: Incident) {
    let Some(sink) = &server.incident_sink else {
        log_incident(&incident);
        return;
    };
    if catch_unwind(AssertUnwindSafe(|| sink.record(&incident))).is_err() {
        error!(
            connection_id = incident.connection_id,
            ?incident,
            "incident sink panicked; closing the connection"
        );
        conn.close();
    }
}

/// The `tracing` fallback for a server built without an incident sink.
fn log_incident(incident: &Incident) {
    let advisory = matches!(
        incident.kind,
        IncidentKind::Slow | IncidentKind::Finished { .. }
    );
    if advisory {
        warn!(
            connection_id = incident.connection_id,
            command = ?incident.command,
            message_id = ?incident.message_id,
            compound_ordinal = ?incident.compound_ordinal,
            path = ?incident.path,
            kind = ?incident.kind,
            "dispatch incident"
        );
    } else {
        error!(
            connection_id = incident.connection_id,
            command = ?incident.command,
            message_id = ?incident.message_id,
            compound_ordinal = ?incident.compound_ordinal,
            path = ?incident.path,
            kind = ?incident.kind,
            "dispatch incident"
        );
    }
}

/// A connection-scoped incident: no sub-request is being supervised.
pub(crate) fn connection_incident(conn: &Connection, kind: IncidentKind) -> Incident {
    Incident {
        at: SystemTime::now(),
        connection_id: conn.connection_id,
        kind,
        command: None,
        message_id: None,
        compound_ordinal: None,
        path: None,
    }
}

/// A malformed frame executes nothing: report it and close the connection.
pub(crate) fn report_malformed(server: &ServerState, conn: &Connection, reason: String) {
    emit(
        server,
        conn,
        connection_incident(conn, IncidentKind::MalformedFrame { reason }),
    );
    conn.close();
}

/// The server's own glue panicked outside any handler: report it and close.
pub(crate) fn report_glue_panic(
    server: &ServerState,
    conn: &Connection,
    payload: &(dyn Any + Send),
) {
    emit(
        server,
        conn,
        connection_incident(
            conn,
            IncidentKind::ConnectionClosed {
                reason: format!("panic outside a handler: {}", panic_message(payload)),
            },
        ),
    );
    conn.close();
}
