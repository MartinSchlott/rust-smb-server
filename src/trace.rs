//! Optional, caller-supplied request trace (`docs/PLAN_smb_round_two.md`
//! Step 1a/1b). No logging framework, no stdout: this crate never decides
//! *where* diagnostics go — it hands correlated events to whatever
//! `Arc<dyn TraceSink>` the caller wired in via
//! `SmbServer::builder().trace_sink(...)`. Absent (the default, `None`),
//! every recording site is a null check and nothing is allocated or
//! formatted.
//!
//! **MUST NOT carry request/response bodies or file content.** Every event
//! variant below is restricted to lengths, offsets, names and statuses.

use std::sync::Arc;

// ---------------------------------------------------------------------------
// TraceKey
// ---------------------------------------------------------------------------

/// Collision-free correlation key for one operation within one request.
///
/// `message_id` is connection-scoped (MS-SMB2), and a single compound
/// request carries several operations under one `message_id` — so neither
/// `message_id` alone, nor `(connection_id, message_id)`, is unique.
/// `compound_ordinal` is the operation's index within its compound chain (0
/// when the request is not compounded). `u32`, not `u16`: a direct-TCP frame
/// may be up to 16 MiB (`SMB2_HEADER_LEN` = 64 bytes per sub-header floor),
/// so a compound chain of small sub-commands can exceed 65536 operations —
/// `u16` would silently collide past that point, which is exactly the
/// uniqueness `D-transport-diagnostics` requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TraceKey {
    pub connection_id: u64,
    pub message_id: u64,
    pub compound_ordinal: u32,
}

// ---------------------------------------------------------------------------
// TraceEvent
// ---------------------------------------------------------------------------

/// One entry of a CREATE request's context chain — its tag and payload
/// length only, never its bytes. A present/ignored boolean cannot
/// distinguish an EA context from an AAPL one; the tag can.
#[derive(Debug, Clone)]
pub struct CreateContextInfo {
    pub name: Vec<u8>,
    pub data_len: u32,
}

/// One traced event, tagged with its `TraceKey` (`None` outside any request
/// scope — a unit test driving the backend directly).
#[derive(Debug, Clone)]
pub enum TraceEvent {
    /// `dispatch.rs`: a request entering dispatch.
    Request {
        cmd: &'static str,
        session_id: u64,
        tree_id: u32,
    },
    /// `dispatch.rs`: the response NTSTATUS leaving dispatch.
    Response { status: u32 },
    /// `create.rs`.
    Create {
        path: String,
        /// The raw `CreateOptions` field (MS-SMB2 §2.2.13) — `directory`/
        /// `non_directory` below are a convenience decode of two of its
        /// bits; every other bit (e.g. `FILE_DELETE_ON_CLOSE`,
        /// `FILE_NO_INTERMEDIATE_BUFFERING`) is otherwise unrecoverable
        /// from the trace once decoded away.
        create_options: u32,
        directory: bool,
        non_directory: bool,
        create_disposition: u32,
        desired_access: u32,
        /// `None` when `backend.open()` failed — MS-SMB2 assigns no FileId
        /// to a CREATE that never opened anything. Recorded regardless of
        /// outcome (`docs/SMB_DEFECTS.md` hygiene gap #6 in the prosopon
        /// consumer): a failing CREATE's disposition/access-mask is exactly
        /// what's needed to tell a server-side rejection apart from a
        /// client that never attempted what the trace's surrounding
        /// context assumed it would.
        file_id: Option<[u8; 16]>,
        contexts: Vec<CreateContextInfo>,
    },
    /// `set_info.rs`, `FILE_RENAME_INFORMATION`: the `ReplaceIfExists` byte,
    /// the requested new name, and the `last_path` the handler resolved as
    /// the rename source — together these settle whether a rename meant for
    /// an AppleDouble sidecar landed on the real file instead.
    SetInfoRename {
        replace_if_exists: bool,
        new_name: String,
        resolved_source: String,
    },
    /// `set_info.rs`, any other information class.
    SetInfoOther { info_class: u8 },
    /// `query_info.rs`: the queried information type and class. Without it a
    /// QUERY_INFO appears as a bare command in the wire log, so a
    /// `FILE_STREAM_INFORMATION` query is indistinguishable from any other.
    QueryInfo { info_type: u8, info_class: u8 },
    /// `write.rs`.
    Write {
        file_id: [u8; 16],
        offset: u64,
        length: u32,
    },
    /// `close.rs`.
    Close {
        file_id: [u8; 16],
        delete_on_close: bool,
        last_path: String,
    },
    /// A backend-layer (`ShareBackend`/`Handle`) event. The fork does not
    /// know backend internals; `text` is whatever the caller's own backend
    /// trace (e.g. prosopon's `BackendOp`) chose to format — still subject
    /// to the "no file content" rule above.
    Backend { text: String },
}

// ---------------------------------------------------------------------------
// TraceSink
// ---------------------------------------------------------------------------

/// Caller-supplied sink for every recorded event. Implementors decide where
/// events go; the fork only decides *when* to call `record` and *never*
/// formats or writes on its own.
pub trait TraceSink: Send + Sync {
    fn record(&self, key: Option<TraceKey>, event: &TraceEvent);
}

// ---------------------------------------------------------------------------
// Request-scoped key propagation (Step 1b)
// ---------------------------------------------------------------------------

tokio::task_local! {
    /// The current request's trace key, bound for the duration of the
    /// dispatcher's backend call. Mirrors prosopon's own `wirelog.rs`
    /// `REQUEST_ID` task-local — same mechanism, same reason: an SMB
    /// connection serves concurrent, interleaved requests, so a backend
    /// event with no key would be ambiguous the moment two requests
    /// overlap.
    static TRACE_KEY: TraceKey;
}

/// Runs `fut` with `key` bound as the current task's trace key. `None` runs
/// `fut` unscoped — `current_trace_key()` then reports `None` for the
/// duration, exactly as if no scope had ever been entered.
pub async fn scoped<F: std::future::Future>(key: Option<TraceKey>, fut: F) -> F::Output {
    match key {
        Some(k) => TRACE_KEY.scope(k, fut).await,
        None => fut.await,
    }
}

/// The current request's trace key, or `None` outside any request scope
/// (e.g. a unit test driving a `ShareBackend` directly, with no dispatcher
/// wrapper).
pub fn current_trace_key() -> Option<TraceKey> {
    TRACE_KEY.try_with(|k| *k).ok()
}

// ---------------------------------------------------------------------------
// The sink handle threaded through `ServerState`
// ---------------------------------------------------------------------------

/// `None` when no sink was configured — every recording site becomes a
/// single `is_none()` check.
pub type SinkHandle = Option<Arc<dyn TraceSink>>;

/// Records `event` under `key` on `sink`, if a sink is configured. Callers
/// MUST use this rather than calling `TraceSink::record` directly so the
/// "is a sink configured at all" check has exactly one call site.
pub fn record(sink: &SinkHandle, key: Option<TraceKey>, event: TraceEvent) {
    if let Some(sink) = sink {
        sink.record(key, &event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct RecordingSink {
        events: Mutex<Vec<(Option<TraceKey>, String)>>,
    }

    impl TraceSink for RecordingSink {
        fn record(&self, key: Option<TraceKey>, event: &TraceEvent) {
            self.events
                .lock()
                .unwrap()
                .push((key, format!("{event:?}")));
        }
    }

    #[test]
    fn record_is_a_no_op_without_a_sink() {
        let sink: SinkHandle = None;
        // A side-effecting event constructor would prove evaluation
        // happened; there is none here because there is nothing to gate —
        // `record` itself is the single check.
        record(&sink, None, TraceEvent::Response { status: 0 });
    }

    #[test]
    fn record_reaches_a_configured_sink_with_its_key() {
        let recorder = Arc::new(RecordingSink {
            events: Mutex::new(Vec::new()),
        });
        let sink: SinkHandle = Some(recorder.clone());
        let key = TraceKey {
            connection_id: 1,
            message_id: 2,
            compound_ordinal: 0,
        };
        record(
            &sink,
            Some(key),
            TraceEvent::Response {
                status: 0xC000_0022,
            },
        );

        let events = recorder.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].0, Some(key));
        assert!(events[0].1.contains(&0xC000_0022u32.to_string()));
    }

    #[tokio::test]
    async fn current_trace_key_is_none_outside_any_scope() {
        assert_eq!(current_trace_key(), None);
    }

    #[tokio::test]
    async fn scoped_binds_the_key_for_the_future_and_only_for_it() {
        let key = TraceKey {
            connection_id: 1,
            message_id: 2,
            compound_ordinal: 0,
        };
        let observed = scoped(Some(key), async { current_trace_key() }).await;
        assert_eq!(observed, Some(key));
        assert_eq!(current_trace_key(), None);
    }

    #[tokio::test]
    async fn two_connections_reusing_the_same_message_id_get_distinct_keys() {
        let a = TraceKey {
            connection_id: 1,
            message_id: 5,
            compound_ordinal: 0,
        };
        let b = TraceKey {
            connection_id: 2,
            message_id: 5,
            compound_ordinal: 0,
        };
        assert_ne!(a, b);

        let (ka, kb) = tokio::join!(
            scoped(Some(a), async {
                tokio::task::yield_now().await;
                current_trace_key()
            }),
            scoped(Some(b), async { current_trace_key() }),
        );
        assert_eq!(ka, Some(a));
        assert_eq!(kb, Some(b));
    }

    #[tokio::test]
    async fn compound_operations_get_distinct_ordinals() {
        let a = TraceKey {
            connection_id: 1,
            message_id: 9,
            compound_ordinal: 0,
        };
        let b = TraceKey {
            connection_id: 1,
            message_id: 9,
            compound_ordinal: 1,
        };
        assert_ne!(a, b);
        let observed_a = scoped(Some(a), async { current_trace_key() }).await;
        let observed_b = scoped(Some(b), async { current_trace_key() }).await;
        assert_eq!(observed_a, Some(a));
        assert_eq!(observed_b, Some(b));
    }
}
