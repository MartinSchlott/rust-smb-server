//! Per-frame dispatch: parse header, route to handler, sign response, encode.

use std::sync::Arc;
use std::time::SystemTime;

use crate::proto::auth::ntlm::Identity;
use crate::proto::crypto::{PreauthIntegrity, sign};
use crate::proto::header::{
    Command, HeaderTail, SMB2_FLAGS_ASYNC_COMMAND, SMB2_FLAGS_RELATED_OPERATIONS,
    SMB2_FLAGS_SERVER_TO_REDIR, SMB2_FLAGS_SIGNED, SMB2_HEADER_LEN, SMB2_MAGIC, Smb2Header,
};
use crate::proto::messages::{CreateRequest, Dialect, ErrorResponse, FileId};
use tokio::time::Instant;
use tracing::{Instrument, debug, debug_span, error, warn};

use crate::conn::state::Connection;
use crate::handlers;
use crate::incident::{Incident, IncidentKind};
use crate::ntstatus;
use crate::server::ServerState;

/// Result of a handler: a complete (unsigned) response payload + the NTSTATUS
/// to set in the header. The dispatcher patches the header, applies signing
/// (if required), and ships the bytes.
pub struct HandlerResponse {
    /// Bytes after the SMB2 header — the body. The handler owns body
    /// construction.
    pub body: Vec<u8>,
    /// NTSTATUS for the response header.
    pub status: u32,
    /// Optional override for `tree_id` on the response header (e.g.
    /// TREE_CONNECT returns the freshly minted tree id).
    pub override_tree_id: Option<u32>,
    /// Optional override for `session_id` on the response header (e.g.
    /// SESSION_SETUP returns the freshly minted session id).
    pub override_session_id: Option<u64>,
    /// If true, the dispatcher will not sign the response. Used for
    /// pre-session-setup messages where no key exists yet.
    pub skip_signing: bool,
    /// If set, take the per-session 3.1.1 preauth snapshot after hashing the
    /// SESSION_SETUP request but before hashing the response. Set by
    /// SESSION_SETUP on the round that produces STATUS_SUCCESS, so the
    /// session's KDF context can use the snapshot.
    pub take_preauth_snapshot_for_session: Option<u64>,
}

impl HandlerResponse {
    pub fn ok(body: Vec<u8>) -> Self {
        Self {
            body,
            status: ntstatus::STATUS_SUCCESS,
            override_tree_id: None,
            override_session_id: None,
            skip_signing: false,
            take_preauth_snapshot_for_session: None,
        }
    }

    pub fn err(status: u32) -> Self {
        let er = ErrorResponse::status(status);
        let mut buf = Vec::new();
        er.write_to(&mut buf).expect("error response encodes");
        Self {
            body: buf,
            status,
            override_tree_id: None,
            override_session_id: None,
            skip_signing: false,
            take_preauth_snapshot_for_session: None,
        }
    }
}

/// What dispatching one frame produced.
pub enum FrameOutcome {
    /// The bytes to push into the writer channel.
    Response(Vec<u8>),
    /// The frame elicits no response: a CANCEL, which the protocol leaves
    /// unanswered, or a frame whose handler could not be stopped, for which
    /// the connection has already been closed instead.
    NoResponse,
    /// The frame's framing or compound chain is malformed. Nothing in it was
    /// executed; the caller closes the connection.
    Malformed { reason: String },
}

/// One sub-request's position in a validated frame.
struct ChainEntry {
    offset: usize,
    /// The sub-request's length including its alignment padding: up to
    /// `NextCommand`, or to the end of the frame for the last one.
    len: usize,
    header: Smb2Header,
}

/// Walks and validates the whole compound chain of `frame`, before anything
/// is dispatched. The reader's classification and `dispatch_frame` both go
/// through here, so they cannot disagree about what a frame is.
///
/// A frame is malformed when it is shorter than a header, a sub-header does
/// not parse, a non-zero `NextCommand` is below the header length, or a
/// non-zero `NextCommand` leaves fewer than a header's worth of bytes for the
/// sub-request it promises. The last rule covers an offset landing exactly at
/// the end of the frame: a chain that promises another header must have one.
fn validate_chain(frame: &[u8]) -> Result<Vec<ChainEntry>, String> {
    if frame.len() < SMB2_HEADER_LEN {
        return Err(format!(
            "frame of {} bytes is shorter than an SMB2 header",
            frame.len()
        ));
    }

    let mut entries = Vec::new();
    let mut offset = 0;
    loop {
        // The initial length check and the previous iteration's
        // `NextCommand` check guarantee a full header here.
        let available = &frame[offset..];
        let (header, _) = Smb2Header::parse(available).map_err(|e| {
            format!(
                "header of sub-request {} does not parse: {e}",
                entries.len()
            )
        })?;

        let next = header.next_command as usize;
        if next == 0 {
            entries.push(ChainEntry {
                offset,
                len: available.len(),
                header,
            });
            return Ok(entries);
        }
        if next < SMB2_HEADER_LEN {
            return Err(format!(
                "sub-request {}: NextCommand {next} is below the header length",
                entries.len()
            ));
        }
        if next > available.len() || available.len() - next < SMB2_HEADER_LEN {
            return Err(format!(
                "sub-request {}: NextCommand {next} leaves fewer than {SMB2_HEADER_LEN} bytes \
                 for the next header ({} bytes remain)",
                entries.len(),
                available.len()
            ));
        }
        entries.push(ChainEntry {
            offset,
            len: next,
            header,
        });
        offset += next;
    }
}

/// The wire bytes of a sub-request next to its effective form.
///
/// `inherit_related_context` rewrites the SessionId, TreeId and FileId
/// sentinels of a related sub-request. Signature verification and the
/// preauth hash run on the bytes as the client sent them, routing and the
/// handlers on the effective ones.
struct SubFrames {
    effective: Vec<u8>,
    /// `Some` only when inheritance changed the bytes.
    wire: Option<Vec<u8>>,
}

impl SubFrames {
    fn wire(&self) -> &[u8] {
        self.wire.as_deref().unwrap_or(&self.effective)
    }
}

/// One sub-request as the supervisor sees it.
struct SubRequest {
    ordinal: u32,
    /// The effective header (after related-context inheritance).
    hdr: Smb2Header,
    frames: Arc<SubFrames>,
    trace_key: Option<crate::trace::TraceKey>,
    inherited_failure: Option<u32>,
}

impl SubRequest {
    fn incident(&self, conn: &Connection, kind: IncidentKind, path: Option<String>) -> Incident {
        Incident {
            at: SystemTime::now(),
            connection_id: conn.connection_id,
            kind,
            command: Some(command_name(self.hdr.command)),
            message_id: Some(self.hdr.message_id),
            compound_ordinal: Some(self.ordinal),
            path,
        }
    }

    /// The path this sub-request concerns, resolved without waiting: a
    /// CREATE's requested name, or the `Open`'s path for a command carrying a
    /// FileId. `None` on any contention.
    fn path_hint(&self, conn: &Connection) -> Option<String> {
        let frame = &self.frames.effective;
        if self.hdr.command == Command::Create {
            let req = CreateRequest::parse(&frame[SMB2_HEADER_LEN..]).ok()?;
            let units = crate::utils::utf16le_to_units(&req.name)?;
            let path = crate::path::SmbPath::from_utf16(&units).ok()?;
            return Some(path.display_backslash());
        }

        let offset = SMB2_HEADER_LEN + file_id_body_offset(self.hdr.command)?;
        if offset + 16 > frame.len() {
            return None;
        }
        let file_id = FileId::new(read_u64(frame, offset), read_u64(frame, offset + 8));
        let session = conn
            .sessions
            .try_read()
            .ok()?
            .get(&self.hdr.session_id)?
            .clone();
        let tree = session
            .try_read()
            .ok()?
            .trees
            .try_read()
            .ok()?
            .get(&self.hdr.tree_id()?)?
            .clone();
        let open = tree
            .try_read()
            .ok()?
            .opens
            .try_read()
            .ok()?
            .get(&file_id)?
            .clone();
        let path = open.try_read().ok()?.last_path.display_backslash();
        Some(path)
    }
}

/// What the handler task produced, up to the session-key bookkeeping that
/// follows the handler.
enum Handled {
    /// CANCEL: fire-and-forget, no response.
    Cancel,
    /// The request failed signature verification.
    Rejected(HandlerResponse),
    Done {
        resp: HandlerResponse,
        dialect: Option<Dialect>,
        session_preauth: Option<PreauthIntegrity>,
    },
}

/// How a supervised sub-request ended.
enum Supervised {
    Completed(Handled),
    /// The handler panicked; the sub-request is answered with an error.
    Panicked,
    /// The frame's budget ran out and the handler was cancelled.
    TimedOut,
    /// The handler could not be stopped; the connection is closed and this
    /// frame sends nothing more.
    Abandoned,
    /// The request could not be supervised and was not run; it is answered
    /// `STATUS_INSUFFICIENT_RESOURCES`.
    Refused,
}

/// Top-level frame dispatch.
///
/// Every sub-request is answered, or the connection is closed — never
/// silence on an open connection:
/// * the whole chain is validated first; a malformed frame executes nothing
///   and is reported as [`FrameOutcome::Malformed`] for the caller to close;
/// * each sub-request's handler runs as its own task under the frame's
///   budget: a panic is answered `STATUS_INTERNAL_ERROR` at once, and a
///   handler still running when the budget ends is cancelled and answered
///   `STATUS_IO_TIMEOUT`;
/// * once the budget is spent, the rest of the chain is answered
///   `STATUS_IO_TIMEOUT` unexecuted, except CLOSEs, which still run — under
///   one shared cleanup window — so no Open created earlier in the frame
///   leaks;
/// * a handler that does not stop within the cancellation grace is stuck in
///   non-yielding code: the connection is closed and nothing more is sent.
///
/// The budget (`dispatch_deadline`) runs from this call, so it bounds the
/// whole frame and the barrier wait behind it. Responses of sub-requests that
/// completed before the failure are never discarded.
pub async fn dispatch_frame(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    frame: &[u8],
) -> FrameOutcome {
    let admitted = Instant::now();

    // SMB1 multi-protocol bootstrap (MS-SMB2 §3.3.5.3.1). The only SMB1 we
    // accept: a NEGOTIATE_REQUEST listing "SMB 2.???" or "SMB 2.002".
    // Reply with an SMB2 NEGOTIATE response and the client follows up with
    // a real SMB2 NEGOTIATE.
    if let Some(bytes) = handle_smb1_multi_protocol(server, conn, frame).await {
        return FrameOutcome::Response(bytes);
    }
    let chain = match validate_chain(frame) {
        Ok(chain) => chain,
        Err(reason) => {
            warn!(%reason, "malformed frame");
            return FrameOutcome::Malformed { reason };
        }
    };

    let budget_end = admitted + server.dispatch_deadline;
    // `Some` once the budget is spent: the one absolute cutoff all remaining
    // CLOSEs share.
    let mut cleanup_cutoff: Option<Instant> = None;
    let mut responses = Vec::new();
    let mut prev_session_id = 0;
    let mut prev_tree_id = 0;
    let mut prev_create_file_id = None;
    // Status of a failed CREATE earlier in the current related chain
    // (MS-SMB2 §3.3.5.2.7.2); see `related_create_failure`.
    let mut create_failure: Option<u32> = None;

    for (index, entry) in chain.iter().enumerate() {
        let ordinal = index as u32;
        let mut effective = frame[entry.offset..entry.offset + entry.len].to_vec();
        let mut req_hdr = entry.header;
        let related = req_hdr.flags & SMB2_FLAGS_RELATED_OPERATIONS != 0;
        if !related {
            // An unrelated operation opens a new chain; a CREATE failure in
            // the previous one no longer applies.
            create_failure = None;
        }
        let inherited_failure = related_create_failure(related, req_hdr.command, create_failure);
        let mut wire = None;
        if related {
            wire = Some(effective.clone());
            inherit_related_context(
                &mut effective,
                &mut req_hdr,
                prev_session_id,
                prev_tree_id,
                prev_create_file_id,
            );
        }

        prev_session_id = req_hdr.session_id;
        prev_tree_id = req_hdr.tree_id().unwrap_or(0);

        let sub = SubRequest {
            ordinal,
            hdr: req_hdr,
            frames: Arc::new(SubFrames { effective, wire }),
            trace_key: server.trace_sink.as_ref().map(|_| crate::trace::TraceKey {
                connection_id: conn.connection_id,
                message_id: req_hdr.message_id,
                compound_ordinal: ordinal,
            }),
            inherited_failure,
        };
        crate::trace::record(
            &server.trace_sink,
            sub.trace_key,
            crate::trace::TraceEvent::Request {
                cmd: command_name(req_hdr.command),
                session_id: req_hdr.session_id,
                tree_id: req_hdr.tree_id().unwrap_or(0),
            },
        );

        if cleanup_cutoff.is_none() && Instant::now() >= budget_end {
            cleanup_cutoff = Some(Instant::now() + server.cancellation_grace);
        }
        let deadline = match cleanup_cutoff {
            None => Some(budget_end),
            // Budget spent: only a CLOSE still within the cleanup window runs.
            Some(cutoff) => (req_hdr.command == Command::Close
                && sub.inherited_failure.is_none()
                && Instant::now() < cutoff)
                .then_some(cutoff),
        };

        let response = match deadline {
            // An unexecuted CANCEL stays unanswered, as the protocol requires.
            None if req_hdr.command == Command::Cancel => None,
            None => {
                let status = sub.inherited_failure.unwrap_or(ntstatus::STATUS_IO_TIMEOUT);
                Some(error_response(server, conn, &sub, status))
            }
            Some(deadline) => match run_supervised(server, conn, &sub, deadline).await {
                Supervised::Completed(handled) => complete(server, conn, &sub, handled).await,
                Supervised::Panicked => Some(error_response(
                    server,
                    conn,
                    &sub,
                    ntstatus::STATUS_INTERNAL_ERROR,
                )),
                Supervised::TimedOut => {
                    if cleanup_cutoff.is_none() {
                        cleanup_cutoff = Some(Instant::now() + server.cancellation_grace);
                    }
                    Some(error_response(
                        server,
                        conn,
                        &sub,
                        ntstatus::STATUS_IO_TIMEOUT,
                    ))
                }
                Supervised::Abandoned => return FrameOutcome::NoResponse,
                Supervised::Refused if req_hdr.command == Command::Cancel => None,
                Supervised::Refused => Some(error_response(
                    server,
                    conn,
                    &sub,
                    ntstatus::STATUS_INSUFFICIENT_RESOURCES,
                )),
            },
        };

        if let Some(response) = response {
            if req_hdr.command == Command::Create {
                prev_create_file_id = capture_create_file_id(&response);
                let status = read_u32(&response, 0x08);
                create_failure = is_error_status(status).then_some(status);
            }
            responses.push(response);
        }
    }

    if responses.is_empty() {
        return FrameOutcome::NoResponse;
    }

    FrameOutcome::Response(stitch_responses(conn, responses))
}

/// Answers `sub` with `status` without running its handler (or after its
/// handler was abandoned), recording the response in the trace.
fn error_response(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    sub: &SubRequest,
    status: u32,
) -> Vec<u8> {
    let bytes = build_response_bytes(conn, &sub.hdr, HandlerResponse::err(status));
    crate::trace::record(
        &server.trace_sink,
        sub.trace_key,
        crate::trace::TraceEvent::Response { status },
    );
    bytes
}

/// Runs `sub`'s handler as its own task and supervises it until `deadline`.
///
/// Reports `Slow` once the handler has run for the slow threshold, and
/// `Finished` if it then completes. At the deadline the task is aborted and
/// given the cancellation grace to drop its future and every lock guard it
/// holds; a task that does not stop is stuck in non-yielding code, so the
/// connection is closed and this call keeps awaiting the task — holding the
/// frame's permit, so quiescence is preserved — without sending anything.
async fn run_supervised(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    sub: &SubRequest,
    deadline: Instant,
) -> Supervised {
    let span = debug_span!(
        "dispatch",
        cmd = ?sub.hdr.command,
        mid = sub.hdr.message_id,
        sid = sub.hdr.session_id,
        tid = sub.hdr.tree_id().unwrap_or(0)
    );
    // The pulse that keeps the runtime's timers alive while a handler blocks a
    // worker (see `crate::pulse`) must be counting before the handler can first
    // be polled, and keep counting for as long as the handler's future exists:
    // the guard travels into the task, so it is released on completion, on
    // panic and on cancellation — and, for a synchronous handler that cannot be
    // cancelled, only when it finally returns.
    let in_flight = match server.pulse.enter() {
        Ok(in_flight) => in_flight,
        Err(e) => {
            // Without the pulse a synchronously blocking handler could stall
            // every timer, including this supervisor's own, so the handler is
            // not run unsupervised. The request can still be answered, so
            // exactly this request is refused and the connection stays open;
            // the next request retries starting the pulse.
            let path = sub.path_hint(conn);
            crate::supervise::emit(
                server,
                conn,
                sub.incident(
                    conn,
                    IncidentKind::SupervisionUnavailable {
                        reason: format!("the runtime pulse thread could not be started: {e}"),
                    },
                    path,
                ),
            );
            return Supervised::Refused;
        }
    };
    // Task-local trace correlation is not inherited across `tokio::spawn`.
    let (task_server, task_conn, task_frames) = (server.clone(), conn.clone(), sub.frames.clone());
    let (task_hdr, task_failure) = (sub.hdr, sub.inherited_failure);
    let mut task = tokio::spawn(
        crate::trace::scoped(sub.trace_key, async move {
            let _in_flight = in_flight;
            handle_one(task_server, task_conn, task_hdr, task_frames, task_failure).await
        })
        .instrument(span),
    );

    let started = Instant::now();
    let slow_at = started + server.slow_dispatch_threshold;
    let mut slow_reported = false;
    let mut path: Option<String> = None;

    loop {
        tokio::select! {
            joined = &mut task => {
                return finish_task(server, conn, sub, joined, slow_reported.then(|| started.elapsed()), path);
            }
            _ = tokio::time::sleep_until(slow_at), if !slow_reported && slow_at < deadline => {
                slow_reported = true;
                path = sub.path_hint(conn);
                crate::supervise::emit(server, conn, sub.incident(conn, IncidentKind::Slow, path.clone()));
            }
            _ = tokio::time::sleep_until(deadline) => break,
        }
    }

    task.abort();
    match tokio::time::timeout(server.cancellation_grace, &mut task).await {
        // A task that completed just before the abort landed is a normal
        // completion; only a cancellation is a timeout.
        Ok(Err(e)) if e.is_cancelled() => {
            let path = path.or_else(|| sub.path_hint(conn));
            crate::supervise::emit(
                server,
                conn,
                sub.incident(conn, IncidentKind::TimedOut, path),
            );
            Supervised::TimedOut
        }
        Ok(joined) => finish_task(
            server,
            conn,
            sub,
            joined,
            slow_reported.then(|| started.elapsed()),
            path,
        ),
        Err(_) => {
            let path = path.or_else(|| sub.path_hint(conn));
            crate::supervise::emit(
                server,
                conn,
                sub.incident(
                    conn,
                    IncidentKind::ConnectionClosed {
                        reason: format!(
                            "handler did not stop within the cancellation grace of {:?}",
                            server.cancellation_grace
                        ),
                    },
                    path,
                ),
            );
            conn.close();
            let _ = (&mut task).await;
            Supervised::Abandoned
        }
    }
}

/// Maps a finished handler task onto the supervisor's outcomes.
fn finish_task(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    sub: &SubRequest,
    joined: Result<Handled, tokio::task::JoinError>,
    slow_elapsed: Option<std::time::Duration>,
    path: Option<String>,
) -> Supervised {
    match joined {
        Ok(handled) => {
            if let Some(elapsed) = slow_elapsed {
                crate::supervise::emit(
                    server,
                    conn,
                    sub.incident(conn, IncidentKind::Finished { elapsed }, path),
                );
            }
            Supervised::Completed(handled)
        }
        Err(e) if e.is_panic() => {
            let message = crate::supervise::panic_message(&*e.into_panic());
            let path = path.or_else(|| sub.path_hint(conn));
            crate::supervise::emit(
                server,
                conn,
                sub.incident(conn, IncidentKind::Panicked { message }, path),
            );
            Supervised::Panicked
        }
        Err(_) => {
            // Cancelled other than by us: the runtime is shutting down.
            crate::supervise::emit(
                server,
                conn,
                sub.incident(
                    conn,
                    IncidentKind::ConnectionClosed {
                        reason: "handler task cancelled".to_owned(),
                    },
                    path,
                ),
            );
            conn.close();
            Supervised::Abandoned
        }
    }
}

fn inherit_related_context(
    sub_frame: &mut [u8],
    req_hdr: &mut Smb2Header,
    prev_session_id: u64,
    prev_tree_id: u32,
    prev_create_file_id: Option<[u8; 16]>,
) {
    if read_u64(sub_frame, 0x28) == u64::MAX {
        sub_frame[0x28..0x30].copy_from_slice(&prev_session_id.to_le_bytes());
        req_hdr.session_id = prev_session_id;
    }

    if read_u32(sub_frame, 0x24) == u32::MAX {
        sub_frame[0x24..0x28].copy_from_slice(&prev_tree_id.to_le_bytes());
        if let HeaderTail::Sync { reserved, .. } = req_hdr.tail {
            req_hdr.tail = HeaderTail::Sync {
                reserved,
                tree_id: prev_tree_id,
            };
        }
    }

    let Some(file_id) = prev_create_file_id else {
        return;
    };
    let Some(body_offset) = file_id_body_offset(req_hdr.command) else {
        return;
    };
    let offset = SMB2_HEADER_LEN + body_offset;
    if offset + 16 <= sub_frame.len()
        && read_u64(sub_frame, offset) == u64::MAX
        && read_u64(sub_frame, offset + 8) == u64::MAX
    {
        sub_frame[offset..offset + 16].copy_from_slice(&file_id);
    }
}

/// The status a related operation MUST fail with because an earlier CREATE
/// in its chain failed, or `None` when it is dispatched normally.
///
/// MS-SMB2 §3.3.5.2.7.2: when the current operation requires a FileId and the
/// operation that would have supplied it failed, the server SHOULD fail the
/// current operation with that same status. Without this, the related FileId
/// stays the `0xFFFF…` sentinel and every follow-up answers
/// `STATUS_FILE_CLOSED`, burying the CREATE's real status.
///
/// Only a failed **CREATE** propagates (Samba's `compound_create_err`), not a
/// failed follow-up: a CREATE that succeeded holds an open handle, and failing
/// its related CLOSE because a QUERY_INFO in between failed would leak it.
fn related_create_failure(
    related: bool,
    command: Command,
    create_failure: Option<u32>,
) -> Option<u32> {
    if related && file_id_body_offset(command).is_some() {
        create_failure
    } else {
        None
    }
}

/// NTSTATUS severity `STATUS_SEVERITY_ERROR` (top two bits set). Warnings
/// such as `STATUS_BUFFER_OVERFLOW` and `STATUS_NO_MORE_FILES` are not
/// failures.
const fn is_error_status(status: u32) -> bool {
    status >> 30 == 0b11
}

fn file_id_body_offset(command: Command) -> Option<usize> {
    match command {
        Command::Close
        | Command::Flush
        | Command::Lock
        | Command::Ioctl
        | Command::QueryDirectory
        | Command::ChangeNotify
        | Command::OplockBreak => Some(8),
        Command::Read | Command::Write => Some(16),
        Command::QueryInfo => Some(24),
        Command::SetInfo => Some(16),
        _ => None,
    }
}

fn capture_create_file_id(response: &[u8]) -> Option<[u8; 16]> {
    if response.len() < SMB2_HEADER_LEN + 80 || read_u32(response, 0x08) != ntstatus::STATUS_SUCCESS
    {
        return None;
    }

    let mut file_id = [0u8; 16];
    let offset = SMB2_HEADER_LEN + 64;
    file_id.copy_from_slice(&response[offset..offset + 16]);
    Some(file_id)
}

fn stitch_responses(conn: &Arc<Connection>, responses: Vec<Vec<u8>>) -> Vec<u8> {
    let mut out = Vec::new();
    let mut ranges = Vec::with_capacity(responses.len());
    let response_count = responses.len();

    for (index, mut response) in responses.into_iter().enumerate() {
        let start = out.len();
        let actual_len = response.len();
        if index + 1 < response_count {
            let next = align_8(actual_len);
            response[0x14..0x18].copy_from_slice(&(next as u32).to_le_bytes());
        }
        out.extend_from_slice(&response);

        // MS-SMB2 §3.1.4.1: the signature of a compound element covers the
        // whole span up to the next element, alignment padding included.
        if index + 1 < response_count {
            let padded = align_8(actual_len);
            out.resize(start + padded, 0);
            ranges.push((start, padded));
        } else {
            ranges.push((start, actual_len));
        }
    }

    for (start, len) in ranges {
        let flags = read_u32(&out, start + 0x10);
        if flags & SMB2_FLAGS_SIGNED == 0 {
            continue;
        }

        let session_id = read_u64(&out, start + 0x28);
        let (algo, session) = conn.signing_context(session_id);
        let Some(session) = session else {
            continue;
        };
        if session.anonymous {
            continue;
        }

        if let Err(e) = sign(&mut out[start..start + len], &session.key, algo) {
            error!(error = %e, "failed to sign compound response");
        }
    }

    out
}

const fn align_8(n: usize) -> usize {
    (n + 7) & !7
}

fn read_u32(buf: &[u8], offset: usize) -> u32 {
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&buf[offset..offset + 4]);
    u32::from_le_bytes(bytes)
}

fn read_u64(buf: &[u8], offset: usize) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&buf[offset..offset + 8]);
    u64::from_le_bytes(bytes)
}

/// Frames that MUST NOT be dispatched concurrently with anything else on
/// their connection (PLAN_PERF1 Step 6).
///
/// Returns `true` if **any** sub-command in the compound chain is
/// `Negotiate`, `SessionSetup`, `Logoff`, `TreeConnect` or
/// `TreeDisconnect` — NEGOTIATE and SESSION_SETUP mutate connection-wide
/// negotiated state and multi-leg auth state (`pending_auths`,
/// `session_preauth`, the `preauth` hash); LOGOFF and TREE_DISCONNECT tear
/// down state an in-flight data operation may hold.
///
/// Walks the **entire** `NextCommand` chain, not just the first header,
/// through the same `validate_chain` that `dispatch_frame` uses — so the two
/// cannot disagree about what a frame is. MS-SMB2 permits compounding
/// unrelated requests, and `dispatch_frame` dispatches every sub-header
/// without filtering, so an `ECHO + LOGOFF` frame classified on its first
/// header alone would be spawned and would tear a session down underneath
/// outstanding READs.
///
/// Also returns `true` for a frame that `validate_chain` rejects (shorter
/// than `SMB2_HEADER_LEN`, a sub-header that does not parse, a `NextCommand`
/// that does not point at a complete subsequent header — including one
/// landing exactly at the frame's end) and for a frame not beginning with the
/// SMB2 magic (the SMB1 multi-protocol bootstrap). Such a frame takes the
/// serialized path, where `dispatch_frame` reports it as malformed without
/// executing anything and the connection is closed.
pub(crate) fn frame_must_be_serialized(frame: &[u8]) -> bool {
    if frame.len() < SMB2_HEADER_LEN || frame[0..4] != SMB2_MAGIC {
        return true;
    }

    match validate_chain(frame) {
        Err(_) => true,
        Ok(chain) => chain.iter().any(|entry| {
            matches!(
                entry.header.command,
                Command::Negotiate
                    | Command::SessionSetup
                    | Command::Logoff
                    | Command::TreeConnect
                    | Command::TreeDisconnect
            )
        }),
    }
}

/// The supervised part of one sub-request: signature verification through
/// the session-key bookkeeping that follows the handler. Runs as its own task
/// (see `run_supervised`), so every `.await` in here is a point at which the
/// supervisor can cancel it.
async fn handle_one(
    server: Arc<ServerState>,
    conn: Arc<Connection>,
    req_hdr: Smb2Header,
    frames: Arc<SubFrames>,
    inherited_failure: Option<u32>,
) -> Handled {
    let cmd = req_hdr.command;
    debug!("dispatch start");

    // Verify the signature on the request as the client sent it (when
    // applicable); the session it names is the effective one.
    if let Err(status) = verify_request_signature(&server, &conn, &req_hdr, frames.wire()).await {
        return Handled::Rejected(HandlerResponse::err(status));
    }

    // CANCEL is fire-and-forget — no response.
    if cmd == Command::Cancel {
        debug!("CANCEL received; no response");
        return Handled::Cancel;
    }

    let dialect = *conn.dialect.read().await;
    let mut session_preauth = None;

    // 3.1.1 preauth is connection-scoped for NEGOTIATE, then per
    // SESSION_SETUP authentication exchange.
    if cmd == Command::Negotiate {
        let mut p = conn
            .preauth
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        p.update(frames.wire());
    } else if cmd == Command::SessionSetup && dialect == Some(Dialect::Smb311) {
        let mut p = take_session_preauth(&conn, req_hdr.session_id).await;
        p.update(frames.wire());
        session_preauth = Some(p);
    }

    let body_bytes = &frames.effective[SMB2_HEADER_LEN..];
    let resp = match inherited_failure {
        Some(status) => HandlerResponse::err(status),
        None => handlers::dispatch_command(&server, &conn, &req_hdr, body_bytes).await,
    };

    // If the handler asked for a preauth snapshot (3.1.1), take it now.
    if let Some(sid) = resp.take_preauth_snapshot_for_session {
        let snap = session_preauth
            .as_ref()
            .expect("SMB 3.1.1 SessionSetup snapshot requires per-session preauth")
            .snapshot();
        // Stash on the session — the handler already created it.
        let sessions = conn.sessions.read().await;
        if let Some(sess_arc) = sessions.get(&sid) {
            let mut sess = sess_arc.write().await;
            sess.preauth_snapshot = Some(snap);
            // For 3.1.1, recompute signing key now that we have the snapshot.
            let dialect = *conn.dialect.read().await;
            if dialect == Some(Dialect::Smb311) {
                sess.signing_key =
                    crate::proto::crypto::signing_key_311(&sess.session_base_key, &snap);
                conn.snapshot_session(sid, sess.signing_key, sess.is_anonymous());
            }
        }
    }

    Handled::Done {
        resp,
        dialect,
        session_preauth,
    }
}

/// Builds `sub`'s response from what its handler produced and finishes the
/// preauth bookkeeping that depends on the response bytes. Returns `None` for
/// a CANCEL.
async fn complete(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    sub: &SubRequest,
    handled: Handled,
) -> Option<Vec<u8>> {
    let req_hdr = &sub.hdr;
    let (resp, dialect, session_preauth) = match handled {
        Handled::Cancel => return None,
        Handled::Rejected(resp) => {
            let status = resp.status;
            let bytes = build_response_bytes(conn, req_hdr, resp);
            crate::trace::record(
                &server.trace_sink,
                sub.trace_key,
                crate::trace::TraceEvent::Response { status },
            );
            return Some(bytes);
        }
        Handled::Done {
            resp,
            dialect,
            session_preauth,
        } => (resp, dialect, session_preauth),
    };

    let bytes = build_response_bytes(conn, req_hdr, resp);
    crate::trace::record(
        &server.trace_sink,
        sub.trace_key,
        crate::trace::TraceEvent::Response {
            status: read_u32(&bytes, 0x08),
        },
    );

    if req_hdr.command == Command::Negotiate {
        let mut p = conn
            .preauth
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        p.update(&bytes);
    } else if req_hdr.command == Command::SessionSetup && dialect == Some(Dialect::Smb311) {
        if read_u32(&bytes, 0x08) == ntstatus::STATUS_MORE_PROCESSING_REQUIRED {
            if let Some(mut p) = session_preauth {
                p.update(&bytes);
                let sid = read_u64(&bytes, 0x28);
                conn.session_preauth.write().await.insert(sid, p);
            }
        } else {
            conn.session_preauth
                .write()
                .await
                .remove(&req_hdr.session_id);
        }
    }

    Some(bytes)
}

/// Stable, `'static` command name for `TraceEvent::Request` — never the
/// request/response body, never file content.
fn command_name(cmd: Command) -> &'static str {
    match cmd {
        Command::Negotiate => "Negotiate",
        Command::SessionSetup => "SessionSetup",
        Command::Logoff => "Logoff",
        Command::TreeConnect => "TreeConnect",
        Command::TreeDisconnect => "TreeDisconnect",
        Command::Create => "Create",
        Command::Close => "Close",
        Command::Flush => "Flush",
        Command::Read => "Read",
        Command::Write => "Write",
        Command::Lock => "Lock",
        Command::Ioctl => "Ioctl",
        Command::Cancel => "Cancel",
        Command::Echo => "Echo",
        Command::QueryDirectory => "QueryDirectory",
        Command::ChangeNotify => "ChangeNotify",
        Command::QueryInfo => "QueryInfo",
        Command::SetInfo => "SetInfo",
        Command::OplockBreak => "OplockBreak",
    }
}

async fn take_session_preauth(conn: &Arc<Connection>, session_id: u64) -> PreauthIntegrity {
    if session_id != 0
        && let Some(preauth) = conn.session_preauth.write().await.remove(&session_id)
    {
        return preauth;
    }

    conn.preauth
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

async fn verify_request_signature(
    _server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    frame: &[u8],
) -> Result<(), u32> {
    if hdr.command == Command::Negotiate {
        return Ok(());
    }
    if hdr.session_id == 0 {
        return Ok(());
    }
    let sessions = conn.sessions.read().await;
    let sess_arc = match sessions.get(&hdr.session_id) {
        Some(s) => s.clone(),
        None => {
            // Unknown session.
            if hdr.flags & SMB2_FLAGS_SIGNED == 0 {
                return Ok(());
            }
            return Err(ntstatus::STATUS_USER_SESSION_DELETED);
        }
    };
    drop(sessions);

    if hdr.flags & SMB2_FLAGS_SIGNED != 0 {
        let sess = sess_arc.read().await;
        if matches!(sess.identity, Identity::Anonymous) {
            return Ok(());
        }
        let key = sess.signing_key;
        drop(sess);
        let algo = *conn.signing_algo.read().await;
        if let Err(e) = crate::proto::crypto::verify(frame, &key, algo) {
            warn!(error = %e, "request signature verification failed");
            return Err(ntstatus::STATUS_ACCESS_DENIED);
        }
    } else if hdr.command != Command::SessionSetup {
        let sess = sess_arc.read().await;
        let need = sess.signing_required && !matches!(sess.identity, Identity::Anonymous);
        drop(sess);
        if need {
            warn!(?hdr.command, "missing required signature on request");
            return Err(ntstatus::STATUS_ACCESS_DENIED);
        }
    }
    Ok(())
}

/// Build the final on-the-wire bytes: header + body, with signing applied
/// when the session has a key.
///
/// Synchronous on purpose: it reads the connection's signing snapshot, never
/// a lock a stuck handler can hold, so a timeout or panic response can always
/// be built.
fn build_response_bytes(
    conn: &Connection,
    req_hdr: &Smb2Header,
    handler_resp: HandlerResponse,
) -> Vec<u8> {
    let mut hdr = *req_hdr;
    hdr.flags |= SMB2_FLAGS_SERVER_TO_REDIR;
    hdr.flags &= !SMB2_FLAGS_ASYNC_COMMAND;
    hdr.next_command = 0;
    hdr.channel_sequence_status = handler_resp.status;
    hdr.tail = HeaderTail::sync(
        handler_resp
            .override_tree_id
            .unwrap_or_else(|| req_hdr.tree_id().unwrap_or(0)),
    );
    if let Some(sid) = handler_resp.override_session_id {
        hdr.session_id = sid;
    }
    hdr.signature = [0u8; 16];

    let request_was_signed = req_hdr.flags & SMB2_FLAGS_SIGNED != 0;
    // MS-SMB2 §3.3.5.5.3 step 12: SessionSetup SUCCESS must be signed for
    // non-anon/non-guest sessions even though the request cannot be signed yet.
    let is_session_setup_success =
        req_hdr.command == Command::SessionSetup && handler_resp.status == ntstatus::STATUS_SUCCESS;
    let mut should_sign = false;
    let mut key = [0u8; 16];
    let (algo, session) = conn.signing_context(hdr.session_id);
    if !handler_resp.skip_signing
        && hdr.session_id != 0
        && (request_was_signed || is_session_setup_success)
        && let Some(session) = session
    {
        let is_guest_response = is_session_setup_success
            && handler_resp.body.len() >= 4
            && (handler_resp.body[2] & 0x01) != 0;
        if !session.anonymous && !is_guest_response && session.key != [0u8; 16] {
            key = session.key;
            should_sign = true;
        }
    }
    if should_sign {
        hdr.flags |= SMB2_FLAGS_SIGNED;
    } else {
        hdr.flags &= !SMB2_FLAGS_SIGNED;
    }
    let mut out = Vec::with_capacity(SMB2_HEADER_LEN + handler_resp.body.len());
    if let Err(e) = hdr.write(&mut out) {
        error!(error = %e, "failed to encode response header");
        return Vec::new();
    }
    out.extend_from_slice(&handler_resp.body);

    if should_sign && let Err(e) = sign(&mut out, &key, algo) {
        error!(error = %e, "failed to sign response");
    }
    out
}

/// Detect and answer an SMB1 multi-protocol NEGOTIATE_REQUEST.
///
/// SMB1 frame layout for the request we accept:
/// * `[0..4]`  — magic `0xFF 'S' 'M' 'B'`
/// * `[4]`     — command (0x72 = SMB_COM_NEGOTIATE)
/// * `[5..32]` — rest of SMB1 header (status, flags, pid, tid, mid …)
/// * `[32]`    — `WordCount` (0 for NEGOTIATE)
/// * `[33..35]`— `ByteCount` (u16 LE)
/// * `[35..]`  — dialect strings, each `0x02 <ASCII> 0x00`.
///
/// Returns `Some(reply_bytes)` only for a SMB1 NEGOTIATE that lists at least
/// one SMB2 dialect we recognise; otherwise `None` so the caller can fall
/// through to the normal SMB2 path.
async fn handle_smb1_multi_protocol(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    frame: &[u8],
) -> Option<Vec<u8>> {
    if frame.len() < 35 || frame[0..4] != [0xFF, b'S', b'M', b'B'] || frame[4] != 0x72 {
        return None;
    }
    let body_start = 33; // 32-byte header + 1-byte WordCount(=0)
    let byte_count = u16::from_le_bytes([frame[body_start], frame[body_start + 1]]) as usize;
    let blob_start = body_start + 2;
    let blob_end = (blob_start + byte_count).min(frame.len());
    let blob = &frame[blob_start..blob_end];

    let mut wants_wildcard = false;
    let mut wants_smb202 = false;
    let mut i = 0;
    while i < blob.len() {
        if blob[i] != 0x02 {
            break;
        }
        i += 1;
        let nul = match blob[i..].iter().position(|&b| b == 0) {
            Some(p) => p,
            None => break,
        };
        let s = std::str::from_utf8(&blob[i..i + nul]).unwrap_or("");
        match s {
            "SMB 2.???" => wants_wildcard = true,
            "SMB 2.002" => wants_smb202 = true,
            _ => {}
        }
        i += nul + 1;
    }

    let chosen = if wants_wildcard {
        crate::proto::messages::Dialect::Smb2Wildcard.as_u16()
    } else if wants_smb202 {
        crate::proto::messages::Dialect::Smb202.as_u16()
    } else {
        return None;
    };

    debug!(
        chosen = %format_args!("0x{chosen:04X}"),
        "SMB1 multi-protocol negotiate"
    );

    // Synthesize a request header so build_response_bytes can mint the
    // SERVER_TO_REDIR response. Per MS-SMB2 §3.3.5.3.1 the response uses
    // message_id=0, tree_id=0xFFFF, session_id=0.
    let req_hdr = Smb2Header {
        command: Command::Negotiate,
        message_id: 0,
        session_id: 0,
        tail: HeaderTail::Sync {
            reserved: 0,
            tree_id: 0xFFFF,
        },
        ..Default::default()
    };
    let resp = handlers::negotiate::multi_protocol_response(server, conn, chosen).await;
    Some(build_response_bytes(conn, &req_hdr, resp))
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn test_conn() -> Arc<Connection> {
        Arc::new(Connection::new(1, Uuid::nil(), 1024 * 1024, 1024 * 1024))
    }

    // ── Trace key generation through the real dispatcher (docs/PLAN_smb_round_two.md
    // Step 1a/1b — the reviewed gate: not just two hand-built `TraceKey` values) ──

    struct CaptureSink {
        events: std::sync::Mutex<Vec<(Option<crate::trace::TraceKey>, String)>>,
    }

    impl crate::trace::TraceSink for CaptureSink {
        fn record(&self, key: Option<crate::trace::TraceKey>, event: &crate::trace::TraceEvent) {
            self.events
                .lock()
                .unwrap()
                .push((key, format!("{event:?}")));
        }
    }

    fn test_server_with_sink(sink: std::sync::Arc<CaptureSink>) -> Arc<ServerState> {
        let cfg = crate::server::ServerConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            netbios_name: "TEST".to_owned(),
            max_read_size: 1024 * 1024,
            max_write_size: 1024 * 1024,
            server_guid: Uuid::nil(),
        };
        let users = crate::server::ServerUsers {
            table: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        };
        let mut state = crate::server::ServerState::new(cfg, users, vec![]);
        state.trace_sink = Some(sink as std::sync::Arc<dyn crate::trace::TraceSink>);
        Arc::new(state)
    }

    /// One ECHO sub-frame — the simplest command needing no session/tree —
    /// with `next_command` set by the caller to chain it into a compound
    /// frame (`0` marks the last sub-frame in the chain).
    fn echo_subframe(message_id: u64, next_command: u32) -> Vec<u8> {
        let hdr = Smb2Header {
            credit_charge: 1,
            channel_sequence_status: 0,
            command: Command::Echo,
            credit_request_response: 1,
            flags: 0,
            next_command,
            message_id,
            tail: HeaderTail::sync(0),
            session_id: 0,
            signature: [0u8; 16],
        };
        let mut buf = Vec::new();
        hdr.write(&mut buf).expect("encode header");
        crate::proto::messages::EchoRequest::default()
            .write_to(&mut buf)
            .expect("encode echo body");
        // MS-SMB2 §3.3.5.9.7: every non-final compound part MUST be
        // 8-byte aligned. A real client pads for exactly this reason, and
        // `next_command` (when the caller passes a nonzero value) already
        // names that padded length — so the wire bytes must match it,
        // using the same `align_8` the dispatcher's own response side
        // uses, not an ad-hoc constant.
        buf.resize(align_8(buf.len()), 0);
        buf
    }

    fn request_keys(
        events: &[(Option<crate::trace::TraceKey>, String)],
    ) -> Vec<crate::trace::TraceKey> {
        events
            .iter()
            .filter(|(_, text)| text.starts_with("Request"))
            .map(|(key, _)| key.expect("a Request event must carry a key when a sink is armed"))
            .collect()
    }

    #[test]
    fn a_failed_create_propagates_to_related_file_id_operations() {
        let failed = Some(ntstatus::STATUS_OBJECT_NAME_NOT_FOUND);
        for command in [
            Command::QueryInfo,
            Command::Read,
            Command::Close,
            Command::SetInfo,
        ] {
            assert_eq!(
                related_create_failure(true, command, failed),
                failed,
                "{command:?} related to a failed CREATE must fail with its status"
            );
        }
    }

    #[test]
    fn no_propagation_without_relation_file_id_or_failure() {
        let failed = Some(ntstatus::STATUS_OBJECT_NAME_NOT_FOUND);
        assert_eq!(related_create_failure(false, Command::Close, failed), None);
        assert_eq!(related_create_failure(true, Command::Echo, failed), None);
        assert_eq!(related_create_failure(true, Command::Create, failed), None);
        assert_eq!(related_create_failure(true, Command::Close, None), None);
    }

    #[test]
    fn only_error_severity_counts_as_failure() {
        assert!(is_error_status(ntstatus::STATUS_OBJECT_NAME_NOT_FOUND));
        assert!(is_error_status(ntstatus::STATUS_FILE_CLOSED));
        assert!(!is_error_status(ntstatus::STATUS_SUCCESS));
        assert!(!is_error_status(0x8000_0005)); // STATUS_BUFFER_OVERFLOW
        assert!(!is_error_status(0x8000_0006)); // STATUS_NO_MORE_FILES
    }

    #[tokio::test]
    async fn compound_frame_gets_sequential_ordinals_from_real_dispatch() {
        let sink = std::sync::Arc::new(CaptureSink {
            events: std::sync::Mutex::new(Vec::new()),
        });
        let server = test_server_with_sink(sink.clone());
        let conn = Arc::new(Connection::new(7, Uuid::nil(), 1024 * 1024, 1024 * 1024));

        // header (64) + 4-byte EchoRequest = 68, 8-byte-aligned up to 72
        // (MS-SMB2 §3.3.5.9.7 — see `echo_subframe`'s padding).
        let sub_len = align_8(SMB2_HEADER_LEN + 4) as u32;
        assert_eq!(sub_len, 72);
        let mut frame = Vec::new();
        frame.extend(echo_subframe(42, sub_len));
        frame.extend(echo_subframe(42, sub_len));
        frame.extend(echo_subframe(42, 0));

        let resp = dispatch_frame(&server, &conn, &frame).await;
        assert!(
            matches!(resp, FrameOutcome::Response(_)),
            "a 3-op ECHO compound must produce a response"
        );

        let events = sink.events.lock().unwrap();
        let mut ordinals: Vec<u32> = request_keys(&events)
            .into_iter()
            .map(|k| {
                assert_eq!(k.connection_id, 7);
                assert_eq!(k.message_id, 42);
                k.compound_ordinal
            })
            .collect();
        ordinals.sort_unstable();
        assert_eq!(
            ordinals,
            vec![0, 1, 2],
            "three compounded operations under one message_id must get three distinct, \
             sequential ordinals from the real dispatch loop"
        );
    }

    #[tokio::test]
    async fn two_real_connections_reusing_the_same_message_id_get_distinct_keys() {
        let sink = std::sync::Arc::new(CaptureSink {
            events: std::sync::Mutex::new(Vec::new()),
        });
        let server = test_server_with_sink(sink.clone());
        let conn_a = Arc::new(Connection::new(1, Uuid::nil(), 1024 * 1024, 1024 * 1024));
        let conn_b = Arc::new(Connection::new(2, Uuid::nil(), 1024 * 1024, 1024 * 1024));

        let frame = echo_subframe(5, 0);
        dispatch_frame(&server, &conn_a, &frame).await;
        dispatch_frame(&server, &conn_b, &frame).await;

        let events = sink.events.lock().unwrap();
        let keys = request_keys(&events);
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].message_id, 5);
        assert_eq!(keys[1].message_id, 5);
        assert_ne!(
            keys[0].connection_id, keys[1].connection_id,
            "two distinct connections reusing message_id=5 must not collide"
        );
    }

    fn negotiated_preauth() -> PreauthIntegrity {
        let mut preauth = PreauthIntegrity::new();
        preauth.update(b"negotiate request");
        preauth.update(b"negotiate response");
        preauth
    }

    #[tokio::test]
    async fn new_session_setup_preauth_starts_from_negotiate_base() {
        let conn = test_conn();
        let base = negotiated_preauth();
        *conn.preauth.lock().expect("preauth lock") = base.clone();

        let mut first_session = take_session_preauth(&conn, 0).await;
        first_session.update(b"session one request");
        first_session.update(b"session one response");
        conn.session_preauth.write().await.insert(1, first_session);

        let mut second_session = take_session_preauth(&conn, 0).await;
        second_session.update(b"session two request");

        let mut expected = base.clone();
        expected.update(b"session two request");

        let mut polluted = base;
        polluted.update(b"session one request");
        polluted.update(b"session one response");
        polluted.update(b"session two request");

        assert_eq!(second_session.snapshot(), expected.snapshot());
        assert_ne!(second_session.snapshot(), polluted.snapshot());
    }

    #[tokio::test]
    async fn followup_session_setup_consumes_stored_session_preauth() {
        let conn = test_conn();
        let mut stored = negotiated_preauth();
        stored.update(b"session setup request");
        stored.update(b"session setup more-processing response");
        let expected = stored.snapshot();
        conn.session_preauth.write().await.insert(7, stored);

        let got = take_session_preauth(&conn, 7).await;

        assert_eq!(got.snapshot(), expected);
        assert!(!conn.session_preauth.read().await.contains_key(&7));
    }

    // ── PLAN_PERF1 Step 6/8.6 — `frame_must_be_serialized` table test ──────

    /// One sub-frame: exactly `SMB2_HEADER_LEN` bytes, header only, no body
    /// — the predicate never looks past the header, so a body adds nothing
    /// but noise. `next_command` is the caller's to set, matching
    /// `echo_subframe`'s convention above.
    fn bare_header(command: Command, next_command: u32) -> Vec<u8> {
        let hdr = Smb2Header {
            credit_charge: 1,
            channel_sequence_status: 0,
            command,
            credit_request_response: 1,
            flags: 0,
            next_command,
            message_id: 1,
            tail: HeaderTail::sync(0),
            session_id: 0,
            signature: [0u8; 16],
        };
        let mut buf = Vec::new();
        hdr.write(&mut buf).expect("encode header");
        assert_eq!(buf.len(), SMB2_HEADER_LEN);
        buf
    }

    /// A compound chain of bare headers, each exactly `SMB2_HEADER_LEN`
    /// bytes — so a non-final element's `NextCommand` is always
    /// `SMB2_HEADER_LEN`, the offset to the very next header.
    fn compound_of(commands: &[Command]) -> Vec<u8> {
        let mut frame = Vec::new();
        for (i, cmd) in commands.iter().enumerate() {
            let next = if i + 1 < commands.len() {
                SMB2_HEADER_LEN as u32
            } else {
                0
            };
            frame.extend(bare_header(*cmd, next));
        }
        frame
    }

    #[test]
    fn frame_must_be_serialized_classifies_every_rule() {
        let cases: Vec<(&str, Vec<u8>, bool)> = vec![
            ("Negotiate alone", compound_of(&[Command::Negotiate]), true),
            (
                "SessionSetup alone",
                compound_of(&[Command::SessionSetup]),
                true,
            ),
            ("Logoff alone", compound_of(&[Command::Logoff]), true),
            (
                "TreeConnect alone",
                compound_of(&[Command::TreeConnect]),
                true,
            ),
            (
                "TreeDisconnect alone",
                compound_of(&[Command::TreeDisconnect]),
                true,
            ),
            (
                "a data-path command alone (Echo)",
                compound_of(&[Command::Echo]),
                false,
            ),
            (
                "NextCommand == 0 terminates normally and is data-path, not malformed",
                bare_header(Command::Read, 0),
                false,
            ),
            (
                "a chain whose serialized command is not first (Echo + Logoff)",
                compound_of(&[Command::Echo, Command::Logoff]),
                true,
            ),
            (
                "a data-path-only chain (Echo + Read)",
                compound_of(&[Command::Echo, Command::Read]),
                false,
            ),
            (
                "a nonzero NextCommand below SMB2_HEADER_LEN",
                bare_header(Command::Echo, 10),
                true,
            ),
            (
                "a nonzero NextCommand overshooting the frame",
                bare_header(Command::Echo, 1000),
                true,
            ),
            (
                "a nonzero NextCommand landing exactly at frame end",
                bare_header(Command::Echo, SMB2_HEADER_LEN as u32),
                true,
            ),
            ("a truncated frame", vec![0xFEu8, b'S', b'M', b'B'], true),
            (
                "a non-SMB2 frame (SMB1 multi-protocol bootstrap magic)",
                {
                    let mut f = vec![0xFFu8, b'S', b'M', b'B'];
                    f.resize(SMB2_HEADER_LEN, 0);
                    f
                },
                true,
            ),
        ];

        for (name, frame, expected) in cases {
            assert_eq!(
                frame_must_be_serialized(&frame),
                expected,
                "case failed: {name}"
            );
        }
    }
}
