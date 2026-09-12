//! Per-frame dispatch: parse header, route to handler, sign response, encode.

use std::sync::Arc;

use crate::proto::auth::ntlm::Identity;
use crate::proto::crypto::{PreauthIntegrity, sign};
use crate::proto::header::{
    Command, HeaderTail, SMB2_FLAGS_ASYNC_COMMAND, SMB2_FLAGS_RELATED_OPERATIONS,
    SMB2_FLAGS_SERVER_TO_REDIR, SMB2_FLAGS_SIGNED, SMB2_HEADER_LEN, SMB2_MAGIC, Smb2Header,
};
use crate::proto::messages::ErrorResponse;
use tracing::{Instrument, debug, debug_span, error, warn};

use crate::conn::state::Connection;
use crate::handlers;
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

/// Top-level frame dispatch. Returns the bytes to push into the writer
/// channel, or `None` if the request elicits no response (CANCEL).
pub async fn dispatch_frame(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    frame: &[u8],
) -> Option<Vec<u8>> {
    // SMB1 multi-protocol bootstrap (MS-SMB2 §3.3.5.3.1). The only SMB1 we
    // accept: a NEGOTIATE_REQUEST listing "SMB 2.???" or "SMB 2.002".
    // Reply with an SMB2 NEGOTIATE response and the client follows up with
    // a real SMB2 NEGOTIATE.
    if let Some(bytes) = handle_smb1_multi_protocol(server, conn, frame).await {
        return Some(bytes);
    }
    if frame.len() < SMB2_HEADER_LEN {
        warn!(len = frame.len(), "frame too short for SMB2 header");
        return None;
    }

    let mut sub_offset = 0;
    let mut responses = Vec::new();
    let mut prev_session_id = 0;
    let mut prev_tree_id = 0;
    let mut prev_create_file_id = None;
    let mut compound_ordinal: u32 = 0;

    while sub_offset < frame.len() {
        let available = &frame[sub_offset..];
        if available.len() < SMB2_HEADER_LEN {
            warn!(remaining = available.len(), "compound tail too short");
            return None;
        }

        let (mut req_hdr, _) = match Smb2Header::parse(available) {
            Ok(p) => p,
            Err(e) => {
                warn!(error = %e, "failed to parse compound sub-header");
                return None;
            }
        };

        let next = req_hdr.next_command as usize;
        let sub_len = if next == 0 {
            available.len()
        } else if next < SMB2_HEADER_LEN || next > available.len() {
            warn!(
                next,
                remaining = available.len(),
                "invalid compound NextCommand"
            );
            return None;
        } else {
            next
        };

        let mut sub_frame = available[..sub_len].to_vec();
        if req_hdr.flags & SMB2_FLAGS_RELATED_OPERATIONS != 0 {
            inherit_related_context(
                &mut sub_frame,
                &mut req_hdr,
                prev_session_id,
                prev_tree_id,
                prev_create_file_id,
            );
        }

        prev_session_id = req_hdr.session_id;
        prev_tree_id = req_hdr.tree_id().unwrap_or(0);

        if let Some(response) = dispatch_one(server, conn, &sub_frame, compound_ordinal).await {
            if req_hdr.command == Command::Create {
                prev_create_file_id = capture_create_file_id(&response);
            }
            responses.push(response);
        }
        compound_ordinal = compound_ordinal.saturating_add(1);

        if next == 0 {
            break;
        }
        sub_offset += next;
    }

    if responses.is_empty() {
        return None;
    }

    Some(stitch_responses(conn, responses).await)
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

async fn stitch_responses(conn: &Arc<Connection>, responses: Vec<Vec<u8>>) -> Vec<u8> {
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
        ranges.push((start, actual_len));

        if index + 1 < response_count {
            out.resize(start + align_8(actual_len), 0);
        }
    }

    let algo = *conn.signing_algo.read().await;
    for (start, len) in ranges {
        let flags = read_u32(&out, start + 0x10);
        if flags & SMB2_FLAGS_SIGNED == 0 {
            continue;
        }

        let session_id = read_u64(&out, start + 0x28);
        let key = {
            let sessions = conn.sessions.read().await;
            sessions.get(&session_id).cloned()
        };
        let Some(session) = key else {
            continue;
        };
        let session = session.read().await;
        if matches!(session.identity, Identity::Anonymous) {
            continue;
        }
        let signing_key = session.signing_key;
        drop(session);

        if let Err(e) = sign(&mut out[start..start + len], &signing_key, algo) {
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
/// Walks the **entire** `NextCommand` chain, not just the first header.
/// MS-SMB2 permits compounding unrelated requests, and `dispatch_frame`
/// dispatches every sub-header without filtering — so an `ECHO + LOGOFF`
/// frame classified on its first header alone would be spawned and would
/// tear a session down underneath outstanding READs.
///
/// Also returns `true` for a frame shorter than `SMB2_HEADER_LEN`, a frame
/// not beginning with the SMB2 magic (the SMB1 multi-protocol bootstrap),
/// and any sub-header that fails to parse or whose `NextCommand` does not
/// point at a complete subsequent header — deliberately stricter than
/// `dispatch_frame`'s own guard, which tolerates `NextCommand` landing
/// exactly at frame end by terminating its loop there. A chain promising a
/// header that cannot exist must not take the concurrent path.
pub(crate) fn frame_must_be_serialized(frame: &[u8]) -> bool {
    if frame.len() < SMB2_HEADER_LEN || frame[0..4] != SMB2_MAGIC {
        return true;
    }

    let mut sub_offset = 0;
    loop {
        let available = &frame[sub_offset..];
        if available.len() < SMB2_HEADER_LEN {
            return true;
        }
        let (hdr, _) = match Smb2Header::parse(available) {
            Ok(p) => p,
            Err(_) => return true,
        };

        if matches!(
            hdr.command,
            Command::Negotiate
                | Command::SessionSetup
                | Command::Logoff
                | Command::TreeConnect
                | Command::TreeDisconnect
        ) {
            return true;
        }

        let next = hdr.next_command as usize;
        // `NextCommand == 0` terminates the chain and is normal — it is how
        // every ordinary single-command frame and every final compound
        // element is encoded. It MUST NOT be treated as malformed.
        if next == 0 {
            return false;
        }
        if next < SMB2_HEADER_LEN || next > available.len() || available.len() - next < SMB2_HEADER_LEN
        {
            return true;
        }
        sub_offset += next;
    }
}

async fn dispatch_one(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    frame: &[u8],
    compound_ordinal: u32,
) -> Option<Vec<u8>> {
    let (req_hdr, body_bytes) = match Smb2Header::parse(frame) {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "failed to parse header");
            return None;
        }
    };

    let cmd = req_hdr.command;
    let mid = req_hdr.message_id;
    let sid = req_hdr.session_id;
    let tid = req_hdr.tree_id().unwrap_or(0);

    let trace_key = server.trace_sink.as_ref().map(|_| crate::trace::TraceKey {
        connection_id: conn.connection_id,
        message_id: mid,
        compound_ordinal,
    });
    crate::trace::record(
        &server.trace_sink,
        trace_key,
        crate::trace::TraceEvent::Request {
            cmd: command_name(cmd),
            session_id: sid,
            tree_id: tid,
        },
    );

    let span = debug_span!("dispatch", cmd = ?cmd, mid, sid, tid);
    crate::trace::scoped(trace_key, async move {
        debug!("dispatch start");

        // Verify signature on incoming request (when applicable).
        if let Err(status) = verify_request_signature(server, conn, &req_hdr, frame).await {
            let bytes = build_response_bytes(conn, &req_hdr, HandlerResponse::err(status)).await;
            crate::trace::record(
                &server.trace_sink,
                trace_key,
                crate::trace::TraceEvent::Response { status },
            );
            return Some(bytes);
        }

        // CANCEL is fire-and-forget — no response.
        if cmd == Command::Cancel {
            debug!("CANCEL received; no response");
            return None;
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
            p.update(frame);
        } else if cmd == Command::SessionSetup
            && dialect == Some(crate::proto::messages::Dialect::Smb311)
        {
            let mut p = take_session_preauth(conn, req_hdr.session_id).await;
            p.update(frame);
            session_preauth = Some(p);
        }

        let resp = handlers::dispatch_command(server, conn, &req_hdr, body_bytes).await;

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
                if dialect == Some(crate::proto::messages::Dialect::Smb311) {
                    sess.signing_key =
                        crate::proto::crypto::signing_key_311(&sess.session_base_key, &snap);
                }
            }
        }

        let bytes = build_response_bytes(conn, &req_hdr, resp).await;
        crate::trace::record(
            &server.trace_sink,
            trace_key,
            crate::trace::TraceEvent::Response {
                status: read_u32(&bytes, 0x08),
            },
        );

        if cmd == Command::Negotiate {
            let mut p = conn
                .preauth
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            p.update(&bytes);
        } else if cmd == Command::SessionSetup
            && dialect == Some(crate::proto::messages::Dialect::Smb311)
        {
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
    })
    .instrument(span)
    .await
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
async fn build_response_bytes(
    conn: &Arc<Connection>,
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
    let algo = *conn.signing_algo.read().await;
    if !handler_resp.skip_signing
        && hdr.session_id != 0
        && (request_was_signed || is_session_setup_success)
    {
        let sessions = conn.sessions.read().await;
        if let Some(sess_arc) = sessions.get(&hdr.session_id) {
            let sess = sess_arc.read().await;
            let is_anon = matches!(sess.identity, Identity::Anonymous);
            let is_guest_response = is_session_setup_success
                && handler_resp.body.len() >= 4
                && (handler_resp.body[2] & 0x01) != 0;
            if !is_anon && !is_guest_response && sess.signing_key != [0u8; 16] {
                key = sess.signing_key;
                should_sign = true;
            }
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
    Some(build_response_bytes(conn, &req_hdr, resp).await)
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
            resp.is_some(),
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
            (
                "Negotiate alone",
                compound_of(&[Command::Negotiate]),
                true,
            ),
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
            (
                "a truncated frame",
                vec![0xFEu8, b'S', b'M', b'B'],
                true,
            ),
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
