//! CHANGE_NOTIFY handler (MS-SMB2 §3.3.5.19).
//!
//! The first request on a directory open starts a watch on it
//! (`crate::notify`); changes collect there from then on. A request that
//! finds changes waiting completes at once; otherwise it is answered
//! `STATUS_PENDING` and completes when a change arrives, when it is
//! cancelled (`STATUS_CANCELLED`), or when the open closes
//! (`STATUS_NOTIFY_CLEANUP`). A completion with changes drops the open's
//! directory cursor so the next QUERY_DIRECTORY on it lists afresh: macOS
//! re-reads the watched folder through the same FileId, often without
//! `RESTART_SCANS`.

use std::sync::Arc;

use tokio::sync::RwLock;

use crate::proto::header::Smb2Header;
use crate::proto::messages::{ChangeNotifyRequest, ChangeNotifyResponse};

use crate::conn::state::{Connection, Open, Pending};
use crate::dispatch::{HandlerResponse, send_final, send_interim};
use crate::handlers::shared::{lookup_open, lookup_session_tree};
use crate::notify::{Completion, Watch};
use crate::ntstatus;
use crate::server::ServerState;

pub async fn handle(
    _server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    body: &[u8],
) -> HandlerResponse {
    let req = match ChangeNotifyRequest::parse(body) {
        Ok(r) => r,
        Err(_) => return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER),
    };
    let tree_arc = match lookup_session_tree(conn, hdr).await {
        Ok(t) => t,
        Err(s) => return HandlerResponse::err(s),
    };
    let Some(notifier) = tree_arc.read().await.share.backend.change_notifier() else {
        return HandlerResponse::err(ntstatus::STATUS_NOT_SUPPORTED);
    };
    let Some(open_arc) = lookup_open(&tree_arc, req.file_id).await else {
        return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED);
    };
    let (watch, owner) = {
        let mut open = open_arc.write().await;
        if open.handle.is_none() {
            return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED);
        }
        if !open.is_directory {
            return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
        }
        let watch = match &open.watch {
            Some(w) => w.clone(),
            None => {
                let w = Watch::new(open.last_path.components());
                notifier.register(&w);
                open.watch = Some(w.clone());
                w
            }
        };
        (watch, open.lock_owner)
    };
    watch.arm(
        req.completion_filter,
        req.flags & ChangeNotifyRequest::FLAG_WATCH_TREE != 0,
    );
    let max_out = req.output_buffer_length;

    if let Some(done) = watch.take(max_out, || true) {
        return complete(&open_arc, done).await;
    }

    let async_id = conn.alloc_async_id();
    let (done, mut done_rx) = tokio::sync::oneshot::channel();
    conn.add_pending(
        async_id,
        Pending {
            message_id: hdr.message_id,
            owner,
            on_close: ntstatus::STATUS_NOTIFY_CLEANUP,
            done,
        },
    );
    send_interim(conn, hdr, async_id).await;
    let conn = conn.clone();
    let hdr = *hdr;
    tokio::spawn(async move {
        let resp = loop {
            tokio::select! {
                status = &mut done_rx => match status {
                    Ok(ntstatus::STATUS_NOTIFY_CLEANUP) => break notify_response(
                        ntstatus::STATUS_NOTIFY_CLEANUP,
                        Vec::new(),
                    ),
                    Ok(s) => break HandlerResponse::err(s),
                    Err(_) => return, // the connection ended
                },
                () = watch.changed.notified() => {
                    if let Some(done) = watch.take(max_out, || conn.take_pending(async_id)) {
                        break complete(&open_arc, done).await;
                    }
                }
            }
        };
        send_final(&conn, &hdr, async_id, resp).await;
    });
    HandlerResponse::pending()
}

async fn complete(open: &Arc<RwLock<Open>>, done: Completion) -> HandlerResponse {
    open.write().await.search_state = None;
    match done {
        Completion::Changes(buf) => notify_response(ntstatus::STATUS_SUCCESS, buf),
        Completion::EnumDir => notify_response(ntstatus::STATUS_NOTIFY_ENUM_DIR, Vec::new()),
    }
}

/// A CHANGE_NOTIFY response body. `STATUS_NOTIFY_ENUM_DIR` and
/// `STATUS_NOTIFY_CLEANUP` are success codes, so they carry this body (with
/// no changes), not an error body, which macOS would fail to parse.
fn notify_response(status: u32, buffer: Vec<u8>) -> HandlerResponse {
    let empty = buffer.is_empty();
    let resp = ChangeNotifyResponse {
        structure_size: 9,
        // macOS subtracts header and fixed part from this even when empty.
        output_buffer_offset: 64 + 8,
        output_buffer_length: buffer.len() as u32,
        buffer,
    };
    let mut body = Vec::new();
    resp.write_to(&mut body).expect("encode");
    if empty {
        // StructureSize 9 counts one byte of buffer.
        body.push(0);
    }
    let mut r = HandlerResponse::ok(body);
    r.status = status;
    r
}
