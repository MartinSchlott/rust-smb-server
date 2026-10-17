//! LOCK handler (MS-SMB2 §3.3.5.14): byte-range locks held in the share's
//! in-memory table (`crate::lock`).
//!
//! A request either unlocks (every element `UNLOCK`) or locks (every element
//! `SHARED` or `EXCLUSIVE`). A set of several locks must all be
//! `FAIL_IMMEDIATELY` and is taken whole or not at all. A single lock without
//! `FAIL_IMMEDIATELY` waits: the client gets `STATUS_PENDING` at once and the
//! final answer when the range frees, the request is cancelled, or the open
//! closes.
//!
//! macOS smbfs sends a whole-file exclusive lock for `flock()` and exclusive
//! ranges for the byte-range-lock fsctl that SQLite's AFP-style locking uses
//! on smbfs; `fcntl()` locks never reach the server (smbfs answers `ENOTSUP`
//! itself on SMB2).

use std::sync::Arc;

use crate::proto::header::Smb2Header;
use crate::proto::messages::{LockElement, LockRequest, LockResponse};

use crate::conn::state::{Connection, Pending};
use crate::dispatch::{HandlerResponse, send_final, send_interim};
use crate::handlers::shared::{lookup_open, lookup_session_tree};
use crate::lock::Range;
use crate::ntstatus;
use crate::server::ServerState;

const KIND: u32 =
    LockElement::FLAG_SHARED_LOCK | LockElement::FLAG_EXCLUSIVE_LOCK | LockElement::FLAG_UNLOCK;

pub async fn handle(
    _server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    body: &[u8],
) -> HandlerResponse {
    let req = match LockRequest::parse(body) {
        Ok(r) if r.lock_count > 0 => r,
        _ => return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER),
    };
    let tree_arc = match lookup_session_tree(conn, hdr).await {
        Ok(t) => t,
        Err(s) => return HandlerResponse::err(s),
    };
    let Some(open_arc) = lookup_open(&tree_arc, req.file_id).await else {
        return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED);
    };
    let (key, owner) = {
        let open = open_arc.read().await;
        if open.handle.is_none() {
            return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED);
        }
        (
            open.last_path.display_backslash().to_lowercase(),
            open.lock_owner,
        )
    };
    let share = tree_arc.read().await.share.clone();
    tracing::debug!(owner, path = %key, locks = ?req.locks, "lock request");

    if req.locks[0].flags & LockElement::FLAG_UNLOCK != 0 {
        if req
            .locks
            .iter()
            .any(|l| l.flags != LockElement::FLAG_UNLOCK)
        {
            return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
        }
        let ranges: Vec<(u64, u64)> = req.locks.iter().map(|l| (l.offset, l.length)).collect();
        let result = share.locks.unlock(&key, owner, &ranges);
        tracing::debug!(owner, ?result, "unlock");
        return match result {
            Ok(()) => ok(),
            Err(s) => HandlerResponse::err(s),
        };
    }

    let mut ranges = Vec::with_capacity(req.locks.len());
    for l in &req.locks {
        let exclusive = match l.flags & KIND {
            LockElement::FLAG_SHARED_LOCK => false,
            LockElement::FLAG_EXCLUSIVE_LOCK => true,
            _ => return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER),
        };
        if req.locks.len() > 1 && l.flags & LockElement::FLAG_FAIL_IMMEDIATELY == 0 {
            return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
        }
        match Range::new(l.offset, l.length, exclusive) {
            Ok(r) => ranges.push(r),
            Err(s) => return HandlerResponse::err(s),
        }
    }
    let result = share.locks.try_lock(&key, owner, &ranges);
    tracing::debug!(owner, ?result, "lock");
    match result {
        Ok(()) => return ok(),
        Err(s) if req.locks[0].flags & LockElement::FLAG_FAIL_IMMEDIATELY != 0 => {
            return HandlerResponse::err(s);
        }
        Err(_) => {}
    }

    // Wait for the range.
    let async_id = conn.alloc_async_id();
    let (done, mut done_rx) = tokio::sync::oneshot::channel();
    conn.add_pending(
        async_id,
        Pending {
            message_id: hdr.message_id,
            owner,
            on_close: ntstatus::STATUS_RANGE_NOT_LOCKED,
            done,
        },
    );
    send_interim(conn, hdr, async_id).await;
    let conn = conn.clone();
    let hdr = *hdr;
    let range = ranges[0];
    tokio::spawn(async move {
        let resp = tokio::select! {
            status = &mut done_rx => match status {
                Ok(s) => HandlerResponse::err(s),
                Err(_) => return, // the connection ended
            },
            () = share.locks.lock_wait(&key, owner, range) => {
                if conn.take_pending(async_id) {
                    ok()
                } else {
                    // Cancelled or closed as the lock came free: give it back.
                    let _ = share.locks.unlock(&key, owner, &[(range.offset, range.length)]);
                    match done_rx.await {
                        Ok(s) => HandlerResponse::err(s),
                        Err(_) => return,
                    }
                }
            }
        };
        send_final(&conn, &hdr, async_id, resp).await;
    });
    HandlerResponse::pending()
}

fn ok() -> HandlerResponse {
    let mut buf = Vec::new();
    LockResponse::default().write_to(&mut buf).expect("encode");
    HandlerResponse::ok(buf)
}
