//! LOCK handler (MS-SMB2 §3.3.5.14): byte-range locks held in the share's
//! in-memory table (`crate::lock`).
//!
//! A request either unlocks (every element `UNLOCK`) or locks (every element
//! `SHARED` or `EXCLUSIVE`). A set of several locks must all be
//! `FAIL_IMMEDIATELY` and is taken whole or not at all. A single lock without
//! `FAIL_IMMEDIATELY` waits: the dispatcher sends `STATUS_PENDING` and owns
//! the final answer — when the range frees, the request is cancelled, or the
//! open closes.
//!
//! macOS smbfs sends a whole-file exclusive lock for `flock()` and exclusive
//! ranges for the byte-range-lock fsctl that SQLite's AFP-style locking uses
//! on smbfs; `fcntl()` locks never reach the server (smbfs answers `ENOTSUP`
//! itself on SMB2).

use std::sync::Arc;

use crate::proto::header::Smb2Header;
use crate::proto::messages::{LockElement, LockRequest, LockResponse};

use crate::conn::state::Connection;
use crate::dispatch::{AsyncWait, HandlerResponse, WaitOutcome};
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
    let (path, owner) = {
        let open = open_arc.read().await;
        if open.handle.is_none() {
            return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED);
        }
        (open.last_path.display_backslash(), open.lock_owner.clone())
    };
    let share = tree_arc.read().await.share.clone();
    // Case folding follows the backend, not the host: a case-insensitive
    // backend serves one file for two spellings, so their locks must meet in
    // one set.
    let key = if share.backend.capabilities().case_sensitive {
        path
    } else {
        path.to_lowercase()
    };
    tracing::debug!(owner = owner.id(), path = %key, locks = ?req.locks, "lock request");

    #[cfg(test)]
    crate::tests::pause::lock_handler(owner.id()).await;

    if req.locks[0].flags & LockElement::FLAG_UNLOCK != 0 {
        if req
            .locks
            .iter()
            .any(|l| l.flags != LockElement::FLAG_UNLOCK)
        {
            return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
        }
        let ranges: Vec<(u64, u64)> = req.locks.iter().map(|l| (l.offset, l.length)).collect();
        let result = share.locks.unlock(&key, &owner, &ranges);
        tracing::debug!(owner = owner.id(), ?result, "unlock");
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
    let result = share.locks.try_lock(&key, &owner, &ranges);
    tracing::debug!(owner = owner.id(), ?result, "lock");
    match result {
        Ok(_) => return ok(),
        Err(s)
            if s == ntstatus::STATUS_FILE_CLOSED
                || req.locks[0].flags & LockElement::FLAG_FAIL_IMMEDIATELY != 0 =>
        {
            return HandlerResponse::err(s);
        }
        Err(_) => {}
    }

    // A single lock without FAIL_IMMEDIATELY waits. The dispatcher sends the
    // interim and owns the final response; this handler returns at once and
    // stays under the frame deadline.
    let table = share.locks.clone();
    let wait_key = key.clone();
    let wait_owner = owner.clone();
    let range = ranges[0];
    let work = Box::pin(async move {
        match table.lock_wait(&wait_key, wait_owner, range).await {
            Ok(grant) => WaitOutcome::Granted {
                resp: ok(),
                held: Box::new(grant),
            },
            Err(status) => WaitOutcome::Failed(status),
        }
    });
    HandlerResponse::async_wait(AsyncWait {
        owner,
        on_close: ntstatus::STATUS_RANGE_NOT_LOCKED,
        refused: ntstatus::STATUS_LOCK_NOT_GRANTED,
        work,
    })
}

fn ok() -> HandlerResponse {
    let mut buf = Vec::new();
    LockResponse::default().write_to(&mut buf).expect("encode");
    HandlerResponse::ok(buf)
}
