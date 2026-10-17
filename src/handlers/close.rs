//! CLOSE handler.

use std::sync::Arc;

use crate::proto::header::Smb2Header;
use crate::proto::messages::{CloseRequest, CloseResponse};
use tracing::debug;

use crate::conn::state::Connection;
use crate::dispatch::HandlerResponse;
use crate::handlers::shared::lookup_session_tree;
use crate::ntstatus;
use crate::server::ServerState;

const FLAG_POSTQUERY_ATTRIB: u16 = 0x0001;

pub async fn handle(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    body: &[u8],
) -> HandlerResponse {
    let req = match CloseRequest::parse(body) {
        Ok(r) => r,
        Err(_) => return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER),
    };
    let tree_arc = match lookup_session_tree(conn, hdr).await {
        Ok(t) => t,
        Err(s) => return HandlerResponse::err(s),
    };
    let removed = {
        let tree = tree_arc.write().await;
        let mut opens = tree.opens.write().await;
        opens.remove(&req.file_id)
    };
    let open_arc = match removed {
        Some(o) => o,
        None => return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED),
    };

    // Pull state out, close the handle, then optionally unlink.
    let mut open = open_arc.write().await;
    let handle = open.handle.take();
    let path = open.last_path.clone();
    let delete_on_close = open.delete_on_close;
    let want_attrs = req.flags & FLAG_POSTQUERY_ATTRIB != 0;
    let lock_owner = open.lock_owner;
    drop(open);
    conn.open_closed(&tree_arc.read().await.share, lock_owner);

    if server.trace_sink.is_some() {
        crate::trace::record(
            &server.trace_sink,
            crate::trace::current_trace_key(),
            crate::trace::TraceEvent::Close {
                file_id: [
                    req.file_id.persistent.to_le_bytes(),
                    req.file_id.volatile.to_le_bytes(),
                ]
                .concat()
                .try_into()
                .expect("FileId is 16 bytes"),
                delete_on_close,
                last_path: path.display_backslash(),
            },
        );
    }

    // Stat before closing if needed.
    let info_before_close = if want_attrs {
        if let Some(h) = handle.as_ref() {
            h.stat().await.ok()
        } else {
            None
        }
    } else {
        None
    };
    if let Some(h) = handle {
        let _ = h.close().await;
    }
    if delete_on_close {
        let tree = tree_arc.read().await;
        let backend = tree.share.backend.clone();
        drop(tree);
        if let Err(e) = backend.unlink(&path).await {
            debug!(error = %e, "delete-on-close unlink failed");
            // The handle is already closed and removed from the open table;
            // the delete is not honoured, and the CLOSE reports why rather
            // than answering success for a delete that did not happen.
            return HandlerResponse::err(e.to_nt_status());
        }
    }

    let resp = CloseResponse {
        structure_size: 60,
        flags: req.flags & FLAG_POSTQUERY_ATTRIB,
        reserved: 0,
        creation_time: info_before_close
            .as_ref()
            .map(|i| i.creation_time)
            .unwrap_or(0),
        last_access_time: info_before_close
            .as_ref()
            .map(|i| i.last_access_time)
            .unwrap_or(0),
        last_write_time: info_before_close
            .as_ref()
            .map(|i| i.last_write_time)
            .unwrap_or(0),
        change_time: info_before_close
            .as_ref()
            .map(|i| i.change_time)
            .unwrap_or(0),
        allocation_size: info_before_close
            .as_ref()
            .map(|i| i.allocation_size)
            .unwrap_or(0),
        end_of_file: info_before_close
            .as_ref()
            .map(|i| i.end_of_file)
            .unwrap_or(0),
        file_attributes: info_before_close
            .as_ref()
            .map(|i| i.attributes())
            .unwrap_or(0),
    };
    let mut buf = Vec::new();
    resp.write_to(&mut buf).expect("encode");
    HandlerResponse::ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::header::Command;
    use crate::tests::handler_support as hs;
    use crate::tests::memfs::MemFsBackend;

    const FILE_CREATE: u32 = 0x0000_0002;
    const FILE_DELETE_ON_CLOSE: u32 = 0x0000_1000;
    const DELETE: u32 = 0x0001_0000;

    /// A backend that keeps the default `check_delete` (returns `Ok`) must
    /// delete on close exactly as it did before the preflight existed.
    #[tokio::test]
    async fn default_hook_delete_on_close_still_deletes_the_file() {
        let server = hs::test_server();
        let backend = MemFsBackend::new();
        let observer = backend.clone();
        let (conn, session_id, tree_id) = hs::test_conn_with_backend(backend).await;

        let hdr = hs::header(session_id, tree_id, Command::Create);
        let body = hs::create_request("tmp.txt", FILE_DELETE_ON_CLOSE, FILE_CREATE, DELETE);
        let resp = crate::handlers::dispatch_command(&server, &conn, &hdr, &body).await;
        assert_eq!(resp.status, ntstatus::STATUS_SUCCESS);

        let (file_id, delete_on_close) = hs::sole_open(&conn, session_id, tree_id).await;
        assert!(delete_on_close);

        let hdr = hs::header(session_id, tree_id, Command::Close);
        let body = hs::close_request(file_id);
        let resp = crate::handlers::dispatch_command(&server, &conn, &hdr, &body).await;
        assert_eq!(resp.status, ntstatus::STATUS_SUCCESS);
        assert!(
            !observer.has_file("tmp.txt"),
            "the default hook leaves the delete-on-close behaviour unchanged"
        );
    }
}
