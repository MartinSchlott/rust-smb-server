//! SET_INFO handler.

use std::sync::Arc;

use crate::proto::header::Smb2Header;
use crate::proto::messages::{InfoType, SetInfoRequest, SetInfoResponse};

use crate::backend::FileTimes;
use crate::conn::state::Connection;
use crate::dispatch::HandlerResponse;
use crate::handlers::shared::{lookup_open, lookup_session_tree};
use crate::info_class as ic;
use crate::ntstatus;
use crate::path::SmbPath;
use crate::server::ServerState;
use crate::utils::utf16le_to_units;

pub async fn handle(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    body: &[u8],
) -> HandlerResponse {
    let req = match SetInfoRequest::parse(body) {
        Ok(r) => r,
        Err(_) => return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER),
    };
    let info_type = match InfoType::from_u8(req.info_type) {
        Some(t) => t,
        None => return HandlerResponse::err(ntstatus::STATUS_INVALID_INFO_CLASS),
    };
    if !matches!(info_type, InfoType::File) {
        return HandlerResponse::err(ntstatus::STATUS_NOT_SUPPORTED);
    }

    let tree_arc = match lookup_session_tree(conn, hdr).await {
        Ok(t) => t,
        Err(s) => return HandlerResponse::err(s),
    };
    let open_arc = match lookup_open(&tree_arc, req.file_id).await {
        Some(o) => o,
        None => return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED),
    };

    let class = req.file_information_class;
    let buffer = req.buffer;
    let backend = {
        let tree = tree_arc.read().await;
        tree.share.backend.clone()
    };

    if class != ic::FILE_RENAME_INFORMATION && server.trace_sink.is_some() {
        crate::trace::record(
            &server.trace_sink,
            crate::trace::current_trace_key(),
            crate::trace::TraceEvent::SetInfoOther { info_class: class },
        );
    }

    let result = match class {
        ic::FILE_BASIC_INFORMATION => {
            if buffer.len() < 36 {
                return HandlerResponse::err(ntstatus::STATUS_INFO_LENGTH_MISMATCH);
            }
            let creation = u64::from_le_bytes(buffer[0..8].try_into().unwrap());
            let access = u64::from_le_bytes(buffer[8..16].try_into().unwrap());
            let write = u64::from_le_bytes(buffer[16..24].try_into().unwrap());
            let change = u64::from_le_bytes(buffer[24..32].try_into().unwrap());
            // 0 means "do not change", -1 (u64::MAX) means "do not change" too per spec.
            let to_some = |v: u64| {
                if v == 0 || v == u64::MAX {
                    None
                } else {
                    Some(v)
                }
            };
            let times = FileTimes {
                creation_time: to_some(creation),
                last_access_time: to_some(access),
                last_write_time: to_some(write),
                change_time: to_some(change),
            };
            let open = open_arc.read().await;
            match open.handle.as_ref() {
                Some(h) => h.set_times(times).await,
                None => return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED),
            }
        }
        ic::FILE_END_OF_FILE_INFORMATION => {
            if buffer.len() < 8 {
                return HandlerResponse::err(ntstatus::STATUS_INFO_LENGTH_MISMATCH);
            }
            let new_len = u64::from_le_bytes(buffer[0..8].try_into().unwrap());
            let open = open_arc.read().await;
            match open.handle.as_ref() {
                Some(h) => h.truncate(new_len).await,
                None => return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED),
            }
        }
        ic::FILE_DISPOSITION_INFORMATION => {
            if buffer.is_empty() {
                return HandlerResponse::err(ntstatus::STATUS_INFO_LENGTH_MISMATCH);
            }
            let request_delete = buffer[0] != 0;
            let mut open = open_arc.write().await;
            // A non-zero value asks for a delete-on-close. Refuse it here, at
            // the client's request, when the backend can already tell the
            // delete would fail; the flag stays unchanged and the later CLOSE
            // performs nothing. A zero value clears the flag without a check.
            if request_delete && let Err(e) = backend.check_delete(&open.last_path).await {
                return HandlerResponse::err(e.to_nt_status());
            }
            open.delete_on_close = request_delete;
            Ok(())
        }
        ic::FILE_RENAME_INFORMATION => {
            // FILE_RENAME_INFORMATION layout (MS-FSCC §2.4.37):
            //   ReplaceIfExists (1) | Reserved (7) | RootDirectory (8) | FileNameLength (4) | FileName...
            if buffer.len() < 20 {
                return HandlerResponse::err(ntstatus::STATUS_INFO_LENGTH_MISMATCH);
            }
            let name_len = u32::from_le_bytes(buffer[16..20].try_into().unwrap()) as usize;
            if buffer.len() < 20 + name_len {
                return HandlerResponse::err(ntstatus::STATUS_INFO_LENGTH_MISMATCH);
            }
            let name_bytes = &buffer[20..20 + name_len];
            let units = match utf16le_to_units(name_bytes) {
                Some(u) => u,
                None => return HandlerResponse::err(ntstatus::STATUS_OBJECT_NAME_INVALID),
            };
            let new_path = match SmbPath::from_utf16(&units) {
                Ok(p) => p,
                Err(_) => return HandlerResponse::err(ntstatus::STATUS_OBJECT_NAME_INVALID),
            };
            let from = open_arc.read().await.last_path.clone();
            // MS-FSCC §2.4.37 byte 0.
            let replace_if_exists = buffer[0] != 0;
            if server.trace_sink.is_some() {
                crate::trace::record(
                    &server.trace_sink,
                    crate::trace::current_trace_key(),
                    crate::trace::TraceEvent::SetInfoRename {
                        replace_if_exists,
                        new_name: new_path.display_backslash(),
                        resolved_source: from.display_backslash(),
                    },
                );
            }
            match backend.rename(&from, &new_path, replace_if_exists).await {
                Ok(()) => {
                    open_arc.write().await.last_path = new_path;
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }
        ic::FILE_ALLOCATION_INFORMATION => {
            // FILE_ALLOCATION_INFORMATION (MS-FSCC §2.4.4) is a single 8-byte
            // LARGE_INTEGER AllocationSize.
            //
            // We still don't preallocate, so raising the allocation stays a
            // no-op. But the spec is explicit that lowering AllocationSize
            // below the current EndOfFile MUST lower EndOfFile to it too —
            // shrinking the allocation *is* a truncate. Acknowledging that
            // with STATUS_SUCCESS while leaving the bytes on disk silently
            // corrupts data: Windows truncates via 0x13 (what .NET
            // `FileStream.SetLength(0)` and PowerShell `Set-Content` emit),
            // never follows up with 0x14, and then reopens with
            // FILE_APPEND_DATA — so the "new" content lands after the stale
            // bytes instead of replacing them. macOS smbfs sends 0x14
            // directly and is unaffected either way.
            if buffer.len() < 8 {
                return HandlerResponse::err(ntstatus::STATUS_INFO_LENGTH_MISMATCH);
            }
            let allocation = u64::from_le_bytes(buffer[0..8].try_into().unwrap());
            let open = open_arc.read().await;
            let handle = match open.handle.as_ref() {
                Some(h) => h,
                None => return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED),
            };
            match handle.stat().await {
                // Shrink: reuse the exact backend set-length path 0x14 takes.
                Ok(info) if allocation < info.end_of_file => handle.truncate(allocation).await,
                // At or above EndOfFile: nothing to do, we never preallocate.
                Ok(_) => Ok(()),
                Err(e) => Err(e),
            }
        }
        _ => return HandlerResponse::err(ntstatus::STATUS_NOT_SUPPORTED),
    };

    if let Err(e) = result {
        return HandlerResponse::err(e.to_nt_status());
    }
    let mut buf = Vec::new();
    SetInfoResponse::default()
        .write_to(&mut buf)
        .expect("encode");
    HandlerResponse::ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::header::Command;
    use crate::tests::handler_support as hs;
    use crate::tests::memfs::RefusingDeleteBackend;

    const FILE_OPEN: u32 = 0x0000_0001;
    const FILE_READ_DATA: u32 = 0x0000_0001;

    /// Open `name` through the CREATE handler and return its FileId.
    async fn open_existing(
        server: &Arc<ServerState>,
        conn: &Arc<Connection>,
        session_id: u64,
        tree_id: u32,
        name: &str,
    ) -> crate::proto::messages::create::FileId {
        let body = hs::create_request(name, 0, FILE_OPEN, FILE_READ_DATA);
        let hdr = hs::header(session_id, tree_id, Command::Create);
        let resp = crate::handlers::dispatch_command(server, conn, &hdr, &body).await;
        assert_eq!(resp.status, ntstatus::STATUS_SUCCESS, "setup: open {name}");
        hs::sole_open(conn, session_id, tree_id).await.0
    }

    #[tokio::test]
    async fn a_refused_disposition_leaves_the_flag_unset_and_nothing_is_deleted() {
        let server = hs::test_server();
        let backend = RefusingDeleteBackend::new().with_file("victim.txt", b"data");
        backend.set_refuse_check_delete(true);
        let observer = backend.clone();
        let (conn, session_id, tree_id) = hs::test_conn_with_backend(backend).await;

        let file_id = open_existing(&server, &conn, session_id, tree_id, "victim.txt").await;

        let hdr = hs::header(session_id, tree_id, Command::SetInfo);
        let body = hs::set_info_disposition(file_id, true);
        let resp = handle(&server, &conn, &hdr, &body).await;
        assert_eq!(
            resp.status,
            ntstatus::STATUS_DIRECTORY_NOT_EMPTY,
            "the backend's refusal must reach the client at its request"
        );

        assert_eq!(observer.check_delete_call_count(), 1);
        let (_, delete_on_close) = hs::sole_open(&conn, session_id, tree_id).await;
        assert!(
            !delete_on_close,
            "a refused disposition must leave the flag unchanged"
        );

        // The later CLOSE has nothing to delete, and the file survives.
        let hdr = hs::header(session_id, tree_id, Command::Close);
        let body = hs::close_request(file_id);
        let resp = crate::handlers::dispatch_command(&server, &conn, &hdr, &body).await;
        assert_eq!(resp.status, ntstatus::STATUS_SUCCESS);
        assert!(
            observer.has_file("victim.txt"),
            "a delete the server refused must not later be performed"
        );
    }

    #[tokio::test]
    async fn an_accepted_disposition_sets_the_flag_and_a_refused_close_reports_it() {
        let server = hs::test_server();
        let backend = RefusingDeleteBackend::new().with_file("victim.txt", b"data");
        // check_delete accepts (default), but the close-time unlink refuses.
        backend.set_refuse_unlink(true);
        let observer = backend.clone();
        let (conn, session_id, tree_id) = hs::test_conn_with_backend(backend).await;

        let file_id = open_existing(&server, &conn, session_id, tree_id, "victim.txt").await;

        let hdr = hs::header(session_id, tree_id, Command::SetInfo);
        let body = hs::set_info_disposition(file_id, true);
        let resp = handle(&server, &conn, &hdr, &body).await;
        assert_eq!(resp.status, ntstatus::STATUS_SUCCESS);
        assert!(
            hs::sole_open(&conn, session_id, tree_id).await.1,
            "an accepted disposition must set the flag"
        );

        let hdr = hs::header(session_id, tree_id, Command::Close);
        let body = hs::close_request(file_id);
        let resp = crate::handlers::dispatch_command(&server, &conn, &hdr, &body).await;
        assert_eq!(
            resp.status,
            ntstatus::STATUS_DIRECTORY_NOT_EMPTY,
            "a CLOSE-time delete failure must be reported, not answered as success"
        );
        assert_eq!(observer.unlink_call_count(), 1);
        assert_eq!(
            hs::open_count(&conn, session_id, tree_id).await,
            0,
            "the handle must still be closed and removed even though the delete failed"
        );
        assert!(observer.has_file("victim.txt"));
    }
}
