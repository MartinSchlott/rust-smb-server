//! IOCTL handler — handles FSCTL_VALIDATE_NEGOTIATE_INFO, the two symlink
//! reparse FSCTLs, and DFS referrals; everything else returns NOT_SUPPORTED.

use std::sync::Arc;

use crate::proto::header::Smb2Header;
use crate::proto::messages::{Fsctl, IoctlRequest, IoctlResponse};

use crate::builder::Access;
use crate::conn::state::Connection;
use crate::dispatch::HandlerResponse;
use crate::handlers::negotiate::{NEGOTIATE_CAPABILITIES, NEGOTIATE_SECURITY_MODE};
use crate::handlers::shared::{lookup_open, lookup_session_tree};
use crate::ntstatus;
use crate::server::ServerState;

/// Absolute offset (from the SMB2 header) the spike measured the macOS client
/// accepts for an IOCTL's output buffer. `64` (header) + `48` (fixed IOCTL
/// response through the 4-byte-aligned `OutputCount`).
const IOCTL_OUTPUT_OFFSET: u32 = 0x70;

/// Builds a success response carrying `output` as the IOCTL output buffer.
fn ok_with_output(req: &IoctlRequest, output: Vec<u8>) -> HandlerResponse {
    let resp = IoctlResponse {
        structure_size: 49,
        reserved: 0,
        ctl_code: req.ctl_code,
        file_id: req.file_id,
        input_offset: IOCTL_OUTPUT_OFFSET,
        input_count: 0,
        output_offset: IOCTL_OUTPUT_OFFSET,
        output_count: output.len() as u32,
        flags: 0,
        reserved2: 0,
        output,
    };
    let mut buf = Vec::new();
    resp.write_to(&mut buf).expect("IOCTL response encodes");
    HandlerResponse::ok(buf)
}

pub async fn handle(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    body: &[u8],
) -> HandlerResponse {
    let req = match IoctlRequest::parse(body) {
        Ok(r) => r,
        Err(_) => return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER),
    };

    match req.fsctl() {
        Fsctl::ValidateNegotiateInfo => {
            // Build VALIDATE_NEGOTIATE_INFO_RESPONSE per MS-SMB2 §2.2.32.6:
            // Capabilities (4) | Guid (16) | SecurityMode (2) | Dialect (2) = 24 bytes.
            let dialect = conn.dialect.read().await.map(|d| d.as_u16()).unwrap_or(0);
            let mut out = Vec::with_capacity(24);
            out.extend_from_slice(&NEGOTIATE_CAPABILITIES.to_le_bytes());
            out.extend_from_slice(server.config.server_guid.as_bytes());
            out.extend_from_slice(&NEGOTIATE_SECURITY_MODE.to_le_bytes());
            out.extend_from_slice(&dialect.to_le_bytes());

            let resp = IoctlResponse {
                structure_size: 49,
                reserved: 0,
                ctl_code: req.ctl_code,
                file_id: req.file_id,
                input_offset: 0,
                input_count: 0,
                output_offset: 0x70,
                output_count: out.len() as u32,
                flags: 0,
                reserved2: 0,
                output: out,
            };
            let mut buf = Vec::new();
            resp.write_to(&mut buf).expect("IOCTL response encodes");
            HandlerResponse::ok(buf)
        }
        Fsctl::GetReparsePoint => {
            let tree_arc = match lookup_session_tree(conn, hdr).await {
                Ok(t) => t,
                Err(s) => return HandlerResponse::err(s),
            };
            let open_arc = match lookup_open(&tree_arc, req.file_id).await {
                Some(o) => o,
                None => return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED),
            };
            let target = {
                let open = open_arc.read().await;
                match open.handle.as_ref() {
                    Some(h) => h.read_link().await,
                    None => return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED),
                }
            };
            let target = match target {
                Ok(t) => t,
                Err(e) => return HandlerResponse::err(e.to_nt_status()),
            };
            let encoded = crate::reparse::encode_symlink_reparse(&target);
            if encoded.len() as u64 > req.max_output_response as u64 {
                return HandlerResponse::err(ntstatus::STATUS_BUFFER_TOO_SMALL);
            }
            ok_with_output(&req, encoded)
        }
        Fsctl::SetReparsePoint => {
            let tree_arc = match lookup_session_tree(conn, hdr).await {
                Ok(t) => t,
                Err(s) => return HandlerResponse::err(s),
            };
            let granted = {
                let tree = tree_arc.read().await;
                tree.granted_access
            };
            // A reparse-point write is a mutation: mirror WRITE's tree-level
            // gate rather than trusting the CREATE's access mask.
            if !matches!(granted, Access::ReadWrite) {
                return HandlerResponse::err(ntstatus::STATUS_ACCESS_DENIED);
            }
            let open_arc = match lookup_open(&tree_arc, req.file_id).await {
                Some(o) => o,
                None => return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED),
            };
            let target = match crate::reparse::decode_symlink_reparse(&req.input) {
                Ok(t) => t,
                Err(_) => return HandlerResponse::err(ntstatus::STATUS_IO_REPARSE_DATA_INVALID),
            };
            let result = {
                let open = open_arc.read().await;
                match open.handle.as_ref() {
                    Some(h) => h.set_symlink(&target).await,
                    None => return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED),
                }
            };
            match result {
                Ok(()) => ok_with_output(&req, Vec::new()),
                Err(e) => HandlerResponse::err(e.to_nt_status()),
            }
        }
        Fsctl::DfsGetReferrals | Fsctl::DfsGetReferralsEx => {
            HandlerResponse::err(ntstatus::STATUS_FS_DRIVER_REQUIRED)
        }
        _ => HandlerResponse::err(ntstatus::STATUS_NOT_SUPPORTED),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{DirEntry, FileInfo, FileTimes, Handle};
    use crate::conn::state::{Open, Session, TreeConnect};
    use crate::error::{SmbError, SmbResult};
    use crate::path::SmbPath;
    use crate::proto::auth::ntlm::Identity;
    use crate::proto::header::{Command, HeaderTail};
    use crate::proto::messages::FileId;
    use crate::server::{ServerConfig, ServerState, ServerUsers, ShareBindings, ShareMode};
    use crate::tests::memfs::MemFsBackend;
    use async_trait::async_trait;
    use bytes::Bytes;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use tokio::sync::RwLock;
    use uuid::Uuid;

    /// A handle that answers `read_link`/`set_symlink` without any disk, so
    /// the two reparse FSCTLs can be driven in isolation.
    struct LinkHandle {
        target: Option<String>,
        set_calls: Arc<Mutex<Vec<String>>>,
    }

    #[async_trait]
    impl Handle for LinkHandle {
        async fn read(&self, _offset: u64, _len: u32) -> SmbResult<Bytes> {
            Err(SmbError::NotSupported)
        }
        async fn write(&self, _offset: u64, _data: &[u8]) -> SmbResult<u32> {
            Err(SmbError::NotSupported)
        }
        async fn flush(&self) -> SmbResult<()> {
            Ok(())
        }
        async fn stat(&self) -> SmbResult<FileInfo> {
            Ok(FileInfo {
                name: "link".to_string(),
                end_of_file: 0,
                allocation_size: 0,
                creation_time: 0,
                last_access_time: 0,
                last_write_time: 0,
                change_time: 0,
                is_directory: false,
                is_symlink: self.target.is_some(),
                file_index: 0,
            })
        }
        async fn set_times(&self, _times: FileTimes) -> SmbResult<()> {
            Ok(())
        }
        async fn truncate(&self, _len: u64) -> SmbResult<()> {
            Err(SmbError::NotSupported)
        }
        async fn list_dir(&self, _pattern: Option<&str>) -> SmbResult<Vec<DirEntry>> {
            Err(SmbError::NotADirectory)
        }
        async fn read_link(&self) -> SmbResult<String> {
            self.target.clone().ok_or(SmbError::NotAReparsePoint)
        }
        async fn set_symlink(&self, target: &str) -> SmbResult<()> {
            self.set_calls.lock().unwrap().push(target.to_string());
            Ok(())
        }
        async fn close(self: Box<Self>) -> SmbResult<()> {
            Ok(())
        }
    }

    fn test_server() -> Arc<ServerState> {
        let cfg = ServerConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            netbios_name: "TEST".to_string(),
            max_read_size: 1024 * 1024,
            max_write_size: 1024 * 1024,
            server_guid: Uuid::nil(),
        };
        let users = ServerUsers {
            table: RwLock::new(HashMap::new()),
        };
        Arc::new(ServerState::new(cfg, users, vec![]))
    }

    /// A connection, session and tree with one pre-inserted open bound to
    /// `handle`. Returns `(conn, session_id, tree_id, file_id)`.
    async fn test_conn_with_open(
        handle: Box<dyn Handle>,
        granted: Access,
    ) -> (Arc<Connection>, u64, u32, FileId) {
        let conn = Arc::new(Connection::new(1, Uuid::nil(), 1024 * 1024, 1024 * 1024));
        let session = Session::new(1, Identity::Anonymous, [0; 16], [0; 16], false, None);
        let session = Arc::new(RwLock::new(session));
        let share = ShareBindings::new(
            "share".to_string(),
            Arc::new(MemFsBackend::new()),
            ShareMode::Public,
            HashMap::new(),
            false,
        );
        let tree = Arc::new(RwLock::new(TreeConnect::new(1, share, granted)));
        let file_id = {
            let t = tree.read().await;
            t.alloc_file_id()
        };
        {
            let t = tree.read().await;
            t.opens.write().await.insert(
                file_id,
                Arc::new(RwLock::new(Open::new(
                    file_id,
                    handle,
                    granted,
                    "link".parse::<SmbPath>().unwrap(),
                    false,
                    false,
                ))),
            );
        }
        {
            let sess = session.read().await;
            sess.trees.write().await.insert(1, tree);
        }
        conn.sessions.write().await.insert(1, session);
        (conn, 1, 1, file_id)
    }

    fn header(session_id: u64, tree_id: u32) -> Smb2Header {
        Smb2Header {
            credit_charge: 1,
            channel_sequence_status: 0,
            command: Command::Ioctl,
            credit_request_response: 1,
            flags: 0,
            next_command: 0,
            message_id: 1,
            tail: HeaderTail::sync(tree_id),
            session_id,
            signature: [0u8; 16],
        }
    }

    fn ioctl_request_bytes(
        ctl_code: u32,
        file_id: FileId,
        input: Vec<u8>,
        max_out: u32,
    ) -> Vec<u8> {
        let req = IoctlRequest {
            structure_size: 57,
            reserved: 0,
            ctl_code,
            file_id,
            input_offset: 0x78,
            input_count: input.len() as u32,
            max_input_response: 0,
            output_offset: 0,
            output_count: 0,
            max_output_response: max_out,
            flags: IoctlRequest::FLAG_IS_FSCTL,
            reserved2: 0,
            input,
        };
        let mut buf = Vec::new();
        req.write_to(&mut buf).unwrap();
        buf
    }

    fn link_handle(target: Option<&str>) -> (Box<dyn Handle>, Arc<Mutex<Vec<String>>>) {
        let set_calls = Arc::new(Mutex::new(Vec::new()));
        let handle = Box::new(LinkHandle {
            target: target.map(str::to_string),
            set_calls: set_calls.clone(),
        });
        (handle, set_calls)
    }

    #[tokio::test]
    async fn get_reparse_point_returns_the_encoded_target() {
        let server = test_server();
        let (handle, _set) = link_handle(Some("../pkg/bin/cli.js"));
        let (conn, sid, tid, file_id) = test_conn_with_open(handle, Access::ReadWrite).await;
        let hdr = header(sid, tid);
        let body = ioctl_request_bytes(Fsctl::GET_REPARSE_POINT, file_id, vec![], 16384);

        let resp = handle_fn(&server, &conn, &hdr, &body).await;
        assert_eq!(resp.status, ntstatus::STATUS_SUCCESS);
        let parsed = IoctlResponse::parse(&resp.body).unwrap();
        assert_eq!(parsed.output_offset, 0x70);
        assert_eq!(
            crate::reparse::decode_symlink_reparse(&parsed.output).unwrap(),
            "../pkg/bin/cli.js"
        );
    }

    #[tokio::test]
    async fn get_reparse_point_on_a_non_reparse_handle_is_not_a_reparse_point() {
        let server = test_server();
        let (handle, _set) = link_handle(None);
        let (conn, sid, tid, file_id) = test_conn_with_open(handle, Access::ReadWrite).await;
        let hdr = header(sid, tid);
        let body = ioctl_request_bytes(Fsctl::GET_REPARSE_POINT, file_id, vec![], 16384);

        let resp = handle_fn(&server, &conn, &hdr, &body).await;
        assert_eq!(resp.status, ntstatus::STATUS_NOT_A_REPARSE_POINT);
    }

    #[tokio::test]
    async fn get_reparse_point_with_a_too_small_buffer_is_buffer_too_small() {
        let server = test_server();
        let (handle, _set) = link_handle(Some("../pkg/bin/cli.js"));
        let (conn, sid, tid, file_id) = test_conn_with_open(handle, Access::ReadWrite).await;
        let hdr = header(sid, tid);
        let body = ioctl_request_bytes(Fsctl::GET_REPARSE_POINT, file_id, vec![], 4);

        let resp = handle_fn(&server, &conn, &hdr, &body).await;
        assert_eq!(resp.status, ntstatus::STATUS_BUFFER_TOO_SMALL);
    }

    #[tokio::test]
    async fn set_reparse_point_passes_the_decoded_posix_target() {
        let server = test_server();
        let (handle, set_calls) = link_handle(None);
        let (conn, sid, tid, file_id) = test_conn_with_open(handle, Access::ReadWrite).await;
        let hdr = header(sid, tid);
        let input = crate::reparse::encode_symlink_reparse("../pkg/bin/cli.js");
        let body = ioctl_request_bytes(Fsctl::SET_REPARSE_POINT, file_id, input, 0);

        let resp = handle_fn(&server, &conn, &hdr, &body).await;
        assert_eq!(resp.status, ntstatus::STATUS_SUCCESS);
        assert_eq!(
            *set_calls.lock().unwrap(),
            vec!["../pkg/bin/cli.js".to_string()]
        );
    }

    #[tokio::test]
    async fn set_reparse_point_with_a_garbage_buffer_is_data_invalid() {
        let server = test_server();
        let (handle, set_calls) = link_handle(None);
        let (conn, sid, tid, file_id) = test_conn_with_open(handle, Access::ReadWrite).await;
        let hdr = header(sid, tid);
        // 8 zero bytes: a zero tag, never `IO_REPARSE_TAG_SYMLINK`.
        let body = ioctl_request_bytes(Fsctl::SET_REPARSE_POINT, file_id, vec![0u8; 8], 0);

        let resp = handle_fn(&server, &conn, &hdr, &body).await;
        assert_eq!(resp.status, ntstatus::STATUS_IO_REPARSE_DATA_INVALID);
        assert!(set_calls.lock().unwrap().is_empty());
    }

    /// The top-level `handle` is shadowed by the `handle` locals above, so
    /// the module function gets this alias.
    async fn handle_fn(
        server: &Arc<ServerState>,
        conn: &Arc<Connection>,
        hdr: &Smb2Header,
        body: &[u8],
    ) -> HandlerResponse {
        super::handle(server, conn, hdr, body).await
    }
}
