//! QUERY_INFO handler.

use std::sync::Arc;

use crate::proto::header::Smb2Header;
use crate::proto::messages::{InfoType, QueryInfoRequest, QueryInfoResponse};

use crate::conn::state::Connection;
use crate::dispatch::HandlerResponse;
use crate::handlers::shared::{lookup_open, lookup_session_tree};
use crate::info_class as ic;
use crate::ntstatus;
use crate::server::ServerState;

const FILE_DEVICE_DISK: u32 = 0x0000_0007;
const FILE_REMOTE_DEVICE: u32 = 0x0000_0010;

// FS attribute flags (MS-FSCC §2.5.1)
const FILE_CASE_SENSITIVE_SEARCH: u32 = 0x0000_0001;
const FILE_CASE_PRESERVED_NAMES: u32 = 0x0000_0002;
const FILE_UNICODE_ON_DISK: u32 = 0x0000_0004;
const FILE_PERSISTENT_ACLS: u32 = 0x0000_0008;
const FILE_FILE_COMPRESSION: u32 = 0x0000_0010;
const FILE_SUPPORTS_HARD_LINKS: u32 = 0x0040_0000;
const FILE_SUPPORTS_EXTENDED_ATTRIBUTES: u32 = 0x0080_0000;
const FILE_NAMED_STREAMS: u32 = 0x0004_0000;

pub async fn handle(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    body: &[u8],
) -> HandlerResponse {
    let req = match QueryInfoRequest::parse(body) {
        Ok(r) => r,
        Err(_) => return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER),
    };
    let info_type = match req.info_type_enum() {
        Some(t) => t,
        None => return HandlerResponse::err(ntstatus::STATUS_INVALID_INFO_CLASS),
    };

    // Record the queried type/class so a `FILE_STREAM_INFORMATION` query is
    // distinguishable in the wire log from any other QUERY_INFO (Step 1d).
    if server.trace_sink.is_some() {
        crate::trace::record(
            &server.trace_sink,
            crate::trace::current_trace_key(),
            crate::trace::TraceEvent::QueryInfo {
                info_type: req.info_type,
                info_class: req.file_information_class,
            },
        );
    }

    let tree_arc = match lookup_session_tree(conn, hdr).await {
        Ok(t) => t,
        Err(s) => return HandlerResponse::err(s),
    };
    let open_arc = match lookup_open(&tree_arc, req.file_id).await {
        Some(o) => o,
        None => return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED),
    };

    // Pull the file index (we use FileId.volatile as the unique handle id).
    let (file_index, info_res) = {
        let open = open_arc.read().await;
        let fid = open.file_id;
        match open.handle.as_ref() {
            Some(h) => (fid.volatile, h.stat().await),
            None => return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED),
        }
    };

    // Set when `FILE_STREAM_INFORMATION` had to be truncated to fit the
    // client's output buffer; answered with `STATUS_BUFFER_OVERFLOW` and the
    // partial (whole-entry) chain, per MS-FSCC §2.4.43.
    let mut buffer_overflow = false;

    let buf: Vec<u8> = match info_type {
        InfoType::File => {
            let info = match info_res {
                Ok(i) => i,
                Err(e) => return HandlerResponse::err(e.to_nt_status()),
            };
            match req.file_information_class {
                ic::FILE_BASIC_INFORMATION => ic::encode_file_basic_information(&info),
                ic::FILE_STANDARD_INFORMATION => ic::encode_file_standard_information(&info),
                ic::FILE_INTERNAL_INFORMATION => ic::encode_file_internal_information(file_index),
                ic::FILE_EA_INFORMATION => ic::encode_file_ea_information(),
                ic::FILE_FULL_EA_INFORMATION => {
                    return HandlerResponse::err(ntstatus::STATUS_NO_EAS_ON_FILE);
                }
                ic::FILE_ACCESS_INFORMATION => ic::encode_file_access_information(0x001F_01FF),
                ic::FILE_POSITION_INFORMATION => ic::encode_file_position_information(),
                ic::FILE_MODE_INFORMATION => ic::encode_file_mode_information(0),
                ic::FILE_ALIGNMENT_INFORMATION => ic::encode_file_alignment_information(),
                ic::FILE_NAME_INFORMATION => ic::encode_file_name_information(&info.name),
                ic::FILE_ALL_INFORMATION => {
                    ic::encode_file_all_information(&info, file_index, 0x001F_01FF)
                }
                ic::FILE_NETWORK_OPEN_INFORMATION => {
                    ic::encode_file_network_open_information(&info)
                }
                ic::FILE_STREAM_INFORMATION => {
                    let streams = {
                        let open = open_arc.read().await;
                        match open.handle.as_ref() {
                            Some(h) => h.list_streams().await,
                            None => return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED),
                        }
                    };
                    let streams = match streams {
                        Ok(s) => s,
                        Err(e) => return HandlerResponse::err(e.to_nt_status()),
                    };
                    let full = ic::encode_file_stream_information(&info, streams.as_deref());
                    if full.len() as u32 > req.output_buffer_length {
                        // A file with many streams can exceed the client's
                        // buffer where the pre-plan single hardcoded entry
                        // never could. Emit as many whole entries as fit —
                        // `::$DATA` first, so the client always learns the
                        // file has a data stream — and terminate the chain.
                        match ic::truncate_file_stream_information(&full, req.output_buffer_length)
                        {
                            Some(partial) => {
                                buffer_overflow = true;
                                partial
                            }
                            None => {
                                return HandlerResponse::err(ntstatus::STATUS_INFO_LENGTH_MISMATCH);
                            }
                        }
                    } else {
                        full
                    }
                }
                _ => return HandlerResponse::err(ntstatus::STATUS_INVALID_INFO_CLASS),
            }
        }
        InfoType::FileSystem => {
            // For FS info we use the open's tree's backend for context.
            let creation_time = info_res.as_ref().map(|i| i.creation_time).unwrap_or(0);
            match req.file_information_class {
                ic::FS_VOLUME_INFORMATION => {
                    ic::encode_fs_volume_information(creation_time, 0xCAFE_BABE, "smb-server")
                }
                ic::FS_SIZE_INFORMATION => {
                    // 1 PiB free pseudo-volume, 4 KiB cluster.
                    ic::encode_fs_size_information(
                        1u64 << 40, // total
                        1u64 << 39, // free
                        1,          // sectors per cluster
                        4096,       // bytes per sector
                    )
                }
                ic::FS_DEVICE_INFORMATION => {
                    ic::encode_fs_device_information(FILE_DEVICE_DISK, FILE_REMOTE_DEVICE)
                }
                ic::FS_ATTRIBUTE_INFORMATION => {
                    // `FILE_NAMED_STREAMS` is advertised only when the
                    // backend actually honours `SmbPath::stream_name()` —
                    // claiming it otherwise would make macOS attempt
                    // stream-backed xattr writes against a backend that
                    // silently drops them onto the primary data stream
                    // (docs/SMB_DEFECTS.md S2/S10 in the prosopon consumer).
                    let backend = {
                        let tree = tree_arc.read().await;
                        tree.share.backend.clone()
                    };
                    let mut attrs = FILE_CASE_SENSITIVE_SEARCH
                        | FILE_CASE_PRESERVED_NAMES
                        | FILE_UNICODE_ON_DISK
                        | FILE_PERSISTENT_ACLS
                        | FILE_FILE_COMPRESSION
                        | FILE_SUPPORTS_HARD_LINKS
                        | FILE_SUPPORTS_EXTENDED_ATTRIBUTES;
                    if backend.capabilities().supports_named_streams {
                        attrs |= FILE_NAMED_STREAMS;
                    }
                    ic::encode_fs_attribute_information(attrs, 255, "NTFS")
                }
                ic::FS_FULL_SIZE_INFORMATION => {
                    ic::encode_fs_full_size_information(1u64 << 40, 1u64 << 39, 1u64 << 39, 1, 4096)
                }
                _ => return HandlerResponse::err(ntstatus::STATUS_INVALID_INFO_CLASS),
            }
        }
        InfoType::Security => ic::encode_minimal_security_descriptor(),
        InfoType::Quota => return HandlerResponse::err(ntstatus::STATUS_NOT_SUPPORTED),
    };

    if buf.len() as u32 > req.output_buffer_length {
        return HandlerResponse::err(ntstatus::STATUS_INFO_LENGTH_MISMATCH);
    }

    let resp = QueryInfoResponse {
        structure_size: 9,
        output_buffer_offset: 64 + 8,
        output_buffer_length: buf.len() as u32,
        buffer: buf,
    };
    let mut out = Vec::new();
    resp.write_to(&mut out)
        .expect("QUERY_INFO response encodes");
    let mut response = HandlerResponse::ok(out);
    if buffer_overflow {
        response.status = ntstatus::STATUS_BUFFER_OVERFLOW;
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{OpenIntent, OpenOptions, ShareBackend as _};
    use crate::conn::state::{Connection, Session, TreeConnect};
    use crate::path::SmbPath;
    use crate::proto::auth::ntlm::Identity;
    use crate::proto::header::{HeaderTail, Smb2Header};
    use crate::proto::messages::{CreateRequest, CreateResponse, FileId};
    use crate::server::{ServerConfig, ServerState, ServerUsers, ShareBindings, ShareMode};
    use crate::tests::memfs::MemFsBackend;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use uuid::Uuid;

    fn test_server() -> Arc<ServerState> {
        let cfg = ServerConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            netbios_name: "TEST".to_string(),
            max_read_size: 1024 * 1024,
            max_write_size: 1024 * 1024,
            server_guid: Uuid::nil(),
        };
        let users = ServerUsers {
            table: tokio::sync::RwLock::new(HashMap::new()),
        };
        Arc::new(ServerState::new(cfg, users, vec![]))
    }

    async fn test_conn_with_tree(backend: MemFsBackend) -> (Arc<Connection>, u64, u32) {
        let conn = Arc::new(Connection::new(1, Uuid::nil(), 1024 * 1024, 1024 * 1024));
        let session = Session::new(1, Identity::Anonymous, [0; 16], [0; 16], false, None);
        let session = Arc::new(tokio::sync::RwLock::new(session));
        let share = ShareBindings::new(
            "share".to_string(),
            Arc::new(backend),
            ShareMode::Public,
            HashMap::new(),
            false,
        );
        let tree = Arc::new(tokio::sync::RwLock::new(TreeConnect::new(
            1,
            share,
            crate::builder::Access::ReadWrite,
        )));
        {
            let sess = session.read().await;
            sess.trees.write().await.insert(1, tree);
        }
        conn.sessions.write().await.insert(1, session);
        (conn, 1, 1)
    }

    fn header(
        session_id: u64,
        tree_id: u32,
        message_id: u64,
        command: crate::proto::header::Command,
    ) -> Smb2Header {
        Smb2Header {
            credit_charge: 1,
            channel_sequence_status: 0,
            command,
            credit_request_response: 1,
            flags: 0,
            next_command: 0,
            message_id,
            tail: HeaderTail::sync(tree_id),
            session_id,
            signature: [0u8; 16],
        }
    }

    /// Opens the share root via a real CREATE and returns the `FileId` from
    /// the response — QUERY_INFO needs a live `Open` to attach to.
    async fn open_root(
        server: &Arc<ServerState>,
        conn: &Arc<Connection>,
        session_id: u64,
        tree_id: u32,
    ) -> FileId {
        let req = CreateRequest {
            structure_size: 57,
            security_flags: 0,
            requested_oplock_level: 0,
            impersonation_level: 2,
            smb_create_flags: 0,
            reserved: 0,
            desired_access: 0x0008_0000,
            file_attributes: 0,
            share_access: 0x0000_0007,
            create_disposition: 1,       // FILE_OPEN
            create_options: 0x0000_0001, // FILE_DIRECTORY_FILE
            name_offset: 0x78,
            name_length: 0,
            create_contexts_offset: 0,
            create_contexts_length: 0,
            name: vec![],
            create_contexts: vec![],
        };
        let mut body = Vec::new();
        req.write_to(&mut body).unwrap();
        let hdr = header(
            session_id,
            tree_id,
            1,
            crate::proto::header::Command::Create,
        );
        let resp = crate::handlers::create::handle(server, conn, &hdr, &body).await;
        assert_eq!(
            resp.status,
            ntstatus::STATUS_SUCCESS,
            "setup: open the share root"
        );
        CreateResponse::parse(&resp.body).unwrap().file_id
    }

    fn fs_attribute_query(file_id: FileId) -> Vec<u8> {
        let req = QueryInfoRequest {
            structure_size: 41,
            info_type: InfoType::FileSystem as u8,
            file_information_class: ic::FS_ATTRIBUTE_INFORMATION,
            output_buffer_length: 4096,
            input_buffer_offset: 0,
            reserved: 0,
            input_buffer_length: 0,
            additional_information: 0,
            flags: 0,
            file_id,
            input_buffer: vec![],
        };
        let mut body = Vec::new();
        req.write_to(&mut body).unwrap();
        body
    }

    #[tokio::test]
    async fn fs_attribute_information_advertises_named_streams_when_the_backend_supports_them() {
        let server = test_server();
        let (conn, session_id, tree_id) = test_conn_with_tree(MemFsBackend::new()).await;
        let file_id = open_root(&server, &conn, session_id, tree_id).await;
        let hdr = header(
            session_id,
            tree_id,
            2,
            crate::proto::header::Command::QueryInfo,
        );

        let resp = handle(&server, &conn, &hdr, &fs_attribute_query(file_id)).await;
        assert_eq!(resp.status, ntstatus::STATUS_SUCCESS);

        let qresp = QueryInfoResponse::parse(&resp.body).unwrap();
        let attrs = u32::from_le_bytes(qresp.buffer[0..4].try_into().unwrap());
        assert_ne!(
            attrs & FILE_NAMED_STREAMS,
            0,
            "MemFsBackend implements streams — FILE_NAMED_STREAMS must be advertised"
        );
    }

    // ── QUERY_INFO information type/class and stream enumeration (Step 1e) ──

    struct RecordingSink {
        events: Mutex<Vec<String>>,
    }

    impl crate::trace::TraceSink for RecordingSink {
        fn record(&self, _key: Option<crate::trace::TraceKey>, event: &crate::trace::TraceEvent) {
            self.events.lock().unwrap().push(format!("{event:?}"));
        }
    }

    fn test_server_with_sink(sink: Arc<dyn crate::trace::TraceSink>) -> Arc<ServerState> {
        let mut server = test_server();
        Arc::get_mut(&mut server)
            .expect("test_server hands back a uniquely owned Arc")
            .trace_sink = Some(sink);
        server
    }

    fn open_opts() -> OpenOptions {
        OpenOptions {
            read: true,
            write: true,
            intent: OpenIntent::OpenOrCreate,
            directory: false,
            non_directory: false,
            delete_on_close: false,
            read_data: true,
            write_data: true,
        }
    }

    /// Opens a named file through a real CREATE and returns its `FileId`.
    async fn open_named(
        server: &Arc<ServerState>,
        conn: &Arc<Connection>,
        session_id: u64,
        tree_id: u32,
        name: &str,
    ) -> FileId {
        let name_u16: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let req = CreateRequest {
            structure_size: 57,
            security_flags: 0,
            requested_oplock_level: 0,
            impersonation_level: 2,
            smb_create_flags: 0,
            reserved: 0,
            desired_access: 0x0012_0089,
            file_attributes: 0,
            share_access: 0x0000_0007,
            create_disposition: 1, // FILE_OPEN
            create_options: 0,
            name_offset: 0x78,
            name_length: name_u16.len() as u16,
            create_contexts_offset: 0,
            create_contexts_length: 0,
            name: name_u16,
            create_contexts: vec![],
        };
        let mut body = Vec::new();
        req.write_to(&mut body).unwrap();
        let hdr = header(
            session_id,
            tree_id,
            1,
            crate::proto::header::Command::Create,
        );
        let resp = crate::handlers::create::handle(server, conn, &hdr, &body).await;
        assert_eq!(resp.status, ntstatus::STATUS_SUCCESS, "setup: open {name}");
        CreateResponse::parse(&resp.body).unwrap().file_id
    }

    fn file_query(file_id: FileId, class: u8, output_buffer_length: u32) -> Vec<u8> {
        let req = QueryInfoRequest {
            structure_size: 41,
            info_type: InfoType::File as u8,
            file_information_class: class,
            output_buffer_length,
            input_buffer_offset: 0,
            reserved: 0,
            input_buffer_length: 0,
            additional_information: 0,
            flags: 0,
            file_id,
            input_buffer: vec![],
        };
        let mut body = Vec::new();
        req.write_to(&mut body).unwrap();
        body
    }

    /// Decodes the names of an encoded `FILE_STREAM_INFORMATION` chain.
    fn stream_names(buf: &[u8]) -> Vec<String> {
        let mut names = Vec::new();
        let mut offset = 0usize;
        while offset + 24 <= buf.len() {
            let next = u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap());
            let name_len =
                u32::from_le_bytes(buf[offset + 4..offset + 8].try_into().unwrap()) as usize;
            let units: Vec<u16> = buf[offset + 24..offset + 24 + name_len]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            names.push(String::from_utf16(&units).unwrap());
            if next == 0 {
                break;
            }
            offset += next as usize;
        }
        names
    }

    #[tokio::test]
    async fn query_info_records_its_information_type_and_class() {
        let recorder = Arc::new(RecordingSink {
            events: Mutex::new(Vec::new()),
        });
        let server = test_server_with_sink(recorder.clone());
        let (conn, session_id, tree_id) = test_conn_with_tree(MemFsBackend::new()).await;
        let file_id = open_root(&server, &conn, session_id, tree_id).await;
        let hdr = header(
            session_id,
            tree_id,
            2,
            crate::proto::header::Command::QueryInfo,
        );

        let resp = handle(&server, &conn, &hdr, &fs_attribute_query(file_id)).await;
        assert_eq!(resp.status, ntstatus::STATUS_SUCCESS);

        let events = recorder.events.lock().unwrap();
        assert!(
            events.iter().any(|e| e.contains("QueryInfo")
                && e.contains("info_type: 2")
                && e.contains("info_class: 5")),
            "the QUERY_INFO type and class must be recorded: {events:?}"
        );
    }

    #[tokio::test]
    async fn stream_information_lists_named_streams_through_the_handler() {
        let server = test_server();
        let backend = MemFsBackend::new().with_file("f.txt", b"primary");
        {
            let h = backend
                .open(
                    &"f.txt:AFP_AfpInfo".parse::<SmbPath>().unwrap(),
                    open_opts(),
                )
                .await
                .unwrap();
            h.write(0, b"finder info blob").await.unwrap();
            h.close().await.unwrap();
        }
        let (conn, session_id, tree_id) = test_conn_with_tree(backend).await;
        let file_id = open_named(&server, &conn, session_id, tree_id, "f.txt").await;
        let hdr = header(
            session_id,
            tree_id,
            3,
            crate::proto::header::Command::QueryInfo,
        );

        let resp = handle(
            &server,
            &conn,
            &hdr,
            &file_query(file_id, ic::FILE_STREAM_INFORMATION, 4096),
        )
        .await;
        assert_eq!(resp.status, ntstatus::STATUS_SUCCESS);

        let qresp = QueryInfoResponse::parse(&resp.body).unwrap();
        assert_eq!(
            stream_names(&qresp.buffer),
            vec!["::$DATA", ":AFP_AfpInfo:$DATA"]
        );
    }

    #[tokio::test]
    async fn stream_information_overflow_returns_a_terminated_partial_chain() {
        let server = test_server();
        let backend = MemFsBackend::new().with_file("f.txt", b"primary");
        {
            for (name, data) in [
                ("aaa", b"A".as_slice()),
                ("bbb", b"BB".as_slice()),
                ("ccc", b"CCC".as_slice()),
            ] {
                let h = backend
                    .open(
                        &format!("f.txt:{name}").parse::<SmbPath>().unwrap(),
                        open_opts(),
                    )
                    .await
                    .unwrap();
                h.write(0, data).await.unwrap();
                h.close().await.unwrap();
            }
        }
        let (conn, session_id, tree_id) = test_conn_with_tree(backend).await;
        let file_id = open_named(&server, &conn, session_id, tree_id, "f.txt").await;
        let hdr = header(
            session_id,
            tree_id,
            4,
            crate::proto::header::Command::QueryInfo,
        );

        // The primary entry is 38 bytes; each `:xxx:$DATA` entry is 42 bytes
        // padded to 48. A 96-byte buffer fits the primary and one stream.
        let resp = handle(
            &server,
            &conn,
            &hdr,
            &file_query(file_id, ic::FILE_STREAM_INFORMATION, 96),
        )
        .await;
        assert_eq!(
            resp.status,
            ntstatus::STATUS_BUFFER_OVERFLOW,
            "a truncated stream chain must be reported as BUFFER_OVERFLOW, not rejected"
        );

        let qresp = QueryInfoResponse::parse(&resp.body).unwrap();
        assert!(qresp.output_buffer_length <= 96);
        let names = stream_names(&qresp.buffer);
        assert_eq!(names[0], "::$DATA", "the primary entry must come first");
        assert_eq!(names.len(), 2, "primary plus one whole named entry");
    }

    #[tokio::test]
    async fn stream_information_too_small_for_the_primary_is_length_mismatch() {
        let server = test_server();
        let backend = MemFsBackend::new().with_file("f.txt", b"primary");
        let (conn, session_id, tree_id) = test_conn_with_tree(backend).await;
        let file_id = open_named(&server, &conn, session_id, tree_id, "f.txt").await;
        let hdr = header(
            session_id,
            tree_id,
            5,
            crate::proto::header::Command::QueryInfo,
        );

        let resp = handle(
            &server,
            &conn,
            &hdr,
            &file_query(file_id, ic::FILE_STREAM_INFORMATION, 10),
        )
        .await;
        assert_eq!(resp.status, ntstatus::STATUS_INFO_LENGTH_MISMATCH);
    }
}
