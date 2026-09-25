//! CREATE handler — open or create a file/directory and allocate a FileId.

use std::sync::Arc;

use crate::proto::header::Smb2Header;
use crate::proto::messages::{CreateRequest, CreateResponse};
use tracing::{debug, warn};

use crate::backend::{OpenIntent, OpenOptions};
use crate::builder::Access;
use crate::conn::state::{Connection, Open};
use crate::dispatch::HandlerResponse;
use crate::handlers::shared::lookup_session_tree;
use crate::ntstatus;
use crate::path::SmbPath;
use crate::server::ServerState;
use crate::utils::utf16le_to_units;

// MS-SMB2 §2.2.13 access mask flags
const FILE_READ_DATA: u32 = 0x0000_0001;
const FILE_WRITE_DATA: u32 = 0x0000_0002;
const FILE_APPEND_DATA: u32 = 0x0000_0004;
const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;
const DELETE: u32 = 0x0001_0000;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
const MAX_ALLOWED: u32 = 0x0200_0000;

// CreateOptions
const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
const FILE_DELETE_ON_CLOSE: u32 = 0x0000_1000;

/// What a CREATE's `DesiredAccess` mask says, split into the two levels a
/// backend actually needs.
///
/// `want_read`/`want_write` are the historical *hints*: they are deliberately
/// wide, because they gate tree-level write rejection and the "neither read
/// nor write" fallback. `want_read` is set by a metadata-only open
/// (`FILE_READ_ATTRIBUTES`), and `want_write` by `FILE_WRITE_ATTRIBUTES` or
/// `DELETE` — none of which grant any right to the file's *contents*.
///
/// `read_data`/`write_data` are the narrow facts. A backend that opens a real
/// descriptor must derive it from these: opening a file the caller only
/// wanted to `stat` can fail on permissions, and renaming or retiming a
/// read-only file is legitimate while opening it for writing is not.
///
/// `GENERIC_ALL` and `MAX_ALLOWED` are catch-alls and therefore appear on
/// BOTH data sides — omitting either one would hand a read-only descriptor to
/// a caller entitled to write.
struct AccessFacts {
    want_read: bool,
    want_write: bool,
    read_data: bool,
    write_data: bool,
}

fn access_facts(desired_access: u32) -> AccessFacts {
    AccessFacts {
        want_read: desired_access
            & (FILE_READ_DATA | FILE_READ_ATTRIBUTES | GENERIC_READ | GENERIC_ALL | MAX_ALLOWED)
            != 0,
        want_write: desired_access
            & (FILE_WRITE_DATA
                | FILE_APPEND_DATA
                | FILE_WRITE_ATTRIBUTES
                | DELETE
                | GENERIC_WRITE
                | GENERIC_ALL
                | MAX_ALLOWED)
            != 0,
        read_data: desired_access & (FILE_READ_DATA | GENERIC_READ | GENERIC_ALL | MAX_ALLOWED)
            != 0,
        write_data: desired_access
            & (FILE_WRITE_DATA | FILE_APPEND_DATA | GENERIC_WRITE | GENERIC_ALL | MAX_ALLOWED)
            != 0,
    }
}

// CreateDisposition
const FILE_SUPERSEDE: u32 = 0x0000_0000;
const FILE_OPEN: u32 = 0x0000_0001;
const FILE_CREATE: u32 = 0x0000_0002;
const FILE_OPEN_IF: u32 = 0x0000_0003;
const FILE_OVERWRITE: u32 = 0x0000_0004;
const FILE_OVERWRITE_IF: u32 = 0x0000_0005;

// CreateAction in response (MS-SMB2 §2.2.14)
const FILE_OPENED: u32 = 0x0000_0001;
const FILE_CREATED: u32 = 0x0000_0002;

pub async fn handle(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    body: &[u8],
) -> HandlerResponse {
    let req = match CreateRequest::parse(body) {
        Ok(r) => r,
        Err(_) => return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER),
    };

    let tree_arc = match lookup_session_tree(conn, hdr).await {
        Ok(t) => t,
        Err(s) => return HandlerResponse::err(s),
    };
    let tree = tree_arc.read().await;
    let granted = tree.granted_access;
    let backend = tree.share.backend.clone();
    drop(tree);

    // Decode path.
    let units = match utf16le_to_units(&req.name) {
        Some(u) => u,
        None => return HandlerResponse::err(ntstatus::STATUS_OBJECT_NAME_INVALID),
    };
    let path = match SmbPath::from_utf16(&units) {
        Ok(p) => p,
        Err(_) => return HandlerResponse::err(ntstatus::STATUS_OBJECT_NAME_INVALID),
    };

    // Translate disposition.
    let intent = match req.create_disposition {
        FILE_SUPERSEDE | FILE_OVERWRITE_IF => OpenIntent::OverwriteOrCreate,
        FILE_OPEN => OpenIntent::Open,
        FILE_CREATE => OpenIntent::Create,
        FILE_OPEN_IF => OpenIntent::OpenOrCreate,
        FILE_OVERWRITE => OpenIntent::Truncate,
        _ => return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER),
    };

    // Translate desired access into read/write hints and the narrower
    // data-access facts (see `access_facts`).
    let AccessFacts {
        want_read,
        want_write,
        read_data,
        write_data,
    } = access_facts(req.desired_access);

    // Reject writes on a read-only tree.
    if want_write && !granted.allows_write() {
        warn!(path = %path, "write open on read-only tree");
        return HandlerResponse::err(ntstatus::STATUS_ACCESS_DENIED);
    }
    // Disposition that creates: requires write permission.
    if !granted.allows_write()
        && matches!(
            intent,
            OpenIntent::Create
                | OpenIntent::OpenOrCreate
                | OpenIntent::OverwriteOrCreate
                | OpenIntent::Truncate
        )
    {
        return HandlerResponse::err(ntstatus::STATUS_ACCESS_DENIED);
    }

    let directory = req.create_options & FILE_DIRECTORY_FILE != 0;
    let non_directory = req.create_options & FILE_NON_DIRECTORY_FILE != 0;
    if directory && non_directory {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    // MS-SMB2 §2.2.13: FILE_DIRECTORY_FILE is valid only paired with
    // FILE_CREATE, FILE_OPEN_IF, or FILE_OPEN — never with a disposition
    // that overwrites or truncates. Validated here, in the fork's own
    // handler, before any backend is called; `smb.rs`'s adapter does not
    // duplicate this check (`docs/PLAN_smb_round_two.md` Step 2, Stage 1).
    if directory && matches!(intent, OpenIntent::OverwriteOrCreate | OpenIntent::Truncate) {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    // A named stream selector never names a directory (v1 doesn't support
    // `$INDEX_ALLOCATION`-type streams — `SmbPath` already rejects any type
    // other than `$DATA`).
    if directory && path.stream_name().is_some() {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    let delete_on_close = req.create_options & FILE_DELETE_ON_CLOSE != 0;

    let opts = OpenOptions {
        read: want_read || !want_write,
        write: want_write,
        read_data,
        write_data,
        intent,
        directory,
        non_directory,
        delete_on_close,
    };

    // Parsed once, used both for the trace (if armed) and for any create
    // context we actually respond to (currently: AAPL — see
    // `build_aapl_response_context`). Malformed input degrades to "no
    // contexts seen" rather than failing the CREATE outright.
    let parsed_contexts = crate::proto::messages::CreateContext::parse_chain(&req.create_contexts)
        .unwrap_or_default();
    let path_for_trace = path.display_backslash();
    let record_create_trace = |file_id: Option<[u8; 16]>| {
        if server.trace_sink.is_none() {
            return;
        }
        let contexts = parsed_contexts
            .iter()
            .map(|c| crate::trace::CreateContextInfo {
                name: c.name.clone(),
                data_len: c.data.len() as u32,
            })
            .collect();
        crate::trace::record(
            &server.trace_sink,
            crate::trace::current_trace_key(),
            crate::trace::TraceEvent::Create {
                path: path_for_trace.clone(),
                create_options: req.create_options,
                directory,
                non_directory,
                create_disposition: req.create_disposition,
                desired_access: req.desired_access,
                file_id,
                contexts,
            },
        );
    };

    let handle = match backend.open(&path, opts).await {
        Ok(h) => h,
        Err(e) => {
            debug!(error = %e, path = %path, "backend open failed");
            // Traced regardless of outcome (`docs/SMB_DEFECTS.md` hygiene
            // gap #6 in the prosopon consumer) — a failing CREATE never
            // gets a FileId, so `file_id: None`.
            record_create_trace(None);
            return HandlerResponse::err(e.to_nt_status());
        }
    };

    // Stat for the response.
    let info = match handle.stat().await {
        Ok(i) => i,
        Err(e) => {
            let _ = handle.close().await;
            record_create_trace(None);
            return HandlerResponse::err(e.to_nt_status());
        }
    };

    // Allocate FileId, register Open.
    let tree = tree_arc.write().await;
    let file_id = tree.alloc_file_id();
    let open = Open::new(
        file_id,
        handle,
        if want_write { granted } else { Access::Read },
        path,
        info.is_directory,
        delete_on_close,
    );
    let open_arc = Arc::new(tokio::sync::RwLock::new(open));
    tree.opens.write().await.insert(file_id, open_arc);
    drop(tree);

    record_create_trace(Some(
        [
            file_id.persistent.to_le_bytes(),
            file_id.volatile.to_le_bytes(),
        ]
        .concat()
        .try_into()
        .expect("FileId is 16 bytes"),
    ));

    let aapl_response = parsed_contexts
        .iter()
        .find(|c| c.name == crate::proto::messages::CreateContext::NAME_AAPL)
        .and_then(build_aapl_response_context);
    let (create_contexts_offset, create_contexts_length, create_contexts) = match aapl_response {
        Some(ctx) => {
            let mut bytes = Vec::new();
            crate::proto::messages::CreateContext::encode_chain(&[ctx], &mut bytes)
                .expect("encode AAPL response context");
            // 64-byte SMB2 header + CreateResponse's fixed 88-byte body —
            // the only offset a create-contexts chain can start at, since
            // CreateResponse carries no other variable-length field before it.
            (152u32, bytes.len() as u32, bytes)
        }
        None => (0u32, 0u32, Vec::new()),
    };

    let create_action = match intent {
        OpenIntent::Create => FILE_CREATED,
        OpenIntent::OpenOrCreate | OpenIntent::OverwriteOrCreate => FILE_OPENED,
        OpenIntent::Open | OpenIntent::Truncate => FILE_OPENED,
    };
    let resp = CreateResponse {
        structure_size: 89,
        oplock_level: 0,
        flags: 0,
        create_action,
        creation_time: info.creation_time,
        last_access_time: info.last_access_time,
        last_write_time: info.last_write_time,
        change_time: info.change_time,
        allocation_size: info.allocation_size,
        end_of_file: info.end_of_file,
        file_attributes: info.attributes(),
        reserved2: 0,
        file_id,
        create_contexts_offset,
        create_contexts_length,
        create_contexts,
    };
    let mut buf = Vec::new();
    resp.write_to(&mut buf).expect("encode");
    HandlerResponse::ok(buf)
}

/// `SMB2_CRTCTX_AAPL` "server query" (`docs/SMB_DEFECTS.md` S2/S10
/// investigation, Step 2). Wire format per Apple's Time Machine over SMB
/// spec and Samba's `vfs_fruit.c` `check_aapl()` (cross-checked against
/// each other — see the `parse_chain` fixture tests in
/// `proto/messages/create.rs`). Only `SERVER_CAPS` and `VOLUME_CAPS` are
/// implemented, with the conservative/honest baseline (a UNIX-like server;
/// no case-sensitivity claim, no Time-Machine-fullsync claim).
/// `MODEL_INFO` is not implemented — if requested, that bit is simply
/// absent from the reply bitmap rather than answered.
const AAPL_CMD_SERVER_QUERY: u32 = 1;
const AAPL_REQ_SERVER_CAPS: u64 = 0x1;
const AAPL_REQ_VOLUME_CAPS: u64 = 0x2;
const AAPL_SERVER_CAPS_UNIX_BASED: u64 = 0x4;

fn build_aapl_response_context(
    aapl: &crate::proto::messages::CreateContext,
) -> Option<crate::proto::messages::CreateContext> {
    // MS-SMB2 §2.2.13.2.10 / Apple's spec: the server query payload is
    // always exactly 24 bytes (CommandCode, Reserved, RequestBitmap,
    // ClientCapabilities). A different length or command isn't something
    // this implementation understands; per MS-SMB2 §3.3.5.9.11 unknown or
    // malformed contexts are ignored, not rejected.
    if aapl.data.len() != 24 {
        return None;
    }
    let command_code = u32::from_le_bytes(aapl.data[0..4].try_into().unwrap());
    if command_code != AAPL_CMD_SERVER_QUERY {
        return None;
    }
    let request_bitmap = u64::from_le_bytes(aapl.data[8..16].try_into().unwrap());

    let mut reply_bitmap: u64 = 0;
    let mut data = Vec::new();
    if request_bitmap & AAPL_REQ_SERVER_CAPS != 0 {
        reply_bitmap |= AAPL_REQ_SERVER_CAPS;
        data.extend_from_slice(&AAPL_SERVER_CAPS_UNIX_BASED.to_le_bytes());
    }
    if request_bitmap & AAPL_REQ_VOLUME_CAPS != 0 {
        reply_bitmap |= AAPL_REQ_VOLUME_CAPS;
        data.extend_from_slice(&0u64.to_le_bytes());
    }

    let mut out = Vec::with_capacity(16 + data.len());
    out.extend_from_slice(&AAPL_CMD_SERVER_QUERY.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // Reserved
    out.extend_from_slice(&reply_bitmap.to_le_bytes());
    out.extend_from_slice(&data);

    Some(crate::proto::messages::CreateContext {
        name: crate::proto::messages::CreateContext::NAME_AAPL.to_vec(),
        data: out,
    })
}

// ---------------------------------------------------------------------------
// Stage 1 handler tests (`docs/PLAN_smb_round_two.md` Step 2)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // The data/hint split (`access_facts`). These four combinations are the
    // ones that bite: each has a hint set where the corresponding data fact
    // must not be, or a catch-all that must reach both sides.

    #[test]
    fn metadata_only_open_is_a_read_hint_but_not_a_data_read() {
        let f = access_facts(FILE_READ_ATTRIBUTES);
        assert!(f.want_read, "the hint stays wide");
        assert!(
            !f.read_data,
            "a stat-only open must not make a backend open the file for reading"
        );
        assert!(!f.write_data);
    }

    #[test]
    fn delete_open_is_a_write_hint_but_not_a_data_write() {
        let f = access_facts(DELETE);
        assert!(f.want_write, "the hint stays wide");
        assert!(
            !f.write_data,
            "renaming or deleting is governed by the parent directory, not by write access to the content"
        );
        assert!(!f.read_data);
    }

    #[test]
    fn attribute_write_is_a_write_hint_but_not_a_data_write() {
        let f = access_facts(FILE_WRITE_ATTRIBUTES);
        assert!(f.want_write);
        assert!(!f.write_data, "retiming a read-only file is legitimate");
    }

    #[test]
    fn max_allowed_grants_both_data_sides() {
        let f = access_facts(MAX_ALLOWED);
        assert!(
            f.read_data && f.write_data,
            "a catch-all must reach both sides, or a writable file gets a read-only descriptor"
        );
    }

    #[test]
    fn generic_all_grants_both_data_sides() {
        let f = access_facts(GENERIC_ALL);
        assert!(f.read_data && f.write_data);
    }

    #[test]
    fn data_read_plus_attribute_write_reads_data_but_does_not_write_it() {
        let f = access_facts(FILE_READ_DATA | FILE_WRITE_ATTRIBUTES);
        assert!(f.read_data);
        assert!(!f.write_data);
        assert!(
            f.want_write,
            "the handle may still be asked to set timestamps, which the opener must allow for"
        );
    }

    #[test]
    fn plain_data_access_sets_both_levels() {
        let r = access_facts(FILE_READ_DATA);
        assert!(r.want_read && r.read_data && !r.write_data);
        let w = access_facts(FILE_WRITE_DATA);
        assert!(w.want_write && w.write_data && !w.read_data);
        let a = access_facts(FILE_APPEND_DATA);
        assert!(a.write_data);
    }

    use crate::conn::state::{Session, TreeConnect};
    use crate::proto::auth::ntlm::Identity;
    use crate::proto::header::HeaderTail;
    use crate::server::{ServerConfig, ServerState, ServerUsers, ShareBindings, ShareMode};
    use crate::tests::memfs::MemFsBackend;
    use std::collections::HashMap;
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

    /// A connection with one anonymous session and one tree bound to a
    /// fresh `MemFsBackend`. Returns `(conn, session_id, tree_id)`.
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
            Access::ReadWrite,
        )));
        {
            let sess = session.read().await;
            sess.trees.write().await.insert(1, tree);
        }
        conn.sessions.write().await.insert(1, session);
        (conn, 1, 1)
    }

    fn create_request_bytes(name: &str, create_options: u32, create_disposition: u32) -> Vec<u8> {
        create_request_bytes_with_contexts(name, create_options, create_disposition, vec![])
    }

    fn create_request_bytes_with_contexts(
        name: &str,
        create_options: u32,
        create_disposition: u32,
        create_contexts: Vec<u8>,
    ) -> Vec<u8> {
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
            create_disposition,
            create_options,
            name_offset: 0x78,
            name_length: name_u16.len() as u16,
            create_contexts_offset: if create_contexts.is_empty() { 0 } else { 0x78 },
            create_contexts_length: create_contexts.len() as u32,
            name: name_u16,
            create_contexts,
        };
        let mut buf = Vec::new();
        req.write_to(&mut buf).unwrap();
        buf
    }

    /// A real SMB2_CRTCTX_AAPL "server query" context requesting both
    /// SERVER_CAPS (1) and VOLUME_CAPS (2) — the same shape a macOS client
    /// sends on its first CREATE against a share (see the wire fixture in
    /// `proto/messages/create.rs`'s `parse_chain_decodes_a_real_aapl_server_query_context`).
    fn aapl_server_query_context_bytes(request_bitmap: u64, client_caps: u64) -> Vec<u8> {
        let ctx = crate::proto::messages::CreateContext {
            name: crate::proto::messages::CreateContext::NAME_AAPL.to_vec(),
            data: {
                let mut d = Vec::new();
                d.extend_from_slice(&1u32.to_le_bytes()); // CommandCode = SERVER_QUERY
                d.extend_from_slice(&0u32.to_le_bytes()); // Reserved
                d.extend_from_slice(&request_bitmap.to_le_bytes());
                d.extend_from_slice(&client_caps.to_le_bytes());
                d
            },
        };
        let mut chain = Vec::new();
        crate::proto::messages::CreateContext::encode_chain(&[ctx], &mut chain).unwrap();
        chain
    }

    fn create_header(session_id: u64, tree_id: u32) -> Smb2Header {
        Smb2Header {
            credit_charge: 1,
            channel_sequence_status: 0,
            command: crate::proto::header::Command::Create,
            credit_request_response: 1,
            flags: 0,
            next_command: 0,
            message_id: 1,
            tail: HeaderTail::sync(tree_id),
            session_id,
            signature: [0u8; 16],
        }
    }

    #[tokio::test]
    async fn both_directory_constraint_flags_set_is_invalid_parameter() {
        let server = test_server();
        let (conn, session_id, tree_id) = test_conn_with_tree(MemFsBackend::new()).await;
        let hdr = create_header(session_id, tree_id);
        let body = create_request_bytes(
            "x",
            FILE_DIRECTORY_FILE | FILE_NON_DIRECTORY_FILE,
            FILE_OPEN,
        );

        let resp = handle(&server, &conn, &hdr, &body).await;
        assert_eq!(resp.status, ntstatus::STATUS_INVALID_PARAMETER);
    }

    #[tokio::test]
    async fn directory_flag_with_overwrite_if_disposition_is_invalid_parameter() {
        let server = test_server();
        let (conn, session_id, tree_id) = test_conn_with_tree(MemFsBackend::new()).await;
        let hdr = create_header(session_id, tree_id);
        // FILE_SUPERSEDE (0) and FILE_OVERWRITE_IF (5) both fold to
        // `OpenIntent::OverwriteOrCreate` — both must be rejected paired
        // with FILE_DIRECTORY_FILE.
        for disposition in [FILE_SUPERSEDE, FILE_OVERWRITE_IF] {
            let body = create_request_bytes("x", FILE_DIRECTORY_FILE, disposition);
            let resp = handle(&server, &conn, &hdr, &body).await;
            assert_eq!(
                resp.status,
                ntstatus::STATUS_INVALID_PARAMETER,
                "disposition {disposition:#x}"
            );
        }
    }

    #[tokio::test]
    async fn directory_flag_with_overwrite_disposition_is_invalid_parameter() {
        let server = test_server();
        let (conn, session_id, tree_id) = test_conn_with_tree(MemFsBackend::new()).await;
        let hdr = create_header(session_id, tree_id);
        let body = create_request_bytes("x", FILE_DIRECTORY_FILE, FILE_OVERWRITE);

        let resp = handle(&server, &conn, &hdr, &body).await;
        assert_eq!(resp.status, ntstatus::STATUS_INVALID_PARAMETER);
    }

    #[tokio::test]
    async fn directory_flag_with_creating_dispositions_survives_stage1() {
        let server = test_server();
        let (conn, session_id, tree_id) = test_conn_with_tree(MemFsBackend::new()).await;
        let hdr = create_header(session_id, tree_id);

        // FILE_CREATE, FILE_OPEN_IF are two of the three dispositions
        // Stage 1 permits paired with FILE_DIRECTORY_FILE — each must
        // reach the backend (a fresh MemFsBackend has no "newdir", so both
        // creating dispositions succeed by creating it).
        for (disposition, name) in [
            (FILE_CREATE, "newdir_create"),
            (FILE_OPEN_IF, "newdir_openif"),
        ] {
            let body = create_request_bytes(name, FILE_DIRECTORY_FILE, disposition);
            let resp = handle(&server, &conn, &hdr, &body).await;
            assert_eq!(
                resp.status,
                ntstatus::STATUS_SUCCESS,
                "disposition {disposition:#x} must survive Stage 1 and reach the backend"
            );
        }
    }

    #[tokio::test]
    async fn directory_flag_with_open_disposition_survives_stage1() {
        let server = test_server();
        let (conn, session_id, tree_id) = test_conn_with_tree(MemFsBackend::new()).await;
        let hdr = create_header(session_id, tree_id);

        // FILE_OPEN is the third disposition Stage 1 permits paired with
        // FILE_DIRECTORY_FILE — but FILE_OPEN requires the target to
        // already exist, so create it first (via FILE_CREATE) and only
        // then exercise FILE_OPEN against it.
        let create_body = create_request_bytes("existing_dir", FILE_DIRECTORY_FILE, FILE_CREATE);
        let create_resp = handle(&server, &conn, &hdr, &create_body).await;
        assert_eq!(
            create_resp.status,
            ntstatus::STATUS_SUCCESS,
            "setup: create the directory"
        );

        let open_body = create_request_bytes("existing_dir", FILE_DIRECTORY_FILE, FILE_OPEN);
        let open_resp = handle(&server, &conn, &hdr, &open_body).await;
        assert_eq!(
            open_resp.status,
            ntstatus::STATUS_SUCCESS,
            "FILE_DIRECTORY_FILE + FILE_OPEN must survive Stage 1 and reach the backend"
        );
    }

    // -- Named streams (docs/SMB_DEFECTS.md S2/S10, Step 3) -----------------

    #[tokio::test]
    async fn stream_create_on_an_existing_file_reaches_the_backend() {
        let server = test_server();
        let (conn, session_id, tree_id) = test_conn_with_tree(MemFsBackend::new()).await;
        let hdr = create_header(session_id, tree_id);

        let host_body = create_request_bytes("new.txt", 0, FILE_CREATE);
        let host_resp = handle(&server, &conn, &hdr, &host_body).await;
        assert_eq!(
            host_resp.status,
            ntstatus::STATUS_SUCCESS,
            "setup: create the host file"
        );

        let stream_body = create_request_bytes("new.txt:AFP_AfpInfo", 0, FILE_CREATE);
        let stream_resp = handle(&server, &conn, &hdr, &stream_body).await;
        assert_eq!(
            stream_resp.status,
            ntstatus::STATUS_SUCCESS,
            "a stream CREATE against an existing host file must reach the backend and succeed"
        );
    }

    #[tokio::test]
    async fn stream_create_paired_with_directory_flag_is_invalid_parameter() {
        let server = test_server();
        let (conn, session_id, tree_id) = test_conn_with_tree(MemFsBackend::new()).await;
        let hdr = create_header(session_id, tree_id);

        let host_body = create_request_bytes("new.txt", 0, FILE_CREATE);
        handle(&server, &conn, &hdr, &host_body).await;

        let body = create_request_bytes("new.txt:AFP_AfpInfo", FILE_DIRECTORY_FILE, FILE_CREATE);
        let resp = handle(&server, &conn, &hdr, &body).await;
        assert_eq!(resp.status, ntstatus::STATUS_INVALID_PARAMETER);
    }

    // -- AAPL create context (docs/SMB_DEFECTS.md S2/S10, Step 2) ----------

    #[test]
    fn build_aapl_response_context_answers_both_requested_bitmaps() {
        let req_ctx = crate::proto::messages::CreateContext {
            name: crate::proto::messages::CreateContext::NAME_AAPL.to_vec(),
            data: {
                let mut d = Vec::new();
                d.extend_from_slice(&1u32.to_le_bytes()); // SERVER_QUERY
                d.extend_from_slice(&0u32.to_le_bytes());
                d.extend_from_slice(&0x3u64.to_le_bytes()); // SERVER_CAPS | VOLUME_CAPS
                d.extend_from_slice(&0xfu64.to_le_bytes());
                d
            },
        };

        let resp = build_aapl_response_context(&req_ctx).expect("must answer a well-formed query");
        assert_eq!(resp.name, crate::proto::messages::CreateContext::NAME_AAPL);
        // 16-byte header + 8 bytes SERVER_CAPS + 8 bytes VOLUME_CAPS.
        assert_eq!(resp.data.len(), 32);
        let command_code = u32::from_le_bytes(resp.data[0..4].try_into().unwrap());
        let reply_bitmap = u64::from_le_bytes(resp.data[8..16].try_into().unwrap());
        let server_caps = u64::from_le_bytes(resp.data[16..24].try_into().unwrap());
        let volume_caps = u64::from_le_bytes(resp.data[24..32].try_into().unwrap());
        assert_eq!(command_code, AAPL_CMD_SERVER_QUERY);
        assert_eq!(reply_bitmap, 0x3);
        assert_eq!(server_caps, AAPL_SERVER_CAPS_UNIX_BASED);
        assert_eq!(volume_caps, 0);
    }

    #[test]
    fn build_aapl_response_context_answers_only_the_requested_bitmap() {
        let req_ctx = crate::proto::messages::CreateContext {
            name: crate::proto::messages::CreateContext::NAME_AAPL.to_vec(),
            data: {
                let mut d = Vec::new();
                d.extend_from_slice(&1u32.to_le_bytes());
                d.extend_from_slice(&0u32.to_le_bytes());
                d.extend_from_slice(&AAPL_REQ_SERVER_CAPS.to_le_bytes()); // SERVER_CAPS only
                d.extend_from_slice(&0u64.to_le_bytes());
                d
            },
        };

        let resp = build_aapl_response_context(&req_ctx).expect("must answer a well-formed query");
        // 16-byte header + 8 bytes SERVER_CAPS only — no VOLUME_CAPS bytes.
        assert_eq!(resp.data.len(), 24);
        let reply_bitmap = u64::from_le_bytes(resp.data[8..16].try_into().unwrap());
        assert_eq!(reply_bitmap, AAPL_REQ_SERVER_CAPS);
    }

    #[test]
    fn build_aapl_response_context_ignores_wrong_length_payload() {
        let req_ctx = crate::proto::messages::CreateContext {
            name: crate::proto::messages::CreateContext::NAME_AAPL.to_vec(),
            data: vec![0u8; 16],
        };
        assert!(build_aapl_response_context(&req_ctx).is_none());
    }

    #[test]
    fn build_aapl_response_context_ignores_unknown_command_code() {
        let req_ctx = crate::proto::messages::CreateContext {
            name: crate::proto::messages::CreateContext::NAME_AAPL.to_vec(),
            data: {
                let mut d = Vec::new();
                d.extend_from_slice(&2u32.to_le_bytes()); // RESOLVE_ID, not SERVER_QUERY
                d.extend_from_slice(&0u32.to_le_bytes());
                d.extend_from_slice(&0x3u64.to_le_bytes());
                d.extend_from_slice(&0u64.to_le_bytes());
                d
            },
        };
        assert!(build_aapl_response_context(&req_ctx).is_none());
    }

    #[tokio::test]
    async fn create_response_carries_an_aapl_context_when_the_client_sends_one() {
        let server = test_server();
        let (conn, session_id, tree_id) = test_conn_with_tree(MemFsBackend::new()).await;
        let hdr = create_header(session_id, tree_id);
        let contexts = aapl_server_query_context_bytes(0x3, 0xf);
        let body = create_request_bytes_with_contexts("aapl_probe", 0, FILE_CREATE, contexts);

        let resp = handle(&server, &conn, &hdr, &body).await;
        assert_eq!(resp.status, ntstatus::STATUS_SUCCESS);

        let create_resp = CreateResponse::parse(&resp.body).expect("a well-formed CreateResponse");
        assert_eq!(
            create_resp.create_contexts_offset, 152,
            "64-byte SMB2 header + 88-byte fixed CreateResponse body"
        );
        assert_eq!(
            create_resp.create_contexts_length as usize,
            create_resp.create_contexts.len()
        );
        let decoded =
            crate::proto::messages::CreateContext::parse_chain(&create_resp.create_contexts)
                .expect("response chain must parse");
        assert_eq!(decoded.len(), 1);
        assert_eq!(
            decoded[0].name,
            crate::proto::messages::CreateContext::NAME_AAPL
        );
    }

    #[tokio::test]
    async fn create_response_has_no_contexts_when_the_client_sends_none() {
        let server = test_server();
        let (conn, session_id, tree_id) = test_conn_with_tree(MemFsBackend::new()).await;
        let hdr = create_header(session_id, tree_id);
        let body = create_request_bytes("no_probe", 0, FILE_CREATE);

        let resp = handle(&server, &conn, &hdr, &body).await;
        assert_eq!(resp.status, ntstatus::STATUS_SUCCESS);

        let create_resp = CreateResponse::parse(&resp.body).expect("a well-formed CreateResponse");
        assert_eq!(create_resp.create_contexts_offset, 0);
        assert_eq!(create_resp.create_contexts_length, 0);
        assert!(create_resp.create_contexts.is_empty());
    }

    // -- Trace hygiene: CREATE is traced on failure too (docs/SMB_DEFECTS.md
    // -- hygiene gap #6 / S9 investigation) -----------------------------------

    struct CaptureSink {
        events: std::sync::Mutex<Vec<crate::trace::TraceEvent>>,
    }

    impl crate::trace::TraceSink for CaptureSink {
        fn record(&self, _key: Option<crate::trace::TraceKey>, event: &crate::trace::TraceEvent) {
            self.events.lock().unwrap().push(event.clone());
        }
    }

    fn test_server_with_sink() -> (Arc<ServerState>, Arc<CaptureSink>) {
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
        let sink = Arc::new(CaptureSink {
            events: std::sync::Mutex::new(Vec::new()),
        });
        let mut server = ServerState::new(cfg, users, vec![]);
        server.trace_sink = Some(sink.clone() as Arc<dyn crate::trace::TraceSink>);
        (Arc::new(server), sink)
    }

    #[tokio::test]
    async fn create_is_traced_with_no_file_id_when_the_backend_rejects_it() {
        let (server, sink) = test_server_with_sink();
        let (conn, session_id, tree_id) = test_conn_with_tree(MemFsBackend::new()).await;
        let hdr = create_header(session_id, tree_id);

        // FILE_OPEN against a path that doesn't exist — backend.open()
        // returns NotFound, never reaching FileId allocation.
        let body = create_request_bytes("ghost.txt", 0, FILE_OPEN);
        let resp = handle(&server, &conn, &hdr, &body).await;
        assert_eq!(resp.status, ntstatus::STATUS_OBJECT_NAME_NOT_FOUND);

        let events = sink.events.lock().unwrap();
        let create_event = events
            .iter()
            .find(|e| matches!(e, crate::trace::TraceEvent::Create { .. }))
            .expect("a failing CREATE must still be traced");
        match create_event {
            crate::trace::TraceEvent::Create {
                path,
                create_disposition,
                file_id,
                ..
            } => {
                assert_eq!(path, "ghost.txt");
                assert_eq!(*create_disposition, FILE_OPEN);
                assert_eq!(
                    *file_id, None,
                    "a CREATE that never opened anything gets no FileId"
                );
            }
            _ => unreachable!(),
        }
    }

    #[tokio::test]
    async fn create_is_traced_with_a_file_id_on_success() {
        let (server, sink) = test_server_with_sink();
        let (conn, session_id, tree_id) = test_conn_with_tree(MemFsBackend::new()).await;
        let hdr = create_header(session_id, tree_id);

        let body = create_request_bytes("new.txt", 0, FILE_CREATE);
        let resp = handle(&server, &conn, &hdr, &body).await;
        assert_eq!(resp.status, ntstatus::STATUS_SUCCESS);

        let events = sink.events.lock().unwrap();
        let create_event = events
            .iter()
            .find(|e| matches!(e, crate::trace::TraceEvent::Create { .. }))
            .expect("a successful CREATE must be traced");
        match create_event {
            crate::trace::TraceEvent::Create { file_id, .. } => {
                assert!(file_id.is_some(), "a successful CREATE gets a real FileId");
            }
            _ => unreachable!(),
        }
    }
}
