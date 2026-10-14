//! Shared driving helpers for handler-level tests (CREATE / SET_INFO / CLOSE).
//!
//! These build a minimal single-session, single-tree connection over any
//! `ShareBackend` and encode the request bodies those handlers parse, so a
//! test can exercise the handler directly rather than through a socket.

use std::collections::HashMap;
use std::sync::Arc;

use uuid::Uuid;

use crate::backend::ShareBackend;
use crate::builder::Access;
use crate::conn::state::{Connection, Session, TreeConnect};
use crate::proto::auth::ntlm::Identity;
use crate::proto::header::{Command, HeaderTail, Smb2Header};
use crate::proto::messages::create::FileId;
use crate::proto::messages::{CreateRequest, SetInfoRequest};
use crate::server::{ServerConfig, ServerState, ServerUsers, ShareBindings, ShareMode};

pub fn test_server() -> Arc<ServerState> {
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

/// A connection with one anonymous session and one tree bound to `backend`.
/// Returns `(conn, session_id, tree_id)`.
pub async fn test_conn_with_backend<B: ShareBackend + 'static>(
    backend: B,
) -> (Arc<Connection>, u64, u32) {
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

pub fn header(session_id: u64, tree_id: u32, command: Command) -> Smb2Header {
    Smb2Header {
        credit_charge: 1,
        channel_sequence_status: 0,
        command,
        credit_request_response: 1,
        flags: 0,
        next_command: 0,
        message_id: 1,
        tail: HeaderTail::sync(tree_id),
        session_id,
        signature: [0u8; 16],
    }
}

pub fn create_request(
    name: &str,
    create_options: u32,
    create_disposition: u32,
    desired_access: u32,
) -> Vec<u8> {
    let name_u16: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access,
        file_attributes: 0,
        share_access: 0x0000_0007,
        create_disposition,
        create_options,
        name_offset: 0x78,
        name_length: name_u16.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name: name_u16,
        create_contexts: vec![],
    };
    let mut buf = Vec::new();
    req.write_to(&mut buf).unwrap();
    buf
}

/// A SET_INFO carrying `FileDispositionInformation` (class 0x0D): one byte,
/// non-zero requests delete-on-close.
pub fn set_info_disposition(file_id: FileId, delete: bool) -> Vec<u8> {
    let req = SetInfoRequest {
        structure_size: 33,
        info_type: 0x01,
        file_information_class: crate::info_class::FILE_DISPOSITION_INFORMATION,
        buffer_length: 1,
        buffer_offset: 0x60,
        reserved: 0,
        additional_information: 0,
        file_id,
        buffer: vec![u8::from(delete)],
    };
    let mut buf = Vec::new();
    req.write_to(&mut buf).unwrap();
    buf
}

pub fn close_request(file_id: FileId) -> Vec<u8> {
    let req = crate::proto::messages::CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id,
    };
    let mut buf = Vec::new();
    req.write_to(&mut buf).unwrap();
    buf
}

/// The tree bound to `(session_id, tree_id)` on `conn`.
pub async fn tree_of(
    conn: &Arc<Connection>,
    session_id: u64,
    tree_id: u32,
) -> Arc<tokio::sync::RwLock<TreeConnect>> {
    let session = conn
        .sessions
        .read()
        .await
        .get(&session_id)
        .cloned()
        .expect("session exists");
    session
        .read()
        .await
        .trees
        .read()
        .await
        .get(&tree_id)
        .cloned()
        .expect("tree exists")
}

/// The only open registered on `(session_id, tree_id)`, as `(file_id, delete_on_close)`.
pub async fn sole_open(conn: &Arc<Connection>, session_id: u64, tree_id: u32) -> (FileId, bool) {
    let tree = tree_of(conn, session_id, tree_id).await;
    let tree = tree.read().await;
    let opens = tree.opens.read().await;
    assert_eq!(opens.len(), 1, "expected exactly one open");
    let open = opens.values().next().unwrap().read().await;
    (open.file_id, open.delete_on_close)
}

/// Total opens currently registered on `(session_id, tree_id)`.
pub async fn open_count(conn: &Arc<Connection>, session_id: u64, tree_id: u32) -> usize {
    let tree = tree_of(conn, session_id, tree_id).await;
    let tree = tree.read().await;
    tree.opens.read().await.len()
}
