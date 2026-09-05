//! SET_INFO / FILE_ALLOCATION_INFORMATION (0x13) regression coverage.
//!
//! Windows truncates over SMB by *shrinking the allocation*: .NET's
//! `FileStream.SetLength(0)` and PowerShell's `Set-Content`/`Clear-Content`
//! emit `SET_INFO info_class=0x13` and never follow up with
//! `FILE_END_OF_FILE_INFORMATION` (0x14). A server that answers
//! STATUS_SUCCESS without truncating leaves the client believing the file is
//! empty; it then reopens with `FILE_APPEND_DATA` and writes at the stale
//! end-of-file, so the "overwrite" silently becomes an append.
//!
//! These tests drive the real command router, not the handler in isolation.

use std::sync::Arc;

use super::memfs::MemFsBackend;
use crate::backend::{OpenIntent, OpenOptions};
use crate::conn::state::{Connection, Open, Session, TreeConnect};
use crate::info_class as ic;
use crate::ntstatus;
use crate::path::SmbPath;
use crate::proto::header::{Command, HeaderTail, Smb2Header};
use crate::proto::messages::{FileId, SetInfoRequest};
use crate::{Access, Identity, Share, SmbServer};

const SEED: &[u8] = b"seed content"; // 12 bytes, as in the reported repro.

fn smb_path(s: &str) -> SmbPath {
    s.parse().expect("path")
}

fn server_with_seed() -> SmbServer {
    SmbServer::builder()
        .listen("127.0.0.1:0".parse().unwrap())
        .user("alice", "password")
        .share(
            Share::new("home", MemFsBackend::new().with_file("seed.txt", SEED))
                .user("alice", Access::ReadWrite),
        )
        .build()
        .expect("build")
}

/// Register a session + tree and a single write-access open on `seed.txt`,
/// mirroring what CREATE would have left behind.
async fn session_with_open(server: &SmbServer, file_id: FileId) -> Arc<Connection> {
    let state = server.state();
    let conn_id = state.active_connections.alloc_id();
    let conn = Arc::new(Connection::new(
        conn_id,
        state.config.server_guid,
        state.config.max_read_size,
        state.config.max_write_size,
    ));
    state.active_connections.insert(conn_id, &conn).await;

    let share = state.find_share("home").await.expect("share");
    let path = smb_path("seed.txt");
    let handle = share
        .backend
        .open(
            &path,
            OpenOptions {
                read: true,
                write: true,
                intent: OpenIntent::Open,
                ..OpenOptions::default()
            },
        )
        .await
        .expect("open seed.txt");

    let tree = TreeConnect::new(1, share, Access::ReadWrite);
    tree.opens.write().await.insert(
        file_id,
        Arc::new(tokio::sync::RwLock::new(Open::new(
            file_id,
            handle,
            Access::ReadWrite,
            path,
            false,
            false,
        ))),
    );

    let session = Session::new(
        1,
        Identity::User {
            user: "alice".to_string(),
            domain: String::new(),
        },
        [0; 16],
        [0; 16],
        false,
        None,
    );
    let session = Arc::new(tokio::sync::RwLock::new(session));
    {
        let sess = session.read().await;
        sess.trees
            .write()
            .await
            .insert(1, Arc::new(tokio::sync::RwLock::new(tree)));
    }
    conn.sessions.write().await.insert(1, session);
    conn
}

/// Send `SET_INFO` with the given file information class and buffer through
/// the command router; returns the response NTSTATUS.
async fn set_info(
    server: &SmbServer,
    conn: &Arc<Connection>,
    file_id: FileId,
    class: u8,
    buffer: Vec<u8>,
) -> u32 {
    let req = SetInfoRequest {
        structure_size: 33,
        info_type: 0x01, // InfoType::File
        file_information_class: class,
        buffer_length: buffer.len() as u32,
        buffer_offset: 0x60,
        reserved: 0,
        additional_information: 0,
        file_id,
        buffer,
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("encode set_info");

    let hdr = Smb2Header {
        credit_charge: 1,
        channel_sequence_status: 0,
        command: Command::SetInfo,
        credit_request_response: 64,
        flags: 0,
        next_command: 0,
        message_id: 4,
        tail: HeaderTail::sync(1),
        session_id: 1,
        signature: [0u8; 16],
    };
    crate::handlers::dispatch_command(&server.state(), conn, &hdr, &body)
        .await
        .status
}

/// Read `seed.txt` back through a *fresh* backend handle — what the next
/// client CREATE would see, and what ends up on disk.
async fn contents(server: &SmbServer) -> Vec<u8> {
    let share = server.state().find_share("home").await.expect("share");
    let handle = share
        .backend
        .open(&smb_path("seed.txt"), OpenOptions::default())
        .await
        .expect("reopen seed.txt");
    let len = handle.stat().await.expect("stat").end_of_file;
    handle
        .read(0, len as u32)
        .await
        .expect("read back")
        .to_vec()
}

/// The reported corruption: allocation dropped to 0 must truncate, not just
/// return STATUS_SUCCESS.
#[tokio::test]
async fn shrinking_allocation_to_zero_truncates_the_file() {
    let server = server_with_seed();
    let file_id = FileId::new(1, 1);
    let conn = session_with_open(&server, file_id).await;

    let status = set_info(
        &server,
        &conn,
        file_id,
        ic::FILE_ALLOCATION_INFORMATION,
        0u64.to_le_bytes().to_vec(),
    )
    .await;

    assert_eq!(status, ntstatus::STATUS_SUCCESS);
    assert!(
        contents(&server).await.is_empty(),
        "allocation 0 must leave the file empty; a client that then appends \
         at the stale end-of-file would silently corrupt the file"
    );
}

/// A partial shrink moves EndOfFile down to exactly the requested allocation.
#[tokio::test]
async fn shrinking_allocation_below_end_of_file_truncates_to_it() {
    let server = server_with_seed();
    let file_id = FileId::new(1, 1);
    let conn = session_with_open(&server, file_id).await;

    let status = set_info(
        &server,
        &conn,
        file_id,
        ic::FILE_ALLOCATION_INFORMATION,
        4u64.to_le_bytes().to_vec(),
    )
    .await;

    assert_eq!(status, ntstatus::STATUS_SUCCESS);
    assert_eq!(contents(&server).await, b"seed");
}

/// Growing (or matching) the allocation stays a no-op: we don't preallocate,
/// and the existing bytes must survive untouched.
#[tokio::test]
async fn growing_allocation_is_a_successful_no_op() {
    for allocation in [SEED.len() as u64, 4096, u64::MAX] {
        let server = server_with_seed();
        let file_id = FileId::new(1, 1);
        let conn = session_with_open(&server, file_id).await;

        let status = set_info(
            &server,
            &conn,
            file_id,
            ic::FILE_ALLOCATION_INFORMATION,
            allocation.to_le_bytes().to_vec(),
        )
        .await;

        assert_eq!(status, ntstatus::STATUS_SUCCESS, "allocation {allocation}");
        assert_eq!(
            contents(&server).await,
            SEED,
            "allocation {allocation} must not preallocate or truncate"
        );
    }
}

/// A short buffer is a malformed request, not a silent success.
#[tokio::test]
async fn allocation_buffer_shorter_than_eight_bytes_is_a_length_mismatch() {
    let server = server_with_seed();
    let file_id = FileId::new(1, 1);
    let conn = session_with_open(&server, file_id).await;

    let status = set_info(
        &server,
        &conn,
        file_id,
        ic::FILE_ALLOCATION_INFORMATION,
        vec![0u8; 4],
    )
    .await;

    assert_eq!(status, ntstatus::STATUS_INFO_LENGTH_MISMATCH);
    assert_eq!(contents(&server).await, SEED);
}

/// The 0x14 path macOS smbfs uses is untouched by the 0x13 fix.
#[tokio::test]
async fn end_of_file_information_still_truncates() {
    let server = server_with_seed();
    let file_id = FileId::new(1, 1);
    let conn = session_with_open(&server, file_id).await;

    let status = set_info(
        &server,
        &conn,
        file_id,
        ic::FILE_END_OF_FILE_INFORMATION,
        0u64.to_le_bytes().to_vec(),
    )
    .await;

    assert_eq!(status, ntstatus::STATUS_SUCCESS);
    assert!(contents(&server).await.is_empty());
}
