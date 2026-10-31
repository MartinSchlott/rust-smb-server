//! Byte-range locks through the real dispatcher, the connection lifecycle and
//! the async completion path.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{RwLock, mpsc};
use uuid::Uuid;

use crate::backend::{
    BackendCapabilities, DirEntry, FileInfo, FileTimes, Handle, OpenOptions, ShareBackend,
};
use crate::builder::Access;
use crate::conn::state::{Connection, Open, Pending, Session, TreeConnect};
use crate::dispatch::{
    AsyncWait, FrameOutcome, HandlerResponse, Held, WaitOutcome, dispatch_frame,
};
use crate::error::SmbResult;
use crate::incident::{Incident, IncidentSink};
use crate::lock::{LockOwner, Range};
use crate::ntstatus;
use crate::path::SmbPath;
use crate::proto::auth::ntlm::Identity;
use crate::proto::framing::{FRAME_HEADER_LEN, decode_frame_header};
use crate::proto::header::{
    Command, HeaderTail, SMB2_FLAGS_ASYNC_COMMAND, SMB2_HEADER_LEN, Smb2Header,
};
use crate::proto::messages::{
    CreateResponse, EchoRequest, FileId, LockElement, LockRequest, TreeDisconnectRequest,
};
use crate::server::{ServerConfig, ServerState, ServerUsers, ShareBindings, ShareMode, SmbServer};
use crate::tests::handler_support::{close_request, create_request};
use crate::tests::memfs::MemFsBackend;

const EX: u32 = LockElement::FLAG_EXCLUSIVE_LOCK;
const SH: u32 = LockElement::FLAG_SHARED_LOCK;
const NOW: u32 = LockElement::FLAG_FAIL_IMMEDIATELY;
const UNLOCK: u32 = LockElement::FLAG_UNLOCK;

// ── frames ─────────────────────────────────────────────────────────────────

fn header(session_id: u64, tree_id: u32, command: Command) -> Smb2Header {
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

fn frame_payload(hdr: &Smb2Header, body: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    hdr.write(&mut payload).expect("encode header");
    payload.extend_from_slice(body);
    payload
}

fn lock_body(file_id: FileId, offset: u64, length: u64, flags: u32) -> Vec<u8> {
    lock_body_multi(file_id, &[(offset, length, flags)])
}

fn lock_body_multi(file_id: FileId, locks: &[(u64, u64, u32)]) -> Vec<u8> {
    let req = LockRequest {
        structure_size: 48,
        lock_count: locks.len() as u16,
        lock_sequence: 0,
        file_id,
        locks: locks
            .iter()
            .map(|&(offset, length, flags)| LockElement {
                offset,
                length,
                flags,
                reserved: 0,
            })
            .collect(),
    };
    let mut buf = Vec::new();
    req.write_to(&mut buf).unwrap();
    buf
}

fn response(outcome: FrameOutcome) -> (Smb2Header, Vec<u8>) {
    match outcome {
        FrameOutcome::Response(bytes) => {
            let (hdr, body) = Smb2Header::parse(&bytes).expect("parse response");
            (hdr, body.to_vec())
        }
        other => panic!(
            "expected a response, got {}",
            match other {
                FrameOutcome::NoResponse => "none",
                FrameOutcome::Malformed { .. } => "a malformed frame",
                FrameOutcome::Response(_) => unreachable!(),
            }
        ),
    }
}

fn status_of(outcome: FrameOutcome) -> u32 {
    response(outcome).0.channel_sequence_status
}

// ── server / server-side connection setup ──────────────────────────────────

fn server_config() -> ServerConfig {
    ServerConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        netbios_name: "TEST".to_owned(),
        max_read_size: 1 << 20,
        max_write_size: 1 << 20,
        server_guid: Uuid::nil(),
    }
}

fn make_server(
    share: Arc<ShareBindings>,
    deadline: Duration,
    incident_sink: Option<Arc<dyn IncidentSink>>,
) -> SmbServer {
    let users = ServerUsers {
        table: RwLock::new(HashMap::new()),
    };
    let mut state = ServerState::new(server_config(), users, vec![share]);
    state.dispatch_deadline = deadline;
    state.incident_sink = incident_sink;
    SmbServer::from_state(state)
}

fn make_share(backend: Arc<dyn ShareBackend>) -> Arc<ShareBindings> {
    ShareBindings::new(
        "share".to_owned(),
        backend,
        ShareMode::Public,
        HashMap::new(),
        false,
    )
}

/// A fabricated session/tree with a pre-seeded open per `names` entry.
async fn seeded_connection(
    server: &Arc<ServerState>,
    share: &Arc<ShareBindings>,
    backend: &Arc<dyn ShareBackend>,
    names: &[&str],
) -> (Arc<Connection>, u64, u32, Vec<FileId>, Vec<u64>) {
    let conn_id = server.active_connections.alloc_id();
    let conn = Arc::new(Connection::new(
        conn_id,
        server.config.server_guid,
        server.config.max_read_size,
        server.config.max_write_size,
    ));
    server.active_connections.insert(conn_id, &conn).await;

    let session_id = 1;
    let tree_id = 1;
    let session = Session::new(
        session_id,
        Identity::Anonymous,
        [0; 16],
        [0; 16],
        false,
        None,
    );
    let tree = TreeConnect::new(tree_id, share.clone(), Access::ReadWrite);
    let mut file_ids = Vec::new();
    let mut owner_ids = Vec::new();
    for name in names {
        let path: SmbPath = (*name).parse().expect("path");
        let handle = backend
            .open(&path, OpenOptions::default())
            .await
            .expect("seed open");
        let file_id = tree.alloc_file_id();
        let open = Open::new(file_id, handle, Access::ReadWrite, path, false, false);
        owner_ids.push(open.lock_owner.id());
        tree.opens
            .write()
            .await
            .insert(file_id, Arc::new(RwLock::new(open)));
        file_ids.push(file_id);
    }
    let session = Arc::new(RwLock::new(session));
    session
        .read()
        .await
        .trees
        .write()
        .await
        .insert(tree_id, Arc::new(RwLock::new(tree)));
    conn.sessions.write().await.insert(session_id, session);
    (conn, session_id, tree_id, file_ids, owner_ids)
}

async fn owner_of(conn: &Arc<Connection>, session_id: u64, tree_id: u32, file_id: FileId) -> u64 {
    let session = conn
        .sessions
        .read()
        .await
        .get(&session_id)
        .cloned()
        .expect("session");
    let tree = session
        .read()
        .await
        .trees
        .read()
        .await
        .get(&tree_id)
        .cloned()
        .expect("tree");
    let open = tree
        .read()
        .await
        .opens
        .read()
        .await
        .get(&file_id)
        .cloned()
        .expect("open");
    open.read().await.lock_owner.id()
}

// ── dispatcher rig ─────────────────────────────────────────────────────────

struct Rig {
    smb: SmbServer,
    server: Arc<ServerState>,
    conn: Arc<Connection>,
    share: Arc<ShareBindings>,
    session_id: u64,
    tree_id: u32,
    frames: mpsc::Receiver<Vec<u8>>,
    next_mid: u64,
}

impl Rig {
    async fn new(backend: MemFsBackend) -> Self {
        Self::with(Arc::new(backend), Duration::from_secs(60), None).await
    }

    async fn with(
        backend: Arc<dyn ShareBackend>,
        deadline: Duration,
        sink: Option<Arc<dyn IncidentSink>>,
    ) -> Self {
        let share = make_share(backend.clone());
        let smb = make_server(share.clone(), deadline, sink);
        let server = smb.state();
        let (conn, session_id, tree_id, _, _) =
            seeded_connection(&server, &share, &backend, &[]).await;
        let (tx, frames) = mpsc::channel(64);
        *conn.writer.lock().unwrap_or_else(|e| e.into_inner()) = Some(tx);
        Self {
            smb,
            server,
            conn,
            share,
            session_id,
            tree_id,
            frames,
            next_mid: 1,
        }
    }

    async fn call(&mut self, command: Command, body: Vec<u8>) -> (Smb2Header, FrameOutcome) {
        let mut hdr = header(self.session_id, self.tree_id, command);
        hdr.message_id = self.next_mid;
        self.next_mid += 1;
        let frame = frame_payload(&hdr, &body);
        let outcome = dispatch_frame(&self.server, &self.conn, &frame).await;
        (hdr, outcome)
    }

    async fn call_async_hdr(
        &mut self,
        hdr: Smb2Header,
        body: Vec<u8>,
    ) -> (Smb2Header, FrameOutcome) {
        let frame = frame_payload(&hdr, &body);
        let outcome = dispatch_frame(&self.server, &self.conn, &frame).await;
        (hdr, outcome)
    }

    async fn open(&mut self, name: &str) -> FileId {
        let (_, outcome) = self
            .call(Command::Create, create_request(name, 0x40, 1, 0x0012_019F))
            .await;
        let (hdr, body) = response(outcome);
        assert_eq!(
            hdr.channel_sequence_status,
            ntstatus::STATUS_SUCCESS,
            "open {name}"
        );
        CreateResponse::parse(&body)
            .expect("create response")
            .file_id
    }

    async fn lock(&mut self, file_id: FileId, offset: u64, length: u64, flags: u32) -> u32 {
        let (_, outcome) = self
            .call(Command::Lock, lock_body(file_id, offset, length, flags))
            .await;
        status_of(outcome)
    }

    async fn next_frame(&mut self) -> (Smb2Header, Vec<u8>) {
        let frame = tokio::time::timeout(Duration::from_secs(2), self.frames.recv())
            .await
            .expect("a frame")
            .expect("writer open");
        {
            let (hdr, body) = Smb2Header::parse(&frame).expect("parse frame");
            (hdr, body.to_vec())
        }
    }

    async fn no_frame(&mut self) {
        match tokio::time::timeout(Duration::from_millis(50), self.frames.recv()).await {
            Err(_) => {}
            Ok(Some(_)) => panic!("unexpected frame"),
            Ok(None) => panic!("writer channel closed"),
        }
    }

    async fn owner_of(&self, file_id: FileId) -> u64 {
        owner_of(&self.conn, self.session_id, self.tree_id, file_id).await
    }

    async fn close(&mut self, file_id: FileId) -> u32 {
        let (_, outcome) = self.call(Command::Close, close_request(file_id)).await;
        status_of(outcome)
    }
}

// ── basics ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn conflicts_follow_windows_rules_and_unlock_matches_exactly() {
    let mut rig = Rig::new(MemFsBackend::new().with_file("db", b"0123456789")).await;
    let a = rig.open("db").await;
    let b = rig.open("db").await;

    assert_eq!(rig.lock(a, 4, 2, EX | NOW).await, ntstatus::STATUS_SUCCESS);
    assert_eq!(
        rig.lock(b, 5, 1, EX | NOW).await,
        ntstatus::STATUS_LOCK_NOT_GRANTED
    );
    assert_eq!(
        rig.lock(b, 5, 1, SH | NOW).await,
        ntstatus::STATUS_LOCK_NOT_GRANTED
    );
    // An exclusive range conflicts with the owner's own lock.
    assert_eq!(
        rig.lock(a, 5, 1, EX | NOW).await,
        ntstatus::STATUS_LOCK_NOT_GRANTED
    );
    // A shared range under one's own exclusive one is allowed.
    assert_eq!(rig.lock(a, 5, 1, SH | NOW).await, ntstatus::STATUS_SUCCESS);

    assert_eq!(
        rig.lock(a, 4, 1, UNLOCK).await,
        ntstatus::STATUS_RANGE_NOT_LOCKED
    );
    assert_eq!(
        rig.lock(a, 0, 1, EX | UNLOCK).await,
        ntstatus::STATUS_INVALID_PARAMETER
    );

    // A multi-element set must be all-or-nothing and all FAIL_IMMEDIATELY.
    let (_, outcome) = rig
        .call(
            Command::Lock,
            lock_body_multi(b, &[(0, 1, EX | NOW), (4, 2, EX | NOW)]),
        )
        .await;
    assert_eq!(status_of(outcome), ntstatus::STATUS_LOCK_NOT_GRANTED);
    let (_, outcome) = rig
        .call(Command::Lock, lock_body_multi(b, &[(0, 1, EX), (4, 2, EX)]))
        .await;
    assert_eq!(status_of(outcome), ntstatus::STATUS_INVALID_PARAMETER);

    // Exact unlock frees the range for another open.
    assert_eq!(rig.lock(a, 5, 1, UNLOCK).await, ntstatus::STATUS_SUCCESS);
    assert_eq!(rig.lock(a, 4, 2, UNLOCK).await, ntstatus::STATUS_SUCCESS);
    assert_eq!(rig.lock(b, 4, 2, EX | NOW).await, ntstatus::STATUS_SUCCESS);
}

#[tokio::test]
async fn a_blocking_lock_gets_pending_then_its_final_on_release() {
    let mut rig = Rig::new(MemFsBackend::new().with_file("db", b"0123456789")).await;
    let a = rig.open("db").await;
    let b = rig.open("db").await;

    assert_eq!(rig.lock(a, 4, 2, EX | NOW).await, ntstatus::STATUS_SUCCESS);

    let (lock_hdr, outcome) = rig.call(Command::Lock, lock_body(b, 5, 1, EX)).await;
    assert!(matches!(outcome, FrameOutcome::NoResponse));

    let (interim, _) = rig.next_frame().await;
    assert_ne!(interim.flags & SMB2_FLAGS_ASYNC_COMMAND, 0);
    assert_eq!(
        (
            interim.channel_sequence_status,
            interim.credit_request_response
        ),
        (ntstatus::STATUS_PENDING, lock_hdr.credit_request_response)
    );
    let async_id = interim.async_id().expect("async id");

    assert_eq!(rig.lock(a, 4, 2, UNLOCK).await, ntstatus::STATUS_SUCCESS);

    let (final_hdr, _) = rig.next_frame().await;
    assert_eq!(
        (
            final_hdr.channel_sequence_status,
            final_hdr.async_id(),
            final_hdr.credit_request_response
        ),
        (ntstatus::STATUS_SUCCESS, Some(async_id), 0)
    );
    rig.no_frame().await;
}

#[tokio::test]
async fn cancel_by_async_id_and_by_message_id_finishes_the_waiter() {
    let mut rig = Rig::new(MemFsBackend::new().with_file("db", b"0123456789")).await;
    let a = rig.open("db").await;
    let b = rig.open("db").await;
    assert_eq!(rig.lock(a, 0, 10, EX | NOW).await, ntstatus::STATUS_SUCCESS);

    // By AsyncId: the CANCEL carries the async-form header.
    let (_, outcome) = rig.call(Command::Lock, lock_body(b, 5, 1, EX)).await;
    assert!(matches!(outcome, FrameOutcome::NoResponse));
    let (interim, _) = rig.next_frame().await;
    let async_id = interim.async_id().expect("async id");

    let mut cancel = header(rig.session_id, rig.tree_id, Command::Cancel);
    cancel.flags |= SMB2_FLAGS_ASYNC_COMMAND;
    cancel.tail = HeaderTail::async_(async_id);
    cancel.message_id = rig.next_mid;
    rig.next_mid += 1;
    let (_, outcome) = rig.call_async_hdr(cancel, Vec::new()).await;
    assert!(
        matches!(outcome, FrameOutcome::NoResponse),
        "CANCEL is unanswered"
    );
    let (final_hdr, _) = rig.next_frame().await;
    assert_eq!(
        (final_hdr.channel_sequence_status, final_hdr.async_id()),
        (ntstatus::STATUS_CANCELLED, Some(async_id))
    );

    // By MessageId: a sync CANCEL naming the waiting request's message.
    let (lock_hdr, outcome) = rig.call(Command::Lock, lock_body(b, 5, 1, EX)).await;
    assert!(matches!(outcome, FrameOutcome::NoResponse));
    let (interim, _) = rig.next_frame().await;
    let async_id = interim.async_id().expect("async id");
    let cancel = header(rig.session_id, rig.tree_id, Command::Cancel);
    let mut cancel = cancel;
    cancel.message_id = lock_hdr.message_id;
    let (_, outcome) = rig.call_async_hdr(cancel, Vec::new()).await;
    assert!(matches!(outcome, FrameOutcome::NoResponse));
    let (final_hdr, _) = rig.next_frame().await;
    assert_eq!(
        (final_hdr.channel_sequence_status, final_hdr.async_id()),
        (ntstatus::STATUS_CANCELLED, Some(async_id))
    );
}

// ── release through every lifecycle exit ───────────────────────────────────

async fn start_waiter(rig: &mut Rig) -> (FileId, FileId, u64) {
    let a = rig.open("db").await;
    let b = rig.open("db").await;
    assert_eq!(
        rig.lock(a, 0, u64::MAX, EX | NOW).await,
        ntstatus::STATUS_SUCCESS
    );
    let (_, outcome) = rig.call(Command::Lock, lock_body(b, 5, 1, EX)).await;
    assert!(matches!(outcome, FrameOutcome::NoResponse));
    let (interim, _) = rig.next_frame().await;
    let async_id = interim.async_id().expect("async id");
    (a, b, async_id)
}

async fn assert_released(rig: &mut Rig, async_id: u64) {
    let (final_hdr, _) = rig.next_frame().await;
    assert_eq!(
        (final_hdr.channel_sequence_status, final_hdr.async_id()),
        (ntstatus::STATUS_RANGE_NOT_LOCKED, Some(async_id))
    );
    let fresh = LockOwner::new();
    assert!(
        rig.share
            .locks
            .try_lock("db", &fresh, &[Range::new(0, u64::MAX, true).unwrap()])
            .is_ok(),
        "the closed opens released their ranges"
    );
}

#[tokio::test]
async fn close_releases_a_waiting_open() {
    let mut rig = Rig::new(MemFsBackend::new().with_file("db", b"0123456789")).await;
    let (a, b, async_id) = start_waiter(&mut rig).await;
    assert_eq!(rig.close(b).await, ntstatus::STATUS_SUCCESS);
    assert_eq!(rig.close(a).await, ntstatus::STATUS_SUCCESS);
    assert_released(&mut rig, async_id).await;
}

#[tokio::test]
async fn tree_disconnect_releases_its_opens() {
    let mut rig = Rig::new(MemFsBackend::new().with_file("db", b"0123456789")).await;
    let (_, _, async_id) = start_waiter(&mut rig).await;
    let mut body = Vec::new();
    TreeDisconnectRequest::default()
        .write_to(&mut body)
        .unwrap();
    let (_, outcome) = rig.call(Command::TreeDisconnect, body).await;
    assert_eq!(status_of(outcome), ntstatus::STATUS_SUCCESS);
    assert_released(&mut rig, async_id).await;
}

#[tokio::test]
async fn logoff_releases_the_sessions_opens() {
    let mut rig = Rig::new(MemFsBackend::new().with_file("db", b"0123456789")).await;
    let (_, _, async_id) = start_waiter(&mut rig).await;
    let (_, outcome) = rig.call(Command::Logoff, Vec::new()).await;
    assert_eq!(status_of(outcome), ntstatus::STATUS_SUCCESS);
    assert_released(&mut rig, async_id).await;
}

#[tokio::test]
async fn a_runtime_session_close_releases_the_opens() {
    let mut rig = Rig::new(MemFsBackend::new().with_file("db", b"0123456789")).await;
    let (_, _, async_id) = start_waiter(&mut rig).await;
    rig.smb
        .config_handle()
        .remove_share("share")
        .await
        .expect("remove share");
    assert_released(&mut rig, async_id).await;
}

// ── close races with the handler ───────────────────────────────────────────

#[tokio::test]
async fn close_between_the_handler_snapshot_and_the_table_refuses_the_lock() {
    let mut rig = Rig::new(MemFsBackend::new().with_file("db", b"0123456789")).await;
    let b = rig.open("db").await;
    let owner = rig.owner_of(b).await;
    let (entered_tx, mut entered_rx) = mpsc::unbounded_channel();
    let (_guard, hook) = crate::tests::pause::hold_handler(owner, entered_tx);

    let server = rig.server.clone();
    let conn = rig.conn.clone();
    let mut hdr = header(rig.session_id, rig.tree_id, Command::Lock);
    hdr.message_id = 99;
    let frame = frame_payload(&hdr, &lock_body(b, 0, 10, EX));
    let lock = tokio::spawn(async move { dispatch_frame(&server, &conn, &frame).await });

    entered_rx.recv().await.expect("handler reached the pause");
    let (_, outcome) = rig.call(Command::Close, close_request(b)).await;
    assert_eq!(status_of(outcome), ntstatus::STATUS_SUCCESS);

    hook.resume();
    let (resp_hdr, _) = response(lock.await.expect("lock task"));
    assert_eq!(
        resp_hdr.channel_sequence_status,
        ntstatus::STATUS_FILE_CLOSED
    );
    rig.no_frame().await;

    let fresh = LockOwner::new();
    assert!(
        rig.share
            .locks
            .try_lock("db", &fresh, &[Range::new(0, 10, true).unwrap()])
            .is_ok()
    );
}

#[tokio::test]
async fn close_refuses_a_conflicting_blocking_lock_synchronously() {
    let mut rig = Rig::new(MemFsBackend::new().with_file("db", b"0123456789")).await;
    let a = rig.open("db").await;
    let b = rig.open("db").await;
    assert_eq!(rig.lock(a, 0, 10, EX | NOW).await, ntstatus::STATUS_SUCCESS);
    let owner = rig.owner_of(b).await;
    let (entered_tx, mut entered_rx) = mpsc::unbounded_channel();
    let (_guard, hook) = crate::tests::pause::hold_handler(owner, entered_tx);

    let server = rig.server.clone();
    let conn = rig.conn.clone();
    let mut hdr = header(rig.session_id, rig.tree_id, Command::Lock);
    hdr.message_id = 100;
    let frame = frame_payload(&hdr, &lock_body(b, 5, 1, EX));
    let lock = tokio::spawn(async move { dispatch_frame(&server, &conn, &frame).await });

    entered_rx.recv().await.expect("handler reached the pause");
    let (_, outcome) = rig.call(Command::Close, close_request(b)).await;
    assert_eq!(status_of(outcome), ntstatus::STATUS_SUCCESS);

    hook.resume();
    let (resp_hdr, _) = response(lock.await.expect("lock task"));
    assert_eq!(
        resp_hdr.channel_sequence_status,
        ntstatus::STATUS_FILE_CLOSED
    );
    rig.no_frame().await;

    // No grant appears later when the conflicting holder releases.
    assert_eq!(rig.lock(a, 0, 10, UNLOCK).await, ntstatus::STATUS_SUCCESS);
    rig.no_frame().await;
}

// ── registration races at the state level ──────────────────────────────────

#[tokio::test]
async fn registration_then_close_delivers_on_close() {
    let backend: Arc<dyn ShareBackend> = Arc::new(MemFsBackend::new());
    let share = make_share(backend);
    let conn = Arc::new(Connection::new(1, Uuid::nil(), 1 << 20, 1 << 20));
    let owner = LockOwner::new();
    let other = LockOwner::new();
    share
        .locks
        .try_lock("db", &other, &[Range::new(0, 10, true).unwrap()])
        .unwrap();
    let (done, done_rx) = tokio::sync::oneshot::channel();
    conn.register_pending(
        1,
        Pending {
            message_id: 7,
            owner: owner.clone(),
            on_close: ntstatus::STATUS_RANGE_NOT_LOCKED,
            done,
        },
    )
    .map_err(|_| ())
    .expect("registered");

    conn.open_closed(&share, &owner);
    assert_eq!(
        done_rx.await.expect("a status"),
        ntstatus::STATUS_RANGE_NOT_LOCKED
    );
}

#[tokio::test]
async fn close_then_registration_returns_the_entry() {
    let backend: Arc<dyn ShareBackend> = Arc::new(MemFsBackend::new());
    let share = make_share(backend);
    let conn = Arc::new(Connection::new(1, Uuid::nil(), 1 << 20, 1 << 20));
    let owner = LockOwner::new();
    conn.open_closed(&share, &owner);

    let (done, _done_rx) = tokio::sync::oneshot::channel();
    let returned = conn
        .register_pending(
            2,
            Pending {
                message_id: 8,
                owner: owner.clone(),
                on_close: ntstatus::STATUS_RANGE_NOT_LOCKED,
                done,
            },
        )
        .expect_err("a closed owner refuses registration");
    assert_eq!(returned.message_id, 8);
}

#[tokio::test]
async fn a_grant_removed_by_close_stays_gone_after_the_waiter_resumes() {
    let backend: Arc<dyn ShareBackend> = Arc::new(MemFsBackend::new());
    let share = make_share(backend);
    let conn = Arc::new(Connection::new(1, Uuid::nil(), 1 << 20, 1 << 20));
    let owner = LockOwner::new();
    let (done, done_rx) = tokio::sync::oneshot::channel();
    conn.register_pending(
        3,
        Pending {
            message_id: 9,
            owner: owner.clone(),
            on_close: ntstatus::STATUS_RANGE_NOT_LOCKED,
            done,
        },
    )
    .map_err(|_| ())
    .expect("registered");

    let grant = share
        .locks
        .lock_wait("db", owner.clone(), Range::new(0, 10, true).unwrap())
        .await
        .expect("granted");
    conn.open_closed(&share, &owner);
    assert!(
        !conn.take_pending(3),
        "the close removed the pending entry before take_pending"
    );
    drop(grant);

    let fresh = LockOwner::new();
    assert!(
        share
            .locks
            .try_lock("db", &fresh, &[Range::new(0, 10, true).unwrap()])
            .is_ok(),
        "the range stays free"
    );
    assert_eq!(
        done_rx.await.expect("on_close"),
        ntstatus::STATUS_RANGE_NOT_LOCKED
    );
}

// ── compounds, deadline, case sensitivity ──────────────────────────────────

#[tokio::test]
async fn a_blocking_lock_in_a_compound_is_refused_without_an_interim() {
    let mut rig = Rig::new(MemFsBackend::new().with_file("db", b"0123456789")).await;
    let a = rig.open("db").await;
    let b = rig.open("db").await;
    assert_eq!(rig.lock(a, 0, 10, EX | NOW).await, ntstatus::STATUS_SUCCESS);

    let lock_body = lock_body(b, 5, 1, EX);
    let padded = (SMB2_HEADER_LEN + lock_body.len() + 7) & !7;
    let mut lock_hdr = header(rig.session_id, rig.tree_id, Command::Lock);
    lock_hdr.message_id = 200;
    lock_hdr.next_command = padded as u32;
    let mut first = frame_payload(&lock_hdr, &lock_body);
    first.resize(padded, 0);

    let mut echo_hdr = header(rig.session_id, rig.tree_id, Command::Echo);
    echo_hdr.message_id = 200;
    let mut echo = Vec::new();
    EchoRequest::default().write_to(&mut echo).unwrap();
    let second = frame_payload(&echo_hdr, &echo);

    let mut compound = first;
    compound.extend(second);
    // The real frame's first header must name the padded length.
    let outcome = dispatch_frame(&rig.server, &rig.conn, &compound).await;
    let bytes = match outcome {
        FrameOutcome::Response(bytes) => bytes,
        _ => panic!("a compound gets its responses"),
    };
    assert_eq!(
        u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
        ntstatus::STATUS_LOCK_NOT_GRANTED
    );
    rig.no_frame().await;
}

#[tokio::test]
async fn a_waiter_outlives_a_short_dispatch_deadline() {
    let mut rig = Rig::with(
        Arc::new(MemFsBackend::new().with_file("db", b"0123456789")),
        Duration::from_millis(100),
        None,
    )
    .await;
    let a = rig.open("db").await;
    let b = rig.open("db").await;
    assert_eq!(rig.lock(a, 0, 10, EX | NOW).await, ntstatus::STATUS_SUCCESS);
    let (_, outcome) = rig.call(Command::Lock, lock_body(b, 5, 1, EX)).await;
    assert!(matches!(outcome, FrameOutcome::NoResponse));
    let (interim, _) = rig.next_frame().await;
    let async_id = interim.async_id().unwrap();

    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(rig.lock(a, 0, 10, UNLOCK).await, ntstatus::STATUS_SUCCESS);
    let (final_hdr, _) = rig.next_frame().await;
    assert_eq!(
        (final_hdr.channel_sequence_status, final_hdr.async_id()),
        (ntstatus::STATUS_SUCCESS, Some(async_id))
    );
}

struct CaseSensitive {
    inner: MemFsBackend,
}

#[async_trait]
impl ShareBackend for CaseSensitive {
    async fn open(&self, path: &SmbPath, opts: OpenOptions) -> SmbResult<Box<dyn Handle>> {
        self.inner.open(path, opts).await
    }
    async fn unlink(&self, path: &SmbPath) -> SmbResult<()> {
        self.inner.unlink(path).await
    }
    async fn rename(&self, from: &SmbPath, to: &SmbPath, replace: bool) -> SmbResult<()> {
        self.inner.rename(from, to, replace).await
    }
    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            case_sensitive: true,
            ..self.inner.capabilities()
        }
    }
}

#[tokio::test]
async fn lock_keys_follow_the_backends_case_sensitivity() {
    // Case-insensitive: two spellings share one lock set.
    let mut rig = Rig::new(
        MemFsBackend::new()
            .with_file("Db", b"0123456789")
            .with_file("db", b"0123456789"),
    )
    .await;
    let a = rig.open("Db").await;
    let b = rig.open("db").await;
    assert_eq!(rig.lock(a, 0, 10, EX | NOW).await, ntstatus::STATUS_SUCCESS);
    assert_eq!(
        rig.lock(b, 5, 1, EX | NOW).await,
        ntstatus::STATUS_LOCK_NOT_GRANTED
    );

    // Case-sensitive: the two spellings are different files.
    let mut rig = Rig::with(
        Arc::new(CaseSensitive {
            inner: MemFsBackend::new()
                .with_file("Db", b"0123456789")
                .with_file("db", b"0123456789"),
        }),
        Duration::from_secs(60),
        None,
    )
    .await;
    let a = rig.open("Db").await;
    let b = rig.open("db").await;
    assert_eq!(rig.lock(a, 0, 10, EX | NOW).await, ntstatus::STATUS_SUCCESS);
    assert_eq!(rig.lock(b, 5, 1, EX | NOW).await, ntstatus::STATUS_SUCCESS);
}

// ── connection end over loopback TCP ───────────────────────────────────────

enum Recv {
    Frame(Smb2Header, Vec<u8>),
    Eof,
    Silent,
}

struct Wire {
    client: Option<TcpStream>,
    lifecycle: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl Wire {
    async fn send(&mut self, payload: &[u8]) {
        let client = self.client.as_mut().expect("client");
        let mut out = Vec::new();
        crate::proto::framing::encode_frame(payload, &mut out);
        client.write_all(&out).await.expect("write frame");
    }

    async fn recv_within(&mut self, within: Duration) -> Recv {
        let client = self.client.as_mut().expect("client");
        let read = async {
            let mut hdr = [0u8; FRAME_HEADER_LEN];
            if client.read_exact(&mut hdr).await.is_err() {
                return None;
            }
            let len = decode_frame_header(&hdr).ok()?;
            let mut payload = vec![0u8; len as usize];
            client.read_exact(&mut payload).await.ok()?;
            Some(payload)
        };
        match tokio::time::timeout(within, read).await {
            Err(_) => Recv::Silent,
            Ok(None) => Recv::Eof,
            Ok(Some(payload)) => {
                let (hdr, body) = Smb2Header::parse(&payload).expect("parse frame");
                Recv::Frame(hdr, body.to_vec())
            }
        }
    }

    async fn recv(&mut self) -> (Smb2Header, Vec<u8>) {
        match self.recv_within(Duration::from_secs(5)).await {
            Recv::Frame(hdr, body) => (hdr, body),
            Recv::Eof => panic!("the connection closed instead of answering"),
            Recv::Silent => panic!("no frame arrived"),
        }
    }

    /// Closes only the client's write half, so the server's reader sees EOF
    /// while this side can still observe whether a final response is written.
    async fn shutdown_write(&mut self) {
        let client = self.client.as_mut().expect("client");
        client.shutdown().await.expect("shutdown client write");
    }

    fn drop_client(&mut self) {
        self.client.take();
    }

    async fn wait(&mut self) {
        (&mut self.lifecycle)
            .await
            .expect("lifecycle")
            .expect("connection");
    }
}

async fn spawn_wire(
    smb: &SmbServer,
    share: &Arc<ShareBindings>,
    backend: &Arc<dyn ShareBackend>,
    names: &[&str],
) -> (Wire, Vec<FileId>, Vec<u64>) {
    let server = smb.state();
    let (conn, _session_id, _tree_id, file_ids, owners) =
        seeded_connection(&server, share, backend, names).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (accepted, connected) = tokio::join!(listener.accept(), TcpStream::connect(addr));
    let server_side = accepted.expect("accept").0;
    let client = connected.expect("connect");
    let (read_half, write_half) = tokio::io::split(server_side);

    // The real production lifecycle, not a copied one: connection_loop is
    // this helper plus registration.
    let lifecycle = tokio::spawn(crate::conn::serve_connection(
        read_half, write_half, server, conn,
    ));

    (
        Wire {
            client: Some(client),
            lifecycle,
        },
        file_ids,
        owners,
    )
}

#[tokio::test]
async fn dropping_a_connection_releases_its_locks() {
    let backend: Arc<dyn ShareBackend> =
        Arc::new(MemFsBackend::new().with_file("db", b"0123456789"));
    let share = make_share(backend.clone());
    let smb = make_server(share.clone(), Duration::from_secs(60), None);

    let (mut first, first_ids, _) = spawn_wire(&smb, &share, &backend, &["db"]).await;
    let mut hdr = header(1, 1, Command::Lock);
    hdr.message_id = 1;
    first
        .send(&frame_payload(
            &hdr,
            &lock_body(first_ids[0], 0, u64::MAX, EX | NOW),
        ))
        .await;
    let (resp, _) = first.recv().await;
    assert_eq!(resp.channel_sequence_status, ntstatus::STATUS_SUCCESS);

    first.drop_client();
    first.wait().await;

    let (mut second, second_ids, _) = spawn_wire(&smb, &share, &backend, &["db"]).await;
    let mut hdr = header(1, 1, Command::Lock);
    hdr.message_id = 1;
    second
        .send(&frame_payload(
            &hdr,
            &lock_body(second_ids[0], 0, u64::MAX, EX | NOW),
        ))
        .await;
    let (resp, _) = second.recv().await;
    assert_eq!(resp.channel_sequence_status, ntstatus::STATUS_SUCCESS);
    second.drop_client();
    second.wait().await;
}

#[tokio::test]
async fn a_waiter_granted_during_teardown_writes_no_final() {
    let backend: Arc<dyn ShareBackend> =
        Arc::new(MemFsBackend::new().with_file("db", b"0123456789"));
    let share = make_share(backend.clone());
    let smb = make_server(share.clone(), Duration::from_secs(60), None);

    let (mut holder, holder_ids, _) = spawn_wire(&smb, &share, &backend, &["db"]).await;
    let mut hdr = header(1, 1, Command::Lock);
    hdr.message_id = 1;
    holder
        .send(&frame_payload(
            &hdr,
            &lock_body(holder_ids[0], 0, u64::MAX, EX | NOW),
        ))
        .await;
    assert_eq!(
        holder.recv().await.0.channel_sequence_status,
        ntstatus::STATUS_SUCCESS
    );

    let (mut waiter, waiter_ids, waiter_owners) = spawn_wire(&smb, &share, &backend, &["db"]).await;
    let (entered_tx, mut entered_rx) = mpsc::unbounded_channel();
    let (_guard, hook) = crate::tests::pause::hold_waiter(waiter_owners[0], entered_tx);
    let (_done_guard, mut done_rx) = crate::tests::pause::waiter_done_hook(waiter_owners[0]);
    let mut hdr = header(1, 1, Command::Lock);
    hdr.message_id = 2;
    waiter
        .send(&frame_payload(&hdr, &lock_body(waiter_ids[0], 5, 1, EX)))
        .await;
    assert_eq!(
        waiter.recv().await.0.channel_sequence_status,
        ntstatus::STATUS_PENDING
    );

    // Release the holder, so the waiter's work resolves and it pauses.
    holder.drop_client();
    holder.wait().await;
    entered_rx.recv().await.expect("waiter reached the pause");

    // The client's write side closes before the waiter resumes; the real
    // connection lifecycle runs teardown with it.
    waiter.shutdown_write().await;
    waiter.wait().await;

    hook.resume();
    done_rx.recv().await.expect("the waiter task finished");
    match waiter.recv_within(Duration::from_millis(500)).await {
        Recv::Eof => {}
        Recv::Frame(hdr, _) => panic!(
            "a final response was written to the dead connection: status 0x{:08X}",
            hdr.channel_sequence_status
        ),
        Recv::Silent => panic!("the server left the half-closed socket open"),
    }

    let (mut second, second_ids, _) = spawn_wire(&smb, &share, &backend, &["db"]).await;
    let mut hdr = header(1, 1, Command::Lock);
    hdr.message_id = 1;
    second
        .send(&frame_payload(
            &hdr,
            &lock_body(second_ids[0], 0, u64::MAX, EX | NOW),
        ))
        .await;
    assert_eq!(
        second.recv().await.0.channel_sequence_status,
        ntstatus::STATUS_SUCCESS
    );
    second.drop_client();
    second.wait().await;
}

// ── waiter panic ───────────────────────────────────────────────────────────

#[derive(Clone, Default)]
struct CaptureIncident {
    events: Arc<Mutex<Vec<Incident>>>,
}

impl IncidentSink for CaptureIncident {
    fn record(&self, incident: &Incident) {
        self.events.lock().unwrap().push(incident.clone());
    }
}

fn empty_ok() -> HandlerResponse {
    HandlerResponse::ok(Vec::new())
}

async fn synthetic(rig: &Rig, wait: AsyncWait) -> Option<Vec<u8>> {
    let mut hdr = header(rig.session_id, rig.tree_id, Command::Lock);
    hdr.message_id = 500;
    crate::dispatch::dispatch_synthetic_wait(&rig.server, &rig.conn, hdr, None, wait, true).await
}

fn work_granted(held: Box<dyn Held>) -> Pin<Box<dyn Future<Output = WaitOutcome> + Send>> {
    Box::pin(async move {
        WaitOutcome::Granted {
            resp: empty_ok(),
            held,
        }
    })
}

#[tokio::test]
async fn a_panicking_work_answers_internal_error_and_frees_nothing() {
    let sink = Arc::new(CaptureIncident::default());
    let mut rig = Rig::with(
        Arc::new(MemFsBackend::new().with_file("db", b"0123456789")),
        Duration::from_secs(60),
        Some(sink.clone()),
    )
    .await;
    let owner = LockOwner::new();
    let (_done_guard, mut done_rx) = crate::tests::pause::waiter_done_hook(owner.id());
    let work: Pin<Box<dyn Future<Output = WaitOutcome> + Send>> = Box::pin(async {
        panic!("work panicked");
    });
    let wait = AsyncWait {
        owner,
        on_close: ntstatus::STATUS_RANGE_NOT_LOCKED,
        refused: ntstatus::STATUS_LOCK_NOT_GRANTED,
        work,
    };
    synthetic(&rig, wait).await;

    let (interim, _) = rig.next_frame().await;
    let async_id = interim.async_id().unwrap();
    let (final_hdr, _) = rig.next_frame().await;
    assert_eq!(
        (final_hdr.channel_sequence_status, final_hdr.async_id()),
        (ntstatus::STATUS_INTERNAL_ERROR, Some(async_id))
    );
    done_rx.recv().await.expect("the waiter task finished");
    rig.no_frame().await;
    let events = sink.events.lock().unwrap();
    assert!(
        events
            .iter()
            .any(|i| matches!(i.kind, crate::incident::IncidentKind::Panicked { .. })),
        "a Panicked incident names the request"
    );
    assert_eq!(events[0].message_id, Some(500));
}

#[tokio::test]
async fn a_panic_after_the_grant_was_claimed_frees_the_range() {
    let mut rig = Rig::new(MemFsBackend::new().with_file("db", b"0123456789")).await;
    let owner = LockOwner::new();
    let _panic = crate::tests::pause::panic_after_claim(owner.id());
    let (_done_guard, mut done_rx) = crate::tests::pause::waiter_done_hook(owner.id());
    let grant = rig
        .share
        .locks
        .lock_wait("db", owner.clone(), Range::new(0, 10, true).unwrap())
        .await
        .expect("granted");
    let wait = AsyncWait {
        owner,
        on_close: ntstatus::STATUS_RANGE_NOT_LOCKED,
        refused: ntstatus::STATUS_LOCK_NOT_GRANTED,
        work: work_granted(Box::new(grant)),
    };
    synthetic(&rig, wait).await;

    let (interim, _) = rig.next_frame().await;
    let async_id = interim.async_id().unwrap();
    let (final_hdr, _) = rig.next_frame().await;
    assert_eq!(
        (final_hdr.channel_sequence_status, final_hdr.async_id()),
        (ntstatus::STATUS_INTERNAL_ERROR, Some(async_id))
    );
    done_rx.recv().await.expect("the waiter task finished");
    rig.no_frame().await;

    let fresh = LockOwner::new();
    assert!(
        rig.share
            .locks
            .try_lock("db", &fresh, &[Range::new(0, 10, true).unwrap()])
            .is_ok()
    );
}

#[tokio::test]
async fn a_taken_writer_slot_rolls_a_grant_back_without_a_final() {
    let mut rig = Rig::new(MemFsBackend::new().with_file("db", b"0123456789")).await;
    let owner = LockOwner::new();
    let (_done_guard, mut done_rx) = crate::tests::pause::waiter_done_hook(owner.id());
    let grant = rig
        .share
        .locks
        .lock_wait("db", owner.clone(), Range::new(0, 10, true).unwrap())
        .await
        .expect("granted");
    let wait = AsyncWait {
        owner,
        on_close: ntstatus::STATUS_RANGE_NOT_LOCKED,
        refused: ntstatus::STATUS_LOCK_NOT_GRANTED,
        work: work_granted(Box::new(grant)),
    };
    // The connection ends before the grant's final can be queued.
    rig.conn
        .writer
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take();
    synthetic(&rig, wait).await;

    done_rx.recv().await.expect("the waiter task finished");
    assert!(rig.frames.try_recv().is_err(), "no final was written");
    let fresh = LockOwner::new();
    assert!(
        rig.share
            .locks
            .try_lock("db", &fresh, &[Range::new(0, 10, true).unwrap()])
            .is_ok()
    );
}

#[tokio::test]
async fn a_panic_after_cancel_answers_cancelled() {
    let sink = Arc::new(CaptureIncident::default());
    let mut rig = Rig::with(
        Arc::new(MemFsBackend::new().with_file("db", b"0123456789")),
        Duration::from_secs(60),
        Some(sink.clone()),
    )
    .await;
    let owner = LockOwner::new();
    let (entered_tx, mut entered_rx) = mpsc::unbounded_channel();
    let (_pause_guard, hook) = crate::tests::pause::hold_before_select(owner.id(), entered_tx);
    let (_done_guard, mut done_rx) = crate::tests::pause::waiter_done_hook(owner.id());
    let work: Pin<Box<dyn Future<Output = WaitOutcome> + Send>> =
        Box::pin(async { panic!("late panic") });
    let wait = AsyncWait {
        owner,
        on_close: ntstatus::STATUS_RANGE_NOT_LOCKED,
        refused: ntstatus::STATUS_LOCK_NOT_GRANTED,
        work,
    };
    synthetic(&rig, wait).await;
    let (interim, _) = rig.next_frame().await;
    let async_id = interim.async_id().unwrap();

    // The waiter is parked before its race. Deliver the cancellation first,
    // then let it resume, so the work panic happens with CANCELLED already
    // waiting — not as a random select tie.
    entered_rx.recv().await.expect("waiter reached the pause");
    rig.conn.cancel(Some(async_id), 0);
    hook.resume();
    done_rx.recv().await.expect("the waiter task finished");

    let (final_hdr, _) = rig.next_frame().await;
    assert_eq!(
        (final_hdr.channel_sequence_status, final_hdr.async_id()),
        (ntstatus::STATUS_CANCELLED, Some(async_id))
    );
    rig.no_frame().await;
    let events = sink.events.lock().unwrap();
    assert!(
        events
            .iter()
            .any(|i| matches!(i.kind, crate::incident::IncidentKind::Panicked { .. })),
        "the panic incident is reported even though the final is CANCELLED"
    );
    assert_eq!(events[0].message_id, Some(500));
}

#[tokio::test]
async fn a_panic_before_the_final_is_queued_closes_and_rolls_back() {
    let mut rig = Rig::new(MemFsBackend::new().with_file("db", b"0123456789")).await;
    let owner = LockOwner::new();
    let _panic = crate::tests::pause::panic_before_final(owner.id());
    let (_done_guard, mut done_rx) = crate::tests::pause::waiter_done_hook(owner.id());
    let grant = rig
        .share
        .locks
        .lock_wait("db", owner.clone(), Range::new(0, 10, true).unwrap())
        .await
        .expect("granted");
    let wait = AsyncWait {
        owner,
        on_close: ntstatus::STATUS_RANGE_NOT_LOCKED,
        refused: ntstatus::STATUS_LOCK_NOT_GRANTED,
        work: work_granted(Box::new(grant)),
    };
    synthetic(&rig, wait).await;
    let (interim, _) = rig.next_frame().await;
    assert_eq!(interim.channel_sequence_status, ntstatus::STATUS_PENDING);

    done_rx.recv().await.expect("the waiter task finished");
    assert!(
        rig.frames.try_recv().is_err(),
        "the grant's final was never queued"
    );
    assert!(
        *rig.conn.subscribe_close().borrow(),
        "a panicking response glue closes the connection"
    );
    let fresh = LockOwner::new();
    assert!(
        rig.share
            .locks
            .try_lock("db", &fresh, &[Range::new(0, 10, true).unwrap()])
            .is_ok(),
        "the armed grant rolled back"
    );
}

// ── lifecycle cleanup with a failing backend close ─────────────────────────

enum CloseMode {
    Panic,
    Stall(mpsc::UnboundedSender<()>),
}

struct TestHandle {
    mode: CloseMode,
}

#[async_trait]
impl Handle for TestHandle {
    async fn read(&self, _offset: u64, _len: u32) -> SmbResult<bytes::Bytes> {
        Ok(bytes::Bytes::new())
    }
    async fn write(&self, _offset: u64, data: &[u8]) -> SmbResult<u32> {
        Ok(data.len() as u32)
    }
    async fn flush(&self) -> SmbResult<()> {
        Ok(())
    }
    async fn stat(&self) -> SmbResult<FileInfo> {
        Ok(FileInfo {
            name: "test".to_owned(),
            end_of_file: 0,
            allocation_size: 0,
            creation_time: 0,
            last_access_time: 0,
            last_write_time: 0,
            change_time: 0,
            is_directory: false,
            is_symlink: false,
            file_index: 0,
        })
    }
    async fn set_times(&self, _times: FileTimes) -> SmbResult<()> {
        Ok(())
    }
    async fn truncate(&self, _len: u64) -> SmbResult<()> {
        Ok(())
    }
    async fn list_dir(&self, _pattern: Option<&str>) -> SmbResult<Vec<DirEntry>> {
        Ok(Vec::new())
    }
    async fn close(self: Box<Self>) -> SmbResult<()> {
        match self.mode {
            CloseMode::Panic => panic!("injected backend close panic"),
            CloseMode::Stall(entered) => {
                let _ = entered.send(());
                std::future::pending::<()>().await;
                Ok(())
            }
        }
    }
}

async fn install_open(tree: &TreeConnect, path: &str, mode: CloseMode) -> Arc<LockOwner> {
    let file_id = tree.alloc_file_id();
    let open = Open::new(
        file_id,
        Box::new(TestHandle { mode }),
        Access::ReadWrite,
        path.parse().expect("path"),
        false,
        false,
    );
    let owner = open.lock_owner.clone();
    tree.opens
        .write()
        .await
        .insert(file_id, Arc::new(RwLock::new(open)));
    owner
}

/// Two trees in one session, each with a locked open plus one waiting open.
/// Returns the connection, every locked path, and the waiters' done channels.
async fn session_with_failing_closes(
    share: &Arc<ShareBindings>,
    stall: Option<mpsc::UnboundedSender<()>>,
) -> (
    Arc<Connection>,
    Vec<&'static str>,
    Vec<tokio::sync::oneshot::Receiver<u32>>,
) {
    let conn = Arc::new(Connection::new(1, Uuid::nil(), 1 << 20, 1 << 20));
    let session = Arc::new(RwLock::new(Session::new(
        1,
        Identity::Anonymous,
        [0; 16],
        [0; 16],
        false,
        None,
    )));

    let tree1 = TreeConnect::new(1, share.clone(), Access::ReadWrite);
    let tree2 = TreeConnect::new(2, share.clone(), Access::ReadWrite);
    let modes = || match &stall {
        Some(tx) => CloseMode::Stall(tx.clone()),
        None => CloseMode::Panic,
    };

    // Tree 1: "a" held, "b" waiting.
    let a = install_open(&tree1, "a", modes()).await;
    share
        .locks
        .try_lock("a", &a, &[Range::new(0, 10, true).unwrap()])
        .unwrap();
    let b = install_open(&tree1, "b", modes()).await;
    let (done_b, wait_b) = tokio::sync::oneshot::channel();
    conn.register_pending(
        1,
        Pending {
            message_id: 1,
            owner: b,
            on_close: ntstatus::STATUS_RANGE_NOT_LOCKED,
            done: done_b,
        },
    )
    .map_err(|_| ())
    .expect("registered");
    // Tree 2: "c" held, "d" waiting.
    let c = install_open(&tree2, "c", modes()).await;
    share
        .locks
        .try_lock("c", &c, &[Range::new(0, 10, true).unwrap()])
        .unwrap();
    let d = install_open(&tree2, "d", modes()).await;
    let (done_d, wait_d) = tokio::sync::oneshot::channel();
    conn.register_pending(
        2,
        Pending {
            message_id: 2,
            owner: d,
            on_close: ntstatus::STATUS_RANGE_NOT_LOCKED,
            done: done_d,
        },
    )
    .map_err(|_| ())
    .expect("registered");

    session
        .read()
        .await
        .trees
        .write()
        .await
        .insert(1, Arc::new(RwLock::new(tree1)));
    session
        .read()
        .await
        .trees
        .write()
        .await
        .insert(2, Arc::new(RwLock::new(tree2)));
    conn.sessions.write().await.insert(1, session);

    (conn, vec!["a", "c"], vec![wait_b, wait_d])
}

#[tokio::test]
async fn a_panicking_backend_close_releases_every_tree_and_waiter() {
    let share = make_share(Arc::new(MemFsBackend::new()));
    let (conn, locked, mut waiters) = session_with_failing_closes(&share, None).await;

    let closer = tokio::spawn({
        let conn = conn.clone();
        async move { conn.close_session(1).await }
    });
    let joined = closer.await;
    assert!(joined.is_err(), "the injected backend close panicked");

    for waiter in waiters.iter_mut() {
        assert_eq!(
            waiter.await.expect("on_close"),
            ntstatus::STATUS_RANGE_NOT_LOCKED,
            "no waiter of the removed session stays pending"
        );
    }
    let fresh = LockOwner::new();
    for path in locked {
        assert!(
            share
                .locks
                .try_lock(path, &fresh, &[Range::new(0, 10, true).unwrap()])
                .is_ok(),
            "a fresh connection can acquire {path}"
        );
    }
}

#[tokio::test]
async fn a_stalled_backend_close_cancelled_before_it_finishes_releases_every_tree_and_waiter() {
    let share = make_share(Arc::new(MemFsBackend::new()));
    let (entered_tx, mut entered_rx) = mpsc::unbounded_channel();
    let (conn, locked, mut waiters) = session_with_failing_closes(&share, Some(entered_tx)).await;

    let closer = tokio::spawn({
        let conn = conn.clone();
        async move { conn.close_session(1).await }
    });
    // The first backend close has started, so every tree's lock cleanup is
    // already done before the await.
    entered_rx.recv().await.expect("a backend close started");
    closer.abort();
    let _ = closer.await;

    for waiter in waiters.iter_mut() {
        assert_eq!(
            waiter.await.expect("on_close"),
            ntstatus::STATUS_RANGE_NOT_LOCKED,
            "no waiter of the removed session stays pending"
        );
    }
    let fresh = LockOwner::new();
    for path in locked {
        assert!(
            share
                .locks
                .try_lock(path, &fresh, &[Range::new(0, 10, true).unwrap()])
                .is_ok(),
            "a fresh connection can acquire {path}"
        );
    }
}
