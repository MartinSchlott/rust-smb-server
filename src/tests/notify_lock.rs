//! CHANGE_NOTIFY and LOCK through the command router: interim
//! `STATUS_PENDING`, the final async response, CANCEL, and CLOSE.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::mpsc;

use super::handler_support::{
    close_request, create_request, header, test_conn_with_backend, test_server,
};
use super::memfs::MemFsBackend;
use crate::backend::{BackendCapabilities, Handle, OpenOptions, ShareBackend};
use crate::conn::state::Connection;
use crate::error::SmbResult;
use crate::notify::{Change, ChangeNotifier, NotifyAction};
use crate::ntstatus;
use crate::path::SmbPath;
use crate::proto::header::{Command, SMB2_FLAGS_ASYNC_COMMAND, Smb2Header};
use crate::proto::messages::{
    ChangeNotifyRequest, CreateResponse, FileId, LockElement, LockRequest,
};
use crate::server::ServerState;

#[derive(Clone)]
struct Notifying {
    fs: MemFsBackend,
    notifier: ChangeNotifier,
}

#[async_trait]
impl ShareBackend for Notifying {
    async fn open(&self, path: &SmbPath, opts: OpenOptions) -> SmbResult<Box<dyn Handle>> {
        self.fs.open(path, opts).await
    }
    async fn unlink(&self, path: &SmbPath) -> SmbResult<()> {
        self.fs.unlink(path).await
    }
    async fn rename(&self, from: &SmbPath, to: &SmbPath, replace: bool) -> SmbResult<()> {
        self.fs.rename(from, to, replace).await
    }
    fn capabilities(&self) -> BackendCapabilities {
        self.fs.capabilities()
    }
    fn change_notifier(&self) -> Option<ChangeNotifier> {
        Some(self.notifier.clone())
    }
}

struct Rig {
    server: Arc<ServerState>,
    conn: Arc<Connection>,
    frames: mpsc::Receiver<Vec<u8>>,
    notifier: ChangeNotifier,
    next_mid: u64,
}

impl Rig {
    async fn new() -> Self {
        let notifier = ChangeNotifier::new();
        let backend = Notifying {
            fs: MemFsBackend::new().with_file("db", b"0123456789"),
            notifier: notifier.clone(),
        };
        let (conn, _, _) = test_conn_with_backend(backend).await;
        let (tx, frames) = mpsc::channel(16);
        *conn.writer.lock().unwrap() = Some(tx);
        Self {
            server: test_server(),
            conn,
            frames,
            notifier,
            next_mid: 1,
        }
    }

    async fn call(
        &mut self,
        command: Command,
        body: Vec<u8>,
    ) -> (Smb2Header, crate::dispatch::HandlerResponse) {
        let mut hdr = header(1, 1, command);
        hdr.message_id = self.next_mid;
        self.next_mid += 1;
        let resp = crate::handlers::dispatch_command(&self.server, &self.conn, &hdr, &body).await;
        (hdr, resp)
    }

    async fn open(&mut self, name: &str, directory: bool) -> FileId {
        let options = if directory { 0x1 } else { 0x40 };
        let (_, resp) = self
            .call(
                Command::Create,
                create_request(name, options, 1, 0x0012_019F),
            )
            .await;
        assert_eq!(resp.status, ntstatus::STATUS_SUCCESS, "open {name}");
        CreateResponse::parse(&resp.body).unwrap().file_id
    }

    /// The next frame sent outside a dispatch: `(status, async_id, credits, body)`.
    async fn frame(&mut self) -> (u32, u64, u16, Vec<u8>) {
        let f = tokio::time::timeout(Duration::from_secs(2), self.frames.recv())
            .await
            .expect("a frame")
            .expect("writer open");
        let (hdr, body) = Smb2Header::parse(&f).unwrap();
        assert_ne!(hdr.flags & SMB2_FLAGS_ASYNC_COMMAND, 0);
        (
            hdr.channel_sequence_status,
            hdr.async_id().unwrap(),
            hdr.credit_request_response,
            body.to_vec(),
        )
    }

    async fn no_frame(&mut self) {
        assert!(
            tokio::time::timeout(Duration::from_millis(50), self.frames.recv())
                .await
                .is_err()
        );
    }
}

fn notify_body(file_id: FileId) -> Vec<u8> {
    let mut buf = Vec::new();
    ChangeNotifyRequest {
        structure_size: 32,
        flags: 0,
        output_buffer_length: 4096,
        file_id,
        completion_filter: 0x1 | 0x2 | 0x4,
        reserved: 0,
    }
    .write_to(&mut buf)
    .unwrap();
    buf
}

fn lock_body(file_id: FileId, offset: u64, length: u64, flags: u32) -> Vec<u8> {
    let mut buf = Vec::new();
    LockRequest {
        structure_size: 48,
        lock_count: 1,
        lock_sequence: 0,
        file_id,
        locks: vec![LockElement {
            offset,
            length,
            flags,
            reserved: 0,
        }],
    }
    .write_to(&mut buf)
    .unwrap();
    buf
}

fn added(name: &str) -> Change {
    Change {
        action: NotifyAction::Added,
        name: name.into(),
        is_dir: false,
    }
}

#[tokio::test]
async fn change_notify_pends_then_completes_cancels_and_cleans_up() {
    let mut rig = Rig::new().await;
    let root = rig.open("", true).await;

    let (_, resp) = rig.call(Command::ChangeNotify, notify_body(root)).await;
    assert!(resp.suppress);
    let (status, id, credits, _) = rig.frame().await;
    assert_eq!((status, credits), (ntstatus::STATUS_PENDING, 1));

    rig.notifier.notify("/", &[added("new.mov")]);
    let (status, final_id, credits, body) = rig.frame().await;
    assert_eq!(
        (status, final_id, credits),
        (ntstatus::STATUS_SUCCESS, id, 0)
    );
    let name: Vec<u8> = "new.mov"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    assert_eq!(&body[8 + 12..8 + 12 + name.len()], &name[..]);

    // A change while no request waits is kept and answers the next at once.
    rig.notifier.notify("", &[added("later")]);
    let (_, resp) = rig.call(Command::ChangeNotify, notify_body(root)).await;
    assert_eq!(resp.status, ntstatus::STATUS_SUCCESS);
    assert!(!resp.suppress);

    // CANCEL by AsyncId.
    rig.call(Command::ChangeNotify, notify_body(root)).await;
    let (_, id, _, _) = rig.frame().await;
    rig.conn.cancel(Some(id), 0);
    let (status, final_id, _, _) = rig.frame().await;
    assert_eq!((status, final_id), (ntstatus::STATUS_CANCELLED, id));

    // CANCEL by MessageId.
    let (hdr, _) = rig.call(Command::ChangeNotify, notify_body(root)).await;
    rig.frame().await;
    rig.conn.cancel(None, hdr.message_id);
    assert_eq!(rig.frame().await.0, ntstatus::STATUS_CANCELLED);

    // CLOSE finishes a waiting request.
    rig.call(Command::ChangeNotify, notify_body(root)).await;
    rig.frame().await;
    let (_, resp) = rig.call(Command::Close, close_request(root)).await;
    assert_eq!(resp.status, ntstatus::STATUS_SUCCESS);
    assert_eq!(rig.frame().await.0, ntstatus::STATUS_NOTIFY_CLEANUP);
    rig.notifier.notify("", &[added("after")]);
    rig.no_frame().await;
}

#[tokio::test]
async fn locks_conflict_wait_and_go_with_their_open() {
    let mut rig = Rig::new().await;
    let a = rig.open("db", false).await;
    let b = rig.open("db", false).await;
    const EX: u32 = LockElement::FLAG_EXCLUSIVE_LOCK;
    const NOW: u32 = LockElement::FLAG_FAIL_IMMEDIATELY;

    let (_, r) = rig.call(Command::Lock, lock_body(a, 4, 2, EX | NOW)).await;
    assert_eq!(r.status, ntstatus::STATUS_SUCCESS);
    let (_, r) = rig.call(Command::Lock, lock_body(b, 5, 1, EX | NOW)).await;
    assert_eq!(r.status, ntstatus::STATUS_LOCK_NOT_GRANTED);
    let (_, r) = rig
        .call(
            Command::Lock,
            lock_body(b, 5, 1, LockElement::FLAG_SHARED_LOCK | NOW),
        )
        .await;
    assert_eq!(r.status, ntstatus::STATUS_LOCK_NOT_GRANTED);
    let (_, r) = rig
        .call(Command::Lock, lock_body(a, 4, 1, LockElement::FLAG_UNLOCK))
        .await;
    assert_eq!(r.status, ntstatus::STATUS_RANGE_NOT_LOCKED);
    let (_, r) = rig
        .call(
            Command::Lock,
            lock_body(a, 0, 1, EX | LockElement::FLAG_UNLOCK),
        )
        .await;
    assert_eq!(r.status, ntstatus::STATUS_INVALID_PARAMETER);

    // B waits; A's unlock lets it in.
    let (_, r) = rig.call(Command::Lock, lock_body(b, 5, 1, EX)).await;
    assert!(r.suppress);
    let (status, id, _, _) = rig.frame().await;
    assert_eq!(status, ntstatus::STATUS_PENDING);
    rig.no_frame().await;
    let (_, r) = rig
        .call(Command::Lock, lock_body(a, 4, 2, LockElement::FLAG_UNLOCK))
        .await;
    assert_eq!(r.status, ntstatus::STATUS_SUCCESS);
    let (status, done_id, _, _) = rig.frame().await;
    assert_eq!((status, done_id), (ntstatus::STATUS_SUCCESS, id));

    // A now waits on B; closing B hands A the range.
    rig.call(Command::Lock, lock_body(a, 0, u64::MAX, EX)).await;
    let (_, a_wait, _, _) = rig.frame().await;
    rig.call(Command::Close, close_request(b)).await;
    let (status, done_id, _, _) = rig.frame().await;
    assert_eq!((status, done_id), (ntstatus::STATUS_SUCCESS, a_wait));

    // A waiting LOCK is cancelled, and a waiting one on a closed open ends.
    let c = rig.open("db", false).await;
    rig.call(Command::Lock, lock_body(c, 9, 1, EX)).await;
    let (_, c_wait, _, _) = rig.frame().await;
    rig.conn.cancel(Some(c_wait), 0);
    assert_eq!(rig.frame().await.0, ntstatus::STATUS_CANCELLED);
    rig.call(Command::Lock, lock_body(c, 9, 1, EX)).await;
    rig.frame().await;
    rig.call(Command::Close, close_request(c)).await;
    assert_eq!(rig.frame().await.0, ntstatus::STATUS_RANGE_NOT_LOCKED);

    // Closing A frees the whole file.
    rig.call(Command::Close, close_request(a)).await;
    let d = rig.open("db", false).await;
    let (_, r) = rig
        .call(Command::Lock, lock_body(d, 0, u64::MAX, EX | NOW))
        .await;
    assert_eq!(r.status, ntstatus::STATUS_SUCCESS);
}
