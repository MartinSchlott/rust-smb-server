//! Connection / session / tree / open state held during a single TCP
//! connection's lifetime.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::proto::auth::ntlm::{Identity, NtlmServer};
use crate::proto::crypto::{PreauthIntegrity, SigningAlgo};
use crate::proto::messages::{Dialect, FileId};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::backend::Handle;
use crate::builder::Access;
use crate::conn::writer::FramePayload;
use crate::lock::LockOwner;
use crate::path::SmbPath;
use crate::server::ShareBindings;

/// In-flight NTLM acceptor + a `is_raw_ntlmssp` flag (true = raw, false =
/// SPNEGO-wrapped). The handler hands the second-round response back in the
/// same form the client opened with.
pub type PendingAuth = Arc<Mutex<(NtlmServer, bool)>>;

// ---------------------------------------------------------------------------
// Connection
// ---------------------------------------------------------------------------

/// One connection's negotiated state and its session/tree/open tables.
pub struct Connection {
    /// Per-accepted-socket counter (`ActiveConnections::alloc_id`) — the
    /// `connection_id` component of a `TraceKey` (Step 1a). `message_id` is
    /// only unique within one connection, so this is what makes the key
    /// collision-free across concurrent connections.
    pub connection_id: u64,
    pub server_guid: Uuid,
    pub client_guid: tokio::sync::RwLock<Uuid>,
    pub dialect: tokio::sync::RwLock<Option<Dialect>>,
    pub signing_algo: tokio::sync::RwLock<SigningAlgo>,
    /// Connection.PreauthIntegrityHashValue after NEGOTIATE. SMB 3.1.1
    /// SESSION_SETUP exchanges fork this into `session_preauth`.
    pub preauth: Mutex<PreauthIntegrity>,
    /// Granted at NEGOTIATE: large MTU support flag etc.
    pub max_read_size: tokio::sync::RwLock<u32>,
    pub max_write_size: tokio::sync::RwLock<u32>,

    /// Sessions keyed by SessionId.
    pub sessions: RwLock<HashMap<u64, Arc<RwLock<Session>>>>,

    /// In-flight NTLM acceptors keyed by SessionId. We keep them out of
    /// `Session` because a session is created only after a successful first
    /// SESSION_SETUP round — between rounds the entry lives here. The
    /// `bool` records whether the client sent raw NTLMSSP (true) or
    /// SPNEGO-wrapped (false) so the second-round response matches form.
    pub pending_auths: RwLock<HashMap<u64, PendingAuth>>,

    /// In-flight SMB 3.1.1 preauth state keyed by SessionId during
    /// multi-leg SESSION_SETUP.
    pub session_preauth: RwLock<HashMap<u64, PreauthIntegrity>>,

    /// Monotonic SessionId allocator.
    next_session_id: AtomicU64,

    /// The connection's writer, for responses sent after the request's own
    /// dispatch returned (a LOCK waiter's interim and final). Taken when the
    /// connection ends so the writer task can finish.
    pub writer: Mutex<Option<tokio::sync::mpsc::Sender<FramePayload>>>,
    /// Requests answered `STATUS_PENDING`, by AsyncId.
    pending: Mutex<HashMap<u64, Pending>>,
    next_async_id: AtomicU64,

    /// Idempotent close signal; the writer task selects on it.
    close: tokio::sync::watch::Sender<bool>,

    /// What response building needs of the connection's signing state, kept
    /// in a synchronous map so that building a response never awaits a lock a
    /// handler (or a long runtime-config operation) can hold. Updated at every
    /// site that changes what it mirrors, while the corresponding tokio write
    /// guard is held; only ever locked for copies, never across an `.await`.
    signing: Mutex<SigningContext>,
}

/// A request answered `STATUS_PENDING` whose final response is still owed.
/// The waiter task always owes that response. Removing the entry never
/// transfers or cancels the obligation; it only means no CANCEL or close
/// status will arrive, and a status sent down `done` is one input to the
/// final the waiter still sends.
pub(crate) struct Pending {
    pub(crate) message_id: u64,
    /// `Open::lock_owner` of the open the request waits on.
    pub(crate) owner: Arc<LockOwner>,
    /// Status to complete with when that open closes.
    pub(crate) on_close: u32,
    pub(crate) done: tokio::sync::oneshot::Sender<u32>,
}

/// The signing facts of one session, as response building needs them.
#[derive(Clone, Copy)]
pub(crate) struct SessionSigning {
    pub key: [u8; 16],
    pub anonymous: bool,
}

struct SigningContext {
    algo: SigningAlgo,
    sessions: HashMap<u64, SessionSigning>,
}

impl Connection {
    pub fn new(
        connection_id: u64,
        server_guid: Uuid,
        max_read_size: u32,
        max_write_size: u32,
    ) -> Self {
        Self {
            connection_id,
            server_guid,
            client_guid: tokio::sync::RwLock::new(Uuid::nil()),
            dialect: tokio::sync::RwLock::new(None),
            signing_algo: tokio::sync::RwLock::new(SigningAlgo::HmacSha256),
            preauth: Mutex::new(PreauthIntegrity::new()),
            max_read_size: tokio::sync::RwLock::new(max_read_size),
            max_write_size: tokio::sync::RwLock::new(max_write_size),
            sessions: RwLock::new(HashMap::new()),
            pending_auths: RwLock::new(HashMap::new()),
            session_preauth: RwLock::new(HashMap::new()),
            next_session_id: AtomicU64::new(1),
            writer: Mutex::new(None),
            pending: Mutex::new(HashMap::new()),
            next_async_id: AtomicU64::new(1),
            close: tokio::sync::watch::channel(false).0,
            signing: Mutex::new(SigningContext {
                algo: SigningAlgo::HmacSha256,
                sessions: HashMap::new(),
            }),
        }
    }

    /// Asks the writer task to shut the socket down, which sends FIN and
    /// drops the channel the reader's admission depends on. Idempotent.
    pub fn close(&self) {
        self.close.send_replace(true);
    }

    pub fn subscribe_close(&self) -> tokio::sync::watch::Receiver<bool> {
        self.close.subscribe()
    }

    fn signing(&self) -> std::sync::MutexGuard<'_, SigningContext> {
        self.signing
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Mirrors the negotiated signing algorithm; call while holding the
    /// `signing_algo` write guard.
    pub(crate) fn set_signing_algo(&self, algo: SigningAlgo) {
        self.signing().algo = algo;
    }

    /// Mirrors a session's signing context; call while holding the
    /// `sessions` write guard (or the session's, for a re-key).
    pub fn snapshot_session(&self, session_id: u64, signing_key: [u8; 16], anonymous: bool) {
        self.signing().sessions.insert(
            session_id,
            SessionSigning {
                key: signing_key,
                anonymous,
            },
        );
    }

    /// Forgets a removed session; call while holding the `sessions` write guard.
    pub(crate) fn forget_session(&self, session_id: u64) {
        self.signing().sessions.remove(&session_id);
    }

    /// The signing algorithm and, for a known session, its signing facts. A
    /// session absent from the snapshot is not signed for.
    pub(crate) fn signing_context(&self, session_id: u64) -> (SigningAlgo, Option<SessionSigning>) {
        let signing = self.signing();
        (signing.algo, signing.sessions.get(&session_id).copied())
    }

    pub fn alloc_async_id(&self) -> u64 {
        self.next_async_id.fetch_add(1, Ordering::Relaxed)
    }

    fn pending(&self) -> std::sync::MutexGuard<'_, HashMap<u64, Pending>> {
        self.pending.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Register a waiting request, linearized against its open's close: the
    /// entry is inserted and the owner's closed flag read under one pending
    /// critical section. A closed owner gets the entry back rather than a
    /// registration, and the caller answers it.
    pub(crate) fn register_pending(&self, async_id: u64, pending: Pending) -> Result<(), Pending> {
        let mut table = self.pending();
        let owner = pending.owner.clone();
        table.insert(async_id, pending);
        if owner.is_closed() {
            return Err(table
                .remove(&async_id)
                .expect("the entry was just inserted"));
        }
        Ok(())
    }

    /// Remove `async_id`'s entry, recording that no CANCEL or close status
    /// will arrive. Returns whether one was still registered. The waiter
    /// always owns the final response either way.
    pub(crate) fn take_pending(&self, async_id: u64) -> bool {
        self.pending().remove(&async_id).is_some()
    }

    /// CANCEL (MS-SMB2 §3.3.5.16): by AsyncId when the request carries one,
    /// otherwise by MessageId.
    pub fn cancel(&self, async_id: Option<u64>, message_id: u64) {
        let mut pending = self.pending();
        let key = async_id.or_else(|| {
            pending
                .iter()
                .find(|(_, p)| p.message_id == message_id)
                .map(|(k, _)| *k)
        });
        if let Some(p) = key.and_then(|k| pending.remove(&k)) {
            let _ = p.done.send(crate::ntstatus::STATUS_CANCELLED);
        }
    }

    /// The open `owner` closed: refuse it further acquisitions, drop its
    /// ranges, then finish every request waiting on it. The lock table's
    /// close comes first, so a registration either lands before the pending
    /// sweep (which finds it) or after it (and sees the closed owner).
    pub(crate) fn open_closed(&self, share: &ShareBindings, owner: &Arc<LockOwner>) {
        share.locks.close_owner(owner);
        let mut pending = self.pending();
        let keys: Vec<u64> = pending
            .iter()
            .filter(|(_, p)| Arc::ptr_eq(&p.owner, owner))
            .map(|(k, _)| *k)
            .collect();
        for key in keys {
            if let Some(p) = pending.remove(&key) {
                let _ = p.done.send(p.on_close);
            }
        }
    }

    /// Send a frame outside a request's own dispatch. Returns whether the
    /// writer accepted it; a missing slot or a closed channel is `false`,
    /// never an error.
    pub async fn send(&self, bytes: Vec<u8>) -> bool {
        let tx = self
            .writer
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        match tx {
            Some(tx) => tx.send(bytes).await.is_ok(),
            None => false,
        }
    }

    /// The connection ended: stop queueing waiters, close every open still in
    /// any session (releasing its locks and finishing its waiters), then drop
    /// what remains of the pending table. Handles are not closed here; they
    /// drop with the connection as before.
    pub async fn teardown(&self) {
        self.writer.lock().unwrap_or_else(|e| e.into_inner()).take();

        let sessions: Vec<_> = self.sessions.read().await.values().cloned().collect();
        for sess_arc in sessions {
            let sess = sess_arc.read().await;
            let trees: Vec<_> = sess.trees.read().await.values().cloned().collect();
            for tree_arc in trees {
                let tree = tree_arc.read().await;
                let opens: Vec<_> = tree.opens.read().await.values().cloned().collect();
                for open_arc in opens {
                    let open = open_arc.read().await;
                    self.open_closed(&tree.share, &open.lock_owner);
                }
            }
        }

        self.pending().clear();
    }

    pub fn alloc_session_id(&self) -> u64 {
        self.next_session_id.fetch_add(1, Ordering::Relaxed)
    }

    pub async fn close_session(&self, session_id: u64) -> bool {
        let removed = {
            let mut sessions = self.sessions.write().await;
            let removed = sessions.remove(&session_id);
            self.forget_session(session_id);
            removed
        };
        if let Some(sess_arc) = removed {
            close_session_state(self, &sess_arc).await;
            true
        } else {
            false
        }
    }

    pub async fn close_tree(&self, session_id: u64, tree_id: u32) -> bool {
        let sess_arc = {
            let sessions = self.sessions.read().await;
            sessions.get(&session_id).cloned()
        };
        let Some(sess_arc) = sess_arc else {
            return false;
        };
        remove_tree_from_session(self, &sess_arc, tree_id).await
    }

    pub async fn close_sessions_for_user(&self, user: &str) -> usize {
        let to_remove = {
            let sessions = self.sessions.read().await;
            let mut ids = Vec::new();
            for (session_id, sess_arc) in sessions.iter() {
                let sess = sess_arc.read().await;
                if matches!(&sess.identity, Identity::User { user: session_user, .. } if session_user == user)
                {
                    ids.push(*session_id);
                }
            }
            ids
        };

        let mut removed = 0;
        for session_id in to_remove {
            if self.close_session(session_id).await {
                removed += 1;
            }
        }
        removed
    }

    pub async fn close_trees_for_share(&self, share_name: &str) -> usize {
        self.close_matching_trees(|_, tree| tree.share.name.eq_ignore_ascii_case(share_name))
            .await
    }

    pub async fn close_trees_for_user_share(&self, user: &str, share_name: &str) -> usize {
        self.close_matching_trees(|sess, tree| {
            matches!(&sess.identity, Identity::User { user: session_user, .. } if session_user == user)
                && tree.share.name.eq_ignore_ascii_case(share_name)
        })
        .await
    }

    async fn close_matching_trees(
        &self,
        matches_tree: impl Fn(&Session, &TreeConnect) -> bool,
    ) -> usize {
        let sessions: Vec<_> = {
            let sessions = self.sessions.read().await;
            sessions.values().cloned().collect()
        };

        let mut removed = 0;
        for sess_arc in sessions {
            let tree_ids = {
                let sess = sess_arc.read().await;
                let trees = sess.trees.read().await;
                let mut ids = Vec::new();
                for (tree_id, tree_arc) in trees.iter() {
                    let tree = tree_arc.read().await;
                    if matches_tree(&sess, &tree) {
                        ids.push(*tree_id);
                    }
                }
                ids
            };

            for tree_id in tree_ids {
                if remove_tree_from_session(self, &sess_arc, tree_id).await {
                    removed += 1;
                }
            }
        }
        removed
    }
}

async fn close_session_state(conn: &Connection, sess_arc: &Arc<RwLock<Session>>) {
    let sess = sess_arc.write().await;
    let trees: Vec<_> = sess.trees.write().await.drain().collect();

    // Close every drained open's lock owner and pending requests across ALL
    // trees before the first backend close awaits. A backend that panics,
    // stalls or is cancelled while closing a handle can therefore only strand
    // handle-close work; no lock or waiter of this removed session is lost.
    let mut handles = Vec::new();
    for (_tree_id, tree_arc) in trees {
        let tree = tree_arc.write().await;
        handles.extend(drain_tree_opens(conn, &tree).await);
    }
    close_handles(handles).await;
}

async fn remove_tree_from_session(
    conn: &Connection,
    sess_arc: &Arc<RwLock<Session>>,
    tree_id: u32,
) -> bool {
    let removed = {
        let sess = sess_arc.read().await;
        let mut trees = sess.trees.write().await;
        trees.remove(&tree_id)
    };
    if let Some(tree_arc) = removed {
        close_tree_state(conn, &tree_arc).await;
        true
    } else {
        false
    }
}

async fn close_tree_state(conn: &Connection, tree_arc: &Arc<RwLock<TreeConnect>>) {
    let tree = tree_arc.write().await;
    let handles = drain_tree_opens(conn, &tree).await;
    // Owners are closed; no backend close should hold the removed tree's lock.
    drop(tree);
    close_handles(handles).await;
}

/// Drains `tree`'s opens, closing every owner's locks and pending requests
/// first, and returns the handles for a later best-effort close. The lock
/// work is synchronous and complete before the caller awaits any backend.
async fn drain_tree_opens(conn: &Connection, tree: &TreeConnect) -> Vec<Box<dyn Handle>> {
    let opens: Vec<_> = tree.opens.write().await.drain().collect();
    let mut handles = Vec::with_capacity(opens.len());
    for (_fid, open_arc) in opens {
        let mut open = open_arc.write().await;
        conn.open_closed(&tree.share, &open.lock_owner);
        if let Some(handle) = open.handle.take() {
            handles.push(handle);
        }
    }
    handles
}

/// Best-effort backend closes. A panic here unwinds only this loop: every
/// owner's locks and pending requests were already completed by the drain.
async fn close_handles(handles: Vec<Box<dyn Handle>>) {
    for handle in handles {
        let _ = handle.close().await;
    }
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

pub struct Session {
    pub id: u64,
    pub identity: Identity,
    pub session_base_key: [u8; 16],
    pub signing_key: [u8; 16],
    /// Whether signing is required for this session's traffic.
    pub signing_required: bool,
    pub trees: RwLock<HashMap<u32, Arc<RwLock<TreeConnect>>>>,
    /// 3.1.1: snapshot taken at SESSION_SETUP completion (after the request
    /// hash but before the response is hashed). Used as KDF context.
    pub preauth_snapshot: Option<[u8; 64]>,

    next_tree_id: AtomicU32,
}

impl Session {
    pub fn new(
        id: u64,
        identity: Identity,
        session_base_key: [u8; 16],
        signing_key: [u8; 16],
        signing_required: bool,
        preauth_snapshot: Option<[u8; 64]>,
    ) -> Self {
        Self {
            id,
            identity,
            session_base_key,
            signing_key,
            signing_required,
            trees: RwLock::new(HashMap::new()),
            preauth_snapshot,
            next_tree_id: AtomicU32::new(1),
        }
    }

    pub fn alloc_tree_id(&self) -> u32 {
        self.next_tree_id.fetch_add(1, Ordering::Relaxed)
    }

    pub fn is_anonymous(&self) -> bool {
        matches!(self.identity, Identity::Anonymous)
    }
}

// ---------------------------------------------------------------------------
// TreeConnect
// ---------------------------------------------------------------------------

pub struct TreeConnect {
    pub id: u32,
    pub share: Arc<ShareBindings>,
    pub granted_access: Access,
    pub opens: RwLock<HashMap<FileId, Arc<RwLock<Open>>>>,
    next_volatile: AtomicU64,
}

impl TreeConnect {
    pub fn new(id: u32, share: Arc<ShareBindings>, granted_access: Access) -> Self {
        Self {
            id,
            share,
            granted_access,
            opens: RwLock::new(HashMap::new()),
            next_volatile: AtomicU64::new(1),
        }
    }

    pub fn alloc_file_id(&self) -> FileId {
        let v = self.next_volatile.fetch_add(1, Ordering::Relaxed);
        FileId::new(v, v)
    }
}

// ---------------------------------------------------------------------------
// Open / DirCursor
// ---------------------------------------------------------------------------

pub struct Open {
    pub file_id: FileId,
    pub handle: Option<Box<dyn Handle>>,
    pub granted_access: Access,
    pub last_path: SmbPath,
    pub is_directory: bool,
    pub delete_on_close: bool,
    pub search_state: Option<DirCursor>,
    /// Owner of this open's byte-range locks and waiting requests; unique
    /// across the server.
    pub(crate) lock_owner: Arc<LockOwner>,
}

impl Open {
    pub fn new(
        file_id: FileId,
        handle: Box<dyn Handle>,
        granted_access: Access,
        last_path: SmbPath,
        is_directory: bool,
        delete_on_close: bool,
    ) -> Self {
        Self {
            file_id,
            handle: Some(handle),
            granted_access,
            last_path,
            is_directory,
            delete_on_close,
            search_state: None,
            lock_owner: LockOwner::new(),
        }
    }
}

/// Iterator state for a directory listing across multiple QUERY_DIRECTORY
/// calls. We snapshot the entries once and consume them in order; subsequent
/// calls advance `next` until exhaustion.
pub struct DirCursor {
    pub entries: Vec<crate::backend::DirEntry>,
    pub next: usize,
    /// The pattern fixed on the first scan; `RESTART_SCANS` resets `next`.
    pub pattern: Option<String>,
}
