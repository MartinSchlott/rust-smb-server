//! Byte-range locks (MS-SMB2 §3.3.5.14), one in-memory table per share.
//!
//! The owner of a lock is an open (`Open::lock_owner`), as in SMB: two opens
//! of one file conflict even on the same connection. A lock is released by an
//! exact UNLOCK, or when its open closes (CLOSE, TREE_DISCONNECT, LOGOFF, or
//! the connection dropping). Locks are advisory: READ and WRITE do not check
//! them.
//!
//! Locks are keyed by the path at lock time, not by file identity: a file
//! renamed while locked starts a fresh lock set under its new name, and its
//! old locks stay with their owner until release. Hard links do not share
//! locks. Neither matters for clients that lock and unlock one path.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::Notify;

use crate::dispatch::Held;
use crate::ntstatus;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Range {
    pub offset: u64,
    pub length: u64,
    pub exclusive: bool,
}

impl Range {
    /// A range is `[offset, offset + length)`; one past `u64::MAX` is refused
    /// (`STATUS_INVALID_LOCK_RANGE`). A zero-length range overlaps nothing.
    pub fn new(offset: u64, length: u64, exclusive: bool) -> Result<Self, u32> {
        offset
            .checked_add(length)
            .ok_or(ntstatus::STATUS_INVALID_LOCK_RANGE)?;
        Ok(Self {
            offset,
            length,
            exclusive,
        })
    }

    fn overlaps(&self, other: &Range) -> bool {
        self.length > 0
            && other.length > 0
            && self.offset < other.offset + other.length
            && other.offset < self.offset + self.length
    }
}

/// The lifetime of one open's locks. Server-unique, so two opens of one file
/// are distinct owners even on the same connection.
pub(crate) struct LockOwner {
    id: u64,
    /// Written only while the table's `files` mutex is held, so an acquisition
    /// is linearized against the owner's close.
    closed: AtomicBool,
}

static NEXT_OWNER_ID: AtomicU64 = AtomicU64::new(1);

impl LockOwner {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            id: NEXT_OWNER_ID.fetch_add(1, Ordering::Relaxed),
            closed: AtomicBool::new(false),
        })
    }

    pub(crate) fn id(&self) -> u64 {
        self.id
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
}

struct Entry {
    id: u64,
    owner: Arc<LockOwner>,
    range: Range,
}

/// A held range. Dropping it removes exactly its own entry; `keep` commits it
/// to the client's ownership.
pub(crate) struct Grant {
    table: Arc<LockTableInner>,
    key: String,
    entry_id: u64,
    armed: bool,
}

impl Held for Grant {
    fn keep(mut self: Box<Self>) {
        self.armed = false;
    }
}

impl Drop for Grant {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut files = self.table.files.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(held) = files.get_mut(&self.key) {
            if let Some(index) = held.iter().position(|e| e.id == self.entry_id) {
                held.remove(index);
            }
            if held.is_empty() {
                files.remove(&self.key);
            }
        }
        drop(files);
        self.table.released.notify_waiters();
    }
}

#[derive(Default)]
struct LockTableInner {
    files: Mutex<HashMap<String, Vec<Entry>>>,
    /// Woken on every release so blocked LOCK requests retry.
    released: Notify,
    /// Source of table-unique entry ids, so a grant's rollback removes
    /// exactly the entry it inserted and never an older range of its owner.
    next_entry_id: AtomicU64,
}

/// The share's byte-range lock table. Cheap to clone: every clone drives the
/// same table.
#[derive(Clone, Default)]
pub(crate) struct LockTable {
    inner: Arc<LockTableInner>,
}

impl LockTable {
    /// Take every range or none (`STATUS_LOCK_NOT_GRANTED`). An exclusive
    /// range conflicts with any overlapping lock, the owner's own included; a
    /// shared one only with another owner's exclusive lock (Windows rules).
    /// Returns the table-unique ids of the inserted entries.
    pub(crate) fn try_lock(
        &self,
        key: &str,
        owner: &Arc<LockOwner>,
        ranges: &[Range],
    ) -> Result<Vec<u64>, u32> {
        let mut files = self.inner.files.lock().unwrap_or_else(|e| e.into_inner());
        if owner.is_closed() {
            return Err(ntstatus::STATUS_FILE_CLOSED);
        }
        let held = files.entry(key.to_string()).or_default();
        let before = held.len();
        let mut ids = Vec::with_capacity(ranges.len());
        for range in ranges {
            let conflict = held.iter().any(|h| {
                h.range.overlaps(range)
                    && (range.exclusive || (h.range.exclusive && !Arc::ptr_eq(&h.owner, owner)))
            });
            if conflict {
                held.truncate(before);
                if held.is_empty() {
                    files.remove(key);
                }
                return Err(ntstatus::STATUS_LOCK_NOT_GRANTED);
            }
            let id = self.inner.next_entry_id.fetch_add(1, Ordering::Relaxed);
            held.push(Entry {
                id,
                owner: owner.clone(),
                range: *range,
            });
            ids.push(id);
        }
        Ok(ids)
    }

    /// Wait until `range` can be taken, then take it. Drop the returned grant
    /// to give the range back; `keep` it to commit it. Returns
    /// `STATUS_FILE_CLOSED` once the owner has closed.
    pub(crate) async fn lock_wait(
        &self,
        key: &str,
        owner: Arc<LockOwner>,
        range: Range,
    ) -> Result<Grant, u32> {
        loop {
            let released = self.inner.released.notified();
            tokio::pin!(released);
            released.as_mut().enable();
            match self.try_lock(key, &owner, &[range]) {
                Ok(mut ids) => {
                    return Ok(Grant {
                        table: self.inner.clone(),
                        key: key.to_string(),
                        entry_id: ids.pop().expect("one range inserted"),
                        armed: true,
                    });
                }
                Err(ntstatus::STATUS_FILE_CLOSED) => {
                    return Err(ntstatus::STATUS_FILE_CLOSED);
                }
                Err(_) => {}
            }
            released.await;
        }
    }

    /// Remove locks that match exactly (offset and length), in order. The
    /// first that matches none fails with `STATUS_RANGE_NOT_LOCKED`; the
    /// ones before it stay unlocked. An unlock for an already-closed owner is
    /// a no-op: the close has already removed its ranges.
    pub(crate) fn unlock(
        &self,
        key: &str,
        owner: &Arc<LockOwner>,
        ranges: &[(u64, u64)],
    ) -> Result<(), u32> {
        let mut files = self.inner.files.lock().unwrap_or_else(|e| e.into_inner());
        if owner.is_closed() {
            return Ok(());
        }
        let mut result = Ok(());
        match files.get_mut(key) {
            Some(held) => {
                for &(offset, length) in ranges {
                    match held.iter().position(|h| {
                        Arc::ptr_eq(&h.owner, owner)
                            && h.range.offset == offset
                            && h.range.length == length
                    }) {
                        Some(index) => {
                            held.remove(index);
                        }
                        None => {
                            result = Err(ntstatus::STATUS_RANGE_NOT_LOCKED);
                            break;
                        }
                    }
                }
                if held.is_empty() {
                    files.remove(key);
                }
            }
            None => result = Err(ntstatus::STATUS_RANGE_NOT_LOCKED),
        }
        drop(files);
        self.inner.released.notify_waiters();
        result
    }

    /// The owner's open closed: refuse it every future acquisition, drop its
    /// ranges and wake the waiters, all in one `files` critical section.
    /// Idempotent.
    pub(crate) fn close_owner(&self, owner: &Arc<LockOwner>) {
        let mut files = self.inner.files.lock().unwrap_or_else(|e| e.into_inner());
        owner.closed.store(true, Ordering::Release);
        files.retain(|_, held| {
            held.retain(|h| !Arc::ptr_eq(&h.owner, owner));
            !held.is_empty()
        });
        drop(files);
        self.inner.released.notify_waiters();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn ex(offset: u64, length: u64) -> Range {
        Range::new(offset, length, true).unwrap()
    }
    fn sh(offset: u64, length: u64) -> Range {
        Range::new(offset, length, false).unwrap()
    }

    #[test]
    fn conflicts_follow_windows_rules() {
        let t = LockTable::default();
        let a = LockOwner::new();
        let b = LockOwner::new();
        t.try_lock("f", &a, &[sh(0, 10)]).unwrap();
        t.try_lock("f", &b, &[sh(5, 10)]).unwrap();
        assert_eq!(
            t.try_lock("f", &b, &[ex(9, 1)]),
            Err(ntstatus::STATUS_LOCK_NOT_GRANTED)
        );
        // Exclusive conflicts with the owner's own lock too.
        t.try_lock("g", &a, &[ex(0, 10)]).unwrap();
        assert!(t.try_lock("g", &a, &[ex(5, 1)]).is_err());
        // A shared lock under the owner's own exclusive one is allowed.
        t.try_lock("g", &a, &[sh(5, 1)]).unwrap();
        assert!(t.try_lock("g", &b, &[sh(5, 1)]).is_err());
        // Adjacent and zero-length ranges do not overlap; other files are apart.
        t.try_lock("g", &b, &[ex(10, 5), ex(3, 0)]).unwrap();
        t.try_lock("h", &b, &[ex(0, 10)]).unwrap();
        // The whole file, as macOS sends for flock().
        t.try_lock("i", &a, &[ex(0, u64::MAX)]).unwrap();
        assert!(t.try_lock("i", &b, &[sh(u64::MAX - 1, 1)]).is_err());
        assert_eq!(
            Range::new(1, u64::MAX, true),
            Err(ntstatus::STATUS_INVALID_LOCK_RANGE)
        );
    }

    #[test]
    fn a_refused_set_takes_nothing() {
        let t = LockTable::default();
        let a = LockOwner::new();
        let b = LockOwner::new();
        t.try_lock("f", &a, &[ex(20, 1)]).unwrap();
        assert!(t.try_lock("f", &b, &[ex(0, 1), ex(20, 1)]).is_err());
        t.try_lock("f", &b, &[ex(0, 1)]).unwrap();
    }

    #[test]
    fn unlock_must_match_exactly() {
        let t = LockTable::default();
        let a = LockOwner::new();
        let b = LockOwner::new();
        t.try_lock("f", &a, &[ex(0, 10)]).unwrap();
        assert_eq!(
            t.unlock("f", &a, &[(0, 5)]),
            Err(ntstatus::STATUS_RANGE_NOT_LOCKED)
        );
        assert_eq!(
            t.unlock("f", &b, &[(0, 10)]),
            Err(ntstatus::STATUS_RANGE_NOT_LOCKED)
        );
        t.unlock("f", &a, &[(0, 10)]).unwrap();
        assert!(t.unlock("f", &a, &[(0, 10)]).is_err());
        t.try_lock("f", &b, &[ex(0, 10)]).unwrap();
    }

    #[tokio::test]
    async fn a_waiter_gets_the_lock_when_released() {
        let t = Arc::new(LockTable::default());
        let a = LockOwner::new();
        let b = LockOwner::new();
        t.try_lock("f", &a, &[ex(0, 10)]).unwrap();
        let waiter = tokio::spawn({
            let t = t.clone();
            let b = b.clone();
            async move { t.lock_wait("f", b, ex(5, 1)).await.map(|_| ()) }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!waiter.is_finished());
        t.close_owner(&a);
        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(t.try_lock("f", &a, &[ex(5, 1)]).is_err());
        assert!(t.try_lock("f", &b, &[ex(5, 1)]).is_ok());
    }

    #[test]
    fn a_closed_owner_holds_nothing_and_is_refused() {
        let t = LockTable::default();
        let a = LockOwner::new();
        let b = LockOwner::new();
        t.try_lock("f", &a, &[ex(0, 10)]).unwrap();
        t.close_owner(&a);
        assert_eq!(
            t.try_lock("f", &a, &[ex(0, 10)]),
            Err(ntstatus::STATUS_FILE_CLOSED)
        );
        t.try_lock("f", &b, &[ex(0, 10)]).unwrap();
        // Idempotent.
        t.close_owner(&a);
        // An unlock for the closed owner is a no-op.
        assert_eq!(t.unlock("f", &a, &[(0, 10)]), Ok(()));
        assert_eq!(
            t.try_lock("f", &b, &[ex(0, 10)]),
            Err(ntstatus::STATUS_LOCK_NOT_GRANTED)
        );
    }

    #[tokio::test]
    async fn a_waiting_owner_closed_returns_file_closed() {
        let t = Arc::new(LockTable::default());
        let a = LockOwner::new();
        let b = LockOwner::new();
        t.try_lock("f", &a, &[ex(0, 10)]).unwrap();
        let waiter = tokio::spawn({
            let t = t.clone();
            let b = b.clone();
            async move { t.lock_wait("f", b, ex(5, 1)).await.map(|_| ()) }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!waiter.is_finished());
        t.close_owner(&b);
        let result = tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result, Err(ntstatus::STATUS_FILE_CLOSED));
    }

    #[tokio::test]
    async fn a_grant_rolls_back_unless_kept() {
        let t = LockTable::default();
        let a = LockOwner::new();
        let b = LockOwner::new();
        let grant = t.lock_wait("f", a.clone(), ex(0, 10)).await.unwrap();
        drop(grant);
        t.try_lock("f", &b, &[ex(0, 10)]).unwrap();
        t.unlock("f", &b, &[(0, 10)]).unwrap();

        let grant = t.lock_wait("f", a.clone(), ex(0, 10)).await.unwrap();
        Box::new(grant).keep();
        assert!(t.try_lock("f", &b, &[ex(0, 10)]).is_err());
        assert!(t.try_lock("f", &b, &[sh(0, 10)]).is_err());
    }

    #[tokio::test]
    async fn a_shared_grant_rolls_back_only_its_own_entry() {
        let t = LockTable::default();
        let a = LockOwner::new();
        let b = LockOwner::new();
        t.try_lock("f", &a, &[ex(0, 10)]).unwrap();
        let shared = t.lock_wait("f", a.clone(), sh(0, 10)).await.unwrap();
        drop(shared);
        // EX(0, 10) must survive the shared grant's rollback.
        assert!(t.try_lock("f", &b, &[sh(0, 10)]).is_err());
        assert!(t.try_lock("f", &b, &[ex(0, 10)]).is_err());
        t.unlock("f", &a, &[(0, 10)]).unwrap();
    }
}
