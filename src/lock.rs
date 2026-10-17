//! Byte-range locks (MS-SMB2 §3.3.5.14), one in-memory table per share.
//!
//! The owner of a lock is an open (`Open::lock_owner`), as in SMB: two opens
//! of one file conflict even on the same connection. A lock is released by an
//! exact UNLOCK, or when its open closes (CLOSE, TREE_DISCONNECT, LOGOFF, or
//! the connection dropping). Locks are advisory: READ and WRITE do not check
//! them.
//
// shortcut: locks are keyed by the path at lock time, so a file renamed while
// locked starts a fresh lock set under its new name; key by file id if a
// client ever holds locks across a rename.

use std::collections::HashMap;
use std::sync::Mutex;

use tokio::sync::Notify;

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

#[derive(Debug, Clone, Copy)]
struct Held {
    owner: u64,
    range: Range,
}

#[derive(Default)]
pub(crate) struct LockTable {
    files: Mutex<HashMap<String, Vec<Held>>>,
    /// Woken on every release so blocked LOCK requests retry.
    released: Notify,
}

impl LockTable {
    /// Take every range or none (`STATUS_LOCK_NOT_GRANTED`). An exclusive
    /// range conflicts with any overlapping lock, the owner's own included; a
    /// shared one only with another owner's exclusive lock (Windows rules).
    pub fn try_lock(&self, key: &str, owner: u64, ranges: &[Range]) -> Result<(), u32> {
        let mut files = self.files.lock().unwrap_or_else(|e| e.into_inner());
        let held = files.entry(key.to_string()).or_default();
        let before = held.len();
        for range in ranges {
            let conflict = held.iter().any(|h| {
                h.range.overlaps(range)
                    && (range.exclusive || (h.range.exclusive && h.owner != owner))
            });
            if conflict {
                held.truncate(before);
                if held.is_empty() {
                    files.remove(key);
                }
                return Err(ntstatus::STATUS_LOCK_NOT_GRANTED);
            }
            held.push(Held {
                owner,
                range: *range,
            });
        }
        Ok(())
    }

    /// Wait until `range` can be taken, then take it. Cancel by dropping the
    /// future.
    pub async fn lock_wait(&self, key: &str, owner: u64, range: Range) {
        loop {
            let released = self.released.notified();
            tokio::pin!(released);
            released.as_mut().enable();
            if self.try_lock(key, owner, &[range]).is_ok() {
                return;
            }
            released.await;
        }
    }

    /// Remove locks that match exactly (offset and length), in order. The
    /// first that matches none fails with `STATUS_RANGE_NOT_LOCKED`; the
    /// ones before it stay unlocked.
    pub fn unlock(&self, key: &str, owner: u64, ranges: &[(u64, u64)]) -> Result<(), u32> {
        let mut files = self.files.lock().unwrap_or_else(|e| e.into_inner());
        let mut result = Ok(());
        if let Some(held) = files.get_mut(key) {
            for &(offset, length) in ranges {
                match held.iter().position(|h| {
                    h.owner == owner && h.range.offset == offset && h.range.length == length
                }) {
                    Some(i) => {
                        held.remove(i);
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
        } else {
            result = Err(ntstatus::STATUS_RANGE_NOT_LOCKED);
        }
        drop(files);
        self.released.notify_waiters();
        result
    }

    /// Drop every lock `owner` holds (its open closed).
    pub fn release_owner(&self, owner: u64) {
        let mut files = self.files.lock().unwrap_or_else(|e| e.into_inner());
        files.retain(|_, held| {
            held.retain(|h| h.owner != owner);
            !held.is_empty()
        });
        drop(files);
        self.released.notify_waiters();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
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
        t.try_lock("f", 1, &[sh(0, 10)]).unwrap();
        t.try_lock("f", 2, &[sh(5, 10)]).unwrap();
        assert_eq!(
            t.try_lock("f", 2, &[ex(9, 1)]),
            Err(ntstatus::STATUS_LOCK_NOT_GRANTED)
        );
        // Exclusive conflicts with the owner's own lock too.
        t.try_lock("g", 1, &[ex(0, 10)]).unwrap();
        assert!(t.try_lock("g", 1, &[ex(5, 1)]).is_err());
        // A shared lock under the owner's own exclusive one is allowed.
        t.try_lock("g", 1, &[sh(5, 1)]).unwrap();
        assert!(t.try_lock("g", 2, &[sh(5, 1)]).is_err());
        // Adjacent and zero-length ranges do not overlap; other files are apart.
        t.try_lock("g", 2, &[ex(10, 5), ex(3, 0)]).unwrap();
        t.try_lock("h", 2, &[ex(0, 10)]).unwrap();
        // The whole file, as macOS sends for flock().
        t.try_lock("i", 1, &[ex(0, u64::MAX)]).unwrap();
        assert!(t.try_lock("i", 2, &[sh(u64::MAX - 1, 1)]).is_err());
        assert_eq!(
            Range::new(1, u64::MAX, true),
            Err(ntstatus::STATUS_INVALID_LOCK_RANGE)
        );
    }

    #[test]
    fn a_refused_set_takes_nothing() {
        let t = LockTable::default();
        t.try_lock("f", 1, &[ex(20, 1)]).unwrap();
        assert!(t.try_lock("f", 2, &[ex(0, 1), ex(20, 1)]).is_err());
        t.try_lock("f", 3, &[ex(0, 1)]).unwrap();
    }

    #[test]
    fn unlock_must_match_exactly() {
        let t = LockTable::default();
        t.try_lock("f", 1, &[ex(0, 10)]).unwrap();
        assert_eq!(
            t.unlock("f", 1, &[(0, 5)]),
            Err(ntstatus::STATUS_RANGE_NOT_LOCKED)
        );
        assert_eq!(
            t.unlock("f", 2, &[(0, 10)]),
            Err(ntstatus::STATUS_RANGE_NOT_LOCKED)
        );
        t.unlock("f", 1, &[(0, 10)]).unwrap();
        assert!(t.unlock("f", 1, &[(0, 10)]).is_err());
        t.try_lock("f", 2, &[ex(0, 10)]).unwrap();
    }

    #[tokio::test]
    async fn a_waiter_gets_the_lock_when_released() {
        let t = Arc::new(LockTable::default());
        t.try_lock("f", 1, &[ex(0, 10)]).unwrap();
        let waiter = tokio::spawn({
            let t = t.clone();
            async move { t.lock_wait("f", 2, ex(5, 1)).await }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!waiter.is_finished());
        t.release_owner(1);
        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .unwrap()
            .unwrap();
        assert!(t.try_lock("f", 1, &[ex(5, 1)]).is_err());
    }
}
