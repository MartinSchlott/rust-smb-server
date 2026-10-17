//! Folder change notifications for SMB2 CHANGE_NOTIFY (MS-SMB2 §3.3.5.19).
//!
//! A backend that knows about changes made elsewhere hands the server a
//! [`ChangeNotifier`] (`ShareBackend::change_notifier`) and calls
//! [`ChangeNotifier::notify`] for each. Every directory open that has sent a
//! CHANGE_NOTIFY keeps a watch: changes collect there between requests, so
//! none is lost while the client re-arms, and a request that finds changes
//! waiting completes at once.

use std::sync::{Arc, Mutex, Weak};

use tokio::sync::Notify;

/// What happened to a name (MS-FSCC §2.7.1 `FILE_ACTION_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotifyAction {
    Added = 1,
    Removed = 2,
    /// Size, times, or attributes changed.
    Modified = 3,
    RenamedOld = 4,
    RenamedNew = 5,
}

/// One change to a name in a folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub action: NotifyAction,
    pub name: String,
    pub is_dir: bool,
}

/// Where a backend reports changes. Cheap to clone; every clone feeds the
/// same watches.
#[derive(Clone, Default)]
pub struct ChangeNotifier {
    watches: Arc<Mutex<Vec<Weak<Watch>>>>,
}

impl ChangeNotifier {
    pub fn new() -> Self {
        Self::default()
    }

    /// Report `changes` to names in folder `dir` (share-relative, `/`
    /// separated; `""` or `"/"` is the root). A same-folder rename is one call
    /// with `RenamedOld` then `RenamedNew`, so both reach the client in one
    /// completion; a move between folders is `Removed` in one and `Added` in
    /// the other. Never blocks; call it from inside a Tokio runtime.
    pub fn notify(&self, dir: &str, changes: &[Change]) {
        let dir = components(dir.split('/'));
        let mut watches = self.watches.lock().unwrap_or_else(|e| e.into_inner());
        watches.retain(|w| w.strong_count() > 0);
        for watch in watches.iter().filter_map(Weak::upgrade) {
            watch.push(&dir, changes);
        }
    }

    pub(crate) fn register(&self, watch: &Arc<Watch>) {
        self.watches
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(Arc::downgrade(watch));
    }
}

/// Names compare case-insensitively.
// shortcut: a case-sensitive share with two folders differing only in case
// over-notifies (the client re-lists one folder too many); harmless.
fn components<'a>(parts: impl Iterator<Item = &'a str>) -> Vec<String> {
    parts
        .filter(|p| !p.is_empty())
        .map(str::to_lowercase)
        .collect()
}

const FILE_NOTIFY_CHANGE_FILE_NAME: u32 = 0x1;
const FILE_NOTIFY_CHANGE_DIR_NAME: u32 = 0x2;
/// Beyond this many bytes of waiting changes the client is told to re-list
/// the folder (`STATUS_NOTIFY_ENUM_DIR`) instead.
const MAX_PENDING_BYTES: usize = 64 * 1024;

/// What a completed watch hands the client.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Completion {
    /// `FILE_NOTIFY_INFORMATION` entries.
    Changes(Vec<u8>),
    /// Too many to send: `STATUS_NOTIFY_ENUM_DIR`.
    EnumDir,
}

/// The watch of one directory open.
pub(crate) struct Watch {
    inner: Mutex<WatchState>,
    /// Woken when a change arrives.
    pub changed: Notify,
}

struct WatchState {
    dir: Vec<String>,
    tree: bool,
    filter: u32,
    entries: Vec<(u32, String)>,
    bytes: usize,
    overflow: bool,
}

impl Watch {
    pub fn new(dir: &[String]) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(WatchState {
                dir: components(dir.iter().map(String::as_str)),
                tree: false,
                filter: 0,
                entries: Vec::new(),
                bytes: 0,
                overflow: false,
            }),
            changed: Notify::new(),
        })
    }

    /// Each CHANGE_NOTIFY sets the filter and tree flag for what follows.
    pub fn arm(&self, filter: u32, tree: bool) {
        let mut s = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        s.filter = filter;
        s.tree = tree;
    }

    fn push(&self, dir: &[String], changes: &[Change]) {
        let mut s = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let prefix = if dir == s.dir.as_slice() {
            String::new()
        } else if s.tree && dir.len() > s.dir.len() && dir.starts_with(&s.dir) {
            // A tree watch names changes below it by their relative path.
            let mut p = dir[s.dir.len()..].join("\\");
            p.push('\\');
            p
        } else {
            return;
        };
        let mut added = false;
        for c in changes {
            let wanted = match c.action {
                NotifyAction::Modified => {
                    s.filter & !(FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME)
                }
                _ if c.is_dir => s.filter & FILE_NOTIFY_CHANGE_DIR_NAME,
                _ => s.filter & FILE_NOTIFY_CHANGE_FILE_NAME,
            };
            if wanted == 0 || s.overflow {
                continue;
            }
            let name = format!("{prefix}{}", c.name);
            s.bytes += 12 + name.len() * 2 + 3;
            s.entries.push((c.action as u32, name));
            if s.bytes > MAX_PENDING_BYTES {
                s.entries.clear();
                s.overflow = true;
            }
            added = true;
        }
        drop(s);
        if added {
            self.changed.notify_one();
        }
    }

    /// Take what has collected, for a client buffer of `max_out` bytes.
    /// `claim` runs first, under the watch lock, and may refuse (the request
    /// was already answered), leaving the changes for the next request.
    pub fn take(&self, max_out: u32, claim: impl FnOnce() -> bool) -> Option<Completion> {
        let mut s = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if (s.entries.is_empty() && !s.overflow) || !claim() {
            return None;
        }
        let entries = std::mem::take(&mut s.entries);
        let overflow = std::mem::replace(&mut s.overflow, false);
        s.bytes = 0;
        drop(s);
        let buf = encode(&entries);
        if overflow || buf.len() > max_out as usize {
            Some(Completion::EnumDir)
        } else {
            Some(Completion::Changes(buf))
        }
    }
}

/// `FILE_NOTIFY_INFORMATION` entries (MS-FSCC §2.7.1), each 4-byte aligned.
fn encode(entries: &[(u32, String)]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut last = 0;
    for (i, (action, name)) in entries.iter().enumerate() {
        if i > 0 {
            while out.len() % 4 != 0 {
                out.push(0);
            }
            let next = (out.len() - last) as u32;
            out[last..last + 4].copy_from_slice(&next.to_le_bytes());
        }
        last = out.len();
        let name: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&action.to_le_bytes());
        out.extend_from_slice(&(name.len() as u32).to_le_bytes());
        out.extend_from_slice(&name);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: u32 = 0xFFF;

    fn change(action: NotifyAction, name: &str, is_dir: bool) -> Change {
        Change {
            action,
            name: name.into(),
            is_dir,
        }
    }

    fn names(c: Option<Completion>) -> Vec<(u32, String)> {
        let Some(Completion::Changes(buf)) = c else {
            panic!("expected changes, got {c:?}");
        };
        let mut out = Vec::new();
        let mut at = 0;
        loop {
            let next = u32::from_le_bytes(buf[at..at + 4].try_into().unwrap()) as usize;
            let action = u32::from_le_bytes(buf[at + 4..at + 8].try_into().unwrap());
            let len = u32::from_le_bytes(buf[at + 8..at + 12].try_into().unwrap()) as usize;
            let units: Vec<u16> = buf[at + 12..at + 12 + len]
                .chunks(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            out.push((action, String::from_utf16(&units).unwrap()));
            if next == 0 {
                return out;
            }
            assert_eq!(next % 4, 0);
            at += next;
        }
    }

    #[test]
    fn changes_collect_between_requests_and_match_the_folder() {
        let n = ChangeNotifier::new();
        let w = Watch::new(&["Film".into()]);
        n.register(&w);
        w.arm(ALL, false);
        n.notify("/film", &[change(NotifyAction::Added, "a.mov", false)]);
        n.notify("/Film/sub", &[change(NotifyAction::Added, "deep", false)]);
        n.notify("/other", &[change(NotifyAction::Added, "x", false)]);
        n.notify(
            "Film/",
            &[
                change(NotifyAction::RenamedOld, "b", true),
                change(NotifyAction::RenamedNew, "c", true),
            ],
        );
        assert_eq!(
            names(w.take(4096, || true)),
            vec![(1, "a.mov".into()), (4, "b".into()), (5, "c".into())]
        );
        assert_eq!(w.take(4096, || true), None);
    }

    #[test]
    fn a_tree_watch_names_changes_below_it_by_relative_path() {
        let n = ChangeNotifier::new();
        let root = Watch::new(&[]);
        n.register(&root);
        root.arm(ALL, true);
        n.notify("/a/b", &[change(NotifyAction::Removed, "f", false)]);
        n.notify("/", &[change(NotifyAction::Added, "g", false)]);
        assert_eq!(
            names(root.take(4096, || true)),
            vec![(2, "a\\b\\f".into()), (1, "g".into())]
        );
    }

    #[test]
    fn the_filter_picks_file_names_dir_names_or_attributes() {
        let n = ChangeNotifier::new();
        let w = Watch::new(&[]);
        n.register(&w);
        // What macOS smbfs asks for: names, attributes, creation, security,
        // stream size and write. No SIZE or LAST_WRITE.
        w.arm(0x1 | 0x2 | 0x4 | 0x40 | 0x100 | 0x400 | 0x800, false);
        n.notify("", &[change(NotifyAction::Modified, "grew", false)]);
        assert_eq!(names(w.take(4096, || true)), vec![(3, "grew".into())]);
        w.arm(FILE_NOTIFY_CHANGE_DIR_NAME, false);
        n.notify("", &[change(NotifyAction::Added, "file", false)]);
        n.notify("", &[change(NotifyAction::Modified, "file", false)]);
        assert_eq!(w.take(4096, || true), None);
        n.notify("", &[change(NotifyAction::Added, "dir", true)]);
        assert_eq!(names(w.take(4096, || true)), vec![(1, "dir".into())]);
    }

    #[test]
    fn too_much_asks_the_client_to_relist() {
        let n = ChangeNotifier::new();
        let w = Watch::new(&[]);
        n.register(&w);
        w.arm(ALL, false);
        n.notify("", &[change(NotifyAction::Added, "abc", false)]);
        assert_eq!(w.take(8, || true), Some(Completion::EnumDir));
        let many: Vec<_> = (0..5000)
            .map(|i| change(NotifyAction::Added, &format!("file-{i}"), false))
            .collect();
        n.notify("", &many);
        assert_eq!(w.take(u32::MAX, || true), Some(Completion::EnumDir));
        // A refused claim leaves the changes for the next request.
        n.notify("", &[change(NotifyAction::Added, "kept", false)]);
        assert_eq!(w.take(4096, || false), None);
        assert_eq!(names(w.take(4096, || true)), vec![(1, "kept".into())]);
    }

    #[test]
    fn a_dropped_watch_is_forgotten() {
        let n = ChangeNotifier::new();
        drop({
            let w = Watch::new(&[]);
            n.register(&w);
            w
        });
        n.notify("", &[change(NotifyAction::Added, "x", false)]);
        assert!(n.watches.lock().unwrap().is_empty());
    }
}
