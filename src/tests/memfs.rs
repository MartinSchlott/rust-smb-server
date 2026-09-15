use std::collections::HashMap;
use std::sync::Mutex;

use crate::backend::{
    BackendCapabilities, DirEntry, FileInfo, FileTimes, Handle, OpenIntent, OpenOptions,
    ShareBackend,
};
use crate::error::{SmbError, SmbResult};
use crate::path::SmbPath;
use async_trait::async_trait;
use bytes::Bytes;

/// Minimal in-memory FS used by integration tests. Files are byte vectors,
/// directories are sets of names. Not threadsafe across workers — only used
/// within one test.
pub struct MemFsBackend {
    inner: std::sync::Arc<Mutex<MemInner>>,
}

#[derive(Default)]
struct MemInner {
    files: HashMap<String, Vec<u8>>,
    /// All directories present (always includes "" for the root). Each
    /// directory is keyed by canonical path string.
    dirs: HashMap<String, ()>,
    /// Named-stream content, keyed by (host file's canonical path, stream
    /// name) — stored independently of `files` so a stream write can never
    /// touch the primary data stream.
    streams: HashMap<(String, String), Vec<u8>>,
}

impl Default for MemFsBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl MemFsBackend {
    pub fn new() -> Self {
        let mut inner = MemInner::default();
        inner.dirs.insert(String::new(), ());
        Self {
            inner: std::sync::Arc::new(Mutex::new(inner)),
        }
    }

    pub fn with_file(self, path: &str, contents: &[u8]) -> Self {
        {
            let mut g = self.inner.lock().unwrap();
            g.files.insert(path.to_string(), contents.to_vec());
        }
        self
    }
}

fn key(path: &SmbPath) -> String {
    path.display_backslash()
}

/// `true` if any file or directory is an immediate or deeper child of
/// `dir_key` — mirrors `MemHandle::list_dir`'s own prefix convention
/// (`"{dir}\\"`), so "non-empty" here means exactly what a listing would
/// show.
fn has_children(inner: &MemInner, dir_key: &str) -> bool {
    let prefix = format!("{dir_key}\\");
    inner.files.keys().any(|k| k.starts_with(&prefix))
        || inner.dirs.keys().any(|k| k.starts_with(&prefix))
}

#[async_trait]
impl ShareBackend for MemFsBackend {
    async fn open(&self, path: &SmbPath, opts: OpenOptions) -> SmbResult<Box<dyn Handle>> {
        let k = key(path);
        let mut g = self.inner.lock().unwrap();
        let exists_file = g.files.contains_key(&k);
        let exists_dir = g.dirs.contains_key(&k);

        if let Some(stream) = path.stream_name() {
            // The stream selector (`file.txt:AFP_AfpInfo`) always resolves
            // to `$DATA` type at this point — `SmbPath` rejects any other
            // type — so it can only ever address a file's stream, never a
            // directory's.
            if exists_dir {
                return Err(SmbError::IsDirectory);
            }
            if !exists_file {
                return Err(SmbError::NotFound);
            }
            let sk = (k.clone(), stream.to_string());
            let exists_stream = g.streams.contains_key(&sk);
            match opts.intent {
                OpenIntent::Open => {
                    if !exists_stream {
                        return Err(SmbError::NotFound);
                    }
                }
                OpenIntent::Create => {
                    if exists_stream {
                        return Err(SmbError::Exists);
                    }
                    g.streams.insert(sk.clone(), Vec::new());
                }
                OpenIntent::OpenOrCreate => {
                    g.streams.entry(sk.clone()).or_default();
                }
                OpenIntent::Truncate => {
                    if !exists_stream {
                        return Err(SmbError::NotFound);
                    }
                    g.streams.insert(sk.clone(), Vec::new());
                }
                OpenIntent::OverwriteOrCreate => {
                    g.streams.insert(sk.clone(), Vec::new());
                }
            }
            return Ok(Box::new(MemHandle::stream(
                self.inner.clone(),
                k,
                stream.to_string(),
            )));
        }

        if opts.directory {
            if exists_file {
                return Err(SmbError::NotADirectory);
            }
            if !exists_dir {
                if matches!(opts.intent, OpenIntent::Create | OpenIntent::OpenOrCreate) {
                    g.dirs.insert(k.clone(), ());
                } else {
                    return Err(SmbError::NotFound);
                }
            }
            return Ok(Box::new(MemHandle::dir(self.inner.clone(), k)));
        }

        if exists_dir {
            return Err(SmbError::IsDirectory);
        }
        match opts.intent {
            OpenIntent::Open => {
                if !exists_file {
                    return Err(SmbError::NotFound);
                }
            }
            OpenIntent::Create => {
                if exists_file {
                    return Err(SmbError::Exists);
                }
                g.files.insert(k.clone(), Vec::new());
            }
            OpenIntent::OpenOrCreate => {
                g.files.entry(k.clone()).or_default();
            }
            OpenIntent::Truncate => {
                if !exists_file {
                    return Err(SmbError::NotFound);
                }
                g.files.insert(k.clone(), Vec::new());
            }
            OpenIntent::OverwriteOrCreate => {
                g.files.insert(k.clone(), Vec::new());
            }
        }
        Ok(Box::new(MemHandle::file(self.inner.clone(), k)))
    }

    async fn unlink(&self, path: &SmbPath) -> SmbResult<()> {
        let k = key(path);
        let mut g = self.inner.lock().unwrap();
        if g.files.remove(&k).is_some() {
            g.streams.retain(|(fk, _), _| fk != &k);
            return Ok(());
        }
        if g.dirs.remove(&k).is_some() {
            return Ok(());
        }
        Err(SmbError::NotFound)
    }

    async fn rename(&self, from: &SmbPath, to: &SmbPath, replace: bool) -> SmbResult<()> {
        let kf = key(from);
        let kt = key(to);
        let mut g = self.inner.lock().unwrap();

        // Source existence/kind MUST be settled before any destination
        // mutation: an absent `from` must leave an existing `to` untouched,
        // not be discovered only after `to` has already been removed.
        let src_is_dir = g.dirs.contains_key(&kf);
        let src_is_file = g.files.contains_key(&kf);
        if !src_is_dir && !src_is_file {
            return Err(SmbError::NotFound);
        }

        let dest_is_file = g.files.contains_key(&kt);
        let dest_is_dir = g.dirs.contains_key(&kt);
        if dest_is_file || dest_is_dir {
            if !replace {
                return Err(SmbError::Exists);
            }
            if kf == kt {
                // POSIX rename(2): identical source and destination is a
                // successful no-op. Without this, the destination-removal
                // below deletes the one entry that is both source and
                // destination, and the re-insert further down never finds
                // it under `kf` again.
                return Ok(());
            }
            // `replace == true`: mirror Unix `rename(2)` semantics — kind
            // mismatches and a non-empty directory target are rejected;
            // otherwise the destination entry is removed first so the
            // insert below never leaves a stale sibling entry (a file and
            // a directory both present under the same key).
            if src_is_dir && dest_is_file {
                return Err(SmbError::NotADirectory);
            }
            if !src_is_dir && dest_is_dir {
                return Err(SmbError::IsDirectory);
            }
            if dest_is_dir && has_children(&g, &kt) {
                return Err(SmbError::NotEmpty);
            }
            g.files.remove(&kt);
            g.dirs.remove(&kt);
        }

        if let Some(data) = g.files.remove(&kf) {
            g.files.insert(kt.clone(), data);
            let stream_keys: Vec<String> = g
                .streams
                .keys()
                .filter(|(fk, _)| fk == &kf)
                .map(|(_, sn)| sn.clone())
                .collect();
            for sn in stream_keys {
                if let Some(data) = g.streams.remove(&(kf.clone(), sn.clone())) {
                    g.streams.insert((kt.clone(), sn), data);
                }
            }
            return Ok(());
        }
        if g.dirs.remove(&kf).is_some() {
            g.dirs.insert(kt, ());
            return Ok(());
        }
        unreachable!("src_is_dir/src_is_file already confirmed one of these branches taken")
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            is_read_only: false,
            case_sensitive: false,
            supports_named_streams: true,
        }
    }
}

pub struct MemHandle {
    inner: std::sync::Arc<Mutex<MemInner>>,
    key: String,
    is_dir: bool,
    /// Set for a named-stream handle — reads/writes/truncate then address
    /// `MemInner::streams` under `(key, stream)` instead of `files[key]`.
    stream: Option<String>,
}

impl MemHandle {
    fn file(inner: std::sync::Arc<Mutex<MemInner>>, key: String) -> Self {
        Self {
            inner,
            key,
            is_dir: false,
            stream: None,
        }
    }

    fn dir(inner: std::sync::Arc<Mutex<MemInner>>, key: String) -> Self {
        Self {
            inner,
            key,
            is_dir: true,
            stream: None,
        }
    }

    fn stream(inner: std::sync::Arc<Mutex<MemInner>>, key: String, stream: String) -> Self {
        Self {
            inner,
            key,
            is_dir: false,
            stream: Some(stream),
        }
    }
}

#[async_trait]
impl Handle for MemHandle {
    async fn read(&self, offset: u64, len: u32) -> SmbResult<Bytes> {
        if self.is_dir {
            return Err(SmbError::IsDirectory);
        }
        let g = self.inner.lock().unwrap();
        let data = match &self.stream {
            Some(s) => g
                .streams
                .get(&(self.key.clone(), s.clone()))
                .ok_or(SmbError::NotFound)?,
            None => g.files.get(&self.key).ok_or(SmbError::NotFound)?,
        };
        let start = offset as usize;
        if start >= data.len() {
            return Ok(Bytes::new());
        }
        let end = (start + len as usize).min(data.len());
        Ok(Bytes::copy_from_slice(&data[start..end]))
    }

    async fn write(&self, offset: u64, data: &[u8]) -> SmbResult<u32> {
        if self.is_dir {
            return Err(SmbError::IsDirectory);
        }
        let mut g = self.inner.lock().unwrap();
        let buf = match &self.stream {
            Some(s) => g
                .streams
                .get_mut(&(self.key.clone(), s.clone()))
                .ok_or(SmbError::NotFound)?,
            None => g.files.get_mut(&self.key).ok_or(SmbError::NotFound)?,
        };
        let needed = (offset as usize) + data.len();
        if buf.len() < needed {
            buf.resize(needed, 0);
        }
        buf[offset as usize..offset as usize + data.len()].copy_from_slice(data);
        Ok(data.len() as u32)
    }

    async fn flush(&self) -> SmbResult<()> {
        Ok(())
    }

    async fn stat(&self) -> SmbResult<FileInfo> {
        let g = self.inner.lock().unwrap();
        let size = if self.is_dir {
            0
        } else {
            match &self.stream {
                Some(s) => g
                    .streams
                    .get(&(self.key.clone(), s.clone()))
                    .ok_or(SmbError::NotFound)?
                    .len() as u64,
                None => g.files.get(&self.key).ok_or(SmbError::NotFound)?.len() as u64,
            }
        };
        let name = self
            .key
            .rsplit_once('\\')
            .map(|(_, n)| n.to_string())
            .unwrap_or_else(|| self.key.clone());
        Ok(FileInfo {
            name,
            end_of_file: size,
            allocation_size: size,
            creation_time: 0x01D9_0000_0000_0000,
            last_access_time: 0x01D9_0000_0000_0000,
            last_write_time: 0x01D9_0000_0000_0000,
            change_time: 0x01D9_0000_0000_0000,
            is_directory: self.is_dir,
            file_index: 0,
        })
    }

    async fn set_times(&self, _times: FileTimes) -> SmbResult<()> {
        Ok(())
    }

    async fn truncate(&self, len: u64) -> SmbResult<()> {
        if self.is_dir {
            return Err(SmbError::IsDirectory);
        }
        let mut g = self.inner.lock().unwrap();
        let buf = match &self.stream {
            Some(s) => g
                .streams
                .get_mut(&(self.key.clone(), s.clone()))
                .ok_or(SmbError::NotFound)?,
            None => g.files.get_mut(&self.key).ok_or(SmbError::NotFound)?,
        };
        buf.resize(len as usize, 0);
        Ok(())
    }

    async fn list_dir(&self, _pattern: Option<&str>) -> SmbResult<Vec<DirEntry>> {
        if !self.is_dir {
            return Err(SmbError::NotADirectory);
        }
        let g = self.inner.lock().unwrap();
        let prefix = if self.key.is_empty() {
            String::new()
        } else {
            format!("{}\\", self.key)
        };
        let mut entries = Vec::new();
        for (k, v) in g.files.iter() {
            if let Some(rest) = k.strip_prefix(&prefix)
                && !rest.contains('\\')
            {
                entries.push(DirEntry {
                    info: FileInfo {
                        name: rest.to_string(),
                        end_of_file: v.len() as u64,
                        allocation_size: v.len() as u64,
                        creation_time: 0x01D9_0000_0000_0000,
                        last_access_time: 0x01D9_0000_0000_0000,
                        last_write_time: 0x01D9_0000_0000_0000,
                        change_time: 0x01D9_0000_0000_0000,
                        is_directory: false,
                        file_index: 0,
                    },
                });
            }
        }
        for k in g.dirs.keys() {
            if let Some(rest) = k.strip_prefix(&prefix)
                && !rest.is_empty()
                && !rest.contains('\\')
            {
                entries.push(DirEntry {
                    info: FileInfo {
                        name: rest.to_string(),
                        end_of_file: 0,
                        allocation_size: 0,
                        creation_time: 0x01D9_0000_0000_0000,
                        last_access_time: 0x01D9_0000_0000_0000,
                        last_write_time: 0x01D9_0000_0000_0000,
                        change_time: 0x01D9_0000_0000_0000,
                        is_directory: true,
                        file_index: 0,
                    },
                });
            }
        }
        Ok(entries)
    }

    async fn close(self: Box<Self>) -> SmbResult<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> SmbPath {
        s.parse().unwrap()
    }

    #[tokio::test]
    async fn replace_false_rejects_existing_destination() {
        let fs = MemFsBackend::new()
            .with_file("src.txt", b"new")
            .with_file("dst.txt", b"old");
        let err = fs
            .rename(&p("src.txt"), &p("dst.txt"), false)
            .await
            .unwrap_err();
        assert!(matches!(err, SmbError::Exists));
        // Destination untouched.
        assert_eq!(
            fs.inner.lock().unwrap().files.get("dst.txt"),
            Some(&b"old".to_vec())
        );
    }

    #[tokio::test]
    async fn replace_true_missing_source_leaves_existing_destination_untouched() {
        // Only the destination exists — `from` is absent. Even with
        // replace=true this must fail NotFound and must not first remove
        // the destination while discovering that.
        let fs = MemFsBackend::new().with_file("dst.txt", b"untouched");
        let err = fs
            .rename(&p("src.txt"), &p("dst.txt"), true)
            .await
            .unwrap_err();
        assert!(matches!(err, SmbError::NotFound), "got {err:?}");
        assert_eq!(
            fs.inner.lock().unwrap().files.get("dst.txt"),
            Some(&b"untouched".to_vec()),
            "the destination must survive a rename whose source never existed"
        );
    }

    #[tokio::test]
    async fn replace_true_self_rename_of_a_file_is_a_successful_no_op() {
        let fs = MemFsBackend::new().with_file("same.txt", b"data");
        fs.rename(&p("same.txt"), &p("same.txt"), true)
            .await
            .expect("identical source and destination must succeed as a no-op");
        assert_eq!(
            fs.inner.lock().unwrap().files.get("same.txt"),
            Some(&b"data".to_vec()),
            "content must be unchanged"
        );
    }

    #[tokio::test]
    async fn replace_true_self_rename_of_a_directory_is_a_successful_no_op() {
        let fs = MemFsBackend::new();
        {
            let mut inner = fs.inner.lock().unwrap();
            inner.dirs.insert("same_dir".to_string(), ());
        }
        fs.rename(&p("same_dir"), &p("same_dir"), true)
            .await
            .expect("identical source and destination must succeed as a no-op");
        assert!(fs.inner.lock().unwrap().dirs.contains_key("same_dir"));
    }

    #[tokio::test]
    async fn replace_false_self_rename_is_still_exists() {
        // The trait contract's `replace=false` branch fires on "does `to`
        // exist" — it must not special-case `from == to` as a no-op.
        let fs = MemFsBackend::new().with_file("same.txt", b"data");
        let err = fs
            .rename(&p("same.txt"), &p("same.txt"), false)
            .await
            .unwrap_err();
        assert!(matches!(err, SmbError::Exists), "got {err:?}");
    }

    #[tokio::test]
    async fn replace_true_replaces_existing_file_without_a_stale_sibling() {
        let fs = MemFsBackend::new()
            .with_file("src.txt", b"new")
            .with_file("dst.txt", b"old");
        fs.rename(&p("src.txt"), &p("dst.txt"), true).await.unwrap();
        let inner = fs.inner.lock().unwrap();
        assert_eq!(inner.files.get("dst.txt"), Some(&b"new".to_vec()));
        assert!(!inner.files.contains_key("src.txt"));
        assert!(!inner.dirs.contains_key("dst.txt"));
    }

    #[tokio::test]
    async fn replace_true_rejects_directory_over_file_kind_mismatch() {
        let fs = MemFsBackend::new().with_file("dst.txt", b"x");
        fs.open(
            &p("src_dir"),
            OpenOptions {
                directory: true,
                intent: OpenIntent::Create,
                ..Default::default()
            },
        )
        .await
        .unwrap();

        let err = fs
            .rename(&p("src_dir"), &p("dst.txt"), true)
            .await
            .unwrap_err();
        assert!(matches!(err, SmbError::NotADirectory), "got {err:?}");
        // Neither side must have been mutated.
        let inner = fs.inner.lock().unwrap();
        assert!(inner.dirs.contains_key("src_dir"));
        assert_eq!(inner.files.get("dst.txt"), Some(&b"x".to_vec()));
    }

    #[tokio::test]
    async fn replace_true_rejects_file_over_directory_kind_mismatch() {
        let fs = MemFsBackend::new().with_file("src.txt", b"x");
        fs.open(
            &p("dst_dir"),
            OpenOptions {
                directory: true,
                intent: OpenIntent::Create,
                ..Default::default()
            },
        )
        .await
        .unwrap();

        let err = fs
            .rename(&p("src.txt"), &p("dst_dir"), true)
            .await
            .unwrap_err();
        assert!(matches!(err, SmbError::IsDirectory), "got {err:?}");
        let inner = fs.inner.lock().unwrap();
        assert!(inner.files.contains_key("src.txt"));
        assert!(inner.dirs.contains_key("dst_dir"));
    }

    #[tokio::test]
    async fn replace_true_rejects_non_empty_directory_target() {
        let fs = MemFsBackend::new()
            .with_file("src_dir\\inside_src", b"x")
            .with_file("dst_dir\\inside_dst", b"y");
        {
            let mut inner = fs.inner.lock().unwrap();
            inner.dirs.insert("src_dir".to_string(), ());
            inner.dirs.insert("dst_dir".to_string(), ());
        }

        let err = fs
            .rename(&p("src_dir"), &p("dst_dir"), true)
            .await
            .unwrap_err();
        assert!(matches!(err, SmbError::NotEmpty), "got {err:?}");
    }

    #[tokio::test]
    async fn replace_true_replaces_an_empty_directory() {
        let fs = MemFsBackend::new();
        {
            let mut inner = fs.inner.lock().unwrap();
            inner.dirs.insert("src_dir".to_string(), ());
            inner.dirs.insert("dst_dir".to_string(), ());
        }

        fs.rename(&p("src_dir"), &p("dst_dir"), true).await.unwrap();
        let inner = fs.inner.lock().unwrap();
        assert!(!inner.dirs.contains_key("src_dir"));
        assert!(inner.dirs.contains_key("dst_dir"));
    }

    // ── Named streams ───────────────────────────────────────────────────

    fn opts_create() -> OpenOptions {
        OpenOptions {
            read: true,
            write: true,
            intent: OpenIntent::Create,
            directory: false,
            non_directory: false,
            delete_on_close: false,
            read_data: true,
            write_data: true,
        }
    }

    fn opts_open_or_create() -> OpenOptions {
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

    #[tokio::test]
    async fn stream_write_never_touches_the_main_file() {
        let fs = MemFsBackend::new().with_file("new.txt", b"fresh");

        let h = fs
            .open(&p("new.txt:AFP_AfpInfo"), opts_create())
            .await
            .expect("stream create must succeed once the host file exists");
        h.write(0, b"finder info blob").await.unwrap();
        h.close().await.unwrap();

        assert_eq!(
            fs.inner.lock().unwrap().files.get("new.txt"),
            Some(&b"fresh".to_vec()),
            "a stream write must never mutate the primary data stream"
        );
        assert_eq!(
            fs.inner
                .lock()
                .unwrap()
                .streams
                .get(&("new.txt".to_string(), "AFP_AfpInfo".to_string())),
            Some(&b"finder info blob".to_vec())
        );
    }

    #[tokio::test]
    async fn stream_open_on_missing_host_file_is_not_found() {
        let fs = MemFsBackend::new();
        let err = match fs.open(&p("ghost.txt:AFP_AfpInfo"), opts_create()).await {
            Err(e) => e,
            Ok(_) => panic!("expected an error"),
        };
        assert!(matches!(err, SmbError::NotFound), "got {err:?}");
    }

    #[tokio::test]
    async fn stream_open_on_a_directory_is_is_directory() {
        let fs = MemFsBackend::new();
        {
            let mut inner = fs.inner.lock().unwrap();
            inner.dirs.insert("adir".to_string(), ());
        }
        let err = match fs.open(&p("adir:AFP_AfpInfo"), opts_create()).await {
            Err(e) => e,
            Ok(_) => panic!("expected an error"),
        };
        assert!(matches!(err, SmbError::IsDirectory), "got {err:?}");
    }

    #[tokio::test]
    async fn distinct_stream_names_on_the_same_file_do_not_collide() {
        let fs = MemFsBackend::new().with_file("new.txt", b"fresh");

        let a = fs
            .open(&p("new.txt:AFP_AfpInfo"), opts_open_or_create())
            .await
            .unwrap();
        a.write(0, b"aaaa").await.unwrap();
        a.close().await.unwrap();

        let b = fs
            .open(&p("new.txt:com.apple.ResourceFork"), opts_open_or_create())
            .await
            .unwrap();
        b.write(0, b"bbbb").await.unwrap();
        b.close().await.unwrap();

        let inner = fs.inner.lock().unwrap();
        assert_eq!(
            inner
                .streams
                .get(&("new.txt".to_string(), "AFP_AfpInfo".to_string())),
            Some(&b"aaaa".to_vec())
        );
        assert_eq!(
            inner
                .streams
                .get(&("new.txt".to_string(), "com.apple.ResourceFork".to_string())),
            Some(&b"bbbb".to_vec())
        );
    }

    #[tokio::test]
    async fn unlink_removes_the_file_and_its_streams() {
        let fs = MemFsBackend::new().with_file("new.txt", b"fresh");
        let h = fs
            .open(&p("new.txt:AFP_AfpInfo"), opts_create())
            .await
            .unwrap();
        h.write(0, b"x").await.unwrap();
        h.close().await.unwrap();

        fs.unlink(&p("new.txt")).await.unwrap();

        let inner = fs.inner.lock().unwrap();
        assert!(!inner.files.contains_key("new.txt"));
        assert!(
            !inner.streams.keys().any(|(fk, _)| fk == "new.txt"),
            "streams must not outlive the file they're attached to"
        );
    }

    #[tokio::test]
    async fn rename_carries_streams_to_the_new_name() {
        let fs = MemFsBackend::new().with_file("old.txt", b"fresh");
        let h = fs
            .open(&p("old.txt:AFP_AfpInfo"), opts_create())
            .await
            .unwrap();
        h.write(0, b"meta").await.unwrap();
        h.close().await.unwrap();

        fs.rename(&p("old.txt"), &p("new.txt"), false)
            .await
            .unwrap();

        let inner = fs.inner.lock().unwrap();
        assert!(
            !inner
                .streams
                .contains_key(&("old.txt".to_string(), "AFP_AfpInfo".to_string()))
        );
        assert_eq!(
            inner
                .streams
                .get(&("new.txt".to_string(), "AFP_AfpInfo".to_string())),
            Some(&b"meta".to_vec())
        );
    }
}
