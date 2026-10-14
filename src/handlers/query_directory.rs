//! QUERY_DIRECTORY handler.

use std::sync::Arc;

use crate::proto::header::Smb2Header;
use crate::proto::messages::{FileInfoClass, QueryDirectoryRequest, QueryDirectoryResponse};

use crate::conn::state::{Connection, DirCursor};
use crate::dispatch::HandlerResponse;
use crate::handlers::shared::{lookup_open, lookup_session_tree};
use crate::info_class::{align8, encode_dir_entry};
use crate::ntstatus;
use crate::server::ServerState;
use crate::utils::{dos_pattern_matches, utf16le_to_string};

pub async fn handle(
    _server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    body: &[u8],
) -> HandlerResponse {
    let req = match QueryDirectoryRequest::parse(body) {
        Ok(r) => r,
        Err(_) => return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER),
    };
    if FileInfoClass::from_u8(req.file_information_class).is_none() {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_INFO_CLASS);
    }
    let class_byte = req.file_information_class;

    let tree_arc = match lookup_session_tree(conn, hdr).await {
        Ok(t) => t,
        Err(s) => return HandlerResponse::err(s),
    };
    let open_arc = match lookup_open(&tree_arc, req.file_id).await {
        Some(o) => o,
        None => return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED),
    };

    let pattern_str = utf16le_to_string(&req.file_name);
    let pattern: Option<String> = if pattern_str.is_empty() || pattern_str == "*" {
        None
    } else {
        Some(pattern_str)
    };

    let restart = req.flags & QueryDirectoryRequest::FLAG_RESTART_SCANS != 0
        || req.flags & QueryDirectoryRequest::FLAG_REOPEN != 0;
    let single_entry = req.flags & QueryDirectoryRequest::FLAG_RETURN_SINGLE_ENTRY != 0;

    // Populate or refresh the cursor.
    {
        let mut open = open_arc.write().await;
        if !open.is_directory {
            return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
        }
        if open.search_state.is_none() || restart {
            // A backend may claim the filter for this pattern
            // (`Handle::applies_pattern`): its `list_dir(Some(pattern))`
            // result already satisfies `pattern` under its own matching, so
            // the protocol-layer post-filter below is skipped. The default
            // (`false`) keeps today's behaviour for every other backend.
            let backend_prefiltered = match (open.handle.as_ref(), pattern.as_deref()) {
                (Some(h), Some(pattern)) => h.applies_pattern(pattern),
                _ => false,
            };
            let entries = match open.handle.as_ref() {
                Some(h) => h.list_dir(pattern.as_deref()).await,
                None => return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED),
            };
            let mut entries = match entries {
                Ok(e) => e,
                Err(e) => return HandlerResponse::err(e.to_nt_status()),
            };
            // `Handle::list_dir` permits backends to ignore `pattern`; the
            // protocol layer owns the final filter so an exact-name lookup
            // can never succeed with an unrelated sibling entry.
            if !backend_prefiltered
                && let Some(pattern) = pattern.as_deref()
            {
                entries.retain(|entry| dos_pattern_matches(pattern, &entry.info.name));
            }
            open.search_state = Some(DirCursor {
                entries,
                next: 0,
                pattern: pattern.clone(),
            });
        }
    }

    // Encode entries into the output buffer.
    let mut buf: Vec<u8> = Vec::new();
    let mut last_offset_pos: Option<usize> = None;
    let cap = req.output_buffer_length as usize;

    {
        let mut open = open_arc.write().await;
        let cursor = open.search_state.as_mut().expect("populated above");
        loop {
            if cursor.next >= cursor.entries.len() {
                break;
            }
            let entry = &cursor.entries[cursor.next];
            let file_index = entry.info.file_index;
            let mut bytes = encode_dir_entry(class_byte, entry, file_index);
            if bytes.is_empty() {
                cursor.next += 1;
                continue;
            }

            // Determine total size with padding for chaining.
            let entry_aligned = align8(bytes.len());
            // If this is *not* the first entry, we already padded the previous
            // entry up to entry_aligned. We commit only if total fits.
            let prev_len = buf.len();
            let total_after = prev_len + entry_aligned;
            if total_after > cap && !buf.is_empty() {
                // No room for this entry; stop.
                break;
            }
            // Patch previous NextEntryOffset.
            if let Some(prev_off) = last_offset_pos {
                let delta = (prev_len - prev_off) as u32;
                buf[prev_off..prev_off + 4].copy_from_slice(&delta.to_le_bytes());
            }
            // Track NextEntryOffset position for the entry we are appending.
            last_offset_pos = Some(prev_len);
            // Append the entry, then pad to 8.
            let target_len = prev_len + entry_aligned;
            buf.append(&mut bytes);
            while buf.len() < target_len {
                buf.push(0);
            }
            cursor.next += 1;
            if single_entry {
                break;
            }
        }
    }
    if buf.is_empty() {
        return HandlerResponse::err(ntstatus::STATUS_NO_MORE_FILES);
    }

    let resp = QueryDirectoryResponse {
        structure_size: 9,
        output_buffer_offset: 64 + 8,
        output_buffer_length: buf.len() as u32,
        buffer: buf,
    };
    let mut out = Vec::new();
    resp.write_to(&mut out).expect("encode");
    HandlerResponse::ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::state::{Connection, Session, TreeConnect};
    use crate::proto::auth::ntlm::Identity;
    use crate::proto::header::{Command, HeaderTail};
    use crate::proto::messages::{CreateRequest, CreateResponse, FileId};
    use crate::server::{ServerConfig, ServerUsers, ShareBindings, ShareMode};
    use crate::tests::memfs::MemFsBackend;
    use std::collections::HashMap;
    use uuid::Uuid;

    fn test_server() -> Arc<ServerState> {
        let config = ServerConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            netbios_name: "TEST".to_string(),
            max_read_size: 1024 * 1024,
            max_write_size: 1024 * 1024,
            server_guid: Uuid::nil(),
        };
        let users = ServerUsers {
            table: tokio::sync::RwLock::new(HashMap::new()),
        };
        Arc::new(ServerState::new(config, users, vec![]))
    }

    async fn test_conn_with_tree(
        backend: Arc<dyn crate::backend::ShareBackend>,
    ) -> (Arc<Connection>, u64, u32) {
        let conn = Arc::new(Connection::new(1, Uuid::nil(), 1024 * 1024, 1024 * 1024));
        let session = Arc::new(tokio::sync::RwLock::new(Session::new(
            1,
            Identity::Anonymous,
            [0; 16],
            [0; 16],
            false,
            None,
        )));
        let share = ShareBindings::new(
            "share".to_string(),
            backend,
            ShareMode::Public,
            HashMap::new(),
            false,
        );
        let tree = Arc::new(tokio::sync::RwLock::new(TreeConnect::new(
            1,
            share,
            crate::builder::Access::ReadWrite,
        )));
        {
            let session = session.read().await;
            session.trees.write().await.insert(1, tree);
        }
        conn.sessions.write().await.insert(1, session);
        (conn, 1, 1)
    }

    fn header(session_id: u64, tree_id: u32, message_id: u64, command: Command) -> Smb2Header {
        Smb2Header {
            credit_charge: 1,
            channel_sequence_status: 0,
            command,
            credit_request_response: 1,
            flags: 0,
            next_command: 0,
            message_id,
            tail: HeaderTail::sync(tree_id),
            session_id,
            signature: [0u8; 16],
        }
    }

    async fn open_root(
        server: &Arc<ServerState>,
        conn: &Arc<Connection>,
        session_id: u64,
        tree_id: u32,
    ) -> FileId {
        let request = CreateRequest {
            structure_size: 57,
            security_flags: 0,
            requested_oplock_level: 0,
            impersonation_level: 2,
            smb_create_flags: 0,
            reserved: 0,
            desired_access: 0x0010_0081,
            file_attributes: 0,
            share_access: 0x0000_0007,
            create_disposition: 1,
            create_options: 0x0000_0001,
            name_offset: 0x78,
            name_length: 0,
            create_contexts_offset: 0,
            create_contexts_length: 0,
            name: vec![],
            create_contexts: vec![],
        };
        let mut body = Vec::new();
        request.write_to(&mut body).unwrap();
        let response = crate::handlers::create::handle(
            server,
            conn,
            &header(session_id, tree_id, 1, Command::Create),
            &body,
        )
        .await;
        assert_eq!(response.status, ntstatus::STATUS_SUCCESS);
        CreateResponse::parse(&response.body).unwrap().file_id
    }

    fn exact_name_query(file_id: FileId, pattern: &str) -> Vec<u8> {
        let file_name = crate::utils::utf16le(pattern);
        let request = QueryDirectoryRequest {
            structure_size: 33,
            file_information_class: FileInfoClass::FileIdBothDirectoryInformation as u8,
            flags: QueryDirectoryRequest::FLAG_RESTART_SCANS
                | QueryDirectoryRequest::FLAG_RETURN_SINGLE_ENTRY,
            file_index: 0,
            file_id,
            file_name_offset: 0x60,
            file_name_length: file_name.len() as u16,
            output_buffer_length: 64 * 1024,
            file_name,
        };
        let mut body = Vec::new();
        request.write_to(&mut body).unwrap();
        body
    }

    #[tokio::test]
    async fn exact_name_lookup_does_not_return_an_unrelated_sibling() {
        // MemFsBackend intentionally ignores list_dir's optional pattern.
        // This pins the protocol-layer post-filter promised by Handle's
        // contract: an exact lookup for a missing name must not return the
        // first unrelated entry from a non-empty directory.
        let server = test_server();
        let backend = MemFsBackend::new().with_file("pre_existing.txt", b"old");
        let (conn, session_id, tree_id) = test_conn_with_tree(Arc::new(backend)).await;
        let file_id = open_root(&server, &conn, session_id, tree_id).await;

        let response = handle(
            &server,
            &conn,
            &header(session_id, tree_id, 2, Command::QueryDirectory),
            &exact_name_query(file_id, "new_sibling.txt"),
        )
        .await;

        assert_eq!(response.status, ntstatus::STATUS_NO_MORE_FILES);
    }

    #[tokio::test]
    async fn exact_name_lookup_is_ascii_case_insensitive() {
        let server = test_server();
        let backend = MemFsBackend::new().with_file("pre_existing.txt", b"old");
        let (conn, session_id, tree_id) = test_conn_with_tree(Arc::new(backend)).await;
        let file_id = open_root(&server, &conn, session_id, tree_id).await;

        let response = handle(
            &server,
            &conn,
            &header(session_id, tree_id, 2, Command::QueryDirectory),
            &exact_name_query(file_id, "PRE_EXISTING.TXT"),
        )
        .await;

        assert_eq!(response.status, ntstatus::STATUS_SUCCESS);
        let response = QueryDirectoryResponse::parse(&response.body).unwrap();
        let name_len = u32::from_le_bytes(response.buffer[60..64].try_into().unwrap()) as usize;
        let name_bytes = &response.buffer[104..104 + name_len];
        assert_eq!(utf16le_to_string(name_bytes), "pre_existing.txt");
    }

    // ── Backend-owned pattern matching (`Handle::applies_pattern`) ──────

    use crate::backend::{
        BackendCapabilities, DirEntry, FileInfo, FileTimes, Handle, OpenOptions, ShareBackend,
    };
    use crate::error::{SmbError, SmbResult};
    use crate::path::SmbPath;
    use async_trait::async_trait;
    use bytes::Bytes;

    /// A backend whose directory handle returns a fixed entry set regardless
    /// of the pattern, and whose `applies_pattern` answer is configurable — so
    /// a QUERY_DIRECTORY test can drive both the claimed-filter and the
    /// default post-filter paths.
    struct PatternBackend {
        entries: Vec<DirEntry>,
        claims: bool,
    }

    fn entry(name: &str) -> DirEntry {
        DirEntry {
            info: FileInfo {
                name: name.to_string(),
                end_of_file: 0,
                allocation_size: 0,
                creation_time: 0,
                last_access_time: 0,
                last_write_time: 0,
                change_time: 0,
                is_directory: false,
                is_symlink: false,
                file_index: 0,
            },
        }
    }

    struct PatternHandle {
        entries: Vec<DirEntry>,
        claims: bool,
    }

    #[async_trait]
    impl ShareBackend for PatternBackend {
        async fn open(&self, _path: &SmbPath, _opts: OpenOptions) -> SmbResult<Box<dyn Handle>> {
            Ok(Box::new(PatternHandle {
                entries: self.entries.clone(),
                claims: self.claims,
            }))
        }
        async fn unlink(&self, _path: &SmbPath) -> SmbResult<()> {
            Err(SmbError::NotSupported)
        }
        async fn rename(&self, _from: &SmbPath, _to: &SmbPath, _replace: bool) -> SmbResult<()> {
            Err(SmbError::NotSupported)
        }
        fn capabilities(&self) -> BackendCapabilities {
            BackendCapabilities {
                is_read_only: true,
                case_sensitive: false,
                supports_named_streams: false,
                supports_symlinks: false,
            }
        }
    }

    #[async_trait]
    impl Handle for PatternHandle {
        async fn read(&self, _offset: u64, _len: u32) -> SmbResult<Bytes> {
            Err(SmbError::NotSupported)
        }
        async fn write(&self, _offset: u64, _data: &[u8]) -> SmbResult<u32> {
            Err(SmbError::NotSupported)
        }
        async fn flush(&self) -> SmbResult<()> {
            Ok(())
        }
        async fn stat(&self) -> SmbResult<FileInfo> {
            Ok(FileInfo {
                name: String::new(),
                end_of_file: 0,
                allocation_size: 0,
                creation_time: 0,
                last_access_time: 0,
                last_write_time: 0,
                change_time: 0,
                is_directory: true,
                is_symlink: false,
                file_index: 0,
            })
        }
        async fn set_times(&self, _times: FileTimes) -> SmbResult<()> {
            Ok(())
        }
        async fn truncate(&self, _len: u64) -> SmbResult<()> {
            Err(SmbError::NotSupported)
        }
        async fn list_dir(&self, _pattern: Option<&str>) -> SmbResult<Vec<DirEntry>> {
            Ok(self.entries.clone())
        }
        fn applies_pattern(&self, _pattern: &str) -> bool {
            self.claims
        }
        async fn close(self: Box<Self>) -> SmbResult<()> {
            Ok(())
        }
    }

    fn first_entry_name(body: &[u8]) -> String {
        let response = QueryDirectoryResponse::parse(body).unwrap();
        let name_len = u32::from_le_bytes(response.buffer[60..64].try_into().unwrap()) as usize;
        let name_bytes = &response.buffer[104..104 + name_len];
        utf16le_to_string(name_bytes)
    }

    #[tokio::test]
    async fn backend_claiming_the_pattern_bypasses_the_post_filter() {
        // The pattern is lowercase NFD `überblick.md`; the entry is the
        // precomposed `Überblick.md`. `dos_pattern_matches` compares ASCII
        // characters case-insensitively and would drop the entry, so survival
        // proves the protocol-layer filter was skipped for the claimed call.
        let server = test_server();
        let backend = PatternBackend {
            entries: vec![entry("\u{00dc}berblick.md")],
            claims: true,
        };
        let (conn, session_id, tree_id) = test_conn_with_tree(Arc::new(backend)).await;
        let file_id = open_root(&server, &conn, session_id, tree_id).await;

        let response = handle(
            &server,
            &conn,
            &header(session_id, tree_id, 2, Command::QueryDirectory),
            &exact_name_query(file_id, "u\u{0308}berblick.md"),
        )
        .await;

        assert_eq!(response.status, ntstatus::STATUS_SUCCESS);
        assert_eq!(first_entry_name(&response.body), "\u{00dc}berblick.md");
    }

    #[tokio::test]
    async fn default_hook_post_filters_the_variant_entry() {
        // Same backend and entries, but the default `applies_pattern` (false)
        // keeps the protocol-layer post-filter: the variant spelling is
        // dropped, so the exact-name lookup reports no more files.
        let server = test_server();
        let backend = PatternBackend {
            entries: vec![entry("\u{00dc}berblick.md")],
            claims: false,
        };
        let (conn, session_id, tree_id) = test_conn_with_tree(Arc::new(backend)).await;
        let file_id = open_root(&server, &conn, session_id, tree_id).await;

        let response = handle(
            &server,
            &conn,
            &header(session_id, tree_id, 2, Command::QueryDirectory),
            &exact_name_query(file_id, "u\u{0308}berblick.md"),
        )
        .await;

        assert_eq!(response.status, ntstatus::STATUS_NO_MORE_FILES);
    }

    #[tokio::test]
    async fn wildcard_pattern_is_still_post_filtered_under_the_default_hook() {
        let server = test_server();
        let backend = PatternBackend {
            entries: vec![entry("a.md"), entry("b.txt")],
            claims: false,
        };
        let (conn, session_id, tree_id) = test_conn_with_tree(Arc::new(backend)).await;
        let file_id = open_root(&server, &conn, session_id, tree_id).await;

        let response = handle(
            &server,
            &conn,
            &header(session_id, tree_id, 2, Command::QueryDirectory),
            &exact_name_query(file_id, "*.md"),
        )
        .await;

        assert_eq!(response.status, ntstatus::STATUS_SUCCESS);
        assert_eq!(first_entry_name(&response.body), "a.md");
    }
}
