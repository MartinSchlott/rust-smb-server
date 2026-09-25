//! Per-connection frame reader: pulls bytes off the socket, frames them,
//! hands each frame to the dispatcher.

use std::io;
use std::sync::Arc;

use crate::proto::framing::{FRAME_HEADER_LEN, decode_frame_header};
use tokio::io::{AsyncReadExt, ReadHalf};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tracing::{debug, error};

use crate::conn::state::Connection;
use crate::server::ServerState;

/// Read one frame's payload (without the 4-byte length prefix).
///
/// Returns `Ok(None)` on a clean EOF, `Ok(Some(bytes))` on a complete frame,
/// `Err` on partial/garbled data.
pub async fn read_one_frame(reader: &mut ReadHalf<TcpStream>) -> io::Result<Option<Vec<u8>>> {
    let mut hdr = [0u8; FRAME_HEADER_LEN];
    match reader.read_exact(&mut hdr).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = match decode_frame_header(&hdr) {
        Ok(n) => n,
        Err(e) => {
            return Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string()));
        }
    };
    let mut payload = vec![0u8; len as usize];
    reader.read_exact(&mut payload).await?;
    Ok(Some(payload))
}

/// Tuning constant, not a protocol constant: bounds memory and task count for
/// the number of dispatches a connection may have in flight at once. Sits far
/// above the concurrency a loopback server over local-SSD I/O can use.
const MAX_INFLIGHT: usize = 64;

/// Continuously read frames and dispatch them.
///
/// Data-path frames are dispatched concurrently, up to `MAX_INFLIGHT` at
/// once (PLAN_PERF1): each gets its own spawned task holding one permit from
/// `inflight`, so the reader can read and admit the next frame without
/// waiting for the previous one's response. A frame classified by
/// `dispatch::frame_must_be_serialized` (NEGOTIATE, SESSION_SETUP, LOGOFF,
/// TREE_CONNECT, TREE_DISCONNECT, anywhere in its compound chain) is instead
/// a hard barrier: the reader waits for every currently in-flight dispatch to
/// finish, then runs it inline, before admitting anything else. This keeps
/// connection- and session-setup frames from racing in-flight data
/// operations while still letting ordinary READ/WRITE/QUERY_INFO/etc. frames
/// overlap.
pub async fn reader_task(
    mut reader: ReadHalf<TcpStream>,
    server: Arc<ServerState>,
    conn: Arc<Connection>,
    tx: tokio::sync::mpsc::Sender<crate::conn::writer::FramePayload>,
) -> io::Result<()> {
    let inflight = Arc::new(Semaphore::new(MAX_INFLIGHT));

    let result = loop {
        // Race the frame read against writer closure so a dead writer is
        // noticed even while parked waiting for the next frame. `biased;`
        // makes closure win deterministically when both are ready, instead
        // of `select!`'s default random choice — which could otherwise pick
        // the work branch and admit one more mutation into a channel nothing
        // will ever drain.
        let frame = tokio::select! {
            biased;
            _ = tx.closed() => {
                debug!("writer channel closed; reader stopping admission");
                break Ok(());
            }
            frame = read_one_frame(&mut reader) => {
                match frame {
                    Ok(Some(b)) => b,
                    Ok(None) => {
                        debug!("client closed connection");
                        break Ok(());
                    }
                    Err(e) => {
                        error!(error = %e, "frame read error");
                        break Err(e);
                    }
                }
            }
        };

        // Check shutdown after every frame.
        if server
            .shutting_down
            .load(std::sync::atomic::Ordering::Acquire)
        {
            debug!("server shutting down; dropping connection");
            break Ok(());
        }

        if crate::dispatch::frame_must_be_serialized(&frame) {
            // Barrier: wait for every spawned dispatch to finish, then run
            // this one inline, exactly like v1's sequential dispatch. Races
            // writer closure the same way the frame read and the permit wait
            // do — a serialized frame is admitted only when `dispatch_frame`
            // is entered (the admission-point rule), so closure arriving
            // while parked here must stop admission before that happens,
            // not after a TREE_DISCONNECT/LOGOFF has already torn down state
            // nothing will ever hear the response to.
            let _permits = tokio::select! {
                biased;
                _ = tx.closed() => {
                    debug!("writer channel closed while waiting for the serialization barrier; reader stopping admission");
                    break Ok(());
                }
                permits = inflight.acquire_many(MAX_INFLIGHT as u32) => {
                    permits.expect("inflight semaphore is never closed")
                }
            };
            let response = crate::dispatch::dispatch_frame(&server, &conn, &frame).await;
            if let Some(bytes) = response
                && tx.send(bytes).await.is_err()
            {
                debug!("writer channel closed; reader exiting");
                break Ok(());
            }
        } else {
            // Backpressure point: admission for a data-path frame waits for
            // a free permit, racing writer closure the same way the frame
            // read does above — otherwise a closure arriving while parked
            // here would go unnoticed and the reader would keep admitting
            // mutations into a dead channel.
            let permit = tokio::select! {
                biased;
                _ = tx.closed() => {
                    debug!("writer channel closed while waiting for a permit; reader stopping admission");
                    break Ok(());
                }
                permit = inflight.clone().acquire_owned() => {
                    permit.expect("inflight semaphore is never closed")
                }
            };
            let server = server.clone();
            let conn = conn.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let response = crate::dispatch::dispatch_frame(&server, &conn, &frame).await;
                if let Some(bytes) = response {
                    let _ = tx.send(bytes).await;
                }
            });
        }
    };

    // On every exit path: acquire every permit before returning, so no
    // dispatch spawned above is still touching connection state after
    // `reader_task` returns.
    let _ = inflight.acquire_many(MAX_INFLIGHT as u32).await;
    result
}

// ── PLAN_PERF1 Step 8 — concurrent reader loop tests ────────────────────────
//
// Every test drives the real `reader_task` over a real loopback TCP pair
// (`reader_task`'s signature is hard-wired to `ReadHalf<TcpStream>`), but
// fabricates `Connection`/`Session`/`TreeConnect`/`Open` state directly
// instead of running a full NEGOTIATE/SESSION_SETUP/TREE_CONNECT/CREATE
// handshake — `read`/`echo`/`tree_disconnect`/`logoff` only ever look up
// state by (session_id, tree_id, file_id), so a fabricated connection with a
// pre-installed `Open` reaches the same handler code a real handshake would.
// `tx`/`rx` are owned directly by the test (no real `writer_task`), so a
// test can either drain responses or drop `rx` to simulate writer closure
// at an exact, deterministic point.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{DirEntry, FileInfo, FileTimes, Handle};
    use crate::builder::Access;
    use crate::conn::state::{Open, Session, TreeConnect};
    use crate::error::SmbResult;
    use crate::proto::auth::ntlm::Identity;
    use crate::proto::framing::encode_frame;
    use crate::proto::header::{Command, HeaderTail, Smb2Header};
    use crate::proto::messages::{
        EchoRequest, FileId, ReadRequest, ReadResponse, TreeDisconnectRequest,
    };
    use crate::server::{ServerConfig, ServerState, ServerUsers, ShareBindings, ShareMode};
    use crate::trace::{TraceEvent, TraceKey, TraceSink};
    use async_trait::async_trait;
    use bytes::Bytes;
    use std::collections::HashMap;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::{Notify, RwLock, mpsc};
    use uuid::Uuid;

    const TEST_CHANNEL: usize = 128;

    // ── wire helpers ─────────────────────────────────────────────────────

    fn header(command: Command, message_id: u64, session_id: u64, tree_id: u32) -> Smb2Header {
        Smb2Header {
            credit_charge: 1,
            channel_sequence_status: 0,
            command,
            credit_request_response: 64,
            flags: 0,
            next_command: 0,
            message_id,
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

    fn read_request_payload(hdr: &Smb2Header, file_id: FileId) -> Vec<u8> {
        let req = ReadRequest {
            structure_size: 49,
            padding: ReadResponse::STANDARD_DATA_OFFSET,
            flags: 0,
            length: 16,
            offset: 0,
            file_id,
            minimum_count: 0,
            channel: 0,
            remaining_bytes: 0,
            read_channel_info_offset: 0,
            read_channel_info_length: 0,
            buffer: vec![0],
        };
        let mut body = Vec::new();
        req.write_to(&mut body).expect("encode read request");
        frame_payload(hdr, &body)
    }

    fn echo_payload(hdr: &Smb2Header) -> Vec<u8> {
        let mut body = Vec::new();
        EchoRequest::default()
            .write_to(&mut body)
            .expect("encode echo request");
        frame_payload(hdr, &body)
    }

    fn tree_disconnect_payload(hdr: &Smb2Header) -> Vec<u8> {
        let mut body = Vec::new();
        TreeDisconnectRequest::default()
            .write_to(&mut body)
            .expect("encode tree disconnect request");
        frame_payload(hdr, &body)
    }

    async fn write_frame(s: &mut TcpStream, payload: &[u8]) {
        let mut framed = Vec::new();
        encode_frame(payload, &mut framed);
        s.write_all(&framed).await.expect("write frame");
    }

    /// A connected loopback pair: the client half the test drives directly,
    /// and the server-side `ReadHalf` `reader_task` reads from. The
    /// server-side `WriteHalf` is discarded — every test manages `tx`/`rx`
    /// itself instead of running a real `writer_task`.
    async fn tcp_pair() -> (TcpStream, ReadHalf<TcpStream>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (accepted, connected) = tokio::join!(listener.accept(), TcpStream::connect(addr));
        let server_side = accepted.expect("accept").0;
        let client_side = connected.expect("connect");
        let (read_half, _write_half) = tokio::io::split(server_side);
        (client_side, read_half)
    }

    fn test_server() -> Arc<ServerState> {
        let cfg = ServerConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            netbios_name: "TEST".to_owned(),
            max_read_size: 1 << 20,
            max_write_size: 1 << 20,
            server_guid: Uuid::nil(),
        };
        let users = ServerUsers {
            table: RwLock::new(HashMap::new()),
        };
        Arc::new(ServerState::new(cfg, users, vec![]))
    }

    // ── a `ShareBackend`/`Handle` whose `read` signals entry then blocks ──

    struct BlockingHandle {
        entered: mpsc::UnboundedSender<()>,
        release: Arc<Notify>,
        content: Bytes,
    }

    #[async_trait]
    impl Handle for BlockingHandle {
        async fn read(&self, _offset: u64, _len: u32) -> SmbResult<Bytes> {
            let _ = self.entered.send(());
            self.release.notified().await;
            Ok(self.content.clone())
        }
        async fn write(&self, _offset: u64, data: &[u8]) -> SmbResult<u32> {
            Ok(data.len() as u32)
        }
        async fn flush(&self) -> SmbResult<()> {
            Ok(())
        }
        async fn stat(&self) -> SmbResult<FileInfo> {
            Ok(FileInfo {
                name: "block".to_owned(),
                end_of_file: self.content.len() as u64,
                allocation_size: self.content.len() as u64,
                creation_time: 0,
                last_access_time: 0,
                last_write_time: 0,
                change_time: 0,
                is_directory: false,
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
            Ok(vec![])
        }
        async fn close(self: Box<Self>) -> SmbResult<()> {
            Ok(())
        }
    }

    /// Installs `handles` as already-open files (`FileId::new(1,1)`,
    /// `(2,1)`, …) on a single fabricated session/tree — bypassing the wire
    /// handshake, see the module doc above.
    async fn seeded_connection(
        server: &Arc<ServerState>,
        handles: Vec<Box<dyn Handle>>,
    ) -> (Arc<Connection>, u64, u32, Vec<FileId>) {
        let _ = server;
        let conn = Arc::new(Connection::new(1, Uuid::nil(), 1 << 20, 1 << 20));
        let session_id = conn.alloc_session_id();
        let session = Session::new(
            session_id,
            Identity::Anonymous,
            [0; 16],
            [0; 16],
            false,
            None,
        );
        let tree_id = session.alloc_tree_id();
        let share = ShareBindings::new(
            "test".to_owned(),
            Arc::new(crate::backend::NotSupportedBackend),
            ShareMode::Public,
            HashMap::new(),
            false,
        );
        let tree = TreeConnect::new(tree_id, share, Access::ReadWrite);
        let mut file_ids = Vec::new();
        for handle in handles {
            let file_id = tree.alloc_file_id();
            let open = Open::new(
                file_id,
                handle,
                Access::ReadWrite,
                "block.txt".parse().expect("path"),
                false,
                false,
            );
            tree.opens
                .write()
                .await
                .insert(file_id, Arc::new(RwLock::new(open)));
            file_ids.push(file_id);
        }
        session
            .trees
            .write()
            .await
            .insert(tree_id, Arc::new(RwLock::new(tree)));
        conn.sessions
            .write()
            .await
            .insert(session_id, Arc::new(RwLock::new(session)));
        (conn, session_id, tree_id, file_ids)
    }

    fn blocking_handle(
        release: Arc<Notify>,
        entered: mpsc::UnboundedSender<()>,
    ) -> Box<dyn Handle> {
        Box::new(BlockingHandle {
            entered,
            release,
            content: Bytes::from_static(b"0123456789abcdef"),
        })
    }

    async fn recv_within(rx: &mut mpsc::UnboundedReceiver<()>, dur: Duration) -> bool {
        tokio::time::timeout(dur, rx.recv()).await.is_ok()
    }

    // ── Test 1 — dispatch overlap is real ─────────────────────────────────

    #[tokio::test]
    async fn concurrent_dispatch_lets_two_reads_overlap() {
        let server = test_server();
        let release = Arc::new(Notify::new());
        let (entered_tx, mut entered_rx) = mpsc::unbounded_channel();
        let handles = vec![
            blocking_handle(release.clone(), entered_tx.clone()),
            blocking_handle(release.clone(), entered_tx.clone()),
        ];
        let (conn, session_id, tree_id, file_ids) = seeded_connection(&server, handles).await;

        let (mut client, read_half) = tcp_pair().await;
        let (tx, mut rx) = mpsc::channel(TEST_CHANNEL);
        let reader = tokio::spawn(reader_task(read_half, server, conn, tx));

        for (i, file_id) in file_ids.iter().enumerate() {
            let hdr = header(Command::Read, 10 + i as u64, session_id, tree_id);
            write_frame(&mut client, &read_request_payload(&hdr, *file_id)).await;
        }

        // Both entry signals must arrive before either is released.
        assert!(
            recv_within(&mut entered_rx, Duration::from_secs(5)).await,
            "first READ must enter"
        );
        assert!(
            recv_within(&mut entered_rx, Duration::from_secs(5)).await,
            "second READ must enter concurrently with the first"
        );

        release.notify_waiters();

        for _ in 0..2 {
            let resp = tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .expect("response timeout")
                .expect("response channel open");
            assert_eq!(read_u32(&resp, 0x08), crate::ntstatus::STATUS_SUCCESS);
        }

        drop(client);
        let _ = tokio::time::timeout(Duration::from_secs(5), reader).await;
    }

    // ── Test 2 — setup frames are a barrier ───────────────────────────────

    struct RequestCmdSink {
        commands: std::sync::Mutex<Vec<&'static str>>,
    }

    impl TraceSink for RequestCmdSink {
        fn record(&self, _key: Option<TraceKey>, event: &TraceEvent) {
            if let TraceEvent::Request { cmd, .. } = event {
                self.commands.lock().unwrap().push(cmd);
            }
        }
    }

    #[tokio::test]
    async fn tree_disconnect_does_not_enter_until_the_read_response_is_enqueued() {
        let sink = Arc::new(RequestCmdSink {
            commands: std::sync::Mutex::new(Vec::new()),
        });
        let mut server = ServerState::new(
            ServerConfig {
                listen_addr: "127.0.0.1:0".parse().unwrap(),
                netbios_name: "TEST".to_owned(),
                max_read_size: 1 << 20,
                max_write_size: 1 << 20,
                server_guid: Uuid::nil(),
            },
            ServerUsers {
                table: RwLock::new(HashMap::new()),
            },
            vec![],
        );
        server.trace_sink = Some(sink.clone());
        let server = Arc::new(server);

        let release = Arc::new(Notify::new());
        let (entered_tx, mut entered_rx) = mpsc::unbounded_channel();
        let (conn, session_id, tree_id, file_ids) =
            seeded_connection(&server, vec![blocking_handle(release.clone(), entered_tx)]).await;

        let (mut client, read_half) = tcp_pair().await;
        let (tx, mut rx) = mpsc::channel(TEST_CHANNEL);
        let reader = tokio::spawn(reader_task(read_half, server, conn, tx));

        let read_hdr = header(Command::Read, 1, session_id, tree_id);
        write_frame(&mut client, &read_request_payload(&read_hdr, file_ids[0])).await;
        assert!(
            recv_within(&mut entered_rx, Duration::from_secs(5)).await,
            "READ must enter"
        );

        let td_hdr = header(Command::TreeDisconnect, 2, session_id, tree_id);
        write_frame(&mut client, &tree_disconnect_payload(&td_hdr)).await;

        // TREE_DISCONNECT must not enter dispatch while the READ is parked.
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            !sink.commands.lock().unwrap().contains(&"TreeDisconnect"),
            "TREE_DISCONNECT must not enter while a READ is in flight"
        );

        release.notify_waiters();

        let read_resp = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("read response timeout")
            .expect("read response present");
        assert_eq!(
            header_command(&read_resp),
            Command::Read as u16,
            "the READ's response must be enqueued first"
        );

        let td_resp = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("tree disconnect response timeout")
            .expect("tree disconnect response present");
        assert_eq!(header_command(&td_resp), Command::TreeDisconnect as u16);
        assert!(sink.commands.lock().unwrap().contains(&"TreeDisconnect"));

        drop(client);
        let _ = tokio::time::timeout(Duration::from_secs(5), reader).await;
    }

    fn header_command(frame: &[u8]) -> u16 {
        u16::from_le_bytes([frame[12], frame[13]])
    }

    fn read_u32(buf: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
        ])
    }

    // ── Test 3 — backpressure holds at the bound (R2) ─────────────────────

    #[tokio::test]
    async fn backpressure_holds_at_max_inflight() {
        let server = test_server();
        let release = Arc::new(Notify::new());
        let (entered_tx, mut entered_rx) = mpsc::unbounded_channel();
        let (conn, session_id, tree_id, file_ids) =
            seeded_connection(&server, vec![blocking_handle(release.clone(), entered_tx)]).await;
        let file_id = file_ids[0];

        let (mut client, read_half) = tcp_pair().await;
        let (tx, mut rx) = mpsc::channel(TEST_CHANNEL);
        let reader = tokio::spawn(reader_task(read_half, server, conn, tx));

        for i in 0..MAX_INFLIGHT as u64 {
            let hdr = header(Command::Read, i, session_id, tree_id);
            write_frame(&mut client, &read_request_payload(&hdr, file_id)).await;
        }
        for i in 0..MAX_INFLIGHT {
            assert!(
                recv_within(&mut entered_rx, Duration::from_secs(5)).await,
                "READ #{i} must be admitted"
            );
        }

        let extra_hdr = header(Command::Read, MAX_INFLIGHT as u64, session_id, tree_id);
        write_frame(&mut client, &read_request_payload(&extra_hdr, file_id)).await;

        assert!(
            !recv_within(&mut entered_rx, Duration::from_millis(300)).await,
            "the (MAX_INFLIGHT+1)th READ must not be dispatched while every permit is held"
        );

        // Release exactly one — frees exactly one permit.
        release.notify_one();

        assert!(
            recv_within(&mut entered_rx, Duration::from_secs(5)).await,
            "the extra READ must be admitted once a permit frees up"
        );

        release.notify_waiters();
        for _ in 0..=MAX_INFLIGHT {
            let _ = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await;
        }
        drop(client);
        let _ = tokio::time::timeout(Duration::from_secs(5), reader).await;
    }

    // ── Test 4 — drain on exit (R3) ────────────────────────────────────────

    macro_rules! assert_not_yet_returned {
        ($handle:expr, $dur:expr, $msg:expr) => {
            tokio::select! {
                res = &mut $handle => panic!("{}: reader returned early: {:?}", $msg, res),
                _ = tokio::time::sleep($dur) => {}
            }
        };
    }

    #[tokio::test]
    async fn drain_waits_for_inflight_dispatch_on_clean_eof() {
        let server = test_server();
        let release = Arc::new(Notify::new());
        let (entered_tx, mut entered_rx) = mpsc::unbounded_channel();
        let (conn, session_id, tree_id, file_ids) =
            seeded_connection(&server, vec![blocking_handle(release.clone(), entered_tx)]).await;

        let (mut client, read_half) = tcp_pair().await;
        let (tx, _rx) = mpsc::channel(TEST_CHANNEL);
        let mut reader = tokio::spawn(reader_task(read_half, server, conn, tx));

        let hdr = header(Command::Read, 1, session_id, tree_id);
        write_frame(&mut client, &read_request_payload(&hdr, file_ids[0])).await;
        assert!(recv_within(&mut entered_rx, Duration::from_secs(5)).await);

        client.shutdown().await.expect("client shutdown (EOF)");

        assert_not_yet_returned!(
            reader,
            Duration::from_millis(300),
            "clean EOF with an in-flight dispatch"
        );

        release.notify_waiters();
        let result = tokio::time::timeout(Duration::from_secs(5), reader)
            .await
            .expect("reader must return once the in-flight dispatch finishes")
            .expect("join");
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn drain_waits_for_inflight_dispatch_on_read_error() {
        let server = test_server();
        let release = Arc::new(Notify::new());
        let (entered_tx, mut entered_rx) = mpsc::unbounded_channel();
        let (conn, session_id, tree_id, file_ids) =
            seeded_connection(&server, vec![blocking_handle(release.clone(), entered_tx)]).await;

        let (mut client, read_half) = tcp_pair().await;
        let (tx, _rx) = mpsc::channel(TEST_CHANNEL);
        let mut reader = tokio::spawn(reader_task(read_half, server, conn, tx));

        let hdr = header(Command::Read, 1, session_id, tree_id);
        write_frame(&mut client, &read_request_payload(&hdr, file_ids[0])).await;
        assert!(recv_within(&mut entered_rx, Duration::from_secs(5)).await);

        // A frame header promising 100 bytes, followed by only 10 and then a
        // hard close: `read_one_frame`'s body `read_exact` hits EOF mid-read
        // and returns `Err`, not the header's clean-EOF `Ok(None)`.
        let mut malformed = Vec::new();
        encode_frame(&[0u8; 100], &mut malformed);
        malformed.truncate(4 + 10);
        client
            .write_all(&malformed)
            .await
            .expect("write partial frame");
        client.shutdown().await.expect("client shutdown");

        assert_not_yet_returned!(
            reader,
            Duration::from_millis(300),
            "a read error with an in-flight dispatch"
        );

        release.notify_waiters();
        let result = tokio::time::timeout(Duration::from_secs(5), reader)
            .await
            .expect("reader must return once the in-flight dispatch finishes")
            .expect("join");
        assert!(
            result.is_err(),
            "a mid-body EOF must surface as a read error"
        );
    }

    // ── Test 5 — closed writer stops admission (R4), in all three wait
    // states ───────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn closed_writer_stops_admission_while_idle() {
        let server = test_server();
        let (conn, _session_id, _tree_id, _file_ids) = seeded_connection(&server, vec![]).await;
        let (_client, read_half) = tcp_pair().await;
        let (tx, rx) = mpsc::channel::<crate::conn::writer::FramePayload>(TEST_CHANNEL);
        drop(rx);

        let result = tokio::time::timeout(
            Duration::from_secs(5),
            reader_task(read_half, server, conn, tx),
        )
        .await
        .expect("reader must notice writer closure while idle and return promptly");
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn closed_writer_stops_admission_with_frame_already_readable() {
        let sink = Arc::new(RequestCmdSink {
            commands: std::sync::Mutex::new(Vec::new()),
        });
        let mut server = ServerState::new(
            ServerConfig {
                listen_addr: "127.0.0.1:0".parse().unwrap(),
                netbios_name: "TEST".to_owned(),
                max_read_size: 1 << 20,
                max_write_size: 1 << 20,
                server_guid: Uuid::nil(),
            },
            ServerUsers {
                table: RwLock::new(HashMap::new()),
            },
            vec![],
        );
        server.trace_sink = Some(sink.clone());
        let server = Arc::new(server);
        let (conn, session_id, tree_id, _file_ids) = seeded_connection(&server, vec![]).await;

        let (mut client, read_half) = tcp_pair().await;
        // The ECHO frame is fully written (and therefore already sitting in
        // the kernel receive buffer, "readable") before the reader ever
        // starts polling.
        let hdr = header(Command::Echo, 1, session_id, tree_id);
        write_frame(&mut client, &echo_payload(&hdr)).await;

        let (tx, rx) = mpsc::channel::<crate::conn::writer::FramePayload>(TEST_CHANNEL);
        drop(rx); // closed before the reader's first poll — biased select must win here.

        let result = tokio::time::timeout(
            Duration::from_secs(5),
            reader_task(read_half, server, conn, tx),
        )
        .await
        .expect("reader must notice writer closure and return promptly");
        assert!(result.is_ok());
        assert!(
            !sink.commands.lock().unwrap().contains(&"Echo"),
            "an already-readable ECHO must not be admitted once the writer is closed"
        );
    }

    #[tokio::test]
    async fn closed_writer_stops_admission_at_the_inflight_bound() {
        let server = test_server();
        let release = Arc::new(Notify::new());
        let (entered_tx, mut entered_rx) = mpsc::unbounded_channel();
        let (conn, session_id, tree_id, file_ids) =
            seeded_connection(&server, vec![blocking_handle(release.clone(), entered_tx)]).await;
        let file_id = file_ids[0];

        let (mut client, read_half) = tcp_pair().await;
        let (tx, rx) = mpsc::channel::<crate::conn::writer::FramePayload>(TEST_CHANNEL);
        let mut reader = tokio::spawn(reader_task(read_half, server, conn, tx));

        for i in 0..MAX_INFLIGHT as u64 {
            let hdr = header(Command::Read, i, session_id, tree_id);
            write_frame(&mut client, &read_request_payload(&hdr, file_id)).await;
        }
        for _ in 0..MAX_INFLIGHT {
            assert!(recv_within(&mut entered_rx, Duration::from_secs(5)).await);
        }

        // One more frame, parking the reader at the permit-wait select.
        let extra_hdr = header(Command::Read, MAX_INFLIGHT as u64, session_id, tree_id);
        write_frame(&mut client, &read_request_payload(&extra_hdr, file_id)).await;
        tokio::time::sleep(Duration::from_millis(200)).await;

        drop(rx);

        assert!(
            !recv_within(&mut entered_rx, Duration::from_millis(300)).await,
            "the extra READ must not be admitted once the writer closes"
        );

        // The reader must still be draining the MAX_INFLIGHT in-flight
        // dispatches, not abandoning them.
        assert_not_yet_returned!(
            reader,
            Duration::from_millis(300),
            "closed writer at the inflight bound, dispatches still parked"
        );

        release.notify_waiters();
        let result = tokio::time::timeout(Duration::from_secs(5), reader)
            .await
            .expect("reader must return once the drain completes")
            .expect("join");
        assert!(result.is_ok());
    }

    /// Regression: a closed writer must stop admission at the serialization
    /// barrier too, not just at the frame read and the data-path permit
    /// wait. Before the fix, `acquire_many` for a barrier frame was awaited
    /// unraced, so a closed-writer TREE_DISCONNECT parked behind an
    /// in-flight READ would still run to completion — tearing the tree down
    /// for a response nothing will ever receive — once the READ released.
    #[tokio::test]
    async fn closed_writer_stops_admission_at_the_serialization_barrier() {
        let sink = Arc::new(RequestCmdSink {
            commands: std::sync::Mutex::new(Vec::new()),
        });
        let mut server = ServerState::new(
            ServerConfig {
                listen_addr: "127.0.0.1:0".parse().unwrap(),
                netbios_name: "TEST".to_owned(),
                max_read_size: 1 << 20,
                max_write_size: 1 << 20,
                server_guid: Uuid::nil(),
            },
            ServerUsers {
                table: RwLock::new(HashMap::new()),
            },
            vec![],
        );
        server.trace_sink = Some(sink.clone());
        let server = Arc::new(server);

        let release = Arc::new(Notify::new());
        let (entered_tx, mut entered_rx) = mpsc::unbounded_channel();
        let (conn, session_id, tree_id, file_ids) =
            seeded_connection(&server, vec![blocking_handle(release.clone(), entered_tx)]).await;

        let (mut client, read_half) = tcp_pair().await;
        let (tx, rx) = mpsc::channel::<crate::conn::writer::FramePayload>(TEST_CHANNEL);
        let reader = tokio::spawn(reader_task(read_half, server.clone(), conn.clone(), tx));

        let read_hdr = header(Command::Read, 1, session_id, tree_id);
        write_frame(&mut client, &read_request_payload(&read_hdr, file_ids[0])).await;
        assert!(recv_within(&mut entered_rx, Duration::from_secs(5)).await);

        let td_hdr = header(Command::TreeDisconnect, 2, session_id, tree_id);
        write_frame(&mut client, &tree_disconnect_payload(&td_hdr)).await;
        // Give the reader a chance to read TREE_DISCONNECT and park at the
        // serialization-barrier wait, behind the still in-flight READ.
        tokio::time::sleep(Duration::from_millis(200)).await;

        drop(rx); // writer closes while the reader is parked at the barrier.
        release.notify_waiters(); // now let the blocked READ finish.

        let result = tokio::time::timeout(Duration::from_secs(5), reader)
            .await
            .expect("reader must return once the drain completes")
            .expect("join");
        assert!(result.is_ok());

        assert!(
            !sink.commands.lock().unwrap().contains(&"TreeDisconnect"),
            "TREE_DISCONNECT must not enter dispatch once the writer has closed"
        );
        let sess_arc = conn
            .sessions
            .read()
            .await
            .get(&session_id)
            .cloned()
            .expect("session must still exist");
        assert!(
            sess_arc
                .read()
                .await
                .trees
                .read()
                .await
                .contains_key(&tree_id),
            "TREE_DISCONNECT must not have torn down the tree it never entered"
        );
    }
}
