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
use crate::conn::writer::FramePayload;
use crate::dispatch::FrameOutcome;
use crate::server::ServerState;
use crate::supervise::{catch_future_unwind, report_glue_panic, report_malformed};

/// The 4-byte length header of a frame could not be decoded. Carried inside
/// the `io::Error` `read_one_frame` returns, so the reader can tell a framing
/// error (a peer speaking garbage, reported as an incident) from a plain I/O
/// error (a connection that ended, which is not).
#[derive(Debug)]
struct FramingError(String);

impl std::fmt::Display for FramingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for FramingError {}

fn is_framing_error(e: &io::Error) -> bool {
    e.get_ref().is_some_and(|inner| inner.is::<FramingError>())
}

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
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                FramingError(e.to_string()),
            ));
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

/// Whether the reader goes on after a frame.
enum FrameResult {
    Continue,
    /// The connection is over for admission purposes: the writer channel is
    /// closed, or the frame was malformed and the connection closed.
    Stop,
}

/// Runs one admitted frame to its answer, under a panic wrapper, and sends
/// the response. The dispatcher supervises every handler inside the frame;
/// this wrapper covers the server's own glue around them (validation,
/// response building, stitching), so the reader task never unwinds from a
/// frame. A panic there closes the connection: a request may be left without
/// an answer, and the only safe way to keep the contract is to end the
/// connection.
///
/// Sending the response stays outside the dispatcher's deadline: it blocks
/// only when the client stops reading, which is transport backpressure, not a
/// stuck request.
async fn run_frame(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    tx: &tokio::sync::mpsc::Sender<FramePayload>,
    frame: &[u8],
) -> FrameResult {
    match catch_future_unwind(crate::dispatch::dispatch_frame(server, conn, frame)).await {
        Ok(FrameOutcome::Response(bytes)) => {
            if tx.send(bytes).await.is_err() {
                debug!("writer channel closed; reader exiting");
                return FrameResult::Stop;
            }
            FrameResult::Continue
        }
        Ok(FrameOutcome::NoResponse) => FrameResult::Continue,
        Ok(FrameOutcome::Malformed { reason }) => {
            report_malformed(server, conn, reason);
            FrameResult::Stop
        }
        Err(payload) => {
            report_glue_panic(server, conn, &*payload);
            FrameResult::Stop
        }
    }
}

/// Continuously read frames and dispatch them.
///
/// Every admitted frame is answered, or the connection is closed — the reader
/// never leaves an open connection silent on a request (CANCEL, which the
/// protocol leaves unanswered, excepted). `dispatch_frame` bounds each frame
/// by a deadline from its admission, answers a panicking or expired handler
/// with an error status, and closes the connection when a handler cannot be
/// stopped; `run_frame` closes it when the server's own glue panics. A frame
/// whose framing or compound chain is malformed closes the connection too.
///
/// Data-path frames are dispatched concurrently, up to `MAX_INFLIGHT` at
/// once (PLAN_PERF1): each gets its own spawned task holding one permit from
/// `inflight`, so the reader can read and admit the next frame without
/// waiting for the previous one's response. A frame classified by
/// `dispatch::frame_must_be_serialized` (NEGOTIATE, SESSION_SETUP, LOGOFF,
/// TREE_CONNECT, TREE_DISCONNECT, anywhere in its compound chain, or a frame
/// that does not validate) is instead a hard barrier: the reader waits for
/// every currently in-flight dispatch to finish, then runs it inline, before
/// admitting anything else. This keeps connection- and session-setup frames
/// from racing in-flight data operations while still letting ordinary
/// READ/WRITE/QUERY_INFO/etc. frames overlap. Because every dispatch ends
/// within its deadline (or the connection closes), the barrier wait is
/// bounded.
///
/// `reader_task` returns only after every dispatch it spawned has ended, so
/// no handler touches connection state afterwards — including a handler that
/// was abandoned and could not be cancelled.
pub async fn reader_task(
    mut reader: ReadHalf<TcpStream>,
    server: Arc<ServerState>,
    conn: Arc<Connection>,
    tx: tokio::sync::mpsc::Sender<FramePayload>,
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
                        if is_framing_error(&e) {
                            report_malformed(&server, &conn, e.to_string());
                        }
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
            if let FrameResult::Stop = run_frame(&server, &conn, &tx, &frame).await {
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
                // A `Stop` needs no action here: the writer channel is
                // already closed, or `conn.close()` has made the writer exit,
                // and either one stops the reader's admission.
                let _ = run_frame(&server, &conn, &tx, &frame).await;
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

    // ── Dispatch supervision: every admitted request is answered, or the
    // connection is closed ────────────────────────────────────────────────
    //
    // These tests drive the real `reader_task` and the real `writer_task`
    // over a loopback socket, so a test sees exactly what a client sees:
    // responses, silence, or EOF. Every wait is bounded, so a missing
    // response fails the test instead of hanging it. They need worker threads
    // beyond the test's own: the supervisor's timers must keep running while a
    // non-yielding handler occupies one.
    mod supervision {
        use super::*;
        use crate::conn::writer::{WRITER_CHANNEL, writer_task};
        use crate::incident::{Incident, IncidentKind, IncidentSink};
        use crate::ntstatus::{
            STATUS_INSUFFICIENT_RESOURCES, STATUS_INTERNAL_ERROR, STATUS_IO_TIMEOUT, STATUS_SUCCESS,
        };
        use crate::proto::crypto::{SigningAlgo, sign, verify};
        use crate::proto::header::{
            SMB2_FLAGS_RELATED_OPERATIONS, SMB2_FLAGS_SIGNED, SMB2_HEADER_LEN,
        };
        use crate::tests::handler_support::{close_request, create_request};
        use std::sync::Mutex as StdMutex;
        use std::sync::atomic::{AtomicBool, Ordering};
        use tokio::io::AsyncReadExt;

        // Short durations: deadline 500 ms, slow threshold 100 ms, grace 200 ms.
        const DEADLINE: Duration = Duration::from_millis(500);
        const SLOW: Duration = Duration::from_millis(100);
        const GRACE: Duration = Duration::from_millis(200);

        const SIGNING_KEY: [u8; 16] = [7; 16];

        // ── incident capture ─────────────────────────────────────────────

        #[derive(Default)]
        struct RecordedIncidents(StdMutex<Vec<Incident>>);

        impl IncidentSink for RecordedIncidents {
            fn record(&self, incident: &Incident) {
                self.0.lock().unwrap().push(incident.clone());
            }
        }

        impl RecordedIncidents {
            fn all(&self) -> Vec<Incident> {
                self.0.lock().unwrap().clone()
            }

            fn of_kind(&self, pick: impl Fn(&IncidentKind) -> bool) -> Vec<Incident> {
                self.all().into_iter().filter(|i| pick(&i.kind)).collect()
            }
        }

        fn is_slow(kind: &IncidentKind) -> bool {
            matches!(kind, IncidentKind::Slow)
        }
        fn is_timed_out(kind: &IncidentKind) -> bool {
            matches!(kind, IncidentKind::TimedOut)
        }
        fn is_panicked(kind: &IncidentKind) -> bool {
            matches!(kind, IncidentKind::Panicked { .. })
        }
        fn is_malformed(kind: &IncidentKind) -> bool {
            matches!(kind, IncidentKind::MalformedFrame { .. })
        }
        fn is_unavailable(kind: &IncidentKind) -> bool {
            matches!(kind, IncidentKind::SupervisionUnavailable { .. })
        }
        fn is_closed(kind: &IncidentKind) -> bool {
            matches!(kind, IncidentKind::ConnectionClosed { .. })
        }

        /// The identity of a sub-request: the fields of the fork's `TraceKey`.
        fn identity(incident: &Incident) -> (u64, Option<u64>, Option<u32>) {
            (
                incident.connection_id,
                incident.message_id,
                incident.compound_ordinal,
            )
        }

        /// Records, at the moment a TREE_DISCONNECT enters dispatch, whether a
        /// flag is already set — proof that something finished *before* the
        /// serialization barrier let the TREE_DISCONNECT run.
        struct FlagAtTreeDisconnect {
            flag: Arc<AtomicBool>,
            seen: StdMutex<Option<bool>>,
        }

        impl TraceSink for FlagAtTreeDisconnect {
            fn record(&self, _key: Option<TraceKey>, event: &TraceEvent) {
                if let TraceEvent::Request { cmd, .. } = event
                    && *cmd == "TreeDisconnect"
                {
                    *self.seen.lock().unwrap() = Some(self.flag.load(Ordering::SeqCst));
                }
            }
        }

        fn supervised_server(
            deadline: Duration,
            slow: Duration,
            grace: Duration,
        ) -> (ServerState, Arc<RecordedIncidents>) {
            let incidents = Arc::new(RecordedIncidents::default());
            let mut state = ServerState::new(
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
            state.incident_sink = Some(incidents.clone());
            state.dispatch_deadline = deadline;
            state.slow_dispatch_threshold = slow;
            state.cancellation_grace = grace;
            (state, incidents)
        }

        fn short_server() -> (Arc<ServerState>, Arc<RecordedIncidents>) {
            let (state, incidents) = supervised_server(DEADLINE, SLOW, GRACE);
            (Arc::new(state), incidents)
        }

        // ── handles whose `read` misbehaves ──────────────────────────────

        enum Fault {
            /// `read` panics.
            Panic,
            /// `read` never completes; its future holds a guard that sets the
            /// flag when dropped, so a test can see that cancellation finished.
            Never { dropped: Arc<AtomicBool> },
            /// `read` blocks the worker thread without yielding.
            SyncBlock(Duration),
            /// `close` panics, which a TREE_DISCONNECT (a serialized frame)
            /// reaches through the tree teardown.
            PanicOnClose,
        }

        struct FaultHandle {
            fault: Fault,
            entered: mpsc::UnboundedSender<()>,
        }

        struct DropFlag(Arc<AtomicBool>);

        impl Drop for DropFlag {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        #[async_trait]
        impl Handle for FaultHandle {
            async fn read(&self, _offset: u64, _len: u32) -> SmbResult<Bytes> {
                let _ = self.entered.send(());
                match &self.fault {
                    Fault::Panic => panic!("handler exploded"),
                    Fault::Never { dropped } => {
                        let _guard = DropFlag(dropped.clone());
                        std::future::pending::<()>().await;
                        unreachable!("a pending future never resolves")
                    }
                    Fault::SyncBlock(duration) => {
                        std::thread::sleep(*duration);
                        Ok(Bytes::from_static(b"0123456789abcdef"))
                    }
                    Fault::PanicOnClose => Ok(Bytes::from_static(b"0123456789abcdef")),
                }
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
                    end_of_file: 16,
                    allocation_size: 16,
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
                Ok(vec![])
            }
            async fn close(self: Box<Self>) -> SmbResult<()> {
                if matches!(self.fault, Fault::PanicOnClose) {
                    panic!("close exploded");
                }
                Ok(())
            }
        }

        fn fault_handle(fault: Fault) -> (Box<dyn Handle>, mpsc::UnboundedReceiver<()>) {
            let (entered, entered_rx) = mpsc::unbounded_channel();
            (Box::new(FaultHandle { fault, entered }), entered_rx)
        }

        fn never_fault() -> (Fault, Arc<AtomicBool>) {
            let dropped = Arc::new(AtomicBool::new(false));
            (
                Fault::Never {
                    dropped: dropped.clone(),
                },
                dropped,
            )
        }

        /// A share backend whose every `open` yields a handle built by `make`,
        /// so a CREATE on the wire reaches a handle of the test's choosing.
        struct HandleBackend {
            make: Box<dyn Fn() -> Box<dyn Handle> + Send + Sync>,
        }

        #[async_trait]
        impl crate::backend::ShareBackend for HandleBackend {
            async fn open(
                &self,
                _path: &crate::path::SmbPath,
                _opts: crate::backend::OpenOptions,
            ) -> SmbResult<Box<dyn Handle>> {
                Ok((self.make)())
            }
            async fn unlink(&self, _path: &crate::path::SmbPath) -> SmbResult<()> {
                Err(crate::error::SmbError::NotSupported)
            }
            async fn rename(
                &self,
                _from: &crate::path::SmbPath,
                _to: &crate::path::SmbPath,
                _replace: bool,
            ) -> SmbResult<()> {
                Err(crate::error::SmbError::NotSupported)
            }
            fn capabilities(&self) -> crate::backend::BackendCapabilities {
                crate::backend::BackendCapabilities::default()
            }
        }

        /// A session of an authenticated user holding `SIGNING_KEY`, one tree
        /// over `backend`, and no opens: a signed session that a CREATE on the
        /// wire populates.
        async fn signed_connection_over(backend: HandleBackend) -> (Arc<Connection>, u64, u32) {
            let conn = Arc::new(Connection::new(1, Uuid::nil(), 1 << 20, 1 << 20));
            let session_id = conn.alloc_session_id();
            let session = Session::new(
                session_id,
                Identity::User {
                    user: "tester".to_owned(),
                    domain: String::new(),
                },
                [0; 16],
                SIGNING_KEY,
                false,
                None,
            );
            let tree_id = session.alloc_tree_id();
            let share = ShareBindings::new(
                "test".to_owned(),
                Arc::new(backend),
                ShareMode::Public,
                HashMap::new(),
                false,
            );
            let tree = TreeConnect::new(tree_id, share, Access::ReadWrite);
            session
                .trees
                .write()
                .await
                .insert(tree_id, Arc::new(RwLock::new(tree)));
            conn.sessions
                .write()
                .await
                .insert(session_id, Arc::new(RwLock::new(session)));
            conn.snapshot_session(session_id, SIGNING_KEY, false);
            (conn, session_id, tree_id)
        }

        // ── the wire ─────────────────────────────────────────────────────

        struct Wire {
            client: TcpStream,
            reader: tokio::task::JoinHandle<io::Result<()>>,
        }

        enum Recv {
            Frame(Vec<u8>),
            Eof,
            Silent,
        }

        impl Recv {
            fn frame(self, what: &str) -> Vec<u8> {
                match self {
                    Recv::Frame(frame) => frame,
                    Recv::Eof => panic!("{what}: the connection closed instead"),
                    Recv::Silent => panic!("{what}: no response arrived in time"),
                }
            }
        }

        /// Runs the connection the way `connection_loop` does — a real writer
        /// task plus `reader_task` — over a loopback socket.
        async fn spawn_wire(server: Arc<ServerState>, conn: Arc<Connection>) -> Wire {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let addr = listener.local_addr().expect("addr");
            let (accepted, connected) = tokio::join!(listener.accept(), TcpStream::connect(addr));
            let server_side = accepted.expect("accept").0;
            let client = connected.expect("connect");
            let (read_half, write_half) = tokio::io::split(server_side);
            let (tx, rx) = mpsc::channel(WRITER_CHANNEL);
            tokio::spawn(writer_task(write_half, rx, conn.subscribe_close()));
            let reader = tokio::spawn(reader_task(read_half, server, conn, tx));
            Wire { client, reader }
        }

        impl Wire {
            async fn send(&mut self, payload: &[u8]) {
                write_frame(&mut self.client, payload).await;
            }

            async fn send_raw(&mut self, bytes: &[u8]) {
                self.client.write_all(bytes).await.expect("write raw bytes");
            }

            async fn recv(&mut self, within: Duration) -> Recv {
                let read = async {
                    let mut hdr = [0u8; FRAME_HEADER_LEN];
                    self.client.read_exact(&mut hdr).await?;
                    let len = decode_frame_header(&hdr)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                    let mut payload = vec![0u8; len as usize];
                    self.client.read_exact(&mut payload).await?;
                    io::Result::Ok(payload)
                };
                match tokio::time::timeout(within, read).await {
                    Err(_) => Recv::Silent,
                    Ok(Ok(frame)) => Recv::Frame(frame),
                    Ok(Err(_)) => Recv::Eof,
                }
            }

            /// A TREE_DISCONNECT is a barrier frame: it is answered, with any
            /// status, only if the connection is alive and unstalled.
            async fn assert_barrier_answered(&mut self, message_id: u64, ids: (u64, u32)) {
                let hdr = header(Command::TreeDisconnect, message_id, ids.0, ids.1);
                self.send(&tree_disconnect_payload(&hdr)).await;
                let response = self
                    .recv(Duration::from_secs(5))
                    .await
                    .frame("the barrier frame after the fault");
                assert_eq!(header_command(&response), Command::TreeDisconnect as u16);
            }
        }

        // ── frame builders ───────────────────────────────────────────────

        fn body_of(payload: &[u8]) -> Vec<u8> {
            payload[SMB2_HEADER_LEN..].to_vec()
        }

        fn read_body(file_id: FileId) -> Vec<u8> {
            let hdr = header(Command::Read, 0, 0, 0);
            body_of(&read_request_payload(&hdr, file_id))
        }

        fn echo_body() -> Vec<u8> {
            body_of(&echo_payload(&header(Command::Echo, 0, 0, 0)))
        }

        fn align8(n: usize) -> usize {
            (n + 7) & !7
        }

        /// Builds a compound frame from `(header, body)` parts. Every part but
        /// the first is marked related; every part is padded to 8 bytes (except
        /// the last) and, with `key`, signed over its own padded bytes, exactly
        /// as a client signs the wire form (sentinel ids included).
        fn compound(parts: Vec<(Smb2Header, Vec<u8>)>, key: Option<[u8; 16]>) -> Vec<u8> {
            let count = parts.len();
            let mut out = Vec::new();
            for (index, (mut hdr, body)) in parts.into_iter().enumerate() {
                let last = index + 1 == count;
                let padded = if last {
                    SMB2_HEADER_LEN + body.len()
                } else {
                    align8(SMB2_HEADER_LEN + body.len())
                };
                hdr.next_command = if last { 0 } else { padded as u32 };
                if index > 0 {
                    hdr.flags |= SMB2_FLAGS_RELATED_OPERATIONS;
                }
                if key.is_some() {
                    hdr.flags |= SMB2_FLAGS_SIGNED;
                }
                let mut part = frame_payload(&hdr, &body);
                part.resize(padded, 0);
                if let Some(key) = key {
                    sign(&mut part, &key, SigningAlgo::HmacSha256).expect("sign request");
                }
                out.extend_from_slice(&part);
            }
            out
        }

        fn sentinel_header(command: Command, message_id: u64) -> Smb2Header {
            header(command, message_id, u64::MAX, u32::MAX)
        }

        /// The entries of a (possibly compound) response, each trimmed of its
        /// alignment padding where the chain says so.
        fn response_entries(frame: &[u8]) -> Vec<Vec<u8>> {
            let mut entries = Vec::new();
            let mut offset = 0;
            loop {
                let next = read_u32(frame, offset + 0x14) as usize;
                if next == 0 {
                    entries.push(frame[offset..].to_vec());
                    return entries;
                }
                entries.push(frame[offset..offset + next].to_vec());
                offset += next;
            }
        }

        fn status_of(entry: &[u8]) -> u32 {
            read_u32(entry, 0x08)
        }

        fn session_id_of(entry: &[u8]) -> u64 {
            u64::from_le_bytes(entry[0x28..0x30].try_into().unwrap())
        }

        fn tree_id_of(entry: &[u8]) -> u32 {
            read_u32(entry, 0x24)
        }

        /// Whether the entry carries a valid signature. The padding after the
        /// signed bytes is unknown to the caller, so each possible length is
        /// tried.
        fn signature_valid(entry: &[u8]) -> bool {
            if read_u32(entry, 0x10) & SMB2_FLAGS_SIGNED == 0 {
                return false;
            }
            (entry.len().saturating_sub(7)..=entry.len())
                .filter(|len| *len >= SMB2_HEADER_LEN)
                .any(|len| verify(&entry[..len], &SIGNING_KEY, SigningAlgo::HmacSha256).is_ok())
        }

        // ── panic and deadline ───────────────────────────────────────────

        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn panicking_dispatch_is_answered_and_the_barrier_proceeds() {
            let (server, incidents) = short_server();
            let (handle, _entered) = fault_handle(Fault::Panic);
            let (conn, session_id, tree_id, file_ids) =
                seeded_connection(&server, vec![handle]).await;
            let mut wire = spawn_wire(server, conn).await;

            let hdr = header(Command::Read, 41, session_id, tree_id);
            wire.send(&read_request_payload(&hdr, file_ids[0])).await;

            let started = std::time::Instant::now();
            let response = wire
                .recv(DEADLINE / 2)
                .await
                .frame("a panicking READ must be answered well before the deadline");
            assert!(started.elapsed() < DEADLINE / 2);
            assert_eq!(header_command(&response), Command::Read as u16);
            assert_eq!(status_of(&response), STATUS_INTERNAL_ERROR);

            wire.assert_barrier_answered(42, (session_id, tree_id))
                .await;

            let panicked = incidents.of_kind(is_panicked);
            assert_eq!(panicked.len(), 1, "exactly one Panicked incident");
            let incident = &panicked[0];
            assert!(matches!(
                &incident.kind,
                IncidentKind::Panicked { message } if message.contains("handler exploded")
            ));
            assert_eq!(incident.command, Some("Read"));
            assert_eq!(incident.message_id, Some(41));
            assert_eq!(incident.path.as_deref(), Some("block.txt"));
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn never_completing_dispatch_times_out_and_the_barrier_proceeds() {
            let (fault, dropped) = never_fault();
            let (handle, _entered) = fault_handle(fault);
            let (mut state, incidents) = supervised_server(DEADLINE, SLOW, GRACE);
            let flag_sink = Arc::new(FlagAtTreeDisconnect {
                flag: dropped.clone(),
                seen: StdMutex::new(None),
            });
            state.trace_sink = Some(flag_sink.clone());
            let server = Arc::new(state);
            let (conn, session_id, tree_id, file_ids) =
                seeded_connection(&server, vec![handle]).await;
            let mut wire = spawn_wire(server, conn).await;

            let hdr = header(Command::Read, 51, session_id, tree_id);
            wire.send(&read_request_payload(&hdr, file_ids[0])).await;

            let started = std::time::Instant::now();
            let response = wire
                .recv(DEADLINE + GRACE + Duration::from_secs(1))
                .await
                .frame("a never-completing READ must be answered at its deadline");
            let elapsed = started.elapsed();
            assert_eq!(status_of(&response), STATUS_IO_TIMEOUT);
            assert!(
                elapsed >= DEADLINE - Duration::from_millis(50),
                "answered before the deadline: {elapsed:?}"
            );
            assert!(
                elapsed < DEADLINE + GRACE,
                "answered later than deadline + grace: {elapsed:?}"
            );

            wire.assert_barrier_answered(52, (session_id, tree_id))
                .await;
            assert_eq!(
                *flag_sink.seen.lock().unwrap(),
                Some(true),
                "the abandoned handler's future must be dropped before the TREE_DISCONNECT runs"
            );

            let slow = incidents.of_kind(is_slow);
            let timed_out = incidents.of_kind(is_timed_out);
            assert_eq!(slow.len(), 1, "one Slow incident");
            assert_eq!(timed_out.len(), 1, "one TimedOut incident");
            assert_eq!(slow[0].path.as_deref(), Some("block.txt"));
            assert_eq!(identity(&slow[0]), identity(&timed_out[0]));
            assert_eq!(slow[0].message_id, Some(51));
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn non_yielding_handler_closes_the_connection_after_the_grace() {
            let (server, incidents) = short_server();
            let block = DEADLINE + GRACE + Duration::from_secs(1);
            let (handle, mut entered) = fault_handle(Fault::SyncBlock(block));
            let (conn, session_id, tree_id, file_ids) =
                seeded_connection(&server, vec![handle]).await;
            let mut wire = spawn_wire(server, conn).await;

            let started = std::time::Instant::now();
            let hdr = header(Command::Read, 61, session_id, tree_id);
            wire.send(&read_request_payload(&hdr, file_ids[0])).await;
            assert!(recv_within(&mut entered, Duration::from_secs(5)).await);
            let td = header(Command::TreeDisconnect, 62, session_id, tree_id);
            wire.send(&tree_disconnect_payload(&td)).await;

            match wire.recv(block - Duration::from_millis(100)).await {
                Recv::Eof => {}
                Recv::Frame(_) => panic!("a response arrived instead of the close"),
                Recv::Silent => panic!(
                    "the connection was not closed after deadline + grace; incidents: {:?}",
                    incidents.all()
                ),
            }
            let closed_after = started.elapsed();
            assert!(
                closed_after >= DEADLINE + GRACE - Duration::from_millis(50),
                "closed before deadline + grace: {closed_after:?}"
            );
            // Real elapsed time, not the runtime's: the `recv` bound above
            // runs on the runtime's own timers, which a blocked worker can
            // stall. The close must land well before the handler's sleep
            // ends; the slack covers the 100 ms pulse lag and scheduling.
            assert!(
                closed_after < DEADLINE + GRACE + Duration::from_millis(500),
                "closed only after {closed_after:?}, not shortly after deadline + grace \
                 (the handler sleeps for {block:?})"
            );
            assert!(
                !wire.reader.is_finished(),
                "reader_task must not return while the abandoned handler still runs"
            );

            let result = tokio::time::timeout(Duration::from_secs(5), &mut wire.reader)
                .await
                .expect("reader_task returns once the sleep ends")
                .expect("join");
            assert!(result.is_ok());
            assert!(started.elapsed() >= block - Duration::from_millis(50));
            assert!(
                !incidents.of_kind(is_closed).is_empty(),
                "a ConnectionClosed incident"
            );
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn timeout_response_is_built_while_session_state_is_contended() {
            let (fault, _dropped) = never_fault();
            let (handle, _entered) = fault_handle(fault);
            let (server, _incidents) = short_server();
            let backend = HandleBackend {
                make: Box::new(|| unreachable!("no CREATE in this test")),
            };
            let (conn, session_id, tree_id) = signed_connection_over(backend).await;
            // Seed an open the READ can target.
            let tree = crate::tests::handler_support::tree_of(&conn, session_id, tree_id).await;
            let file_id = {
                let tree = tree.read().await;
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
                file_id
            };
            let session = conn
                .sessions
                .read()
                .await
                .get(&session_id)
                .cloned()
                .expect("session");
            let mut wire = spawn_wire(server, conn.clone()).await;

            // Contend the session state from before the READ is admitted until
            // after the deadline.
            let sessions_guard = conn.sessions.write().await;
            let session_guard = session.write().await;

            let mut hdr = header(Command::Read, 71, session_id, tree_id);
            hdr.flags |= SMB2_FLAGS_SIGNED;
            let mut payload = read_request_payload(&hdr, file_id);
            sign(&mut payload, &SIGNING_KEY, SigningAlgo::HmacSha256).expect("sign");
            wire.send(&payload).await;

            let response = wire
                .recv(DEADLINE + GRACE + Duration::from_secs(1))
                .await
                .frame("the timeout response must not wait for the contended session state");
            assert_eq!(status_of(&response), STATUS_IO_TIMEOUT);
            assert!(
                signature_valid(&response),
                "the timeout response of a signed session must be correctly signed"
            );

            drop(session_guard);
            drop(sessions_guard);
            wire.assert_barrier_answered(72, (session_id, tree_id))
                .await;
        }

        // ── compounds ────────────────────────────────────────────────────

        /// CREATE + related READ + related CLOSE, signed, with the all-ones
        /// sentinels a client puts on the related requests; every handle the
        /// backend yields is `fault`.
        async fn run_signed_create_read_close(
            fault: impl Fn() -> Fault + Send + Sync + 'static,
        ) -> (Vec<Vec<u8>>, Arc<RecordedIncidents>, usize, (u64, u32)) {
            let (server, incidents) = short_server();
            let backend = HandleBackend {
                make: Box::new(move || fault_handle(fault()).0),
            };
            let (conn, session_id, tree_id) = signed_connection_over(backend).await;
            let mut wire = spawn_wire(server, conn.clone()).await;

            let create_hdr = header(Command::Create, 81, session_id, tree_id);
            let create_body = create_request("hang.txt", 0, 1, 0x1);
            let read_hdr = sentinel_header(Command::Read, 82);
            let close_hdr = sentinel_header(Command::Close, 83);
            let frame = compound(
                vec![
                    (create_hdr, create_body),
                    (read_hdr, read_body(FileId::any())),
                    (close_hdr, close_request(FileId::any())),
                ],
                Some(SIGNING_KEY),
            );
            wire.send(&frame).await;

            let response = wire
                .recv(DEADLINE + 3 * GRACE + Duration::from_secs(1))
                .await
                .frame("the compound response");
            let entries = response_entries(&response);
            // Counted before the barrier frame, which tears the tree down.
            let opens = crate::tests::handler_support::open_count(&conn, session_id, tree_id).await;
            wire.assert_barrier_answered(84, (session_id, tree_id))
                .await;
            (entries, incidents, opens, (session_id, tree_id))
        }

        fn assert_prefix_kept_and_rest_run(
            entries: &[Vec<u8>],
            ids: (u64, u32),
            expected_middle: u32,
        ) {
            assert_eq!(entries.len(), 3, "one compound response with three entries");
            assert_eq!(status_of(&entries[0]), STATUS_SUCCESS, "CREATE kept");
            assert_eq!(status_of(&entries[1]), expected_middle, "READ");
            assert_eq!(status_of(&entries[2]), STATUS_SUCCESS, "CLOSE ran");
            for (position, entry) in entries.iter().enumerate() {
                assert_eq!(session_id_of(entry), ids.0, "entry {position}: session id");
                assert_eq!(tree_id_of(entry), ids.1, "entry {position}: tree id");
                assert!(signature_valid(entry), "entry {position}: signature");
            }
        }

        fn assert_attributed_to_the_read(incident: &Incident) {
            assert_eq!(incident.command, Some("Read"));
            assert_eq!(incident.message_id, Some(82));
            assert_eq!(incident.compound_ordinal, Some(1));
            assert_eq!(incident.path.as_deref(), Some("hang.txt"));
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn signed_related_compound_keeps_completed_prefix_and_runs_the_rest() {
            let (entries, incidents, opens, ids) =
                run_signed_create_read_close(|| never_fault().0).await;
            assert_prefix_kept_and_rest_run(&entries, ids, STATUS_IO_TIMEOUT);
            assert_eq!(opens, 0, "the CLOSE released the Open the CREATE made");

            let slow = incidents.of_kind(is_slow);
            let timed_out = incidents.of_kind(is_timed_out);
            assert_eq!(slow.len(), 1);
            assert_eq!(timed_out.len(), 1);
            assert_attributed_to_the_read(&slow[0]);
            assert_attributed_to_the_read(&timed_out[0]);
            assert_eq!(identity(&slow[0]), identity(&timed_out[0]));
            assert!(
                incidents
                    .all()
                    .iter()
                    .all(|i| i.command != Some("Create") && i.command != Some("Close")),
                "no incident names the CREATE or the CLOSE"
            );
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn signed_related_compound_panic_keeps_completed_prefix() {
            let (entries, incidents, _opens, ids) =
                run_signed_create_read_close(|| Fault::Panic).await;
            assert_prefix_kept_and_rest_run(&entries, ids, STATUS_INTERNAL_ERROR);

            let panicked = incidents.of_kind(is_panicked);
            assert_eq!(panicked.len(), 1, "a single Panicked incident");
            assert_attributed_to_the_read(&panicked[0]);
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn compound_of_pending_reads_is_answered_within_one_budget() {
            let (server, incidents) = short_server();
            let mut handles = Vec::new();
            let mut entries_rx = Vec::new();
            for _ in 0..3 {
                let (fault, _dropped) = never_fault();
                let (handle, entered) = fault_handle(fault);
                handles.push(handle);
                entries_rx.push(entered);
            }
            let (conn, session_id, tree_id, file_ids) = seeded_connection(&server, handles).await;
            let mut wire = spawn_wire(server, conn.clone()).await;

            let mut parts = Vec::new();
            for (index, file_id) in file_ids.iter().enumerate() {
                parts.push((
                    header(Command::Read, 90 + index as u64, session_id, tree_id),
                    read_body(*file_id),
                ));
            }
            parts.push((
                header(Command::Close, 93, session_id, tree_id),
                close_request(file_ids[0]),
            ));
            let started = std::time::Instant::now();
            wire.send(&compound(parts, None)).await;

            let response = wire
                .recv(DEADLINE + 3 * GRACE + Duration::from_secs(1))
                .await
                .frame("the compound of pending READs");
            let elapsed = started.elapsed();
            assert!(
                elapsed >= DEADLINE - Duration::from_millis(50)
                    && elapsed < DEADLINE * 2 - Duration::from_millis(100),
                "answered within one budget, not one per READ: {elapsed:?}"
            );
            let entries = response_entries(&response);
            let statuses: Vec<u32> = entries.iter().map(|e| status_of(e)).collect();
            assert_eq!(
                statuses,
                vec![
                    STATUS_IO_TIMEOUT,
                    STATUS_IO_TIMEOUT,
                    STATUS_IO_TIMEOUT,
                    STATUS_SUCCESS
                ]
            );
            assert!(
                entries_rx[0].try_recv().is_ok(),
                "READ 1 entered its handler"
            );
            assert!(
                entries_rx[1].try_recv().is_err() && entries_rx[2].try_recv().is_err(),
                "READs 2 and 3 are answered without being executed"
            );
            assert_eq!(
                crate::tests::handler_support::open_count(&conn, session_id, tree_id).await,
                2,
                "the CLOSE executed: only READ 1's open is gone"
            );
            let timed_out = incidents.of_kind(is_timed_out);
            assert_eq!(timed_out.len(), 1, "READ 1 has a TimedOut incident");
            assert_eq!(timed_out[0].message_id, Some(90));

            wire.assert_barrier_answered(94, (session_id, tree_id))
                .await;
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn reused_message_id_keeps_distinct_identities() {
            let (server, incidents) = short_server();
            let (fault, _dropped) = never_fault();
            let (handle, _entered) = fault_handle(fault);
            let (conn, session_id, tree_id, file_ids) =
                seeded_connection(&server, vec![handle]).await;
            let mut wire = spawn_wire(server, conn).await;

            let frame = compound(
                vec![
                    (header(Command::Echo, 5, session_id, tree_id), echo_body()),
                    (
                        header(Command::Read, 5, session_id, tree_id),
                        read_body(file_ids[0]),
                    ),
                ],
                None,
            );
            wire.send(&frame).await;
            let response = wire
                .recv(DEADLINE + 3 * GRACE + Duration::from_secs(1))
                .await
                .frame("the compound response");
            let entries = response_entries(&response);
            assert_eq!(status_of(&entries[0]), STATUS_SUCCESS);
            assert_eq!(status_of(&entries[1]), STATUS_IO_TIMEOUT);

            let slow = incidents.of_kind(is_slow);
            let timed_out = incidents.of_kind(is_timed_out);
            assert_eq!(slow.len(), 1);
            assert_eq!(timed_out.len(), 1);
            assert_eq!(slow[0].compound_ordinal, Some(1));
            assert_eq!(timed_out[0].compound_ordinal, Some(1));
            assert!(
                incidents
                    .all()
                    .iter()
                    .all(|i| i.compound_ordinal != Some(0)),
                "no incident carries ordinal 0"
            );
            assert_eq!(identity(&slow[0]), identity(&timed_out[0]));
            wire.assert_barrier_answered(6, (session_id, tree_id)).await;
        }

        // ── malformed frames ─────────────────────────────────────────────

        async fn expect_closed_without_response(wire: &mut Wire, what: &str) {
            match wire.recv(Duration::from_secs(3)).await {
                Recv::Eof => {}
                Recv::Frame(_) => panic!("{what}: a response arrived, the connection must close"),
                Recv::Silent => panic!("{what}: the connection stayed open and silent"),
            }
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn malformed_frame_closes_the_connection() {
            let (server, incidents) = short_server();
            let (conn, session_id, tree_id, _files) = seeded_connection(&server, vec![]).await;
            let mut wire = spawn_wire(server, conn).await;

            // A valid length prefix over a header whose command opcode is unknown.
            let mut garbled =
                frame_payload(&header(Command::Echo, 1, session_id, tree_id), &[0; 4]);
            garbled[12] = 0xFF;
            garbled[13] = 0xFF;
            wire.send(&garbled).await;
            let td = header(Command::TreeDisconnect, 2, session_id, tree_id);
            wire.send(&tree_disconnect_payload(&td)).await;

            expect_closed_without_response(&mut wire, "a header that does not parse").await;
            let malformed = incidents.of_kind(is_malformed);
            assert_eq!(malformed.len(), 1);
            assert!(matches!(
                &malformed[0].kind,
                IncidentKind::MalformedFrame { reason } if !reason.is_empty()
            ));
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn next_command_at_frame_end_is_malformed() {
            let (server, incidents) = short_server();
            let (conn, session_id, tree_id, _files) = seeded_connection(&server, vec![]).await;
            let mut wire = spawn_wire(server, conn).await;

            let mut hdr = header(Command::Echo, 1, session_id, tree_id);
            let length = SMB2_HEADER_LEN + echo_body().len();
            hdr.next_command = length as u32;
            wire.send(&frame_payload(&hdr, &echo_body())).await;

            expect_closed_without_response(&mut wire, "NextCommand at the frame end").await;
            assert_eq!(incidents.of_kind(is_malformed).len(), 1);
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn short_compound_tail_is_malformed_and_runs_nothing() {
            let (server, incidents) = short_server();
            let release = Arc::new(Notify::new());
            let (entered_tx, mut entered_rx) = mpsc::unbounded_channel();
            let (conn, session_id, tree_id, file_ids) =
                seeded_connection(&server, vec![blocking_handle(release.clone(), entered_tx)])
                    .await;
            let mut wire = spawn_wire(server, conn).await;

            let read_hdr = header(Command::Read, 1, session_id, tree_id);
            let mut frame = compound(
                vec![
                    (read_hdr, read_body(file_ids[0])),
                    (header(Command::Echo, 2, session_id, tree_id), echo_body()),
                ],
                None,
            );
            // Cut the second element down to fewer bytes than a header.
            let second_start = read_u32(&frame, 0x14) as usize;
            frame.truncate(second_start + SMB2_HEADER_LEN - 30);
            wire.send(&frame).await;

            expect_closed_without_response(&mut wire, "a compound tail shorter than a header")
                .await;
            assert!(
                entered_rx.try_recv().is_err(),
                "the READ handler must never be entered"
            );
            assert_eq!(incidents.of_kind(is_malformed).len(), 1);
            release.notify_waiters();
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn invalid_frame_length_header_is_a_malformed_incident() {
            let (server, incidents) = short_server();
            let (conn, _session_id, _tree_id, _files) = seeded_connection(&server, vec![]).await;
            let mut wire = spawn_wire(server, conn).await;

            // The NetBIOS session-message type byte must be zero.
            wire.send_raw(&[0x01, 0x00, 0x00, 0x04, 0, 0, 0, 0]).await;

            expect_closed_without_response(&mut wire, "an undecodable framing header").await;
            let malformed = incidents.of_kind(is_malformed);
            assert_eq!(
                malformed.len(),
                1,
                "a MalformedFrame incident for the framing error"
            );
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn a_failed_pulse_start_refuses_that_request_and_keeps_the_connection() {
            let (state, incidents) = supervised_server(DEADLINE, SLOW, GRACE);
            // Exactly one start fails, through the test seam; the retry on the
            // next request succeeds.
            state.pulse.inject_start_failures(1);
            let server = Arc::new(state);
            let release = Arc::new(Notify::new());
            let (entered_tx, mut entered_rx) = mpsc::unbounded_channel();
            let (conn, session_id, tree_id, file_ids) =
                seeded_connection(&server, vec![blocking_handle(release.clone(), entered_tx)])
                    .await;
            let connection_id = conn.connection_id;
            let mut wire = spawn_wire(server, conn).await;

            // A READ whose handler would signal on entry: refused, never run.
            let first = header(Command::Read, 11, session_id, tree_id);
            wire.send(&read_request_payload(&first, file_ids[0])).await;
            let response = wire
                .recv(Duration::from_secs(3))
                .await
                .frame("the refused request must still be answered");
            assert_eq!(header_command(&response), Command::Read as u16);
            assert_eq!(status_of(&response), STATUS_INSUFFICIENT_RESOURCES);
            assert!(
                entered_rx.try_recv().is_err(),
                "the refused request's handler must never run"
            );

            // The same connection retries the start and answers normally.
            let second = header(Command::Echo, 12, session_id, tree_id);
            wire.send(&echo_payload(&second)).await;
            let response = wire
                .recv(Duration::from_secs(3))
                .await
                .frame("the connection must stay usable and retry the start");
            assert_eq!(header_command(&response), Command::Echo as u16);
            assert_eq!(status_of(&response), STATUS_SUCCESS);

            let unavailable = incidents.of_kind(is_unavailable);
            assert_eq!(
                unavailable.len(),
                1,
                "one incident for the one failed start"
            );
            assert!(matches!(
                &unavailable[0].kind,
                IncidentKind::SupervisionUnavailable { reason }
                    if reason.contains("injected pulse start failure")
            ));
            assert_eq!(
                identity(&unavailable[0]),
                (connection_id, Some(11), Some(0))
            );
            assert_eq!(unavailable[0].command, Some("Read"));
            assert_eq!(unavailable[0].path.as_deref(), Some("block.txt"));
            assert!(
                incidents.of_kind(is_closed).is_empty(),
                "the connection was not closed"
            );
            wire.assert_barrier_answered(13, (session_id, tree_id))
                .await;
        }

        /// A CANCEL is never answered, not even when it is the request that
        /// is refused: it takes the injected start failure silently, and the
        /// next request is the one that is answered.
        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn a_refused_cancel_stays_unanswered() {
            let (state, incidents) = supervised_server(DEADLINE, SLOW, GRACE);
            state.pulse.inject_start_failures(1);
            let server = Arc::new(state);
            let (conn, session_id, tree_id, _files) = seeded_connection(&server, vec![]).await;
            let mut wire = spawn_wire(server, conn).await;

            // One compound frame, so the CANCEL is deterministically the
            // sub-request that meets the failed start.
            let frame = compound(
                vec![
                    (
                        header(Command::Cancel, 21, session_id, tree_id),
                        vec![0u8; 4],
                    ),
                    (header(Command::Echo, 22, session_id, tree_id), echo_body()),
                ],
                None,
            );
            wire.send(&frame).await;

            let response = wire
                .recv(Duration::from_secs(3))
                .await
                .frame("the ECHO after the refused CANCEL");
            assert_eq!(
                header_command(&response),
                Command::Echo as u16,
                "the response must be the ECHO's alone, not the CANCEL's"
            );
            assert_eq!(status_of(&response), STATUS_SUCCESS);
            assert_eq!(
                response_entries(&response).len(),
                1,
                "the CANCEL contributes no entry"
            );
            assert_eq!(incidents.of_kind(is_unavailable).len(), 1);
        }

        /// Once the frame's budget is spent, the rest of the chain is answered
        /// unexecuted — but a CANCEL never gets the timeout response.
        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn a_cancel_after_the_budget_is_spent_stays_unanswered() {
            let (server, _incidents) = short_server();
            let (fault, _dropped) = never_fault();
            let (handle, _entered) = fault_handle(fault);
            let (conn, session_id, tree_id, file_ids) =
                seeded_connection(&server, vec![handle]).await;
            let mut wire = spawn_wire(server, conn).await;

            let frame = compound(
                vec![
                    (
                        header(Command::Read, 31, session_id, tree_id),
                        read_body(file_ids[0]),
                    ),
                    (
                        header(Command::Cancel, 32, session_id, tree_id),
                        vec![0u8; 4],
                    ),
                    (header(Command::Echo, 33, session_id, tree_id), echo_body()),
                ],
                None,
            );
            wire.send(&frame).await;
            let response = wire
                .recv(DEADLINE + 3 * GRACE + Duration::from_secs(1))
                .await
                .frame("the compound response");
            let entries = response_entries(&response);
            let statuses: Vec<u32> = entries.iter().map(|e| status_of(e)).collect();
            assert_eq!(
                statuses,
                vec![STATUS_IO_TIMEOUT, STATUS_IO_TIMEOUT],
                "READ and ECHO are answered; the CANCEL contributes no entry"
            );
            let commands: Vec<u16> = entries.iter().map(|e| header_command(e)).collect();
            assert_eq!(commands, vec![Command::Read as u16, Command::Echo as u16]);
            wire.assert_barrier_answered(34, (session_id, tree_id))
                .await;
        }

        // ── load and barrier frames ──────────────────────────────────────

        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn sixty_four_hung_dispatches_do_not_stall_the_connection() {
            let (server, _incidents) = short_server();
            let (fault, _dropped) = never_fault();
            let (handle, _entered) = fault_handle(fault);
            let (conn, session_id, tree_id, file_ids) =
                seeded_connection(&server, vec![handle]).await;
            let mut wire = spawn_wire(server, conn).await;

            for i in 0..MAX_INFLIGHT as u64 {
                let hdr = header(Command::Read, 100 + i, session_id, tree_id);
                wire.send(&read_request_payload(&hdr, file_ids[0])).await;
            }
            let echo = header(Command::Echo, 999, session_id, tree_id);
            wire.send(&echo_payload(&echo)).await;

            let mut timed_out = 0;
            let mut echoed = false;
            for _ in 0..=MAX_INFLIGHT {
                let response = wire
                    .recv(Duration::from_secs(10))
                    .await
                    .frame("every READ and the ECHO behind them are answered");
                match header_command(&response) {
                    c if c == Command::Read as u16 => {
                        assert_eq!(status_of(&response), STATUS_IO_TIMEOUT);
                        timed_out += 1;
                    }
                    c if c == Command::Echo as u16 => {
                        assert_eq!(status_of(&response), STATUS_SUCCESS);
                        echoed = true;
                    }
                    other => panic!("unexpected response command {other}"),
                }
            }
            assert_eq!(timed_out, MAX_INFLIGHT);
            assert!(echoed);
            wire.assert_barrier_answered(1000, (session_id, tree_id))
                .await;
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn panic_in_a_serialized_frame_does_not_kill_the_reader() {
            let (server, incidents) = short_server();
            let (handle, _entered) = fault_handle(Fault::PanicOnClose);
            let (conn, session_id, tree_id, _files) =
                seeded_connection(&server, vec![handle]).await;
            let mut wire = spawn_wire(server, conn).await;

            // The TREE_DISCONNECT is a serialized frame whose handler closes
            // the tree's opens, and the open's `close` panics.
            let td = header(Command::TreeDisconnect, 1, session_id, tree_id);
            wire.send(&tree_disconnect_payload(&td)).await;
            let response = wire
                .recv(Duration::from_secs(3))
                .await
                .frame("a panicking serialized frame must be answered");
            assert_eq!(header_command(&response), Command::TreeDisconnect as u16);
            assert_eq!(status_of(&response), STATUS_INTERNAL_ERROR);

            let echo = header(Command::Echo, 2, session_id, tree_id);
            wire.send(&echo_payload(&echo)).await;
            let response = wire
                .recv(Duration::from_secs(3))
                .await
                .frame("the reader must survive the panic and answer the next frame");
            assert_eq!(header_command(&response), Command::Echo as u16);
            assert_eq!(status_of(&response), STATUS_SUCCESS);
            assert_eq!(incidents.of_kind(is_panicked).len(), 1);
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn slow_dispatch_that_finishes_reports_finished() {
            let (server, incidents) = short_server();
            let release = Arc::new(Notify::new());
            let (entered_tx, mut entered_rx) = mpsc::unbounded_channel();
            let (conn, session_id, tree_id, file_ids) =
                seeded_connection(&server, vec![blocking_handle(release.clone(), entered_tx)])
                    .await;
            let mut wire = spawn_wire(server, conn).await;

            let hdr = header(Command::Read, 31, session_id, tree_id);
            wire.send(&read_request_payload(&hdr, file_ids[0])).await;
            assert!(recv_within(&mut entered_rx, Duration::from_secs(5)).await);

            // Past the threshold, before the deadline.
            tokio::time::sleep(SLOW * 2).await;
            release.notify_waiters();

            let response = wire
                .recv(Duration::from_secs(3))
                .await
                .frame("the released READ");
            assert_eq!(status_of(&response), STATUS_SUCCESS);

            let all = incidents.all();
            assert_eq!(all.len(), 2, "Slow, then Finished: {all:?}");
            assert!(matches!(all[0].kind, IncidentKind::Slow));
            assert!(matches!(
                all[1].kind,
                IncidentKind::Finished { elapsed } if elapsed >= SLOW
            ));
            assert_eq!(identity(&all[0]), identity(&all[1]));
            assert_eq!(all[0].message_id, Some(31));
            wire.assert_barrier_answered(32, (session_id, tree_id))
                .await;
        }
    }
}
