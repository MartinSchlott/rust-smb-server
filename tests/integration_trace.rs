//! Cross-stack trace integration tests: a real CREATE+WRITE+CLOSE over the
//! wire, with a capturing `TraceSink`
//! wired into the server, proving — against actually-dispatched traffic,
//! not hand-built events — that the trace carries `create_options` and
//! never carries written bytes.

mod common;

use common::{
    STATUS_SUCCESS, anonymous_session_setup, build_header, negotiate, parse_response_header,
    read_frame, tree_connect, utf16le, write_frame,
};
use smb_server::wire::header::Command;
use smb_server::wire::messages::{
    CloseRequest, CreateRequest, CreateResponse, WriteRequest, WriteResponse,
};
use smb_server::{LocalFsBackend, Share, SmbServer, TraceEvent, TraceKey, TraceSink};
use std::sync::{Arc, Mutex};
use tempfile::tempdir;
use tokio::net::TcpStream;

struct CaptureSink {
    lines: Mutex<Vec<String>>,
}

impl TraceSink for CaptureSink {
    fn record(&self, key: Option<TraceKey>, event: &TraceEvent) {
        self.lines
            .lock()
            .unwrap()
            .push(format!("{key:?} {event:?}"));
    }
}

#[tokio::test]
async fn write_trace_never_carries_the_written_bytes_and_create_carries_raw_options() {
    let td = tempdir().expect("tempdir");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let capture = Arc::new(CaptureSink {
        lines: Mutex::new(Vec::new()),
    });

    let server = SmbServer::builder()
        .listen("127.0.0.1:0".parse().unwrap())
        .user("alice", "password")
        .share(Share::new("share", backend).public())
        .netbios_name("TESTSERVER")
        .trace_sink(capture.clone())
        .build()
        .expect("build");

    server.bind().await.expect("bind");
    let addr = server.local_addr().await.expect("addr");
    let handle = tokio::spawn(async move { server.serve().await });
    tokio::task::yield_now().await;

    let mut s = TcpStream::connect(addr).await.expect("connect");
    let _ = negotiate(&mut s).await;
    let session_id = anonymous_session_setup(&mut s).await;
    let tree_id = tree_connect(&mut s, "\\\\127.0.0.1\\share", session_id, 3).await;

    // ---- CREATE marker.txt, FILE_NON_DIRECTORY_FILE set in CreateOptions ----
    const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
    let name_u16 = utf16le("marker.txt");
    let cr_req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: 0x0012_0089 | 0x0012_0116,
        file_attributes: 0,
        share_access: 0x0000_0007,
        create_disposition: 5, // FILE_OVERWRITE_IF
        create_options: FILE_NON_DIRECTORY_FILE,
        name_offset: 0x78,
        name_length: name_u16.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name: name_u16,
        create_contexts: vec![],
    };
    let mut body = Vec::new();
    cr_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Create, 4, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let cr_resp = CreateResponse::parse(rb).expect("parse create resp");
    let file_id = cr_resp.file_id;

    // ---- WRITE a payload with a unique, greppable marker -----------------
    let payload = b"PAYLOAD_MARKER_DO_NOT_LEAK_0123456789ABCDEF";
    let wr_req = WriteRequest {
        structure_size: 49,
        data_offset: WriteRequest::STANDARD_DATA_OFFSET,
        length: payload.len() as u32,
        offset: 0,
        file_id,
        channel: 0,
        remaining_bytes: 0,
        write_channel_info_offset: 0,
        write_channel_info_length: 0,
        flags: 0,
        data: payload.to_vec(),
    };
    let mut body = Vec::new();
    wr_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Write, 5, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let wr_resp = WriteResponse::parse(rb).expect("parse write resp");
    assert_eq!(wr_resp.count as usize, payload.len());

    // ---- CLOSE -------------------------------------------------------------
    let cl_req = CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id,
    };
    let mut body = Vec::new();
    cl_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Close, 6, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);

    // Confirm the bytes actually landed on disk — the trace assertions
    // below are only meaningful if a real write with these exact bytes
    // happened.
    let on_disk = std::fs::read(td.path().join("marker.txt")).expect("file on disk");
    assert_eq!(on_disk, payload);

    let lines = capture.lines.lock().unwrap();
    assert!(
        !lines.is_empty(),
        "expected Request/Response/Create/Write/Close events to have been captured"
    );

    let marker = std::str::from_utf8(payload).unwrap();
    for line in lines.iter() {
        assert!(
            !line.contains(marker),
            "trace line leaked the written payload bytes: {line}"
        );
    }

    // The WRITE event must still name the length, proving the leak-check
    // above isn't vacuously true because nothing about the write was
    // ever recorded.
    assert!(
        lines
            .iter()
            .any(|l| l.contains("Write") && l.contains(&payload.len().to_string())),
        "expected a Write trace event naming length={}, got: {lines:#?}",
        payload.len()
    );

    // create_options must be the raw CreateOptions value, not just the
    // decoded directory/non_directory booleans.
    assert!(
        lines.iter().any(|l| l.contains("create_options: 64")),
        "expected a Create trace event carrying raw create_options=64 \
         (FILE_NON_DIRECTORY_FILE), got: {lines:#?}"
    );

    drop(s);
    handle.abort();
}
