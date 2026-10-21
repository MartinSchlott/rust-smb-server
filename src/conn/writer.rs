//! Per-connection writer task: serializes responses, applies signing, and
//! frames the bytes onto the wire.

use crate::proto::framing::encode_frame;
use tokio::io::{AsyncWriteExt, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};
use tracing::{debug, error};

/// One packet of bytes to send. Already includes the final SMB2 header +
/// body, *with signing already applied if required*.
pub type FramePayload = Vec<u8>;

/// Writer-task channel size: large enough that a slow remote rarely backs up
/// the dispatcher.
pub const WRITER_CHANNEL: usize = 64;

/// Writes responses until the channel closes or the connection is told to
/// close (`Connection::close`). Either way it ends with `shutdown()`, which
/// sends FIN; returning drops the receiver, which is what stops the reader's
/// admission.
///
/// A close request wins over queued responses: a connection being closed has
/// no use for them, and a client blocked on a response it will never get is
/// freed by the FIN.
pub async fn writer_task(
    mut writer: WriteHalf<TcpStream>,
    mut rx: mpsc::Receiver<FramePayload>,
    mut close: watch::Receiver<bool>,
) {
    loop {
        // A dropped signal sender means nothing can ask for a close any more,
        // not that a close was asked for.
        let close_requested = async {
            if close.wait_for(|closed| *closed).await.is_err() {
                std::future::pending::<()>().await;
            }
        };
        tokio::select! {
            biased;
            _ = close_requested => {
                debug!("writer task: close requested");
                break;
            }
            payload = rx.recv() => {
                let Some(payload) = payload else { break };
                let mut out = Vec::with_capacity(payload.len() + 4);
                encode_frame(&payload, &mut out);
                if let Err(e) = writer.write_all(&out).await {
                    error!(error = %e, "writer task: socket write failed");
                    return;
                }
                debug!(len = out.len(), "wrote frame");
            }
        }
    }
    // Channel closed or close requested — flush and bail.
    if let Err(e) = writer.shutdown().await {
        debug!(error = %e, "writer shutdown error (best-effort)");
    }
}
