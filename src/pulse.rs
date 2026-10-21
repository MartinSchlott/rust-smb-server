//! The runtime pulse: keeps the runtime's timers alive while a handler blocks
//! a worker thread.
//!
//! A handler that blocks synchronously (a syscall, a lock, `thread::sleep`)
//! can stall *every* timer of a multi-thread tokio runtime. The worker woken
//! by socket I/O holds the time driver, runs reader -> frame task -> handler
//! through its LIFO slot and blocks; the other workers stay parked on their
//! condvar and nobody polls the driver. The supervisor's slow, deadline and
//! grace timers — the only way to free a client from such a handler — would
//! never fire.
//!
//! A remote `spawn` wakes a parked worker, which then takes over the driver.
//! So while at least one supervised handler is in flight, one OS thread spawns
//! an empty task on the server's runtime every [`PULSE_INTERVAL`]; the timers
//! then fire with at most about that much lag. With nothing in flight the
//! thread parks, so an idle mount pays no wakeups.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, Once, Weak};
use std::time::Duration;

/// How often the pulse wakes the runtime while a handler is in flight.
const PULSE_INTERVAL: Duration = Duration::from_millis(100);

/// How often an idle pulse thread checks that its server still exists.
const IDLE_CHECK: Duration = Duration::from_secs(1);

struct Shared {
    in_flight: AtomicUsize,
    /// Only ever locked to park on, or to wake, `wake_up`.
    parked: Mutex<()>,
    wake_up: Condvar,
}

/// One per `ServerState`; the thread starts lazily on the first handler.
pub(crate) struct Pulse {
    shared: Arc<Shared>,
    started: Once,
}

/// Marks one supervised handler as in flight until dropped.
pub(crate) struct InFlight<'a> {
    shared: &'a Shared,
}

impl Pulse {
    pub(crate) fn new() -> Self {
        Self {
            shared: Arc::new(Shared {
                in_flight: AtomicUsize::new(0),
                parked: Mutex::new(()),
                wake_up: Condvar::new(),
            }),
            started: Once::new(),
        }
    }

    /// Registers a handler as in flight. Must be called inside the server's
    /// runtime: the first call captures its handle for the pulse thread.
    pub(crate) fn enter(&self) -> InFlight<'_> {
        self.started.call_once(|| {
            let handle = tokio::runtime::Handle::current();
            let shared = Arc::downgrade(&self.shared);
            let spawned = std::thread::Builder::new()
                .name("smb-runtime-pulse".to_owned())
                .spawn(move || run(shared, handle));
            if let Err(e) = spawned {
                tracing::error!(error = %e, "could not start the runtime pulse thread");
            }
        });
        if self.shared.in_flight.fetch_add(1, Ordering::SeqCst) == 0 {
            // Taking the lock orders this wake-up after a thread that has
            // checked the counter but not yet parked.
            let _parked = self.shared.parked.lock().unwrap_or_else(|p| p.into_inner());
            self.shared.wake_up.notify_one();
        }
        InFlight {
            shared: &self.shared,
        }
    }
}

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        self.shared.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

fn run(shared: Weak<Shared>, handle: tokio::runtime::Handle) {
    loop {
        // Holding the state only weakly: when the server is dropped the
        // upgrade fails and the thread ends.
        let Some(strong) = shared.upgrade() else {
            return;
        };
        let busy = strong.in_flight.load(Ordering::SeqCst) > 0;
        if busy {
            handle.spawn(async {});
        }
        let parked = strong.parked.lock().unwrap_or_else(|p| p.into_inner());
        // Re-checked under the lock: a handler that arrives after the check
        // above takes the lock to wake us, so an idle wait cannot miss it. A
        // busy thread simply sleeps one interval.
        if busy || strong.in_flight.load(Ordering::SeqCst) == 0 {
            let timeout = if busy { PULSE_INTERVAL } else { IDLE_CHECK };
            let _ = strong
                .wake_up
                .wait_timeout(parked, timeout)
                .unwrap_or_else(|p| p.into_inner());
        }
    }
}
