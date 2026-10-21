//! The runtime pulse: keeps the runtime's timers alive while a handler blocks
//! a worker thread.
//!
//! A handler that blocks synchronously (a syscall, a lock, `thread::sleep`)
//! can stall *every* timer of a multi-thread tokio runtime. This was measured:
//! the worker woken by socket I/O runs reader -> frame task -> handler through
//! its LIFO slot and blocks, the other workers stay parked on their condvar,
//! and nobody polls the time driver — a 100 ms heartbeat went silent for the
//! whole 1.5 s block. The supervisor's slow, deadline and grace timers, the
//! only way to free a client from such a handler, would never fire.
//!
//! A remote `spawn` wakes a parked worker, which then takes over the driver.
//! So while at least one supervised handler is in flight, one OS thread spawns
//! an empty task on the server's runtime every [`PULSE_INTERVAL`]. The timers
//! then fire within roughly that interval plus scheduling latency; that is a
//! measured behaviour of tokio's scheduler, not a guarantee it makes. With
//! nothing in flight the thread parks, so an idle mount pays no wakeups.
//!
//! Everything here is plain `std` state under one mutex: neither the
//! in-flight count, nor the thread's lifetime, nor its wake-ups depend on a
//! tokio timer making progress — the very thing the pulse exists to restore.

use std::io;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::Duration;

/// How often the pulse wakes the runtime while a handler is in flight.
const PULSE_INTERVAL: Duration = Duration::from_millis(100);

struct State {
    in_flight: usize,
    /// Set when the owning `Pulse` is dropped; ends the thread.
    shutdown: bool,
    /// Whether a pulse thread exists. Cleared again if creating it failed, so
    /// the next handler retries.
    started: bool,
    /// How many empty tasks the thread has spawned.
    #[cfg(test)]
    ticks: u64,
}

struct Shared {
    state: Mutex<State>,
    /// Signalled on the 0 -> 1 transition and on shutdown. The predicate
    /// (`in_flight`, `shutdown`) lives in `state`, under the same mutex, so a
    /// change cannot slip between the thread's check and its wait.
    changed: Condvar,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }
}

/// One per `ServerState`. Dropping it ends the thread, parked or not.
pub(crate) struct Pulse {
    shared: Arc<Shared>,
}

/// Marks one supervised handler as in flight until dropped — on normal
/// completion, on panic and on cancellation alike. It owns its share of the
/// pulse, so it can travel into the handler's task and live exactly as long as
/// the handler's future does, abandoned synchronous handler included.
pub(crate) struct InFlight {
    shared: Arc<Shared>,
}

impl Pulse {
    pub(crate) fn new() -> Self {
        Self {
            shared: Arc::new(Shared {
                state: Mutex::new(State {
                    in_flight: 0,
                    shutdown: false,
                    started: false,
                    #[cfg(test)]
                    ticks: 0,
                }),
                changed: Condvar::new(),
            }),
        }
    }

    /// Registers a handler as in flight, starting the thread on first use.
    /// Must be called inside the server's runtime: the first call captures its
    /// handle. Call it before the handler's task can first be polled.
    ///
    /// # Errors
    /// The thread could not be created. Nothing is registered; the caller must
    /// not run the handler unsupervised.
    pub(crate) fn enter(&self) -> io::Result<InFlight> {
        let mut state = self.shared.lock();
        if !state.started {
            let handle = tokio::runtime::Handle::current();
            let shared = self.shared.clone();
            std::thread::Builder::new()
                .name("smb-runtime-pulse".to_owned())
                .spawn(move || run(shared, handle))?;
            state.started = true;
        }
        state.in_flight += 1;
        if state.in_flight == 1 {
            self.shared.changed.notify_all();
        }
        Ok(InFlight {
            shared: self.shared.clone(),
        })
    }

    #[cfg(test)]
    fn in_flight(&self) -> usize {
        self.shared.lock().in_flight
    }

    #[cfg(test)]
    fn ticks(&self) -> u64 {
        self.shared.lock().ticks
    }
}

impl Drop for Pulse {
    fn drop(&mut self) {
        // The thread holds the shared state, not the `ServerState`, so there
        // is no reference cycle to wait out; it is told to end explicitly
        // because a condvar parked without a timeout would never notice a
        // dropped owner. It is never joined: `drop` may run on the pulse
        // thread's own runtime, and the thread needs nothing from us.
        let mut state = self.shared.lock();
        state.shutdown = true;
        self.shared.changed.notify_all();
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.shared.lock().in_flight -= 1;
    }
}

fn run(shared: Arc<Shared>, handle: tokio::runtime::Handle) {
    let mut state = shared.lock();
    loop {
        // Idle: park until a handler arrives or the owner goes away.
        while state.in_flight == 0 && !state.shutdown {
            state = shared
                .changed
                .wait(state)
                .unwrap_or_else(|p| p.into_inner());
        }
        if state.shutdown {
            return;
        }
        // Busy: wake the runtime, then sleep one interval (cut short by a
        // shutdown; an `InFlight` dropping needs no wake-up, the next lap
        // simply finds the count at zero and parks).
        handle.spawn(async {});
        #[cfg(test)]
        {
            state.ticks += 1;
        }
        state = shared
            .changed
            .wait_timeout(state, PULSE_INTERVAL)
            .unwrap_or_else(|p| p.into_inner())
            .0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn wait_until(what: &str, bound: Duration, predicate: impl Fn() -> bool) {
        let deadline = Instant::now() + bound;
        while !predicate() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_count_follows_the_guards_and_an_idle_pulse_does_not_tick() {
        let pulse = Pulse::new();
        let first = pulse.enter().expect("start");
        let second = pulse.enter().expect("count");
        assert_eq!(pulse.in_flight(), 2);
        drop(first);
        assert_eq!(pulse.in_flight(), 1);
        drop(second);
        assert_eq!(pulse.in_flight(), 0);

        // Let the thread notice and park, then confirm it stays quiet.
        std::thread::sleep(PULSE_INTERVAL * 2);
        let settled = pulse.ticks();
        std::thread::sleep(PULSE_INTERVAL * 4);
        assert_eq!(
            pulse.ticks(),
            settled,
            "an idle pulse must not wake the runtime"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_busy_pulse_ticks_and_the_zero_to_one_transition_wakes_a_parked_thread() {
        let pulse = Pulse::new();
        // Start the thread, let it park idle, then enter again: the wake-up
        // must reach the parked thread.
        drop(pulse.enter().expect("start"));
        std::thread::sleep(PULSE_INTERVAL * 3);
        let before = pulse.ticks();
        let _busy = pulse.enter().expect("enter");
        wait_until("two ticks while busy", Duration::from_secs(2), || {
            pulse.ticks() >= before + 2
        });
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_panicking_holder_releases_its_count() {
        let pulse = Pulse::new();
        let guard = pulse.enter().expect("enter");
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _guard = guard;
            panic!("a handler panics while counted");
        }));
        assert!(result.is_err());
        assert_eq!(pulse.in_flight(), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropping_the_pulse_ends_an_idle_parked_thread() {
        let pulse = Pulse::new();
        drop(pulse.enter().expect("start"));
        let shared = Arc::downgrade(&pulse.shared);
        std::thread::sleep(PULSE_INTERVAL * 3); // parked, with no timeout
        drop(pulse);
        // The thread owns the last strong reference until it exits.
        wait_until("the parked thread to end", Duration::from_secs(2), || {
            shared.upgrade().is_none()
        });
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropping_the_pulse_ends_a_busy_thread_too() {
        let pulse = Pulse::new();
        let guard = pulse.enter().expect("enter");
        let shared = Arc::downgrade(&pulse.shared);
        drop(pulse);
        drop(guard);
        wait_until("the busy thread to end", Duration::from_secs(2), || {
            shared.upgrade().is_none()
        });
    }
}
