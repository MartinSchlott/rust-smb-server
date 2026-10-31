//! Deterministic pause points for lock tests.
//!
//! A hook is installed for one owner id, so parallel tests never pause each
//! other's handlers. The handler announces entry on a channel and waits for a
//! permit; nothing sleeps.

use std::sync::{Arc, Mutex};

use tokio::sync::{Notify, mpsc};

pub(crate) struct Pause {
    target: u64,
    entered: mpsc::UnboundedSender<()>,
    resume: Notify,
}

impl Pause {
    pub(crate) fn resume(&self) {
        self.resume.notify_one();
    }
}

enum Kind {
    Handler,
    Waiter,
    BeforeSelect,
}

pub(crate) struct Guard {
    hook: Arc<Pause>,
    kind: Kind,
}

impl Drop for Guard {
    fn drop(&mut self) {
        let list = match self.kind {
            Kind::Handler => &HANDLER,
            Kind::Waiter => &WAITER,
            Kind::BeforeSelect => &BEFORE_SELECT,
        };
        let mut hooks = list.lock().unwrap_or_else(|e| e.into_inner());
        hooks.retain(|h| !Arc::ptr_eq(h, &self.hook));
    }
}

static HANDLER: Mutex<Vec<Arc<Pause>>> = Mutex::new(Vec::new());
static WAITER: Mutex<Vec<Arc<Pause>>> = Mutex::new(Vec::new());
static BEFORE_SELECT: Mutex<Vec<Arc<Pause>>> = Mutex::new(Vec::new());
static AFTER_CLAIM: Mutex<Vec<u64>> = Mutex::new(Vec::new());
static BEFORE_FINAL: Mutex<Vec<u64>> = Mutex::new(Vec::new());
static DONE: Mutex<Vec<(u64, mpsc::UnboundedSender<()>)>> = Mutex::new(Vec::new());

/// Makes the next final-response build by `target` panic before the frame is
/// queued, so a test drives the glue failure with an armed grant.
pub(crate) struct PanicBeforeFinal {
    target: u64,
}

impl Drop for PanicBeforeFinal {
    fn drop(&mut self) {
        BEFORE_FINAL
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|t| *t != self.target);
    }
}

pub(crate) fn panic_before_final(target: u64) -> PanicBeforeFinal {
    BEFORE_FINAL
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push(target);
    PanicBeforeFinal { target }
}

pub(crate) fn before_final(target: u64) {
    if BEFORE_FINAL
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .contains(&target)
    {
        panic!("injected panic before the final response was queued");
    }
}

/// Notifies the test when `target`'s waiter task has finished, so a test can
/// assert on its last frame instead of sleeping.
pub(crate) struct DoneHook {
    target: u64,
}

impl Drop for DoneHook {
    fn drop(&mut self) {
        DONE.lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|(t, _)| *t != self.target);
    }
}

pub(crate) fn waiter_done_hook(target: u64) -> (DoneHook, mpsc::UnboundedReceiver<()>) {
    let (tx, rx) = mpsc::unbounded_channel();
    DONE.lock()
        .unwrap_or_else(|e| e.into_inner())
        .push((target, tx));
    (DoneHook { target }, rx)
}

pub(crate) fn waiter_done(target: u64) {
    let done = DONE.lock().unwrap_or_else(|e| e.into_inner());
    for (t, tx) in done.iter() {
        if *t == target {
            let _ = tx.send(());
        }
    }
}

/// Makes the next claim by `target` panic, so a test drives the waiter's
/// post-claim panic path without touching production code.
pub(crate) struct PanicAfterClaim {
    target: u64,
}

impl Drop for PanicAfterClaim {
    fn drop(&mut self) {
        AFTER_CLAIM
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|t| *t != self.target);
    }
}

pub(crate) fn panic_after_claim(target: u64) -> PanicAfterClaim {
    AFTER_CLAIM
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push(target);
    PanicAfterClaim { target }
}

pub(crate) fn after_claim(target: u64) {
    if AFTER_CLAIM
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .contains(&target)
    {
        panic!("injected panic after the grant was claimed");
    }
}

fn install(
    list: &'static Mutex<Vec<Arc<Pause>>>,
    target: u64,
    kind: Kind,
    entered: mpsc::UnboundedSender<()>,
) -> (Guard, Arc<Pause>) {
    let hook = Arc::new(Pause {
        target,
        entered,
        resume: Notify::new(),
    });
    list.lock()
        .unwrap_or_else(|e| e.into_inner())
        .push(hook.clone());
    (
        Guard {
            hook: hook.clone(),
            kind,
        },
        hook,
    )
}

/// Install a handler pause for `target`; the test supplies the entry channel
/// so it can wait for the handler to arrive.
pub(crate) fn hold_handler(target: u64, entered: mpsc::UnboundedSender<()>) -> (Guard, Arc<Pause>) {
    install(&HANDLER, target, Kind::Handler, entered)
}

/// Install a waiter pause for `target`.
pub(crate) fn hold_waiter(target: u64, entered: mpsc::UnboundedSender<()>) -> (Guard, Arc<Pause>) {
    install(&WAITER, target, Kind::Waiter, entered)
}

async fn wait_at(list: &'static Mutex<Vec<Arc<Pause>>>, target: u64) {
    let hook = list
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .find(|h| h.target == target)
        .cloned();
    if let Some(hook) = hook {
        let _ = hook.entered.send(());
        hook.resume.notified().await;
    }
}

pub(crate) async fn lock_handler(target: u64) {
    wait_at(&HANDLER, target).await;
}

pub(crate) async fn lock_waiter(target: u64) {
    wait_at(&WAITER, target).await;
}

/// Park the waiter after its interim and before it races `done` against
/// `work`, so a test can make both ready before the race starts.
pub(crate) fn hold_before_select(
    target: u64,
    entered: mpsc::UnboundedSender<()>,
) -> (Guard, Arc<Pause>) {
    install(&BEFORE_SELECT, target, Kind::BeforeSelect, entered)
}

pub(crate) async fn before_select(target: u64) {
    wait_at(&BEFORE_SELECT, target).await;
}
