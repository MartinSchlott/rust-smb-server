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

pub(crate) struct Guard {
    hook: Arc<Pause>,
    waiter: bool,
}

impl Drop for Guard {
    fn drop(&mut self) {
        let list = if self.waiter { &WAITER } else { &HANDLER };
        let mut hooks = list.lock().unwrap_or_else(|e| e.into_inner());
        hooks.retain(|h| !Arc::ptr_eq(h, &self.hook));
    }
}

static HANDLER: Mutex<Vec<Arc<Pause>>> = Mutex::new(Vec::new());
static WAITER: Mutex<Vec<Arc<Pause>>> = Mutex::new(Vec::new());
static AFTER_CLAIM: Mutex<Vec<u64>> = Mutex::new(Vec::new());

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
    waiter: bool,
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
            waiter,
        },
        hook,
    )
}

/// Install a handler pause for `target`; the test supplies the entry channel
/// so it can wait for the handler to arrive.
pub(crate) fn hold_handler(target: u64, entered: mpsc::UnboundedSender<()>) -> (Guard, Arc<Pause>) {
    install(&HANDLER, target, false, entered)
}

/// Install a waiter pause for `target`.
pub(crate) fn hold_waiter(target: u64, entered: mpsc::UnboundedSender<()>) -> (Guard, Arc<Pause>) {
    install(&WAITER, target, true, entered)
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
