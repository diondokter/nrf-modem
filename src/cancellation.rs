use crate::Error;
use core::{
    sync::atomic::{AtomicBool, Ordering},
    task::{Context, Poll},
};
use futures::task::AtomicWaker;

/// A token you can pass to certain async functions that let you cancel them.
///
/// This can be nice for example when you have a task that is 'stuck' receiving data that never arrives,
/// but you want it to stop doing that so it can continue doing something else.
/// 
/// It is recommended to create a new token for every operation because once cancelled, the token stays in the cancelled state.
#[derive(Default)]
pub struct CancellationToken {
    canceled: AtomicBool,
    waker: AtomicWaker,
}

impl CancellationToken {
    /// Create a new token
    pub const fn new() -> Self {
        Self {
            canceled: AtomicBool::new(false),
            waker: AtomicWaker::new(),
        }
    }

    /// Registers the waker of the task that executes this function.
    /// When the cancel function is called, the waker is used to wake the future for which this token is used.
    pub(crate) async fn bind_to_current_task(&self) {
        core::future::poll_fn(|cx| {
            self.bind_to_context(cx);
            Poll::Ready(())
        }).await;
    }

    pub(crate) fn bind_to_context(&self, cx: &Context) {
        self.waker.register(cx.waker())
    }

    /// Set the token to cancel the operation that uses this token.
    /// 
    /// This may not cancel the task immediately because that may not always be possible.
    pub fn cancel(&self) {
        self.canceled.store(true, Ordering::SeqCst);
        self.waker.wake();
    }

    /// Returns whether or not the cancel function has been called already
    pub fn is_cancelled(&self) -> bool {
        self.canceled.load(Ordering::SeqCst)
    }

    /// Creates a result of this type to the `?` operator can be used to return from code.
    /// 
    /// It returns an OK if the token hasn't been cancelled yet and an error if it has been cancelled.
    pub(crate) fn as_result(&self) -> Result<(), Error> {
        match self.is_cancelled() {
            true => Err(Error::OperationCancelled),
            false => Ok(()),
        }
    }
}
