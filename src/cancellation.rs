use crate::Error;
use core::{
    future::Future,
    sync::atomic::{AtomicBool, Ordering},
    task::{Context, Poll},
};
use futures::task::AtomicWaker;

/// A token you can pass to certain async functions that let you cancel them.
///
/// This can be nice for example when you have a task that is 'stuck' receiving data that never arrives,
/// but you want it to stop doing that so it can continue doing something else.
#[derive(Default)]
pub struct CancellationToken {
    canceled: AtomicBool,
    waker: AtomicWaker,
}

impl CancellationToken {
    pub const fn new() -> Self {
        Self {
            canceled: AtomicBool::new(false),
            waker: AtomicWaker::new(),
        }
    }

    pub(crate) fn bind_to_current_task(&self) -> RegisterWakerFuture<'_> {
        RegisterWakerFuture::new(self)
    }

    pub(crate) fn bind_to_context(&self, cx: &Context) {
        self.waker.register(cx.waker())
    }

    pub fn cancel(&self) {
        self.canceled.store(true, Ordering::SeqCst);
        self.waker.wake();
    }

    pub fn is_cancelled(&self) -> bool {
        self.canceled.load(Ordering::SeqCst)
    }

    pub fn as_result(&self) -> Result<(), Error> {
        match self.is_cancelled() {
            true => Err(Error::OperationCancelled),
            false => Ok(()),
        }
    }
}

pub struct RegisterWakerFuture<'a> {
    inner: &'a CancellationToken,
}

impl<'a> RegisterWakerFuture<'a> {
    pub fn new(inner: &'a CancellationToken) -> Self {
        Self { inner }
    }
}

impl<'a> Future for RegisterWakerFuture<'a> {
    type Output = ();

    fn poll(
        self: core::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> core::task::Poll<Self::Output> {
        self.inner.bind_to_context(cx);
        Poll::Ready(())
    }
}
