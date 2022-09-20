use crate::error::{Error, ErrorSource};
use arrayvec::ArrayString;
use core::{
    cell::RefCell,
    future::Future,
    sync::atomic::{AtomicBool, Ordering},
    task::Poll,
};
use critical_section::Mutex;
use futures::task::AtomicWaker;

// AT commands usually get a quick response, so there's only one active waiter at a time.
// If two futures wait, then they will get bumped out and reregister.
// This fighting only happens for a bit

/// Set to false if there's no at command in progress.
/// There can only be one in progress at a time.
static AT_PROGRESS: AtomicBool = AtomicBool::new(false);
/// This waker gets called when the [AT_PROGRESS] is set to false.
/// This can be used by a future to await being able to send a command.
static AT_PROGRESS_WAKER: AtomicWaker = AtomicWaker::new();

/// The from the callback is stored in this variable
static AT_DATA: Mutex<RefCell<ArrayString<256>>> =
    Mutex::new(RefCell::new(ArrayString::new_const()));
/// When the [AT_DATA] is updated, this waker is called so a future can be woken up.
static AT_DATA_WAKER: AtomicWaker = AtomicWaker::new();

/// The callback that will be called by nrfxlib when the at command has a response.
/// The `resp` is a null-terminated string.
unsafe extern "C" fn at_callback(resp: *const u8) {
    // Let's be lazy and let Rust figure out how to convert the pointer to a string
    let cstring = core::ffi::CStr::from_ptr(resp as _);
    // We can unwrap this because the response is always an ascii string
    let string = cstring.to_str().unwrap();

    #[cfg(feature = "defmt")]
    defmt::trace!("AT <- {}", string);

    // Store the data and wake the future that waits for it
    critical_section::with(|cs| AT_DATA.borrow_ref_mut(cs).push_str(string));
    AT_DATA_WAKER.wake();
}

/// Send an AT command to the modem
pub async fn send_at(command: &str) -> Result<ArrayString<256>, Error> {
    SendATFuture {
        state: Default::default(),
        command: command.as_bytes(),
    }
    .await
}

pub fn send_at_blocking(command: &str) -> Result<ArrayString<256>, Error> {
    #[cfg(feature = "defmt")]
    defmt::trace!("AT -> {}", command);

    let mut buffer = ArrayString::new();
    unsafe {
        nrfxlib_sys::nrf_modem_at_cmd(
            buffer.as_mut_ptr() as _,
            256,
            b"%.*s\0".as_ptr(),
            command.len(),
            command.as_ptr(),
        )
        .into_result()?;
    }

    #[cfg(feature = "defmt")]
    defmt::trace!("AT <- {}", buffer.as_str());

    Ok(buffer)
}

pub async fn send_at_bytes(command: &[u8]) -> Result<ArrayString<256>, Error> {
    SendATFuture {
        state: Default::default(),
        command,
    }
    .await
}

struct SendATFuture<'c> {
    state: SendATState,
    command: &'c [u8],
}

impl<'c> Future for SendATFuture<'c> {
    type Output = Result<ArrayString<256>, Error>;

    fn poll(
        mut self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Self::Output> {
        match self.state {
            SendATState::WaitingOnAccess => {
                if AT_PROGRESS.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                    == Ok(false)
                {
                    self.state = SendATState::AccessGranted;
                    cx.waker().wake_by_ref();
                    Poll::Pending
                } else {
                    AT_PROGRESS_WAKER.register(cx.waker());
                    Poll::Pending
                }
            }
            SendATState::AccessGranted => {
                // Clear any old data
                critical_section::with(|cs| AT_DATA.borrow_ref_mut(cs).clear());
                AT_DATA_WAKER.register(cx.waker());

                #[cfg(feature = "defmt")]
                defmt::trace!(
                    "AT -> {}",
                    defmt::unwrap!(core::str::from_utf8(self.command).ok())
                );

                let result = unsafe {
                    nrfxlib_sys::nrf_modem_at_cmd_async(
                        Some(at_callback),
                        b"%.*s\0".as_ptr(),
                        self.command.len(),
                        self.command.as_ptr(),
                    )
                    .into_result()
                };

                match result {
                    Ok(_) => {
                        self.state = SendATState::WaitingOnData;
                        Poll::Pending
                    }
                    Err(e) => Poll::Ready(Err(e)),
                }
            }
            SendATState::WaitingOnData => critical_section::with(|cs| {
                let data = AT_DATA.borrow_ref_mut(cs);
                match (!data.is_empty()).then(|| *data) {
                    Some(data) => {
                        AT_PROGRESS.store(false, Ordering::SeqCst);
                        AT_PROGRESS_WAKER.wake();
                        Poll::Ready(Ok(data))
                    }
                    None => {
                        AT_DATA_WAKER.register(cx.waker());
                        Poll::Pending
                    }
                }
            }),
        }
    }
}

impl<'c> Drop for SendATFuture<'c> {
    fn drop(&mut self) {
        match self.state {
            SendATState::WaitingOnAccess => {}
            SendATState::AccessGranted | SendATState::WaitingOnData => {
                AT_PROGRESS.store(false, Ordering::SeqCst);
                AT_PROGRESS_WAKER.wake();
            }
        }
    }
}

#[derive(Default)]
enum SendATState {
    #[default]
    WaitingOnAccess,
    AccessGranted,
    WaitingOnData,
}
