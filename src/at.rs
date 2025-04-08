//! Implementation of AT functionality

use crate::error::{Error, ErrorSource};
use arrayvec::ArrayString;
use core::{
    cell::RefCell,
    future::Future,
    ops::DerefMut,
    sync::atomic::{AtomicBool, AtomicPtr, Ordering},
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

/// A pointer to where the data should be written to
static AT_DATA: Mutex<RefCell<(AtomicPtr<u8>, usize)>> =
    Mutex::new(RefCell::new((AtomicPtr::new(core::ptr::null_mut()), 0)));
/// When the [AT_DATA] is updated, this waker is called so a future can be woken up.
static AT_DATA_WAKER: AtomicWaker = AtomicWaker::new();

/// The callback that will be called by nrfxlib when the at command has a response.
/// The `resp` is a null-terminated string.
unsafe extern "C" fn at_callback(resp: *const core::ffi::c_char) {
    #[cfg(feature = "defmt")]
    defmt::trace!(
        "AT <- {}",
        core::ffi::CStr::from_ptr(resp as _).to_str().unwrap()
    );

    // Store the data and wake the future that waits for it
    critical_section::with(|cs| {
        let mut data = AT_DATA.borrow_ref_mut(cs);
        let (ptr, size) = data.deref_mut();

        if ptr.get_mut().is_null() {
            return;
        }

        // Copy the contents
        let mut index = 0;
        while index < *size && *resp.add(index) != 0 {
            *ptr.get_mut().add(index) = *resp.add(index);
            index += 1;
        }

        // Reset the data so that the future knows that the callback was called
        *ptr = AtomicPtr::default();
        *size = 0;
    });
    AT_DATA_WAKER.wake();
}

/// Send an AT command to the modem.
///
/// The const `CAP` parameter is the size of the returned response string.
/// It is ok to set this to 0 you don't need the response.
///
/// If the `CAP` is too small to contain the entire response, then the string is simply tuncated.
pub async fn send_at<const CAP: usize>(command: &str) -> Result<ArrayString<CAP>, Error> {
    SendATFuture {
        state: Default::default(),
        command: command.as_bytes(),
        response: [0; CAP],
    }
    .await
}

/// Same as [send_at], but send a byte array (that must contain ascii chars) instead
pub async fn send_at_bytes<const CAP: usize>(command: &[u8]) -> Result<ArrayString<CAP>, Error> {
    SendATFuture {
        state: Default::default(),
        command,
        response: [0; CAP],
    }
    .await
}

/// Sends a blocking AT command. The non-blocking variants should be preferred, but sometimes it's necessary to
/// call this in e.g. a drop function.
///
/// If a capacity of 0 is given, then the command is given in a way where no textual response is gotten.
/// A capacity of >0 will require you to have a capacity that is big enough to contain the full message.
/// This is different from the async functions where the message is simply truncated.
pub fn send_at_blocking<const CAP: usize>(command: &str) -> Result<ArrayString<CAP>, Error> {
    #[cfg(feature = "defmt")]
    defmt::trace!("AT -> {}", command);

    let string = if CAP > 0 {
        let mut buffer = [0; CAP];
        unsafe {
            nrfxlib_sys::nrf_modem_at_cmd(
                buffer.as_mut_ptr() as _,
                buffer.len(),
                c"%.*s".as_ptr() as *const core::ffi::c_char,
                command.len(),
                command.as_ptr(),
            )
            .into_result()?;
        }

        let mut return_string = ArrayString::from_byte_string(&buffer).unwrap();
        strip_null_bytes(&mut return_string);
        return_string
    } else {
        unsafe {
            nrfxlib_sys::nrf_modem_at_printf(
                c"%.*s".as_ptr() as *const core::ffi::c_char,
                command.len(),
                command.as_ptr(),
            )
            .into_result()?;
        }

        ArrayString::new()
    };

    #[cfg(feature = "defmt")]
    defmt::trace!("AT <- {}", string.as_str());

    Ok(string)
}

struct SendATFuture<'c, const CAP: usize> {
    state: SendATState,
    command: &'c [u8],
    response: [u8; CAP],
}

impl<const CAP: usize> Future for SendATFuture<'_, CAP> {
    type Output = Result<ArrayString<CAP>, Error>;

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
                // Set the data pointer. This can be done because we are pinned
                critical_section::with(|cs| {
                    *AT_DATA.borrow_ref_mut(cs) = (AtomicPtr::new(self.response.as_mut_ptr()), CAP)
                });
                AT_DATA_WAKER.register(cx.waker());

                #[cfg(feature = "defmt")]
                defmt::trace!(
                    "AT -> {}",
                    defmt::unwrap!(core::str::from_utf8(self.command).ok())
                );

                let result = unsafe {
                    nrfxlib_sys::nrf_modem_at_cmd_async(
                        Some(at_callback),
                        c"%.*s".as_ptr() as *const core::ffi::c_char,
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
                let mut data = AT_DATA.borrow_ref_mut(cs);

                if data.0.get_mut().is_null() {
                    // The callback was called and we have the response

                    // Because we handle with c strings, let's at least make the last byte in the buffer a null character
                    if let Some(last) = self.response.last_mut() {
                        *last = 0
                    }

                    let mut return_string = ArrayString::from_byte_string(&self.response).unwrap();
                    strip_null_bytes(&mut return_string);

                    Poll::Ready(Ok(return_string))
                } else {
                    AT_DATA_WAKER.register(cx.waker());
                    Poll::Pending
                }
            }),
        }
    }
}

impl<const CAP: usize> Drop for SendATFuture<'_, CAP> {
    fn drop(&mut self) {
        match self.state {
            SendATState::WaitingOnAccess => {}
            SendATState::AccessGranted | SendATState::WaitingOnData => {
                // Reset the data. We don't have to worry that somebody else accessed this
                // because they're only allowed to after we've set `AT_PROGRESS` back to false which we're
                // gonna do after this.
                critical_section::with(|cs| {
                    *AT_DATA.borrow_ref_mut(cs) = (AtomicPtr::default(), 0)
                });
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

fn strip_null_bytes<const CAP: usize>(string: &mut ArrayString<CAP>) {
    if let Some((reverse_index, _)) = string
        .bytes()
        .rev()
        .enumerate()
        .find(|(_, byte)| *byte != 0)
    {
        let index = string.len() - reverse_index;
        string.truncate(index);
    }
}
