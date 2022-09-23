use crate::{
    error::{Error, ErrorSource},
    waker_node_list::{WakerNode, WakerNodeList},
};
use arrayvec::{ArrayString, ArrayVec};
use core::{cell::RefCell, task::Poll};
use critical_section::Mutex;

static WAKER_NODE_LIST: Mutex<RefCell<WakerNodeList<dyn NotificationBuffer>>> =
    Mutex::new(RefCell::new(WakerNodeList::new()));

pub(crate) unsafe extern "C" fn at_notification_handler(notif: *const u8) {
    #[cfg(feature = "defmt")]
    defmt::trace!("AT notification <- {}", core::ffi::CStr::from_ptr(notif as *const _).to_str().unwrap());

    critical_section::with(|cs| {
        WAKER_NODE_LIST
            .borrow_ref_mut(cs)
            .wake_all(|c| c.write(notif))
    });
}

pub(crate) fn initialize() -> Result<(), Error> {
    unsafe {
        nrfxlib_sys::nrf_modem_at_notif_handler_set(Some(at_notification_handler)).into_result()?;
    }

    Ok(())
}

pub fn get_stream<const CAP: usize, const COUNT: usize>(
) -> AtNotificationStream<CAP, COUNT> {
    AtNotificationStream {
        buffer: Default::default(),
        waker_node: None,
    }
}

pub struct AtNotificationStream<const CAP: usize, const COUNT: usize> {
    buffer: ArrayVec<ArrayString<CAP>, COUNT>,
    waker_node: Option<WakerNode<dyn NotificationBuffer>>,
}

impl<const CAP: usize, const COUNT: usize> futures::Stream for AtNotificationStream<CAP, COUNT> {
    type Item = ArrayString<CAP>;

    fn poll_next(
        mut self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        if self.waker_node.is_none() {
            // Initialize the waker node
            let buffer_ptr = &mut self.buffer as *mut dyn NotificationBuffer;
            let waker_node = self
                .waker_node
                .get_or_insert_with(|| WakerNode::new(Some(buffer_ptr), cx.waker().clone()));

            critical_section::with(|cs| unsafe {
                WAKER_NODE_LIST
                    .borrow_ref_mut(cs)
                    .append_node(waker_node as *mut _)
            });
        }

        critical_section::with(|_| {
            if !self.buffer.is_empty() {
                Poll::Ready(Some(self.buffer.remove(0)))
            } else {
                Poll::Pending
            }
        })
    }
}

impl<const CAP: usize, const COUNT: usize> Drop for AtNotificationStream<CAP, COUNT> {
    fn drop(&mut self) {
        if let Some(waker_node) = self.waker_node.as_mut() {
            critical_section::with(|cs| unsafe {
                WAKER_NODE_LIST
                    .borrow_ref_mut(cs)
                    .remove_node(waker_node as *mut _)
            });
        }
    }
}

trait NotificationBuffer {
    fn write(&mut self, notif: *const u8);
}

impl<const CAP: usize, const COUNT: usize> NotificationBuffer
    for ArrayVec<ArrayString<CAP>, COUNT>
{
    fn write(&mut self, mut notif: *const u8) {
        if self.is_full() {
            #[cfg(feature = "defmt")]
            defmt::warn!("Notification buffer is full");

            return;
        }

        let mut string = ArrayString::new();

        while !self.is_full() && unsafe { *notif != 0 } {
            let c = unsafe { char::from_u32_unchecked(((*notif) & 0x7F) as u32) };
            string.push(c);

            notif = unsafe { notif.add(1) };
        }

        self.push(string);
    }
}
