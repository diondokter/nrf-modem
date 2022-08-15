use crate::error::{Error, ErrorSource};
use crate::waker_node_list::{WakerNode, WakerNodeList};
use arrayvec::ArrayString;
use core::{cell::RefCell, future::Future, task::Poll};
use embassy::blocking_mutex::CriticalSectionMutex;

static WAKER_NODE_LIST: CriticalSectionMutex<RefCell<WakerNodeList<dyn NotificationBuffer>>> =
    CriticalSectionMutex::new(RefCell::new(WakerNodeList::new()));

unsafe extern "C" fn at_notification_handler(notif: *const u8) {
    WAKER_NODE_LIST.lock(|list| {
        list.borrow_mut().wake_all(|c| c.write(notif));
    });
}

pub(crate) fn initialize() -> Result<(), Error> {
    unsafe {
        nrfxlib_sys::nrf_modem_at_notif_handler_set(Some(at_notification_handler)).into_result()?;
    }

    Ok(())
}

pub fn wait_for_at_notification<const CAP: usize>() -> impl Future<Output = ArrayString<CAP>> {
    AtNotificationFuture {
        buffer: ArrayString::new(),
        waker_node: None,
    }
}

struct AtNotificationFuture<const CAP: usize> {
    buffer: ArrayString<CAP>,
    waker_node: Option<WakerNode<dyn NotificationBuffer>>,
}

impl<const CAP: usize> Future for AtNotificationFuture<CAP> {
    type Output = ArrayString<CAP>;

    fn poll(
        mut self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> Poll<Self::Output> {
        WAKER_NODE_LIST.lock(|list| {
            // Are we done?
            if !self.buffer.is_empty() {
                // Yes.
                // We must make sure our list doesn't contain pointers to our node anymore
                if let Some(waker_node) = self.waker_node.as_mut() {
                    unsafe {
                        list.borrow_mut()
                            .remove_node(waker_node as *mut WakerNode<_>)
                    };
                    self.waker_node = None;
                }
                return Poll::Ready(self.buffer);
            }

            let buffer_ptr = &mut self.buffer as *mut dyn NotificationBuffer;
            let waker_node = self.waker_node.get_or_insert_with(|| WakerNode::new(buffer_ptr, cx.waker().clone()));

            unsafe { list.borrow_mut().append_node(waker_node as *mut _) };

            Poll::Pending
        })
    }
}

impl<const CAP: usize> Drop for AtNotificationFuture<CAP> {
    fn drop(&mut self) {
        if let Some(waker_node) = self.waker_node.as_mut() {
            WAKER_NODE_LIST
                .lock(|list| unsafe { list.borrow_mut().remove_node(waker_node as *mut _) });
        }
    }
}

trait NotificationBuffer {
    fn write(&mut self, notif: *const u8);
}

impl<const CAP: usize> NotificationBuffer for ArrayString<CAP> {
    fn write(&mut self, mut notif: *const u8) {
        self.clear();

        while !self.is_full() && unsafe { *notif != 0 } {
            let c = unsafe { char::from_u32_unchecked(((*notif) & 0x7F) as u32) };
            self.push(c);

            notif = unsafe { notif.add(1) };
        }
    }
}
