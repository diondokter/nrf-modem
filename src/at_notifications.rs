use crate::error::{Error, ErrorSource};
use arrayvec::ArrayString;
use core::{cell::RefCell, future::Future, task::Poll};
use embassy::blocking_mutex::CriticalSectionMutex;

static WAKER_NODE_LIST: CriticalSectionMutex<RefCell<WakerNodeList>> =
    CriticalSectionMutex::new(RefCell::new(WakerNodeList { next_node: None }));

unsafe extern "C" fn at_notification_handler(notif: *const u8) {
    WAKER_NODE_LIST.lock(|list| {
        // Get the first node
        let mut node = match list.borrow_mut().next_node {
            Some(node) => node,
            None => return,
        };

        loop {
            // Write the notification to the node's buffer
            (*(*node).buffer).write(notif);
            // Wake the node
            (*node).waker.take().unwrap().wake();

            // Get the next node if there is one
            match (*node).next_node {
                Some(next_node) => {
                    node = next_node;
                }
                None => {
                    break;
                }
            }
        }

        list.borrow_mut().next_node = None;
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
    waker_node: Option<WakerNode>,
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
                    list.borrow_mut().remove_node(waker_node as *mut WakerNode);
                    self.waker_node = None;
                }
                return Poll::Ready(self.buffer);
            }

            let buffer_ptr = &mut self.buffer as *mut dyn NotificationBuffer;
            let waker_node = self.waker_node.get_or_insert_with(|| WakerNode {
                buffer: buffer_ptr,
                waker: None,
                previous_node: None,
                next_node: None,
            });
            waker_node.waker = Some(cx.waker().clone());

            list.borrow_mut().append_node(waker_node as *mut _);

            Poll::Pending
        })
    }
}

impl<const CAP: usize> Drop for AtNotificationFuture<CAP> {
    fn drop(&mut self) {
        if let Some(waker_node) = self.waker_node.as_mut() {
            WAKER_NODE_LIST.lock(|list| list.borrow_mut().remove_node(waker_node as *mut _));
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

// Ok, this is gonna be really unsafe...
struct WakerNode {
    buffer: *mut dyn NotificationBuffer,
    waker: Option<core::task::Waker>,
    previous_node: Option<*mut WakerNode>,
    next_node: Option<*mut WakerNode>,
}

struct WakerNodeList {
    next_node: Option<*mut WakerNode>,
}

unsafe impl Send for WakerNodeList {}

impl WakerNodeList {
    fn append_node(&mut self, node: *mut WakerNode) {
        if node.is_null() {
            panic!("Node cannot be null");
        }

        let mut other = match self.next_node {
            Some(other) => other,
            None => {
                self.next_node = Some(node);
                return;
            }
        };

        unsafe {
            // Find the last one in the chain of the others
            loop {
                match (*other).next_node {
                    Some(next_node) => other = next_node,
                    None => break,
                }
            }

            (*other).next_node = Some(node);
            (*node).previous_node = Some(other);
        }
    }

    fn remove_node(&mut self, node: *mut WakerNode) {
        if node.is_null() {
            panic!("Node cannot be null");
        }

        unsafe {
            let next_node = (*node).next_node;
            let previous_node = (*node).previous_node;

            match next_node {
                Some(next_node) => (*next_node).previous_node = previous_node,
                None => {}
            }

            match previous_node {
                Some(previous_node) => (*previous_node).next_node = next_node,
                None => {}
            }

            if self.next_node == Some(node) {
                self.next_node = next_node;
            }

            (*node).next_node = None;
            (*node).previous_node = None;
        }
    }
}
