// Ok, this is gonna be really unsafe...
pub struct WakerNode<T: ?Sized> {
    pub context: Option<*mut T>,
    pub waker: core::task::Waker,
    previous_node: Option<*mut WakerNode<T>>,
    next_node: Option<*mut WakerNode<T>>,
}

impl<T: ?Sized> WakerNode<T> {
    pub fn new(context: Option<*mut T>, waker: core::task::Waker) -> Self {
        Self {
            context,
            waker,
            previous_node: None,
            next_node: None,
        }
    }
}

pub struct WakerNodeList<T: ?Sized> {
    next_node: Option<*mut WakerNode<T>>,
}

unsafe impl<T: ?Sized> Send for WakerNodeList<T> {}
unsafe impl<T: ?Sized> Sync for WakerNodeList<T> {}

impl<T: ?Sized> WakerNodeList<T> {
    pub const fn new() -> Self {
        Self { next_node: None }
    }

    pub unsafe fn append_node(&mut self, node: *mut WakerNode<T>) {
        if node.is_null() {
            panic!("Node cannot be null");
        }

        let mut other = match self.next_node {
            Some(other) if other != node => other,
            Some(_) => {
                // Already in the list
                return;
            }
            None => {
                self.next_node = Some(node);
                return;
            }
        };

        // Find the last one in the chain of the others
        loop {
            match (*other).next_node {
                Some(next_node) if next_node != node => other = next_node,
                Some(_) => {
                    // Already in the list
                    return;
                }
                None => break,
            }
        }

        (*other).next_node = Some(node);
        (*node).previous_node = Some(other);
        (*node).next_node = None;
    }

    pub unsafe fn remove_node(&mut self, node: *mut WakerNode<T>) {
        if node.is_null() {
            panic!("Node cannot be null");
        }

        let next_node = (*node).next_node;
        let previous_node = (*node).previous_node;

        if let Some(next_node) = next_node {
            (*next_node).previous_node = previous_node
        }

        if let Some(previous_node) = previous_node {
            (*previous_node).next_node = next_node
        }

        if self.next_node == Some(node) {
            self.next_node = next_node;
        }

        (*node).next_node = None;
        (*node).previous_node = None;
    }

    /// Wakes all nodes
    pub fn wake_all(&mut self, mut wake_function: impl FnMut(&mut T)) {
        // Get the first node
        let mut node = match self.next_node {
            Some(node) => node,
            None => return,
        };

        unsafe {
            loop {
                // Run the callback if there is a context
                if let Some(context) = (*node).context {
                    wake_function(&mut *context);
                }

                // Wake the node
                (*node).waker.wake_by_ref();

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
        }
    }

    /// Wakes all nodes and reset the list so they won't get woken up again
    pub fn wake_all_and_reset(&mut self, mut wake_function: impl FnMut(&mut T)) {
        // Get the first node
        let mut node = match self.next_node {
            Some(node) => node,
            None => return,
        };

        unsafe {
            loop {
                // Run the callback if there is a context
                if let Some(context) = (*node).context {
                    wake_function(&mut *context);
                }

                // Wake the node
                (*node).waker.wake_by_ref();

                // Get the next node if there is one
                match (*node).next_node {
                    Some(next_node) => {
                        (*node).next_node = None;
                        (*node).previous_node = None;
                        node = next_node;
                    }
                    None => {
                        break;
                    }
                }
            }
        }

        self.next_node = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::{cell::RefCell, future::Future, task::Poll};
    use critical_section::Mutex;
    use futures::FutureExt;

    static WAKER_NODE_LIST: Mutex<RefCell<WakerNodeList<(u8, bool)>>> =
        Mutex::new(RefCell::new(WakerNodeList::new()));

    fn wake_futures() {
        critical_section::with(|cs| {
            WAKER_NODE_LIST
                .borrow_ref_mut(cs)
                .wake_all_and_reset(|(data, done)| {
                    *data *= 2;
                    *done = true;
                });
        })
    }

    struct TestFuture {
        waker_node: Option<WakerNode<(u8, bool)>>,
        data: (u8, bool),
    }

    impl TestFuture {
        fn new(data: u8) -> Self {
            Self {
                waker_node: None,
                data: (data, false),
            }
        }
    }

    impl Future for TestFuture {
        type Output = u8;

        fn poll(
            mut self: core::pin::Pin<&mut Self>,
            cx: &mut core::task::Context<'_>,
        ) -> Poll<Self::Output> {
            // Register our waker node
            critical_section::with(|cs| {
                let data_ptr = &mut self.data as *mut _;

                let mut list = WAKER_NODE_LIST.borrow_ref_mut(cs);
                let waker_node = self
                    .waker_node
                    .get_or_insert_with(|| WakerNode::new(Some(data_ptr), cx.waker().clone()));
                waker_node.waker = cx.waker().clone();
                unsafe {
                    list.append_node(waker_node as *mut _);
                }
            });

            if self.data.1 {
                Poll::Ready(self.data.0)
            } else {
                Poll::Pending
            }
        }
    }

    impl Drop for TestFuture {
        fn drop(&mut self) {
            // Make sure to remove the waker node from this list when we have to
            if let Some(waker_node) = self.waker_node.as_mut() {
                critical_section::with(|cs| unsafe {
                    WAKER_NODE_LIST
                        .borrow_ref_mut(cs)
                        .remove_node(waker_node as *mut _)
                });
            }
        }
    }

    #[futures_test::test]
    async fn node_waker_list_no_ub() {
        assert_eq!(TestFuture::new(5).await, 10);
    }
}
