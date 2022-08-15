// Ok, this is gonna be really unsafe...
pub struct WakerNode<T: ?Sized> {
    pub context: *mut T,
    pub waker: core::task::Waker,
    previous_node: Option<*mut WakerNode<T>>,
    next_node: Option<*mut WakerNode<T>>,
}

impl<T: ?Sized> WakerNode<T> {
    pub fn new(context: *mut T, waker: core::task::Waker) -> Self {
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
            Some(other) => other,
            None => {
                self.next_node = Some(node);
                return;
            }
        };

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

    pub unsafe fn remove_node(&mut self, node: *mut WakerNode<T>) {
        if node.is_null() {
            panic!("Node cannot be null");
        }

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

    pub fn wake_all(&mut self, mut wake_function: impl FnMut(&mut T)) {
        // Get the first node
        let mut node = match self.next_node {
            Some(node) => node,
            None => return,
        };

        unsafe {
            loop {
                // Write the notification to the node's buffer
                wake_function(&mut (*(*node).context));
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

        self.next_node = None;
    }
}
