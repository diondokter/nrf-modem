//! # FFI (Foreign Function Interface) Module
//!
//! This module contains implementations of functions that libbsd.a expects to
//! be able to call.
//!
//! Copyright (c) 42 Technology, 2019
//!
//! Dual-licensed under MIT and Apache 2.0. See the [README](../README.md) for
//! more details.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// Number of IPC configurations in `NrfxIpcConfig`
const IPC_CONF_NUM: usize = 8;

// Normally a notify should wake all threads. We don't have threads, so a single bool should be enough
static NOTIFY_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Used by `libmodem` to configure the IPC peripheral. See `nrfx_ipc_config_t`
/// in `nrfx/drivers/include/nrfx_ipc.h`.
#[derive(Debug, Clone)]
pub struct NrfxIpcConfig {
    /// Configuration of the connection between signals and IPC channels.
    send_task_config: [u32; IPC_CONF_NUM],
    /// Configuration of the connection between events and IPC channels.
    receive_event_config: [u32; IPC_CONF_NUM],
    /// Bitmask with events to be enabled to generate interrupt.
    receive_events_enabled: u32,
}

/// IPC callback function type
type NrfxIpcHandler = extern "C" fn(event_mask: u32, ptr: *mut u8);

/// IPC error type
#[repr(u32)]
#[derive(Debug, Copy, Clone)]
pub enum NrfxErr {
    ///< Operation performed successfully.
    Success = 0x0BAD0000,
    ///< Internal error.
    ErrorInternal = (0x0BAD0000 + 1),
    ///< No memory for operation.
    ErrorNoMem = (0x0BAD0000 + 2),
    ///< Not supported.
    ErrorNotSupported = (0x0BAD0000 + 3),
    ///< Invalid parameter.
    ErrorInvalidParam = (0x0BAD0000 + 4),
    ///< Invalid state, operation disallowed in this state.
    ErrorInvalidState = (0x0BAD0000 + 5),
    ///< Invalid length.
    ErrorInvalidLength = (0x0BAD0000 + 6),
    ///< Operation timed out.
    ErrorTimeout = (0x0BAD0000 + 7),
    ///< Operation is forbidden.
    ErrorForbidden = (0x0BAD0000 + 8),
    ///< Null pointer.
    ErrorNull = (0x0BAD0000 + 9),
    ///< Bad memory address.
    ErrorInvalidAddr = (0x0BAD0000 + 10),
    ///< Busy.
    ErrorBusy = (0x0BAD0000 + 11),
    ///< Module already initialized.
    ErrorAlreadyInitialized = (0x0BAD0000 + 12),
}

/// Stores the last error from the library. See `nrf_modem_os_errno_set` and
/// `get_last_error`.
static LAST_ERROR: core::sync::atomic::AtomicIsize = core::sync::atomic::AtomicIsize::new(0);

/// Remembers the IPC interrupt context we were given
static IPC_CONTEXT: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Remembers the IPC handler function we were given
static IPC_HANDLER: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Function required by BSD library. We need to set the EGU1 interrupt.
#[no_mangle]
pub extern "C" fn nrf_modem_os_application_irq_set() {
    cortex_m::peripheral::NVIC::pend(nrf9160_pac::Interrupt::EGU1);
}

/// Function required by BSD library. We need to clear the EGU1 interrupt.
#[no_mangle]
pub extern "C" fn nrf_modem_os_application_irq_clear() {
    cortex_m::peripheral::NVIC::unpend(nrf9160_pac::Interrupt::EGU1);
}

/// Function required by BSD library. We need to set the EGU2 interrupt.
#[no_mangle]
pub extern "C" fn nrf_modem_os_trace_irq_set() {
    cortex_m::peripheral::NVIC::pend(nrf9160_pac::Interrupt::EGU2);
}

/// Function required by BSD library. We need to clear the EGU2 interrupt.
#[no_mangle]
pub extern "C" fn nrf_modem_os_trace_irq_clear() {
    cortex_m::peripheral::NVIC::unpend(nrf9160_pac::Interrupt::EGU2);
}

/// Function required by BSD library. We have no init to do.
#[no_mangle]
pub extern "C" fn nrf_modem_os_init() {
    // Nothing
}

/// Function required by BSD library. Stores an error code we can read later.
#[no_mangle]
pub extern "C" fn nrf_modem_os_errno_set(errno: isize) {
    LAST_ERROR.store(errno, core::sync::atomic::Ordering::SeqCst);
}

/// Return the last error stored by the nrfxlib C library.
pub fn get_last_error() -> isize {
    LAST_ERROR.load(core::sync::atomic::Ordering::SeqCst)
}

/// Function required by BSD library
#[no_mangle]
pub extern "C" fn nrf_modem_os_busywait(usec: i32) {
    if usec > 0 {
        // NRF9160 runs at 64 MHz, so this is close enough
        cortex_m::asm::delay((usec as u32) * 64);
    }
}

/// Put a thread to sleep for a specific time or until an event occurs.
///
/// All waiting threads shall be woken by nrf_modem_event_notify.
///
/// **Parameters**
/// - context – (in) A unique identifier assigned by the library to identify the context.
/// - timeout – (inout) Timeout in millisec or -1 for infinite timeout.
/// Contains the timeout value as input and the remainig time to sleep as output.
///
/// **Return values**
/// - 0 – The thread is woken before the timeout expired.
/// - -NRF_EAGAIN – The timeout expired.
/// - -NRF_ESHUTDOWN – Modem is not initialized, or was shut down.
#[no_mangle]
pub unsafe extern "C" fn nrf_modem_os_timedwait(_context: u32, timeout: *mut i32) -> i32 {
    if nrf_modem_os_is_in_isr() {
        return -(nrfxlib_sys::NRF_EPERM as i32);
    }

    if !nrfxlib_sys::nrf_modem_is_initialized() {
        return -(nrfxlib_sys::NRF_ESHUTDOWN as i32);
    }

    if *timeout < -2 {
        // With Zephyr, negative timeouts pend on a semaphore with K_FOREVER.
        // We can't do that here.
        0i32
    } else {
        loop {
            nrf_modem_os_busywait(1000);

            if NOTIFY_ACTIVE.swap(false, Ordering::Relaxed) {
                return 0;
            }

            match *timeout {
                -1 => continue,
                0 => return -(nrfxlib_sys::NRF_EAGAIN as i32),
                _ => *timeout -= 1,
            }
        }
    }
}

/// Notify the application that an event has occurred.
///
/// This function shall wake all threads sleeping in nrf_modem_os_timedwait.
#[no_mangle]
pub extern "C" fn nrf_modem_os_event_notify() {
    NOTIFY_ACTIVE.store(true, Ordering::SeqCst);
}

/// Function required by BSD library
#[no_mangle]
pub extern "C" fn nrf_modem_os_trace_put(_data: *const u8, _len: u32) -> i32 {
    // Do nothing
    0
}

/// Function required by BSD library
#[no_mangle]
pub extern "C" fn nrf_modem_irrecoverable_error_handler(err: u32) -> ! {
    panic!("bsd_irrecoverable_error_handler({})", err);
}

/// The Modem library needs to dynamically allocate memory (a heap) for proper
/// functioning. This memory is used to store the internal data structures that
/// are used to manage the communication between the application core and the
/// modem core. This memory is never shared with the modem core and hence, it
/// can be located anywhere in the application core's RAM instead of the shared
/// memory regions. This function allocates dynamic memory for the library.
#[no_mangle]
pub extern "C" fn nrf_modem_os_alloc(num_bytes_requested: usize) -> *mut u8 {
    unsafe { generic_alloc(num_bytes_requested, &crate::LIBRARY_ALLOCATOR) }
}

/// The Modem library needs to dynamically allocate memory (a heap) for proper
/// functioning. This memory is used to store the internal data structures that
/// are used to manage the communication between the application core and the
/// modem core. This memory is never shared with the modem core and hence, it
/// can be located anywhere in the application core's RAM instead of the shared
/// memory regions. This function allocates dynamic memory for the library.
#[no_mangle]
pub unsafe extern "C" fn nrf_modem_os_free(ptr: *mut u8) {
    generic_free(ptr, &crate::LIBRARY_ALLOCATOR);
}

/// Allocate a buffer on the TX area of shared memory.
///
/// @param bytes Buffer size.
/// @return pointer to allocated memory
#[no_mangle]
pub extern "C" fn nrf_modem_os_shm_tx_alloc(num_bytes_requested: usize) -> *mut u8 {
    unsafe { generic_alloc(num_bytes_requested, &crate::TX_ALLOCATOR) }
}

/// Free a shared memory buffer in the TX area.
///
/// @param ptr Th buffer to free.
#[no_mangle]
pub unsafe extern "C" fn nrf_modem_os_shm_tx_free(ptr: *mut u8) {
    generic_free(ptr, &crate::TX_ALLOCATOR);
}

#[no_mangle]
pub extern "C" fn nrf_modem_os_trace_alloc(_bytes: usize) -> *mut u8 {
    unimplemented!()
}

#[no_mangle]
pub extern "C" fn nrf_modem_os_trace_free(_mem: *mut u8) {
    unimplemented!()
}

/// @brief Function for loading configuration directly into IPC peripheral.
///
/// @param p_config Pointer to the structure with the initial configuration.
#[no_mangle]
pub unsafe extern "C" fn nrfx_ipc_config_load(p_config: *const NrfxIpcConfig) {
    let config: &NrfxIpcConfig = &*p_config;

    let ipc = &(*nrf9160_pac::IPC_NS::ptr());

    for (i, value) in config.send_task_config.iter().enumerate() {
        ipc.send_cnf[i].write(|w| w.bits(*value));
    }

    for (i, value) in config.receive_event_config.iter().enumerate() {
        ipc.receive_cnf[i].write(|w| w.bits(*value));
    }

    ipc.intenset
        .write(|w| w.bits(config.receive_events_enabled));
}

///
/// @brief Function for initializing the IPC driver.
///
/// @param irq_priority Interrupt priority.
/// @param handler      Event handler provided by the user. Cannot be NULL.
/// @param p_context    Context passed to event handler.
///
/// @retval NRFX_SUCCESS             Initialization was successful.
/// @retval NRFX_ERROR_INVALID_STATE Driver is already initialized.
#[no_mangle]
pub extern "C" fn nrfx_ipc_init(
    irq_priority: u8,
    handler: NrfxIpcHandler,
    p_context: usize,
) -> NrfxErr {
    use cortex_m::interrupt::InterruptNumber;
    let irq = nrf9160_pac::Interrupt::IPC;
    let irq_num = usize::from(irq.number());
    unsafe {
        cortex_m::peripheral::NVIC::unmask(irq);
        (*cortex_m::peripheral::NVIC::PTR).ipr[irq_num].write(irq_priority);
    }
    IPC_CONTEXT.store(p_context, core::sync::atomic::Ordering::SeqCst);
    IPC_HANDLER.store(handler as usize, core::sync::atomic::Ordering::SeqCst);
    // Report success
    NrfxErr::Success
}

/// Function for uninitializing the IPC module.
#[no_mangle]
pub extern "C" fn nrfx_ipc_uninit() {
    let ipc = unsafe { &(*nrf9160_pac::IPC_NS::ptr()) };

    for i in 0..IPC_CONF_NUM {
        ipc.send_cnf[i].reset();
    }

    for i in 0..IPC_CONF_NUM {
        ipc.receive_cnf[i].reset();
    }

    ipc.intenset.reset();
}

#[no_mangle]
pub extern "C" fn nrfx_ipc_receive_event_enable(event_index: u8) {
    let ipc = unsafe { &(*nrf9160_pac::IPC_NS::ptr()) };
    ipc.inten
        .modify(|r, w| unsafe { w.bits(r.bits() | 1 << event_index) })
}

#[no_mangle]
pub extern "C" fn nrfx_ipc_receive_event_disable(event_index: u8) {
    let ipc = unsafe { &(*nrf9160_pac::IPC_NS::ptr()) };
    ipc.inten
        .modify(|r, w| unsafe { w.bits(r.bits() & !(1 << event_index)) })
}

/// Allocate some memory from the given heap.
///
/// We allocate four extra bytes so that we can store the number of bytes
/// requested. This will be needed later when the memory is freed.
///
/// This function is safe to call from an ISR.
unsafe fn generic_alloc(num_bytes_requested: usize, heap: &crate::WrappedHeap) -> *mut u8 {
    let sizeof_usize = core::mem::size_of::<usize>();
    let mut result = core::ptr::null_mut();
    cortex_m::interrupt::free(|cs| {
        let num_bytes_allocated = num_bytes_requested + sizeof_usize;
        let layout =
            core::alloc::Layout::from_size_align_unchecked(num_bytes_allocated, sizeof_usize);
        if let Some(ref mut inner_alloc) = *heap.borrow(cs).borrow_mut() {
            match inner_alloc.allocate_first_fit(layout) {
                Ok(real_block) => {
                    let real_ptr = real_block.as_ptr();
                    // We need the block size to run the de-allocation. Store it in the first four bytes.
                    core::ptr::write_volatile::<usize>(real_ptr as *mut usize, num_bytes_allocated);
                    // Give them the rest of the block
                    result = real_ptr.add(sizeof_usize);
                }
                Err(_e) => {
                    // Ignore
                }
            }
        }
    });
    result
}

/// Free some memory back on to the given heap.
///
/// First we must wind the pointer back four bytes to recover the `usize` we
/// stashed during the allocation. We use this to recreate the `Layout` required
/// for the `deallocate` function.
///
/// This function is safe to call from an ISR.
unsafe fn generic_free(ptr: *mut u8, heap: &crate::WrappedHeap) {
    let sizeof_usize = core::mem::size_of::<usize>() as isize;
    cortex_m::interrupt::free(|cs| {
        // Fetch the size from the previous four bytes
        let real_ptr = ptr.offset(-sizeof_usize);
        let num_bytes_allocated = core::ptr::read_volatile::<usize>(real_ptr as *const usize);
        let layout = core::alloc::Layout::from_size_align_unchecked(
            num_bytes_allocated,
            sizeof_usize as usize,
        );
        if let Some(ref mut inner_alloc) = *heap.borrow(cs).borrow_mut() {
            inner_alloc.deallocate(core::ptr::NonNull::new_unchecked(real_ptr), layout);
        }
    });
}

/// Call this when we have an IPC IRQ. Not `extern C` as its not called by the
/// library, only our interrupt handler code.
pub unsafe fn nrf_ipc_irq_handler() {
    // Get the information about events that fired this interrupt
    let events_map = (*nrf9160_pac::IPC_NS::ptr()).intpend.read().bits();

    // Clear these events
    let mut bitmask = events_map;
    while bitmask != 0 {
        let event_idx = bitmask.trailing_zeros();
        bitmask &= !(1 << event_idx);
        (*nrf9160_pac::IPC_NS::ptr()).events_receive[event_idx as usize].write(|w| w.bits(0));
    }

    // Execute interrupt handler to provide information about events to app
    let handler_addr = IPC_HANDLER.load(core::sync::atomic::Ordering::SeqCst);
    let handler = core::mem::transmute::<usize, NrfxIpcHandler>(handler_addr);
    let context = IPC_CONTEXT.load(core::sync::atomic::Ordering::SeqCst);
    (handler)(events_map, context as *mut u8);
}

/// Initialize a semaphore.
///
/// The function shall allocate and initialize a semaphore and return its address as an output.
/// If an address of an already allocated semaphore is provided as an input, the allocation part is skipped and the semaphore is only reinitialized.
///
/// **Parameters**:
/// - sem – (inout) The address of the semaphore.
/// - initial_count – Initial semaphore count.
/// - limit – Maximum semaphore count.
///
/// **Returns**
/// - 0 on success, a negative errno otherwise.
#[no_mangle]
pub unsafe extern "C" fn nrf_modem_os_sem_init(
    sem: *mut *mut nrfxlib_sys::ctypes::c_void,
    initial_count: nrfxlib_sys::ctypes::c_uint,
    limit: nrfxlib_sys::ctypes::c_uint,
) -> nrfxlib_sys::ctypes::c_int {
    if sem.is_null() || initial_count > limit {
        return -(nrfxlib_sys::NRF_EINVAL as i32);
    }

    // Allocate if we need to
    if (*sem).is_null() {
        // Allocate our semaphore datastructure
        *sem = nrf_modem_os_alloc(core::mem::size_of::<Semaphore>()) as *mut _;

        if (*sem).is_null() {
            // We are out of memory
            return -(nrfxlib_sys::NRF_ENOMEM as i32);
        }
    }

    // Initialize the data
    *((*sem) as *mut Semaphore) = Semaphore {
        max_value: limit,
        current_value: AtomicU32::new(initial_count),
    };

    0
}

/// Give a semaphore.
///
/// *Note*: Can be called from an ISR.
///
/// **Parameters**
/// - sem – The semaphore.
#[no_mangle]
pub extern "C" fn nrf_modem_os_sem_give(sem: *mut nrfxlib_sys::ctypes::c_void) {
    unsafe {
        if sem.is_null() {
            return;
        }

        let max_value = (*(sem as *mut Semaphore)).max_value;
        (*(sem as *mut Semaphore))
            .current_value
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |val| {
                (val < max_value).then_some(val + 1)
            })
            .ok();
    }
}

/// Take a semaphore.
///
/// *Note*: timeout shall be set to NRF_MODEM_OS_NO_WAIT if called from ISR.
///
/// **Parameters**
/// - sem – The semaphore.
/// - timeout – Timeout in milliseconds. NRF_MODEM_OS_FOREVER indicates infinite timeout. NRF_MODEM_OS_NO_WAIT indicates no timeout.
///
/// **Return values**
/// - 0 – on success.
/// - -NRF_EAGAIN – If the semaphore could not be taken.
#[no_mangle]
pub extern "C" fn nrf_modem_os_sem_take(
    sem: *mut nrfxlib_sys::ctypes::c_void,
    mut timeout: nrfxlib_sys::ctypes::c_int,
) -> nrfxlib_sys::ctypes::c_int {
    unsafe {
        if sem.is_null() {
            return -(nrfxlib_sys::NRF_EAGAIN as i32);
        }

        if nrfxlib_sys::nrf_modem_os_is_in_isr() {
            timeout = nrfxlib_sys::NRF_MODEM_OS_NO_WAIT as i32;
        }

        loop {
            if (*(sem as *mut Semaphore))
                .current_value
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |val| {
                    if val > 0 {
                        Some(val - 1)
                    } else {
                        None
                    }
                })
                .is_ok()
            {
                return 0;
            }

            match timeout {
                0 => return -(nrfxlib_sys::NRF_EAGAIN as i32),
                nrfxlib_sys::NRF_MODEM_OS_FOREVER => {
                    nrf_modem_os_busywait(1);
                }
                _ => {
                    timeout -= 1;
                    nrf_modem_os_busywait(1);
                }
            }
        }
    }
}

/// Get a semaphore’s count.
///
/// **Parameters**
/// - sem – The semaphore.
///
/// **Returns**
/// - Current semaphore count.
#[no_mangle]
pub extern "C" fn nrf_modem_os_sem_count_get(
    sem: *mut nrfxlib_sys::ctypes::c_void,
) -> nrfxlib_sys::ctypes::c_uint {
    unsafe {
        if sem.is_null() {
            return 0;
        }

        (*(sem as *mut Semaphore))
            .current_value
            .load(Ordering::SeqCst)
    }
}

struct Semaphore {
    max_value: u32,
    current_value: AtomicU32,
}

/// Check if executing in interrupt context.
#[no_mangle]
pub extern "C" fn nrf_modem_os_is_in_isr() -> bool {
    cortex_m::peripheral::SCB::vect_active() != cortex_m::peripheral::scb::VectActive::ThreadMode
}
