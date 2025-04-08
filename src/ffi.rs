//! # FFI (Foreign Function Interface) Module
//!
//! This module contains implementations of functions that libbsd.a expects to
//! be able to call.
//!
//! Copyright (c) 42 Technology, 2019
//!
//! Dual-licensed under MIT and Apache 2.0. See the [README](../README.md) for
//! more details.

#![allow(clippy::missing_safety_doc)]

use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

#[cfg(feature = "nrf9160")]
use nrf9160_pac as pac;

#[cfg(feature = "nrf9120")]
use nrf9120_pac as pac;

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
// based on https://github.com/NordicSemiconductor/nrfx/blob/98d6f433313a3d8dcf08dce25e744617b45aa913/drivers/include/nrfx_ipc.h#L56
type NrfxIpcHandler = extern "C" fn(event_idx: u8, ptr: *mut u8);

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

/// Function required by BSD library. We have no init to do.
#[no_mangle]
pub extern "C" fn nrf_modem_os_init() {
    // Nothing
}

/// Function required by BSD library. We have no shutdown to do.
#[no_mangle]
pub extern "C" fn nrf_modem_os_shutdown() {
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
        // The nRF91* Arm Cortex-M33 runs at 64 MHz, so this is close enough
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
///   Contains the timeout value as input and the remainig time to sleep as output.
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

/// @brief Function for loading configuration directly into IPC peripheral.
///
/// @param p_config Pointer to the structure with the initial configuration.
#[no_mangle]
pub unsafe extern "C" fn nrfx_ipc_config_load(p_config: *const NrfxIpcConfig) {
    let config: &NrfxIpcConfig = &*p_config;

    let ipc = &(*pac::IPC_NS::ptr());

    for (i, value) in config.send_task_config.iter().enumerate() {
        ipc.send_cnf[i].write(|w| w.bits(*value));
    }

    for (i, value) in config.receive_event_config.iter().enumerate() {
        ipc.receive_cnf[i].write(|w| w.bits(*value));
    }

    ipc.intenset
        .write(|w| w.bits(config.receive_events_enabled));
}

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
    let irq = pac::Interrupt::IPC;
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
    let ipc = unsafe { &(*pac::IPC_NS::ptr()) };

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
    let ipc = unsafe { &(*pac::IPC_NS::ptr()) };
    ipc.inten
        .modify(|r, w| unsafe { w.bits(r.bits() | 1 << event_index) })
}

#[no_mangle]
pub extern "C" fn nrfx_ipc_receive_event_disable(event_index: u8) {
    let ipc = unsafe { &(*pac::IPC_NS::ptr()) };
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
    critical_section::with(|cs| {
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
    critical_section::with(|cs| {
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
// This function seems to be based on this verion in C:
// https://github.com/NordicSemiconductor/nrfx/blob/98d6f433313a3d8dcf08dce25e744617b45aa913/drivers/src/nrfx_ipc.c#L146-L163
pub unsafe fn nrf_ipc_irq_handler() {
    // Get the information about events that fired this interrupt
    let events_map = (*pac::IPC_NS::ptr()).intpend.read().bits();

    // Fetch interrupt handler and context to use during event resolution
    let handler_addr = IPC_HANDLER.load(core::sync::atomic::Ordering::SeqCst);
    let handler = if handler_addr != 0 {
        let handler = core::mem::transmute::<usize, NrfxIpcHandler>(handler_addr);
        Some(handler)
    } else {
        #[cfg(feature = "defmt")]
        defmt::warn!("No IPC handler registered");
        None
    };
    let context = IPC_CONTEXT.load(core::sync::atomic::Ordering::SeqCst);

    // Clear these events
    let mut bitmask = events_map;
    while bitmask != 0 {
        let event_idx = bitmask.trailing_zeros();
        bitmask &= !(1 << event_idx);
        (*pac::IPC_NS::ptr()).events_receive[event_idx as usize].write(|w| w.bits(0));

        // Execute interrupt handler to provide information about events to app
        if let Some(handler) = handler {
            let event_idx = event_idx
                .try_into()
                .expect("A u32 has less then 255 trailing zeroes");
            (handler)(event_idx, context as *mut u8);
        }
    }
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
    sem: *mut *mut core::ffi::c_void,
    initial_count: core::ffi::c_uint,
    limit: core::ffi::c_uint,
) -> core::ffi::c_int {
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
pub extern "C" fn nrf_modem_os_sem_give(sem: *mut core::ffi::c_void) {
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
    sem: *mut core::ffi::c_void,
    mut timeout: core::ffi::c_int,
) -> core::ffi::c_int {
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
                    nrf_modem_os_busywait(1000);
                }
                _ => {
                    timeout -= 1;
                    nrf_modem_os_busywait(1000);
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
pub extern "C" fn nrf_modem_os_sem_count_get(sem: *mut core::ffi::c_void) -> core::ffi::c_uint {
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

// A basic mutex lock implementation for the os mutex functions below
struct MutexLock {
    lock: AtomicBool,
}

impl MutexLock {
    pub fn lock(&self) -> bool {
        matches!(
            self.lock
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst),
            Ok(false)
        )
    }

    pub fn unlock(&self) {
        self.lock.store(false, Ordering::SeqCst);
    }
}

/// Initialize a mutex.
///
/// The function shall allocate and initialize a mutex and return its address
/// as an output. If an address of an already allocated mutex is provided as
/// an input, the allocation part is skipped and the mutex is only reinitialized.
///
/// **Parameters**:
/// - mutex – (inout) The address of the mutex.
///
/// **Returns**
/// - 0 on success, a negative errno otherwise.
#[no_mangle]
pub unsafe extern "C" fn nrf_modem_os_mutex_init(
    mutex: *mut *mut core::ffi::c_void,
) -> core::ffi::c_int {
    if mutex.is_null() {
        return -(nrfxlib_sys::NRF_EINVAL as i32);
    }

    // Allocate if needed
    if (*mutex).is_null() {
        // Allocate memory for the MutexLock
        let p = nrf_modem_os_alloc(core::mem::size_of::<MaybeUninit<MutexLock>>())
            as *mut MaybeUninit<MutexLock>;

        if p.is_null() {
            // We are out of memory
            return -(nrfxlib_sys::NRF_ENOMEM as i32);
        }

        // Initialize the MutexLock
        p.write(MaybeUninit::new(MutexLock {
            lock: AtomicBool::new(false),
        }));

        // Assign the mutex
        *mutex = p as *mut core::ffi::c_void;
    } else {
        // Already allocated, so just reinitialize (unlock) the mutex
        (*(mutex as *mut MutexLock)).unlock();
    }

    0
}

/// Lock a mutex.
///
/// **Parameters**:
/// - mutex – (in) The mutex.
/// - timeout – Timeout in milliseconds. NRF_MODEM_OS_FOREVER indicates infinite timeout. NRF_MODEM_OS_NO_WAIT indicates no timeout.
///
/// **Return values**
/// - 0 – on success.
/// - -NRF_EAGAIN – If the mutex could not be taken.
#[no_mangle]
pub unsafe extern "C" fn nrf_modem_os_mutex_lock(
    mutex: *mut core::ffi::c_void,
    timeout: core::ffi::c_int,
) -> core::ffi::c_int {
    if mutex.is_null() {
        return -(nrfxlib_sys::NRF_EINVAL as i32);
    }

    let mutex = &*(mutex as *mut MutexLock);

    let mut locked = mutex.lock();

    if locked || timeout == nrfxlib_sys::NRF_MODEM_OS_NO_WAIT as i32 {
        return if locked {
            0
        } else {
            -(nrfxlib_sys::NRF_EAGAIN as i32)
        };
    }

    let mut elapsed = 0;
    const WAIT_US: core::ffi::c_int = 100;

    while !locked {
        nrf_modem_os_busywait(WAIT_US);

        if timeout != nrfxlib_sys::NRF_MODEM_OS_FOREVER {
            elapsed += WAIT_US;
            if (elapsed / 1000) > timeout {
                return -(nrfxlib_sys::NRF_EAGAIN as i32);
            }
        }

        locked = mutex.lock();
    }

    0
}

/// Unlock a mutex.
///
/// **Parameters**:
/// - mutex – (in) The mutex.
///
/// **Return values**
/// - 0 – on success.
/// - -NRF_EPERM – If the current thread does not own this mutex.
/// - -NRF_EINVAL – If the mutex is not locked.
#[no_mangle]
pub unsafe extern "C" fn nrf_modem_os_mutex_unlock(
    mutex: *mut core::ffi::c_void,
) -> core::ffi::c_int {
    if mutex.is_null() {
        return -(nrfxlib_sys::NRF_EINVAL as i32);
    }
    (*(mutex as *mut MutexLock)).unlock();
    0
}

/// Generic logging procedure
///
/// **Parameters**:
/// - level – Log level
/// - msg - Message
/// - ... – Varargs
#[no_mangle]
pub unsafe extern "C" fn nrf_modem_os_log_wrapped(
    _level: core::ffi::c_int,
    _msg: *const core::ffi::c_char,
) {
    #[cfg(all(feature = "defmt", feature = "modem-log"))]
    {
        let msg = core::ffi::CStr::from_ptr(_msg);
        if let Ok(msg) = msg.to_str() {
            defmt::trace!("Modem log <{}>: {}", _level, msg);
        }
    }
}

/// Logging procedure for dumping hex representation of object.
///
/// **Parameters**:
/// - level – Log level.
/// - strdata - String to print in the log.
/// - data - Data whose hex representation we want to log.
/// - len - Length of the data to hex dump.
#[no_mangle]
pub extern "C" fn nrf_modem_os_logdump(
    _level: core::ffi::c_int,
    _strdata: *const core::ffi::c_char,
    _data: *const core::ffi::c_void,
    _len: core::ffi::c_int,
) {
    // TODO FIXME
}
