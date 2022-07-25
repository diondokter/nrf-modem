#![no_std]
#![feature(async_iterator)]

use crate::error::ErrorSource;
use core::cell::RefCell;
use cortex_m::interrupt::Mutex;
use error::Error;
use linked_list_allocator::Heap;

pub mod error;
pub mod gnss;
pub mod ffi;

/// We need to wrap our heap so it's creatable at run-time and accessible from an ISR.
///
/// * The Mutex allows us to safely share the heap between interrupt routines
///   and the main thread - and nrfxlib will definitely use the heap in an
///   interrupt.
/// * The RefCell lets us share and object and mutate it (but not at the same
///   time)
/// * The Option is because the `linked_list_allocator::empty()` function is not
///   `const` yet and cannot be called here
///
type WrappedHeap = Mutex<RefCell<Option<Heap>>>;

//******************************************************************************
// Constants
//******************************************************************************

// None

//******************************************************************************
// Global Variables
//******************************************************************************

/// Our general heap.
///
/// We initialise it later with a static variable as the backing store.
static LIBRARY_ALLOCATOR: WrappedHeap = Mutex::new(RefCell::new(None));

/// Our transmit heap.

/// We initalise this later using a special region of shared memory that can be
/// seen by the Cortex-M33 and the modem CPU.
static TX_ALLOCATOR: WrappedHeap = Mutex::new(RefCell::new(None));

//******************************************************************************
// Macros
//******************************************************************************

// None

//******************************************************************************
// Public Functions and Impl on Public Types
//******************************************************************************

/// Start the NRF Modem library
pub fn init() -> Result<(), Error> {
    unsafe {
        /// Allocate some space in global data to use as a heap.
        static mut HEAP_MEMORY: [u32; 1024] = [0u32; 1024];
        let heap_start = HEAP_MEMORY.as_ptr() as usize;
        let heap_size = HEAP_MEMORY.len() * core::mem::size_of::<u32>();
        cortex_m::interrupt::free(|cs| {
            *LIBRARY_ALLOCATOR.borrow(cs).borrow_mut() = Some(Heap::new(heap_start, heap_size))
        });
    }

    // Tell nrf_modem what memory it can use.
    let params = nrfxlib_sys::nrf_modem_init_params_t {
        shmem: nrfxlib_sys::nrf_modem_shmem_cfg {
            ctrl: nrfxlib_sys::nrf_modem_shmem_cfg__bindgen_ty_1 {
                // At start of shared memory (see memory.x)
                base: 0x2001_0000,
                // This is the amount specified in the NCS 1.5.1 release.
                size: 0x0000_04e8,
            },
            tx: nrfxlib_sys::nrf_modem_shmem_cfg__bindgen_ty_2 {
                // Follows on from control buffer
                base: 0x2001_04e8,
                // This is the amount specified in the NCS 1.5.1 release.
                size: 0x0000_2000,
            },
            rx: nrfxlib_sys::nrf_modem_shmem_cfg__bindgen_ty_3 {
                // Follows on from TX buffer
                base: 0x2001_24e8,
                // This is the amount specified in the NCS 1.5.1 release.
                size: 0x0000_2000,
            },
            // No trace info
            trace: nrfxlib_sys::nrf_modem_shmem_cfg__bindgen_ty_4 { base: 0, size: 0 },
        },
        ipc_irq_prio: 0,
        fault_handler: Some(modem_fault_handler),
    };

    unsafe {
        // Use the same TX memory region as above
        cortex_m::interrupt::free(|cs| {
            *TX_ALLOCATOR.borrow(cs).borrow_mut() = Some(Heap::new(
                params.shmem.tx.base as usize,
                params.shmem.tx.size as usize,
            ))
        });
    }

    // OK, let's start the library
    unsafe { nrfxlib_sys::nrf_modem_init(&params, nrfxlib_sys::nrf_modem_mode_t_NORMAL_MODE) }
        .into_result()
}

unsafe extern "C" fn modem_fault_handler(_info: *mut nrfxlib_sys::nrf_modem_fault_info) {
    #[cfg(feature = "defmt")]
    defmt::error!("Modem fault - reason: {}, pc: {}", (*_info).reason, (*_info).program_counter);
}

/// You must call this when an EGU1 interrupt occurs.
pub fn application_irq_handler() {
	unsafe {
		nrfxlib_sys::nrf_modem_application_irq_handler();
        nrfxlib_sys::nrf_modem_os_event_notify();
	}
}

/// must call this when an EGU2 interrupt occurs.
pub fn trace_irq_handler() {
	unsafe {
		nrfxlib_sys::nrf_modem_trace_irq_handler();
        nrfxlib_sys::nrf_modem_os_event_notify();
	}
}

/// IPC code now lives outside `lib_modem`, so call our IPC handler function.
pub fn ipc_irq_handler() {
	unsafe {
		crate::ffi::nrf_ipc_irq_handler();
        nrfxlib_sys::nrf_modem_os_event_notify();
	}
}
