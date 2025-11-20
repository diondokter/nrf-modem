use cortex_m::peripheral::NVIC;
use defmt::{debug, warn};
use embassy_nrf::{
    bind_interrupts,
    gpio::{Level, Output, OutputDrive},
    interrupt::typelevel,
    pac,
};

use {defmt_rtt as _, panic_probe as _};
extern crate tinyrlibc;

#[doc(hidden)]
pub struct InterruptHandler {
    _private: (),
}

impl typelevel::Handler<typelevel::IPC> for InterruptHandler {
    unsafe fn on_interrupt() {
        nrf_modem::ipc_irq_handler();
    }
}

bind_interrupts!(struct Irqs{
    IPC => InterruptHandler;
});

extern "C" {
    static __start_ipc: u8;
    static __end_ipc: u8;
}

pub async fn init() -> (u32, [Output<'static>; 4]) {
    // Copied from latest embassy-nrf init:
    let mut needs_reset = false;
    // Workaround used in the nrf mdk: file system_nrf91.c , function SystemInit(), after `#if !defined(NRF_SKIP_UICR_HFXO_WORKAROUND)`
    let uicr = embassy_nrf::pac::UICR_S;
    let hfxocnt = uicr.hfxocnt().read().hfxocnt().to_bits();
    let hfxosrc = uicr.hfxosrc().read().hfxosrc().to_bits();
    const UICR_HFXOSRC: *mut u32 = 0x00FF801C as *mut u32;
    const UICR_HFXOCNT: *mut u32 = 0x00FF8020 as *mut u32;
    if hfxosrc == 1 {
        unsafe {
            let _ = uicr_helpers::uicr_write(UICR_HFXOSRC, 0);
        }
        needs_reset = true;
    }
    if hfxocnt == 255 {
        unsafe {
            let _ = uicr_helpers::uicr_write(UICR_HFXOCNT, 32);
        }
        needs_reset = true;
    }
    if needs_reset {
        panic!(
            "UICR bits were gravely misconfigure. Fixed, but this requires a reboot; you may want to run again with --preverify."
        );
    }
    // end copied

    let p = embassy_nrf::init(Default::default());

    fn configure_modem_non_secure() -> u32 {
        // The RAM memory space is divided into 32 regions of 8 KiB.
        // Set IPC RAM to nonsecure
        const SPU_REGION_SIZE: u32 = 0x2000; // 8kb
        const RAM_START: u32 = 0x2000_0000; // 256kb
        let ipc_start: u32 = unsafe { &__start_ipc as *const u8 } as u32;
        let ipc_reg_offset = (ipc_start - RAM_START) / SPU_REGION_SIZE;
        let ipc_reg_count =
            (unsafe { &__end_ipc as *const u8 } as u32 - ipc_start) / SPU_REGION_SIZE;
        let spu = embassy_nrf::pac::SPU;
        let range = ipc_reg_offset..(ipc_reg_offset + ipc_reg_count);
        debug!("marking region as non secure: {}", range);
        for i in range {
            spu.ramregion(i as usize).perm().write(|w| {
                w.set_execute(true);
                w.set_write(true);
                w.set_read(true);
                w.set_secattr(false);
                w.set_lock(false);
            })
        }

        // Set regulator access registers to nonsecure
        spu.periphid(4).perm().write(|w| w.set_secattr(false));
        // Set clock and power access registers to nonsecure
        spu.periphid(5).perm().write(|w| w.set_secattr(false));
        // Set IPC access register to nonsecure
        spu.periphid(42).perm().write(|w| w.set_secattr(false));
        ipc_start
    }
    let ipc_start = configure_modem_non_secure();

    let mut cp = cortex_m::Peripherals::take().expect("Failed to take Cortex-M peripherals");

    // Enable the modem interrupts
    unsafe {
        NVIC::unmask(pac::Interrupt::IPC);
        cp.NVIC.set_priority(pac::Interrupt::IPC, 0 << 5);
    }

    // nRF9151 LED pins
    let leds = [
        Output::new(p.P0_00, Level::Low, OutputDrive::Standard),
        Output::new(p.P0_01, Level::Low, OutputDrive::Standard),
        Output::new(p.P0_04, Level::Low, OutputDrive::Standard),
        Output::new(p.P0_05, Level::Low, OutputDrive::Standard),
    ];

    (ipc_start, leds)
}

// See top of the init function: adapted from embassy-nrf
mod uicr_helpers {
    pub unsafe fn uicr_write(address: *mut u32, value: u32) {
        uicr_write_masked(address, value, 0xFFFF_FFFF)
    }

    pub unsafe fn uicr_write_masked(address: *mut u32, value: u32, mask: u32) {
        let curr_val = address.read_volatile();
        if curr_val & mask == value & mask {
            return;
        }

        // We can only change `1` bits to `0` bits.
        if curr_val & value & mask != value & mask {
            panic!("Can't write");
        }

        // Nrf9151 errata 7, need to disable interrups + use DSB https://docs.nordicsemi.com/bundle/errata_nRF9151_Rev2/page/ERR/nRF9151/Rev2/latest/anomaly_151_7.html
        cortex_m::interrupt::free(|_cs| {
            let nvmc = embassy_nrf::pac::NVMC;

            nvmc.config()
                .write(|w| w.set_wen(embassy_nrf::pac::nvmc::vals::Wen::WEN));
            while !nvmc.ready().read().ready() {}
            address.write_volatile(value | !mask);
            cortex_m::asm::dsb();
            while !nvmc.ready().read().ready() {}
            nvmc.config().write(|_| {});
            while !nvmc.ready().read().ready() {}
        });
    }
}
