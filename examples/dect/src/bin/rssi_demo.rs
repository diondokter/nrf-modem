#![no_std]
#![no_main]

use cortex_m::peripheral::NVIC;
use defmt::{debug, info, warn};
use embassy_executor::Spawner;
use embassy_nrf::{
    bind_interrupts,
    gpio::{Level, Output, OutputDrive},
    interrupt::typelevel,
    pac,
};
use embassy_time::{Duration, Timer};
use embedded_io_async::Write;
use nrf_modem::MemoryLayout;
use static_cell::StaticCell;

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

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let p = embassy_nrf::init(Default::default());

    let mut led = Output::new(p.P0_00, Level::Low, OutputDrive::Standard);

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

    let dect = nrf_modem::init_dect_with_custom_layout(MemoryLayout {
        base_address: ipc_start,
        tx_area_size: 0x2000,
        rx_area_size: 0x2000,
        trace_area_size: 0x1000,
    })
    .await
    .unwrap();

    for _ in 0..30 {
        info!("DECT time is {}", dect.time_get().await);

        info!("RSSI for band 1");
        for carrier in 1657..=1677 {
            info!("RSSI is {}", dect.rssi(carrier).await);
        }
        info!("RSSI for band 2");
        for carrier in 1680..=1700 {
            info!("RSSI is {}", dect.rssi(carrier).await);
        }
        info!("RSSI for band 9");
        for carrier in 1703..=1711 {
            info!("RSSI is {}", dect.rssi(carrier).await);
        }
        // Not scanning band 22 yet: That is weirdly spanning others

        // Probably out of reach? 400kHz area -- funny, it gives Ok but no frames.
        info!("RSSI is {}", dect.rssi(1).await);

        Timer::after_millis(500).await;
    }



    panic!("Got DECT what now?");
}
