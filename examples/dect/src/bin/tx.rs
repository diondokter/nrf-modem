//! Minimal transmit example
//!
//! This sends a hand-crafted beacon message whenever the first button is pressed.
#![no_std]
#![no_main]

use defmt::info;
use embassy_executor::Spawner;
use embassy_time::Timer;
use nrf_modem::MemoryLayout;


use dect_example::common::*;

#[embassy_executor::main]
async fn main(_spawner: Spawner) {
    let (ipc_start, _leds, buttons) = init().await;

    let mut dect = dect::DectPhy::init_with_custom_layout(MemoryLayout {
        base_address: ipc_start,
        tx_area_size: 0x2000,
        rx_area_size: 0x2000,
        trace_area_size: 0x1000,
    })
    .await
    .unwrap();

    loop {
        while buttons[0].is_high() {}
        info!("Press.");

        dect.tx(
            0,
            1665,
            // FIXME: Not using a proper network ID yet
            0x12345678,
            // Beacon as seen by the dect_shell
            &[17, 120, 150, 24, 112],
            &[
                1, 18, 52, 86, 0, 0, 0, 38, 73, 5, 176, 16, 6, 0, 13, 83, 7, 8, 12, 138, 160, 215,
                2, 100, 64, 24, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0,
            ],
        )
        .await
        .unwrap();

        // Debounce and wait for release
        Timer::after_millis(5).await;
        while buttons[0].is_low() {}
        Timer::after_millis(5).await;
    }

    // No need to have a panic exit path to not lockup the CPU: This only transmits on demand
    // anyway.
}
