//! Minimal receive example
//!
//! While this is running, peers executing the nRF dect_shell example and running `dect ping -c`
//! produce visible traffic.
#![no_std]
#![no_main]

use defmt::info;
use embassy_executor::Spawner;
use embassy_time::{Duration, Timer};
use nrf_modem::MemoryLayout;

use dect_example::common::*;

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let (ipc_start, leds) = init().await;

    let mut dect = nrf_modem::init_dect_with_custom_layout(MemoryLayout {
        base_address: ipc_start,
        tx_area_size: 0x2000,
        rx_area_size: 0x2000,
        trace_area_size: 0x1000,
    })
    .await
    .unwrap();

    for _ in 0..100 {
        info!("DECT time is {}", dect.time_get().await);

        info!("Received {}", dect.rx().await);

        Timer::after_millis(500).await;
    }

    panic!("If we want to be able to re-flash, we better things at some point to avoid going through unlock again.");
}
