#![no_std]
#![no_main]

use defmt::info;
use embassy_executor::Spawner;
use embassy_time::{Duration, Timer};
use nrf_modem::MemoryLayout;

use dect_example::common::*;

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let (ipc_start, _leds, _buttons) = init().await;

    let dect_preinit = nrf_modem::init_dect_with_custom_layout(
        MemoryLayout {
            base_address: ipc_start,
            tx_area_size: 0x2000,
            rx_area_size: 0x2000,
            trace_area_size: 0x1000,
        },
        nrf_modem::dect::dect_event,
    )
    .unwrap();

    let mut dect = nrf_modem::dect::DectPhy::new(dect_preinit).await.unwrap();

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
