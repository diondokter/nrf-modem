#![no_std]
#![no_main]

use defmt::info;
use embassy_executor::Spawner;
use embassy_time::Timer;
use nrf_modem::MemoryLayout;

use dect_example::common::*;

#[embassy_executor::main]
async fn main(_spawner: Spawner) {
    let (ipc_start, _leds, _buttons) = init().await;

    let mut dect = dect::DectPhy::init_with_custom_layout(MemoryLayout {
        base_address: ipc_start,
        tx_area_size: 0x2000,
        rx_area_size: 0x2000,
        trace_area_size: 0x1000,
    })
    .await
    .unwrap();

    for _ in 0..30 {
        info!("DECT time is {}", dect.time_get().await);

        info!("Scanning band 1");
        for carrier in 1657..=1677 {
            if let Ok(rssi) = dect.rssi(carrier).await {
                info!("RSSI for {} at {}: {}", carrier, rssi.0, rssi.1.data());
            }
        }
        info!("Scanning band 2");
        for carrier in 1680..=1700 {
            if let Ok(rssi) = dect.rssi(carrier).await {
                info!("RSSI for {} at {}: {}", carrier, rssi.0, rssi.1.data());
            }
        }
        info!("Scanning band 9");
        for carrier in 1703..=1711 {
            if let Ok(rssi) = dect.rssi(carrier).await {
                info!("RSSI for {} at {}: {}", carrier, rssi.0, rssi.1.data());
            }
        }
        // Not scanning band 22 yet: That is weirdly spanning others

        // Probably out of reach? 400kHz area -- funny, it initializes and gives COMPLETED but no frames.
        dect.rssi(1).await.map(|_| ()).unwrap_err();

        Timer::after_millis(500).await;
    }

    panic!("Got DECT what now?");
}
