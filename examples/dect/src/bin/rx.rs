//! Minimal receive example
//!
//! While this is running, peers executing the nRF dect_shell example and running `dect ping -c`
//! produce visible traffic.
#![no_std]
#![no_main]

use defmt::{info, warn};
use embassy_executor::Spawner;
use embassy_time::{Duration, Timer};
use nrf_modem::MemoryLayout;

use ts_103_636_numbers as numbers;

use dect_example::common::*;

fn log_header(header: &[u8]) {
    // Following ETSI TS 103 636-4 V2.1.1 Section 6.2
    let hdr_format = header[0] >> 5;
    let packet_len = header[0] & 0x0f;
    let packet_len_units = if header[0] & 0x10 == 0 {
        "subslots"
    } else {
        "slots"
    };
    let short_nid = header[1];
    let transmitter_id = u16::from_be_bytes(header[2..4].try_into().unwrap());
    let transmit_power = header[4] >> 4;
    // Weird enough, in the 5-byte header the MSB of this is reserved, but we can still
    // decode it this way:
    let df_mcs = header[4] & 0x0f;

    match header.len() {
        5 => {
            info!(
                "Header details: format {} length {} {}, nid {}, from {}, tx power {}, df_mcs {}",
                hdr_format,
                packet_len,
                packet_len_units,
                short_nid,
                transmitter_id,
                transmit_power,
                df_mcs
            );
        }
        10 => {
            let receiver_id = u16::from_be_bytes(header[5..7].try_into().unwrap());
            // Ignoring remaining feedback info for the moment; its interpretation depends on hdr_format
            // (although that really only tells if that's reserved or used).
            info!(
                "Header details: format {} length {} {}, nid {}, from {} to {}, tx power {}, df_mcs {}",
                hdr_format,
                packet_len,
                packet_len_units,
                short_nid,
                transmitter_id,
                receiver_id,
                transmit_power,
                df_mcs
            );
        }
        _ => unreachable!("Header length is always 5 or 10"),
    }
}

fn log_data(data: &[u8]) {
    // Following ETSI TS 103 636-4 V2.1.1 Section 6.3
    let version = data[0] >> 6;
    if version == 3 {
        warn!("Can not decode dect_shell ping (or whatever nonstandard version this is)");
        return;
    }
    if version != numbers::mac_pdu::VERSION {
        warn!("Unknown MAC version.");
        return;
    }
    let mac_sec_version = data[0] >> 6;
    let mac_hdr_type = data[0] & 0x0f;
    let mac_hdr_type_name = match mac_hdr_type {
        // FIXME: Add Formatter?
        numbers::mac_pdu::header_type::DATA_MAC_PDU => "DATA MAC PDU",
        numbers::mac_pdu::header_type::BEACON => "Beacon",
        numbers::mac_pdu::header_type::UNICAST => "Unicast",
        numbers::mac_pdu::header_type::RD_BROADCAST => "RD Broadcast",
        _ => "unknown",
    };
    info!(
        "Header data: MAC security {}, header type {} {}",
        mac_sec_version, mac_hdr_type, mac_hdr_type_name
    );
    let end_common_header = match mac_hdr_type {
        numbers::mac_pdu::header_type::DATA_MAC_PDU => {
            let reset = (data[1] & 0x10) >> 4;
            let seqno = (data[1] as u16 & 0x0f) << 8 | (data[2] as u16);

            let transmitter = &data[4..8];
            info!("DATA MAC PDU details: reset {}, seqno {}", reset, seqno);
            3
        }
        numbers::mac_pdu::header_type::BEACON => {
            let long_nid = &data[1..4];
            let transmitter = &data[4..8];
            info!(
                "Beacon details: Network {:x}, transmitter {:x}",
                long_nid, transmitter
            );
            8
        }
        numbers::mac_pdu::header_type::UNICAST => {
            let reset = (data[1] & 0x10) >> 4;
            let mac_sequence = data[1] & 0x0f;
            let seqno = data[2];
            let receiver = &data[3..7];
            let transmitter = &data[7..11];
            info!(
                "Unicast details: reset {}, mac_sequence {}, seqno {}, to {} from {}",
                reset, mac_sequence, seqno, receiver, transmitter,
            );
            11
        }
        numbers::mac_pdu::header_type::RD_BROADCAST => {
            let reset = (data[1] & 0x10) >> 4;
            let seqno = (data[1] as u16 & 0x0f) << 8 | (data[2] as u16);
            let transmitter = &data[3..7];
            info!(
                "RD Broadcast details: reset {}, seqno {}, from {}",
                reset, seqno, transmitter,
            );
            7
        }
        _ => {
            info!("Unknown common header, can not decode further");
            return;
        }
    };
    if mac_sec_version != 0 {
        info!("No link-layer security implemented, bailing.");
        return;
    }
    let mut tail = &data[end_common_header..];
    while !tail.is_empty() {
        let mac_ext = tail[0] >> 6;
        let ie_type = tail[0] & 0x3f;
        let ie_type = numbers::mac_ie::IEType6bit::try_from(ie_type).unwrap();
        match mac_ext {
            numbers::mac_pdu::mux_ext::NO_LENGTH_FIELD => {
                // No length
                info!("Don't know how to decode no-length fields, bailing.");
                return;
            }
            numbers::mac_pdu::mux_ext::LENGTH_8BIT => {
                let len = tail[1];
                let end = 2 + len as usize;
                let payload = &tail[2..end];
                info!("IE type {} payload {}", ie_type, payload);
                tail = &tail[end..];
                continue;
            }
            numbers::mac_pdu::mux_ext::LENGTH_16BIT => {
                let len = u16::from_be_bytes(tail[1..3].try_into().unwrap());
                let end = 3 + len as usize;
                let payload = &tail[3..end];
                info!("IE type {} payload {}", ie_type, payload);
                tail = &tail[end..];
                continue;
            }
            numbers::mac_pdu::mux_ext::SHORT_IE => {
                info!("Don't know how to decode Short IE, bailing.");
                return;
            }
            _ => unreachable!(),
        }
    }
    info!("Complete message processed.");
}

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

    for _ in 0..100 {
        if let Some(received) = dect
            .rx()
            .await
            .expect("Receive operation failed as a whole") {
            let start = received.pcc_time();
            let pcc = received.pcc();
            let pdc = received.pdc();
            if let (Ok(start), Ok(pcc), Ok(pdc)) = (start, pcc, pdc) {
                info!(
                    "Received at {}: {:?} {:?}",
                    start,
                    pcc,
                    pdc
                );
                log_header(pcc);
                log_data(pdc);
            } else {
                warn!("Received partial transmission: {:?} {:?} {:?}", start, pcc, pdc);
            }
        }

        Timer::after_millis(500).await;
    }

    panic!("If we want to be able to re-flash, we better things at some point to avoid going through unlock again.");
}
