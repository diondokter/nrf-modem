#![no_std]
#![no_main]

use core::{net::IpAddr, str::FromStr};
use cortex_m::peripheral::NVIC;
use defmt::{debug, info, warn};
use embassy_executor::Spawner;
use embassy_net::{Ipv4Cidr, Stack, StackResources};
use embassy_nrf::{
    bind_interrupts,
    gpio::{Level, Output, OutputDrive},
    interrupt::typelevel,
    pac,
};
use embassy_time::{Duration, Timer};
use embedded_io_async::Write;
use heapless::Vec;
use nrf_modem::embassy_net_modem::{
    context::{self, PdConfig, PdpType, Status},
    NetDriver, Runner, State,
};
use nrf_modem::{ConnectionPreference, MemoryLayout, SystemMode};
use static_cell::StaticCell;

use {defmt_rtt as _, panic_probe as _};
extern crate tinyrlibc;

pub type NetworkDevice = NetDriver<'static>;
const MAX_CONCURRENT_SOCKETS: usize = 4;

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

#[embassy_executor::task]
pub(crate) async fn net_task(mut runner: embassy_net::Runner<'static, NetworkDevice>) -> ! {
    runner.run().await
}

#[embassy_executor::task]
async fn modem_task(runner: Runner<'static>) -> ! {
    runner.run().await
}

#[embassy_executor::task]
pub async fn control_task(
    control: &'static context::Control<'static>,
    config: PdConfig<'static>,
    pin: Option<&'static [u8]>,
    stack: Stack<'static>,
) {
    control.configure(&config, pin).await.unwrap();

    control
        .run(|status| {
            stack.set_config_v4(status_to_config(status));
        })
        .await
        .unwrap();
}
pub fn status_to_config(status: &Status) -> embassy_net::ConfigV4 {
    let Some(IpAddr::V4(addr)) = status.ip1 else {
        panic!("Unexpected IP address");
    };

    let gateway = match status.gateway {
        Some(IpAddr::V4(addr)) => Some(addr),
        _ => None,
    };

    let mut dns_servers = Vec::new();
    for dns in status.dns.iter() {
        if let IpAddr::V4(ip) = dns {
            dns_servers.push(*ip).unwrap();
        }
    }

    embassy_net::ConfigV4::Static(embassy_net::StaticConfigV4 {
        address: Ipv4Cidr::new(addr, 32),
        gateway,
        dns_servers,
    })
}

pub async fn init<'a>(spawner: Spawner) -> (NetworkDevice, &'a context::Control<'a>) {
    static STATE: StaticCell<State> = StaticCell::new();
    let (driver, control, runner) =
        nrf_modem::embassy_net_modem::new(STATE.init(State::new())).await;

    spawner.spawn(modem_task(runner)).unwrap();

    static CONTROL: StaticCell<context::Control<'static>> = StaticCell::new();
    let control = CONTROL.init(context::Control::new(control, 0).await);

    (driver, control)
}

extern "C" {
    static __start_ipc: u8;
    static __end_ipc: u8;
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let p = embassy_nrf::init(Default::default());

    let mut led = Output::new(p.P0_02, Level::Low, OutputDrive::Standard);

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

    nrf_modem::init_with_custom_layout(
        SystemMode {
            lte_support: true,
            lte_psm_support: true,
            nbiot_support: false,
            gnss_support: true,
            preference: ConnectionPreference::None,
        },
        MemoryLayout {
            base_address: ipc_start,
            tx_area_size: 0x2000,
            rx_area_size: 0x2000,
            trace_area_size: 0x1000,
        },
    )
    .await
    .unwrap();

    let (device, control) = init(spawner).await;

    let config = embassy_net::Config::default();

    static RESOURCES: StaticCell<StackResources<MAX_CONCURRENT_SOCKETS>> = StaticCell::new();

    let seed = 123456;

    let (stack, runner) = embassy_net::new(
        device,
        config,
        RESOURCES.init_with(StackResources::new),
        seed,
    );

    let config = PdConfig {
        apn: None,
        pdn_auth: None,
        pdp_type: PdpType::Ip,
    };

    spawner.spawn(net_task(runner)).unwrap();
    spawner
        .spawn(control_task(control, config, None, stack))
        .unwrap();

    info!("Waiting for modem to be ready...");
    led.set_low();
    stack.wait_config_up().await;

    info!("Modem is ready!");

    let mut rx_buffer = [0; 4096];
    let mut tx_buffer = [0; 4096];
    loop {
        led.set_high();
        let mut socket = embassy_net::tcp::TcpSocket::new(stack, &mut rx_buffer, &mut tx_buffer);
        socket.set_timeout(Some(Duration::from_secs(10)));

        info!("Connecting...");
        let host_addr = embassy_net::Ipv4Address::from_str("45.79.112.203").unwrap();
        if let Err(e) = socket.connect((host_addr, 4242)).await {
            warn!("connect error: {:?}", e);
            Timer::after_secs(10).await;
            continue;
        }
        info!("Connected to {:?}", socket.remote_endpoint());

        let msg = b"Hello world!\n";
        for _ in 0..10 {
            if let Err(e) = socket.write_all(msg).await {
                warn!("write error: {:?}", e);
                break;
            }
            info!("txd: {}", core::str::from_utf8(msg).unwrap());
            Timer::after_secs(1).await;
        }
        led.set_low();
        Timer::after_secs(4).await;
    }
}
