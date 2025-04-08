# nRF-Modem

[![crates.io](https://img.shields.io/crates/v/nrf-modem.svg)](https://crates.io/crates/nrf-modem) [![Documentation](https://docs.rs/nrf-modem/badge.svg)](https://docs.rs/nrf-modem)

This is a library that provides a high-level async API for the modem on the Nordic nRF91* series chips (System-in-Packages). Supported chips are the following:

* nRF9160
* nRF9151
* nRF9161

It can be used with any executor.

## Using

In your own program or library, you can depend on this crate in the usual fashion.

nrf9160:

```toml
[dependencies]
nrf-modem = { version = "x.x.x", features = ["nrf9160"] }
```

nrf9161:

```toml
[dependencies]
nrf-modem = { version = "x.x.x", features = ["nrf9161"] }
```

nrf9151:

```toml
[dependencies]
nrf-modem = { version = "x.x.x", features = ["nrf9151"] }
```

 The built-in modem DNS resolver is blocking. If you want to use an async DNS resolver you can enable the feature `dns-async`. This will switch to an async implementation which uses publicly availabe DNS servers.

## Errors and recovery

Dropping LteLink and Gnss (which also include all sockets and GnssStream) *can* lead to the modem staying active.
There's an internal mutex that can be locked. Panicking is the only sane reaction to that.
If you have a better idea, please open an issue or PR!
The async `deactivate` function is way less likely to go wrong and you'll get a Result back so you know that something has gone wrong.

If anything does go wrong, `has_runtime_state_error()` will return true.
Everything should stay working, but it's likely that the modem won't be properly turned off.
This can be recovered by calling the `reset_runtime_state()` function when you've made sure nothing of the modem is used anymore.

## Receiving packets with TLS

When receiving packets with TLS enabled, the nrf9160 modem can handle a maximum packet size of 2kB which is well below the default settings for most servers ([see](https://devzone.nordicsemi.com/f/nordic-q-a/88768/socket-recv-returning--122-nrf9160) [here](https://devzone.nordicsemi.com/f/nordic-q-a/91700/unusual-socket-errno-122-when-using-nrf91-tls-psk)). The library will throw an error with the variant `TlsPacketTooBig` if the modem receives a packet over this size. You will need to change settings at the server side if this error occurs, or use a proxy server.

## Setup

There are a couple of things you must do to be able to use the library.

First of which, make sure to have the `llvm-tools` installed.
This can be done using `rustup component add llvm-tools-preview`.

The library also needs some `libc` functions.
The best way to import them is with [tinyrlibc](https://github.com/rust-embedded-community/tinyrlibc).
As of writing the newest release is `0.3.0`. This version does not include a needed API,
so it's better to include the latest master branch or any newer released version.

This library has been tested with modem firmware version `1.3.4` but might work with earlier versions.
When this library starts to require a newer version, then that will be seen as a breaking change.
But it's easy to miss something, so this is a 'best effort' guarantee only.

### Memory

The model library from Nordic needs some memory for its state and buffers. You need to reserve some memory in your memory.x file for the modem:

```ld
MEMORY
{
    FLASH : ORIGIN = 0x00000000, LENGTH = 1024K
    MODEM : ORIGIN = 0x20000000, LENGTH = 32K
    RAM   : ORIGIN = 0x20008000, LENGTH = 224K
}
```

### Secure and nonsecure operation

Warning: The underlying C library, `libmodem`, assumes and 'officially' requires to be run in the non-secure mode of the chip.
So that's the only official support this wrapper can deliver too.

The library *can* be used in secure contexts, though. Some additional initialization is necessary for the secure context because the underlying libmodem C library by Nordic expects access to nonsecure memory and resources. If you do not use the memory layout defined above, you need to adapt the addresses below. 

For running in the secure context on some chips and version and at your own risk and peril:
```rust,ignore
// Initializing embassy_nrf has to come first because it assumes POWER and CLOCK at the secure address
let embassy_peripherals = embassy_nrf::init(Default::default());

// Set IPC RAM to nonsecure
const SPU_REGION_SIZE: u32 = 0x2000; // 8kb
const RAM_START: u32 = 0x2000_0000; // 256kb
let spu = embassy_nrf::pac::SPU;
let region_start = 0x2000_000 - RAM_START / SPU_REGION_SIZE;
let region_end = region_start + (0x2000_8000 - 0x2000_0000) / SPU_REGION_SIZE;
for i in region_start..region_end {
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
```

### Interrupts

The `IPC` interrupts must be routed to the modem software.

```rust,ignore
// Interrupt Handler for LTE related hardware. Defer straight to the library.
#[interrupt]
#[allow(non_snake_case)]
fn IPC() {
    nrf_modem::ipc_irq_handler();
}

let mut cp = unwrap!(cortex_m::Peripherals::take());

// Enable the modem interrupts
unsafe {
    NVIC::unmask(pac::Interrupt::IPC);
    cp.NVIC.set_priority(pac::Interrupt::IPC, 0 << 5);
}
```

### Power

The DC/DC converter is automatically enabled for you when the library is initialized.
This is required for certified operation of the modem.

### Initialization

Now it's time to initialize the library. Here you can make a selection for the connectivity for the modem:

```rust,ignore
nrf_modem::init(SystemMode {
    lte_support: true,
    lte_psm_support: true,
    nbiot_support: true,
    gnss_support: true,
    preference: ConnectionPreference::None,
})
.await
.unwrap();
```

Now the library is ready to be used.

## AT Commands

```rust,ignore
let response = nrf_modem::send_at::<64>("AT+CGMI").await.unwrap();
assert_eq!(response, "AT+CGMI\n\rNordic Semiconductor ASA\n\rOK\n\r");
```

## DNS request

```rust,ignore
let google_ip = nrf_modem::get_host_by_name("www.google.com").await.unwrap();
```

## Tcp connection

```rust,ignore
let stream = nrf_modem::TcpStream::connect(SocketAddr::from((google_ip, 80))).await.unwrap();

stream
    .write("GET / HTTP/1.0\nHost: google.com\r\n\r\n".as_bytes())
    .await
    .unwrap();

let mut buffer = [0; 1024];
let received = stream.receive(&mut buffer).await.unwrap();

println!("Google response: {}", core::str::from_utf8(received).unwrap());

// Drop the stream async (normal Drop is ok too, but that's blocking)
stream.deactivate().await.unwrap();
```

## Udp socket

```rust,ignore
let socket =
    nrf_modem::UdpSocket::bind(SocketAddr::from_str("0.0.0.0:53").unwrap())
        .await
        .unwrap();

// Do a DNS request
socket
    .send_to(
        &[
            0xdb, 0x42, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77,
            0x77, 0x77, 0x0C, 0x6E, 0x6F, 0x72, 0x74, 0x68, 0x65, 0x61, 0x73, 0x74, 0x65, 0x72,
            0x6E, 0x03, 0x65, 0x64, 0x75, 0x00, 0x00, 0x01, 0x00, 0x01,
        ],
        SocketAddr::from_str("8.8.8.8:53").unwrap(),
    )
    .await
    .unwrap();
let (response, source_addr) = socket.receive_from(&mut buffer).await.unwrap();

println!("Result: {:X}", response);
println!("Source: {}", source_addr);
```

## Secure tcp connection over TLS

Before this can run, you need to store the required certificate in a security tag on the modem using AT commands. See the [Nordic Docs](https://docs.nordicsemi.com/bundle/ncs-latest/page/nrf/libraries/modem/modem_key_mgmt.html) on how to do this. TLS handshake will be much faster if you enforce an efficient cipher suite like `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`.

```rust,ignore
    let stream = nrf_modem::TlsStream::connect(
        "example.com",
        443,
        PeerVerification::Optional,
        &[ROOT_PEM],
        None,
    )
    .await
    .unwrap();

    stream
        .write("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".as_bytes())
        .await
        .unwrap();

    let mut buffer = [0; 1024];
    let received = stream
        .receive(&mut buffer)
        .await
        .unwrap();

    // Drop the stream async (normal Drop is ok too, but that's blocking)
    stream
        .deactivate().await.unwrap();
```

## Debugging

If you're facing problems with this library, you have the following tools for debugging:
- Enable the features `modem-log` and `defmt`: This will enable logging for Nordic's nrfxlib modem driver.
- Enable the feature `modem-trace` and call the function `nrf_modem::fetch_trace()` regularly. This function is called with an async closure handing over chunks of tracing data. Write this data to a UART and use Nordic's nRF Connect tool to collect and interprete the tracing data.
